"""Named checks behind rule IDs. Rules are data (YAML); checks are code."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .facts import (
    ARTIFACT_SOURCE_EVENTS,
    UNTRUSTED_EVENTS,
    Workflow,
    job_guards,
    references_triggering_run,
    secrets_in_scope,
    steps_using,
    untrusted_context_hits,
    untrusted_ref_hits,
    workflow_run_filters,
    write_scopes,
)
from .models import Finding, Severity
from .rules.model import Rule

if TYPE_CHECKING:
    from .facts import Step

DOWNLOAD_ARTIFACT = "actions/download-artifact"
UPLOAD_ARTIFACT = "actions/upload-artifact"


@dataclass
class JobContext:
    """Everything a check needs about one agent-bearing job."""

    workflow: Workflow
    name: str
    job: dict
    steps: list[Step]
    agent_steps: list[Step]

    def finding(
        self,
        rule: Rule,
        message: str,
        step: Step | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            severity=severity or rule.severity,
            title=rule.title,
            message=message,
            workflow=self.workflow.path,
            job=self.name,
            step=step.name if step is not None else "",
        )


@dataclass
class RepoContext:
    """Everything a repository-level check needs across workflow files."""

    workflows: list[Workflow]
    root: Path

    def finding(
        self,
        rule: Rule,
        message: str,
        workflow: Workflow,
        job: str = "",
        step: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            severity=severity or rule.severity,
            title=rule.title,
            message=message,
            workflow=workflow.path,
            job=job,
            step=step,
        )


def _guard_note(ctx: JobContext, rule: Rule) -> str | None:
    """Note when a job restricts triggering via ``if:`` guards (opt-in per rule)."""
    if not rule.params.get("guard_downgrade"):
        return None
    guards = job_guards(ctx.job)
    if not guards:
        return None
    return (
        f"Job-level `if:` guard restricts triggering ({', '.join(guards)}); "
        "exposure is reduced but not eliminated (compromised accounts, indirect injection)."
    )


def _untrusted_events(ctx: JobContext) -> str:
    return ", ".join(sorted(ctx.workflow.events & UNTRUSTED_EVENTS))


def check_secrets_untrusted_event(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step + untrusted trigger + runner secrets in scope."""
    if not ctx.workflow.untrusted:
        return []
    secrets = secrets_in_scope(ctx.workflow.raw, ctx.job)
    if not secrets:
        return []
    names = ", ".join(f"secrets.{name}" for name in sorted(secrets))
    note = _guard_note(ctx, rule)
    message = (
        f"Agent step runs on untrusted events ({_untrusted_events(ctx)}) while "
        f"{names} is in scope. Injected instructions in the event payload can "
        "read and exfiltrate these credentials."
    )
    if note:
        message = f"{message} {note}"
    return [
        ctx.finding(
            rule,
            message,
            severity=rule.severity.weaken() if note else None,
        )
    ]


def check_untrusted_context_flow(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Attacker-controlled event fields interpolated into an agent step."""
    findings: list[Finding] = []
    for step in ctx.agent_steps:
        hits = untrusted_context_hits(step.text)
        if not hits:
            continue
        findings.append(
            ctx.finding(
                rule,
                "Agent step reads attacker-controlled event data directly: "
                + ", ".join(hits)
                + ". Treat event text as data, not instructions; keep this job "
                "unprivileged and secret-free (Rule of Two).",
                step=step,
            )
        )
    return findings


def check_write_permissions_untrusted_event(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step + untrusted trigger + explicit write permissions."""
    if not ctx.workflow.untrusted:
        return []
    scopes = write_scopes(ctx.workflow.raw, ctx.job)
    if not scopes:
        return []
    note = _guard_note(ctx, rule)
    message = (
        f"Agent step runs on untrusted events ({_untrusted_events(ctx)}) with write "
        f"permissions: {', '.join(scopes)}. A hijacked agent can push commits, "
        "comments or releases with the workflow token."
    )
    if note:
        message = f"{message} {note}"
    return [
        ctx.finding(
            rule,
            message,
            severity=rule.severity.weaken() if note else None,
        )
    ]


def check_pull_request_target(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step in a pull_request_target workflow."""
    if "pull_request_target" not in ctx.workflow.events:
        return []
    return [
        ctx.finding(
            rule,
            "Agent step runs in a pull_request_target workflow, which exposes secrets "
            "and write tokens to fork pull requests. Do not run agents on this trigger; "
            "use pull_request and isolate privileged follow-up in workflow_run.",
        )
    ]


def check_egress_tool_grants(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step granted shell/network tools or containing egress commands."""
    patterns = rule.params.get("patterns", [])
    compiled = [
        (str(item.get("name", "pattern")), re.compile(str(item["regex"])))
        for item in patterns
        if isinstance(item, dict) and "regex" in item
    ]
    findings: list[Finding] = []
    for step in ctx.agent_steps:
        named_hits: list[str] = []
        for name, pattern in compiled:
            if pattern.search(step.text):
                named_hits.append(name)
        if named_hits:
            findings.append(
                ctx.finding(
                    rule,
                    "Agent step can execute commands or reach the network "
                    f"({', '.join(sorted(set(named_hits)))}). Prefer a narrow tool "
                    "allowlist; egress is the third leg of the Rule of Two.",
                    step=step,
                )
            )
    return findings


def check_untrusted_checkout_ref(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent job checks out an attacker-controlled ref."""
    findings: list[Finding] = []
    for step in ctx.steps:
        if not step.uses.startswith("actions/checkout"):
            continue
        with_block = step.raw.get("with", {})
        ref = str(with_block.get("ref", "")) if isinstance(with_block, dict) else ""
        hits = untrusted_ref_hits(ref)
        if hits:
            findings.append(
                ctx.finding(
                    rule,
                    "Agent job checks out an attacker-controlled ref ("
                    + ", ".join(hits)
                    + "). Fork code enters the workspace the agent operates on; "
                    "keep the job secret-free and read-only, or check out the "
                    "base ref and fetch the diff instead.",
                    step=step,
                )
            )
    return findings


def check_artifact_trust_chain(ctx: RepoContext, rule: Rule) -> list[Finding]:
    """Privileged ``workflow_run`` job consumes artifacts from untrusted runs.

    Cordyceps (Novee, June 2026): a workflow triggered by attacker input
    uploads an artifact; a second, privileged workflow downloads it via
    ``workflow_run``. Neither file is exploitable alone — the risk lives in the
    composition, which per-file scanners do not see.
    """
    producers: dict[str, Workflow] = {}
    for workflow in ctx.workflows:
        if not workflow.untrusted_artifact_source:
            continue
        if not any(steps_using(job, UPLOAD_ARTIFACT) for job in workflow.jobs.values()):
            continue
        for key in {str(workflow.raw.get("name", "")), workflow.path.stem}:
            if key:
                producers.setdefault(key, workflow)

    findings: list[Finding] = []
    for workflow in ctx.workflows:
        filters = workflow_run_filters(workflow.raw)
        if filters is None:
            continue
        matches = (
            [producers[name] for name in filters if name in producers]
            if filters
            else list(dict.fromkeys(producers.values()))
        )
        if not matches:
            continue
        source = matches[0]
        events = ", ".join(sorted(source.events & ARTIFACT_SOURCE_EVENTS))
        for job_name, job in workflow.jobs.items():
            downloads = [
                step
                for step in steps_using(job, DOWNLOAD_ARTIFACT)
                if references_triggering_run(step.raw, job)
            ]
            if not downloads:
                continue
            secrets = secrets_in_scope(workflow.raw, job)
            writes = write_scopes(workflow.raw, job)
            if not secrets and not writes:
                continue
            signals = [f"secrets.{name}" for name in sorted(secrets)]
            signals += [f"{scope}: write" for scope in writes]
            note = ""
            environment = str(job.get("environment", "")).strip()
            if environment and rule.params.get("environment_downgrade"):
                note = (
                    f" Job gated by environment {environment!r}: approvals reduce "
                    "but do not remove exposure."
                )
            message = (
                f"Privileged workflow_run job fetches artifacts from the run of "
                f"untrusted-triggered workflow {source.path.name!r} ({events}) "
                f"while {', '.join(signals)} is in scope. Artifact content is "
                "attacker-influenced; a poisoned artifact turns the low-privilege "
                "run into code or data consumed here (Cordyceps artifact chain). "
                "Treat artifacts as untrusted data: validate the producing run "
                "(actor association, head repository), verify digests, and never "
                "execute artifact code with secrets in scope."
                + note
            )
            findings.append(
                ctx.finding(
                    rule,
                    message,
                    workflow=workflow,
                    job=job_name,
                    step=downloads[0].name,
                    severity=rule.severity.weaken() if note else None,
                )
            )
    return findings


CHECKS: dict[str, Callable[[JobContext, Rule], list[Finding]]] = {
    "secrets_untrusted_event": check_secrets_untrusted_event,
    "untrusted_context_flow": check_untrusted_context_flow,
    "write_permissions_untrusted_event": check_write_permissions_untrusted_event,
    "pull_request_target_agent": check_pull_request_target,
    "egress_tool_grants": check_egress_tool_grants,
    "untrusted_checkout_ref": check_untrusted_checkout_ref,
}

REPO_CHECKS: dict[str, Callable[[RepoContext, Rule], list[Finding]]] = {
    "artifact_trust_chain": check_artifact_trust_chain,
}
