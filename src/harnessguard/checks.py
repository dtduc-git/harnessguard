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
    agent_steps,
    job_guards,
    load_workflow,
    mcp_launch_packages,
    mcp_plaintext_endpoint,
    mcp_unpinned,
    references_triggering_run,
    secrets_in_scope,
    steps_using,
    untrusted_context_hits,
    untrusted_context_hits_in,
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
    """Attacker-controlled event fields reaching the agent, directly or via env."""
    findings: list[Finding] = []
    for label, value in (
        ("job-level env", ctx.job.get("env", {})),
        ("workflow-level env", ctx.workflow.raw.get("env", {})),
    ):
        hits = untrusted_context_hits_in(value)
        if hits:
            findings.append(
                ctx.finding(
                    rule,
                    f"Agent job reads attacker-controlled event data via {label}: "
                    + ", ".join(hits)
                    + ". Treat event text as data, not instructions; keep this job "
                    "unprivileged and secret-free (Rule of Two).",
                )
            )
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


def _untrusted_artifact_producers(workflows: list[Workflow]) -> dict[str, Workflow]:
    """Workflows an attacker can trigger that upload an artifact, keyed by name."""
    producers: dict[str, Workflow] = {}
    for workflow in workflows:
        if not workflow.untrusted_artifact_source:
            continue
        if not any(steps_using(job, UPLOAD_ARTIFACT) for job in workflow.jobs.values()):
            continue
        for key in {str(workflow.raw.get("name", "")), workflow.path.stem}:
            if key:
                producers.setdefault(key, workflow)
    return producers


def _match_producers(workflow: Workflow, producers: dict[str, Workflow]) -> list[Workflow]:
    """Untrusted producers a ``workflow_run`` consumer listens to ([] if none)."""
    filters = workflow_run_filters(workflow.raw)
    if filters is None:
        return []
    if filters:
        return [producers[name] for name in filters if name in producers]
    return list(dict.fromkeys(producers.values()))


def check_artifact_trust_chain(ctx: RepoContext, rule: Rule) -> list[Finding]:
    """Privileged ``workflow_run`` job consumes artifacts from untrusted runs.

    Cordyceps (Novee, June 2026): a workflow triggered by attacker input
    uploads an artifact; a second, privileged workflow downloads it via
    ``workflow_run``. Neither file is exploitable alone — the risk lives in the
    composition, which per-file scanners do not see.
    """
    producers = _untrusted_artifact_producers(ctx.workflows)

    findings: list[Finding] = []
    for workflow in ctx.workflows:
        matches = _match_producers(workflow, producers)
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


def check_untrusted_artifact_to_agent(ctx: RepoContext, rule: Rule) -> list[Finding]:
    """Agent step consumes artifacts produced by an untrusted-triggered run.

    The mirror image of HG007: instead of a privileged job, the consumer is the
    agent itself. Poisoned artifact content reaches the agent as instructions
    or tool input — untrusted input meeting an agent, the first two legs of the
    Rule of Two, composed across two files.
    """
    producers = _untrusted_artifact_producers(ctx.workflows)
    if not producers:
        return []
    findings: list[Finding] = []
    for workflow in ctx.workflows:
        matches = _match_producers(workflow, producers)
        if not matches:
            continue
        source = matches[0]
        events = ", ".join(sorted(source.events & ARTIFACT_SOURCE_EVENTS))
        for job_name, job in workflow.jobs.items():
            agent = agent_steps(job)
            if not agent:
                continue
            fetches = [
                step
                for step in steps_using(job, DOWNLOAD_ARTIFACT)
                if references_triggering_run(step.raw, job)
            ]
            if not fetches:
                continue
            message = (
                f"Agent step consumes artifacts from the run of untrusted-triggered "
                f"workflow {source.path.name!r} ({events}). Artifact content is "
                "attacker-influenced: poisoned files become instructions or tool "
                "input the agent obeys (Rule of Two leg one reaches the agent). "
                "Validate the producing run (actor association, head repository) "
                "and treat artifact content as untrusted data, not instructions."
            )
            findings.append(
                ctx.finding(
                    rule,
                    message,
                    workflow=workflow,
                    job=job_name,
                    step=agent[0].name,
                )
            )
    return findings


REUSABLE_WORKFLOW_PREFIXES = ("./.github/workflows/", "$/.github/workflows/")


def _repo_root(workflow: Workflow, fallback: Path) -> Path:
    path = workflow.path.resolve()
    if path.parent.name == "workflows" and path.parent.parent.name == ".github":
        return path.parent.parent.parent
    return fallback


def _resolve_callee(workflow: Workflow, root: Path, target: str) -> Path | None:
    relative = target.removeprefix("./").removeprefix("$/")
    candidates = [
        _repo_root(workflow, root) / relative,
        workflow.path.parent / Path(relative).name,
    ]
    return next((path for path in candidates if path.is_file()), None)


def _caller_guard_note(workflow_raw: dict, job: dict, rule: Rule) -> str | None:
    if not rule.params.get("guard_downgrade"):
        return None
    guards = job_guards(job)
    if guards:
        return (
            f" Calling job has an `if:` guard ({', '.join(guards)}); exposure is "
            "reduced but not eliminated."
        )
    if "needs." not in str(job.get("if", "")):
        return None
    needs = job.get("needs")
    needed = [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []
    upstream_jobs = workflow_raw.get("jobs", {})
    for name in needed:
        upstream = upstream_jobs.get(name) if isinstance(upstream_jobs, dict) else None
        upstream_guards = job_guards(upstream) if isinstance(upstream, dict) else []
        if upstream_guards:
            return (
                f" Calling job is gated indirectly via `needs: {name}`, whose `if:` "
                f"restricts triggering ({', '.join(upstream_guards)}); exposure is "
                "reduced but not eliminated (other event paths may bypass the guard)."
            )
    return None


def check_reusable_workflow_chain(ctx: RepoContext, rule: Rule) -> list[Finding]:
    """Untrusted caller passes secrets to an agent-bearing reusable workflow.

    HG001 split across two files: the caller is triggered by issues, comments
    or similar, and hands its secrets to a ``workflow_call`` workflow that runs
    an agent. Each file looks harmless alone; per-file scanners miss the chain.
    """
    findings: list[Finding] = []
    for workflow in ctx.workflows:
        if not workflow.untrusted:
            continue
        events = ", ".join(sorted(workflow.events & UNTRUSTED_EVENTS))
        for job_name, job in workflow.jobs.items():
            target = str(job.get("uses", ""))
            if not target.startswith(REUSABLE_WORKFLOW_PREFIXES):
                continue
            if not job.get("secrets"):
                continue
            callee_path = _resolve_callee(workflow, ctx.root, target)
            callee = load_workflow(callee_path) if callee_path is not None else None
            if callee is None:
                continue
            agent_jobs = {
                name: agent_steps(job_raw)
                for name, job_raw in callee.jobs.items()
                if agent_steps(job_raw) and secrets_in_scope(callee.raw, job_raw)
            }
            if not agent_jobs:
                continue
            callee_job = next(iter(agent_jobs))
            agent = agent_jobs[callee_job][0]
            passed = (
                "`secrets: inherit`"
                if job.get("secrets") == "inherit"
                else "an explicit secrets mapping"
            )
            note = _caller_guard_note(workflow.raw, job, rule)
            message = (
                f"Untrusted-triggered workflow ({events}) calls reusable workflow "
                f"{target!r} with {passed}, and that workflow runs an agent "
                f"({agent.name!r} in job {callee_job!r}). Attacker-influenced input "
                "passes into an agent-bearing workflow with the caller's secrets in "
                "scope, and no single file shows the violation. Keep agent workflows "
                "secret-free; pass secrets only to non-agent jobs after validation."
                + (note or "")
            )
            findings.append(
                ctx.finding(
                    rule,
                    message,
                    workflow=workflow,
                    job=job_name,
                    severity=rule.severity.weaken() if note else None,
                )
            )
    return findings


def check_mcp_config_hygiene(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step launches unpinned MCP servers or plaintext MCP endpoints."""
    findings: list[Finding] = []
    for step in ctx.agent_steps:
        problems: list[str] = []
        for package in mcp_launch_packages(step.text):
            if mcp_unpinned(package):
                problems.append(f"unpinned MCP server package {package!r}")
        if mcp_plaintext_endpoint(step.text):
            problems.append("plaintext HTTP MCP endpoint")
        if not problems:
            continue
        findings.append(
            ctx.finding(
                rule,
                "Agent step configures MCP servers insecurely: "
                + "; ".join(problems)
                + ". Pin MCP server packages to immutable versions (OWASP MCP04 "
                "supply chain) and use TLS or loopback endpoints for MCP traffic.",
                step=step,
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
    "mcp_config_hygiene": check_mcp_config_hygiene,
}

REPO_CHECKS: dict[str, Callable[[RepoContext, Rule], list[Finding]]] = {
    "artifact_trust_chain": check_artifact_trust_chain,
    "untrusted_artifact_to_agent": check_untrusted_artifact_to_agent,
    "reusable_workflow_chain": check_reusable_workflow_chain,
}
