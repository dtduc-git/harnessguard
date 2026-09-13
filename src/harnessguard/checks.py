"""Named checks behind rule IDs. Rules are data (YAML); checks are code."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .facts import (
    UNTRUSTED_EVENTS,
    Workflow,
    secrets_in_job,
    untrusted_context_hits,
    write_scopes,
)
from .models import Finding
from .rules.model import Rule

if TYPE_CHECKING:
    from .facts import Step


@dataclass
class JobContext:
    """Everything a check needs about one agent-bearing job."""

    workflow: Workflow
    name: str
    job: dict
    agent_steps: list[Step]

    def finding(self, rule: Rule, message: str, step: Step | None = None) -> Finding:
        return Finding(
            rule_id=rule.id,
            severity=rule.severity,
            title=rule.title,
            message=message,
            workflow=self.workflow.path,
            job=self.name,
            step=step.name if step is not None else "",
        )


def _untrusted_events(ctx: JobContext) -> str:
    return ", ".join(sorted(ctx.workflow.events & UNTRUSTED_EVENTS))


def check_secrets_untrusted_event(ctx: JobContext, rule: Rule) -> list[Finding]:
    """Agent step + untrusted trigger + runner secrets in scope."""
    if not ctx.workflow.untrusted:
        return []
    secrets = secrets_in_job(ctx.job)
    if not secrets:
        return []
    names = ", ".join(f"secrets.{name}" for name in sorted(secrets))
    return [
        ctx.finding(
            rule,
            f"Agent step runs on untrusted events ({_untrusted_events(ctx)}) while "
            f"{names} is in scope. Injected instructions in the event payload can "
            "read and exfiltrate these credentials.",
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
    return [
        ctx.finding(
            rule,
            f"Agent step runs on untrusted events ({_untrusted_events(ctx)}) with write "
            f"permissions: {', '.join(scopes)}. A hijacked agent can push commits, "
            "comments or releases with the workflow token.",
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


CHECKS: dict[str, Callable[[JobContext, Rule], list[Finding]]] = {
    "secrets_untrusted_event": check_secrets_untrusted_event,
    "untrusted_context_flow": check_untrusted_context_flow,
    "write_permissions_untrusted_event": check_write_permissions_untrusted_event,
    "pull_request_target_agent": check_pull_request_target,
    "egress_tool_grants": check_egress_tool_grants,
}
