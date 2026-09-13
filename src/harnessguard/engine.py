"""Scan orchestration."""

from __future__ import annotations

from pathlib import Path

from .checks import CHECKS, REPO_CHECKS, JobContext, RepoContext
from .discovery import discover, root_of
from .facts import Workflow, all_steps, is_agent_step, load_workflow
from .models import ScanResult
from .rules.model import Rule


def scan(paths: list[Path], rules: list[Rule]) -> ScanResult:
    return scan_workflow_files(discover(paths), rules, root=root_of(paths))


def _validate_rules(rules: list[Rule]) -> None:
    known = sorted(set(CHECKS) | set(REPO_CHECKS))
    for rule in rules:
        if rule.check not in CHECKS and rule.check not in REPO_CHECKS:
            raise ValueError(
                f"rule {rule.id}: unknown check {rule.check!r}; "
                f"valid checks: {', '.join(known)}"
            )


def scan_workflow_files(
    workflow_paths: list[Path], rules: list[Rule], root: Path | None = None
) -> ScanResult:
    """Scan already-resolved workflow files (used by the CLI and the research scripts)."""
    _validate_rules(rules)
    findings = []
    workflows: list[Workflow] = []
    scanned = 0
    for path in workflow_paths:
        workflow = load_workflow(path)
        if workflow is None:
            continue
        scanned += 1
        workflows.append(workflow)
        for job_name, job in workflow.jobs.items():
            steps = all_steps(job)
            agent = [step for step in steps if is_agent_step(step)]
            if not agent:
                continue
            ctx = JobContext(
                workflow=workflow, name=job_name, job=job, steps=steps, agent_steps=agent
            )
            for rule in rules:
                check = CHECKS.get(rule.check)
                if check is not None:
                    findings.extend(check(ctx, rule))

    repo_rules = [rule for rule in rules if rule.check in REPO_CHECKS]
    if repo_rules:
        repo_ctx = RepoContext(workflows=workflows, root=root or Path.cwd())
        for rule in repo_rules:
            findings.extend(REPO_CHECKS[rule.check](repo_ctx, rule))

    findings.sort(key=lambda f: (f.severity.rank, f.rule_id, str(f.workflow), f.job))
    return ScanResult(root=root or Path.cwd(), findings=findings, workflows_scanned=scanned)
