"""Scan orchestration."""

from __future__ import annotations

from pathlib import Path

from .checks import CHECKS, JobContext
from .discovery import discover, root_of
from .facts import agent_steps, load_workflow
from .models import ScanResult
from .rules.model import Rule


def scan(paths: list[Path], rules: list[Rule]) -> ScanResult:
    return scan_workflow_files(discover(paths), rules, root=root_of(paths))


def scan_workflow_files(
    workflow_paths: list[Path], rules: list[Rule], root: Path | None = None
) -> ScanResult:
    """Scan already-resolved workflow files (used by the CLI and the research scripts)."""
    findings = []
    scanned = 0
    for path in workflow_paths:
        workflow = load_workflow(path)
        if workflow is None:
            continue
        scanned += 1
        for job_name, job in workflow.jobs.items():
            steps = agent_steps(job)
            if not steps:
                continue
            ctx = JobContext(workflow=workflow, name=job_name, job=job, agent_steps=steps)
            for rule in rules:
                check = CHECKS.get(rule.check)
                if check is None:
                    raise ValueError(
                        f"rule {rule.id}: unknown check {rule.check!r}; "
                        f"valid checks: {', '.join(sorted(CHECKS))}"
                    )
                findings.extend(check(ctx, rule))

    findings.sort(key=lambda f: (f.severity.rank, f.rule_id, str(f.workflow), f.job))
    return ScanResult(root=root or Path.cwd(), findings=findings, workflows_scanned=scanned)
