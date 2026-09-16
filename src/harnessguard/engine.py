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
    workflows = [
        workflow for path in workflow_paths if (workflow := load_workflow(path)) is not None
    ]
    return run_checks(workflows, rules, root or Path.cwd())


def scan_workflow(
    raw: dict, rules: list[Rule], name: str = "workflow.yml", root: Path | None = None
) -> ScanResult:
    """Scan one workflow mapping (used by the MCP server for generated YAML)."""
    _validate_rules(rules)
    workflow = Workflow(path=Path(name), raw=raw)
    return run_checks([workflow], rules, root or Path.cwd())


def run_checks(workflows: list[Workflow], rules: list[Rule], root: Path) -> ScanResult:
    findings = []
    for workflow in workflows:
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
        repo_ctx = RepoContext(workflows=workflows, root=root)
        for rule in repo_rules:
            findings.extend(REPO_CHECKS[rule.check](repo_ctx, rule))

    findings.sort(key=lambda f: (f.severity.rank, f.rule_id, str(f.workflow), f.job))
    return ScanResult(root=root, findings=findings, workflows_scanned=len(workflows))
