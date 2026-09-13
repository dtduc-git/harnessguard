"""Output rendering: text, JSON, SARIF."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .models import ScanResult, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_text(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.findings:
        console.print(
            f"[green]No findings[/green] in {result.workflows_scanned} workflow(s) "
            f"under {result.root}"
        )
        return
    table = Table(title=f"harnessguard findings ({len(result.findings)})")
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Workflow")
    table.add_column("Job")
    table.add_column("Finding")
    for finding in result.findings:
        table.add_row(
            finding.rule_id,
            str(finding.severity),
            _relative(finding.workflow, result.root),
            finding.job,
            finding.message,
        )
    console.print(table)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def to_json(result: ScanResult) -> dict:
    return {
        "tool": "harnessguard",
        "version": __version__,
        "root": str(result.root),
        "workflows_scanned": result.workflows_scanned,
        "counts": result.by_severity(),
        "findings": [finding.to_dict() for finding in result.findings],
    }


def to_sarif(result: ScanResult) -> dict:
    seen: dict[str, str] = {}
    for finding in result.findings:
        seen.setdefault(finding.rule_id, finding.title)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "harnessguard",
                        "informationUri": "https://github.com/dtduc-git/harnessguard",
                        "version": __version__,
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": title},
                            }
                            for rule_id, title in sorted(seen.items())
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": SARIF_LEVEL[finding.severity],
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": _relative(finding.workflow, result.root)
                                    }
                                }
                            }
                        ],
                    }
                    for finding in result.findings
                ],
            }
        ],
    }
