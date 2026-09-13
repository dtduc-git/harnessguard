"""harnessguard command line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import scan as run_scan
from .models import severity_from
from .report import render_text, to_json, to_sarif
from .rules import load_rules

app = typer.Typer(
    name="harnessguard",
    help=(
        "Static hardening linter for GitHub Actions workflows that run AI agents. "
        "Enforces the Agent Rule of Two. Never executes anything."
    ),
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect available rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info", "none")
FORMAT_CHOICES = ("text", "json")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"harnessguard {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """Guard the agent harness in your CI."""


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        None, help="Files or directories to scan; searches .github/workflows."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", help=f"Exit 1 at this severity or above: {' | '.join(FAIL_ON_CHOICES)}"
    ),
    format: str = typer.Option("text", "--format", help=f"{' | '.join(FORMAT_CHOICES)}"),
    sarif: Path | None = typer.Option(None, "--sarif", help="Write SARIF results to this path."),
    rules_dir: list[Path] = typer.Option(
        None, "--rules-dir", help="Extra rule directories to overlay on the builtin rules."
    ),
) -> None:
    """Scan workflow files for agent trust-boundary risks."""
    if fail_on not in FAIL_ON_CHOICES:
        err_console.print(f"[red]unknown --fail-on value:[/red] {fail_on}")
        raise typer.Exit(2)
    if format not in FORMAT_CHOICES:
        err_console.print(f"[red]unknown --format value:[/red] {format}")
        raise typer.Exit(2)

    target_paths = list(paths) if paths else [Path(".")]
    rules = load_rules(list(rules_dir) if rules_dir else None)
    result = run_scan(target_paths, rules)

    if sarif is not None:
        sarif.write_text(json.dumps(to_sarif(result), indent=2) + "\n", encoding="utf-8")

    if format == "json":
        console.print_json(json.dumps(to_json(result)))
    else:
        render_text(result, console)

    if fail_on != "none" and result.has_at_or_above(severity_from(fail_on)):
        raise typer.Exit(1)


@rules_app.command("list")
def rules_list(
    format: str = typer.Option("text", "--format", help=f"{' | '.join(FORMAT_CHOICES)}"),
) -> None:
    """List the loaded rules."""
    rules = load_rules()
    if format == "json":
        console.print_json(json.dumps([rule.model_dump() for rule in rules]))
        return
    table = Table(title=f"harnessguard rules ({len(rules)})")
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Title")
    for rule in rules:
        table.add_row(rule.id, str(rule.severity), rule.owasp, rule.title)
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
