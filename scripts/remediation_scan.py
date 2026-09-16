#!/usr/bin/env python3
"""Pass 3: re-scan the pass-1 corpus and measure remediation churn.

The pass-1 sample downloaded 490 workflow files (337 agent-bearing) on
2026-09-13. This script re-fetches the same repository paths today, scans the
old snapshot and the current file with the *same* engine version, and compares
the findings per file. Comparing same-engine results isolates content changes
from rule changes; the pass-1 numbers recorded with harnessguard 0.3.0 are not
used as the baseline.

Raw per-file results stay under ``research/data/`` (gitignored); the committed
report contains aggregates only.

Usage:
    uv run python scripts/remediation_scan.py --limit 20   # smoke run
    uv run python scripts/remediation_scan.py
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harnessguard import __version__
from harnessguard.engine import scan_workflow_files
from harnessguard.rules import load_rules

RAW_JSON = Path("research/data/raw.json")
CHECK_DIR = Path("research/data/recheck")
RAW_OUT = Path("research/data/remediation_raw.json")
REPORT = Path("research/state-of-agent-workflows.md")
SECTION_START = "<!-- remediation-scan:start -->"
SECTION_END = "<!-- remediation-scan:end -->"

MAX_FILE_BYTES = 200_000
FETCH_WORKERS = 8


def load_records() -> list[dict[str, Any]]:
    payload = json.loads(RAW_JSON.read_text(encoding="utf-8"))
    seen: set[tuple[str, str]] = set()
    records: list[dict[str, Any]] = []
    for record in payload["records"]:
        key = (record["repo"], record["path"])
        if key in seen or not record.get("hasAgent"):
            continue
        seen.add(key)
        records.append(record)
    return records


def fetch_current(repo: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "harnessguard-remediation-scan"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(MAX_FILE_BYTES + 1)
    except Exception:  # noqa: BLE001 - best effort over hundreds of URLs
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def scan_keys(path: Path, rules: list[Any]) -> set[tuple[str, str, str]] | None:
    if not path.is_file():
        return None
    result = scan_workflow_files([path], rules, root=path.parent)
    return {(f.rule_id, f.job, f.step) for f in result.findings}


def analyze(record: dict[str, Any], rules: list[Any]) -> dict[str, Any]:
    old_path = Path(record["localPath"])
    new_path = CHECK_DIR / f"{Path(record['localPath']).stem}.yml"
    old_keys = scan_keys(old_path, rules)
    current = fetch_current(record["repo"], record["path"])
    entry: dict[str, Any] = {
        "repo": record["repo"],
        "path": record["path"],
        "gone": current is None,
        "oldRules": sorted({key[0] for key in (old_keys or set())}),
        "newRules": [],
    }
    if current is not None:
        new_path.write_text(current, encoding="utf-8")
        new_keys = scan_keys(new_path, rules) or set()
        entry["newRules"] = sorted({key[0] for key in new_keys})
        entry["resolved"] = sorted({key[0] for key in (old_keys or set()) - new_keys})
        entry["introduced"] = sorted({key[0] for key in new_keys - (old_keys or set())})
        if current == old_path.read_text(encoding="utf-8", errors="replace"):
            entry["identical"] = True
    return entry


def build_section(entries: list[dict[str, Any]], generated_at: str) -> str:
    def pct(part: int, whole: int) -> str:
        return f"{(100.0 * part / whole):.1f}%" if whole else "n/a"

    fetched = [entry for entry in entries if not entry["gone"]]
    gone = len(entries) - len(fetched)
    unchanged = [entry for entry in fetched if entry.get("identical")]
    introduced_files = [entry for entry in fetched if entry.get("introduced")]
    old_with_findings = [entry for entry in fetched if entry["oldRules"]]
    new_with_findings = [entry for entry in fetched if entry["newRules"]]
    fully_remediated = [entry for entry in fetched if entry["oldRules"] and not entry["newRules"]]

    old_rule_files: Counter[str] = Counter()
    new_rule_files: Counter[str] = Counter()
    for entry in fetched:
        old_rule_files.update(entry["oldRules"])
        new_rule_files.update(entry["newRules"])

    lines: list[str] = []
    lines.append(SECTION_START)
    lines.append("")
    lines.append("## Re-scan after publication (pass 3)")
    lines.append("")
    lines.append(
        f"_Generated {generated_at} with harnessguard {__version__}. Same corpus as "
        "pass 1 (agent-bearing workflow files); each file re-fetched from its "
        "repository and compared against the 2026-09-13 snapshot with the same engine._"
    )
    lines.append("")
    lines.append("### Headline")
    lines.append("")
    lines.append(
        f"- Files re-checked: **{len(fetched)}** of {len(entries)} "
        f"({gone} no longer retrievable at the same path)"
    )
    lines.append(
        f"- **{len(unchanged)}** files byte-identical to the 2026-09-13 snapshot "
        f"({pct(len(unchanged), len(fetched))}) — the corpus is largely static"
    )
    lines.append(
        f"- **{len(fully_remediated)}** files fixed every finding they previously had; "
        f"**{len(introduced_files)}** gained at least one new finding"
    )
    lines.append(
        f"- Files carrying at least one finding: **{len(old_with_findings)} → "
        f"{len(new_with_findings)}** against the same rule set"
    )
    lines.append("")
    lines.append("### Findings by rule, before → after")
    lines.append("")
    lines.append("| Rule | Files (snapshot) | Files (today) |")
    lines.append("| --- | --- | --- |")
    for rule in sorted(set(old_rule_files) | set(new_rule_files)):
        lines.append(f"| {rule} | {old_rule_files[rule]} | {new_rule_files[rule]} |")
    lines.append("")
    rule_resolved: Counter[str] = Counter()
    rule_introduced: Counter[str] = Counter()
    for entry in fetched:
        rule_resolved.update(entry.get("resolved", []))
        rule_introduced.update(entry.get("introduced", []))
    if rule_resolved or rule_introduced:
        lines.append("| Rule | Findings resolved | Findings introduced |")
        lines.append("| --- | --- | --- |")
        for rule in sorted(set(rule_resolved) | set(rule_introduced)):
            lines.append(f"| {rule} | {rule_resolved[rule]} | {rule_introduced[rule]} |")
        lines.append("")
    lines.append("### Caveats")
    lines.append("")
    lines.append(
        "- The window between snapshot and re-scan is three days; a low change rate "
        "is expected and does not measure the blog's effect."
    )
    lines.append(
        "- Files live on default branches; edits can be unrelated to security "
        "(dependency bumps, renames, refactors), and repositories can be archived."
    )
    lines.append(
        "- Repo-level chain rules (HG007–HG009) cannot be evaluated per file and are "
        "excluded from this comparison; HG010 is included."
    )
    lines.append("")
    lines.append(SECTION_END)
    return "\n".join(lines)


def update_report(section: str) -> None:
    text = REPORT.read_text(encoding="utf-8")
    if SECTION_START in text and SECTION_END in text:
        start = text.index(SECTION_START)
        end = text.index(SECTION_END) + len(SECTION_END)
        text = text[:start] + section + text[end:]
    else:
        marker = "\n## Caveats\n"
        text = text.replace(marker, f"\n{section}\n{marker}", 1)
    REPORT.write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=0, help="only scan the first N records")
    parser.add_argument("--workers", type=int, default=FETCH_WORKERS)
    args = parser.parse_args()

    rules = load_rules()
    CHECK_DIR.mkdir(parents=True, exist_ok=True)
    records = load_records()
    if args.limit:
        records = records[: args.limit]
    print(f"records: {len(records)}")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        entries = list(pool.map(lambda record: analyze(record, rules), records))

    RAW_OUT.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    generated_at = datetime.now(UTC).isoformat()
    section = build_section(entries, generated_at)
    update_report(section)
    print(section)


if __name__ == "__main__":
    main()
