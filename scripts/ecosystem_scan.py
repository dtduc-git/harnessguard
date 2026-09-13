#!/usr/bin/env python3
"""Ecosystem scan: sample real-world AI-agent workflows from public GitHub repos.

Fetches workflow files via GitHub code search, runs the harnessguard rule
engine over them, and aggregates findings into a report. Repo names are kept
only in the private raw dataset; the generated report contains aggregates only.

Usage:
    uv run python scripts/ecosystem_scan.py --out research/data --per-query 150
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harnessguard import __version__
from harnessguard.engine import scan_workflow_files
from harnessguard.facts import UNTRUSTED_EVENTS, agent_steps, job_guards, load_workflow
from harnessguard.rules import load_rules

QUERIES: list[str] = [
    "claude-code-action path:.github/workflows",
    "run-gemini-cli path:.github/workflows",
    "codex-action path:.github/workflows",
    "copilot-coding-agent path:.github/workflows",
]

MAX_FILE_BYTES = 200_000
SEARCH_SLEEP_SECONDS = 7.0
FETCH_SLEEP_SECONDS = 0.05
OWN_REPO = "dtduc-git/harnessguard"


def is_workflow_path(path: str) -> bool:
    """Code search matches substrings; keep only files directly under .github/workflows."""
    parts = path.split("/")
    if not parts[-1].endswith((".yml", ".yaml")):
        return False
    for index in range(len(parts) - 1):
        if parts[index] == ".github" and parts[index + 1] == "workflows":
            return index + 2 == len(parts) - 1
    return False


def search(query: str, per_query: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    pages = max(1, (per_query + 99) // 100)
    for page in range(1, pages + 1):
        url = f"search/code?q={urllib.parse.quote_plus(query)}&per_page=100&page={page}"
        proc = subprocess.run(["gh", "api", url], capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"warn: search failed ({query}): {proc.stderr.strip()[:200]}", file=sys.stderr)
            break
        payload = json.loads(proc.stdout)
        items.extend(payload.get("items", []))
        time.sleep(SEARCH_SLEEP_SECONDS)
    return items[:per_query]


def fetch_raw(item: dict[str, Any]) -> str | None:
    repo = item["repository"]
    branch = repo.get("default_branch") or "HEAD"
    path = urllib.parse.quote(item["path"], safe="/")
    url = f"https://raw.githubusercontent.com/{repo['full_name']}/{branch}/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "harnessguard-ecosystem-scan"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(MAX_FILE_BYTES + 1)
    except Exception:  # noqa: BLE001 - best effort over hundreds of URLs
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def classify(workflow_path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    workflow = load_workflow(workflow_path)
    if workflow is None:
        return {}
    rules = {finding["rule"] for finding in findings}
    return {
        "name": str(workflow.raw.get("name", "")),
        "events": sorted(workflow.events),
        "untrustedEvents": sorted(workflow.events & UNTRUSTED_EVENTS),
        "hasAgent": any(agent_steps(job) for job in workflow.jobs.values()),
        "guarded": any(job_guards(job) for job in workflow.jobs.values()),
        "rules": sorted(rules),
        "findings": findings,
    }


def build_report(
    sample: dict[str, Any],
    records: list[dict[str, Any]],
    generated_at: str,
) -> str:
    files = [record for record in records if record.get("hasAgent")]
    files_parsed = len(files)
    repo_count = len({record["repo"] for record in files})
    rule_files: dict[str, set[str]] = defaultdict(set)
    files_with_findings = 0
    untrusted_trigger_files = 0
    event_counts: Counter[str] = Counter()
    for record in files:
        key = record["localPath"]
        if record["findings"]:
            files_with_findings += 1
        if record["untrustedEvents"]:
            untrusted_trigger_files += 1
            for event in record["untrustedEvents"]:
                event_counts[event] += 1
        for rule in record["rules"]:
            rule_files[rule].add(key)

    def pct(part: int, whole: int) -> str:
        return f"{(100.0 * part / whole):.1f}%" if whole else "n/a"

    privilege_files = rule_files.get("HG001", set()) | rule_files.get("HG003", set())
    injection_files = rule_files.get("HG002", set())
    privilege_guarded = sum(
        1 for record in files if record["guarded"] and record["localPath"] in privilege_files
    )

    lines: list[str] = []
    lines.append("# State of AI-agent workflows in the wild")
    lines.append("")
    lines.append(f"_Generated {generated_at} with harnessguard {__version__}._")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Public GitHub Actions workflow files matching known AI-agent actions were "
        "sampled via the GitHub code search API (queries below, best-match results), "
        "filtered to files directly under `.github/workflows/`, downloaded from "
        "raw.githubusercontent.com, and analyzed with the harnessguard rule engine. "
        "Only files where the engine detected at least one agent step are counted. "
        "All stats are aggregate; no repository is named in this report."
    )
    lines.append("")
    lines.append("| Query | Candidates requested |")
    lines.append("| --- | --- |")
    for query in QUERIES:
        lines.append(f"| `{query}` | {sample['perQuery'].get(query, 0)} |")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(f"- Agent workflow files analyzed: **{files_parsed}** from **{repo_count}** repos")
    lines.append(
        f"- **{pct(files_with_findings, files_parsed)}** have at least one rule-of-two finding"
    )
    lines.append(
        f"- **{pct(len(privilege_files), files_parsed)}** combine untrusted events with "
        "runner secrets or write permissions (HG001/HG003)"
    )
    lines.append(
        f"- **{pct(len(injection_files), files_parsed)}** interpolate attacker-controlled "
        "event data into agent steps (HG002)"
    )
    lines.append(
        f"- **{pct(len(rule_files.get('HG004', set())), files_parsed)}** run an agent on "
        "`pull_request_target` (HG004)"
    )
    lines.append(
        f"- **{pct(untrusted_trigger_files, files_parsed)}** are triggered by at least one "
        "event carrying attacker-controlled content"
    )
    lines.append(
        f"- Of the privilege-combining files, **{pct(privilege_guarded, len(privilege_files))}** "
        "restrict triggering with `github.actor` / `author_association` guards — reduced, "
        "not eliminated, exposure"
    )
    lines.append("")
    lines.append("## Sample")
    lines.append("")
    lines.append(f"- Files downloaded and parsed: **{sample['filesParsed']}**")
    lines.append(f"- Files with a detected agent step: **{files_parsed}**")
    lines.append(f"- Repositories: **{repo_count}**")
    lines.append(f"- Download / parse failures: {sample['failures']}")
    lines.append("")
    lines.append("### Untrusted trigger mix (agent files)")
    lines.append("")
    lines.append("| Event | Files |")
    lines.append("| --- | --- |")
    for event, count in event_counts.most_common():
        lines.append(f"| `{event}` | {count} |")
    lines.append("")
    lines.append("## Findings by rule")
    lines.append("")
    lines.append("| Rule | Files affected | Share of agent files |")
    lines.append("| --- | --- | --- |")
    for rule_id, paths in sorted(rule_files.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {rule_id} | {len(paths)} | {pct(len(paths), files_parsed)} |")
    lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append(
        "- GitHub code search returns best-match results, not a uniform random "
        "sample; popularity and recency skew the corpus."
    )
    lines.append(
        "- Workflows are point-in-time snapshots; a repo can fix a finding later."
    )
    lines.append(
        "- Heuristic rules trade precision for recall; counts are a lower bound on "
        "real risk signals, not a per-repo verdict, and not every flagged workflow "
        "is exploitable (mitigations may exist outside the file)."
    )
    lines.append(
        "- Agent detection is pattern-based (known actions and CLI invocations); "
        "custom or renamed integrations are not counted."
    )
    lines.append(
        "- Job-level guards (actor allowlists, author-association checks) are "
        "recognized for HG001/HG003 and downgrade those findings one level; other "
        "rules do not consider guards, and a guard still leaves compromised-account "
        "and indirect-injection risk."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("research/data"))
    parser.add_argument("--per-query", type=int, default=150)
    args = parser.parse_args()

    out_dir: Path = args.out
    downloads_dir = out_dir / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    seen: set[tuple[str, str]] = set()
    selected: list[dict[str, Any]] = []
    per_query_counts: dict[str, int] = {}
    for query in QUERIES:
        count = 0
        for item in search(query, args.per_query):
            repo = item["repository"]
            if repo["full_name"] == OWN_REPO or repo.get("fork"):
                continue
            if not is_workflow_path(item["path"]):
                continue
            key = (repo["full_name"], item["path"])
            if key in seen:
                continue
            seen.add(key)
            selected.append(item)
            count += 1
        per_query_counts[query] = count
        print(f"{query}: selected {count}", file=sys.stderr)

    parsed_paths: list[Path] = []
    pairs: list[tuple[dict[str, Any], Path]] = []
    failures = 0
    for index, item in enumerate(selected):
        text = fetch_raw(item)
        time.sleep(FETCH_SLEEP_SECONDS)
        if text is None:
            failures += 1
            continue
        local_path = downloads_dir / f"{index:04d}.yml"
        local_path.write_text(text, encoding="utf-8")
        parsed_paths.append(local_path)
        pairs.append((item, local_path))

    print(f"downloaded: {len(parsed_paths)} / {len(selected)}", file=sys.stderr)

    rules = load_rules()
    result = scan_workflow_files(parsed_paths, rules, root=out_dir)

    findings_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in result.findings:
        findings_by_path[str(finding.workflow)].append(
            {
                "rule": finding.rule_id,
                "severity": str(finding.severity),
                "job": finding.job,
                "step": finding.step,
                "message": finding.message,
            }
        )

    records: list[dict[str, Any]] = []
    for item, local_path in pairs:
        repo = item["repository"]
        info = classify(local_path, findings_by_path.get(str(local_path), []))
        if not info:
            failures += 1
            continue
        records.append(
            {
                "repo": repo["full_name"],
                "path": item["path"],
                "localPath": str(local_path),
                "stars": repo.get("stargazers_count", 0),
                **info,
            }
        )

    agent_files = sum(1 for record in records if record["hasAgent"])
    print(f"parsed: {len(records)}, with agent step: {agent_files}", file=sys.stderr)

    generated_at = datetime.now(UTC).isoformat()
    sample = {
        "generatedAt": generated_at,
        "perQuery": per_query_counts,
        "filesParsed": len(records),
        "agentFiles": agent_files,
        "failures": failures,
    }
    (out_dir / "raw.json").write_text(
        json.dumps({"sample": sample, "records": records}, indent=2),
        encoding="utf-8",
    )

    report_dir = Path("research")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "state-of-agent-workflows.md"
    report_path.write_text(
        build_report(sample, records, generated_at) + "\n", encoding="utf-8"
    )
    print(f"report: {report_path}", file=sys.stderr)
    print(json.dumps(sample, indent=2))


if __name__ == "__main__":
    main()
