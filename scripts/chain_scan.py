#!/usr/bin/env python3
"""Pass 2: artifact trust chains across full repository workflow sets.

The pass-1 sample (``scripts/ecosystem_scan.py``) downloads only agent-bearing
workflow files. HG007 needs the opposite view: every workflow in a repository,
because the untrusted producer and the privileged ``workflow_run`` consumer
usually run no agent at all.

This script reads the repository list from the private pass-1 dataset, fetches
each repository's full ``.github/workflows`` directory through the GitHub
contents API, runs the harnessguard engine per repository, and rewrites the
"Artifact trust chains" section of the public report between HTML markers.
Raw per-repo results stay under ``research/data/`` (gitignored); the committed
report contains aggregates only.

Usage:
    uv run python scripts/chain_scan.py --limit 20   # smoke run
    uv run python scripts/chain_scan.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harnessguard import __version__
from harnessguard.engine import scan_workflow_files
from harnessguard.facts import (
    ARTIFACT_SOURCE_EVENTS,
    Workflow,
    agent_steps,
    load_workflow,
    steps_using,
    workflow_run_filters,
)
from harnessguard.rules import load_rules

RAW_JSON = Path("research/data/raw.json")
CHAIN_RAW = Path("research/data/chain_raw.json")
REPORT = Path("research/state-of-agent-workflows.md")
SECTION_START = "<!-- chain-scan:start -->"
SECTION_END = "<!-- chain-scan:end -->"

UPLOAD_ARTIFACT = "actions/upload-artifact"
DOWNLOAD_ARTIFACT = "actions/download-artifact"
MAX_FILE_BYTES = 200_000
API_SLEEP_SECONDS = 0.2
FETCH_SLEEP_SECONDS = 0.05
PROGRESS_EVERY = 25


def corpus_repos() -> list[str]:
    payload = json.loads(RAW_JSON.read_text(encoding="utf-8"))
    return sorted(
        {record["repo"] for record in payload["records"] if record.get("hasAgent")}
    )


def list_workflows(repo: str) -> list[dict[str, Any]]:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/.github/workflows"],
        capture_output=True,
        text=True,
    )
    time.sleep(API_SLEEP_SECONDS)
    if proc.returncode != 0:
        return []
    payload = json.loads(proc.stdout)
    entries = payload if isinstance(payload, list) else [payload]
    return [
        entry
        for entry in entries
        if entry.get("type") == "file"
        and str(entry.get("name", "")).endswith((".yml", ".yaml"))
        and entry.get("download_url")
    ]


def fetch(url: str) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": "harnessguard-chain-scan"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(MAX_FILE_BYTES + 1)
    except Exception:  # noqa: BLE001 - best effort over hundreds of URLs
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def repo_cache_dir(repo: str) -> Path:
    return Path("research/data/repos") / repo.replace("/", "__")


def sync_repo(repo: str, cache: Path) -> list[Path]:
    cache.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for entry in list_workflows(repo):
        dest = cache / entry["name"]
        if not dest.exists():
            text = fetch(str(entry["download_url"]))
            time.sleep(FETCH_SLEEP_SECONDS)
            if text is None:
                continue
            dest.write_text(text, encoding="utf-8")
        paths.append(dest)
    return sorted(paths)


def is_agent_workflow(workflow: Workflow) -> bool:
    return any(agent_steps(job) for job in workflow.jobs.values())


def analyze_repo(paths: list[Path]) -> dict[str, Any]:
    """Producer/consumer picture for the HG007 chain, plus agent involvement."""
    workflows = [w for w in (load_workflow(path) for path in paths) if w is not None]
    producers: dict[str, Workflow] = {}
    for workflow in workflows:
        if not (workflow.events & ARTIFACT_SOURCE_EVENTS):
            continue
        if not any(steps_using(job, UPLOAD_ARTIFACT) for job in workflow.jobs.values()):
            continue
        for key in {str(workflow.raw.get("name", "")), workflow.path.stem}:
            if key:
                producers.setdefault(key, workflow)
    consumers: dict[str, list[Workflow]] = {}
    for workflow in workflows:
        filters = workflow_run_filters(workflow.raw)
        if filters is None:
            continue
        if not any(steps_using(job, DOWNLOAD_ARTIFACT) for job in workflow.jobs.values()):
            continue
        matches = [producers[name] for name in filters if name in producers]
        if not matches and not filters:
            matches = list(dict.fromkeys(producers.values()))
        if matches:
            consumers[str(workflow.path)] = matches
    return {
        "workflows": workflows,
        "producer_count": len({id(w) for w in producers.values()}),
        "consumers": consumers,
        "agent_by_path": {str(w.path): is_agent_workflow(w) for w in workflows},
    }


def build_section(stats: dict[str, Any], generated_at: str) -> str:
    def pct(part: int, whole: int) -> str:
        return f"{(100.0 * part / whole):.1f}%" if whole else "n/a"

    lines: list[str] = []
    lines.append(SECTION_START)
    lines.append("")
    lines.append("## Artifact trust chains (pass 2)")
    lines.append("")
    lines.append(
        f"_Generated {generated_at} with harnessguard {__version__}. Raw per-repo "
        "results are private; aggregates only._"
    )
    lines.append("")
    lines.append(
        "Pass 1 sampled agent workflow files in isolation. HG007 (the Cordyceps "
        "pattern) needs the opposite view: the full `.github/workflows` directory "
        "of every repository in the pass-1 corpus, because the attacker-triggered "
        "producer and the privileged `workflow_run` consumer usually contain no "
        "agent step at all."
    )
    lines.append("")
    repos = stats["reposScanned"]
    lines.append("### Headline")
    lines.append("")
    lines.append(
        f"- Repositories with retrievable workflows: **{repos}** "
        f"(of {stats['reposCorpus']} in the pass-1 corpus)"
    )
    lines.append(f"- Workflow files parsed: **{stats['filesScanned']}**")
    lines.append(
        f"- **{pct(stats['reposWithProducer'], repos)}** upload artifacts from "
        "workflows an attacker can trigger (`pull_request`, comments, issues)"
    )
    lines.append(
        f"- **{pct(stats['reposWithChain'], repos)}** have the full chain: "
        "attacker-triggered producer plus a privileged artifact consumer "
        f"(**{stats['reposWithChain']}** repositories, {stats['findingsTotal']} HG007 findings)"
    )
    lines.append(
        f"- **{pct(stats['findingsAgentFree'], stats['findingsTotal'])}** of the chains "
        "run no AI agent on either side — invisible to agent-only scanners and to "
        "single-file linters alike"
    )
    if stats["findingsTotal"]:
        lines.append(
            f"- The chains collapse into **{stats['distinctTemplates']} distinct "
            "producer→consumer template pair(s)**; the largest family appears in "
            f"**{stats['largestTemplateFamily']} repositories** (fork propagation)"
        )
    lines.append("")
    lines.append("### HG007 findings by severity")
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("| --- | --- |")
    for severity, count in sorted(stats["severityCounts"].items()):
        lines.append(f"| {severity} | {count} |")
    lines.append("")
    lines.append("### Caveats")
    lines.append("")
    lines.append(
        "- Same corpus as pass 1 (GitHub code search, best-match, not a uniform "
        "random sample); workflow snapshots are from the default branch at scan time."
    )
    lines.append(
        "- Chain detection is name-based (`workflow_run.workflows` ↔ workflow name "
        "or file stem) and conservative on purpose: an unmatched producer name "
        "produces no finding."
    )
    lines.append(
        "- Environment-gated consumers are downgraded one severity level, not "
        "cleared; a chain finding is a trust-boundary signal, not a per-repo verdict."
    )
    lines.append(
        "- The corpus is fork-heavy: a few upstream templates are inherited by many "
        "forks, so repository counts overstate the number of independent "
        "implementations."
    )
    lines.append("")
    lines.append(SECTION_END)
    return "\n".join(lines)


def update_report(section: str) -> None:
    text = REPORT.read_text(encoding="utf-8")
    start = text.find(SECTION_START)
    end = text.find(SECTION_END)
    if start == -1 or end == -1 or end < start:
        raise SystemExit(f"markers not found in {REPORT}; run scripts/ecosystem_scan.py first")
    end += len(SECTION_END)
    REPORT.write_text(text[:start] + section + text[end:], encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=0, help="Only scan the first N repos.")
    parser.add_argument("--report", action="store_true", help="Update the public report.")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Rebuild the report section from the saved chain_raw.json without scanning.",
    )
    args = parser.parse_args()

    if args.report_only:
        payload = json.loads(CHAIN_RAW.read_text(encoding="utf-8"))
        update_report(build_section(payload["stats"], payload["generatedAt"]))
        print(f"report updated: {REPORT}", file=sys.stderr)
        return

    repos = corpus_repos()
    if args.limit:
        repos = repos[: args.limit]

    rules = load_rules()
    records: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}
    findings_total = 0
    findings_agent_free = 0
    template_pairs: dict[tuple[str, str], set[str]] = {}
    repos_with_producer = 0
    repos_with_chain = 0
    files_scanned = 0
    repos_skipped = 0

    for index, repo in enumerate(repos, start=1):
        paths = sync_repo(repo, repo_cache_dir(repo))
        if not paths:
            repos_skipped += 1
            continue
        files_scanned += len(paths)
        result = scan_workflow_files(paths, rules, root=repo_cache_dir(repo))
        view = analyze_repo(paths)
        hg007 = [finding for finding in result.findings if finding.rule_id == "HG007"]
        if view["producer_count"]:
            repos_with_producer += 1
        if hg007:
            repos_with_chain += 1
        for finding in hg007:
            findings_total += 1
            severity = str(finding.severity)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            consumer_key = str(finding.workflow)
            producer_files = view["consumers"].get(consumer_key, [])
            for source in producer_files:
                pair = (source.path.name, Path(consumer_key).name)
                template_pairs.setdefault(pair, set()).add(repo)
            agent_free = not view["agent_by_path"].get(consumer_key, False) and all(
                not view["agent_by_path"].get(str(source.path), False)
                for source in producer_files
            )
            if agent_free:
                findings_agent_free += 1
        records.append(
            {
                "repo": repo,
                "files": [str(path) for path in paths],
                "producers": sorted(
                    {str(w.path) for matches in view["consumers"].values() for w in matches}
                ),
                "findings": [
                    {
                        "severity": str(finding.severity),
                        "workflow": str(finding.workflow),
                        "job": finding.job,
                        "message": finding.message,
                    }
                    for finding in hg007
                ],
            }
        )
        if index % PROGRESS_EVERY == 0:
            print(f"scanned {index}/{len(repos)} repos", file=sys.stderr)

    stats = {
        "reposCorpus": len(corpus_repos()),
        "reposScanned": len(records),
        "reposSkipped": repos_skipped,
        "filesScanned": files_scanned,
        "reposWithProducer": repos_with_producer,
        "reposWithChain": repos_with_chain,
        "findingsTotal": findings_total,
        "findingsAgentFree": findings_agent_free,
        "distinctTemplates": len(template_pairs),
        "largestTemplateFamily": max(
            (len(repos) for repos in template_pairs.values()), default=0
        ),
        "severityCounts": severity_counts,
    }
    generated_at = datetime.now(UTC).isoformat()
    CHAIN_RAW.write_text(
        json.dumps({"generatedAt": generated_at, "stats": stats, "records": records}, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(stats, indent=2))

    if args.report:
        update_report(build_section(stats, generated_at))
        print(f"report updated: {REPORT}", file=sys.stderr)


if __name__ == "__main__":
    main()
