"""Extract security-relevant facts from GitHub Actions workflow YAML.

The vocabulary lives here: what counts as an agent step, which events carry
attacker-controlled content, how interpolated untrusted context looks.
Rules combine these facts through named checks. Nothing is ever executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

#: Events whose payload is (partly) attacker-controlled on public repos.
UNTRUSTED_EVENTS = frozenset(
    {"issues", "issue_comment", "pull_request_target", "discussion", "discussion_comment"}
)

#: Events that let an attacker influence the content of an uploaded artifact.
ARTIFACT_SOURCE_EVENTS = UNTRUSTED_EVENTS | {"pull_request"}

#: ``uses:`` values that identify an AI agent / AI review action.
AGENT_ACTION_PATTERNS = (
    r"anthropics/claude-code-action",
    r"google-github-actions/run-gemini-cli",
    r"openai/codex-action",
    r"github/copilot",
    r"copilot-coding-agent",
    r"coderabbitai/",
    r"graphite-app/",
)

#: Shell invocations that identify an AI agent CLI step.
AGENT_RUN_PATTERNS = (
    r"(?i)\bnpx\b[^\n]*(@anthropic-ai/claude-code|@google/gemini-cli|@openai/codex)",
    r"(?i)\b(claude|gemini|codex)\b[^\n]{0,60}(--print|--prompt|--dangerously-skip-permissions|-p\b)",
    r"(?i)\bopencode\b[^\n]*\brun\b",
    r"(?i)\baider\b",
)

#: Attacker-controllable event fields interpolated via expressions.
UNTRUSTED_CONTEXT_RE = re.compile(
    r"github\.(?:"
    r"event\.(?:issue|comment|discussion|review|pull_request)[\w.]*\.(?:body|title)"
    r"|head_ref"
    r")\b",
    re.IGNORECASE,
)

#: Job-level ``if:`` conditions that restrict who can trigger the job.
GUARD_PATTERNS = (
    ("author association check", re.compile(r"author_association", re.IGNORECASE)),
    ("actor allowlist", re.compile(r"github\.actor\b")),
    ("JSON allowlist condition", re.compile(r"fromJSON\(")),
)

#: Attacker-controllable refs used as checkout targets.
UNTRUSTED_REF_RE = re.compile(
    r"github\.(?:"
    r"head_ref"
    r"|event\.(?:pull_request|pull_request_target)[\w.]*\.head[\w.]*"
    r")\b",
    re.IGNORECASE,
)

SECRETS_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")

#: References to the workflow run that triggered a ``workflow_run`` consumer.
TRIGGERING_RUN_RE = re.compile(r"github\.event\.workflow_run\b")


def _dump(value: Any) -> str:
    try:
        return yaml.safe_dump(value, default_flow_style=False)
    except yaml.YAMLError:  # pragma: no cover - defensive
        return str(value)


def references_triggering_run(step_raw: dict[str, Any], job: dict[str, Any]) -> bool:
    """True when a step fetches data from the run that triggered this workflow.

    Artifact downloads that do not reference the triggering run (for example
    ``download-artifact`` by ``artifact-ids`` within the same run) stay inside
    one trust boundary and are not part of a cross-workflow chain.
    """
    if TRIGGERING_RUN_RE.search(_dump(step_raw)):
        return True
    return bool(TRIGGERING_RUN_RE.search(_dump(job.get("env", {}))))


@dataclass
class Step:
    """A single workflow step."""

    name: str
    raw: dict[str, Any]

    @property
    def uses(self) -> str:
        return str(self.raw.get("uses", ""))

    @property
    def run(self) -> str:
        return str(self.raw.get("run", ""))

    @property
    def text(self) -> str:
        """Everything in the step an agent could read or obey."""
        with_block = self.raw.get("with", {})
        try:
            with_text = yaml.safe_dump(with_block, default_flow_style=False)
        except yaml.YAMLError:  # pragma: no cover - defensive
            with_text = str(with_block)
        return "\n".join([self.uses, self.run, with_text])


@dataclass
class Workflow:
    """A parsed workflow file."""

    path: Path
    raw: dict[str, Any]

    @property
    def events(self) -> frozenset[str]:
        return parse_events(self.raw)

    @property
    def untrusted(self) -> bool:
        return bool(self.events & UNTRUSTED_EVENTS)

    @property
    def untrusted_artifact_source(self) -> bool:
        """True when an attacker can influence what this workflow uploads."""
        return bool(self.events & ARTIFACT_SOURCE_EVENTS)

    @property
    def jobs(self) -> dict[str, dict[str, Any]]:
        jobs = self.raw.get("jobs")
        return jobs if isinstance(jobs, dict) else {}


def parse_events(raw: dict[str, Any]) -> frozenset[str]:
    """Normalize the ``on:`` block. PyYAML may parse the key as boolean True."""
    on_block = raw.get("on", raw.get(True))
    if on_block is None:
        return frozenset()
    if isinstance(on_block, str):
        return frozenset({on_block})
    if isinstance(on_block, list):
        return frozenset(str(item) for item in on_block)
    if isinstance(on_block, dict):
        return frozenset(str(key) for key in on_block)
    return frozenset()


def is_agent_step(step: Step) -> bool:
    if any(re.search(pattern, step.uses, re.IGNORECASE) for pattern in AGENT_ACTION_PATTERNS):
        return True
    return any(re.search(pattern, step.run) for pattern in AGENT_RUN_PATTERNS)


def all_steps(job: dict[str, Any]) -> list[Step]:
    steps = job.get("steps") if isinstance(job, dict) else None
    if not isinstance(steps, list):
        return []
    result: list[Step] = []
    for item in steps:
        if not isinstance(item, dict):
            continue
        label = str(item.get("name") or item.get("uses") or "step")
        result.append(Step(name=label, raw=item))
    return result


def agent_steps(job: dict[str, Any]) -> list[Step]:
    return [step for step in all_steps(job) if is_agent_step(step)]


def steps_using(job: dict[str, Any], action: str) -> list[Step]:
    """Steps that invoke a given action (matched by ``uses:`` prefix)."""
    return [step for step in all_steps(job) if step.uses.startswith(action)]


def workflow_run_filters(raw: dict[str, Any]) -> list[str] | None:
    """Workflow names a ``workflow_run`` trigger listens to.

    Returns ``None`` when the workflow has no ``workflow_run`` trigger and an
    empty list when it listens without a ``workflows`` filter.
    """
    on_block = raw.get("on", raw.get(True))
    if not isinstance(on_block, dict):
        return None
    trigger = on_block.get("workflow_run")
    if trigger is None:
        return None
    if isinstance(trigger, dict):
        names = trigger.get("workflows")
        if isinstance(names, list):
            return [str(name) for name in names]
    return []


def secrets_in_job(job: dict[str, Any]) -> set[str]:
    try:
        text = yaml.safe_dump(job, default_flow_style=False)
    except yaml.YAMLError:  # pragma: no cover - defensive
        text = str(job)
    return set(SECRETS_RE.findall(text))


def secrets_in_scope(workflow_raw: dict[str, Any], job: dict[str, Any]) -> set[str]:
    """Secrets reachable by the job: job/step scope plus workflow-level ``env:``."""
    names = secrets_in_job(job)
    try:
        env_text = yaml.safe_dump(workflow_raw.get("env", {}), default_flow_style=False)
    except yaml.YAMLError:  # pragma: no cover - defensive
        env_text = str(workflow_raw.get("env", {}))
    names |= set(SECRETS_RE.findall(env_text))
    return names


def untrusted_ref_hits(text: str) -> list[str]:
    return sorted({match.group(0) for match in UNTRUSTED_REF_RE.finditer(text)})


def write_scopes(workflow_raw: dict[str, Any], job: dict[str, Any]) -> list[str]:
    """Return explicitly granted ``write`` permission scopes (job over workflow)."""
    perms = job.get("permissions", workflow_raw.get("permissions"))
    if perms is None:
        return []
    if isinstance(perms, str):
        return ["write-all"] if perms.strip() == "write-all" else []
    if isinstance(perms, dict):
        return sorted(str(key) for key, value in perms.items() if str(value).lower() == "write")
    return []


def untrusted_context_hits(text: str) -> list[str]:
    return sorted({match.group(0) for match in UNTRUSTED_CONTEXT_RE.finditer(text)})


def untrusted_context_hits_in(value: Any) -> list[str]:
    """Untrusted event references nested inside a mapping (``env:`` blocks)."""
    try:
        text = yaml.safe_dump(value, default_flow_style=False)
    except yaml.YAMLError:  # pragma: no cover - defensive
        text = str(value)
    return untrusted_context_hits(text)


def job_guards(job: dict[str, Any]) -> list[str]:
    """Job-level ``if:`` guards that restrict who can trigger the job."""
    condition = str(job.get("if", ""))
    if not condition:
        return []
    return [label for label, pattern in GUARD_PATTERNS if pattern.search(condition)]


def load_workflow(path: Path) -> Workflow | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    return Workflow(path=path, raw=data)
