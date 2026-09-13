"""Core data models for harnessguard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def weaken(self) -> Severity:
        """One level less severe (INFO stays INFO)."""
        return _SEVERITY_ORDER[min(self.rank + 1, len(_SEVERITY_ORDER) - 1)]


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_from(value: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError as exc:
        raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass
class Finding:
    """One security finding produced by a rule."""

    rule_id: str
    severity: Severity
    title: str
    message: str
    workflow: Path
    job: str = ""
    step: str = ""
    line: int | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "title": self.title,
            "message": self.message,
            "workflow": str(self.workflow),
            "job": self.job,
            "step": self.step,
            "line": self.line,
        }


@dataclass
class ScanResult:
    """Aggregate result of scanning one or more workflow trees."""

    root: Path
    findings: list[Finding] = field(default_factory=list)
    workflows_scanned: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {str(s): 0 for s in Severity}
        for finding in self.findings:
            counts[str(finding.severity)] += 1
        return counts

    def has_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity.rank <= threshold.rank for f in self.findings)
