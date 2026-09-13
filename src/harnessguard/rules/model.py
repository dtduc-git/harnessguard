"""Rule metadata model. Rules are data (YAML); checks are code."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..models import Severity


class Rule(BaseModel):
    id: str
    title: str
    severity: Severity
    check: str
    owasp: str = ""
    description: str = ""
    remediation: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
