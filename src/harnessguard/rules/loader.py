"""Load rule definitions from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import Rule


def builtin_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules_data"


def load_rules(extra_dirs: list[Path] | None = None) -> list[Rule]:
    """Load builtin rules, then overlay any user-provided rule directories.

    YAML files without an ``id`` key are data files, not rules, and are skipped.
    """
    rules: dict[str, Rule] = {}
    directories = [builtin_rules_dir(), *(extra_dirs or [])]
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "id" not in data:
                continue
            rule = Rule.model_validate(data)
            rules[rule.id] = rule
    return sorted(rules.values(), key=lambda r: r.id)
