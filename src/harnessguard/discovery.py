"""Discover GitHub Actions workflow files under the given paths."""

from __future__ import annotations

from pathlib import Path

WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def discover(paths: list[Path]) -> list[Path]:
    """Find workflow YAML files.

    Accepts a workflow file, a repository root (searches
    ``.github/workflows/``), or a workflows directory directly.
    """
    found: set[Path] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            if path.suffix in WORKFLOW_SUFFIXES:
                found.add(path)
            continue
        if not path.is_dir():
            continue
        if path.name == "workflows" and path.parent.name == ".github":
            candidates = [path]
        else:
            candidates = [path / ".github" / "workflows"]
        for directory in candidates:
            if not directory.is_dir():
                continue
            for candidate in directory.iterdir():
                if candidate.is_file() and candidate.suffix in WORKFLOW_SUFFIXES:
                    found.add(candidate)
    return sorted(found)


def root_of(paths: list[Path]) -> Path:
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            return path.resolve()
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            return path.resolve().parent
    return Path.cwd()
