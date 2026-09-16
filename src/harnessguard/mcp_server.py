"""Minimal stdio MCP server: lets coding agents lint the workflows they generate.

Implements the MCP 2025-06-18 handshake and tool surface over newline-delimited
JSON-RPC 2.0 on stdin/stdout — no dependencies, no network, no execution.
ponytail: hand-rolled subset (initialize/tools/list/tools/call/ping); swap to
the official mcp SDK if resources, prompts or sampling are ever needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

import yaml

from . import __version__
from .engine import scan, scan_workflow
from .models import ScanResult
from .rules import load_rules
from .rules.model import Rule

PROTOCOL_VERSION = "2025-06-18"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_repository",
        "description": (
            "Scan a repository's .github/workflows for AI-agent CI trust-boundary "
            "risks (Microsoft Agents Rule of Two, OWASP Agentic Top 10). Read-only; "
            "never executes workflows."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repository root to scan (default: current directory)",
                }
            },
        },
    },
    {
        "name": "scan_workflow",
        "description": (
            "Lint a single GitHub Actions workflow YAML string before writing it to "
            "disk. Use this to verify agent workflows you generate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "yaml": {"type": "string", "description": "Workflow YAML content"},
                "path": {
                    "type": "string",
                    "description": "Virtual file name for reporting (default: workflow.yml)",
                },
            },
            "required": ["yaml"],
        },
    },
    {
        "name": "list_rules",
        "description": "List the harnessguard rules: id, severity, OWASP mapping, title.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _render(result: ScanResult, rules: list[Rule]) -> str:
    counts = ", ".join(
        f"{count} {severity}" for severity, count in result.by_severity().items() if count
    )
    lines = [
        f"harnessguard {__version__}: {result.workflows_scanned} workflow(s) scanned, "
        f"{len(result.findings)} finding(s)" + (f" ({counts})" if counts else "")
    ]
    for finding in result.findings:
        lines.append(
            f"- [{finding.severity}] {finding.rule_id} {Path(finding.workflow).name} "
            f"job={finding.job or '-'} step={finding.step or '-'}: {finding.message}"
        )
    remediations = {
        rule.id: rule.remediation.strip()
        for rule in rules
        if rule.remediation and any(f.rule_id == rule.id for f in result.findings)
    }
    if remediations:
        lines.append("Remediation:")
        lines.extend(f"- {rule_id}: {text}" for rule_id, text in sorted(remediations.items()))
    return "\n".join(lines)


def _handle_tool(name: str, arguments: dict[str, Any], rules: list[Rule]) -> str:
    if name == "scan_repository":
        target = Path(str(arguments.get("path", "."))).expanduser()
        return _render(scan([target], rules), rules)
    if name == "scan_workflow":
        content = str(arguments.get("yaml", ""))
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("input is not a workflow YAML mapping")
        label = str(arguments.get("path", "workflow.yml"))
        return _render(scan_workflow(data, rules, name=label), rules)
    if name == "list_rules":
        return "\n".join(
            f"- {rule.id} ({rule.severity}) {rule.title} [{rule.owasp}]" for rule in rules
        )
    raise ValueError(f"unknown tool: {name}")


def _handle(message: dict[str, Any], rules: list[Rule]) -> dict[str, Any] | None:
    request_id = message.get("id")
    if request_id is None:
        return None  # notification
    method = str(message.get("method", ""))
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    try:
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": str(params.get("protocolVersion") or PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "harnessguard", "version": __version__},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            text = _handle_tool(
                str(params.get("name", "")), params.get("arguments") or {}, rules
            )
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        elif method == "ping":
            result = {}
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
    except Exception as exc:  # noqa: BLE001 - surface tool errors to the client
        if method == "tools/call":
            result = {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(exc)},
            }
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Serve newline-delimited JSON-RPC until stdin closes."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    rules = load_rules()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        response = _handle(message, rules)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
