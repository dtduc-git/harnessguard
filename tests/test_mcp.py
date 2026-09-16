"""End-to-end tests for the stdio MCP server."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

GENERATED_WORKFLOW = """
name: generated-review
on:
  issue_comment:
    types: [created]

permissions:
  contents: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Review: ${{ github.event.comment.body }}"
"""


def _call_server(requests: list[dict]) -> dict[int, dict]:
    payload = "\n".join(json.dumps(request) for request in requests) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "harnessguard", "mcp"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    responses = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            message = json.loads(line)
            responses[message["id"]] = message
    return responses


def test_mcp_server_tool_roundtrip() -> None:
    responses = _call_server(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "test"}},
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "scan_workflow",
                    "arguments": {"yaml": GENERATED_WORKFLOW, "path": "generated.yml"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "scan_repository",
                    "arguments": {"path": str(FIXTURES / "vulnerable-repo")},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "list_rules", "arguments": {}},
            },
            {"jsonrpc": "2.0", "id": 6, "method": "bogus/method"},
        ]
    )

    assert responses[1]["result"]["serverInfo"]["name"] == "harnessguard"
    tools = {tool["name"] for tool in responses[2]["result"]["tools"]}
    assert {"scan_repository", "scan_workflow", "list_rules"} <= tools

    generated = responses[3]["result"]
    assert generated["isError"] is False
    text = generated["content"][0]["text"]
    assert "HG001" in text
    assert "Remediation:" in text

    repository = responses[4]["result"]["content"][0]["text"]
    assert "HG001" in repository
    assert "HG008" in repository

    rules = responses[5]["result"]["content"][0]["text"]
    assert "HG010" in rules

    assert responses[6]["error"]["code"] == -32601


def test_mcp_server_reports_tool_errors() -> None:
    responses = _call_server(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_workflow", "arguments": {"yaml": "just a string"}},
            }
        ]
    )
    result = responses[1]["result"]
    assert result["isError"] is True
    assert "error" in result["content"][0]["text"]
