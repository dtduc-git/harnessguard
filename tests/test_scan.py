import json
from dataclasses import replace
from pathlib import Path

from typer.testing import CliRunner

from harnessguard.cli import app, load_baseline
from harnessguard.engine import scan
from harnessguard.models import Severity
from harnessguard.report import fingerprint, to_json, to_sarif
from harnessguard.rules import load_rules

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EXPECTED_VULNERABLE = {
    "HG001",
    "HG002",
    "HG003",
    "HG004",
    "HG005",
    "HG006",
    "HG007",
    "HG008",
    "HG009",
    "HG010",
}


def _scan(name: str):
    return scan([FIXTURES / name], load_rules())


def test_vulnerable_fixture_triggers_expected_rules() -> None:
    result = _scan("vulnerable-repo")
    ids = {finding.rule_id for finding in result.findings}
    missing = EXPECTED_VULNERABLE - ids
    assert not missing, f"missing expected findings: {sorted(missing)}"


def test_clean_fixture_has_no_findings() -> None:
    result = _scan("clean-repo")
    assert result.findings == [], [f.to_dict() for f in result.findings]


def test_secret_finding_names_credentials() -> None:
    result = _scan("vulnerable-repo")
    secrets = [f for f in result.findings if f.rule_id == "HG001"]
    assert secrets
    assert "secrets.ANTHROPIC_API_KEY" in secrets[0].message


def test_untrusted_context_finding_lists_fields() -> None:
    result = _scan("vulnerable-repo")
    contexts = [f for f in result.findings if f.rule_id == "HG002"]
    assert any("github.event.issue.body" in f.message for f in contexts)


def test_untrusted_context_via_job_env_detected() -> None:
    result = _scan("vulnerable-repo")
    env_findings = [
        f
        for f in result.findings
        if f.rule_id == "HG002" and f.workflow.name == "env-scope.yml"
    ]
    assert env_findings, "job-level env untrusted context not detected"
    assert "job-level env" in env_findings[0].message
    assert "github.event.issue.title" in env_findings[0].message


def test_pull_request_target_finding_reported() -> None:
    result = _scan("vulnerable-repo")
    assert any(f.rule_id == "HG004" for f in result.findings)


def test_clean_fixture_still_scans_workflows() -> None:
    result = _scan("clean-repo")
    assert result.workflows_scanned == 8


def test_guarded_job_downgrades_privilege_findings() -> None:
    result = _scan("vulnerable-repo")
    guarded = [f for f in result.findings if f.workflow.name == "guarded.yml"]
    by_rule = {f.rule_id: f.severity for f in guarded}
    assert by_rule["HG001"] == Severity.HIGH  # critical, downgraded one level
    assert by_rule["HG003"] == Severity.MEDIUM  # high, downgraded one level
    assert "guard" in next(f for f in guarded if f.rule_id == "HG001").message
    unguarded = [
        f for f in result.findings if f.workflow.name == "triage.yml" and f.rule_id == "HG001"
    ]
    assert unguarded[0].severity == Severity.CRITICAL


def test_workflow_level_env_secret_detected() -> None:
    result = _scan("vulnerable-repo")
    env_findings = [
        f
        for f in result.findings
        if f.workflow.name == "workflow-env.yml" and f.rule_id == "HG001"
    ]
    assert env_findings, "workflow-level env secret not detected"
    assert "secrets.AGENT_API_KEY" in env_findings[0].message


def test_untrusted_checkout_ref_finding_reported() -> None:
    result = _scan("vulnerable-repo")
    refs = [
        f
        for f in result.findings
        if f.rule_id == "HG006" and f.workflow.name == "checkout-ref.yml"
    ]
    assert refs
    assert "github.event.pull_request.head.ref" in refs[0].message


def test_artifact_trust_chain_flagged() -> None:
    result = _scan("vulnerable-repo")
    consumers = [
        f
        for f in result.findings
        if f.rule_id == "HG007" and f.workflow.name == "artifact-consumer.yml"
    ]
    assert consumers
    finding = consumers[0]
    assert finding.severity == Severity.HIGH
    assert "artifact-producer" in finding.message
    assert "pull_request" in finding.message
    assert "secrets.DEPLOY_KEY" in finding.message
    assert "contents: write" in finding.message


def test_artifact_consumer_with_environment_is_downgraded() -> None:
    result = _scan("vulnerable-repo")
    guarded = [
        f
        for f in result.findings
        if f.rule_id == "HG007" and f.workflow.name == "artifact-consumer-guarded.yml"
    ]
    assert guarded
    assert guarded[0].severity == Severity.MEDIUM
    assert "environment" in guarded[0].message


def test_same_run_artifact_download_not_flagged() -> None:
    result = _scan("vulnerable-repo")
    same_run = [f for f in result.findings if f.workflow.name == "artifact-consumer-same-run.yml"]
    assert not same_run, [f.to_dict() for f in same_run]


def test_trusted_artifact_producer_not_flagged() -> None:
    result = _scan("clean-repo")
    assert not [f for f in result.findings if f.rule_id == "HG007"]


def test_agent_consuming_untrusted_artifact_flagged() -> None:
    result = _scan("vulnerable-repo")
    consumers = [
        f
        for f in result.findings
        if f.rule_id == "HG009" and f.workflow.name == "artifact-agent-consumer.yml"
    ]
    assert consumers, "agent consuming untrusted artifact not detected"
    assert "artifact-producer" in consumers[0].message
    assert "pull_request" in consumers[0].message


def test_reusable_workflow_secret_chain_flagged() -> None:
    result = _scan("vulnerable-repo")
    chains = [
        f
        for f in result.findings
        if f.rule_id == "HG008" and f.workflow.name == "reusable-caller.yml"
    ]
    assert chains, "untrusted caller passing secrets into agent callee not detected"
    assert chains[0].severity == Severity.HIGH
    assert "secrets: inherit" in chains[0].message
    assert "reusable-agent.yml" in chains[0].message


def test_trusted_reusable_caller_not_flagged() -> None:
    result = _scan("clean-repo")
    assert not [f for f in result.findings if f.rule_id == "HG008"]


def test_dollar_prefix_reusable_caller_flagged() -> None:
    result = _scan("vulnerable-repo")
    chains = [
        f
        for f in result.findings
        if f.rule_id == "HG008" and f.workflow.name == "reusable-dollar-caller.yml"
    ]
    assert chains, "$/ reusable workflow reference not resolved"
    assert "reusable-agent.yml" in chains[0].message


def test_indirectly_guarded_reusable_caller_downgraded() -> None:
    result = _scan("vulnerable-repo")
    chains = [
        f
        for f in result.findings
        if f.rule_id == "HG008" and f.workflow.name == "reusable-guarded-caller.yml"
    ]
    assert chains, "guarded reusable chain not detected"
    assert chains[0].severity == Severity.MEDIUM
    assert "needs: gate" in chains[0].message


def test_unpinned_mcp_servers_flagged() -> None:
    result = _scan("vulnerable-repo")
    mcp = [f for f in result.findings if f.rule_id == "HG010"]
    assert mcp, "unpinned MCP server not detected"
    message = mcp[0].message
    assert "ols-mcp" in message
    assert "mcp-remote" in message
    assert "plaintext HTTP MCP endpoint" in message


def test_pinned_and_loopback_mcp_not_flagged() -> None:
    result = _scan("clean-repo")
    assert not [f for f in result.findings if f.rule_id == "HG010"]


def test_cursor_agent_cli_detected() -> None:
    from harnessguard.facts import Step, is_agent_step

    assert is_agent_step(Step(name="run", raw={"run": 'cursor-agent -p "$(cat prompt.txt)"'}))
    assert not is_agent_step(Step(name="run", raw={"run": "cursor-agent models"}))


def test_scoped_mcp_packages_detected_with_pin_state() -> None:
    from harnessguard.facts import mcp_launch_packages, mcp_unpinned

    pinned = (
        'claude_args: \'--mcp-config {"mcpServers": {"fs": {"command": "npx", '
        '"args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"]}}}\''
    )
    packages = mcp_launch_packages(pinned)
    assert packages == ["@modelcontextprotocol/server-filesystem@0.6.2"]
    assert mcp_unpinned(packages[0]) is False

    unpinned = (
        'claude_args: \'--mcp-config {"mcpServers": {"think": {"command": "npx", '
        '"args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]}}}\''
    )
    packages = mcp_launch_packages(unpinned)
    assert packages == ["@modelcontextprotocol/server-sequential-thinking"]
    assert mcp_unpinned(packages[0]) is True


def test_mcp_tool_permission_tokens_ignored() -> None:
    from harnessguard.facts import mcp_launch_packages

    text = 'allowed_tools: "Bash(npx *) mcp__sequential-thinking__sequentialthinking"'
    assert mcp_launch_packages(text) == []


def test_secretless_agent_callee_not_flagged() -> None:
    result = _scan("clean-repo")
    chains = [f for f in result.findings if f.workflow.name == "reusable-open-caller.yml"]
    assert not chains, [f.to_dict() for f in chains]


def test_sarif_contains_rules_and_results() -> None:
    result = _scan("vulnerable-repo")
    sarif = to_sarif(result)
    json.dumps(sarif)
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert EXPECTED_VULNERABLE <= rule_ids
    assert run["results"]
    assert all(result_["level"] in {"error", "warning", "note"} for result_ in run["results"])
    assert all("partialFingerprints" in result_ for result_ in run["results"])


def test_fingerprint_ignores_message_wording() -> None:
    result = _scan("vulnerable-repo")
    finding = result.findings[0]
    clone = replace(finding, message="rewritten", severity=Severity.LOW)
    assert fingerprint(clone, result.root) == fingerprint(finding, result.root)


def test_baseline_json_roundtrip(tmp_path) -> None:
    result = _scan("vulnerable-repo")
    document = to_json(result)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(document), encoding="utf-8")
    known = load_baseline(baseline)
    assert known == {entry["fingerprint"] for entry in document["findings"]}
    assert all(fingerprint(finding, result.root) in known for finding in result.findings)


def test_cli_baseline_suppresses_existing_findings(tmp_path) -> None:
    runner = CliRunner()
    fixture = str(FIXTURES / "vulnerable-repo")
    args = ["scan", fixture, "--fail-on", "none", "--format", "json"]
    first = runner.invoke(app, args, env={"COLUMNS": "400"})
    assert first.exit_code == 0
    baseline = tmp_path / "baseline.json"
    baseline.write_text(first.stdout, encoding="utf-8")
    second = runner.invoke(app, [*args, "--baseline", str(baseline)], env={"COLUMNS": "400"})
    assert second.exit_code == 0
    document = json.loads(second.stdout)
    assert document["findings"] == []
    assert document["baseline_suppressed"] > 0
