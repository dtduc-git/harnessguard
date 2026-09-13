import json
from pathlib import Path

from harnessguard.engine import scan
from harnessguard.models import Severity
from harnessguard.report import to_sarif
from harnessguard.rules import load_rules

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EXPECTED_VULNERABLE = {"HG001", "HG002", "HG003", "HG004", "HG005", "HG006", "HG007"}


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


def test_pull_request_target_finding_reported() -> None:
    result = _scan("vulnerable-repo")
    assert any(f.rule_id == "HG004" for f in result.findings)


def test_clean_fixture_still_scans_workflows() -> None:
    result = _scan("clean-repo")
    assert result.workflows_scanned == 3


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


def test_trusted_artifact_producer_not_flagged() -> None:
    result = _scan("clean-repo")
    assert not [f for f in result.findings if f.rule_id == "HG007"]


def test_sarif_contains_rules_and_results() -> None:
    result = _scan("vulnerable-repo")
    sarif = to_sarif(result)
    json.dumps(sarif)
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert EXPECTED_VULNERABLE <= rule_ids
    assert run["results"]
    assert all(result_["level"] in {"error", "warning", "note"} for result_ in run["results"])
