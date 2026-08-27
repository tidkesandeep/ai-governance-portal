import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.domains.findings.service import (
    FindingRuleError,
    auto_promotes,
    incident_fingerprint_records,
    validate_finding,
)
from aigov.domains.policy.engine import NON_WAIVABLE
from aigov.main import create_app
from tests.test_api import allow_fraud, auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/findings.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_finding_rules_reject_unknown_type_and_short_summary() -> None:
    validate_finding(
        finding_type="EVAL_REGRESSION",
        severity="CRITICAL",
        summary="holdout recall dropped below the production floor",
    )
    assert auto_promotes("CRITICAL")
    assert auto_promotes("HIGH")
    assert not auto_promotes("MEDIUM")
    try:
        validate_finding(finding_type="UNKNOWN", severity="HIGH", summary="long enough")
        raise AssertionError("expected FindingRuleError")
    except FindingRuleError:
        pass
    try:
        validate_finding(finding_type="DATA_DRIFT", severity="LOW", summary="short")
        raise AssertionError("expected FindingRuleError")
    except FindingRuleError:
        pass


def test_incident_fingerprint_includes_only_open_rows() -> None:
    class Row:
        def __init__(self, ident: str, status: str) -> None:
            self.id = ident
            self.severity = "HIGH"
            self.status = status

    records = incident_fingerprint_records([Row("inc_b", "OPEN"), Row("inc_a", "RESOLVED")])
    assert records == [{"id": "inc_b", "severity": "HIGH", "status": "OPEN"}]


def test_critical_finding_revokes_authorization_and_blocks_gate(client) -> None:
    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    recorded = client.post(
        f"/v1/ai-systems/{system_id}/findings",
        json={
            "findingType": "EVAL_REGRESSION",
            "severity": "CRITICAL",
            "summary": "holdout recall dropped below the production floor",
            "detector": "eval-monitor",
        },
        headers=auth("demo"),
    )
    assert recorded.status_code == 201, recorded.text
    body = recorded.json()
    assert body["system"]["status"] == "BLOCKED"
    assert body["findings"][0]["status"] == "PROMOTED"
    assert body["incidents"][0]["status"] == "OPEN"
    assert body["latestIncident"]["status"] == "OPEN"
    assert body["latestAuthorization"]["revokedAt"]
    assert body["latestCase"]["caseType"] == "INCIDENT"
    assert body["latestCase"]["status"] == "OPEN"

    denied = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert denied.json()["outcome"] == "DENY"
    assert "REVOKED" in denied.json()["reasons"]

    blocked = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert blocked.json()["outcome"] == "BLOCK"
    codes = {reason["code"] for reason in blocked.json()["reasons"]}
    assert "RUNTIME_INCIDENT" in codes
    snapshot = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo")).json()
    assert "incidentDigest" in snapshot["latestSnapshot"]["snapshot"]

    refused = client.post(
        f"/v1/ai-systems/{system_id}/exceptions",
        json={
            "violationCode": "RUNTIME_INCIDENT",
            "justification": "cannot waive an open runtime incident",
        },
        headers=auth("demo"),
    )
    assert refused.status_code == 422
    assert refused.json()["code"] == "EXCEPTION_NOT_WAIVABLE"
    assert "RUNTIME_INCIDENT" in NON_WAIVABLE

    incident_id = body["incidents"][0]["id"]
    sod = client.post(
        f"/v1/ai-systems/{system_id}/incidents/{incident_id}/resolve",
        headers=auth("demo"),
    )
    assert sod.status_code == 409
    assert sod.json()["code"] == "SOD_VIOLATION"

    resolved = client.post(
        f"/v1/ai-systems/{system_id}/incidents/{incident_id}/resolve",
        headers=auth("demo-reviewer"),
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["incidents"][0]["status"] == "RESOLVED"
    assert resolved.json()["findings"][0]["status"] == "RESOLVED"
    assert resolved.json()["latestAuthorization"]["revokedAt"]

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.json()["outcome"] == "ALLOW"
    assert allowed.json()["authorizationId"]
    assert allowed.json()["authorizationId"] != auth_id


def test_medium_finding_stays_open_until_promoted_or_dismissed(client) -> None:
    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    recorded = client.post(
        f"/v1/ai-systems/{system_id}/findings",
        json={
            "findingType": "DATA_DRIFT",
            "severity": "MEDIUM",
            "summary": "feature distribution shifted on the live scoring window",
        },
        headers=auth("demo"),
    )
    assert recorded.status_code == 201, recorded.text
    finding_id = recorded.json()["findings"][0]["id"]
    assert recorded.json()["findings"][0]["status"] == "OPEN"
    assert recorded.json()["incidents"] == []
    assert recorded.json()["latestAuthorization"]["revokedAt"] is None

    still_valid = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert still_valid.json()["outcome"] == "ALLOW"

    sod = client.post(
        f"/v1/ai-systems/{system_id}/findings/{finding_id}/promote",
        headers=auth("demo"),
    )
    assert sod.status_code == 409

    promoted = client.post(
        f"/v1/ai-systems/{system_id}/findings/{finding_id}/promote",
        headers=auth("demo-reviewer"),
    )
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["findings"][0]["status"] == "PROMOTED"
    assert promoted.json()["incidents"][0]["status"] == "OPEN"
    assert promoted.json()["latestAuthorization"]["revokedAt"]

    system_id, _ = allow_fraud(client)
    dismissed_record = client.post(
        f"/v1/ai-systems/{system_id}/findings",
        json={
            "findingType": "HUMAN_REPORT",
            "severity": "LOW",
            "summary": "operator reported a benign scoring glitch",
        },
        headers=auth("demo"),
    )
    dismissed_id = dismissed_record.json()["findings"][0]["id"]
    dismissed = client.post(
        f"/v1/ai-systems/{system_id}/findings/{dismissed_id}/dismiss",
        headers=auth("demo-reviewer"),
    )
    assert dismissed.status_code == 200
    assert dismissed.json()["findings"][0]["status"] == "DISMISSED"
    assert dismissed.json()["incidents"] == []


def test_invalid_finding_is_rejected(client) -> None:
    system_id, _ = allow_fraud(client)
    response = client.post(
        f"/v1/ai-systems/{system_id}/findings",
        json={
            "findingType": "EVAL_REGRESSION",
            "severity": "CRITICAL",
            "summary": "short",
        },
        headers=auth("demo"),
    )
    assert response.status_code == 422
