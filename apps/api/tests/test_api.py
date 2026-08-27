from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.main import create_app

FRAUD = {
    "name": "Fraud Risk Model v4.2",
    "systemType": "PREDICTIVE_MODEL",
    "businessPurpose": "Score payment transactions for fraud",
    "owner": "payments-ml",
    "environment": "production",
    "dataClassification": "PII",
    "geography": "EU",
    "autonomyLevel": "ASSISTIVE",
    "customerImpact": "HIGH",
    "financialImpact": "HIGH",
    "usesCustomerDecision": True,
    "modelRefs": ["model:fraud-v4.2"],
}

INTERNAL = {
    "name": "Weekly cohort rollup",
    "systemType": "PREDICTIVE_MODEL",
    "businessPurpose": "Internal analytics",
    "owner": "analytics",
    "environment": "dev",
    "dataClassification": "INTERNAL",
    "geography": "US",
    "autonomyLevel": "HUMAN_IN_LOOP",
    "customerImpact": "LOW",
    "financialImpact": "NONE",
    "evaluationRefs": ["eval_internal"],
    "monitoringEnabled": True,
    "humanOversight": ["analyst_review"],
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def attach_required_evidence(client: TestClient, system_id: str) -> None:
    samples = [
        ("MODEL_CARD", "model-card.md", "# Fraud Risk Model v4.2\nNo raw customer data."),
        ("EVALUATION_RUN", "eval.json", '{"recall": 0.96, "precision": 0.94}'),
        ("FAIRNESS_EVALUATION", "fairness.json", '{"group_gap": 0.02}'),
    ]
    for evidence_type, filename, content in samples:
        response = client.post(
            f"/v1/ai-systems/{system_id}/evidence",
            json={"type": evidence_type, "filename": filename, "content": content},
            headers=auth("demo"),
        )
        assert response.status_code == 201, response.text


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_register_assess_gate_block_then_allow(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=FRAUD, headers=auth("demo"))
    assert created.status_code == 201
    system_id = created.json()["system"]["id"]
    assert created.json()["system"]["status"] == "DRAFT"
    assert created.json()["system"]["urn"].startswith("urn:ai-gov:demo:aisystem:")

    assessed = client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    assert assessed.status_code == 201
    body = assessed.json()
    assert body["riskBand"] in {"HIGH", "CRITICAL"}
    assert body["confidence"] > 0
    assert body["engineVersion"] == "risk-engine@2.0.0"

    blocked = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert blocked.status_code == 200
    decision = blocked.json()
    assert decision["outcome"] == "BLOCK"
    codes = {reason["code"] for reason in decision["reasons"]}
    assert "MISSING_PRIVACY_APPROVAL" in codes
    assert decision["inputDigest"].startswith("sha256:")
    assert decision["fingerprint"].startswith("sha256:")
    assert decision.get("authorizationId") is None
    blocked_view = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
    case = blocked_view.json()["latestCase"]
    assert case["status"] == "OPEN"
    assert case["slaStatus"] == "ON_TRACK"
    assert "MISSING_PRIVACY_APPROVAL" in case["reasonCodes"]

    sod = client.post(
        f"/v1/ai-systems/{system_id}/approvals",
        json={"function": "privacy", "approved": True},
        headers=auth("demo"),
    )
    assert sod.status_code == 409
    assert sod.json()["code"] == "SOD_VIOLATION"

    for function in ("privacy", "security", "risk"):
        approved = client.post(
            f"/v1/ai-systems/{system_id}/approvals",
            json={"function": function, "approved": True},
            headers=auth("demo-reviewer"),
        )
        assert approved.status_code == 201, approved.text

    still_blocked = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert still_blocked.status_code == 200
    assert still_blocked.json()["outcome"] == "BLOCK"
    assert still_blocked.json().get("authorizationId") is None
    assert "MISSING_REQUIRED_EVIDENCE" in {
        reason["code"] for reason in still_blocked.json()["reasons"]
    }

    attach_required_evidence(client, system_id)

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.status_code == 200
    assert allowed.json()["outcome"] == "ALLOW"
    assert allowed.json()["fingerprint"].startswith("sha256:")
    assert allowed.json()["snapshotId"]
    assert allowed.json()["authorizationId"]
    view = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
    assert view.json()["latestSnapshot"]["fingerprint"] == allowed.json()["fingerprint"]
    assert view.json()["latestAuthorization"]["id"] == allowed.json()["authorizationId"]
    assert view.json()["latestCase"]["status"] == "CLOSED"

    events = client.get(f"/v1/ai-systems/{system_id}/audit-events", headers=auth("demo"))
    assert events.status_code == 200
    types = [item["eventType"] for item in events.json()["items"]]
    assert types[0] == "AISystemRegistered"
    assert "RiskAssessmentCompleted" in types
    assert "DeploymentGateEvaluated" in types
    assert "DeploymentAuthorizationIssued" in types
    assert "WorkflowCaseOpened" in types
    assert "WorkflowCaseClosed" in types
    hashes = [item["hash"] for item in events.json()["items"]]
    assert all(item.startswith("sha256:") for item in hashes)
    # hash chain: each event commits to the previous hash
    items = events.json()["items"]
    for index in range(1, len(items)):
        assert items[index]["previousEventHash"] == items[index - 1]["hash"]


def test_stale_evidence_is_review(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=INTERNAL, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    decision = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={"evidenceStale": True},
        headers=auth("demo"),
    )
    assert decision.status_code == 200
    assert decision.json()["outcome"] == "REVIEW"


def test_cross_tenant_is_not_found(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=INTERNAL, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    response = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo-other-tenant"))
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


def test_stale_required_evidence_blocks_high(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=FRAUD, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    for function in ("privacy", "security", "risk"):
        client.post(
            f"/v1/ai-systems/{system_id}/approvals",
            json={"function": function, "approved": True},
            headers=auth("demo-reviewer"),
        )
    client.post(
        f"/v1/ai-systems/{system_id}/evidence",
        json={
            "type": "EVALUATION_RUN",
            "filename": "old-eval.json",
            "content": '{"recall": 0.96}',
            "collectedAt": "2020-01-01T00:00:00Z",
        },
        headers=auth("demo"),
    )
    client.post(
        f"/v1/ai-systems/{system_id}/evidence",
        json={"type": "MODEL_CARD", "filename": "card.md", "content": "# card"},
        headers=auth("demo"),
    )
    client.post(
        f"/v1/ai-systems/{system_id}/evidence",
        json={"type": "FAIRNESS_EVALUATION", "filename": "fair.json", "content": "{}"},
        headers=auth("demo"),
    )
    decision = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert decision.json()["outcome"] == "BLOCK"
    assert "STALE_EVIDENCE" in {reason["code"] for reason in decision.json()["reasons"]}


def test_new_version_unbinds_evidence(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=FRAUD, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    attach_required_evidence(client, system_id)
    before = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
    assert all(item["status"] == "PASS" for item in before.json()["controls"])
    cut = client.post(f"/v1/ai-systems/{system_id}/versions", headers=auth("demo"))
    assert cut.status_code == 201
    statuses = {item["status"] for item in cut.json()["controls"]}
    assert statuses == {"UNKNOWN"}


def test_eicar_upload_is_rejected(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=INTERNAL, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    response = client.post(
        f"/v1/ai-systems/{system_id}/evidence",
        json={
            "type": "MODEL_CARD",
            "filename": "eicar.txt",
            "content": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        },
        headers=auth("demo"),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "EVIDENCE_REJECTED"


def allow_fraud(client: TestClient) -> tuple[str, dict]:
    created = client.post("/v1/ai-systems", json=FRAUD, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    for function in ("privacy", "security", "risk"):
        client.post(
            f"/v1/ai-systems/{system_id}/approvals",
            json={"function": function, "approved": True},
            headers=auth("demo-reviewer"),
        )
    attach_required_evidence(client, system_id)
    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["outcome"] == "ALLOW"
    return system_id, allowed.json()


def test_authorization_verify_revoke_and_consume(client: TestClient) -> None:
    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    verified = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert verified.status_code == 200
    assert verified.json()["outcome"] == "ALLOW"
    assert verified.json()["reasons"] == []

    tampered = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={"signature": "hmac-sha256:" + ("ab" * 32)},
        headers=auth("demo"),
    )
    assert tampered.status_code == 200
    assert tampered.json()["outcome"] == "DENY"
    assert "INVALID_SIGNATURE" in tampered.json()["reasons"]

    consumed = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={"consume": True},
        headers=auth("demo"),
    )
    assert consumed.json()["outcome"] == "ALLOW"
    reused = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert reused.json()["outcome"] == "DENY"
    assert "CONSUMED" in reused.json()["reasons"]

    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    revoked = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/revoke",
        headers=auth("demo"),
    )
    assert revoked.status_code == 200
    assert revoked.json()["revokedAt"]
    denied = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert denied.json()["outcome"] == "DENY"
    assert "REVOKED" in denied.json()["reasons"]


def test_version_cut_revokes_authorization(client: TestClient) -> None:
    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    cut = client.post(f"/v1/ai-systems/{system_id}/versions", headers=auth("demo"))
    assert cut.status_code == 201
    assert cut.json()["latestAuthorization"]["revokedAt"]
    denied = client.post(
        f"/v1/ai-systems/{system_id}/authorizations/{auth_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert denied.json()["outcome"] == "DENY"
    reasons = set(denied.json()["reasons"])
    assert "REVOKED" in reasons
    assert "ASSET_VERSION_MISMATCH" in reasons


def test_zero_ttl_authorization_expires_immediately(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/ttl.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("AIGOV_AUTHORIZATION_TTL_SECONDS", "0")
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        system_id, decision = allow_fraud(test_client)
        denied = test_client.post(
            f"/v1/ai-systems/{system_id}/authorizations/{decision['authorizationId']}/verify",
            json={},
            headers=auth("demo"),
        )
        assert denied.json()["outcome"] == "DENY"
        assert "EXPIRED" in denied.json()["reasons"]
    get_settings.cache_clear()


def test_exception_waives_missing_evidence_then_revoke_blocks(client: TestClient) -> None:
    created = client.post("/v1/ai-systems", json=FRAUD, headers=auth("demo"))
    system_id = created.json()["system"]["id"]
    client.post(f"/v1/ai-systems/{system_id}/assessments", headers=auth("demo"))
    for function in ("privacy", "security", "risk"):
        client.post(
            f"/v1/ai-systems/{system_id}/approvals",
            json={"function": function, "approved": True},
            headers=auth("demo-reviewer"),
        )
    blocked = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert blocked.json()["outcome"] == "BLOCK"
    case = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo")).json()["latestCase"]
    assert case["status"] == "OPEN"
    assert case["slaStatus"] == "ON_TRACK"

    refused = client.post(
        f"/v1/ai-systems/{system_id}/exceptions",
        json={
            "violationCode": "EVIDENCE_HASH_FAILURE",
            "justification": "cannot waive a failed digest",
        },
        headers=auth("demo"),
    )
    assert refused.status_code == 422
    assert refused.json()["code"] == "EXCEPTION_NOT_WAIVABLE"

    requested = client.post(
        f"/v1/ai-systems/{system_id}/exceptions",
        json={
            "violationCode": "MISSING_REQUIRED_EVIDENCE",
            "justification": "hotfix window while evaluation is refreshed",
        },
        headers=auth("demo"),
    )
    assert requested.status_code == 201, requested.text
    exception_id = requested.json()["exceptions"][0]["id"]
    assert requested.json()["exceptions"][0]["status"] == "REQUESTED"

    sod = client.post(
        f"/v1/ai-systems/{system_id}/exceptions/{exception_id}/grant",
        headers=auth("demo"),
    )
    assert sod.status_code == 409
    assert sod.json()["code"] == "SOD_VIOLATION"

    granted = client.post(
        f"/v1/ai-systems/{system_id}/exceptions/{exception_id}/grant",
        headers=auth("demo-reviewer"),
    )
    assert granted.status_code == 200, granted.text
    assert granted.json()["exceptions"][0]["status"] == "GRANTED"

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.json()["outcome"] == "ALLOW"
    assert allowed.json()["authorizationId"]
    view = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
    snapshot = view.json()["latestSnapshot"]
    assert "exceptionDigest" in snapshot["snapshot"]

    revoked = client.post(
        f"/v1/ai-systems/{system_id}/exceptions/{exception_id}/revoke",
        headers=auth("demo-reviewer"),
    )
    assert revoked.status_code == 200
    assert revoked.json()["exceptions"][0]["status"] == "REVOKED"
    assert revoked.json()["latestAuthorization"]["revokedAt"]

    blocked_again = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert blocked_again.json()["outcome"] == "BLOCK"
    assert "MISSING_REQUIRED_EVIDENCE" in {
        reason["code"] for reason in blocked_again.json()["reasons"]
    }


def test_unauthorized(client: TestClient) -> None:
    response = client.get("/v1/ai-systems")
    assert response.status_code == 401
