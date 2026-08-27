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
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.status_code == 200
    assert allowed.json()["outcome"] == "ALLOW"

    events = client.get(f"/v1/ai-systems/{system_id}/audit-events", headers=auth("demo"))
    assert events.status_code == 200
    types = [item["eventType"] for item in events.json()["items"]]
    assert types[0] == "AISystemRegistered"
    assert "RiskAssessmentCompleted" in types
    assert "DeploymentGateEvaluated" in types
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


def test_unauthorized(client: TestClient) -> None:
    response = client.get("/v1/ai-systems")
    assert response.status_code == 401
