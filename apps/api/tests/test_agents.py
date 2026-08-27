import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.domains.agents.service import (
    CapabilityRuleError,
    resource_permitted,
    select_capability,
    validate_capability,
)
from aigov.main import create_app
from tests.test_api import attach_required_evidence, auth

AGENT = {
    "name": "Refund concierge agent",
    "systemType": "AGENT",
    "businessPurpose": "Issue retail payment refunds within a declared ceiling",
    "owner": "payments-ops",
    "environment": "production",
    "dataClassification": "PII",
    "geography": "EU",
    "autonomyLevel": "SEMI_AUTONOMOUS",
    "customerImpact": "HIGH",
    "financialImpact": "HIGH",
    "usesCustomerDecision": True,
    "monitoringEnabled": True,
    "evaluationRefs": ["eval_refund_agent"],
    "humanOversight": ["refund_queue"],
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/agents.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def allow_agent(client: TestClient) -> str:
    created = client.post("/v1/ai-systems", json=AGENT, headers=auth("demo"))
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
    return system_id


def test_resource_pattern_and_privileged_rules() -> None:
    assert resource_permitted("account:retail-*", "account:retail-123")
    assert not resource_permitted("account:retail-*", "account:wholesale-1")
    validate_capability(
        action="crm.read",
        resource_pattern="customer:*",
        max_amount=None,
        requires_approval=False,
    )
    with pytest.raises(CapabilityRuleError) as rejected:
        validate_capability(
            action="payments.refund",
            resource_pattern="account:retail-*",
            max_amount=500,
            requires_approval=False,
        )
    assert rejected.value.code == "PRIVILEGED_REQUIRES_APPROVAL"
    with pytest.raises(CapabilityRuleError):
        validate_capability(
            action="crm.read",
            resource_pattern="*",
            max_amount=None,
            requires_approval=False,
        )


def test_select_capability_prefers_longer_matching_pattern() -> None:
    class Row:
        def __init__(self, ident: str, pattern: str) -> None:
            self.id = ident
            self.action = "crm.read"
            self.resource_pattern = pattern
            self.revoked_at = None
            self.bound_version_id = "ver_1"

    match = select_capability(
        [Row("cap_wide", "customer:*"), Row("cap_narrow", "customer:eu-*")],
        action="crm.read",
        resource="customer:eu-99",
        version_id="ver_1",
    )
    assert match.resource_match
    assert match.capability.id == "cap_narrow"


def test_agent_action_allow_deny_and_runtime_revoke(client: TestClient) -> None:
    system_id = allow_agent(client)
    refused_model = client.post(
        "/v1/ai-systems",
        json={**AGENT, "name": "Fraud Risk Model v4.2", "systemType": "PREDICTIVE_MODEL"},
        headers=auth("demo"),
    )
    model_id = refused_model.json()["system"]["id"]
    not_agent = client.post(
        f"/v1/ai-systems/{model_id}/capabilities",
        json={"action": "crm.read", "resourcePattern": "customer:*"},
        headers=auth("demo"),
    )
    assert not_agent.status_code == 422
    assert not_agent.json()["code"] == "NOT_AN_AGENT"

    refund = client.post(
        f"/v1/ai-systems/{system_id}/capabilities",
        json={
            "action": "payments.refund",
            "resourcePattern": "account:retail-*",
            "maxAmount": 500,
            "requiresApproval": True,
        },
        headers=auth("demo"),
    )
    assert refund.status_code == 201, refund.text
    refund_id = next(
        item["id"] for item in refund.json()["capabilities"] if item["action"] == "payments.refund"
    )
    assert refund.json()["capabilities"][0]["requiresApproval"] is True
    assert refund.json()["capabilities"][0]["approved"] is False

    crm = client.post(
        f"/v1/ai-systems/{system_id}/capabilities",
        json={"action": "crm.read", "resourcePattern": "customer:*"},
        headers=auth("demo"),
    )
    assert crm.status_code == 201
    assert any(
        item["action"] == "crm.read" and item["approved"] for item in crm.json()["capabilities"]
    )

    pending = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
        headers=auth("demo"),
    )
    assert pending.json()["outcome"] == "DENY"
    assert "MISSING_ACTION_APPROVAL" in {reason["code"] for reason in pending.json()["reasons"]}

    sod = client.post(
        f"/v1/ai-systems/{system_id}/capabilities/{refund_id}/approve",
        headers=auth("demo"),
    )
    assert sod.status_code == 409

    approved = client.post(
        f"/v1/ai-systems/{system_id}/capabilities/{refund_id}/approve",
        headers=auth("demo-reviewer"),
    )
    assert approved.status_code == 200, approved.text
    assert any(
        item["id"] == refund_id and item["approved"] for item in approved.json()["capabilities"]
    )

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
        headers=auth("demo"),
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["outcome"] == "ALLOW"
    assert allowed.json()["authorizationId"]
    actz_id = allowed.json()["authorizationId"]

    verified = client.post(
        f"/v1/ai-systems/{system_id}/action-authorizations/{actz_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert verified.json()["outcome"] == "ALLOW"

    wholesale = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "payments.refund", "resource": "account:wholesale-1", "amount": 50},
        headers=auth("demo"),
    )
    assert wholesale.json()["outcome"] == "DENY"
    assert "RESOURCE_NOT_PERMITTED" in {reason["code"] for reason in wholesale.json()["reasons"]}

    undeclared = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "ledger.write", "resource": "ledger:core"},
        headers=auth("demo"),
    )
    assert undeclared.json()["outcome"] == "DENY"
    assert "UNDECLARED_ACTION" in {reason["code"] for reason in undeclared.json()["reasons"]}

    over = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "payments.refund", "resource": "account:retail-123", "amount": 5000},
        headers=auth("demo"),
    )
    assert "AMOUNT_EXCEEDS_LIMIT" in {reason["code"] for reason in over.json()["reasons"]}

    finding = client.post(
        f"/v1/ai-systems/{system_id}/findings",
        json={
            "findingType": "EVAL_REGRESSION",
            "severity": "CRITICAL",
            "summary": "refund agent holdout quality collapsed",
        },
        headers=auth("demo"),
    )
    assert finding.status_code == 201
    denied = client.post(
        f"/v1/ai-systems/{system_id}/action-authorizations/{actz_id}/verify",
        json={},
        headers=auth("demo"),
    )
    assert denied.json()["outcome"] == "DENY"
    assert "REVOKED" in denied.json()["reasons"]

    blocked = client.post(
        f"/v1/ai-systems/{system_id}/actions/authorize",
        json={"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
        headers=auth("demo"),
    )
    codes = {reason["code"] for reason in blocked.json()["reasons"]}
    assert blocked.json()["outcome"] == "DENY"
    assert "RUNTIME_INCIDENT" in codes
    assert blocked.json()["authorizationId"] is None
