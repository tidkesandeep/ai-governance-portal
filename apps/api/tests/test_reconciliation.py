from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.domains.policy.engine import NON_WAIVABLE
from aigov.domains.reconciliation.service import (
    DesiredState,
    ObservationRuleError,
    ObservedState,
    desired_from_snapshot,
    reconcile,
    validate_observation,
)
from aigov.main import create_app
from tests.test_api import allow_fraud, auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/reconciliation.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_no_observation_is_unknown_and_does_not_block() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    desired = DesiredState(
        authorized=True,
        asset_version_id="ver_1",
        environment="production",
        fingerprint="sha256:abc",
    )
    result = reconcile(
        desired=desired,
        observed=None,
        now=now,
        max_age_seconds=900,
        high_risk=True,
    )
    assert result.status == "UNKNOWN"
    assert result.reasons == []
    assert not result.high_drift


def test_matching_observation_is_in_sync() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    desired = DesiredState(
        authorized=True,
        asset_version_id="ver_1",
        environment="production",
        fingerprint="sha256:abc",
    )
    result = reconcile(
        desired=desired,
        observed=ObservedState(
            running=True,
            asset_version_id="ver_1",
            environment="production",
            cloud="local",
            region=None,
            fingerprint="sha256:abc",
            observed_at=now,
        ),
        now=now,
        max_age_seconds=900,
        high_risk=True,
    )
    assert result.status == "IN_SYNC"
    assert result.reasons == []


def test_version_mismatch_and_unauthorized_runtime_are_high_drift() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    mismatch = reconcile(
        desired=DesiredState(
            authorized=True,
            asset_version_id="ver_1",
            environment="production",
            fingerprint="sha256:abc",
        ),
        observed=ObservedState(
            running=True,
            asset_version_id="ver_other",
            environment="production",
            cloud="local",
            region=None,
            fingerprint="sha256:abc",
            observed_at=now,
        ),
        now=now,
        max_age_seconds=900,
        high_risk=True,
    )
    assert mismatch.status == "DRIFT"
    assert mismatch.high_drift
    assert any(item["code"] == "ASSET_VERSION_MISMATCH" for item in mismatch.reasons)
    unauthorized = reconcile(
        desired=DesiredState(
            authorized=False,
            asset_version_id="ver_1",
            environment="production",
            fingerprint=None,
        ),
        observed=ObservedState(
            running=True,
            asset_version_id="ver_1",
            environment="production",
            cloud="local",
            region=None,
            fingerprint=None,
            observed_at=now,
        ),
        now=now,
        max_age_seconds=900,
        high_risk=False,
    )
    assert any(item["code"] == "UNAUTHORIZED_RUNTIME" for item in unauthorized.reasons)


def test_stale_observation_is_unknown_and_high_when_high_risk() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    result = reconcile(
        desired=DesiredState(
            authorized=True,
            asset_version_id="ver_1",
            environment="production",
            fingerprint="sha256:abc",
        ),
        observed=ObservedState(
            running=True,
            asset_version_id="ver_1",
            environment="production",
            cloud="local",
            region=None,
            fingerprint="sha256:abc",
            observed_at=now - timedelta(seconds=900),
        ),
        now=now,
        max_age_seconds=900,
        high_risk=True,
    )
    assert result.status == "UNKNOWN"
    assert not result.high_drift
    assert result.reasons[0]["code"] == "STALE_OBSERVATION"
    assert result.reasons[0]["severity"] == "HIGH"


def test_desired_from_snapshot_requires_allow_on_current_version() -> None:
    class Snapshot:
        outcome = "BLOCK"
        asset_version_id = "ver_1"
        fingerprint = "sha256:abc"
        snapshot = {"environment": "production"}

    desired = desired_from_snapshot(
        Snapshot(),
        current_version_id="ver_1",
        environment="production",
    )
    assert desired.authorized is False
    assert desired.fingerprint is None
    try:
        validate_observation(asset_version_id="", environment="production")
        raise AssertionError("expected ObservationRuleError")
    except ObservationRuleError:
        pass


def test_in_sync_then_drift_revokes_and_re_gate_allows(client) -> None:
    system_id, decision = allow_fraud(client)
    auth_id = decision["authorizationId"]
    snapshot = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo")).json()
    assert snapshot["latestReconciliation"]["status"] == "UNKNOWN"
    assert snapshot["latestObservation"] is None

    in_sync = client.post(
        f"/v1/ai-systems/{system_id}/observations",
        json={},
        headers=auth("demo"),
    )
    assert in_sync.status_code == 201, in_sync.text
    body = in_sync.json()
    assert body["latestReconciliation"]["status"] == "IN_SYNC"
    assert body["system"]["status"] == "APPROVED"
    assert body["latestAuthorization"]["revokedAt"] is None

    drifted = client.post(
        f"/v1/ai-systems/{system_id}/observations",
        json={"assetVersionId": "ver_not_authorized"},
        headers=auth("demo"),
    )
    assert drifted.status_code == 201, drifted.text
    drifted_body = drifted.json()
    assert drifted_body["system"]["status"] == "BLOCKED"
    assert drifted_body["latestReconciliation"]["status"] == "DRIFT"
    reason_codes = {item["code"] for item in drifted_body["latestReconciliation"]["reasons"]}
    assert "ASSET_VERSION_MISMATCH" in reason_codes
    assert drifted_body["latestAuthorization"]["revokedAt"]
    assert drifted_body["latestCase"]["caseType"] == "RECONCILIATION"

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
    assert "RUNTIME_DRIFT" in codes
    gated = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo")).json()
    assert "reconciliationDigest" in gated["latestSnapshot"]["snapshot"]

    refused = client.post(
        f"/v1/ai-systems/{system_id}/exceptions",
        json={
            "violationCode": "RUNTIME_DRIFT",
            "justification": "cannot waive an unauthorized runtime",
        },
        headers=auth("demo"),
    )
    assert refused.status_code == 422
    assert refused.json()["code"] == "EXCEPTION_NOT_WAIVABLE"
    assert "RUNTIME_DRIFT" in NON_WAIVABLE

    restored = client.post(
        f"/v1/ai-systems/{system_id}/observations",
        json={
            "assetVersionId": body["system"]["currentVersionId"],
            "environment": "production",
            "fingerprint": body["latestSnapshot"]["fingerprint"],
        },
        headers=auth("demo"),
    )
    assert restored.status_code == 201, restored.text
    restored_body = restored.json()
    assert restored_body["latestReconciliation"]["status"] == "IN_SYNC"
    assert restored_body["system"]["status"] == "BLOCKED"
    assert restored_body["latestAuthorization"]["revokedAt"]
    assert restored_body["latestAuthorization"]["id"] == auth_id

    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.json()["outcome"] == "ALLOW"
    assert allowed.json()["authorizationId"]
    assert allowed.json()["authorizationId"] != auth_id


def test_stale_observation_blocks_high_risk_and_is_waivable(client) -> None:
    system_id, _decision = allow_fraud(client)
    stale_at = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
    recorded = client.post(
        f"/v1/ai-systems/{system_id}/observations",
        json={"observedAt": stale_at},
        headers=auth("demo"),
    )
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["latestReconciliation"]["status"] == "UNKNOWN"
    assert recorded.json()["latestReconciliation"]["reasons"][0]["code"] == "STALE_OBSERVATION"
    assert recorded.json()["latestAuthorization"]["revokedAt"] is None

    blocked = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert blocked.json()["outcome"] == "BLOCK"
    codes = {reason["code"] for reason in blocked.json()["reasons"]}
    assert "STALE_OBSERVATION" in codes

    requested = client.post(
        f"/v1/ai-systems/{system_id}/exceptions",
        json={
            "violationCode": "STALE_OBSERVATION",
            "justification": "collector outage during a change freeze",
        },
        headers=auth("demo"),
    )
    assert requested.status_code == 201, requested.text
    exception_id = requested.json()["exceptions"][0]["id"]
    granted = client.post(
        f"/v1/ai-systems/{system_id}/exceptions/{exception_id}/grant",
        headers=auth("demo-reviewer"),
    )
    assert granted.status_code == 200, granted.text
    allowed = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert allowed.json()["outcome"] == "ALLOW"
