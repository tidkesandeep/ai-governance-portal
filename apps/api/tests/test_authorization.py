from datetime import UTC, datetime, timedelta

from aigov.domains.authorization.service import (
    build_action_snapshot_parts,
    build_snapshot_parts,
    evaluate_authorization,
    governance_fingerprint,
    sign_authorization,
    signature_is_valid,
)

PARTS = dict(
    asset_version_id="ver_1",
    environment="production",
    risk={"band": "HIGH", "score": 70.7},
    controls=[{"controlId": "CTRL-ML-PERF-001", "status": "PASS"}],
    evidence_hashes=["sha256:aaa", "sha256:bbb"],
    approvals={"privacy": True, "security": True, "risk": True},
    policy_bundle="payments-baseline@0.2.0",
    policy_digest="sha256:policy",
    engine_versions={"risk": "risk-engine@2.0.0", "policy": "payments-baseline@0.2.0"},
)


def test_fingerprint_is_stable_and_version_sensitive() -> None:
    first = build_snapshot_parts(**PARTS)
    second = build_snapshot_parts(**PARTS)
    assert first == second
    assert governance_fingerprint(first) == governance_fingerprint(second)
    changed = build_snapshot_parts(**{**PARTS, "asset_version_id": "ver_2"})
    assert governance_fingerprint(changed) != governance_fingerprint(first)
    with_incident = build_snapshot_parts(
        **{**PARTS, "incidents": [{"id": "inc_1", "severity": "CRITICAL", "status": "OPEN"}]}
    )
    assert "incidentDigest" in first
    with_recon = build_snapshot_parts(
        **{**PARTS, "reconciliation": {"status": "DRIFT", "reasons": ["ASSET_VERSION_MISMATCH"]}}
    )
    assert "reconciliationDigest" in first
    assert governance_fingerprint(with_recon) != governance_fingerprint(first)
    assert governance_fingerprint(with_incident) != governance_fingerprint(first)
    action_first = build_action_snapshot_parts(
        asset_version_id="ver_1",
        action="payments.refund",
        resource="account:retail-123",
        amount=50,
        capability={"action": "payments.refund", "resource_match": True},
        deploy_authorized=True,
        policy_bundle="agent-actions@0.1.0",
        policy_digest="sha256:policy",
    )
    action_changed = build_action_snapshot_parts(
        asset_version_id="ver_1",
        action="payments.refund",
        resource="account:wholesale-1",
        amount=50,
        capability={"action": "payments.refund", "resource_match": False},
        deploy_authorized=True,
        policy_bundle="agent-actions@0.1.0",
        policy_digest="sha256:policy",
    )
    assert governance_fingerprint(action_first) != governance_fingerprint(action_changed)


def test_hmac_round_trip_and_tamper() -> None:
    expires = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    signature = sign_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires,
    )
    assert signature.startswith("hmac-sha256:")
    assert signature_is_valid(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires,
        signature=signature,
    )
    flipped = signature[:-1] + ("0" if signature[-1] != "0" else "1")
    assert not signature_is_valid(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires,
        signature=flipped,
    )


def test_evaluate_authorization_deny_reasons() -> None:
    expires = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    signature = sign_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires,
    )
    expired = evaluate_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires,
        signature=signature,
        presented_signature=None,
        now=expires,
        revoked_at=None,
        consumed_at=None,
        bound_version_id="ver_1",
        current_version_id="ver_1",
    )
    assert expired.outcome == "DENY"
    assert expired.reasons == ["EXPIRED"]

    allowed = evaluate_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=expires + timedelta(minutes=15),
        signature=signature,
        presented_signature=signature,
        now=expires,
        revoked_at=None,
        consumed_at=None,
        bound_version_id="ver_1",
        current_version_id="ver_1",
    )
    # signature was computed for the original expires_at, so this presented
    # signature will not match the recomputed HMAC for the later expiry.
    assert allowed.outcome == "DENY"
    assert "INVALID_SIGNATURE" in allowed.reasons

    valid_expires = expires + timedelta(minutes=15)
    valid_signature = sign_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=valid_expires,
    )
    ok = evaluate_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=valid_expires,
        signature=valid_signature,
        presented_signature=valid_signature,
        now=expires,
        revoked_at=None,
        consumed_at=None,
        bound_version_id="ver_1",
        current_version_id="ver_1",
    )
    assert ok.outcome == "ALLOW"
    assert ok.reasons == []

    mismatch = evaluate_authorization(
        secret="dev-secret",
        authorization_id="authz_1",
        fingerprint="sha256:abc",
        nonce="nce_1",
        expires_at=valid_expires,
        signature=valid_signature,
        presented_signature="hmac-sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        now=expires,
        revoked_at=expires,
        consumed_at=expires,
        bound_version_id="ver_1",
        current_version_id="ver_2",
    )
    assert mismatch.outcome == "DENY"
    assert mismatch.reasons == [
        "INVALID_SIGNATURE",
        "REVOKED",
        "CONSUMED",
        "ASSET_VERSION_MISMATCH",
    ]
