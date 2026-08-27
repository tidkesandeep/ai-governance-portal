from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def digest_payload(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def governance_fingerprint(parts: dict[str, Any]) -> str:
    return digest_payload(parts)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_timestamp(value: datetime) -> str:
    return as_utc(value).isoformat()


def build_snapshot_parts(
    *,
    asset_version_id: str,
    environment: str,
    risk: dict[str, Any],
    controls: list[dict[str, Any]],
    evidence_hashes: list[str],
    approvals: dict[str, bool],
    policy_bundle: str,
    policy_digest: str | None,
    engine_versions: dict[str, str],
) -> dict[str, Any]:
    return {
        "assetVersionId": asset_version_id,
        "environment": environment,
        "riskDigest": digest_payload(risk),
        "controlDigest": digest_payload({"controls": controls}),
        "evidenceDigest": digest_payload({"hashes": sorted(evidence_hashes)}),
        "approvalDigest": digest_payload(approvals),
        "policyBundle": policy_bundle,
        "policyDigest": policy_digest,
        "engineVersions": engine_versions,
    }


def sign_authorization(
    *,
    secret: str,
    authorization_id: str,
    fingerprint: str,
    nonce: str,
    expires_at: datetime,
) -> str:
    message = f"{authorization_id}|{fingerprint}|{nonce}|{canonical_timestamp(expires_at)}"
    digest = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def signature_is_valid(
    *,
    secret: str,
    authorization_id: str,
    fingerprint: str,
    nonce: str,
    expires_at: datetime,
    signature: str,
) -> bool:
    expected = sign_authorization(
        secret=secret,
        authorization_id=authorization_id,
        fingerprint=fingerprint,
        nonce=nonce,
        expires_at=expires_at,
    )
    return hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class AuthorizationCheck:
    outcome: Literal["ALLOW", "DENY"]
    reasons: list[str]


def evaluate_authorization(
    *,
    secret: str,
    authorization_id: str,
    fingerprint: str,
    nonce: str,
    expires_at: datetime,
    signature: str,
    presented_signature: str | None,
    now: datetime,
    revoked_at: datetime | None,
    consumed_at: datetime | None,
    bound_version_id: str,
    current_version_id: str,
) -> AuthorizationCheck:
    reasons: list[str] = []
    if presented_signature is not None and not hmac.compare_digest(presented_signature, signature):
        reasons.append("INVALID_SIGNATURE")
    if not signature_is_valid(
        secret=secret,
        authorization_id=authorization_id,
        fingerprint=fingerprint,
        nonce=nonce,
        expires_at=expires_at,
        signature=signature,
    ):
        if "INVALID_SIGNATURE" not in reasons:
            reasons.append("INVALID_SIGNATURE")
    if as_utc(now) >= as_utc(expires_at):
        reasons.append("EXPIRED")
    if revoked_at is not None:
        reasons.append("REVOKED")
    if consumed_at is not None:
        reasons.append("CONSUMED")
    if bound_version_id != current_version_id:
        reasons.append("ASSET_VERSION_MISMATCH")
    return AuthorizationCheck(outcome="DENY" if reasons else "ALLOW", reasons=reasons)
