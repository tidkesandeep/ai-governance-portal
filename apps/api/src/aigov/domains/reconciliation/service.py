from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

HIGH_DRIFT_CODES = frozenset(
    {
        "ASSET_VERSION_MISMATCH",
        "FINGERPRINT_MISMATCH",
        "UNAUTHORIZED_RUNTIME",
        "ENVIRONMENT_MISMATCH",
    }
)

RECONCILIATION_STATUSES = frozenset({"IN_SYNC", "DRIFT", "UNKNOWN"})


class ObservationRuleError(Exception):
    def __init__(self, detail: str, code: str = "OBSERVATION_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True)
class DesiredState:
    authorized: bool
    asset_version_id: str
    environment: str
    fingerprint: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "assetVersionId": self.asset_version_id,
            "environment": self.environment,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class ObservedState:
    running: bool
    asset_version_id: str
    environment: str
    cloud: str
    region: str | None
    fingerprint: str | None
    observed_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "assetVersionId": self.asset_version_id,
            "environment": self.environment,
            "cloud": self.cloud,
            "region": self.region,
            "fingerprint": self.fingerprint,
            "observedAt": as_utc(self.observed_at).isoformat(),
        }


@dataclass(frozen=True)
class ReconciliationOutcome:
    status: str
    reasons: list[dict[str, str]]
    desired: dict[str, Any]
    observed: dict[str, Any] | None

    @property
    def high_drift(self) -> bool:
        return any(
            item.get("code") in HIGH_DRIFT_CODES and item.get("severity") == "HIGH"
            for item in self.reasons
        )


def desired_from_snapshot(
    snapshot: Any | None,
    *,
    current_version_id: str,
    environment: str,
) -> DesiredState:
    authorized = (
        snapshot is not None
        and getattr(snapshot, "outcome", None) == "ALLOW"
        and getattr(snapshot, "asset_version_id", None) == current_version_id
    )
    snap_env = environment
    fingerprint = None
    if snapshot is not None:
        payload = getattr(snapshot, "snapshot", None) or {}
        if isinstance(payload, dict) and payload.get("environment"):
            snap_env = str(payload["environment"])
        if authorized:
            fingerprint = getattr(snapshot, "fingerprint", None)
    return DesiredState(
        authorized=bool(authorized),
        asset_version_id=current_version_id,
        environment=snap_env,
        fingerprint=fingerprint,
    )


def validate_observation(*, asset_version_id: str, environment: str) -> None:
    if not asset_version_id or not str(asset_version_id).strip():
        raise ObservationRuleError("assetVersionId is required")
    if not environment or not str(environment).strip():
        raise ObservationRuleError("environment is required")


def reconcile(
    *,
    desired: DesiredState,
    observed: ObservedState | None,
    now: datetime,
    max_age_seconds: int,
    high_risk: bool,
) -> ReconciliationOutcome:
    desired_dict = desired.as_dict()
    if observed is None:
        return ReconciliationOutcome(
            status="UNKNOWN",
            reasons=[],
            desired=desired_dict,
            observed=None,
        )
    age = (as_utc(now) - as_utc(observed.observed_at)).total_seconds()
    if age >= max_age_seconds:
        severity = "HIGH" if high_risk else "MEDIUM"
        return ReconciliationOutcome(
            status="UNKNOWN",
            reasons=[
                {
                    "code": "STALE_OBSERVATION",
                    "severity": severity,
                    "message": "runtime observation is stale relative to the freshness window",
                }
            ],
            desired=desired_dict,
            observed=observed.as_dict(),
        )
    reasons: list[dict[str, str]] = []
    if observed.running and not desired.authorized:
        reasons.append(
            {
                "code": "UNAUTHORIZED_RUNTIME",
                "severity": "HIGH",
                "message": "the runtime is operating without a current deployment authorization",
            }
        )
    if observed.asset_version_id != desired.asset_version_id:
        reasons.append(
            {
                "code": "ASSET_VERSION_MISMATCH",
                "severity": "HIGH",
                "message": "observed asset version is not the authorized version",
            }
        )
    if observed.environment != desired.environment:
        reasons.append(
            {
                "code": "ENVIRONMENT_MISMATCH",
                "severity": "HIGH",
                "message": "observed environment is not the authorized environment",
            }
        )
    if desired.fingerprint and observed.fingerprint != desired.fingerprint:
        reasons.append(
            {
                "code": "FINGERPRINT_MISMATCH",
                "severity": "HIGH",
                "message": "observed fingerprint does not match the authorized fingerprint",
            }
        )
    return ReconciliationOutcome(
        status="DRIFT" if reasons else "IN_SYNC",
        reasons=reasons,
        desired=desired_dict,
        observed=observed.as_dict(),
    )


def reconciliation_to_policy_document(result: ReconciliationOutcome) -> dict[str, Any]:
    return {
        "status": result.status,
        "reasons": result.reasons,
        "high_drift": result.high_drift,
    }


def reconciliation_fingerprint_record(result: ReconciliationOutcome) -> dict[str, Any]:
    return {
        "status": result.status,
        "reasons": sorted(item.get("code", "") for item in result.reasons),
        "highDrift": result.high_drift,
    }
