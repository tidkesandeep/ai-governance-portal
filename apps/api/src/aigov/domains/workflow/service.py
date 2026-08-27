from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from aigov.domains.policy.engine import NON_WAIVABLE

SLA_HOURS = {
    "CRITICAL": 8,
    "HIGH": 24,
    "MEDIUM": 72,
    "LOW": 168,
}

MAX_EXCEPTION_DAYS = {
    "CRITICAL": 7,
    "HIGH": 14,
    "MEDIUM": 30,
    "LOW": 30,
}

DEFAULT_EXCEPTION_DAYS = 7
MIN_JUSTIFICATION = 8


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def sla_hours(risk_band: str | None) -> int:
    return SLA_HOURS.get(risk_band or "LOW", SLA_HOURS["LOW"])


def compute_due_at(opened_at: datetime, risk_band: str | None) -> datetime:
    return as_utc(opened_at) + timedelta(hours=sla_hours(risk_band))


def compute_sla_status(opened_at: datetime, due_at: datetime, now: datetime) -> str:
    opened = as_utc(opened_at)
    due = as_utc(due_at)
    current = as_utc(now)
    if current >= due:
        return "OVERDUE"
    window = due - opened
    remaining = due - current
    if window.total_seconds() > 0 and remaining <= window * 0.25:
        return "DUE_SOON"
    return "ON_TRACK"


def max_exception_days(risk_band: str | None) -> int:
    return MAX_EXCEPTION_DAYS.get(risk_band or "LOW", MAX_EXCEPTION_DAYS["LOW"])


def default_expires_at(now: datetime, risk_band: str | None) -> datetime:
    days = min(DEFAULT_EXCEPTION_DAYS, max_exception_days(risk_band))
    return as_utc(now) + timedelta(days=days)


class ExceptionRuleError(Exception):
    def __init__(self, detail: str, code: str = "EXCEPTION_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


def validate_exception_request(
    *,
    violation_code: str,
    justification: str,
    expires_at: datetime,
    now: datetime,
    risk_band: str | None,
) -> None:
    if violation_code in NON_WAIVABLE:
        raise ExceptionRuleError(
            f"{violation_code} cannot be waived",
            "EXCEPTION_NOT_WAIVABLE",
        )
    if not justification or len(justification.strip()) < MIN_JUSTIFICATION:
        raise ExceptionRuleError("justification must be at least 8 characters")
    expiry = as_utc(expires_at)
    current = as_utc(now)
    if expiry <= current:
        raise ExceptionRuleError("exception expiry must be in the future")
    limit = current + timedelta(days=max_exception_days(risk_band))
    if expiry > limit:
        raise ExceptionRuleError(
            f"exception cannot exceed {max_exception_days(risk_band)} days "
            f"for {risk_band or 'LOW'} risk"
        )


def exception_is_active(
    *,
    status: str,
    expires_at: datetime,
    bound_version_id: str,
    current_version_id: str,
    now: datetime,
) -> bool:
    if status != "GRANTED":
        return False
    if bound_version_id != current_version_id:
        return False
    return as_utc(now) < as_utc(expires_at)


def exceptions_to_policy_document(
    rows: list[Any],
    *,
    current_version_id: str,
    now: datetime,
) -> list[dict[str, Any]]:
    document: list[dict[str, Any]] = []
    for row in rows:
        active = exception_is_active(
            status=row.status,
            expires_at=row.expires_at,
            bound_version_id=row.bound_version_id,
            current_version_id=current_version_id,
            now=now,
        )
        document.append(
            {
                "id": row.id,
                "violation_code": row.violation_code,
                "control_id": row.control_id,
                "status": "GRANTED" if active else row.status,
                "expired": not active,
                "bound_version_id": row.bound_version_id,
            }
        )
    return document


def exception_fingerprint_records(
    rows: list[Any], *, current_version_id: str, now: datetime
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in rows:
        if not exception_is_active(
            status=row.status,
            expires_at=row.expires_at,
            bound_version_id=row.bound_version_id,
            current_version_id=current_version_id,
            now=now,
        ):
            continue
        records.append(
            {
                "id": row.id,
                "violationCode": row.violation_code,
                "boundVersionId": row.bound_version_id,
                "expiresAt": as_utc(row.expires_at).isoformat(),
            }
        )
    return sorted(records, key=lambda item: item["id"])
