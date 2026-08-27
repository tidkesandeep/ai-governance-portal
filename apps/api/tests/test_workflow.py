from datetime import UTC, datetime, timedelta

import pytest

from aigov.domains.policy.engine import NON_WAIVABLE
from aigov.domains.workflow.service import (
    ExceptionRuleError,
    compute_due_at,
    compute_sla_status,
    exception_is_active,
    max_exception_days,
    sla_hours,
    validate_exception_request,
)


def test_high_risk_sla_is_24_hours() -> None:
    opened = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    due = compute_due_at(opened, "HIGH")
    assert sla_hours("HIGH") == 24
    assert due == opened + timedelta(hours=24)
    assert compute_sla_status(opened, due, opened + timedelta(hours=1)) == "ON_TRACK"
    assert compute_sla_status(opened, due, opened + timedelta(hours=20)) == "DUE_SOON"
    assert compute_sla_status(opened, due, due) == "OVERDUE"


def test_critical_sla_is_8_hours() -> None:
    assert sla_hours("CRITICAL") == 8
    assert max_exception_days("CRITICAL") == 7
    assert max_exception_days("HIGH") == 14


def test_exception_request_rejects_non_waivable_and_past_expiry() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    with pytest.raises(ExceptionRuleError) as rejected:
        validate_exception_request(
            violation_code="EVIDENCE_HASH_FAILURE",
            justification="need a hotfix window",
            expires_at=now + timedelta(days=1),
            now=now,
            risk_band="HIGH",
        )
    assert rejected.value.code == "EXCEPTION_NOT_WAIVABLE"
    assert "EVIDENCE_HASH_FAILURE" in NON_WAIVABLE
    assert "RUNTIME_INCIDENT" in NON_WAIVABLE
    assert "RUNTIME_DRIFT" in NON_WAIVABLE
    with pytest.raises(ExceptionRuleError):
        validate_exception_request(
            violation_code="MISSING_REQUIRED_EVIDENCE",
            justification="short",
            expires_at=now + timedelta(days=1),
            now=now,
            risk_band="HIGH",
        )
    with pytest.raises(ExceptionRuleError):
        validate_exception_request(
            violation_code="MISSING_REQUIRED_EVIDENCE",
            justification="hotfix window for eval refresh",
            expires_at=now,
            now=now,
            risk_band="HIGH",
        )
    with pytest.raises(ExceptionRuleError):
        validate_exception_request(
            violation_code="MISSING_REQUIRED_EVIDENCE",
            justification="hotfix window for eval refresh",
            expires_at=now + timedelta(days=30),
            now=now,
            risk_band="HIGH",
        )


def test_exception_is_active_only_when_granted_unexpired_and_version_bound() -> None:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    expires = now + timedelta(days=7)
    assert exception_is_active(
        status="GRANTED",
        expires_at=expires,
        bound_version_id="ver_1",
        current_version_id="ver_1",
        now=now,
    )
    assert not exception_is_active(
        status="REQUESTED",
        expires_at=expires,
        bound_version_id="ver_1",
        current_version_id="ver_1",
        now=now,
    )
    assert not exception_is_active(
        status="GRANTED",
        expires_at=now,
        bound_version_id="ver_1",
        current_version_id="ver_1",
        now=now,
    )
    assert not exception_is_active(
        status="GRANTED",
        expires_at=expires,
        bound_version_id="ver_1",
        current_version_id="ver_2",
        now=now,
    )
