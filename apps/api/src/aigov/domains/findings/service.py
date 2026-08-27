from __future__ import annotations

from typing import Any

FINDING_TYPES = frozenset(
    {
        "EVAL_REGRESSION",
        "FAIRNESS_DRIFT",
        "SECURITY_SIGNAL",
        "DATA_DRIFT",
        "POLICY_VIOLATION",
        "HUMAN_REPORT",
    }
)

FINDING_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
AUTO_PROMOTE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


class FindingRuleError(Exception):
    def __init__(self, detail: str, code: str = "FINDING_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


def validate_finding(*, finding_type: str, severity: str, summary: str) -> None:
    if finding_type not in FINDING_TYPES:
        raise FindingRuleError(f"unsupported finding type {finding_type}")
    if severity not in FINDING_SEVERITIES:
        raise FindingRuleError(f"unsupported severity {severity}")
    if not summary or len(summary.strip()) < 8:
        raise FindingRuleError("summary must be at least 8 characters")


def auto_promotes(severity: str) -> bool:
    return severity in AUTO_PROMOTE_SEVERITIES


def incident_title(finding_type: str, severity: str) -> str:
    return f"{finding_type} ({severity})"


def open_incidents_to_policy_document(rows: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "status": row.status,
            "severity": row.severity,
            "title": row.title,
        }
        for row in rows
        if row.status == "OPEN"
    ]


def incident_fingerprint_records(rows: list[Any]) -> list[dict[str, Any]]:
    records = [
        {"id": row.id, "severity": row.severity, "status": row.status}
        for row in rows
        if row.status == "OPEN"
    ]
    return sorted(records, key=lambda item: item["id"])
