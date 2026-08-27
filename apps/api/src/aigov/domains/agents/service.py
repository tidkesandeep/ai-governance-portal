from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")

PRIVILEGED_ACTIONS = frozenset(
    {
        "payments.refund",
        "payments.transfer",
        "payments.payout",
        "code.execute",
        "secrets.read",
        "email.send",
        "account.close",
    }
)


class CapabilityRuleError(Exception):
    def __init__(self, detail: str, code: str = "CAPABILITY_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


@dataclass(frozen=True)
class CapabilityMatch:
    capability: Any | None
    resource_match: bool
    undeclared: bool


def is_privileged(action: str) -> bool:
    if action in PRIVILEGED_ACTIONS:
        return True
    prefix = action.split(".", 1)[0]
    return prefix in {"payments", "secrets", "code"}


def validate_capability(
    *,
    action: str,
    resource_pattern: str,
    max_amount: float | None,
    requires_approval: bool,
) -> bool:
    if not ACTION_PATTERN.match(action):
        raise CapabilityRuleError("action must be a dotted lowercase identifier")
    pattern = resource_pattern.strip()
    if len(pattern) < 3:
        raise CapabilityRuleError("resource pattern must be at least 3 characters")
    if pattern.replace("*", "") == "":
        raise CapabilityRuleError("resource pattern cannot be a bare wildcard")
    if max_amount is not None and max_amount < 0:
        raise CapabilityRuleError("max amount cannot be negative")
    privileged = is_privileged(action)
    if privileged and not requires_approval:
        raise CapabilityRuleError(
            "privileged actions always require reviewer approval",
            "PRIVILEGED_REQUIRES_APPROVAL",
        )
    return privileged


def resource_permitted(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource, pattern)


def select_capability(
    rows: list[Any], *, action: str, resource: str, version_id: str
) -> CapabilityMatch:
    candidates = [
        row
        for row in rows
        if row.action == action and row.revoked_at is None and row.bound_version_id == version_id
    ]
    if not candidates:
        return CapabilityMatch(capability=None, resource_match=False, undeclared=True)
    matching = [row for row in candidates if resource_permitted(row.resource_pattern, resource)]
    if not matching:
        best = max(candidates, key=lambda row: len(row.resource_pattern))
        return CapabilityMatch(capability=best, resource_match=False, undeclared=False)
    best = max(matching, key=lambda row: len(row.resource_pattern))
    return CapabilityMatch(capability=best, resource_match=True, undeclared=False)


def capability_to_policy_document(
    match: CapabilityMatch, *, current_version_id: str
) -> dict[str, Any] | None:
    row = match.capability
    if row is None:
        return None
    return {
        "id": row.id,
        "action": row.action,
        "resource_pattern": row.resource_pattern,
        "resource_match": match.resource_match,
        "bound_version_id": row.bound_version_id,
        "version_match": row.bound_version_id == current_version_id,
        "max_amount": row.max_amount,
        "requires_approval": bool(row.requires_approval),
        "approved": bool(row.approved),
        "privileged": is_privileged(row.action),
    }


def capability_fingerprint_records(rows: list[Any]) -> list[dict[str, Any]]:
    records = [
        {
            "id": row.id,
            "action": row.action,
            "resourcePattern": row.resource_pattern,
            "maxAmount": row.max_amount,
            "approved": bool(row.approved),
            "boundVersionId": row.bound_version_id,
        }
        for row in rows
        if row.revoked_at is None
    ]
    return sorted(records, key=lambda item: item["id"])
