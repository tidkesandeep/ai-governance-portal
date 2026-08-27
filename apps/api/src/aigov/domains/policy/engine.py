from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

POLICY_BUNDLE = "payments-baseline@0.4.0"
POLICY_DIGEST = "sha256:slice5-payments-baseline-0.4.0"

NON_WAIVABLE = frozenset(
    {
        "EVIDENCE_HASH_FAILURE",
        "MISSING_ASSESSMENT",
        "POLICY_ENGINE_UNAVAILABLE",
        "RUNTIME_INCIDENT",
    }
)


@dataclass(frozen=True)
class PolicyReason:
    code: str
    severity: str
    message: str


@dataclass(frozen=True)
class PolicyEvaluation:
    outcome: str
    reasons: list[PolicyReason]
    required_actions: list[str]
    policy_bundle: str = POLICY_BUNDLE
    policy_digest: str = POLICY_DIGEST


ACTIONS = {
    "MISSING_SECURITY_APPROVAL": "complete security review",
    "MISSING_PRIVACY_APPROVAL": "complete privacy review",
    "MISSING_HUMAN_OVERSIGHT": "attach human oversight controls",
    "MISSING_RISK_APPROVAL": "complete risk review",
    "STALE_EVIDENCE": "refresh evaluation evidence",
    "LOW_CONFIDENCE": "supply missing risk attributes and reassess",
    "MISSING_ASSESSMENT": "run risk assessment",
    "MISSING_REQUIRED_EVIDENCE": "attach required evidence for the current asset version",
    "EVIDENCE_HASH_FAILURE": "re-upload evidence; stored digest does not match bytes",
    "RUNTIME_INCIDENT": "resolve the open incident and re-evaluate the deployment gate",
}


class PolicyEngine(Protocol):
    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation: ...


def evaluate_deployment_document(document: dict[str, Any]) -> PolicyEvaluation:
    """Embedded evaluator. Must stay aligned with policies/rego/deployment.rego."""
    reasons: list[PolicyReason] = []
    asset = document.get("asset") or {}
    approvals = document.get("approvals") or {}
    oversight = (document.get("human_oversight") or {}).get("controls") or []
    risk = document.get("risk") or {}
    evidence = document.get("evidence") or {}

    band = asset.get("risk_band")
    high_risk = band in {"HIGH", "CRITICAL"}
    sensitive = asset.get("data_classification") in {"PII", "PCI", "RESTRICTED"}

    if not risk.get("band"):
        reasons.append(
            PolicyReason(
                "MISSING_ASSESSMENT",
                "HIGH",
                "deployment gate requires a current risk assessment",
            )
        )
    if high_risk and not approvals.get("security"):
        reasons.append(
            PolicyReason(
                "MISSING_SECURITY_APPROVAL",
                "HIGH",
                "security approval required for HIGH or CRITICAL risk AI systems",
            )
        )
    if sensitive and not approvals.get("privacy"):
        reasons.append(
            PolicyReason(
                "MISSING_PRIVACY_APPROVAL",
                "HIGH",
                "privacy approval required for PII or PCI processing",
            )
        )
    if asset.get("autonomy_level") == "AUTONOMOUS" and len(oversight) == 0:
        reasons.append(
            PolicyReason(
                "MISSING_HUMAN_OVERSIGHT",
                "HIGH",
                "autonomous systems require human oversight controls",
            )
        )
    if high_risk and asset.get("uses_customer_decision") and not approvals.get("risk"):
        reasons.append(
            PolicyReason(
                "MISSING_RISK_APPROVAL",
                "HIGH",
                "risk approval required for HIGH or CRITICAL customer-decision systems",
            )
        )
    if evidence.get("stale") is True:
        reasons.append(
            PolicyReason(
                "STALE_EVIDENCE",
                "HIGH" if high_risk else "MEDIUM",
                "evidence is stale relative to the control freshness policy",
            )
        )
    for control in evidence.get("controls") or []:
        status = control.get("status")
        required = control.get("required", True)
        if not required:
            continue
        if status == "UNKNOWN":
            reasons.append(
                PolicyReason(
                    "MISSING_REQUIRED_EVIDENCE",
                    "HIGH",
                    "unknown evidence cannot satisfy a mandatory control",
                )
            )
            break
        if status == "FAIL":
            reasons.append(
                PolicyReason(
                    "EVIDENCE_HASH_FAILURE",
                    "HIGH",
                    "evidence hash verification failed",
                )
            )
            break
        if status == "STALE" and high_risk:
            if not any(reason.code == "STALE_EVIDENCE" for reason in reasons):
                reasons.append(
                    PolicyReason(
                        "STALE_EVIDENCE",
                        "HIGH",
                        "stale evidence cannot satisfy a HIGH or CRITICAL control",
                    )
                )
    confidence = risk.get("confidence")
    if confidence is not None and confidence < 0.7:
        reasons.append(
            PolicyReason(
                "LOW_CONFIDENCE",
                "MEDIUM",
                "risk confidence is below the automated-gate threshold",
            )
        )
    if any((item or {}).get("status") == "OPEN" for item in document.get("incidents") or []):
        reasons.append(
            PolicyReason(
                "RUNTIME_INCIDENT",
                "HIGH",
                "an open runtime incident revokes deployment authorization",
            )
        )

    waived = _waived_codes(document)
    reasons = [reason for reason in reasons if reason.code not in waived]

    if any(reason.severity == "HIGH" for reason in reasons):
        outcome = "BLOCK"
    elif reasons:
        outcome = "REVIEW"
    else:
        outcome = "ALLOW"

    actions = [ACTIONS[reason.code] for reason in reasons if reason.code in ACTIONS]
    return PolicyEvaluation(outcome=outcome, reasons=reasons, required_actions=actions)


def _waived_codes(document: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    for exception in document.get("exceptions") or []:
        if exception.get("status") != "GRANTED" or exception.get("expired"):
            continue
        code = exception.get("violation_code")
        if code and code not in NON_WAIVABLE:
            codes.add(code)
    return codes


class EmbeddedPolicyEngine:
    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation:
        return evaluate_deployment_document(document)
