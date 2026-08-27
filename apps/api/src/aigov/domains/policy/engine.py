from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

POLICY_BUNDLE = "payments-baseline@0.1.0"
POLICY_DIGEST = "sha256:slice1-payments-baseline-0.1.0"


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
}


class PolicyEngine(Protocol):
    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation: ...


def evaluate_deployment_document(document: dict[str, Any]) -> PolicyEvaluation:
    """Embedded Slice-1 evaluator. Must stay aligned with policies/rego/deployment.rego."""
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
                "MEDIUM",
                "evidence is stale relative to the control freshness policy",
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

    if any(reason.severity == "HIGH" for reason in reasons):
        outcome = "BLOCK"
    elif reasons:
        outcome = "REVIEW"
    else:
        outcome = "ALLOW"

    actions = [ACTIONS[reason.code] for reason in reasons if reason.code in ACTIONS]
    return PolicyEvaluation(outcome=outcome, reasons=reasons, required_actions=actions)


class EmbeddedPolicyEngine:
    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation:
        return evaluate_deployment_document(document)
