from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

POLICY_BUNDLE = "payments-baseline@0.5.0"
POLICY_DIGEST = "sha256:slice7-payments-baseline-0.5.0"

NON_WAIVABLE = frozenset(
    {
        "EVIDENCE_HASH_FAILURE",
        "MISSING_ASSESSMENT",
        "POLICY_ENGINE_UNAVAILABLE",
        "RUNTIME_INCIDENT",
        "RUNTIME_DRIFT",
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
    "RUNTIME_DRIFT": "restore the authorized runtime version and re-evaluate the deployment gate",
    "STALE_OBSERVATION": "refresh the runtime observation within the freshness window",
}

ACTION_BUNDLE = "agent-actions@0.1.0"
ACTION_DIGEST = "sha256:slice6-agent-actions-0.1.0"

ACTION_ACTIONS = {
    "NOT_AN_AGENT": "register an AGENT system before requesting action authorization",
    "NOT_DEPLOY_AUTHORIZED": "evaluate the deployment gate to ALLOW before the agent may act",
    "SYSTEM_BLOCKED": "clear the blocked lifecycle and re-evaluate the deployment gate",
    "RUNTIME_INCIDENT": "resolve the open incident and re-authorize the action",
    "UNDECLARED_ACTION": "declare a version-bound capability for this action",
    "RESOURCE_NOT_PERMITTED": "declare a capability whose resource pattern covers this resource",
    "AMOUNT_EXCEEDS_LIMIT": "request a lower amount or raise the capability ceiling",
    "MISSING_ACTION_APPROVAL": "have a reviewer approve the capability",
    "POLICY_ENGINE_UNAVAILABLE": "restore the policy engine and retry action authorization",
}


class PolicyEngine(Protocol):
    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation: ...

    async def evaluate_action(self, document: dict[str, Any]) -> PolicyEvaluation: ...


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
    reconciliation = document.get("reconciliation") or {}
    recon_reasons = reconciliation.get("reasons") or []
    high_drift = reconciliation.get("high_drift") is True or (
        reconciliation.get("status") == "DRIFT"
        and any((item or {}).get("severity") == "HIGH" for item in recon_reasons)
    )
    if high_drift:
        reasons.append(
            PolicyReason(
                "RUNTIME_DRIFT",
                "HIGH",
                "observed runtime state does not match the authorized desired state",
            )
        )
    for item in recon_reasons:
        if (item or {}).get("code") == "STALE_OBSERVATION":
            stale_severity = str((item or {}).get("severity") or "")
            if stale_severity not in {"HIGH", "MEDIUM"}:
                stale_severity = "HIGH" if high_risk else "MEDIUM"
            reasons.append(
                PolicyReason(
                    "STALE_OBSERVATION",
                    stale_severity,
                    "runtime observation is stale relative to the freshness window",
                )
            )
            break

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

    async def evaluate_action(self, document: dict[str, Any]) -> PolicyEvaluation:
        return evaluate_action_document(document)


def evaluate_action_document(document: dict[str, Any]) -> PolicyEvaluation:
    """Embedded evaluator. Must stay aligned with policies/rego/action.rego."""
    reasons: list[PolicyReason] = []
    asset = document.get("asset") or {}
    request = document.get("request") or {}
    capability = document.get("capability")
    incidents = document.get("incidents") or []

    if asset.get("system_type") != "AGENT":
        reasons.append(
            PolicyReason(
                "NOT_AN_AGENT",
                "HIGH",
                "only AGENT systems may request action authorization",
            )
        )
    if not asset.get("deploy_authorized"):
        reasons.append(
            PolicyReason(
                "NOT_DEPLOY_AUTHORIZED",
                "HIGH",
                "the agent is not currently authorized to operate",
            )
        )
    if asset.get("status") == "BLOCKED":
        reasons.append(
            PolicyReason(
                "SYSTEM_BLOCKED",
                "HIGH",
                "a blocked system cannot act",
            )
        )
    if any((item or {}).get("status") == "OPEN" for item in incidents):
        reasons.append(
            PolicyReason(
                "RUNTIME_INCIDENT",
                "HIGH",
                "an open runtime incident revokes action authorization",
            )
        )
    if capability is None:
        reasons.append(
            PolicyReason(
                "UNDECLARED_ACTION",
                "HIGH",
                "the requested action is not declared for the current asset version",
            )
        )
    else:
        if capability.get("resource_match") is not True:
            reasons.append(
                PolicyReason(
                    "RESOURCE_NOT_PERMITTED",
                    "HIGH",
                    "the requested resource is outside the declared capability pattern",
                )
            )
        max_amount = capability.get("max_amount")
        amount = request.get("amount")
        if max_amount is not None and amount is not None and amount > max_amount:
            reasons.append(
                PolicyReason(
                    "AMOUNT_EXCEEDS_LIMIT",
                    "HIGH",
                    "the requested amount exceeds the capability ceiling",
                )
            )
        if capability.get("requires_approval") and not capability.get("approved"):
            reasons.append(
                PolicyReason(
                    "MISSING_ACTION_APPROVAL",
                    "HIGH",
                    "privileged or approval-gated capabilities require a reviewer grant",
                )
            )

    outcome = "DENY" if reasons else "ALLOW"
    actions = [ACTION_ACTIONS[reason.code] for reason in reasons if reason.code in ACTION_ACTIONS]
    return PolicyEvaluation(
        outcome=outcome,
        reasons=reasons,
        required_actions=actions,
        policy_bundle=ACTION_BUNDLE,
        policy_digest=ACTION_DIGEST,
    )
