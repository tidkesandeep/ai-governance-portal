from __future__ import annotations

from dataclasses import dataclass
from typing import Any

RISK_ENGINE_VERSION = "risk-engine@2.0.0"

DATA_SCORES: dict[str, float] = {
    "PUBLIC": 8,
    "INTERNAL": 22,
    "CONFIDENTIAL": 58,
    "PII": 82,
    "PCI": 92,
    "RESTRICTED": 88,
}

AUTONOMY_SCORES: dict[str, float] = {
    "HUMAN_IN_LOOP": 12,
    "ASSISTIVE": 34,
    "SEMI_AUTONOMOUS": 68,
    "AUTONOMOUS": 92,
}

ENVIRONMENT_SCORES: dict[str, float] = {
    "dev": 8,
    "test": 14,
    "staging": 32,
    "production": 72,
}

IMPACT_SCORES: dict[str, float] = {
    "NONE": 0,
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 75,
    "CRITICAL": 95,
}

WEIGHTS = {
    "impact": 0.25,
    "data": 0.20,
    "autonomy": 0.15,
    "exposure": 0.10,
    "regulatory": 0.15,
    "control_gap": 0.15,
}


@dataclass(frozen=True)
class RiskDriver:
    code: str
    contribution: float
    detail: str


@dataclass(frozen=True)
class RiskResult:
    score: float
    risk_band: str
    confidence: float
    drivers: list[RiskDriver]
    hard_constraints: list[str]
    missing_inputs: list[str]
    engine_version: str = RISK_ENGINE_VERSION


def band_for(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _regulatory_score(geography: str, data_classification: str) -> float:
    geo = geography.upper()
    base = 20
    if geo in {"EU", "EEA", "UK", "IN", "US-CA"} or "EU" in geo:
        base = 70
    if data_classification in {"PII", "PCI", "RESTRICTED"}:
        base = max(base, 80)
    if data_classification == "PCI":
        base = max(base, 90)
    return float(base)


def _control_gap(registration: dict[str, Any]) -> tuple[float, list[str]]:
    missing: list[str] = []
    gap = 15.0
    if not registration.get("evaluationRefs"):
        missing.append("evaluation_refs")
        gap += 35
    if not registration.get("monitoringEnabled"):
        missing.append("monitoring")
        gap += 25
    if registration.get("autonomyLevel") == "AUTONOMOUS" and not registration.get("humanOversight"):
        missing.append("human_oversight")
        gap += 20
    return min(gap, 100.0), missing


def assess(registration: dict[str, Any]) -> RiskResult:
    missing: list[str] = []
    if not registration.get("customerImpact"):
        missing.append("customer_impact")
    if not registration.get("financialImpact"):
        missing.append("financial_impact")
    if not registration.get("intendedUsers"):
        missing.append("intended_users")

    customer = IMPACT_SCORES.get(registration.get("customerImpact") or "NONE", 0)
    financial = IMPACT_SCORES.get(registration.get("financialImpact") or "NONE", 0)
    uses_customer_decision = bool(registration.get("usesCustomerDecision"))
    impact = max(customer, financial)
    if uses_customer_decision:
        impact = max(impact, 70)
    if registration.get("systemType") == "AGENT":
        impact = max(impact, 55)

    data_score = DATA_SCORES[registration["dataClassification"]]
    autonomy_score = AUTONOMY_SCORES[registration["autonomyLevel"]]
    exposure = ENVIRONMENT_SCORES[registration["environment"]]
    if registration.get("publicEndpoint"):
        exposure = max(exposure, 85)
    regulatory = _regulatory_score(registration["geography"], registration["dataClassification"])
    control_gap, control_missing = _control_gap(registration)
    missing.extend(control_missing)

    raw = (
        WEIGHTS["impact"] * impact
        + WEIGHTS["data"] * data_score
        + WEIGHTS["autonomy"] * autonomy_score
        + WEIGHTS["exposure"] * exposure
        + WEIGHTS["regulatory"] * regulatory
        + WEIGHTS["control_gap"] * control_gap
    )
    score = round(raw, 1)

    hard_constraints: list[str] = []
    if uses_customer_decision and max(customer, financial) >= IMPACT_SCORES["HIGH"]:
        hard_constraints.append("CUSTOMER_DECISION_HIGH_IMPACT")
        score = max(score, 60.0)
    if registration["autonomyLevel"] == "AUTONOMOUS":
        hard_constraints.append("PRIVILEGED_AUTONOMOUS_ACTION")
        score = max(score, 60.0)
    if registration["dataClassification"] == "PCI":
        hard_constraints.append("PCI_DATA")
        score = max(score, 60.0)

    confidence = 1.0 - min(len(set(missing)) * 0.08, 0.45)
    if registration.get("evaluationRefs"):
        confidence = min(1.0, confidence + 0.05)
    confidence = round(confidence, 2)

    if confidence < 0.7:
        hard_constraints.append("LOW_CONFIDENCE_REVIEW")

    drivers = [
        RiskDriver("FINANCIAL_IMPACT", round(WEIGHTS["impact"] * impact, 1), "impact / harm"),
        RiskDriver("DATA_SENSITIVE", round(WEIGHTS["data"] * data_score, 1), "data classification"),
        RiskDriver(
            "AUTONOMOUS_ACTION",
            round(WEIGHTS["autonomy"] * autonomy_score, 1),
            "autonomy level",
        ),
        RiskDriver(
            "PUBLIC_EXPOSURE",
            round(WEIGHTS["exposure"] * exposure, 1),
            "environment / exposure",
        ),
        RiskDriver(
            "REGULATORY_REVIEW",
            round(WEIGHTS["regulatory"] * regulatory, 1),
            "jurisdiction and data obligations",
        ),
        RiskDriver(
            "MISSING_EVALUATION",
            round(WEIGHTS["control_gap"] * control_gap, 1),
            "control gap",
        ),
    ]
    drivers.sort(key=lambda item: item.contribution, reverse=True)

    return RiskResult(
        score=score,
        risk_band=band_for(score),
        confidence=confidence,
        drivers=drivers,
        hard_constraints=hard_constraints,
        missing_inputs=sorted(set(missing)),
    )
