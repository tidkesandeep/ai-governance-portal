from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aigov.infrastructure.models import AISystemModel, EvidenceArtifactModel, RiskAssessmentModel

COLLECTOR_VERSION = "evidence-collector@0.2.0"

ALLOWED_TYPES = {
    "MODEL_CARD",
    "EVALUATION_RUN",
    "FAIRNESS_EVALUATION",
    "SECURITY_SCAN",
    "SBOM",
}

EICAR_PREFIX = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"


@dataclass(frozen=True)
class ControlSpec:
    control_id: str
    evidence_type: str
    max_age_days: int
    objective: str


@dataclass(frozen=True)
class ControlAssessment:
    control_id: str
    evidence_type: str
    required: bool
    status: str
    evidence_id: str | None
    reason: str
    max_age_days: int
    sha256: str | None = None


def applicable_controls(
    system: AISystemModel, assessment: RiskAssessmentModel | None
) -> list[ControlSpec]:
    band = assessment.risk_band if assessment else None
    high = band in {"HIGH", "CRITICAL"}
    specs: list[ControlSpec] = []
    if high or system.environment == "production":
        specs.append(
            ControlSpec(
                "CTRL-MODEL-CARD-001",
                "MODEL_CARD",
                365,
                "System card / model card is attached for the current asset version",
            )
        )
    if high:
        specs.append(
            ControlSpec(
                "CTRL-ML-PERF-001",
                "EVALUATION_RUN",
                30,
                "Production model performance evidence remains within freshness limits",
            )
        )
    if high and bool(system.registration.get("usesCustomerDecision")):
        specs.append(
            ControlSpec(
                "CTRL-FAIRNESS-001",
                "FAIRNESS_EVALUATION",
                30,
                "Customer-decision systems require a current fairness evaluation",
            )
        )
    return specs


def assess_controls(
    system: AISystemModel,
    assessment: RiskAssessmentModel | None,
    artifacts: list[EvidenceArtifactModel],
    *,
    now: datetime | None = None,
) -> list[ControlAssessment]:
    clock = now or datetime.now(UTC)
    results: list[ControlAssessment] = []
    for spec in applicable_controls(system, assessment):
        results.append(_assess_one(spec, system.current_version_id, artifacts, clock))
    return results


def _assess_one(
    spec: ControlSpec,
    current_version_id: str,
    artifacts: list[EvidenceArtifactModel],
    now: datetime,
) -> ControlAssessment:
    candidates = [
        item
        for item in artifacts
        if item.evidence_type == spec.evidence_type and item.bound_version_id == current_version_id
    ]
    candidates.sort(key=lambda item: item.collected_at, reverse=True)
    if not candidates:
        wrong_version = any(item.evidence_type == spec.evidence_type for item in artifacts)
        reason = (
            "evidence is bound to a previous asset version"
            if wrong_version
            else "no evidence of this type is attached"
        )
        return ControlAssessment(
            spec.control_id,
            spec.evidence_type,
            True,
            "UNKNOWN",
            None,
            reason,
            spec.max_age_days,
        )
    latest = candidates[0]
    if latest.verification_status != "VERIFIED":
        return ControlAssessment(
            spec.control_id,
            spec.evidence_type,
            True,
            "FAIL",
            latest.id,
            "evidence hash verification failed",
            spec.max_age_days,
            latest.sha256,
        )
    collected = latest.collected_at
    if collected.tzinfo is None:
        collected = collected.replace(tzinfo=UTC)
    age = now - collected
    if age > timedelta(days=spec.max_age_days):
        return ControlAssessment(
            spec.control_id,
            spec.evidence_type,
            True,
            "STALE",
            latest.id,
            f"evidence is older than {spec.max_age_days} days",
            spec.max_age_days,
            latest.sha256,
        )
    return ControlAssessment(
        spec.control_id,
        spec.evidence_type,
        True,
        "PASS",
        latest.id,
        "fresh verified evidence bound to the current asset version",
        spec.max_age_days,
        latest.sha256,
    )


def controls_to_policy_document(assessments: list[ControlAssessment]) -> dict[str, Any]:
    return {
        "stale": any(item.status == "STALE" for item in assessments),
        "controls": [
            {
                "id": item.control_id,
                "type": item.evidence_type,
                "required": item.required,
                "status": item.status,
            }
            for item in assessments
        ],
    }


def reject_upload(content: bytes, evidence_type: str, max_bytes: int) -> str | None:
    if evidence_type not in ALLOWED_TYPES:
        return "unsupported evidence type"
    if not content:
        return "empty evidence is not allowed"
    if len(content) > max_bytes:
        return "evidence exceeds maximum size"
    if content.startswith(EICAR_PREFIX) or b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
        return "evidence failed malware screening"
    return None
