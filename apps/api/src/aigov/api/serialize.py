from __future__ import annotations

from aigov.api.schemas import (
    AISystem360Out,
    AISystemOut,
    ApprovalOut,
    AuditEventOut,
    PolicyDecisionOut,
    PolicyReasonOut,
    RiskAssessmentOut,
    RiskDriverOut,
)
from aigov.infrastructure.models import (
    AISystemModel,
    ApprovalModel,
    AuditEventModel,
    PolicyDecisionModel,
    RiskAssessmentModel,
)


def system_out(row: AISystemModel, risk_band: str | None = None) -> AISystemOut:
    return AISystemOut(
        id=row.id,
        urn=row.urn,
        tenantId=row.tenant_id,
        name=row.name,
        systemType=row.system_type,
        businessPurpose=row.business_purpose,
        owner=row.owner,
        environment=row.environment,
        dataClassification=row.data_classification,
        geography=row.geography,
        autonomyLevel=row.autonomy_level,
        status=row.status,
        riskBand=risk_band,
        createdAt=row.created_at,
        updatedAt=row.updated_at,
    )


def assessment_out(row: RiskAssessmentModel) -> RiskAssessmentOut:
    return RiskAssessmentOut(
        id=row.id,
        systemId=row.system_id,
        score=row.score,
        riskBand=row.risk_band,
        confidence=row.confidence,
        drivers=[RiskDriverOut(**item) for item in row.drivers],
        hardConstraints=row.hard_constraints,
        missingInputs=row.missing_inputs,
        engineVersion=row.engine_version,
        assessedAt=row.assessed_at,
    )


def decision_out(row: PolicyDecisionModel) -> PolicyDecisionOut:
    return PolicyDecisionOut(
        id=row.id,
        systemId=row.system_id,
        outcome=row.outcome,
        policyBundle=row.policy_bundle,
        reasons=[PolicyReasonOut(**item) for item in row.reasons],
        requiredActions=row.required_actions,
        policyDigest=row.policy_digest,
        inputDigest=row.input_digest,
        decidedAt=row.decided_at,
    )


def approval_out(row: ApprovalModel) -> ApprovalOut:
    return ApprovalOut(
        function=row.function,
        approved=row.approved,
        actorId=row.actor_id,
        recordedAt=row.recorded_at,
    )


def audit_out(row: AuditEventModel) -> AuditEventOut:
    return AuditEventOut(
        eventId=row.id,
        eventType=row.event_type,
        aggregateId=row.aggregate_id,
        actor=row.actor,
        occurredAt=row.occurred_at,
        payload=row.payload,
        hash=row.hash,
        previousEventHash=row.previous_event_hash,
    )


def system_360(
    system: AISystemModel,
    assessment: RiskAssessmentModel | None,
    decision: PolicyDecisionModel | None,
    approvals: list[ApprovalModel],
) -> AISystem360Out:
    return AISystem360Out(
        system=system_out(system, assessment.risk_band if assessment else None),
        registration=system.registration,
        latestAssessment=assessment_out(assessment) if assessment else None,
        latestDecision=decision_out(decision) if decision else None,
        approvals=[approval_out(row) for row in approvals],
        humanOversight=system.human_oversight,
    )
