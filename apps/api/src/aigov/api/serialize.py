from __future__ import annotations

from aigov.api.schemas import (
    AISystem360Out,
    AISystemOut,
    ApprovalOut,
    AuditEventOut,
    ControlAssessmentOut,
    DeploymentAuthorizationOut,
    EvidenceArtifactOut,
    GovernanceSnapshotOut,
    PolicyDecisionOut,
    PolicyReasonOut,
    RiskAssessmentOut,
    RiskDriverOut,
)
from aigov.application.governance import GateResult
from aigov.domains.evidence.service import ControlAssessment
from aigov.infrastructure.models import (
    AISystemModel,
    ApprovalModel,
    AuditEventModel,
    DeploymentAuthorizationModel,
    EvidenceArtifactModel,
    GovernanceDecisionModel,
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
        currentVersionId=row.current_version_id,
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


def decision_out(
    row: PolicyDecisionModel,
    *,
    fingerprint: str | None = None,
    snapshot_id: str | None = None,
    authorization_id: str | None = None,
) -> PolicyDecisionOut:
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
        fingerprint=fingerprint,
        snapshotId=snapshot_id,
        authorizationId=authorization_id,
    )


def snapshot_out(row: GovernanceDecisionModel) -> GovernanceSnapshotOut:
    return GovernanceSnapshotOut(
        id=row.id,
        systemId=row.system_id,
        policyDecisionId=row.policy_decision_id,
        outcome=row.outcome,
        assetVersionId=row.asset_version_id,
        fingerprint=row.fingerprint,
        snapshot=row.snapshot,
        createdAt=row.created_at,
    )


def authorization_out(row: DeploymentAuthorizationModel) -> DeploymentAuthorizationOut:
    return DeploymentAuthorizationOut(
        id=row.id,
        systemId=row.system_id,
        decisionId=row.decision_id,
        assetVersionId=row.asset_version_id,
        environment=row.environment,
        cloud=row.cloud,
        region=row.region,
        audience=row.audience,
        nonce=row.nonce,
        fingerprint=row.fingerprint,
        signature=row.signature,
        issuedAt=row.issued_at,
        expiresAt=row.expires_at,
        revokedAt=row.revoked_at,
        consumedAt=row.consumed_at,
    )


def gate_out(result: GateResult) -> PolicyDecisionOut:
    return decision_out(
        result.decision,
        fingerprint=result.snapshot.fingerprint,
        snapshot_id=result.snapshot.id,
        authorization_id=result.authorization.id if result.authorization else None,
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


def evidence_out(row: EvidenceArtifactModel) -> EvidenceArtifactOut:
    return EvidenceArtifactOut(
        id=row.id,
        systemId=row.system_id,
        boundVersionId=row.bound_version_id,
        type=row.evidence_type,
        filename=row.filename,
        uri=row.uri,
        sha256=row.sha256,
        bytesSize=row.bytes_size,
        collectorVersion=row.collector_version,
        verificationStatus=row.verification_status,
        collectedAt=row.collected_at,
        createdAt=row.created_at,
    )


def control_out(item: ControlAssessment) -> ControlAssessmentOut:
    return ControlAssessmentOut(
        controlId=item.control_id,
        evidenceType=item.evidence_type,
        required=item.required,
        status=item.status,
        evidenceId=item.evidence_id,
        reason=item.reason,
        maxAgeDays=item.max_age_days,
        sha256=item.sha256,
    )


def system_360(
    system: AISystemModel,
    assessment: RiskAssessmentModel | None,
    decision: PolicyDecisionModel | None,
    approvals: list[ApprovalModel],
    evidence: list[EvidenceArtifactModel] | None = None,
    controls: list[ControlAssessment] | None = None,
    snapshot: GovernanceDecisionModel | None = None,
    authorization: DeploymentAuthorizationModel | None = None,
) -> AISystem360Out:
    return AISystem360Out(
        system=system_out(system, assessment.risk_band if assessment else None),
        registration=system.registration,
        latestAssessment=assessment_out(assessment) if assessment else None,
        latestDecision=decision_out(
            decision,
            fingerprint=snapshot.fingerprint if snapshot else None,
            snapshot_id=snapshot.id if snapshot else None,
            authorization_id=(
                authorization.id
                if authorization is not None
                and snapshot is not None
                and authorization.decision_id == snapshot.id
                else None
            ),
        )
        if decision
        else None,
        approvals=[approval_out(row) for row in approvals],
        humanOversight=system.human_oversight,
        evidence=[evidence_out(row) for row in evidence or []],
        controls=[control_out(item) for item in controls or []],
        latestSnapshot=snapshot_out(snapshot) if snapshot else None,
        latestAuthorization=authorization_out(authorization) if authorization else None,
    )
