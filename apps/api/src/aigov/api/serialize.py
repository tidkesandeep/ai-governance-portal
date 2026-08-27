from __future__ import annotations

from aigov.api.schemas import (
    ActionAuthorizationOut,
    ActionDecisionOut,
    AdapterRunOut,
    AISystem360Out,
    AISystemOut,
    ApprovalOut,
    AuditEventOut,
    CapabilityOut,
    ControlAssessmentOut,
    DeploymentAuthorizationOut,
    EvidenceArtifactOut,
    ExceptionOut,
    FindingOut,
    GitHubCheckOut,
    GovernanceSnapshotOut,
    IncidentOut,
    OutboxEventOut,
    PolicyDecisionOut,
    PolicyReasonOut,
    ReconciliationOut,
    RiskAssessmentOut,
    RiskDriverOut,
    RuntimeBindingOut,
    RuntimeObservationOut,
    WorkflowCaseOut,
)
from aigov.application.governance import ActionResult, GateResult
from aigov.domains.evidence.service import ControlAssessment
from aigov.domains.workflow.service import compute_sla_status
from aigov.infrastructure.ids import utcnow
from aigov.infrastructure.models import (
    ActionAuthorizationModel,
    ActionDecisionModel,
    AdapterRunModel,
    AISystemModel,
    ApprovalModel,
    AuditEventModel,
    CapabilityModel,
    DeploymentAuthorizationModel,
    EventOutboxModel,
    EvidenceArtifactModel,
    ExceptionModel,
    FindingModel,
    GitHubCheckModel,
    GovernanceDecisionModel,
    IncidentModel,
    PolicyDecisionModel,
    ReconciliationResultModel,
    RiskAssessmentModel,
    RuntimeBindingModel,
    RuntimeObservationModel,
    WorkflowCaseModel,
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


def case_out(row: WorkflowCaseModel) -> WorkflowCaseOut:
    return WorkflowCaseOut(
        id=row.id,
        systemId=row.system_id,
        decisionId=row.decision_id,
        snapshotId=row.snapshot_id,
        caseType=row.case_type,
        status=row.status,
        riskBand=row.risk_band,
        reasonCodes=list(row.reason_codes or []),
        slaStatus=compute_sla_status(row.opened_at, row.due_at, utcnow()),
        openedAt=row.opened_at,
        dueAt=row.due_at,
        closedAt=row.closed_at,
    )


def exception_out(row: ExceptionModel) -> ExceptionOut:
    return ExceptionOut(
        id=row.id,
        systemId=row.system_id,
        caseId=row.case_id,
        violationCode=row.violation_code,
        controlId=row.control_id,
        boundVersionId=row.bound_version_id,
        justification=row.justification,
        status=row.status,
        requestedBy=row.requested_by,
        grantedBy=row.granted_by,
        requestedAt=row.requested_at,
        grantedAt=row.granted_at,
        expiresAt=row.expires_at,
        revokedAt=row.revoked_at,
    )


def finding_out(row: FindingModel) -> FindingOut:
    return FindingOut(
        id=row.id,
        systemId=row.system_id,
        incidentId=row.incident_id,
        boundVersionId=row.bound_version_id,
        findingType=row.finding_type,
        severity=row.severity,
        summary=row.summary,
        detector=row.detector,
        status=row.status,
        recordedBy=row.recorded_by,
        recordedAt=row.recorded_at,
        resolvedAt=row.resolved_at,
        dismissedAt=row.dismissed_at,
    )


def incident_out(row: IncidentModel) -> IncidentOut:
    return IncidentOut(
        id=row.id,
        systemId=row.system_id,
        severity=row.severity,
        status=row.status,
        title=row.title,
        summary=row.summary,
        openedBy=row.opened_by,
        resolvedBy=row.resolved_by,
        openedAt=row.opened_at,
        resolvedAt=row.resolved_at,
    )


def capability_out(row: CapabilityModel) -> CapabilityOut:
    return CapabilityOut(
        id=row.id,
        systemId=row.system_id,
        boundVersionId=row.bound_version_id,
        action=row.action,
        resourcePattern=row.resource_pattern,
        maxAmount=row.max_amount,
        requiresApproval=row.requires_approval,
        approved=row.approved,
        declaredBy=row.declared_by,
        approvedBy=row.approved_by,
        declaredAt=row.declared_at,
        approvedAt=row.approved_at,
        revokedAt=row.revoked_at,
    )


def action_decision_out(
    row: ActionDecisionModel, *, authorization_id: str | None = None
) -> ActionDecisionOut:
    return ActionDecisionOut(
        id=row.id,
        systemId=row.system_id,
        outcome=row.outcome,
        action=row.action,
        resource=row.resource,
        amount=row.amount,
        capabilityId=row.capability_id,
        reasons=[PolicyReasonOut(**item) for item in row.reasons],
        requiredActions=row.required_actions,
        policyBundle=row.policy_bundle,
        policyDigest=row.policy_digest,
        inputDigest=row.input_digest,
        fingerprint=row.fingerprint,
        authorizationId=authorization_id,
        decidedAt=row.decided_at,
    )


def action_authorization_out(row: ActionAuthorizationModel) -> ActionAuthorizationOut:
    return ActionAuthorizationOut(
        id=row.id,
        systemId=row.system_id,
        decisionId=row.decision_id,
        assetVersionId=row.asset_version_id,
        action=row.action,
        resource=row.resource,
        nonce=row.nonce,
        fingerprint=row.fingerprint,
        signature=row.signature,
        issuedAt=row.issued_at,
        expiresAt=row.expires_at,
        revokedAt=row.revoked_at,
        consumedAt=row.consumed_at,
    )


def action_gate_out(result: ActionResult) -> ActionDecisionOut:
    return action_decision_out(
        result.decision,
        authorization_id=result.authorization.id if result.authorization else None,
    )


def observation_out(row: RuntimeObservationModel) -> RuntimeObservationOut:
    return RuntimeObservationOut(
        id=row.id,
        systemId=row.system_id,
        boundVersionId=row.bound_version_id,
        environment=row.environment,
        cloud=row.cloud,
        region=row.region,
        fingerprint=row.fingerprint,
        running=row.running,
        observedAt=row.observed_at,
        recordedBy=row.recorded_by,
        recordedAt=row.recorded_at,
    )


def reconciliation_out(row: ReconciliationResultModel) -> ReconciliationOut:
    return ReconciliationOut(
        id=row.id,
        systemId=row.system_id,
        observationId=row.observation_id,
        status=row.status,
        reasons=[PolicyReasonOut(**item) for item in row.reasons or []],
        desired=row.desired or {},
        observed=row.observed,
        reconciledAt=row.reconciled_at,
    )


def outbox_out(row: EventOutboxModel) -> OutboxEventOut:
    return OutboxEventOut(
        id=row.id,
        eventId=row.event_id,
        eventType=row.event_type,
        aggregateId=row.aggregate_id,
        occurredAt=row.occurred_at,
        publishedAt=row.published_at,
        publishAttempts=int(row.publish_attempts or 0),
        lastError=row.last_error,
    )


def github_check_out(row: GitHubCheckModel) -> GitHubCheckOut:
    return GitHubCheckOut(
        id=row.id,
        systemId=row.system_id,
        sha=row.sha,
        repo=row.repo,
        name=row.name,
        status=row.status,
        conclusion=row.conclusion,
        htmlUrl=row.html_url,
        decisionId=row.decision_id,
        recordedAt=row.recorded_at,
    )


def runtime_binding_out(row: RuntimeBindingModel) -> RuntimeBindingOut:
    return RuntimeBindingOut(
        id=row.id,
        systemId=row.system_id,
        provider=row.provider,
        service=row.service,
        resourceRef=row.resource_ref,
        region=row.region,
        accountRef=row.account_ref,
        status=row.status,
        createdAt=row.created_at,
        supersededAt=row.superseded_at,
    )


def adapter_run_out(row: AdapterRunModel) -> AdapterRunOut:
    return AdapterRunOut(
        id=row.id,
        systemId=row.system_id,
        bindingId=row.binding_id,
        kind=row.kind,
        provider=row.provider,
        status=row.status,
        action=row.action,
        result=row.result or {},
        error=row.error,
        recordedAt=row.recorded_at,
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
    cases: list[WorkflowCaseModel] | None = None,
    exceptions: list[ExceptionModel] | None = None,
    findings: list[FindingModel] | None = None,
    incidents: list[IncidentModel] | None = None,
    capabilities: list[CapabilityModel] | None = None,
    action_decision: ActionDecisionModel | None = None,
    action_authorization: ActionAuthorizationModel | None = None,
    observation: RuntimeObservationModel | None = None,
    reconciliation: ReconciliationResultModel | None = None,
    outbox_events: list[EventOutboxModel] | None = None,
    github_checks: list[GitHubCheckModel] | None = None,
    binding: RuntimeBindingModel | None = None,
    adapter_runs: list[AdapterRunModel] | None = None,
) -> AISystem360Out:
    case_items = [case_out(row) for row in cases or []]
    incident_items = [incident_out(row) for row in incidents or []]
    latest_incident = next(
        (item for item in incident_items if item.status == "OPEN"),
        incident_items[0] if incident_items else None,
    )
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
        latestCase=case_items[0] if case_items else None,
        cases=case_items,
        exceptions=[exception_out(row) for row in exceptions or []],
        findings=[finding_out(row) for row in findings or []],
        incidents=incident_items,
        latestIncident=latest_incident,
        capabilities=[capability_out(row) for row in capabilities or []],
        latestActionDecision=action_decision_out(
            action_decision,
            authorization_id=(
                action_authorization.id
                if action_authorization is not None
                and action_decision is not None
                and action_authorization.decision_id == action_decision.id
                else None
            ),
        )
        if action_decision
        else None,
        latestActionAuthorization=(
            action_authorization_out(action_authorization) if action_authorization else None
        ),
        latestObservation=observation_out(observation) if observation else None,
        latestReconciliation=reconciliation_out(reconciliation) if reconciliation else None,
        latestOutboxEvents=[outbox_out(row) for row in outbox_events or []],
        githubChecks=[github_check_out(row) for row in github_checks or []],
        latestGithubCheck=github_check_out(github_checks[0]) if github_checks else None,
        runtimeBinding=runtime_binding_out(binding) if binding else None,
        adapterRuns=[adapter_run_out(row) for row in adapter_runs or []],
        latestAdapterRun=adapter_run_out(adapter_runs[0]) if adapter_runs else None,
    )
