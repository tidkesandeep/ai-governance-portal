from fastapi import APIRouter, Depends, HTTPException

from aigov.api.deps import current_principal, governance_service
from aigov.api.schemas import (
    ActionAuthorizationOut,
    ActionAuthorizationVerifyOut,
    ActionAuthorizeRequest,
    ActionDecisionOut,
    AISystem360Out,
    AISystemListOut,
    AISystemRegistration,
    ApprovalRequest,
    AuditEventListOut,
    AuthorizationVerifyOut,
    AuthorizationVerifyRequest,
    CapabilityRequest,
    DeploymentAuthorizationOut,
    DeploymentGateRequest,
    EvidenceAttachRequest,
    ExceptionRequest,
    FindingRequest,
    GitHubCheckOut,
    GitHubCheckRequest,
    ObservationRequest,
    OversightRequest,
    PolicyDecisionOut,
    RiskAssessmentOut,
)
from aigov.api.serialize import (
    action_authorization_out,
    action_gate_out,
    assessment_out,
    audit_out,
    authorization_out,
    gate_out,
    github_check_out,
    system_360,
    system_out,
)
from aigov.application.governance import (
    CapabilityRejectedError,
    EvidenceRejectedError,
    ExceptionRejectedError,
    FindingRejectedError,
    GovernanceService,
    NotFoundError,
    ObservationRejectedError,
    SegregationOfDutiesError,
)
from aigov.domains.identity.principal import Principal

router = APIRouter(prefix="/v1/ai-systems", tags=["AI Systems"])


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "type": "https://api.aigov.local/problems/not-found",
            "title": "AI system not found",
            "status": 404,
            "code": "NOT_FOUND",
        },
    )


def _sod(exc: SegregationOfDutiesError) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "type": "https://api.aigov.local/problems/segregation-of-duties",
            "title": "Segregation of duties violation",
            "status": 409,
            "code": "SOD_VIOLATION",
            "detail": exc.detail,
        },
    )


def _exception_rejected(exc: ExceptionRejectedError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "type": "https://api.aigov.local/problems/exception-rejected",
            "title": "Exception rejected",
            "status": 422,
            "code": exc.code,
            "detail": exc.detail,
        },
    )


def _finding_rejected(exc: FindingRejectedError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "type": "https://api.aigov.local/problems/finding-rejected",
            "title": "Finding rejected",
            "status": 422,
            "code": exc.code,
            "detail": exc.detail,
        },
    )


def _capability_rejected(exc: CapabilityRejectedError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "type": "https://api.aigov.local/problems/capability-rejected",
            "title": "Capability rejected",
            "status": 422,
            "code": exc.code,
            "detail": exc.detail,
        },
    )


def _observation_rejected(exc: ObservationRejectedError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "type": "https://api.aigov.local/problems/observation-rejected",
            "title": "Observation rejected",
            "status": 422,
            "code": exc.code,
            "detail": exc.detail,
        },
    )


async def _system_360(
    svc: GovernanceService, principal: Principal, system_id: str
) -> AISystem360Out:
    system = await svc.get_system(principal, system_id)
    assessment = await svc.latest_assessment(principal, system_id)
    decision = await svc.latest_decision(principal, system_id)
    approvals = await svc.list_approvals(principal, system_id)
    evidence = await svc.list_evidence(principal, system_id)
    controls = await svc.control_posture(principal, system_id)
    snapshot = await svc.latest_snapshot(principal, system_id)
    authorization = await svc.latest_authorization(principal, system_id)
    cases = await svc.list_cases(principal, system_id)
    exceptions = await svc.list_exceptions(principal, system_id)
    findings = await svc.list_findings(principal, system_id)
    incidents = await svc.list_incidents(principal, system_id)
    capabilities = await svc.list_capabilities(principal, system_id)
    action_decision = await svc.latest_action_decision(principal, system_id)
    action_authorization = await svc.latest_action_authorization(principal, system_id)
    observation = await svc.latest_observation(principal, system_id)
    reconciliation = await svc.latest_reconciliation(principal, system_id)
    outbox_events = await svc.list_outbox(principal, system_id)
    github_checks = await svc.list_github_checks(principal, system_id)
    return system_360(
        system,
        assessment,
        decision,
        approvals,
        evidence,
        controls,
        snapshot,
        authorization,
        cases,
        exceptions,
        findings,
        incidents,
        capabilities,
        action_decision,
        action_authorization,
        observation,
        reconciliation,
        outbox_events,
        github_checks,
    )


@router.get("", response_model=AISystemListOut)
async def list_systems(
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystemListOut:
    rows = await svc.list_systems(principal)
    items = []
    for row in rows:
        assessment = await svc.latest_assessment(principal, row.id)
        items.append(system_out(row, assessment.risk_band if assessment else None))
    return AISystemListOut(items=items)


@router.post("", response_model=AISystem360Out, status_code=201)
async def register_system(
    body: AISystemRegistration,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    row = await svc.register(principal, body.model_dump())
    return await _system_360(svc, principal, row.id)


@router.get("/{system_id}", response_model=AISystem360Out)
async def get_system(
    system_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc


@router.post("/{system_id}/assessments", response_model=RiskAssessmentOut, status_code=201)
async def assess_system(
    system_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> RiskAssessmentOut:
    try:
        row = await svc.assess(principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    return assessment_out(row)


@router.post("/{system_id}/approvals", response_model=AISystem360Out, status_code=201)
async def record_approval(
    system_id: str,
    body: ApprovalRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.record_approval(principal, system_id, body.function, body.approved)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "type": "https://api.aigov.local/problems/segregation-of-duties",
                "title": "Segregation of duties violation",
                "status": 409,
                "code": "SOD_VIOLATION",
                "detail": exc.detail,
            },
        ) from exc


@router.post("/{system_id}/oversight", response_model=AISystem360Out)
async def attach_oversight(
    system_id: str,
    body: OversightRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.attach_oversight(principal, system_id, body.controls)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc


@router.post("/{system_id}/deployments/gate", response_model=PolicyDecisionOut)
async def evaluate_gate(
    system_id: str,
    body: DeploymentGateRequest | None = None,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> PolicyDecisionOut:
    payload = body or DeploymentGateRequest()
    try:
        result = await svc.evaluate_gate(
            principal,
            system_id,
            environment=payload.environment,
            evidence_stale=payload.evidenceStale,
            cloud=payload.cloud,
            region=payload.region,
            audience=payload.audience,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    return gate_out(result)


@router.get("/{system_id}/audit-events", response_model=AuditEventListOut)
async def list_audit(
    system_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AuditEventListOut:
    try:
        await svc.get_system(principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    events = await svc.audit.list_for(tenant_id=principal.tenant_id, aggregate_id=system_id)
    return AuditEventListOut(items=[audit_out(event) for event in events])


@router.post("/{system_id}/evidence", response_model=AISystem360Out, status_code=201)
async def attach_evidence(
    system_id: str,
    body: EvidenceAttachRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.attach_evidence(
            principal,
            system_id,
            evidence_type=body.type,
            filename=body.filename,
            content=body.content.encode("utf-8"),
            collected_at=body.collectedAt,
            bound_version_id=body.boundVersionId,
            media_type=body.mediaType,
        )
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except EvidenceRejectedError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "type": "https://api.aigov.local/problems/evidence-rejected",
                "title": "Evidence rejected",
                "status": 422,
                "code": "EVIDENCE_REJECTED",
                "detail": exc.detail,
            },
        ) from exc


@router.post("/{system_id}/evidence/{evidence_id}/verify", response_model=AISystem360Out)
async def verify_evidence(
    system_id: str,
    evidence_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.verify_evidence(principal, system_id, evidence_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc


@router.post(
    "/{system_id}/authorizations/{authorization_id}/verify",
    response_model=AuthorizationVerifyOut,
)
async def verify_authorization(
    system_id: str,
    authorization_id: str,
    body: AuthorizationVerifyRequest | None = None,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AuthorizationVerifyOut:
    payload = body or AuthorizationVerifyRequest()
    try:
        row, check = await svc.verify_authorization(
            principal,
            system_id,
            authorization_id,
            presented_signature=payload.signature,
            consume=payload.consume,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    return AuthorizationVerifyOut(
        outcome=check.outcome,
        reasons=check.reasons,
        authorization=authorization_out(row),
    )


@router.post(
    "/{system_id}/authorizations/{authorization_id}/revoke",
    response_model=DeploymentAuthorizationOut,
)
async def revoke_authorization(
    system_id: str,
    authorization_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> DeploymentAuthorizationOut:
    try:
        row = await svc.revoke_authorization(principal, system_id, authorization_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    return authorization_out(row)


@router.post("/{system_id}/exceptions", response_model=AISystem360Out, status_code=201)
async def request_exception(
    system_id: str,
    body: ExceptionRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.request_exception(
            principal,
            system_id,
            violation_code=body.violationCode,
            justification=body.justification,
            expires_at=body.expiresAt,
            control_id=body.controlId,
        )
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except ExceptionRejectedError as exc:
        raise _exception_rejected(exc) from exc


@router.post("/{system_id}/exceptions/{exception_id}/grant", response_model=AISystem360Out)
async def grant_exception(
    system_id: str,
    exception_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.grant_exception(principal, system_id, exception_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except ExceptionRejectedError as exc:
        raise _exception_rejected(exc) from exc


@router.post("/{system_id}/exceptions/{exception_id}/deny", response_model=AISystem360Out)
async def deny_exception(
    system_id: str,
    exception_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.deny_exception(principal, system_id, exception_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except ExceptionRejectedError as exc:
        raise _exception_rejected(exc) from exc


@router.post("/{system_id}/exceptions/{exception_id}/revoke", response_model=AISystem360Out)
async def revoke_exception(
    system_id: str,
    exception_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.revoke_exception(principal, system_id, exception_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except ExceptionRejectedError as exc:
        raise _exception_rejected(exc) from exc


@router.post("/{system_id}/findings", response_model=AISystem360Out, status_code=201)
async def record_finding(
    system_id: str,
    body: FindingRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.record_finding(
            principal,
            system_id,
            finding_type=body.findingType,
            severity=body.severity,
            summary=body.summary,
            detector=body.detector,
        )
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except FindingRejectedError as exc:
        raise _finding_rejected(exc) from exc


@router.post("/{system_id}/findings/{finding_id}/promote", response_model=AISystem360Out)
async def promote_finding(
    system_id: str,
    finding_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.promote_finding(principal, system_id, finding_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except FindingRejectedError as exc:
        raise _finding_rejected(exc) from exc


@router.post("/{system_id}/findings/{finding_id}/dismiss", response_model=AISystem360Out)
async def dismiss_finding(
    system_id: str,
    finding_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.dismiss_finding(principal, system_id, finding_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except FindingRejectedError as exc:
        raise _finding_rejected(exc) from exc


@router.post("/{system_id}/incidents/{incident_id}/resolve", response_model=AISystem360Out)
async def resolve_incident(
    system_id: str,
    incident_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.resolve_incident(principal, system_id, incident_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except FindingRejectedError as exc:
        raise _finding_rejected(exc) from exc


@router.post("/{system_id}/capabilities", response_model=AISystem360Out, status_code=201)
async def declare_capability(
    system_id: str,
    body: CapabilityRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.declare_capability(
            principal,
            system_id,
            action=body.action,
            resource_pattern=body.resourcePattern,
            max_amount=body.maxAmount,
            requires_approval=body.requiresApproval,
        )
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except CapabilityRejectedError as exc:
        raise _capability_rejected(exc) from exc


@router.post("/{system_id}/capabilities/{capability_id}/approve", response_model=AISystem360Out)
async def approve_capability(
    system_id: str,
    capability_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.approve_capability(principal, system_id, capability_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except SegregationOfDutiesError as exc:
        raise _sod(exc) from exc
    except CapabilityRejectedError as exc:
        raise _capability_rejected(exc) from exc


@router.post("/{system_id}/actions/authorize", response_model=ActionDecisionOut)
async def authorize_action(
    system_id: str,
    body: ActionAuthorizeRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> ActionDecisionOut:
    try:
        result = await svc.authorize_action(
            principal,
            system_id,
            action=body.action,
            resource=body.resource,
            amount=body.amount,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    except CapabilityRejectedError as exc:
        raise _capability_rejected(exc) from exc
    return action_gate_out(result)


@router.post(
    "/{system_id}/action-authorizations/{authorization_id}/verify",
    response_model=ActionAuthorizationVerifyOut,
)
async def verify_action_authorization(
    system_id: str,
    authorization_id: str,
    body: AuthorizationVerifyRequest | None = None,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> ActionAuthorizationVerifyOut:
    payload = body or AuthorizationVerifyRequest()
    try:
        row, check = await svc.verify_action_authorization(
            principal,
            system_id,
            authorization_id,
            presented_signature=payload.signature,
            consume=payload.consume,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    return ActionAuthorizationVerifyOut(
        outcome=check.outcome,
        reasons=check.reasons,
        authorization=action_authorization_out(row),
    )


@router.post(
    "/{system_id}/action-authorizations/{authorization_id}/revoke",
    response_model=ActionAuthorizationOut,
)
async def revoke_action_authorization(
    system_id: str,
    authorization_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> ActionAuthorizationOut:
    try:
        row = await svc.revoke_action_authorization(principal, system_id, authorization_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    return action_authorization_out(row)


@router.post("/{system_id}/observations", response_model=AISystem360Out, status_code=201)
async def record_observation(
    system_id: str,
    body: ObservationRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.record_observation(
            principal,
            system_id,
            running=body.running,
            asset_version_id=body.assetVersionId,
            environment=body.environment,
            cloud=body.cloud,
            region=body.region,
            fingerprint=body.fingerprint,
            observed_at=body.observedAt,
        )
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    except ObservationRejectedError as exc:
        raise _observation_rejected(exc) from exc


@router.post("/{system_id}/github-checks", response_model=GitHubCheckOut, status_code=201)
async def record_github_check(
    system_id: str,
    body: GitHubCheckRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> GitHubCheckOut:
    try:
        row = await svc.record_github_check(
            principal,
            system_id,
            sha=body.sha,
            repo=body.repo,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    return github_check_out(row)


@router.post("/{system_id}/versions", response_model=AISystem360Out, status_code=201)
async def cut_version(
    system_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        await svc.cut_version(principal, system_id)
        return await _system_360(svc, principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
