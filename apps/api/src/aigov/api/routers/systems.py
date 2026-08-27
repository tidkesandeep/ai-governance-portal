from fastapi import APIRouter, Depends, HTTPException

from aigov.api.deps import current_principal, governance_service
from aigov.api.schemas import (
    AISystem360Out,
    AISystemListOut,
    AISystemRegistration,
    ApprovalRequest,
    AuditEventListOut,
    DeploymentGateRequest,
    OversightRequest,
    PolicyDecisionOut,
    RiskAssessmentOut,
)
from aigov.api.serialize import assessment_out, audit_out, decision_out, system_360, system_out
from aigov.application.governance import GovernanceService, NotFoundError, SegregationOfDutiesError
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
    return system_360(row, None, None, [])


@router.get("/{system_id}", response_model=AISystem360Out)
async def get_system(
    system_id: str,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        system = await svc.get_system(principal, system_id)
    except NotFoundError as exc:
        raise _not_found() from exc
    assessment = await svc.latest_assessment(principal, system_id)
    decision = await svc.latest_decision(principal, system_id)
    approvals = await svc.list_approvals(principal, system_id)
    return system_360(system, assessment, decision, approvals)


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
        system = await svc.get_system(principal, system_id)
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
    assessment = await svc.latest_assessment(principal, system_id)
    decision = await svc.latest_decision(principal, system_id)
    approvals = await svc.list_approvals(principal, system_id)
    return system_360(system, assessment, decision, approvals)


@router.post("/{system_id}/oversight", response_model=AISystem360Out)
async def attach_oversight(
    system_id: str,
    body: OversightRequest,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> AISystem360Out:
    try:
        system = await svc.attach_oversight(principal, system_id, body.controls)
    except NotFoundError as exc:
        raise _not_found() from exc
    assessment = await svc.latest_assessment(principal, system_id)
    decision = await svc.latest_decision(principal, system_id)
    approvals = await svc.list_approvals(principal, system_id)
    return system_360(system, assessment, decision, approvals)


@router.post("/{system_id}/deployments/gate", response_model=PolicyDecisionOut)
async def evaluate_gate(
    system_id: str,
    body: DeploymentGateRequest | None = None,
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> PolicyDecisionOut:
    payload = body or DeploymentGateRequest()
    try:
        row = await svc.evaluate_gate(
            principal,
            system_id,
            environment=payload.environment,
            evidence_stale=payload.evidenceStale,
        )
    except NotFoundError as exc:
        raise _not_found() from exc
    return decision_out(row)


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
