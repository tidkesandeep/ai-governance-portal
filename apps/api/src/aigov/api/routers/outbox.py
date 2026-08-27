from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from aigov.api.deps import current_principal, governance_service
from aigov.api.schemas import OutboxPublishOut
from aigov.application.governance import GovernanceService
from aigov.domains.identity.principal import Principal

router = APIRouter(prefix="/v1/outbox", tags=["Outbox"])


@router.post("/publish", response_model=OutboxPublishOut)
async def publish_outbox(
    limit: int = Query(default=100, ge=1, le=1000),
    principal: Principal = Depends(current_principal),
    svc: GovernanceService = Depends(governance_service),
) -> OutboxPublishOut:
    published = await svc.publish_outbox(principal, limit=limit)
    return OutboxPublishOut(published=published)
