from __future__ import annotations

from fastapi import APIRouter, Depends

from aigov.api.deps import current_principal
from aigov.api.schemas import PrincipalOut
from aigov.domains.identity.principal import Principal

router = APIRouter(prefix="/v1", tags=["Identity"])


@router.get("/me", response_model=PrincipalOut)
async def read_me(principal: Principal = Depends(current_principal)) -> PrincipalOut:
    return PrincipalOut(
        tenantId=principal.tenant_id,
        actorId=principal.actor_id,
        actorType=principal.actor_type,
        roles=list(principal.roles),
        displayName=principal.display_name,
        authMethod=principal.auth_method,
    )
