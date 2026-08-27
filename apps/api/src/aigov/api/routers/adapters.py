from __future__ import annotations

from fastapi import APIRouter, Depends

from aigov.api.deps import settings_dep
from aigov.api.schemas import AdapterStatusOut
from aigov.config import Settings
from aigov.infrastructure.adapters import execution_plane_from_settings

router = APIRouter(prefix="/v1/adapters", tags=["Adapters"])


@router.get("", response_model=AdapterStatusOut)
async def adapter_status(settings: Settings = Depends(settings_dep)) -> AdapterStatusOut:
    plane = execution_plane_from_settings(settings)
    return AdapterStatusOut(
        mode=plane.mode,
        providers=plane.providers,
        objectStore=settings.object_store,
    )
