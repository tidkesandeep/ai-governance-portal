from fastapi import APIRouter

from aigov.api.schemas import HealthStatus

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthStatus)
async def health() -> HealthStatus:
    return HealthStatus(status="ok")


@router.get("/ready", response_model=HealthStatus)
async def ready() -> HealthStatus:
    return HealthStatus(status="ok", details={"database": "ok"})
