from fastapi import APIRouter

from aigov.api.schemas import HealthStatus
from aigov.config import get_settings

router = APIRouter(tags=["Health"])


def _auth_status() -> str:
    settings = get_settings()
    if (settings.oidc_issuer or "").strip():
        return "oidc"
    if settings.demo_auth:
        return "demo"
    return "unconfigured"


@router.get("/health", response_model=HealthStatus)
async def health() -> HealthStatus:
    return HealthStatus(status="ok", details={"auth": _auth_status()})


@router.get("/ready", response_model=HealthStatus)
async def ready() -> HealthStatus:
    return HealthStatus(status="ok", details={"database": "ok", "auth": _auth_status()})
