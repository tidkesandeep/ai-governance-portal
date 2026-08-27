from aigov.api.routers.health import router as health_router
from aigov.api.routers.identity import router as identity_router
from aigov.api.routers.systems import router as systems_router

__all__ = ["health_router", "identity_router", "systems_router"]
