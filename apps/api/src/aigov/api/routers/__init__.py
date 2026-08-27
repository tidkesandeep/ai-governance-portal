from aigov.api.routers.adapters import router as adapters_router
from aigov.api.routers.health import router as health_router
from aigov.api.routers.identity import router as identity_router
from aigov.api.routers.integrations import router as integrations_router
from aigov.api.routers.outbox import router as outbox_router
from aigov.api.routers.systems import router as systems_router

__all__ = [
    "adapters_router",
    "health_router",
    "identity_router",
    "integrations_router",
    "outbox_router",
    "systems_router",
]
