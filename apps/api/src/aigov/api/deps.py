from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.application.governance import GovernanceService
from aigov.config import Settings, get_settings
from aigov.domains.identity.principal import Principal, principal_from_bearer
from aigov.domains.policy.engine import EmbeddedPolicyEngine, PolicyEngine
from aigov.infrastructure.db import session_scope
from aigov.infrastructure.object_store import LocalObjectStore
from aigov.infrastructure.opa import OPAPolicyEngine

_bearer = HTTPBearer(auto_error=False)


def settings_dep() -> Settings:
    return get_settings()


async def db_session() -> AsyncSession:
    async for session in session_scope():
        yield session


def policy_engine(settings: Settings = Depends(settings_dep)) -> PolicyEngine:
    if settings.opa_url:
        return OPAPolicyEngine(settings.opa_url)
    return EmbeddedPolicyEngine()


async def current_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(settings_dep),
) -> Principal:
    token = creds.credentials if creds else request.headers.get("x-demo-token")
    principal = principal_from_bearer(token, demo_auth=settings.demo_auth)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail={
                "type": "https://api.aigov.local/problems/unauthorized",
                "title": "Unauthorized",
                "status": 401,
                "code": "UNAUTHORIZED",
                "detail": "Provide Authorization: Bearer demo or Bearer demo-reviewer",
            },
        )
    return principal


def governance_service(
    session: AsyncSession = Depends(db_session),
    engine: PolicyEngine = Depends(policy_engine),
    settings: Settings = Depends(settings_dep),
) -> GovernanceService:
    store = LocalObjectStore(settings.evidence_dir)
    return GovernanceService(session, engine, store, settings)
