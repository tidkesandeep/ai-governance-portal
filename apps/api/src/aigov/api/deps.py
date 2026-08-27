from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.application.governance import GovernanceService
from aigov.config import Settings, get_settings
from aigov.domains.identity.principal import AuthError, Principal
from aigov.domains.identity.service import resolve_principal
from aigov.domains.policy.engine import EmbeddedPolicyEngine, PolicyEngine
from aigov.infrastructure.db import session_scope
from aigov.infrastructure.jwks import JwksClient
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


def jwks_client(settings: Settings = Depends(settings_dep)) -> JwksClient:
    return JwksClient(settings)


async def current_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(settings_dep),
    keys: JwksClient = Depends(jwks_client),
) -> Principal:
    token = creds.credentials if creds else request.headers.get("x-demo-token")
    try:
        return await resolve_principal(token, settings=settings, jwks_client=keys)
    except AuthError as exc:
        status = 503 if exc.code == "AUTH_UNAVAILABLE" else 401
        raise HTTPException(
            status_code=status,
            detail={
                "type": "https://api.aigov.local/problems/unauthorized",
                "title": "Unauthorized" if status == 401 else "Identity provider unavailable",
                "status": status,
                "code": exc.code,
                "detail": exc.detail,
            },
        ) from exc


def governance_service(
    session: AsyncSession = Depends(db_session),
    engine: PolicyEngine = Depends(policy_engine),
    settings: Settings = Depends(settings_dep),
) -> GovernanceService:
    store = LocalObjectStore(settings.evidence_dir)
    return GovernanceService(session, engine, store, settings)
