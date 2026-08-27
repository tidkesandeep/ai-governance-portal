from __future__ import annotations

from aigov.config import Settings
from aigov.domains.identity.oidc import principal_from_jwt
from aigov.domains.identity.principal import AuthError, Principal, principal_from_bearer
from aigov.infrastructure.jwks import JwksClient


async def resolve_principal(
    token: str | None,
    *,
    settings: Settings,
    jwks_client: JwksClient,
) -> Principal:
    if not token or not token.strip():
        raise AuthError("missing bearer token", "UNAUTHORIZED")
    demo = principal_from_bearer(token.strip(), demo_auth=settings.demo_auth)
    if demo is not None:
        return demo
    issuer = (settings.oidc_issuer or "").strip()
    if not issuer:
        if settings.demo_auth:
            raise AuthError("unknown bearer token", "UNAUTHORIZED")
        raise AuthError("OIDC issuer is not configured", "AUTH_UNAVAILABLE")
    jwks = await jwks_client.get_jwks()
    return principal_from_jwt(
        token.strip(),
        jwks=jwks,
        issuer=issuer,
        audience=settings.oidc_audience,
        tenant_claim=settings.oidc_tenant_claim,
        roles_claim=settings.oidc_roles_claim,
    )
