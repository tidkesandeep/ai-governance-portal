from __future__ import annotations

import json
from typing import Any

import jwt

from aigov.domains.identity.principal import (
    CANONICAL_ROLES,
    ROLE_ALIASES,
    AuthError,
    Principal,
)

ALLOWED_ALGS = ("RS256", "ES256", "PS256")
LEEWAY_SECONDS = 30


def principal_from_jwt(
    token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
    tenant_claim: str = "tid",
    roles_claim: str = "roles",
) -> Principal:
    claims = _decode_claims(token, jwks=jwks, issuer=issuer, audience=audience)
    actor_id = str(claims.get("sub") or "").strip()
    if not actor_id:
        raise AuthError("token is missing sub", "INVALID_TOKEN")
    tenant_id = _claim_tenant(claims, tenant_claim)
    if not tenant_id:
        raise AuthError("token is missing a tenant claim", "TENANT_CLAIM_MISSING")
    display = str(
        claims.get("name") or claims.get("preferred_username") or actor_id
    ).strip()
    actor_type = "service" if _is_service(claims) else "user"
    return Principal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_type=actor_type,
        roles=_map_roles(_claim_roles(claims, roles_claim)),
        display_name=display,
        auth_method="oidc",
    )


def _decode_claims(
    token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise AuthError("token header is invalid", "INVALID_TOKEN") from exc
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise AuthError("token algorithm is not allowed", "INVALID_TOKEN")
    key = _signing_key(header, jwks, alg)
    try:
        payload = jwt.decode(
            token,
            key=key,
            algorithms=list(ALLOWED_ALGS),
            issuer=issuer.rstrip("/"),
            audience=audience,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token is expired", "INVALID_TOKEN") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("token is invalid", "INVALID_TOKEN") from exc
    if not isinstance(payload, dict):
        raise AuthError("token is invalid", "INVALID_TOKEN")
    return payload


def _signing_key(header: dict[str, Any], jwks: dict[str, Any], alg: str) -> Any:
    keys = [item for item in (jwks.get("keys") or []) if isinstance(item, dict)]
    kid = header.get("kid")
    selected: dict[str, Any] | None = None
    if kid:
        selected = next((item for item in keys if item.get("kid") == kid), None)
    elif len(keys) == 1:
        selected = keys[0]
    if selected is None:
        raise AuthError("signing key not found", "INVALID_TOKEN")
    try:
        algorithm = jwt.get_algorithm_by_name(selected.get("alg") or alg)
        return algorithm.from_jwk(json.dumps(selected))
    except (jwt.InvalidKeyError, ValueError, TypeError) as exc:
        raise AuthError("signing key is invalid", "INVALID_TOKEN") from exc


def _claim_tenant(claims: dict[str, Any], tenant_claim: str) -> str | None:
    for key in (tenant_claim, "tid", "tenant_id", "org_id"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _claim_roles(claims: dict[str, Any], roles_claim: str) -> list[str]:
    raw = claims.get(roles_claim)
    if raw is None:
        raw = (claims.get("realm_access") or {}).get("roles")
    if isinstance(raw, str):
        return [part for part in raw.replace(",", " ").split() if part]
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return []


def _map_roles(raw: list[str]) -> tuple[str, ...]:
    mapped: list[str] = []
    for role in raw:
        key = role.strip().lower().replace("-", "_").replace(" ", "_")
        canonical = ROLE_ALIASES.get(key, key)
        if canonical in CANONICAL_ROLES:
            mapped.append(canonical)
    return tuple(dict.fromkeys(mapped))


def _is_service(claims: dict[str, Any]) -> bool:
    token_use = str(claims.get("token_use") or claims.get("typ") or "").lower()
    actor_type = str(claims.get("actor_type") or "").lower()
    return token_use in {"client_credentials", "at+jwt"} or actor_type == "service"
