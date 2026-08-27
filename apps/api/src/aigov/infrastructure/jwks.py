from __future__ import annotations

import json
import time
from typing import Any

import httpx

from aigov.config import Settings
from aigov.domains.identity.principal import AuthError


class JwksClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._cached: tuple[float, dict[str, Any]] | None = None

    async def get_jwks(self) -> dict[str, Any]:
        inline = (self._settings.oidc_jwks_json or "").strip()
        if inline:
            return _parse_jwks(inline)
        now = time.monotonic()
        ttl = max(0, int(self._settings.oidc_jwks_cache_seconds))
        if self._cached is not None and now < self._cached[0]:
            return self._cached[1]
        payload = await self._fetch_jwks()
        self._cached = (now + ttl, payload)
        return payload

    async def _fetch_jwks(self) -> dict[str, Any]:
        url = (self._settings.oidc_jwks_url or "").strip() or None
        issuer = (self._settings.oidc_issuer or "").rstrip("/")
        if url is None and issuer:
            url = await self._discover_jwks_uri(issuer)
        if not url:
            raise AuthError("OIDC JWKS URL is not configured", "AUTH_UNAVAILABLE")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise AuthError("OIDC JWKS is unreachable", "AUTH_UNAVAILABLE") from exc
        except ValueError as exc:
            raise AuthError("OIDC JWKS is invalid", "AUTH_UNAVAILABLE") from exc
        if not isinstance(payload, dict) or not payload.get("keys"):
            raise AuthError("OIDC JWKS is invalid", "AUTH_UNAVAILABLE")
        return payload

    async def _discover_jwks_uri(self, issuer: str) -> str:
        discovery = f"{issuer}/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(discovery)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise AuthError("OIDC discovery is unreachable", "AUTH_UNAVAILABLE") from exc
        except ValueError as exc:
            raise AuthError("OIDC discovery is invalid", "AUTH_UNAVAILABLE") from exc
        uri = (payload or {}).get("jwks_uri") if isinstance(payload, dict) else None
        if not isinstance(uri, str) or not uri.strip():
            raise AuthError("OIDC discovery is missing jwks_uri", "AUTH_UNAVAILABLE")
        return uri.strip()


def _parse_jwks(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthError("OIDC JWKS configuration is invalid", "AUTH_UNAVAILABLE") from exc
    if not isinstance(payload, dict) or not payload.get("keys"):
        raise AuthError("OIDC JWKS configuration is invalid", "AUTH_UNAVAILABLE")
    return payload
