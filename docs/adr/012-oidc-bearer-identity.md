# ADR-012: OIDC bearer identity

## Status

Accepted

## Context

Demo bearer tokens (`demo`, `demo-reviewer`) prove SoD and tenant isolation locally. They are not an identity system. Production principals must come from the organization's IdP. Tenant must never be taken from a request body.

## Decision

- The control plane authenticates **Bearer JWTs** issued by a configured OIDC issuer. Signature is verified against JWKS (`RS256`, `ES256`, or `PS256` only). `alg=none` and HMAC algorithms are rejected.
- Required claims: `iss`, `aud`, `exp`, `sub`, and a tenant claim (`tid` by default). Roles map onto the existing SoD roles (`ml_engineer`, `owner`, `privacy`, `security`, `risk_reviewer`).
- Tenant, actor, and roles are taken only from the validated token. The API does not trust `X-Tenant-Id` or body fields.
- `AIGOV_DEMO_AUTH=true` (local/CI default) still accepts the static demo tokens. When it is `false`, demo tokens are rejected and OIDC is required. Missing issuer/JWKS or an unreachable JWKS endpoint fails closed (`AUTH_UNAVAILABLE`).
- `GET /v1/me` returns the bound principal so the portal can display tenant, roles, and whether the session is `demo` or `oidc`.

## Consequences

Local tests keep using `Bearer demo`. A production or staging deploy points `AIGOV_OIDC_ISSUER` / `AIGOV_OIDC_AUDIENCE` at the IdP. CI/CD and collectors present client-credentials JWTs on the same path.
