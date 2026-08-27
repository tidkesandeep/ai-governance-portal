from __future__ import annotations

from dataclasses import dataclass


class AuthError(Exception):
    def __init__(self, detail: str, code: str = "UNAUTHORIZED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


CANONICAL_ROLES = frozenset(
    {"ml_engineer", "owner", "privacy", "security", "risk_reviewer"}
)

ROLE_ALIASES = {
    "engineer": "ml_engineer",
    "ml-engineer": "ml_engineer",
    "ml_engineer": "ml_engineer",
    "risk": "risk_reviewer",
    "risk-reviewer": "risk_reviewer",
    "risk_reviewer": "risk_reviewer",
}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    actor_type: str
    roles: tuple[str, ...]
    display_name: str
    auth_method: str = "demo"

    def has_role(self, *roles: str) -> bool:
        return any(role in self.roles for role in roles)


DEMO_PRINCIPALS: dict[str, Principal] = {
    "demo": Principal(
        tenant_id="demo",
        actor_id="u_engineer",
        actor_type="user",
        roles=("ml_engineer", "owner"),
        display_name="Demo Engineer",
        auth_method="demo",
    ),
    "demo-reviewer": Principal(
        tenant_id="demo",
        actor_id="u_reviewer",
        actor_type="user",
        roles=("privacy", "security", "risk_reviewer"),
        display_name="Demo Reviewer",
        auth_method="demo",
    ),
    "demo-other-tenant": Principal(
        tenant_id="acme",
        actor_id="u_acme",
        actor_type="user",
        roles=("ml_engineer",),
        display_name="Acme Engineer",
        auth_method="demo",
    ),
}


def principal_from_bearer(token: str | None, *, demo_auth: bool) -> Principal | None:
    if not token:
        return None
    if demo_auth:
        return DEMO_PRINCIPALS.get(token)
    return None
