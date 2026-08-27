from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    actor_type: str
    roles: tuple[str, ...]
    display_name: str

    def has_role(self, *roles: str) -> bool:
        return any(role in self.roles for role in roles)


DEMO_PRINCIPALS: dict[str, Principal] = {
    "demo": Principal(
        tenant_id="demo",
        actor_id="u_engineer",
        actor_type="user",
        roles=("ml_engineer", "owner"),
        display_name="Demo Engineer",
    ),
    "demo-reviewer": Principal(
        tenant_id="demo",
        actor_id="u_reviewer",
        actor_type="user",
        roles=("privacy", "security", "risk_reviewer"),
        display_name="Demo Reviewer",
    ),
    "demo-other-tenant": Principal(
        tenant_id="acme",
        actor_id="u_acme",
        actor_type="user",
        roles=("ml_engineer",),
        display_name="Acme Engineer",
    ),
}


def principal_from_bearer(token: str | None, *, demo_auth: bool) -> Principal | None:
    if not token:
        return None
    if demo_auth:
        return DEMO_PRINCIPALS.get(token)
    return None
