from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AIGOV_", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./aigov.db"
    opa_url: str | None = None
    cors_origins: str = "http://localhost:3000"
    demo_auth: bool = True
    log_level: str = "INFO"
    policy_bundle: str = "payments-baseline@0.2.0"
    risk_engine_version: str = "risk-engine@2.0.0"
    evidence_dir: str = "./data/evidence"
    evidence_max_bytes: int = 512000
    collector_version: str = "evidence-collector@0.2.0"
    authorization_secret: str = "dev-only-authorization-secret"
    authorization_ttl_seconds: int = 900
    action_authorization_ttl_seconds: int = 60
    observation_max_age_seconds: int = 900
    oidc_issuer: str | None = None
    oidc_audience: str = "aigov-api"
    oidc_jwks_url: str | None = None
    oidc_jwks_json: str | None = None
    oidc_tenant_claim: str = "tid"
    oidc_roles_claim: str = "roles"
    oidc_jwks_cache_seconds: int = 300
    kafka_bootstrap_servers: str | None = None
    kafka_topic: str = "aigov.governance.events"
    github_webhook_secret: str = ""
    github_token: str | None = None
    api_url: str = "http://localhost:8000"

    @property
    def cors_origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
