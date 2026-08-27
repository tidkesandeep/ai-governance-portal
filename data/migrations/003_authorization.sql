-- Slice 3: immutable governance snapshots and short-lived deployment authorizations

CREATE TABLE IF NOT EXISTS governance_decisions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    policy_decision_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    asset_version_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gov_decisions_system ON governance_decisions (tenant_id, system_id);

CREATE TABLE IF NOT EXISTS deployment_authorizations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    decision_id TEXT NOT NULL,
    asset_version_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    cloud TEXT NOT NULL,
    region TEXT,
    audience TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_authz_system ON deployment_authorizations (tenant_id, system_id);
