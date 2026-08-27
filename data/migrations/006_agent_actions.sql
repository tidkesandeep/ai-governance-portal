-- Slice 6: agent capabilities and action authorization

CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    bound_version_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    max_amount DOUBLE PRECISION,
    requires_approval BOOLEAN NOT NULL,
    approved BOOLEAN NOT NULL,
    declared_by TEXT NOT NULL,
    approved_by TEXT,
    declared_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_capabilities_system ON capabilities (tenant_id, system_id);

CREATE TABLE IF NOT EXISTS action_decisions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    outcome TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    amount DOUBLE PRECISION,
    capability_id TEXT,
    reasons JSONB NOT NULL,
    required_actions JSONB NOT NULL,
    policy_bundle TEXT NOT NULL,
    policy_digest TEXT,
    input_digest TEXT,
    fingerprint TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_decisions_system ON action_decisions (tenant_id, system_id);

CREATE TABLE IF NOT EXISTS action_authorizations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    decision_id TEXT NOT NULL,
    asset_version_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_action_authorizations_system ON action_authorizations (tenant_id, system_id);
