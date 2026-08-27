"""Slice-1 schema snapshot. PostgreSQL is the system of record; SQLAlchemy create_all is used at boot until Alembic lands."""

-- tenants are logical; tenant_id is denormalized onto every row
CREATE TABLE IF NOT EXISTS ai_systems (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    urn TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    system_type TEXT NOT NULL,
    business_purpose TEXT NOT NULL,
    owner TEXT NOT NULL,
    environment TEXT NOT NULL,
    data_classification TEXT NOT NULL,
    geography TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    status TEXT NOT NULL,
    registration JSONB NOT NULL,
    human_oversight JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_systems_tenant ON ai_systems (tenant_id);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    score DOUBLE PRECISION NOT NULL,
    risk_band TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    drivers JSONB NOT NULL,
    hard_constraints JSONB NOT NULL,
    missing_inputs JSONB NOT NULL,
    engine_version TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    function TEXT NOT NULL,
    approved BOOLEAN NOT NULL,
    actor_id TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    outcome TEXT NOT NULL,
    policy_bundle TEXT NOT NULL,
    reasons JSONB NOT NULL,
    required_actions JSONB NOT NULL,
    policy_digest TEXT,
    input_digest TEXT,
    decided_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    hash TEXT NOT NULL,
    previous_event_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_aggregate ON audit_events (tenant_id, aggregate_id, occurred_at);
