-- Slice 10: runtime bindings and execution-plane adapter runs

CREATE TABLE IF NOT EXISTS runtime_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    provider TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    region TEXT,
    account_ref TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_runtime_bindings_system ON runtime_bindings (tenant_id, system_id, status);

CREATE TABLE IF NOT EXISTS adapter_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    binding_id TEXT NOT NULL REFERENCES runtime_bindings (id),
    kind TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    action TEXT,
    result JSONB NOT NULL,
    error TEXT,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_adapter_runs_system ON adapter_runs (tenant_id, system_id, recorded_at);
