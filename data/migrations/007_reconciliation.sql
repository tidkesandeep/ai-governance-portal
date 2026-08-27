-- Slice 7: desired versus observed reconciliation

CREATE TABLE IF NOT EXISTS runtime_observations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    bound_version_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    cloud TEXT NOT NULL,
    region TEXT,
    fingerprint TEXT,
    running BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runtime_observations_system ON runtime_observations (tenant_id, system_id);

CREATE TABLE IF NOT EXISTS reconciliation_results (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    observation_id TEXT,
    status TEXT NOT NULL,
    reasons JSONB NOT NULL,
    desired JSONB NOT NULL,
    observed JSONB,
    reconciled_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reconciliation_results_system ON reconciliation_results (tenant_id, system_id);
