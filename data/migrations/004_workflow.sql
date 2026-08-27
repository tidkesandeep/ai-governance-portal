-- Slice 4: workflow cases, time-bounded exceptions, SLA clocks

CREATE TABLE IF NOT EXISTS workflow_cases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    decision_id TEXT,
    snapshot_id TEXT,
    case_type TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_band TEXT,
    reason_codes JSONB NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_workflow_cases_system ON workflow_cases (tenant_id, system_id);

CREATE TABLE IF NOT EXISTS exceptions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    case_id TEXT REFERENCES workflow_cases (id),
    violation_code TEXT NOT NULL,
    control_id TEXT,
    bound_version_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    granted_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL,
    granted_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exceptions_system ON exceptions (tenant_id, system_id);
