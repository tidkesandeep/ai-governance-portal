-- Slice 9: transactional outbox and GitHub deployment checks

CREATE TABLE IF NOT EXISTS event_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_event_outbox_unpublished ON event_outbox (published_at, occurred_at);
CREATE INDEX IF NOT EXISTS idx_event_outbox_aggregate ON event_outbox (tenant_id, aggregate_id);

CREATE TABLE IF NOT EXISTS github_checks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    sha TEXT NOT NULL,
    repo TEXT,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    html_url TEXT,
    decision_id TEXT,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_github_checks_system ON github_checks (tenant_id, system_id);
