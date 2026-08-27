-- Slice 2: evidence artifacts and asset version binding

ALTER TABLE ai_systems ADD COLUMN IF NOT EXISTS current_version_id TEXT;

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES ai_systems (id),
    bound_version_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    filename TEXT NOT NULL,
    media_type TEXT NOT NULL,
    uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes_size INTEGER NOT NULL,
    collector_version TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_system ON evidence_artifacts (tenant_id, system_id);
