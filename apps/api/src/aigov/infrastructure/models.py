from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AISystemModel(Base):
    __tablename__ = "ai_systems"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    urn: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    system_type: Mapped[str] = mapped_column(String(64))
    business_purpose: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(200))
    environment: Mapped[str] = mapped_column(String(32))
    data_classification: Mapped[str] = mapped_column(String(32))
    geography: Mapped[str] = mapped_column(String(64))
    autonomy_level: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(64))
    registration: Mapped[dict] = mapped_column(JSON)
    human_oversight: Mapped[list] = mapped_column(JSON, default=list)
    current_version_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RiskAssessmentModel(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    score: Mapped[float] = mapped_column(Float)
    risk_band: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    drivers: Mapped[list] = mapped_column(JSON)
    hard_constraints: Mapped[list] = mapped_column(JSON)
    missing_inputs: Mapped[list] = mapped_column(JSON)
    engine_version: Mapped[str] = mapped_column(String(64))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApprovalModel(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    function: Mapped[str] = mapped_column(String(32))
    approved: Mapped[bool] = mapped_column(Boolean)
    actor_id: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PolicyDecisionModel(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    policy_bundle: Mapped[str] = mapped_column(String(128))
    reasons: Mapped[list] = mapped_column(JSON)
    required_actions: Mapped[list] = mapped_column(JSON)
    policy_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    aggregate_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(128))
    actor: Mapped[dict] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict] = mapped_column(JSON)
    hash: Mapped[str] = mapped_column(String(128))
    previous_event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)


class GovernanceDecisionModel(Base):
    __tablename__ = "governance_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    policy_decision_id: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    asset_version_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(128))
    snapshot: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DeploymentAuthorizationModel(Base):
    __tablename__ = "deployment_authorizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    decision_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_version_id: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str] = mapped_column(String(32))
    cloud: Mapped[str] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    audience: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    fingerprint: Mapped[str] = mapped_column(String(128))
    signature: Mapped[str] = mapped_column(String(128))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WorkflowCaseModel(Base):
    __tablename__ = "workflow_cases"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    case_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    risk_band: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason_codes: Mapped[list] = mapped_column(JSON)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExceptionModel(Base):
    __tablename__ = "exceptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    violation_code: Mapped[str] = mapped_column(String(64))
    control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bound_version_id: Mapped[str] = mapped_column(String(64), index=True)
    justification: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32))
    requested_by: Mapped[str] = mapped_column(String(64))
    granted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceArtifactModel(Base):
    __tablename__ = "evidence_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    bound_version_id: Mapped[str] = mapped_column(String(64), index=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(255))
    media_type: Mapped[str] = mapped_column(String(128))
    uri: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(128))
    bytes_size: Mapped[int] = mapped_column(Integer)
    collector_version: Mapped[str] = mapped_column(String(64))
    verification_status: Mapped[str] = mapped_column(String(32))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bound_version_id: Mapped[str] = mapped_column(String(64), index=True)
    finding_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    detector: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    recorded_by: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text)
    opened_by: Mapped[str] = mapped_column(String(64))
    resolved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CapabilityModel(Base):
    __tablename__ = "capabilities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    bound_version_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    resource_pattern: Mapped[str] = mapped_column(String(128))
    max_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean)
    approved: Mapped[bool] = mapped_column(Boolean)
    declared_by: Mapped[str] = mapped_column(String(64))
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    declared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ActionDecisionModel(Base):
    __tablename__ = "action_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(128))
    amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    capability_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reasons: Mapped[list] = mapped_column(JSON)
    required_actions: Mapped[list] = mapped_column(JSON)
    policy_bundle: Mapped[str] = mapped_column(String(128))
    policy_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(128))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ActionAuthorizationModel(Base):
    __tablename__ = "action_authorizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    decision_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_version_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(128))
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    fingerprint: Mapped[str] = mapped_column(String(128))
    signature: Mapped[str] = mapped_column(String(128))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RuntimeObservationModel(Base):
    __tablename__ = "runtime_observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    bound_version_id: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str] = mapped_column(String(32))
    cloud: Mapped[str] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    running: Mapped[bool] = mapped_column(Boolean)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_by: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReconciliationResultModel(Base):
    __tablename__ = "reconciliation_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    observation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list] = mapped_column(JSON)
    desired: Mapped[dict] = mapped_column(JSON)
    observed: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reconciled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EventOutboxModel(Base):
    __tablename__ = "event_outbox"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    aggregate_id: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    publish_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class GitHubCheckModel(Base):
    __tablename__ = "github_checks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    sha: Mapped[str] = mapped_column(String(64))
    repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32))
    conclusion: Mapped[str] = mapped_column(String(32))
    html_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RuntimeBindingModel(Base):
    __tablename__ = "runtime_bindings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    service: Mapped[str] = mapped_column(String(64))
    resource_ref: Mapped[str] = mapped_column(String(256))
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    account_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AdapterRunModel(Base):
    __tablename__ = "adapter_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    binding_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result: Mapped[dict] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
