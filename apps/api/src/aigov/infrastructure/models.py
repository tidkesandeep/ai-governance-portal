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
