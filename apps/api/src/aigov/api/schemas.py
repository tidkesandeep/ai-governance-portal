from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SystemType = Literal["PREDICTIVE_MODEL", "GENAI_APP", "AGENT", "THIRD_PARTY_LLM", "DATASET"]
Environment = Literal["dev", "test", "staging", "production"]
DataClassification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "PCI", "RESTRICTED"]
AutonomyLevel = Literal["HUMAN_IN_LOOP", "ASSISTIVE", "SEMI_AUTONOMOUS", "AUTONOMOUS"]
ImpactLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AISystemRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    systemType: SystemType
    businessPurpose: str
    owner: str
    environment: Environment
    dataClassification: DataClassification
    geography: str
    autonomyLevel: AutonomyLevel
    modelRefs: list[str] = Field(default_factory=list)
    vendorRefs: list[str] = Field(default_factory=list)
    intendedUsers: str | None = None
    customerImpact: ImpactLevel | None = None
    financialImpact: ImpactLevel | None = None
    humanOversight: list[str] = Field(default_factory=list)
    knownLimitations: str | None = None
    usesCustomerDecision: bool = False
    publicEndpoint: bool = False
    evaluationRefs: list[str] = Field(default_factory=list)
    monitoringEnabled: bool = False


class ApprovalRequest(BaseModel):
    function: Literal["privacy", "security", "risk", "owner"]
    approved: bool = True


class OversightRequest(BaseModel):
    controls: list[str] = Field(min_length=1)


class DeploymentGateRequest(BaseModel):
    environment: Environment | None = None
    evidenceStale: bool = False
    cloud: str = "local"
    region: str | None = None
    audience: str = "cicd"


EvidenceType = Literal[
    "MODEL_CARD",
    "EVALUATION_RUN",
    "FAIRNESS_EVALUATION",
    "SECURITY_SCAN",
    "SBOM",
]


class EvidenceAttachRequest(BaseModel):
    type: EvidenceType
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)
    collectedAt: datetime | None = None
    boundVersionId: str | None = None
    mediaType: str = "text/plain"


class EvidenceArtifactOut(BaseModel):
    id: str
    systemId: str
    boundVersionId: str
    type: str
    filename: str
    uri: str
    sha256: str
    bytesSize: int
    collectorVersion: str
    verificationStatus: str
    collectedAt: datetime
    createdAt: datetime


class ControlAssessmentOut(BaseModel):
    controlId: str
    evidenceType: str
    required: bool
    status: str
    evidenceId: str | None = None
    reason: str
    maxAgeDays: int
    sha256: str | None = None


class HealthStatus(BaseModel):
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class Problem(BaseModel):
    type: str
    title: str
    status: int
    code: str
    detail: str | None = None
    traceId: str | None = None
    reasons: list[str] = Field(default_factory=list)


class RiskDriverOut(BaseModel):
    code: str
    contribution: float
    detail: str | None = None


class RiskAssessmentOut(BaseModel):
    id: str
    systemId: str
    score: float
    riskBand: str
    confidence: float
    drivers: list[RiskDriverOut]
    hardConstraints: list[str]
    missingInputs: list[str]
    engineVersion: str
    assessedAt: datetime


class PolicyReasonOut(BaseModel):
    code: str
    severity: str
    message: str | None = None


class PolicyDecisionOut(BaseModel):
    id: str
    systemId: str
    outcome: str
    policyBundle: str
    reasons: list[PolicyReasonOut]
    requiredActions: list[str]
    policyDigest: str | None = None
    inputDigest: str | None = None
    decidedAt: datetime
    fingerprint: str | None = None
    snapshotId: str | None = None
    authorizationId: str | None = None


class GovernanceSnapshotOut(BaseModel):
    id: str
    systemId: str
    policyDecisionId: str
    outcome: str
    assetVersionId: str
    fingerprint: str
    snapshot: dict[str, Any]
    createdAt: datetime


class DeploymentAuthorizationOut(BaseModel):
    id: str
    systemId: str
    decisionId: str
    assetVersionId: str
    environment: str
    cloud: str
    region: str | None = None
    audience: str
    nonce: str
    fingerprint: str
    signature: str
    issuedAt: datetime
    expiresAt: datetime
    revokedAt: datetime | None = None
    consumedAt: datetime | None = None


class AuthorizationVerifyRequest(BaseModel):
    signature: str | None = None
    consume: bool = False


class AuthorizationVerifyOut(BaseModel):
    outcome: Literal["ALLOW", "DENY"]
    reasons: list[str] = Field(default_factory=list)
    authorization: DeploymentAuthorizationOut


class ExceptionRequest(BaseModel):
    violationCode: str = Field(min_length=1, max_length=64)
    justification: str = Field(min_length=8, max_length=2000)
    expiresAt: datetime | None = None
    controlId: str | None = None


class WorkflowCaseOut(BaseModel):
    id: str
    systemId: str
    decisionId: str | None = None
    snapshotId: str | None = None
    caseType: str
    status: str
    riskBand: str | None = None
    reasonCodes: list[str] = Field(default_factory=list)
    slaStatus: str
    openedAt: datetime
    dueAt: datetime
    closedAt: datetime | None = None


class ExceptionOut(BaseModel):
    id: str
    systemId: str
    caseId: str | None = None
    violationCode: str
    controlId: str | None = None
    boundVersionId: str
    justification: str
    status: str
    requestedBy: str
    grantedBy: str | None = None
    requestedAt: datetime
    grantedAt: datetime | None = None
    expiresAt: datetime
    revokedAt: datetime | None = None


class ApprovalOut(BaseModel):
    function: str
    approved: bool
    actorId: str
    recordedAt: datetime


class AISystemOut(BaseModel):
    id: str
    urn: str
    tenantId: str
    name: str
    systemType: str
    businessPurpose: str
    owner: str
    environment: str
    dataClassification: str
    geography: str
    autonomyLevel: str
    status: str
    riskBand: str | None = None
    currentVersionId: str
    createdAt: datetime
    updatedAt: datetime | None = None


class AISystemListOut(BaseModel):
    items: list[AISystemOut]


class AISystem360Out(BaseModel):
    system: AISystemOut
    registration: dict[str, Any]
    latestAssessment: RiskAssessmentOut | None = None
    latestDecision: PolicyDecisionOut | None = None
    approvals: list[ApprovalOut] = Field(default_factory=list)
    humanOversight: list[str] = Field(default_factory=list)
    evidence: list[EvidenceArtifactOut] = Field(default_factory=list)
    controls: list[ControlAssessmentOut] = Field(default_factory=list)
    latestSnapshot: GovernanceSnapshotOut | None = None
    latestAuthorization: DeploymentAuthorizationOut | None = None
    latestCase: WorkflowCaseOut | None = None
    cases: list[WorkflowCaseOut] = Field(default_factory=list)
    exceptions: list[ExceptionOut] = Field(default_factory=list)


class AuditEventOut(BaseModel):
    eventId: str
    eventType: str
    aggregateId: str
    actor: dict[str, Any]
    occurredAt: datetime
    payload: dict[str, Any]
    hash: str
    previousEventHash: str | None = None


class AuditEventListOut(BaseModel):
    items: list[AuditEventOut]
