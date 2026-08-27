export type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type GateOutcome = "ALLOW" | "REVIEW" | "BLOCK";

export type AISystem = {
  id: string;
  urn: string;
  tenantId: string;
  name: string;
  systemType: string;
  businessPurpose: string;
  owner: string;
  environment: string;
  dataClassification: string;
  geography: string;
  autonomyLevel: string;
  status: string;
  riskBand?: string | null;
  currentVersionId?: string;
  createdAt: string;
  updatedAt?: string | null;
};

export type RiskDriver = { code: string; contribution: number; detail?: string | null };

export type RiskAssessment = {
  id: string;
  systemId: string;
  score: number;
  riskBand: RiskBand;
  confidence: number;
  drivers: RiskDriver[];
  hardConstraints: string[];
  missingInputs: string[];
  engineVersion: string;
  assessedAt: string;
};

export type PolicyReason = { code: string; severity: string; message?: string | null };

export type PolicyDecision = {
  id: string;
  systemId: string;
  outcome: GateOutcome;
  policyBundle: string;
  reasons: PolicyReason[];
  requiredActions: string[];
  policyDigest?: string | null;
  inputDigest?: string | null;
  decidedAt: string;
  fingerprint?: string | null;
  snapshotId?: string | null;
  authorizationId?: string | null;
};

export type GovernanceSnapshot = {
  id: string;
  systemId: string;
  policyDecisionId: string;
  outcome: GateOutcome;
  assetVersionId: string;
  fingerprint: string;
  snapshot: Record<string, unknown>;
  createdAt: string;
};

export type DeploymentAuthorization = {
  id: string;
  systemId: string;
  decisionId: string;
  assetVersionId: string;
  environment: string;
  cloud: string;
  region?: string | null;
  audience: string;
  nonce: string;
  fingerprint: string;
  signature: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string | null;
  consumedAt?: string | null;
};

export type AuthorizationVerify = {
  outcome: "ALLOW" | "DENY";
  reasons: string[];
  authorization: DeploymentAuthorization;
};

export type WorkflowCase = {
  id: string;
  systemId: string;
  decisionId?: string | null;
  snapshotId?: string | null;
  caseType: string;
  status: string;
  riskBand?: string | null;
  reasonCodes: string[];
  slaStatus: string;
  openedAt: string;
  dueAt: string;
  closedAt?: string | null;
};

export type GovernanceException = {
  id: string;
  systemId: string;
  caseId?: string | null;
  violationCode: string;
  controlId?: string | null;
  boundVersionId: string;
  justification: string;
  status: string;
  requestedBy: string;
  grantedBy?: string | null;
  requestedAt: string;
  grantedAt?: string | null;
  expiresAt: string;
  revokedAt?: string | null;
};

export type Approval = {
  function: string;
  approved: boolean;
  actorId: string;
  recordedAt: string;
};

export type AuditEvent = {
  eventId: string;
  eventType: string;
  aggregateId: string;
  actor: Record<string, string>;
  occurredAt: string;
  payload: Record<string, unknown>;
  hash: string;
  previousEventHash?: string | null;
};

export type EvidenceArtifact = {
  id: string;
  systemId: string;
  boundVersionId: string;
  type: string;
  filename: string;
  uri: string;
  sha256: string;
  bytesSize: number;
  collectorVersion: string;
  verificationStatus: string;
  collectedAt: string;
  createdAt: string;
};

export type ControlAssessment = {
  controlId: string;
  evidenceType: string;
  required: boolean;
  status: string;
  evidenceId?: string | null;
  reason: string;
  maxAgeDays: number;
  sha256?: string | null;
};

export type AISystem360 = {
  system: AISystem;
  registration: Record<string, unknown>;
  latestAssessment?: RiskAssessment | null;
  latestDecision?: PolicyDecision | null;
  approvals: Approval[];
  humanOversight: string[];
  evidence: EvidenceArtifact[];
  controls: ControlAssessment[];
  latestSnapshot?: GovernanceSnapshot | null;
  latestAuthorization?: DeploymentAuthorization | null;
  latestCase?: WorkflowCase | null;
  cases: WorkflowCase[];
  exceptions: GovernanceException[];
};

export type Registration = {
  name: string;
  systemType: string;
  businessPurpose: string;
  owner: string;
  environment: string;
  dataClassification: string;
  geography: string;
  autonomyLevel: string;
  customerImpact: string;
  financialImpact: string;
  usesCustomerDecision: boolean;
  publicEndpoint: boolean;
  monitoringEnabled: boolean;
  evaluationRefs: string[];
  humanOversight: string[];
  modelRefs: string[];
};
