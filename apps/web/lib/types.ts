export type Principal = {
  tenantId: string;
  actorId: string;
  actorType: string;
  roles: string[];
  displayName: string;
  authMethod: "demo" | "oidc" | string;
};

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

export type Finding = {
  id: string;
  systemId: string;
  incidentId?: string | null;
  boundVersionId: string;
  findingType: string;
  severity: string;
  summary: string;
  detector: string;
  status: string;
  recordedBy: string;
  recordedAt: string;
  resolvedAt?: string | null;
  dismissedAt?: string | null;
};

export type Incident = {
  id: string;
  systemId: string;
  severity: string;
  status: string;
  title: string;
  summary: string;
  openedBy: string;
  resolvedBy?: string | null;
  openedAt: string;
  resolvedAt?: string | null;
};

export type Capability = {
  id: string;
  systemId: string;
  boundVersionId: string;
  action: string;
  resourcePattern: string;
  maxAmount?: number | null;
  requiresApproval: boolean;
  approved: boolean;
  declaredBy: string;
  approvedBy?: string | null;
  declaredAt: string;
  approvedAt?: string | null;
  revokedAt?: string | null;
};

export type ActionDecision = {
  id: string;
  systemId: string;
  outcome: "ALLOW" | "DENY";
  action: string;
  resource: string;
  amount?: number | null;
  capabilityId?: string | null;
  reasons: PolicyReason[];
  requiredActions: string[];
  policyBundle: string;
  policyDigest?: string | null;
  inputDigest?: string | null;
  fingerprint: string;
  authorizationId?: string | null;
  decidedAt: string;
};

export type ActionAuthorization = {
  id: string;
  systemId: string;
  decisionId: string;
  assetVersionId: string;
  action: string;
  resource: string;
  nonce: string;
  fingerprint: string;
  signature: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string | null;
  consumedAt?: string | null;
};

export type ActionAuthorizationVerify = {
  outcome: "ALLOW" | "DENY";
  reasons: string[];
  authorization: ActionAuthorization;
};

export type RuntimeObservation = {
  id: string;
  systemId: string;
  boundVersionId: string;
  environment: string;
  cloud: string;
  region?: string | null;
  fingerprint?: string | null;
  running: boolean;
  observedAt: string;
  recordedBy: string;
  recordedAt: string;
};

export type ReconciliationResult = {
  id: string;
  systemId: string;
  observationId?: string | null;
  status: "IN_SYNC" | "DRIFT" | "UNKNOWN";
  reasons: PolicyReason[];
  desired: Record<string, unknown>;
  observed?: Record<string, unknown> | null;
  reconciledAt: string;
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
  findings: Finding[];
  incidents: Incident[];
  latestIncident?: Incident | null;
  capabilities: Capability[];
  latestActionDecision?: ActionDecision | null;
  latestActionAuthorization?: ActionAuthorization | null;
  latestObservation?: RuntimeObservation | null;
  latestReconciliation?: ReconciliationResult | null;
  latestOutboxEvents?: OutboxEvent[];
  githubChecks?: GitHubCheck[];
  latestGithubCheck?: GitHubCheck | null;
  runtimeBinding?: RuntimeBinding | null;
  adapterRuns?: AdapterRun[];
  latestAdapterRun?: AdapterRun | null;
};

export type RuntimeBinding = {
  id: string;
  systemId: string;
  provider: string;
  service: string;
  resourceRef: string;
  region?: string | null;
  accountRef?: string | null;
  status: string;
  createdAt: string;
  supersededAt?: string | null;
};

export type AdapterRun = {
  id: string;
  systemId: string;
  bindingId: string;
  kind: string;
  provider: string;
  status: string;
  action?: string | null;
  result: Record<string, unknown>;
  error?: string | null;
  recordedAt: string;
};

export type OutboxEvent = {
  id: string;
  eventId: string;
  eventType: string;
  aggregateId: string;
  occurredAt: string;
  publishedAt?: string | null;
  publishAttempts: number;
  lastError?: string | null;
};

export type GitHubCheck = {
  id: string;
  systemId: string;
  sha: string;
  repo?: string | null;
  name: string;
  status: string;
  conclusion: string;
  htmlUrl?: string | null;
  decisionId?: string | null;
  recordedAt: string;
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
