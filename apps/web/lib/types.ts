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

export type AISystem360 = {
  system: AISystem;
  registration: Record<string, unknown>;
  latestAssessment?: RiskAssessment | null;
  latestDecision?: PolicyDecision | null;
  approvals: Approval[];
  humanOversight: string[];
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
