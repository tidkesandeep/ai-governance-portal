import type { Registration } from "./types";

export const FRAUD_SAMPLE: Registration = {
  name: "Fraud Risk Model v4.2",
  systemType: "PREDICTIVE_MODEL",
  businessPurpose: "Score payment transactions for fraud before authorization.",
  owner: "payments-ml",
  environment: "production",
  dataClassification: "PII",
  geography: "EU",
  autonomyLevel: "ASSISTIVE",
  customerImpact: "HIGH",
  financialImpact: "HIGH",
  usesCustomerDecision: true,
  publicEndpoint: false,
  monitoringEnabled: false,
  evaluationRefs: [],
  humanOversight: [],
  modelRefs: ["model:fraud-v4.2"],
};

export const INTERNAL_SAMPLE: Registration = {
  name: "Weekly cohort rollup",
  systemType: "PREDICTIVE_MODEL",
  businessPurpose: "Internal analytics with no customer decisioning.",
  owner: "analytics",
  environment: "dev",
  dataClassification: "INTERNAL",
  geography: "US",
  autonomyLevel: "HUMAN_IN_LOOP",
  customerImpact: "LOW",
  financialImpact: "NONE",
  usesCustomerDecision: false,
  publicEndpoint: false,
  monitoringEnabled: true,
  evaluationRefs: ["eval_internal"],
  humanOversight: ["analyst_review"],
  modelRefs: ["model:cohort-v1"],
};
