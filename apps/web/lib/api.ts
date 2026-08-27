"use client";

import type {
  ActionAuthorizationVerify,
  ActionDecision,
  AISystem360,
  AuditEvent,
  AuthorizationVerify,
  DeploymentAuthorization,
  GitHubCheck,
  PolicyDecision,
  Principal,
  Registration,
  RiskAssessment,
} from "./types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
export const TOKEN_KEY = "aigov.token";

export function getToken(): string {
  if (typeof window === "undefined") return "demo";
  return window.localStorage.getItem(TOKEN_KEY) ?? "demo";
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${getToken()}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_URL}${path}`, { ...init, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail || payload.title || response.statusText;
    throw new Error(typeof detail === "string" ? detail : payload.code || "Request failed");
  }
  return payload as T;
}

export const api = {
  me: () => request<Principal>("/v1/me"),
  list: () => request<{ items: AISystem360["system"][] }>("/v1/ai-systems"),
  get: (id: string) => request<AISystem360>(`/v1/ai-systems/${id}`),
  register: (body: Registration) =>
    request<AISystem360>("/v1/ai-systems", { method: "POST", body: JSON.stringify(body) }),
  assess: (id: string) =>
    request<RiskAssessment>(`/v1/ai-systems/${id}/assessments`, { method: "POST" }),
  approve: (id: string, fn: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/approvals`, {
      method: "POST",
      body: JSON.stringify({ function: fn, approved: true }),
    }),
  oversight: (id: string, controls: string[]) =>
    request<AISystem360>(`/v1/ai-systems/${id}/oversight`, {
      method: "POST",
      body: JSON.stringify({ controls }),
    }),
  gate: (id: string, evidenceStale = false) =>
    request<PolicyDecision>(`/v1/ai-systems/${id}/deployments/gate`, {
      method: "POST",
      body: JSON.stringify({ evidenceStale }),
    }),
  attachEvidence: (
    id: string,
    body: { type: string; filename: string; content: string; collectedAt?: string },
  ) =>
    request<AISystem360>(`/v1/ai-systems/${id}/evidence`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  cutVersion: (id: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/versions`, { method: "POST" }),
  verifyAuthorization: (id: string, authorizationId: string, signature?: string, consume = false) =>
    request<AuthorizationVerify>(`/v1/ai-systems/${id}/authorizations/${authorizationId}/verify`, {
      method: "POST",
      body: JSON.stringify({ signature: signature ?? null, consume }),
    }),
  revokeAuthorization: (id: string, authorizationId: string) =>
    request<DeploymentAuthorization>(
      `/v1/ai-systems/${id}/authorizations/${authorizationId}/revoke`,
      { method: "POST" },
    ),
  requestException: (id: string, violationCode: string, justification: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/exceptions`, {
      method: "POST",
      body: JSON.stringify({ violationCode, justification }),
    }),
  grantException: (id: string, exceptionId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/exceptions/${exceptionId}/grant`, { method: "POST" }),
  denyException: (id: string, exceptionId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/exceptions/${exceptionId}/deny`, { method: "POST" }),
  revokeException: (id: string, exceptionId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/exceptions/${exceptionId}/revoke`, { method: "POST" }),
  recordFinding: (
    id: string,
    body: { findingType: string; severity: string; summary: string; detector?: string },
  ) =>
    request<AISystem360>(`/v1/ai-systems/${id}/findings`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  promoteFinding: (id: string, findingId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/findings/${findingId}/promote`, { method: "POST" }),
  dismissFinding: (id: string, findingId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/findings/${findingId}/dismiss`, { method: "POST" }),
  resolveIncident: (id: string, incidentId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/incidents/${incidentId}/resolve`, { method: "POST" }),
  declareCapability: (
    id: string,
    body: { action: string; resourcePattern: string; maxAmount?: number; requiresApproval?: boolean },
  ) =>
    request<AISystem360>(`/v1/ai-systems/${id}/capabilities`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  approveCapability: (id: string, capabilityId: string) =>
    request<AISystem360>(`/v1/ai-systems/${id}/capabilities/${capabilityId}/approve`, { method: "POST" }),
  authorizeAction: (id: string, body: { action: string; resource: string; amount?: number }) =>
    request<ActionDecision>(`/v1/ai-systems/${id}/actions/authorize`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  verifyActionAuthorization: (id: string, authorizationId: string) =>
    request<ActionAuthorizationVerify>(
      `/v1/ai-systems/${id}/action-authorizations/${authorizationId}/verify`,
      { method: "POST", body: JSON.stringify({}) },
    ),
  recordObservation: (
    id: string,
    body: {
      running?: boolean;
      assetVersionId?: string;
      environment?: string;
      cloud?: string;
      region?: string;
      fingerprint?: string;
      observedAt?: string;
    },
  ) =>
    request<AISystem360>(`/v1/ai-systems/${id}/observations`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  publishOutbox: (limit = 100) =>
    request<{ published: number }>(`/v1/outbox/publish?limit=${limit}`, { method: "POST" }),
  recordGithubCheck: (id: string, body: { sha: string; repo?: string }) =>
    request<GitHubCheck>(`/v1/ai-systems/${id}/github-checks`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  audit: (id: string) => request<{ items: AuditEvent[] }>(`/v1/ai-systems/${id}/audit-events`),
};
