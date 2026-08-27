"use client";

import type { AISystem360, AuditEvent, PolicyDecision, Registration, RiskAssessment } from "./types";

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
  audit: (id: string) => request<{ items: AuditEvent[] }>(`/v1/ai-systems/${id}/audit-events`),
};
