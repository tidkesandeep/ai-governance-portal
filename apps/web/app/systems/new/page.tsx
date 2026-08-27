"use client";

import type { FormEvent, ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { AGENT_SAMPLE, FRAUD_SAMPLE, INTERNAL_SAMPLE } from "@/lib/samples";
import type { Registration } from "@/lib/types";

const empty: Registration = {
  name: "",
  systemType: "PREDICTIVE_MODEL",
  businessPurpose: "",
  owner: "",
  environment: "production",
  dataClassification: "INTERNAL",
  geography: "US",
  autonomyLevel: "HUMAN_IN_LOOP",
  customerImpact: "MEDIUM",
  financialImpact: "LOW",
  usesCustomerDecision: false,
  publicEndpoint: false,
  monitoringEnabled: false,
  evaluationRefs: [],
  humanOversight: [],
  modelRefs: [],
};

function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="font-mono text-[11px] uppercase tracking-wider text-navy/60">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

const inputClass = "w-full border border-rule bg-panel px-3 py-2 text-sm outline-none focus:border-ink";

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState<Registration>(empty);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function set<K extends keyof Registration>(key: K, value: Registration[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const created = await api.register(form);
      router.push(`/systems/${created.system.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
      setPending(false);
    }
  }

  return (
    <div className="max-w-3xl">
      <h1 className="font-serif text-4xl">Register an AI system</h1>
      <p className="mt-2 text-navy/70">
        Capture the facts the risk engine and policy bundle need. Do not paste prompts or
        raw customer data into this control plane.
      </p>
      <div className="mt-4 flex gap-2">
        <button
          type="button"
          className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
          onClick={() => setForm(FRAUD_SAMPLE)}
        >
          Load fraud model sample
        </button>
          <button
          type="button"
          className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
          onClick={() => setForm(INTERNAL_SAMPLE)}
        >
          Load internal analytics sample
        </button>
        <button
          type="button"
          className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
          onClick={() => setForm(AGENT_SAMPLE)}
        >
          Load refund agent sample
        </button>
      </div>
      <form className="mt-8 grid gap-5" onSubmit={onSubmit}>
        <Field label="Name">
          <input className={inputClass} value={form.name} onChange={(e) => set("name", e.target.value)} required />
        </Field>
        <Field label="Business purpose">
          <textarea
            className={inputClass}
            rows={3}
            value={form.businessPurpose}
            onChange={(e) => set("businessPurpose", e.target.value)}
            required
          />
        </Field>
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Owner">
            <input className={inputClass} value={form.owner} onChange={(e) => set("owner", e.target.value)} required />
          </Field>
          <Field label="Geography">
            <input className={inputClass} value={form.geography} onChange={(e) => set("geography", e.target.value)} />
          </Field>
          <Field label="System type">
            <select className={inputClass} value={form.systemType} onChange={(e) => set("systemType", e.target.value)}>
              <option>PREDICTIVE_MODEL</option>
              <option>GENAI_APP</option>
              <option>AGENT</option>
              <option>THIRD_PARTY_LLM</option>
            </select>
          </Field>
          <Field label="Environment">
            <select className={inputClass} value={form.environment} onChange={(e) => set("environment", e.target.value)}>
              <option>dev</option>
              <option>test</option>
              <option>staging</option>
              <option>production</option>
            </select>
          </Field>
          <Field label="Data classification">
            <select
              className={inputClass}
              value={form.dataClassification}
              onChange={(e) => set("dataClassification", e.target.value)}
            >
              <option>PUBLIC</option>
              <option>INTERNAL</option>
              <option>CONFIDENTIAL</option>
              <option>PII</option>
              <option>PCI</option>
              <option>RESTRICTED</option>
            </select>
          </Field>
          <Field label="Autonomy">
            <select
              className={inputClass}
              value={form.autonomyLevel}
              onChange={(e) => set("autonomyLevel", e.target.value)}
            >
              <option>HUMAN_IN_LOOP</option>
              <option>ASSISTIVE</option>
              <option>SEMI_AUTONOMOUS</option>
              <option>AUTONOMOUS</option>
            </select>
          </Field>
          <Field label="Customer impact">
            <select
              className={inputClass}
              value={form.customerImpact}
              onChange={(e) => set("customerImpact", e.target.value)}
            >
              <option>NONE</option>
              <option>LOW</option>
              <option>MEDIUM</option>
              <option>HIGH</option>
              <option>CRITICAL</option>
            </select>
          </Field>
          <Field label="Financial impact">
            <select
              className={inputClass}
              value={form.financialImpact}
              onChange={(e) => set("financialImpact", e.target.value)}
            >
              <option>NONE</option>
              <option>LOW</option>
              <option>MEDIUM</option>
              <option>HIGH</option>
              <option>CRITICAL</option>
            </select>
          </Field>
        </div>
        <div className="flex flex-wrap gap-6 font-mono text-xs">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.usesCustomerDecision}
              onChange={(e) => set("usesCustomerDecision", e.target.checked)}
            />
            Customer-facing decision
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.publicEndpoint}
              onChange={(e) => set("publicEndpoint", e.target.checked)}
            />
            Public endpoint
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={form.monitoringEnabled}
              onChange={(e) => set("monitoringEnabled", e.target.checked)}
            />
            Monitoring enabled
          </label>
        </div>
        {error ? <p className="text-carmine">{error}</p> : null}
        <button
          type="submit"
          disabled={pending}
          className="w-fit border border-ink bg-ink px-5 py-2 font-mono text-xs uppercase tracking-wider text-paper disabled:opacity-50"
        >
          {pending ? "Registering…" : "Create DRAFT record"}
        </button>
      </form>
    </div>
  );
}
