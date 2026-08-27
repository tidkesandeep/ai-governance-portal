"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { bandClass, outcomeClass } from "@/lib/style";
import type { AISystem360, AuditEvent, PolicyDecision } from "@/lib/types";

export default function System360Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [data, setData] = useState<AISystem360 | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  const refresh = useCallback(async () => {
    const [payload, events] = await Promise.all([api.get(id), api.audit(id)]);
    setData(payload);
    setAudit(events.items);
  }, [id]);

  useEffect(() => {
    refresh().catch((err) => setError(err.message));
  }, [refresh]);

  async function run(label: string, action: () => Promise<unknown>) {
    setBusy(label);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  if (!data) {
    return <p className="text-navy/70">{error ?? "Loading system…"}</p>;
  }

  const assessment = data.latestAssessment;
  const decision = data.latestDecision;
  const approvalState = Object.fromEntries(data.approvals.map((row) => [row.function, row]));

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-navy/50">AI System 360</p>
          <h1 className="mt-1 font-serif text-4xl">{data.system.name}</h1>
          <p className="mt-2 max-w-2xl text-navy/70">{data.system.businessPurpose}</p>
          <p className="mt-2 font-mono text-[11px] text-navy/50">{data.system.urn}</p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <span className={`border px-2 py-1 font-mono text-xs ${bandClass(data.system.riskBand)}`}>
            {data.system.riskBand ?? "UNSCORED"} · {data.system.status}
          </span>
          <span className="font-mono text-[11px] text-navy/50">
            {data.system.systemType} · {data.system.environment}
          </span>
        </div>
      </header>

      {error ? (
        <div className="border border-carmine/40 bg-carmine/10 px-4 py-3 text-sm text-carmine">{error}</div>
      ) : null}

      <section className="grid gap-4 lg:grid-cols-3">
        <Fact label="Owner" value={data.system.owner} />
        <Fact label="Data" value={data.system.dataClassification} />
        <Fact label="Autonomy" value={data.system.autonomyLevel} />
        <Fact label="Geography" value={data.system.geography} />
        <Fact label="Customer decision" value={String(data.registration.usesCustomerDecision)} />
        <Fact label="Oversight" value={data.humanOversight.join(", ") || "none"} />
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="border border-rule bg-panel p-5">
          <div className="flex items-center justify-between">
            <h2 className="font-serif text-2xl">Risk</h2>
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              onClick={() => run("assess", () => api.assess(id))}
              disabled={busy !== null}
            >
              {busy === "assess" ? "Scoring…" : "Run assessment"}
            </button>
          </div>
          {assessment ? (
            <div className="mt-4">
              <div className="flex items-baseline gap-3">
                <span className="font-serif text-5xl">{assessment.score.toFixed(1)}</span>
                <span className={`border px-2 py-0.5 font-mono text-xs ${bandClass(assessment.riskBand)}`}>
                  {assessment.riskBand}
                </span>
                <span className="font-mono text-xs text-navy/60">
                  confidence {assessment.confidence.toFixed(2)}
                </span>
              </div>
              <p className="mt-1 font-mono text-[11px] text-navy/50">{assessment.engineVersion}</p>
              <ul className="mt-4 space-y-2">
                {assessment.drivers.map((driver) => (
                  <li key={driver.code}>
                    <div className="flex justify-between font-mono text-[11px]">
                      <span>{driver.code}</span>
                      <span>{driver.contribution.toFixed(1)}</span>
                    </div>
                    <div className="mt-1 h-1.5 bg-rule">
                      <div
                        className="h-1.5 bg-navy"
                        style={{ width: `${Math.min(100, driver.contribution * 4)}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
              {assessment.hardConstraints.length > 0 ? (
                <p className="mt-4 font-mono text-[11px] text-carmine">
                  Hard constraints: {assessment.hardConstraints.join(", ")}
                </p>
              ) : null}
              {assessment.missingInputs.length > 0 ? (
                <p className="mt-2 font-mono text-[11px] text-brass">
                  Missing inputs: {assessment.missingInputs.join(", ")}
                </p>
              ) : null}
            </div>
          ) : (
            <p className="mt-4 text-sm text-navy/60">No assessment yet. Score the system before gating a deploy.</p>
          )}
        </div>

        <WhyBlocked decision={decision} />
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Approvals</h2>
          <p className="mt-1 text-sm text-navy/60">
            Switch to the reviewer principal in the header. The engineer token is rejected by
            segregation of duties.
          </p>
          <div className="mt-4 space-y-2">
            {(["privacy", "security", "risk"] as const).map((fn) => (
              <div key={fn} className="flex items-center justify-between border border-rule px-3 py-2">
                <div>
                  <p className="font-mono text-xs uppercase">{fn}</p>
                  <p className="font-mono text-[11px] text-navy/50">
                    {approvalState[fn]?.approved ? `granted by ${approvalState[fn].actorId}` : "missing"}
                  </p>
                </div>
                <button
                  className="border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                  onClick={() => run(`approve-${fn}`, () => api.approve(id, fn))}
                  disabled={busy !== null}
                >
                  Record
                </button>
              </div>
            ))}
          </div>
          <button
            className="mt-4 border border-rule px-3 py-2 font-mono text-[11px] uppercase"
            onClick={() => run("oversight", () => api.oversight(id, ["human_review_queue"]))}
            disabled={busy !== null}
          >
            Attach human oversight
          </button>
        </div>

        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Deployment gate</h2>
          <p className="mt-1 text-sm text-navy/60">
            Evaluates the versioned policy bundle. Unknown or stale evidence cannot silently pass.
          </p>
          <label className="mt-4 flex items-center gap-2 font-mono text-xs">
            <input type="checkbox" checked={stale} onChange={(e) => setStale(e.target.checked)} />
            Simulate stale evidence
          </label>
          <button
            className="mt-4 border border-ink bg-ink px-4 py-2 font-mono text-xs uppercase tracking-wider text-paper"
            onClick={() => run("gate", () => api.gate(id, stale))}
            disabled={busy !== null}
          >
            {busy === "gate" ? "Evaluating…" : "Evaluate production gate"}
          </button>
          {decision ? (
            <p className="mt-4 break-all font-mono text-[11px] text-navy/50">
              decision {decision.id}
              <br />
              bundle {decision.policyBundle}
              <br />
              input {decision.inputDigest}
            </p>
          ) : null}
        </div>
      </section>

      <section className="border border-rule bg-panel p-5">
        <h2 className="font-serif text-2xl">Audit trail</h2>
        <ol className="mt-4 space-y-3">
          {audit.map((event) => (
            <li key={event.eventId} className="border-l-2 border-navy/30 pl-4">
              <p className="font-mono text-xs">
                {event.eventType} · {new Date(event.occurredAt).toISOString()}
              </p>
              <p className="font-mono text-[11px] text-navy/50">{event.hash}</p>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-rule bg-panel px-4 py-3">
      <p className="font-mono text-[11px] uppercase tracking-wider text-navy/50">{label}</p>
      <p className="mt-1 text-sm">{value}</p>
    </div>
  );
}

function WhyBlocked({ decision }: { decision?: PolicyDecision | null }) {
  if (!decision) {
    return (
      <div className="border border-dashed border-rule bg-panel/60 p-5">
        <h2 className="font-serif text-2xl">Why blocked?</h2>
        <p className="mt-2 text-sm text-navy/60">
          Run the deployment gate to persist an ALLOW / REVIEW / BLOCK decision with reason codes.
        </p>
      </div>
    );
  }
  return (
    <div className="border border-rule bg-panel p-5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-serif text-2xl">Why blocked?</h2>
        <span className={`px-3 py-1 font-mono text-xs ${outcomeClass(decision.outcome)}`}>
          {decision.outcome}
        </span>
      </div>
      {decision.outcome === "ALLOW" ? (
        <p className="mt-3 text-sm text-forest">All Slice-1 controls passed. Authorization can proceed.</p>
      ) : (
        <ul className="mt-4 space-y-3">
          {decision.reasons.map((reason) => (
            <li key={reason.code} className="border border-rule px-3 py-2">
              <p className="font-mono text-xs">
                {reason.severity} · {reason.code}
              </p>
              <p className="text-sm text-navy/70">{reason.message}</p>
            </li>
          ))}
        </ul>
      )}
      {decision.requiredActions.length > 0 ? (
        <div className="mt-4">
          <p className="font-mono text-[11px] uppercase tracking-wider text-navy/50">Required actions</p>
          <ul className="mt-1 list-disc pl-5 text-sm">
            {decision.requiredActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
