"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { bandClass, outcomeClass } from "@/lib/style";
import type {
  ActionAuthorizationVerify,
  ActionDecision,
  AISystem360,
  AuditEvent,
  AuthorizationVerify,
  PolicyDecision,
} from "@/lib/types";

const NON_WAIVABLE = new Set([
  "EVIDENCE_HASH_FAILURE",
  "MISSING_ASSESSMENT",
  "POLICY_ENGINE_UNAVAILABLE",
  "RUNTIME_INCIDENT",
  "RUNTIME_DRIFT",
]);

const SAMPLES: Record<string, { filename: string; content: string }> = {
  MODEL_CARD: {
    filename: "model-card.md",
    content: "# Fraud Risk Model v4.2\nIntended use: payment fraud scoring. No raw customer payloads.",
  },
  EVALUATION_RUN: {
    filename: "eval.json",
    content: '{"recall": 0.96, "precision": 0.94, "dataset": "holdout-2026-08"}',
  },
  FAIRNESS_EVALUATION: {
    filename: "fairness.json",
    content: '{"group_gap": 0.02, "methodology": "equalized-odds"}',
  },
};

export default function System360Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [data, setData] = useState<AISystem360 | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [verification, setVerification] = useState<AuthorizationVerify | null>(null);
  const [actionDecision, setActionDecision] = useState<ActionDecision | null>(null);
  const [actionVerification, setActionVerification] = useState<ActionAuthorizationVerify | null>(null);
  const [checkSha, setCheckSha] = useState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  const [checkRepo, setCheckRepo] = useState("acme/fraud-model");

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
  const authorization = data.latestAuthorization;
  const snapshot = data.latestSnapshot;
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
        <Fact label="Asset version" value={data.system.currentVersionId ?? "—"} />
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-serif text-2xl">Control posture</h2>
            <button
              className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
              onClick={() => run("version", () => api.cutVersion(id))}
              disabled={busy !== null}
            >
              Cut new version
            </button>
          </div>
          <p className="mt-1 text-sm text-navy/60">
            UNKNOWN and STALE cannot satisfy a mandatory control. Evidence is bound to the current
            asset version.
          </p>
          <ul className="mt-4 space-y-2">
            {(data.controls ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No mandatory controls until the system is scored.</li>
            ) : (
              data.controls.map((control) => (
                <li key={control.controlId} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">{control.controlId}</p>
                    <span className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(control.status)}`}>
                      {control.status}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-navy/70">{control.reason}</p>
                  <p className="font-mono text-[11px] text-navy/50">
                    {control.evidenceType} · max age {control.maxAgeDays}d
                  </p>
                </li>
              ))
            )}
          </ul>
        </div>
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Evidence</h2>
          <p className="mt-1 text-sm text-navy/60">
            Artifacts are hashed on attach. Content is untrusted and never treated as policy.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {Object.keys(SAMPLES).map((type) => (
              <button
                key={type}
                className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
                disabled={busy !== null}
                onClick={() =>
                  run(`evidence-${type}`, () =>
                    api.attachEvidence(id, {
                      type,
                      filename: SAMPLES[type].filename,
                      content: SAMPLES[type].content,
                    }),
                  )
                }
              >
                Attach {type.replaceAll("_", " ").toLowerCase()}
              </button>
            ))}
          </div>
          <ul className="mt-4 space-y-2">
            {(data.evidence ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No evidence attached.</li>
            ) : (
              data.evidence.map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <p className="font-mono text-xs">
                    {item.type} · {item.filename} · {item.verificationStatus}
                  </p>
                  <p className="break-all font-mono text-[11px] text-navy/50">{item.sha256}</p>
                  <p className="font-mono text-[11px] text-navy/50">
                    bound {item.boundVersionId}
                  </p>
                </li>
              ))
            )}
          </ul>
        </div>
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
              {decision.fingerprint ? (
                <>
                  <br />
                  fingerprint {decision.fingerprint}
                </>
              ) : null}
            </p>
          ) : null}
        </div>
      </section>

      <section className="border border-rule bg-panel p-5">
        <h2 className="font-serif text-2xl">Deployment authorization</h2>
        <p className="mt-1 text-sm text-navy/60">
          ALLOW mints a short-lived HMAC-signed token bound to the decision fingerprint and asset
          version. Verify returns ALLOW or DENY. Revoke or cut a version immediately invalidates it.
        </p>
        {authorization ? (
          <div className="mt-4 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`border px-2 py-1 font-mono text-xs ${outcomeClass(authorization.revokedAt ? "DENY" : "ALLOW")}`}>
                {authorization.revokedAt ? "REVOKED" : authorization.consumedAt ? "CONSUMED" : "ISSUED"}
              </span>
              <span className="font-mono text-[11px] text-navy/50">
                expires {new Date(authorization.expiresAt).toISOString()}
              </span>
            </div>
            <p className="break-all font-mono text-[11px] text-navy/50">
              id {authorization.id}
              <br />
              fingerprint {authorization.fingerprint}
              <br />
              version {authorization.assetVersionId}
              {snapshot ? (
                <>
                  <br />
                  snapshot {snapshot.id}
                </>
              ) : null}
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
                disabled={busy !== null}
                onClick={() =>
                  run("verify-authz", async () => {
                    const result = await api.verifyAuthorization(id, authorization.id);
                    setVerification(result);
                  })
                }
              >
                {busy === "verify-authz" ? "Verifying…" : "Verify"}
              </button>
              <button
                className="border border-carmine/40 px-3 py-1 font-mono text-[11px] uppercase text-carmine"
                disabled={busy !== null || Boolean(authorization.revokedAt)}
                onClick={() =>
                  run("revoke-authz", async () => {
                    await api.revokeAuthorization(id, authorization.id);
                    setVerification(null);
                  })
                }
              >
                Revoke
              </button>
            </div>
            {verification ? (
              <div className="border border-rule px-3 py-2">
                <p className={`inline-block px-2 py-0.5 font-mono text-xs ${outcomeClass(verification.outcome)}`}>
                  {verification.outcome}
                </p>
                {verification.reasons.length > 0 ? (
                  <p className="mt-2 font-mono text-[11px] text-navy/70">
                    {verification.reasons.join(", ")}
                  </p>
                ) : (
                  <p className="mt-2 text-sm text-forest">Signature, expiry, revocation, and version all match.</p>
                )}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="mt-4 text-sm text-navy/60">
            No authorization yet. BLOCK and REVIEW persist a snapshot but do not mint a token.
          </p>
        )}
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Workflow case</h2>
          <p className="mt-1 text-sm text-navy/60">
            BLOCK and REVIEW open a case. The SLA clock starts once and is not reset by re-gating.
            ALLOW closes the case.
          </p>
          {data.latestCase ? (
            <div className="mt-4 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`border px-2 py-1 font-mono text-xs ${bandClass(data.latestCase.status)}`}>
                  {data.latestCase.status}
                </span>
                <span className={`border px-2 py-1 font-mono text-xs ${bandClass(data.latestCase.slaStatus)}`}>
                  SLA {data.latestCase.slaStatus}
                </span>
              </div>
              <p className="font-mono text-[11px] text-navy/50">
                due {new Date(data.latestCase.dueAt).toISOString()}
                <br />
                {data.latestCase.caseType} · {data.latestCase.reasonCodes.join(", ") || "no codes"}
              </p>
            </div>
          ) : (
            <p className="mt-4 text-sm text-navy/60">No workflow case yet. Evaluate the gate to open one.</p>
          )}
        </div>

        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Exceptions</h2>
          <p className="mt-1 text-sm text-navy/60">
            A granted exception waives one named violation until it expires or the asset version
            changes. Hash failures cannot be waived. The engineer requests; the reviewer grants.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {(decision?.reasons ?? [])
              .map((reason) => reason.code)
              .filter((code, index, all) => all.indexOf(code) === index)
              .filter((code) => !NON_WAIVABLE.has(code))
              .map((code) => (
                <button
                  key={code}
                  className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
                  disabled={busy !== null}
                  onClick={() =>
                    run(`exception-${code}`, () =>
                      api.requestException(
                        id,
                        code,
                        "Time-bounded hotfix while the required evidence is refreshed.",
                      ),
                    )
                  }
                >
                  Request {code.replaceAll("_", " ").toLowerCase()}
                </button>
              ))}
          </div>
          <ul className="mt-4 space-y-2">
            {(data.exceptions ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No exceptions requested.</li>
            ) : (
              data.exceptions.map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">{item.violationCode}</p>
                    <span className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(item.status)}`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-navy/70">{item.justification}</p>
                  <p className="font-mono text-[11px] text-navy/50">
                    expires {new Date(item.expiresAt).toISOString()}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {item.status === "REQUESTED" ? (
                      <>
                        <button
                          className="border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                          disabled={busy !== null}
                          onClick={() => run(`grant-${item.id}`, () => api.grantException(id, item.id))}
                        >
                          Grant
                        </button>
                        <button
                          className="border border-rule px-2 py-1 font-mono text-[11px] uppercase"
                          disabled={busy !== null}
                          onClick={() => run(`deny-${item.id}`, () => api.denyException(id, item.id))}
                        >
                          Deny
                        </button>
                      </>
                    ) : null}
                    {item.status === "GRANTED" ? (
                      <button
                        className="border border-carmine/40 px-2 py-1 font-mono text-[11px] uppercase text-carmine"
                        disabled={busy !== null}
                        onClick={() => run(`revoke-exc-${item.id}`, () => api.revokeException(id, item.id))}
                      >
                        Revoke exception
                      </button>
                    ) : null}
                  </div>
                </li>
              ))
            )}
          </ul>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Findings</h2>
          <p className="mt-1 text-sm text-navy/60">
            HIGH and CRITICAL findings auto-promote to an incident, revoke live authorization, and
            block the gate with a non-waivable <span className="font-mono">RUNTIME_INCIDENT</span>.
            MEDIUM and LOW stay open until a reviewer promotes or dismisses them.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              className="border border-carmine/40 px-3 py-1 font-mono text-[11px] uppercase text-carmine"
              disabled={busy !== null}
              onClick={() =>
                run("finding-critical", () =>
                  api.recordFinding(id, {
                    findingType: "EVAL_REGRESSION",
                    severity: "CRITICAL",
                    summary: "Holdout recall dropped below the production floor.",
                    detector: "eval-monitor",
                  }),
                )
              }
            >
              Record CRITICAL eval regression
            </button>
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("finding-medium", () =>
                  api.recordFinding(id, {
                    findingType: "DATA_DRIFT",
                    severity: "MEDIUM",
                    summary: "Feature distribution shifted on the live scoring window.",
                    detector: "drift-monitor",
                  }),
                )
              }
            >
              Record MEDIUM data drift
            </button>
          </div>
          <ul className="mt-4 space-y-2">
            {(data.findings ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No findings recorded.</li>
            ) : (
              data.findings.map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">
                      {item.severity} · {item.findingType}
                    </p>
                    <span className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(item.status)}`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-navy/70">{item.summary}</p>
                  <p className="font-mono text-[11px] text-navy/50">
                    {item.detector} · bound {item.boundVersionId}
                  </p>
                  {item.status === "OPEN" ? (
                    <div className="mt-2 flex flex-wrap gap-2">
                      <button
                        className="border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                        disabled={busy !== null}
                        onClick={() => run(`promote-${item.id}`, () => api.promoteFinding(id, item.id))}
                      >
                        Promote
                      </button>
                      <button
                        className="border border-rule px-2 py-1 font-mono text-[11px] uppercase"
                        disabled={busy !== null}
                        onClick={() => run(`dismiss-${item.id}`, () => api.dismissFinding(id, item.id))}
                      >
                        Dismiss
                      </button>
                    </div>
                  ) : null}
                </li>
              ))
            )}
          </ul>
        </div>

        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Incidents</h2>
          <p className="mt-1 text-sm text-navy/60">
            Resolving an incident does not mint a new token. Re-evaluate the deployment gate after
            containment.
          </p>
          <ul className="mt-4 space-y-2">
            {(data.incidents ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No incidents opened.</li>
            ) : (
              data.incidents.map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">{item.title}</p>
                    <span className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(item.status)}`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-navy/70">{item.summary}</p>
                  {item.status === "OPEN" ? (
                    <button
                      className="mt-2 border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                      disabled={busy !== null}
                      onClick={() => run(`resolve-${item.id}`, () => api.resolveIncident(id, item.id))}
                    >
                      Resolve
                    </button>
                  ) : null}
                </li>
              ))
            )}
          </ul>
        </div>
      </section>

      <section className="border border-rule bg-panel p-5">
        <h2 className="font-serif text-2xl">Desired vs observed</h2>
        <p className="mt-1 text-sm text-navy/60">
          A gate ALLOW authorizes a version. It does not prove that version is what is running.
          HIGH drift revokes live tokens and blocks the gate with a non-waivable{" "}
          <span className="font-mono">RUNTIME_DRIFT</span>. A later matching observation does not
          mint a new token.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
            disabled={busy !== null}
            onClick={() => run("obs-sync", () => api.recordObservation(id, {}))}
          >
            Report in-sync
          </button>
          <button
            className="border border-carmine/40 px-3 py-1 font-mono text-[11px] uppercase text-carmine"
            disabled={busy !== null}
            onClick={() =>
              run("obs-drift", () => api.recordObservation(id, { assetVersionId: "ver_not_authorized" }))
            }
          >
            Report drifted version
          </button>
          <button
            className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
            disabled={busy !== null}
            onClick={() =>
              run("obs-stale", () =>
                api.recordObservation(id, {
                  observedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
                }),
              )
            }
          >
            Report stale observation
          </button>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <div className="border border-rule px-3 py-2">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-navy/50">Observation</p>
            {data.latestObservation ? (
              <>
                <p className="mt-2 font-mono text-xs">
                  {data.latestObservation.running ? "RUNNING" : "STOPPED"} · {data.latestObservation.environment}
                </p>
                <p className="font-mono text-[11px] text-navy/50">
                  version {data.latestObservation.boundVersionId}
                </p>
                <p className="break-all font-mono text-[11px] text-navy/50">
                  {data.latestObservation.fingerprint ?? "no fingerprint"}
                </p>
              </>
            ) : (
              <p className="mt-2 text-sm text-navy/60">No runtime observation recorded.</p>
            )}
          </div>
          <div className="border border-rule px-3 py-2">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-navy/50">Reconciliation</p>
            {data.latestReconciliation ? (
              <>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <p className="font-mono text-xs">{data.latestReconciliation.status}</p>
                  <span
                    className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(data.latestReconciliation.status)}`}
                  >
                    {data.latestReconciliation.status}
                  </span>
                </div>
                {(data.latestReconciliation.reasons ?? []).length === 0 ? (
                  <p className="mt-1 text-sm text-navy/60">No drift reasons.</p>
                ) : (
                  <ul className="mt-1 space-y-1">
                    {data.latestReconciliation.reasons.map((reason) => (
                      <li key={reason.code} className="font-mono text-[11px] text-navy/70">
                        {reason.severity} · {reason.code}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            ) : (
              <p className="mt-2 text-sm text-navy/60">No reconciliation computed yet.</p>
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Outbound events</h2>
          <p className="mt-1 text-sm text-navy/60">
            Every hash-chained audit event is dual-written to the outbox in the same transaction.
            Publish drains unpublished rows to structured logs, or Kafka when{" "}
            <span className="font-mono">AIGOV_KAFKA_BOOTSTRAP_SERVERS</span> is set.
          </p>
          <div className="mt-4">
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() => run("outbox", () => api.publishOutbox())}
            >
              Publish outbox
            </button>
          </div>
          <ul className="mt-4 space-y-2">
            {(data.latestOutboxEvents ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No outbound events yet.</li>
            ) : (
              (data.latestOutboxEvents ?? []).slice(0, 8).map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">{item.eventType}</p>
                    <span
                      className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(
                        item.publishedAt ? "IN_SYNC" : "UNKNOWN",
                      )}`}
                    >
                      {item.publishedAt ? "published" : "pending"}
                    </span>
                  </div>
                  <p className="mt-1 break-all font-mono text-[11px] text-navy/50">{item.eventId}</p>
                </li>
              ))
            )}
          </ul>
        </div>
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">GitHub checks</h2>
          <p className="mt-1 text-sm text-navy/60">
            Records the latest deployment-gate conclusion against a commit SHA. Missing GitHub
            credentials still persist the result so the gate remains the system of record.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <input
              className="min-w-[12rem] flex-1 border border-rule bg-panel px-2 py-1 font-mono text-[11px]"
              value={checkSha}
              onChange={(event) => setCheckSha(event.target.value)}
              placeholder="commit sha"
            />
            <input
              className="min-w-[10rem] border border-rule bg-panel px-2 py-1 font-mono text-[11px]"
              value={checkRepo}
              onChange={(event) => setCheckRepo(event.target.value)}
              placeholder="owner/repo"
            />
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null || !checkSha.trim()}
              onClick={() =>
                run("gh-check", () =>
                  api.recordGithubCheck(id, {
                    sha: checkSha.trim(),
                    repo: checkRepo.trim() || undefined,
                  }),
                )
              }
            >
              Record check
            </button>
          </div>
          {data.latestGithubCheck ? (
            <div className="mt-4 border border-rule px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <p className="font-mono text-xs">{data.latestGithubCheck.name}</p>
                <span
                  className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(
                    data.latestGithubCheck.conclusion,
                  )}`}
                >
                  {data.latestGithubCheck.conclusion}
                </span>
              </div>
              <p className="mt-1 break-all font-mono text-[11px] text-navy/50">
                {data.latestGithubCheck.sha}
              </p>
              <p className="font-mono text-[11px] text-navy/50">
                {data.latestGithubCheck.repo ?? "no repo"} · {data.latestGithubCheck.status}
              </p>
            </div>
          ) : (
            <p className="mt-4 text-sm text-navy/60">No GitHub check recorded.</p>
          )}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Capabilities</h2>
          <p className="mt-1 text-sm text-navy/60">
            Agents may only act through version-bound capabilities. Privileged payments actions
            always require a reviewer approval. The engineer cannot approve their own declaration.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("cap-refund", () =>
                  api.declareCapability(id, {
                    action: "payments.refund",
                    resourcePattern: "account:retail-*",
                    maxAmount: 500,
                    requiresApproval: true,
                  }),
                )
              }
            >
              Declare retail refund ≤ 500
            </button>
            <button
              className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("cap-crm", () =>
                  api.declareCapability(id, {
                    action: "crm.read",
                    resourcePattern: "customer:*",
                  }),
                )
              }
            >
              Declare CRM read
            </button>
          </div>
          <ul className="mt-4 space-y-2">
            {(data.capabilities ?? []).length === 0 ? (
              <li className="text-sm text-navy/60">No capabilities declared.</li>
            ) : (
              data.capabilities.map((item) => (
                <li key={item.id} className="border border-rule px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs">{item.action}</p>
                    <span
                      className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(item.approved ? "APPROVED" : "REQUESTED")}`}
                    >
                      {item.approved ? "APPROVED" : "PENDING"}
                    </span>
                  </div>
                  <p className="font-mono text-[11px] text-navy/50">
                    {item.resourcePattern}
                    {item.maxAmount != null ? ` · max ${item.maxAmount}` : ""}
                  </p>
                  {item.requiresApproval && !item.approved ? (
                    <button
                      className="mt-2 border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                      disabled={busy !== null}
                      onClick={() => run(`approve-cap-${item.id}`, () => api.approveCapability(id, item.id))}
                    >
                      Approve
                    </button>
                  ) : null}
                </li>
              ))
            )}
          </ul>
        </div>

        <div className="border border-rule bg-panel p-5">
          <h2 className="font-serif text-2xl">Action authorization</h2>
          <p className="mt-1 text-sm text-navy/60">
            Real-time ALLOW or DENY. Undeclared tools, out-of-pattern resources, amount ceilings,
            missing approvals, and open incidents all fail closed.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              className="border border-ink px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("act-retail", async () => {
                  const result = await api.authorizeAction(id, {
                    action: "payments.refund",
                    resource: "account:retail-123",
                    amount: 50,
                  });
                  setActionDecision(result);
                  setActionVerification(null);
                })
              }
            >
              Authorize retail refund $50
            </button>
            <button
              className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("act-wholesale", async () => {
                  const result = await api.authorizeAction(id, {
                    action: "payments.refund",
                    resource: "account:wholesale-1",
                    amount: 50,
                  });
                  setActionDecision(result);
                  setActionVerification(null);
                })
              }
            >
              Authorize wholesale refund
            </button>
            <button
              className="border border-rule px-3 py-1 font-mono text-[11px] uppercase"
              disabled={busy !== null}
              onClick={() =>
                run("act-undeclared", async () => {
                  const result = await api.authorizeAction(id, {
                    action: "ledger.write",
                    resource: "ledger:core",
                  });
                  setActionDecision(result);
                  setActionVerification(null);
                })
              }
            >
              Authorize undeclared ledger.write
            </button>
          </div>
          {(() => {
            const latest = actionDecision ?? data.latestActionDecision;
            const token = data.latestActionAuthorization;
            return (
              <div className="mt-4 space-y-3">
                {latest ? (
                  <div className="border border-rule px-3 py-2">
                    <p className={`inline-block px-2 py-0.5 font-mono text-xs ${outcomeClass(latest.outcome)}`}>
                      {latest.outcome}
                    </p>
                    <p className="mt-2 font-mono text-[11px] text-navy/70">
                      {latest.action} · {latest.resource}
                      {latest.amount != null ? ` · ${latest.amount}` : ""}
                    </p>
                    {latest.reasons.length > 0 ? (
                      <p className="mt-1 font-mono text-[11px] text-carmine">
                        {latest.reasons.map((reason) => reason.code).join(", ")}
                      </p>
                    ) : null}
                  </div>
                ) : (
                  <p className="text-sm text-navy/60">No action decision yet.</p>
                )}
                {token ? (
                  <div>
                    <span
                      className={`border px-2 py-1 font-mono text-xs ${outcomeClass(token.revokedAt ? "DENY" : "ALLOW")}`}
                    >
                      {token.revokedAt ? "REVOKED" : "ISSUED"}
                    </span>
                    <button
                      className="ml-2 border border-ink px-2 py-1 font-mono text-[11px] uppercase"
                      disabled={busy !== null}
                      onClick={() =>
                        run("verify-actz", async () => {
                          const result = await api.verifyActionAuthorization(id, token.id);
                          setActionVerification(result);
                        })
                      }
                    >
                      Verify action token
                    </button>
                    {actionVerification ? (
                      <p className="mt-2 font-mono text-[11px] text-navy/70">
                        {actionVerification.outcome}
                        {actionVerification.reasons.length > 0
                          ? ` · ${actionVerification.reasons.join(", ")}`
                          : ""}
                      </p>
                    ) : null}
                  </div>
                ) : null}
              </div>
            );
          })()}
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
        <p className="mt-3 text-sm text-forest">Required controls passed for this decision snapshot.</p>
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
