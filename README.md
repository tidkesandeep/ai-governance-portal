# AI Governance Control Plane

Centralized governance control plane for predictive ML, GenAI applications, and AI agents. This repository implements **Slice 0–10** of the architecture: contracts, a FastAPI modular monolith, deterministic risk scoring, hashed evidence, an OPA-aligned deployment gate, immutable decision snapshots, short-lived authorization, workflow cases with SLA clocks, time-bounded exceptions, findings that promote to incidents and revoke live authorization, agent action/resource authorization, desired versus observed reconciliation, OIDC bearer identity, Alembic schema migrations, a transactional audit outbox, an operator CLI, GitHub deployment checks, cloud-neutral execution-plane adapters for AWS, Azure, and GCP, append-only audit events, and a thin Next.js portal.

The portal is not a model registry. It exists to answer: what AI exists, what risk and controls apply, whether it is authorized to deploy or keep operating **or act**, whether the authorized version is what is actually running, and what evidence/decision snapshot proves that. Identity is bound to the bearer token.

## Current slice

| Capability | Status |
|---|---|
| OpenAPI 3.1 contract | Yes |
| AI system registration + inventory | Yes |
| Deterministic risk engine with drivers + confidence | Yes |
| Deployment gate `ALLOW / REVIEW / BLOCK` | Yes |
| Policy-as-code (Rego + embedded evaluator) | Yes |
| Hash-chained audit trail | Yes |
| Segregation of duties on approvals | Yes |
| Tenant isolation | Yes |
| Thin UI: inventory, register, System 360, Why blocked? | Yes |
| Hashed evidence, freshness, version binding | Yes |
| Immutable governance snapshots | Yes |
| Short-lived, revocable HMAC deployment authorization | Yes |
| Workflow cases with SLA clocks | Yes |
| Time-bounded exceptions (SoD, version-bound, expiring) | Yes |
| Findings, incidents, and runtime revocation | Yes |
| Agent action and resource authorization | Yes |
| Desired versus observed reconciliation | Yes |
| OIDC bearer identity (`GET /v1/me`) | Yes |
| Alembic migrations at API boot | Yes |
| Transactional audit outbox (log sink; Kafka optional) | Yes |
| Operator CLI (`aigov gate`, `migrate`, `outbox publish`) | Yes |
| GitHub deployment checks / HMAC webhooks | Yes |
| Execution-plane adapters (AWS / Azure / GCP, fake default) | Yes |

## Quick start

Requires Python 3.12 and Node 22.

```bash
python3 -m pip install -e "apps/api[dev]"
cd apps/api && python3 -m pytest -q

# terminal 1
make api

# terminal 2
cd apps/web && npm install && npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

Demo tokens:

- `demo` — ML engineer / requester (cannot grant privacy/security/risk approvals)
- `demo-reviewer` — privacy, security, and risk reviewer
- `demo-other-tenant` — different tenant; used in isolation tests

The header switch on the portal selects the first two.

### First demo path

1. Register → **Load fraud model sample** → create DRAFT
2. Run assessment → expect **HIGH**
3. Evaluate production gate → **BLOCK** with missing approvals
4. Switch actor to reviewer → record privacy, security, and risk approvals
5. Gate again → still **BLOCK** (`MISSING_REQUIRED_EVIDENCE`); a workflow case is **OPEN** with SLA **ON_TRACK**
6. Optional exception path: request `MISSING_REQUIRED_EVIDENCE` as engineer → reviewer **Grant** → gate **ALLOW**. Revoke the exception → **BLOCK** again.
7. Or attach model card, evaluation run, and fairness evaluation
8. Gate → **ALLOW** and a short-lived deployment authorization is issued; the case **CLOSES**
9. Verify the authorization → **ALLOW**; revoke or cut a version → verify returns **DENY**
10. Cut a new asset version → controls return to **UNKNOWN**; prior evidence and exceptions cannot satisfy vN+1
11. Confirm the audit trail hash-chains
12. Record a **CRITICAL** eval regression → authorization verify returns **DENY** (`REVOKED`); gate **BLOCK** `RUNTIME_INCIDENT`
13. Resolve the incident as reviewer (engineer is rejected by SoD) → re-gate **ALLOW**
14. Record a **MEDIUM** data-drift finding → authorization stays valid until a reviewer **Promote**s it
15. Or register the **refund agent sample**, attach evidence, gate **ALLOW**, declare `payments.refund` on `account:retail-*`, reviewer **Approve**, then authorize a retail refund → **ALLOW**. Wholesale or undeclared actions **DENY**. A CRITICAL finding revokes the action token.
16. After a fraud-model **ALLOW**, **Report in-sync** → `IN_SYNC`. **Report drifted version** → tokens revoked, status **BLOCKED**, gate **BLOCK** `RUNTIME_DRIFT`. Report in-sync again → still **BLOCKED** with no new token until you re-evaluate the gate.
17. Header shows the bound principal from `GET /v1/me` (demo engineer vs reviewer). Production deploys set `AIGOV_DEMO_AUTH=false` and `AIGOV_OIDC_ISSUER` / `AIGOV_OIDC_AUDIENCE`; tenant and roles then come only from the JWT.
18. `aigov gate <systemId>` exits 0/1/2 for ALLOW/BLOCK/REVIEW. **Publish outbox** drains dual-written audit events. **Record GitHub check** stores the latest gate conclusion against a commit SHA (and posts a Check Run when `AIGOV_GITHUB_TOKEN` is set).
19. **Bind AWS SageMaker** → **Discover** → **Collect in-sync** → `IN_SYNC`. **Collect drifted version** → tokens revoked, adapter **CONTAIN**, gate **BLOCK** `RUNTIME_DRIFT`. Live clouds require `AIGOV_CLOUD_ADAPTER_MODE=live` and `aigov[aws]` / `[azure]` / `[gcp]`; without them the adapter fails closed.

Optional: load the internal analytics sample and gate with “simulate stale evidence” to see **REVIEW**. Attach an evaluation dated 2020 to a HIGH system to see **STALE** block.

## Layout

```text
contracts/openapi/aigov.yaml     HTTP contract
policies/rego/                   OPA/Rego gate
apps/api/                        FastAPI modular monolith
apps/web/                        Next.js portal
data/migrations/                 SQL snapshot of the Slice-1 schema
docs/adr/                        architecture decisions
infra/local/                     Postgres + OPA + API compose
```

## Design rules in force

See `docs/adr/`. In particular: control plane stays cloud-neutral; PostgreSQL is transactional truth; OPA decides the gate; fail closed; regulatory class is not the risk score; start as a modular monolith.

Local API defaults to SQLite so the walking skeleton runs without Docker. Compose (`make compose-up`) runs Postgres + OPA + the API.

## License

Apache-2.0
