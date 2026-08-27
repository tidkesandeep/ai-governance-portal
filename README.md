# AI Governance Control Plane

Centralized governance control plane for predictive ML, GenAI applications, and AI agents. This repository implements **Slice 0–1** of the architecture: contracts, a FastAPI modular monolith, deterministic risk scoring, an OPA-aligned deployment gate, append-only audit events, and a thin Next.js portal.

The portal is not a model registry. It exists to answer: what AI exists, what risk and controls apply, whether it is authorized to deploy, and what evidence/decision snapshot proves that.

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
| Cloud adapters, Kafka, evidence store, agent authz | Later slices |

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
3. Evaluate production gate → **BLOCK** with `MISSING_PRIVACY_APPROVAL` (and related HIGH reasons)
4. Switch actor to reviewer → record privacy, security, and risk approvals
5. Evaluate gate again → **ALLOW**
6. Confirm the audit trail hash-chains

Optional: load the internal analytics sample and gate with “simulate stale evidence” to see **REVIEW**.

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
