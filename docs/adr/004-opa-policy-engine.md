# ADR-004: OPA/Rego as the deployment policy engine

## Status

Accepted

## Context

Deployment gating must be versioned, testable, and explainable. Encoding production rules as scattered Python `if` statements makes policy unreviewable.

## Decision

Open Policy Agent evaluates deployment-gate input documents and returns `ALLOW | REVIEW | BLOCK` with reason codes. Rego lives in `policies/rego/` and is tested with `opa test`.

The API talks to OPA over HTTP when `AIGOV_OPA_URL` is set. When OPA is unavailable (unit tests / sparse local runs), an embedded evaluator implements the **same Slice-1 rule set and reason codes**. The embedded path is a compatibility adapter, not a second policy product; golden fixtures must pass on both.

Risk scoring stays in Python: it is a deterministic function, not a policy bundle.

## Consequences

- Policy reasons are structured (`code`, `severity`, `message`), never a bare boolean.
- High-severity violations fail closed (`BLOCK`).
- Unknown / stale evidence cannot satisfy a mandatory control (enforced as a violation).
