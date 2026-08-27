# ADR-009: Findings, incidents, and runtime revocation

## Status

Accepted

## Context

A gate ALLOW and a short-lived token answer deploy-time authorization. They do not answer: if a fairness gap, eval regression, or security signal appears while the system is running, is it still authorized to operate? A ticket that does not revoke authorization is not a control.

## Decision

- Findings are version-bound records (`EVAL_REGRESSION`, `FAIRNESS_DRIFT`, `SECURITY_SIGNAL`, `DATA_DRIFT`, `POLICY_VIOLATION`, `HUMAN_REPORT`) with severity LOW–CRITICAL.
- HIGH and CRITICAL findings auto-promote to an `OPEN` incident, revoke active deployment authorizations, revoke granted exceptions, and set lifecycle `BLOCKED` immediately.
- MEDIUM and LOW findings stay open until a reviewer promotes or dismisses them.
- An open incident is a non-waivable `RUNTIME_INCIDENT` HIGH violation at the deployment gate. Resolving the incident does not mint a new authorization; the gate must be re-evaluated.
- The governance fingerprint includes an incident digest so later snapshots prove whether runtime containment was in force.

## Consequences

The fraud-model demo can proceed: ALLOW + ISSUED token → record CRITICAL eval regression → authorizations revoked (verify DENY) → gate BLOCK `RUNTIME_INCIDENT` → resolve incident → re-gate ALLOW.
