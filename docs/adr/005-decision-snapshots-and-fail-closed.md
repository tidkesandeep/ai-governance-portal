# ADR-005: Explainable decisions and fail-closed gates

## Status

Accepted

## Context

An approval that points at mutable rows is not auditable. A registry that cannot block a deploy is not a control plane.

## Decision

- The risk engine is rules-based and returns score, band, confidence, drivers, missing inputs, and engine version.
- Regulatory classification is stored separately from enterprise risk band (even if Slice 1 only populates both from the same registration).
- The deployment gate persists a `PolicyDecision` with the input digest, policy bundle version, and outcome.
- Audit events are hash-chained per aggregate.
- If policy evaluation fails unexpectedly, production-like deploys are blocked (fail closed).

Short-lived deployment authorization tokens, reconciliation, and agent action authz are deferred to later slices. The gate API is the first authorization surface.

## Consequences

Slice 1 can already demonstrate: register → assess → BLOCK with `MISSING_PRIVACY_APPROVAL` → attach approval → ALLOW.
