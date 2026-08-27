# ADR-008: Workflow cases, time-bounded exceptions, and SLA clocks

## Status

Accepted

## Context

A BLOCK with no case is an unowned finding. An exception that never expires is a permanent bypass. Slice 3 can mint a short-lived authorization, but it cannot record who is working the gate, when it is due, or a justified, expiring waiver.

## Decision

- `BLOCK` and `REVIEW` open (or refresh) a single `OPEN` workflow case per system. `ALLOW` closes it. The SLA clock starts when the case opens and is not reset by re-evaluation.
- SLA windows are deterministic: CRITICAL 8h, HIGH 24h, MEDIUM 72h, LOW 168h. Status is `ON_TRACK`, `DUE_SOON` (≤25% remaining), or `OVERDUE`. There is no background worker; status is computed on read.
- Exceptions waive a named violation code for a bounded time and the current asset version. Granting requires a reviewer role and segregation of duties. Hash failures, missing assessments, and policy-engine unavailability are not waivable.
- The gate receives only currently active exceptions. Expired, revoked, or version-unbound exceptions cannot satisfy a control. The governance fingerprint includes an exception digest. Revoking or version-cutting an exception revokes active deployment authorizations.

## Consequences

The fraud-model demo can proceed: BLOCK (missing evidence) → case with SLA → request exception → reviewer grant → ALLOW → revoke or cut version → BLOCK again.
