# ADR-011: Desired versus observed reconciliation

## Status

Accepted

## Context

A gate ALLOW and a short-lived token answer whether a version was authorized at decision time. They do not answer: is that version what is actually running? A ticket that does not revoke authorization is not a control.

## Decision

- Desired state is taken from the latest `ALLOW` snapshot for the current asset version (`authorized`, `assetVersionId`, `environment`, `fingerprint`). If that snapshot is missing or not `ALLOW` for the current version, `authorized` is false.
- Observed state arrives through `POST /v1/ai-systems/{id}/observations` from the execution-plane collector (`running`, version, environment, cloud, region, fingerprint, `observedAt`).
- Reconciliation is `IN_SYNC`, `DRIFT`, or `UNKNOWN`. No observation is `UNKNOWN` and does not block (bootstrap). A stale observation (`now - observedAt >= observation_max_age_seconds`, default 900) is `UNKNOWN` plus waivable `STALE_OBSERVATION`.
- HIGH drift codes are `ASSET_VERSION_MISMATCH`, `FINGERPRINT_MISMATCH`, `UNAUTHORIZED_RUNTIME`, and `ENVIRONMENT_MISMATCH`. On HIGH drift the control plane persists the observation and reconciliation, revokes deploy and action tokens, sets lifecycle `BLOCKED`, and opens or refreshes a `RECONCILIATION` workflow case.
- Open HIGH drift is a non-waivable `RUNTIME_DRIFT` HIGH violation at the deployment gate. A later matching observation sets `IN_SYNC` but does not mint a new authorization; the gate must be re-evaluated.
- The governance fingerprint includes a reconciliation digest so later snapshots prove whether runtime drift was in force.

## Consequences

The fraud-model demo can proceed: ALLOW + ISSUED token → report in-sync → `IN_SYNC` → report a drifted version → tokens revoked, status `BLOCKED`, gate `BLOCK` `RUNTIME_DRIFT` → report matching again → `IN_SYNC` but still `BLOCKED` / no new token → re-gate `ALLOW`.
