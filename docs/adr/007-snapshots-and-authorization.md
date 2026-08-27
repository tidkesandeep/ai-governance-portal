# ADR-007: Immutable snapshots and short-lived deployment authorization

## Status

Accepted

## Context

A gate ALLOW that only stores `outcome=ALLOW` cannot answer: which facts, controls, evidence, policies, and approvals authorized this deploy? A long-lived reusable production token cannot be revoked when posture changes.

## Decision

- Every gate evaluation persists an immutable `GovernanceDecision` snapshot: asset version, risk digest, control digest, evidence digest, policy bundle/digest, approval digest, engine versions, and a `governance_fingerprint`.
- `ALLOW` issues a short-lived `DeploymentAuthorization` bound to that fingerprint, environment, asset version, and a unique nonce. It is HMAC-signed and revocable.
- Verification checks signature, expiry, revocation, nonce, and that the system's current asset version still matches the snapshot. Version cut or explicit revoke makes the authorization invalid.
- BLOCK/REVIEW snapshots are stored; they never mint an authorization.

## Consequences

CI/CD presents the authorization id + signature. The control plane can reconstruct why a deploy was allowed and can revoke it without waiting for TTL.
