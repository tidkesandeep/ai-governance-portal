# ADR-006: Evidence immutability and freshness

## Status

Accepted

## Context

A governance ALLOW that points at a mutable attachment is not reconstructable. Unknown or stale files must not silently satisfy a mandatory control.

## Decision

- Evidence bytes are stored behind an `ObjectStorePort`. Slice 2 uses a local filesystem adapter; S3/Blob/GCS remain later execution-plane implementations.
- The governance record stores URI, SHA-256 digest, collector version, collected-at, and the asset version the artifact is bound to.
- Control assessment is `PASS | FAIL | STALE | UNKNOWN | NOT_APPLICABLE`. `UNKNOWN` cannot satisfy a mandatory control. `STALE` is evaluated against that control's max age. `FAIL` (hash mismatch) is blocking.
- Evidence content is untrusted input: it is never executed or interpreted as policy.
- An evaluation bound to version N cannot satisfy version N+1.

## Consequences

The deployment gate reads control posture assembled from evidence, not a caller-supplied `evidenceStale` flag alone. The flag remains as a fixture override for low-risk review demos.
