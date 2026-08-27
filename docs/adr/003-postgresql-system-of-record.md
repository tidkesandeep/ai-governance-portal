# ADR-003: PostgreSQL as governance system of record

## Status

Accepted

## Context

Governance state is transactional: registrations, assessments, approvals, exceptions, and authorizations must be consistent. A graph database or event store as primary would overfit the first slices.

## Decision

PostgreSQL is authoritative transactional state. Object storage will hold evidence bytes later. The audit table is append-only with a hash chain. Kafka, search, and a lakehouse are explicitly deferred until a workload justifies them.

SQLite is allowed only for unit tests.

## Consequences

- Every domain table includes `tenant_id`.
- Tenant identity is taken from the authenticated principal, never from a request field.
- Schema migrations will move to Alembic after the walking skeleton; Slice 1 uses SQLAlchemy `create_all` plus a documented SQL snapshot.
