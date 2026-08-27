# ADR-002: Modular monolith first

## Status

Accepted

## Context

The architecture identifies many bounded contexts (assets, risk, policy, workflow, evidence, findings, adapters). Premature microservice extraction would dominate operational cost for a single-team delivery.

## Decision

Ship one FastAPI deployable with strict domain packages and explicit events/APIs at the boundaries. Extract a service only when an operational reason appears (scale, failure isolation, independent lifecycle).

## Consequences

- Local development is `docker compose` plus two processes (API, web).
- Package imports across domains go through application services / ports, not random internals.
- Kafka is an event *contract*, not a day-one broker requirement. Slice 1 persists audit events in PostgreSQL; an outbox publisher can follow.
