# ADR-013: Operator plane — migrations, outbox, CLI, GitHub checks

## Status

Accepted

## Context

`create_all` cannot alter a live database. Audit events that exist only in PostgreSQL cannot feed CI, a lakehouse, or a SIEM. A portal click is not how a pipeline asks "may this version deploy?" A GitHub ticket after a merge is not a control.

## Decision

- **Alembic** is the schema migrator. API boot runs `upgrade head`. SQLAlchemy `create_all` is no longer the production path. `data/migrations/*.sql` remains a human-readable snapshot.
- Every hash-chained audit event is dual-written to an **`event_outbox`** row in the same transaction. A publisher marks rows published after a sink accepts them. The default sink is structured logs. If `AIGOV_KAFKA_BOOTSTRAP_SERVERS` is set, the sink is Kafka topic `aigov.governance.events`. Domain packages do not import a Kafka client.
- The **`aigov` CLI** is the operator/CI surface: `health`, `me`, `systems`, `gate` (exit 0/1/2 for ALLOW/BLOCK/REVIEW), `migrate`, `outbox publish`, and `github check`.
- A **GitHub check** records the latest deployment-gate outcome against a commit SHA. Webhooks are HMAC-verified (`X-Hub-Signature-256`). If a GitHub token is configured, the control plane also posts a Check Run. Missing GitHub credentials still persist the conclusion locally so the gate remains the system of record.

## Consequences

CI can fail a deploy without opening the portal. Downstream consumers read the outbox (or Kafka) without dual-writing from domain services. Schema changes become additive revisions instead of wiping SQLite files.
