# ADR-010: Agent action and resource authorization

## Status

Accepted

## Context

A deployment ALLOW and a short-lived deploy token answer whether a version may run. They do not answer: may this agent invoke `payments.refund` on `account:retail-123` for $50 right now? An agent with undeclared tools is not governed. A ticket after the refund is not a control.

## Decision

- `AGENT` systems declare version-bound **capabilities**: an action, a resource pattern, an optional amount ceiling, and whether reviewer approval is required.
- Privileged actions (`payments.refund`, `payments.transfer`, `code.execute`, `secrets.read`, and peers) always require reviewer approval and cannot be self-approved (SoD).
- Action authorization is a separate fail-closed gate (`ALLOW` | `DENY`). There is no `REVIEW` outcome at action time.
- The gate denies when the system is not an agent, is not currently deploy-authorized, is `BLOCKED`, has an open incident, the action is undeclared, the resource does not match, the amount exceeds the ceiling, or a required capability approval is missing.
- `ALLOW` mints a short-lived HMAC action token bound to the action fingerprint, asset version, action, and resource. Incident promotion, version cut, and deploy revocation also revoke action tokens.
- Resolving an incident or re-approving a capability does not mint an action token; the action must be authorized again.

## Consequences

The refund-agent demo can proceed: deploy ALLOW → declare `payments.refund` on `account:retail-*` → reviewer approves → authorize retail refund ALLOW → wholesale or undeclared DENY → CRITICAL finding → action DENY `RUNTIME_INCIDENT`.
