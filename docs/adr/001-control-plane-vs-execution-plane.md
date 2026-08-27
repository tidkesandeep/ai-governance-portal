# ADR-001: Control plane vs execution plane

## Status

Accepted

## Context

The portal must govern AI systems that run on AWS, Azure, and Google Cloud without becoming a lowest-common-denominator wrapper around every cloud AI service.

## Decision

Governance logic (inventory, risk, controls, policy, decisions, authorization, evidence) lives in a cloud-neutral **control plane**. Cloud-specific discovery, enforcement hooks, and evidence collection live in **execution-plane adapters** behind ports.

Domain packages must not import AWS, Azure, or GCP SDKs.

## Consequences

- The same API contracts and policy bundles can govern assets in any cloud.
- Adapters can be fakes in local/CI and real later without rewriting the domain.
- We will not attempt a universal Terraform resource model for every provider service.
