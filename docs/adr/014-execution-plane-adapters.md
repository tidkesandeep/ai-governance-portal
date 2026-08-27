# ADR-014: Execution-plane adapters behind ports

## Status

Accepted

## Context

The control plane authorizes a version. It does not itself start a SageMaker endpoint, disable an Azure OpenAI deployment, or undeploy a Vertex model. Discovery, runtime collection, and enforcement are cloud-specific. Putting AWS, Azure, or GCP SDKs in domain packages would make the gate a lowest-common-denominator wrapper and break local/CI.

## Decision

- Execution-plane work is three ports: **discover**, **collect**, and **enforce**. Domain packages speak those ports only.
- An AI system must be **bound** to a provider (`aws` | `azure` | `gcp` | `local`), region, and resource reference before an adapter may run.
- Default mode is **fake**: deterministic in-process simulators (SageMaker, Azure OpenAI, Vertex AI) so local and CI never call a cloud. `AIGOV_CLOUD_ADAPTER_MODE=live` selects live adapters, which fail closed (`ADAPTER_UNAVAILABLE`) unless the matching optional extra (`aigov[aws]`, `aigov[azure]`, `aigov[gcp]`) is installed.
- **Collect** feeds `record_observation` so reconciliation remains the system of record. A HIGH drift contain still revokes tokens in the control plane and, when a binding exists, asks the adapter to **CONTAIN** at the edge.
- Evidence bytes stay behind `ObjectStorePort`. Local filesystem remains the default. `s3` / `azure` / `gcs` mint cloud URIs; live object stores fail closed without their SDK.

## Consequences

The fraud-model demo can bind AWS SageMaker, collect in-sync, collect a drifted version (tokens revoked, `RUNTIME_DRIFT`), and record a CONTAIN enforcement without credentials. Real clouds can be wired later without rewriting inventory, risk, or the gate.
