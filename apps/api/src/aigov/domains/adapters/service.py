from __future__ import annotations

from aigov.domains.adapters.ports import BindingRuleError

PROVIDERS = frozenset({"aws", "azure", "gcp", "local"})
SCENARIOS = frozenset({"in_sync", "drift", "stopped"})
ENFORCE_ACTIONS = frozenset({"CONTAIN", "PERMIT"})
DEFAULT_SERVICE = {
    "aws": "sagemaker",
    "azure": "azure-openai",
    "gcp": "vertex",
    "local": "process",
}
ENFORCE_MECHANISM = {
    "aws": "sagemaker.UpdateEndpointWeightsAndCapacities",
    "azure": "azure-openai.DisableDeployment",
    "gcp": "vertex.UndeployModel",
    "local": "process.Stop",
}


def validate_binding(
    *,
    provider: str,
    resource_ref: str,
    service: str | None = None,
    region: str | None = None,
) -> tuple[str, str, str, str | None]:
    cloud = (provider or "").strip().lower()
    if cloud not in PROVIDERS:
        raise BindingRuleError("provider must be aws, azure, gcp, or local", "UNKNOWN_PROVIDER")
    ref = (resource_ref or "").strip()
    if not ref:
        raise BindingRuleError("resourceRef is required", "MISSING_RESOURCE_REF")
    resolved_service = (service or DEFAULT_SERVICE[cloud]).strip() or DEFAULT_SERVICE[cloud]
    resolved_region = (region or "").strip() or None
    return cloud, resolved_service, ref, resolved_region


def validate_scenario(scenario: str | None) -> str:
    value = (scenario or "in_sync").strip() or "in_sync"
    if value not in SCENARIOS:
        raise BindingRuleError("scenario must be in_sync, drift, or stopped", "UNKNOWN_SCENARIO")
    return value


def validate_enforce_action(action: str | None) -> str:
    value = (action or "CONTAIN").strip().upper() or "CONTAIN"
    if value not in ENFORCE_ACTIONS:
        raise BindingRuleError("action must be CONTAIN or PERMIT", "UNKNOWN_ENFORCE_ACTION")
    return value
