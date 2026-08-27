from __future__ import annotations

from typing import Any

from aigov.domains.adapters.ports import CollectedObservation, RuntimeBindingView
from aigov.domains.adapters.service import ENFORCE_MECHANISM


class FakeAdapter:
    provider: str
    service: str

    def __init__(self, provider: str, service: str) -> None:
        self.provider = provider
        self.service = service

    async def discover(self, binding: RuntimeBindingView) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "service": binding.service or self.service,
            "resourceRef": binding.resource_ref,
            "region": binding.region,
            "status": "InService",
            "mode": "fake",
            "locator": _locator(self.provider, binding),
        }

    async def collect(
        self,
        binding: RuntimeBindingView,
        *,
        current_version_id: str,
        environment: str,
        scenario: str,
    ) -> CollectedObservation:
        running = scenario != "stopped"
        version = current_version_id if scenario != "drift" else "ver_not_authorized"
        fingerprint = None if scenario != "drift" else "sha256:execution-plane-drift"
        return CollectedObservation(
            running=running,
            asset_version_id=version,
            environment=environment,
            cloud=self.provider,
            region=binding.region,
            fingerprint=fingerprint,
            raw={
                "provider": self.provider,
                "service": binding.service or self.service,
                "scenario": scenario,
                "mode": "fake",
                "locator": _locator(self.provider, binding),
            },
        )

    async def enforce(
        self,
        binding: RuntimeBindingView,
        *,
        action: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "action": action,
            "reason": reason,
            "applied": True,
            "mode": "fake",
            "mechanism": ENFORCE_MECHANISM[self.provider],
            "locator": _locator(self.provider, binding),
        }


class FakeAwsAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__("aws", "sagemaker")


class FakeAzureAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__("azure", "azure-openai")


class FakeGcpAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__("gcp", "vertex")


class FakeLocalAdapter(FakeAdapter):
    def __init__(self) -> None:
        super().__init__("local", "process")


def _locator(provider: str, binding: RuntimeBindingView) -> str:
    region = binding.region or "unspecified"
    if provider == "aws":
        return f"arn:aws:sagemaker:{region}:123456789012:endpoint/{binding.resource_ref}"
    if provider == "azure":
        return (
            f"/subscriptions/demo/resourceGroups/aigov/providers/"
            f"Microsoft.CognitiveServices/{binding.resource_ref}"
        )
    if provider == "gcp":
        return f"projects/demo/locations/{region}/endpoints/{binding.resource_ref}"
    return f"local://{binding.resource_ref}"
