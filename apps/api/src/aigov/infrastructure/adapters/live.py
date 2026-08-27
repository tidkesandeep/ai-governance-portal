from __future__ import annotations

from typing import Any

from aigov.domains.adapters.ports import AdapterError, CollectedObservation, RuntimeBindingView

_LIVE_HINT = {
    "aws": "install aigov[aws] and configure AWS credentials",
    "azure": "install aigov[azure] and configure Azure credentials",
    "gcp": "install aigov[gcp] and configure GCP credentials",
}


class LiveAdapter:
    def __init__(self, provider: str) -> None:
        self.provider = provider

    def _unavailable(self) -> AdapterError:
        hint = _LIVE_HINT.get(self.provider, "configure cloud credentials")
        return AdapterError(
            f"live {self.provider} adapter is unavailable; {hint}",
            "ADAPTER_UNAVAILABLE",
        )

    async def discover(self, binding: RuntimeBindingView) -> dict[str, Any]:
        _ = binding
        raise self._unavailable()

    async def collect(
        self,
        binding: RuntimeBindingView,
        *,
        current_version_id: str,
        environment: str,
        scenario: str,
    ) -> CollectedObservation:
        _ = (binding, current_version_id, environment, scenario)
        raise self._unavailable()

    async def enforce(
        self,
        binding: RuntimeBindingView,
        *,
        action: str,
        reason: str,
    ) -> dict[str, Any]:
        _ = (binding, action, reason)
        raise self._unavailable()


class LiveAwsAdapter(LiveAdapter):
    def __init__(self) -> None:
        super().__init__("aws")


class LiveAzureAdapter(LiveAdapter):
    def __init__(self) -> None:
        super().__init__("azure")


class LiveGcpAdapter(LiveAdapter):
    def __init__(self) -> None:
        super().__init__("gcp")
