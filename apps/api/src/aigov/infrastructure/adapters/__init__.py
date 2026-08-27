from __future__ import annotations

from aigov.config import Settings
from aigov.domains.adapters.ports import AdapterError, ExecutionAdapter
from aigov.infrastructure.adapters.fake import (
    FakeAwsAdapter,
    FakeAzureAdapter,
    FakeGcpAdapter,
    FakeLocalAdapter,
)
from aigov.infrastructure.adapters.live import LiveAwsAdapter, LiveAzureAdapter, LiveGcpAdapter


class ExecutionPlane:
    def __init__(self, adapters: dict[str, ExecutionAdapter], *, mode: str) -> None:
        self._adapters = adapters
        self.mode = mode

    @property
    def providers(self) -> list[str]:
        return sorted(self._adapters)

    def adapter(self, provider: str) -> ExecutionAdapter:
        try:
            return self._adapters[provider]
        except KeyError as exc:
            raise AdapterError(f"no adapter registered for {provider}", "UNKNOWN_PROVIDER") from exc


def execution_plane_from_settings(settings: Settings) -> ExecutionPlane:
    mode = (settings.cloud_adapter_mode or "fake").strip().lower() or "fake"
    if mode == "live":
        return ExecutionPlane(
            {
                "aws": LiveAwsAdapter(),
                "azure": LiveAzureAdapter(),
                "gcp": LiveGcpAdapter(),
                "local": FakeLocalAdapter(),
            },
            mode="live",
        )
    return ExecutionPlane(
        {
            "aws": FakeAwsAdapter(),
            "azure": FakeAzureAdapter(),
            "gcp": FakeGcpAdapter(),
            "local": FakeLocalAdapter(),
        },
        mode="fake",
    )
