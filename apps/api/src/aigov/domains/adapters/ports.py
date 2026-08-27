from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class AdapterError(Exception):
    def __init__(self, detail: str, code: str = "ADAPTER_UNAVAILABLE") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


class BindingRuleError(Exception):
    def __init__(self, detail: str, code: str = "BINDING_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


@dataclass(frozen=True)
class RuntimeBindingView:
    id: str
    system_id: str
    provider: str
    service: str
    resource_ref: str
    region: str | None
    account_ref: str | None


@dataclass(frozen=True)
class CollectedObservation:
    running: bool
    asset_version_id: str | None
    environment: str | None
    cloud: str
    region: str | None
    fingerprint: str | None
    raw: dict[str, Any]


class ExecutionAdapter(Protocol):
    provider: str

    async def discover(self, binding: RuntimeBindingView) -> dict[str, Any]: ...

    async def collect(
        self,
        binding: RuntimeBindingView,
        *,
        current_version_id: str,
        environment: str,
        scenario: str,
    ) -> CollectedObservation: ...

    async def enforce(
        self,
        binding: RuntimeBindingView,
        *,
        action: str,
        reason: str,
    ) -> dict[str, Any]: ...
