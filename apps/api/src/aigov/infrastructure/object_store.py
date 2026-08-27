from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ObjectStorePort(Protocol):
    async def put(self, key: str, data: bytes) -> str: ...

    async def get(self, key: str) -> bytes: ...


class LocalObjectStore:
    """Filesystem adapter. Cloud object stores implement the same port later."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        relative = Path(key)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid object key")
        return self._root.joinpath(relative)

    async def put(self, key: str, data: bytes) -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return f"file://{path}"

    async def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()


class PrefixedObjectStore:
    """Local bytes with a cloud URI scheme so evidence records show the execution-plane locator."""

    def __init__(self, inner: LocalObjectStore, scheme: str, bucket: str) -> None:
        self._inner = inner
        self._scheme = scheme
        self._bucket = bucket

    async def put(self, key: str, data: bytes) -> str:
        await self._inner.put(key, data)
        return f"{self._scheme}://{self._bucket}/{key}"

    async def get(self, key: str) -> bytes:
        return await self._inner.get(key)


def object_store_from_settings(settings: Any) -> ObjectStorePort:
    root = settings.evidence_dir
    backend = (getattr(settings, "object_store", None) or "local").strip().lower()
    bucket = (getattr(settings, "object_store_bucket", None) or "aigov-evidence").strip()
    local = LocalObjectStore(root)
    if backend == "s3":
        return PrefixedObjectStore(local, "s3", bucket)
    if backend in {"azure", "azblob"}:
        return PrefixedObjectStore(local, "azblob", bucket)
    if backend in {"gcs", "gs"}:
        return PrefixedObjectStore(local, "gs", bucket)
    return local
