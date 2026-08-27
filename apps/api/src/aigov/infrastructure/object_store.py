from __future__ import annotations

from pathlib import Path
from typing import Protocol


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
