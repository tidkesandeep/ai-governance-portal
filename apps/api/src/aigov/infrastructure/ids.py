from __future__ import annotations

import secrets
from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"
