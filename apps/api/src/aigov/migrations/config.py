from __future__ import annotations

from pathlib import Path

from alembic.config import Config

from aigov.infrastructure.models import Base

target_metadata = Base.metadata


def to_sync_url(url: str) -> str:
    if url.startswith("sqlite+aiosqlite://"):
        return "sqlite://" + url.removeprefix("sqlite+aiosqlite://")
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    return url


def script_location() -> Path:
    return Path(__file__).resolve().parent


def alembic_config(database_url: str) -> Config:
    cfg = Config(str(script_location() / "alembic.ini"))
    cfg.set_main_option("script_location", str(script_location()))
    cfg.set_main_option("sqlalchemy.url", to_sync_url(database_url))
    cfg.set_main_option("prepend_sys_path", ".")
    return cfg
