from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aigov.config import Settings
from aigov.infrastructure.migrate import upgrade_head

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings) -> None:
    global _engine, _sessionmaker
    connect_args = {}
    if settings.database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    _engine = create_async_engine(settings.database_url, echo=False, connect_args=connect_args)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)


def require_sessionmaker() -> async_sessionmaker[AsyncSession]:
    assert _sessionmaker is not None
    return _sessionmaker


async def create_schema(database_url: str) -> None:
    assert _engine is not None
    await upgrade_head(_engine, database_url)


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def session_scope() -> AsyncIterator[AsyncSession]:
    assert _sessionmaker is not None
    async with _sessionmaker() as session:
        yield session
