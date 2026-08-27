from __future__ import annotations

import asyncio

from alembic import command
from sqlalchemy.ext.asyncio import AsyncEngine

from aigov.migrations.config import alembic_config


def upgrade_sync(database_url: str) -> None:
    command.upgrade(alembic_config(database_url), "head")


async def upgrade_head(engine: AsyncEngine, database_url: str) -> None:
    await asyncio.to_thread(upgrade_sync, database_url)
    _ = engine
