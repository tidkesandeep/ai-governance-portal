from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from aigov.infrastructure.migrate import upgrade_sync
from aigov.migrations.config import to_sync_url


def test_to_sync_url_rewrites_async_drivers() -> None:
    assert to_sync_url("sqlite+aiosqlite:///./aigov.db") == "sqlite:///./aigov.db"
    assert (
        to_sync_url("postgresql+asyncpg://aigov:aigov@localhost:5432/aigov")
        == "postgresql+psycopg://aigov:aigov@localhost:5432/aigov"
    )


def test_upgrade_head_creates_outbox_and_github_tables(tmp_path) -> None:
    db_path = tmp_path / "migrate.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    upgrade_sync(url)
    engine = create_engine(to_sync_url(url))
    tables = set(inspect(engine).get_table_names())
    assert "event_outbox" in tables
    assert "github_checks" in tables
    assert "runtime_bindings" in tables
    assert "adapter_runs" in tables
    assert "alembic_version" in tables
    assert "ai_systems" in tables
    with engine.connect() as conn:
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert revision == "010_cloud_adapters"
