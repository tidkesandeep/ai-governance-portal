"""Alembic revision: runtime bindings and adapter runs."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from aigov.infrastructure.models import AdapterRunModel, RuntimeBindingModel

revision: str = "010_cloud_adapters"
down_revision: str | Sequence[str] | None = "009_operator_plane"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    RuntimeBindingModel.__table__.create(bind=bind, checkfirst=True)
    AdapterRunModel.__table__.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    AdapterRunModel.__table__.drop(bind=bind, checkfirst=True)
    RuntimeBindingModel.__table__.drop(bind=bind, checkfirst=True)
