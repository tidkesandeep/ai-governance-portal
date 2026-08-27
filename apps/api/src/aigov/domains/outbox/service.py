from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.infrastructure.ids import utcnow
from aigov.infrastructure.models import EventOutboxModel

OUTBOX_TOPIC = "aigov.governance.events"


class OutboxError(Exception):
    def __init__(self, detail: str, code: str = "OUTBOX_PUBLISH_FAILED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


class OutboxSink(Protocol):
    async def publish(self, row: EventOutboxModel) -> None: ...


def outbox_message(row: EventOutboxModel) -> dict[str, Any]:
    occurred = row.occurred_at
    occurred_at = occurred.isoformat() if isinstance(occurred, datetime) else occurred
    return {
        "eventId": row.event_id,
        "outboxId": row.id,
        "eventType": row.event_type,
        "tenantId": row.tenant_id,
        "aggregateId": row.aggregate_id,
        "occurredAt": occurred_at,
        "payload": row.payload,
        "topic": OUTBOX_TOPIC,
    }


async def publish_unpublished(
    session: AsyncSession,
    sink: OutboxSink,
    *,
    limit: int = 100,
    tenant_id: str | None = None,
) -> int:
    query = select(EventOutboxModel).where(EventOutboxModel.published_at.is_(None))
    if tenant_id:
        query = query.where(EventOutboxModel.tenant_id == tenant_id)
    result = await session.scalars(
        query.order_by(EventOutboxModel.occurred_at.asc()).limit(max(1, limit))
    )
    published = 0
    for row in result:
        try:
            await sink.publish(row)
            row.published_at = utcnow()
            row.last_error = None
            published += 1
        except OutboxError as exc:
            row.publish_attempts = int(row.publish_attempts or 0) + 1
            row.last_error = exc.detail[:500]
    await session.commit()
    return published
