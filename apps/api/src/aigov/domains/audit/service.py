from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.infrastructure.ids import new_id
from aigov.infrastructure.models import AuditEventModel, EventOutboxModel


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(
    *,
    event_id: str,
    aggregate_id: str,
    event_type: str,
    actor: dict[str, Any],
    occurred_at: datetime,
    payload: dict[str, Any],
    previous_event_hash: str | None,
) -> str:
    envelope = {
        "event_id": event_id,
        "aggregate_id": aggregate_id,
        "event_type": event_type,
        "actor": actor,
        "occurred_at": occurred_at.isoformat(),
        "payload": payload,
        "previous_event_hash": previous_event_hash,
    }
    digest = hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class AuditLog:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        tenant_id: str,
        aggregate_id: str,
        event_type: str,
        actor: dict[str, Any],
        payload: dict[str, Any],
    ) -> AuditEventModel:
        previous = await self._session.scalar(
            select(AuditEventModel)
            .where(
                AuditEventModel.tenant_id == tenant_id,
                AuditEventModel.aggregate_id == aggregate_id,
            )
            .order_by(AuditEventModel.occurred_at.desc())
            .limit(1)
        )
        previous_hash = previous.hash if previous else None
        occurred_at = datetime.now(UTC)
        event_id = new_id("evt")
        event_hash = compute_event_hash(
            event_id=event_id,
            aggregate_id=aggregate_id,
            event_type=event_type,
            actor=actor,
            occurred_at=occurred_at,
            payload=payload,
            previous_event_hash=previous_hash,
        )
        row = AuditEventModel(
            id=event_id,
            tenant_id=tenant_id,
            aggregate_id=aggregate_id,
            event_type=event_type,
            actor=actor,
            occurred_at=occurred_at,
            payload=payload,
            hash=event_hash,
            previous_event_hash=previous_hash,
        )
        outbox = EventOutboxModel(
            id=new_id("obx"),
            tenant_id=tenant_id,
            aggregate_id=aggregate_id,
            event_id=event_id,
            event_type=event_type,
            payload={
                "eventId": event_id,
                "eventType": event_type,
                "tenantId": tenant_id,
                "aggregateId": aggregate_id,
                "occurredAt": occurred_at.isoformat(),
                "payload": payload,
                "hash": event_hash,
                "actor": actor,
            },
            occurred_at=occurred_at,
            published_at=None,
            publish_attempts=0,
            last_error=None,
        )
        self._session.add(row)
        self._session.add(outbox)
        await self._session.flush()
        return row

    async def list_for(self, *, tenant_id: str, aggregate_id: str) -> list[AuditEventModel]:
        result = await self._session.scalars(
            select(AuditEventModel)
            .where(
                AuditEventModel.tenant_id == tenant_id,
                AuditEventModel.aggregate_id == aggregate_id,
            )
            .order_by(AuditEventModel.occurred_at.asc())
        )
        return list(result)
