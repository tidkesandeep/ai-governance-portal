from __future__ import annotations

import json
import logging

from aigov.domains.outbox.service import OutboxError, OutboxSink, outbox_message
from aigov.infrastructure.models import EventOutboxModel

logger = logging.getLogger("aigov.outbox")


class LogOutboxSink:
    async def publish(self, row: EventOutboxModel) -> None:
        logger.info("outbox %s", json.dumps(outbox_message(row), default=str))


class KafkaOutboxSink:
    def __init__(self, bootstrap_servers: str, topic: str) -> None:
        self._bootstrap = bootstrap_servers
        self._topic = topic

    async def publish(self, row: EventOutboxModel) -> None:
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError as exc:
            raise OutboxError(
                "aiokafka is not installed; install aigov[events] to publish to Kafka",
                "KAFKA_UNAVAILABLE",
            ) from exc
        producer = AIOKafkaProducer(bootstrap_servers=self._bootstrap)
        try:
            await producer.start()
            body = json.dumps(outbox_message(row), default=str).encode("utf-8")
            await producer.send_and_wait(self._topic, body, key=row.aggregate_id.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 — sink must fail closed to retry
            raise OutboxError("Kafka publish failed", "KAFKA_UNAVAILABLE") from exc
        finally:
            await producer.stop()


def sink_from_settings(bootstrap_servers: str | None, topic: str) -> OutboxSink:
    if bootstrap_servers and bootstrap_servers.strip():
        return KafkaOutboxSink(bootstrap_servers.strip(), topic)
    return LogOutboxSink()
