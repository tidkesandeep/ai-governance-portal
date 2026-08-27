from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_writes_unpublished_outbox_then_publish_marks_it(client: TestClient) -> None:
    created = client.post(
        "/v1/ai-systems",
        json={
            "name": "Outbox Probe",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Prove dual-write",
            "owner": "payments-ml",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
        },
        headers=auth("demo"),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    system_id = body["system"]["id"]
    events = body["latestOutboxEvents"]
    assert events
    assert events[0]["eventType"] == "AISystemRegistered"
    assert events[0]["publishedAt"] is None
    assert events[0]["eventId"].startswith("evt_")

    published = client.post("/v1/outbox/publish", headers=auth("demo"))
    assert published.status_code == 200, published.text
    assert published.json()["published"] >= 1

    view = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
    assert view.status_code == 200
    after = view.json()["latestOutboxEvents"]
    assert after
    assert after[0]["publishedAt"] is not None


def test_outbox_publish_requires_bearer(client: TestClient) -> None:
    response = client.post("/v1/outbox/publish")
    assert response.status_code == 401
