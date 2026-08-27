from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.infrastructure.object_store import LocalObjectStore, PrefixedObjectStore
from aigov.main import create_app
from tests.test_api import allow_fraud, auth


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


def test_collect_requires_binding(client: TestClient) -> None:
    created = client.post(
        "/v1/ai-systems",
        json={
            "name": "Unbound probe",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Adapter bind required",
            "owner": "payments-ml",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
        },
        headers=auth("demo"),
    )
    system_id = created.json()["system"]["id"]
    response = client.post(
        f"/v1/ai-systems/{system_id}/runtime/collect",
        json={"scenario": "in_sync"},
        headers=auth("demo"),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "BINDING_REQUIRED"


def test_aws_fake_discover_collect_in_sync_and_drift_contain(client: TestClient) -> None:
    system_id, _decision = allow_fraud(client)
    bound = client.post(
        f"/v1/ai-systems/{system_id}/runtime-bindings",
        json={"provider": "aws", "resourceRef": "fraud-endpoint", "region": "us-east-1"},
        headers=auth("demo"),
    )
    assert bound.status_code == 201, bound.text
    binding = bound.json()["runtimeBinding"]
    assert binding["provider"] == "aws"
    assert binding["service"] == "sagemaker"
    assert binding["status"] == "ACTIVE"

    discovered = client.post(
        f"/v1/ai-systems/{system_id}/runtime/discover",
        headers=auth("demo"),
    )
    assert discovered.status_code == 201, discovered.text
    run = discovered.json()["latestAdapterRun"]
    assert run["kind"] == "discover"
    assert run["status"] == "SUCCEEDED"
    assert run["result"]["mode"] == "fake"
    assert "sagemaker" in run["result"]["locator"]

    synced = client.post(
        f"/v1/ai-systems/{system_id}/runtime/collect",
        json={"scenario": "in_sync"},
        headers=auth("demo"),
    )
    assert synced.status_code == 201, synced.text
    assert synced.json()["latestReconciliation"]["status"] == "IN_SYNC"
    assert synced.json()["latestObservation"]["cloud"] == "aws"

    drifted = client.post(
        f"/v1/ai-systems/{system_id}/runtime/collect",
        json={"scenario": "drift"},
        headers=auth("demo"),
    )
    assert drifted.status_code == 201, drifted.text
    assert drifted.json()["system"]["status"] == "BLOCKED"
    assert drifted.json()["latestReconciliation"]["status"] == "DRIFT"
    enforce = drifted.json()["latestAdapterRun"]
    assert enforce["kind"] == "enforce"
    assert enforce["action"] == "CONTAIN"
    assert enforce["status"] == "SUCCEEDED"
    gate = client.post(
        f"/v1/ai-systems/{system_id}/deployments/gate",
        json={},
        headers=auth("demo"),
    )
    assert gate.status_code == 200
    assert gate.json()["outcome"] == "BLOCK"
    assert "RUNTIME_DRIFT" in {reason["code"] for reason in gate.json()["reasons"]}


def test_azure_and_gcp_fake_discover_shapes(client: TestClient) -> None:
    created = client.post(
        "/v1/ai-systems",
        json={
            "name": "Multi-cloud probe",
            "systemType": "GENAI_APP",
            "businessPurpose": "Adapter shapes",
            "owner": "platform",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
        },
        headers=auth("demo"),
    )
    system_id = created.json()["system"]["id"]
    azure = client.post(
        f"/v1/ai-systems/{system_id}/runtime-bindings",
        json={"provider": "azure", "resourceRef": "gpt4-deploy", "region": "eastus"},
        headers=auth("demo"),
    )
    assert azure.status_code == 201
    discovered = client.post(f"/v1/ai-systems/{system_id}/runtime/discover", headers=auth("demo"))
    assert discovered.json()["latestAdapterRun"]["result"]["service"] == "azure-openai"
    locator = discovered.json()["latestAdapterRun"]["result"]["locator"]
    assert "Microsoft.CognitiveServices" in locator

    gcp = client.post(
        f"/v1/ai-systems/{system_id}/runtime-bindings",
        json={"provider": "gcp", "resourceRef": "fraud-ep", "region": "us-central1"},
        headers=auth("demo"),
    )
    assert gcp.status_code == 201
    assert gcp.json()["runtimeBinding"]["provider"] == "gcp"
    discovered = client.post(f"/v1/ai-systems/{system_id}/runtime/discover", headers=auth("demo"))
    assert discovered.json()["latestAdapterRun"]["result"]["service"] == "vertex"
    assert "endpoints/fraud-ep" in discovered.json()["latestAdapterRun"]["result"]["locator"]


def test_explicit_enforce_permit(client: TestClient) -> None:
    created = client.post(
        "/v1/ai-systems",
        json={
            "name": "Enforce probe",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Permit",
            "owner": "payments-ml",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
        },
        headers=auth("demo"),
    )
    system_id = created.json()["system"]["id"]
    client.post(
        f"/v1/ai-systems/{system_id}/runtime-bindings",
        json={"provider": "local", "resourceRef": "pid-1"},
        headers=auth("demo"),
    )
    response = client.post(
        f"/v1/ai-systems/{system_id}/runtime/enforce",
        json={"action": "PERMIT"},
        headers=auth("demo"),
    )
    assert response.status_code == 201, response.text
    run = response.json()["latestAdapterRun"]
    assert run["action"] == "PERMIT"
    assert run["result"]["applied"] is True


def test_live_mode_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("AIGOV_CLOUD_ADAPTER_MODE", "live")
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        created = client.post(
            "/v1/ai-systems",
            json={
                "name": "Live probe",
                "systemType": "PREDICTIVE_MODEL",
                "businessPurpose": "Fail closed",
                "owner": "payments-ml",
                "environment": "dev",
                "dataClassification": "INTERNAL",
                "geography": "US",
                "autonomyLevel": "HUMAN_IN_LOOP",
            },
            headers=auth("demo"),
        )
        system_id = created.json()["system"]["id"]
        client.post(
            f"/v1/ai-systems/{system_id}/runtime-bindings",
            json={"provider": "aws", "resourceRef": "prod-ep", "region": "us-east-1"},
            headers=auth("demo"),
        )
        response = client.post(
            f"/v1/ai-systems/{system_id}/runtime/discover",
            headers=auth("demo"),
        )
        assert response.status_code == 503
        assert response.json()["code"] == "ADAPTER_UNAVAILABLE"
    get_settings.cache_clear()


def test_adapter_status_endpoint(client: TestClient) -> None:
    response = client.get("/v1/adapters", headers=auth("demo"))
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "fake"
    assert set(body["providers"]) == {"aws", "azure", "gcp", "local"}


@pytest.mark.asyncio
async def test_prefixed_object_store_mints_s3_uri(tmp_path) -> None:
    inner = LocalObjectStore(tmp_path / "bytes")
    store = PrefixedObjectStore(inner, "s3", "aigov-evidence")
    uri = await store.put("card.md", b"# card")
    assert uri == "s3://aigov-evidence/card.md"
    assert await store.get("card.md") == b"# card"


def test_adapter_domain_does_not_import_cloud_sdks() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "aigov" / "domains"
    blob = "".join(path.read_text() for path in root.rglob("*.py"))
    for needle in ("boto3", "botocore", "azure.identity", "google.cloud"):
        assert needle not in blob
