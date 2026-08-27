from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from aigov.config import get_settings
from aigov.domains.integrations.github import conclusion_for_outcome, verify_signature
from aigov.main import create_app


def _client(tmp_path, monkeypatch, **env: str) -> TestClient:
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return TestClient(create_app())


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def test_conclusion_mapping() -> None:
    assert conclusion_for_outcome("ALLOW") == "success"
    assert conclusion_for_outcome("REVIEW") == "neutral"
    assert conclusion_for_outcome("BLOCK") == "failure"
    assert conclusion_for_outcome("UNKNOWN") == "failure"


def test_verify_signature_rejects_missing_secret() -> None:
    from aigov.domains.integrations.github import GitHubWebhookError

    with pytest.raises(GitHubWebhookError) as exc:
        verify_signature(secret="", body=b"{}", header="sha256=abc")
    assert exc.value.code == "AUTH_UNAVAILABLE"


def test_webhook_rejects_bad_signature(tmp_path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, AIGOV_GITHUB_WEBHOOK_SECRET="s3cret") as client:
        body = b'{"client_payload":{"systemId":"sys_x","sha":"abc"}}'
        response = client.post(
            "/v1/integrations/github/webhook",
            content=body,
            headers={"X-Hub-Signature-256": "sha256=deadbeef", "Content-Type": "application/json"},
        )
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_SIGNATURE"


def test_webhook_unavailable_without_secret(tmp_path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as client:
        response = client.post(
            "/v1/integrations/github/webhook",
            content=b"{}",
            headers={"X-Hub-Signature-256": "sha256=abc", "Content-Type": "application/json"},
        )
        assert response.status_code == 503
        assert response.json()["code"] == "AUTH_UNAVAILABLE"


def test_webhook_requires_system_id(tmp_path, monkeypatch) -> None:
    secret = "s3cret"
    body = json.dumps({"client_payload": {"sha": "abc1234"}}).encode()
    with _client(tmp_path, monkeypatch, AIGOV_GITHUB_WEBHOOK_SECRET=secret) as client:
        response = client.post(
            "/v1/integrations/github/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(secret, body),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 422
        assert response.json()["code"] == "MISSING_SYSTEM_ID"


def test_github_check_persists_locally_without_token(tmp_path, monkeypatch) -> None:
    secret = "s3cret"
    with _client(tmp_path, monkeypatch, AIGOV_GITHUB_WEBHOOK_SECRET=secret) as client:
        created = client.post(
            "/v1/ai-systems",
            json={
                "name": "GitHub Probe",
                "systemType": "PREDICTIVE_MODEL",
                "businessPurpose": "CI gate",
                "owner": "payments-ml",
                "environment": "production",
                "dataClassification": "INTERNAL",
                "geography": "US",
                "autonomyLevel": "HUMAN_IN_LOOP",
            },
            headers=auth("demo"),
        )
        assert created.status_code == 201, created.text
        system_id = created.json()["system"]["id"]
        recorded = client.post(
            f"/v1/ai-systems/{system_id}/github-checks",
            json={"sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "repo": "acme/fraud"},
            headers=auth("demo"),
        )
        assert recorded.status_code == 201, recorded.text
        check = recorded.json()
        assert check["conclusion"] == "failure"
        assert check["htmlUrl"] is None
        assert check["sha"].startswith("deadbeef")

        payload = {
            "client_payload": {
                "systemId": system_id,
                "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "repo": "acme/fraud",
            }
        }
        body = json.dumps(payload).encode()
        webhook = client.post(
            "/v1/integrations/github/webhook",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(secret, body),
                "Content-Type": "application/json",
            },
        )
        assert webhook.status_code == 201, webhook.text
        view = client.get(f"/v1/ai-systems/{system_id}", headers=auth("demo"))
        assert view.status_code == 200
        checks = view.json()["githubChecks"]
        assert len(checks) >= 2
        assert view.json()["latestGithubCheck"]["id"] == webhook.json()["id"]


def test_github_check_posts_check_run_when_token_configured(tmp_path, monkeypatch) -> None:
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {"html_url": "https://github.com/acme/fraud/runs/1"}
    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=None)
    fake_client.post = AsyncMock(return_value=fake_response)
    monkeypatch.setattr("aigov.infrastructure.github.httpx.AsyncClient", lambda **_k: fake_client)

    with _client(
        tmp_path,
        monkeypatch,
        AIGOV_GITHUB_TOKEN="ghs_test",
    ) as client:
        created = client.post(
            "/v1/ai-systems",
            json={
                "name": "GitHub API Probe",
                "systemType": "PREDICTIVE_MODEL",
                "businessPurpose": "CI gate",
                "owner": "payments-ml",
                "environment": "dev",
                "dataClassification": "INTERNAL",
                "geography": "US",
                "autonomyLevel": "HUMAN_IN_LOOP",
            },
            headers=auth("demo"),
        )
        system_id = created.json()["system"]["id"]
        recorded = client.post(
            f"/v1/ai-systems/{system_id}/github-checks",
            json={"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "repo": "acme/fraud"},
            headers=auth("demo"),
        )
        assert recorded.status_code == 201, recorded.text
        assert recorded.json()["htmlUrl"] == "https://github.com/acme/fraud/runs/1"
        fake_client.post.assert_awaited()
