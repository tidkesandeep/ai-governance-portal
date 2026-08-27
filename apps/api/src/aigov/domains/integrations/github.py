from __future__ import annotations

import hashlib
import hmac
from typing import Any

CHECK_NAME = "aigov-deployment-gate"


class GitHubWebhookError(Exception):
    def __init__(self, detail: str, code: str = "GITHUB_WEBHOOK_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


def verify_signature(*, secret: str, body: bytes, header: str | None) -> None:
    if not secret.strip():
        raise GitHubWebhookError("GitHub webhook secret is not configured", "AUTH_UNAVAILABLE")
    if not header or not header.startswith("sha256="):
        raise GitHubWebhookError("missing X-Hub-Signature-256", "INVALID_SIGNATURE")
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header):
        raise GitHubWebhookError("invalid webhook signature", "INVALID_SIGNATURE")


def parse_system_id(payload: dict[str, Any]) -> str | None:
    client = payload.get("client_payload")
    if isinstance(client, dict) and client.get("systemId"):
        return str(client["systemId"]).strip() or None
    body = ""
    pull = payload.get("pull_request")
    if isinstance(pull, dict):
        body = str(pull.get("body") or "")
    for line in body.splitlines():
        if line.lower().startswith("aigov-system:"):
            return line.split(":", 1)[1].strip() or None
    return None


def parse_sha(payload: dict[str, Any]) -> str | None:
    client = payload.get("client_payload")
    if isinstance(client, dict) and client.get("sha"):
        return str(client["sha"]).strip() or None
    pull = payload.get("pull_request")
    if isinstance(pull, dict):
        head = pull.get("head") or {}
        if isinstance(head, dict) and head.get("sha"):
            return str(head["sha"])
    suite = payload.get("check_suite")
    if isinstance(suite, dict) and suite.get("head_sha"):
        return str(suite["head_sha"])
    return None


def parse_repo(payload: dict[str, Any]) -> str | None:
    repo = payload.get("repository")
    if isinstance(repo, dict) and repo.get("full_name"):
        return str(repo["full_name"])
    client = payload.get("client_payload")
    if isinstance(client, dict) and client.get("repo"):
        return str(client["repo"])
    return None


def conclusion_for_outcome(outcome: str) -> str:
    return {"ALLOW": "success", "REVIEW": "neutral", "BLOCK": "failure"}.get(outcome, "failure")
