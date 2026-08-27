from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any

import httpx

from aigov.config import get_settings

GATE_EXIT = {"ALLOW": 0, "REVIEW": 2, "BLOCK": 1}


def gate_exit_code(outcome: str) -> int:
    return GATE_EXIT.get(outcome, 1)


def _api_url(override: str | None) -> str:
    if override:
        return override.rstrip("/")
    return get_settings().api_url.rstrip("/")


def request(
    method: str,
    path: str,
    *,
    token: str,
    api_url: str,
    json: dict[str, Any] | None = None,
) -> httpx.Response:
    with httpx.Client(base_url=api_url, timeout=15.0) as client:
        return client.request(
            method,
            path,
            json=json,
            headers={"Authorization": f"Bearer {token}"},
        )


def _print_json(payload: Any) -> None:
    import json

    print(json.dumps(payload, indent=2, default=str))


def cmd_health(args: argparse.Namespace) -> int:
    response = request("GET", "/health", token=args.token, api_url=_api_url(args.api_url))
    _print_json(response.json())
    return 0 if response.status_code == 200 else 1


def cmd_me(args: argparse.Namespace) -> int:
    response = request("GET", "/v1/me", token=args.token, api_url=_api_url(args.api_url))
    _print_json(response.json())
    return 0 if response.status_code == 200 else 1


def cmd_systems(args: argparse.Namespace) -> int:
    response = request("GET", "/v1/ai-systems", token=args.token, api_url=_api_url(args.api_url))
    _print_json(response.json())
    return 0 if response.status_code == 200 else 1


def cmd_gate(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {}
    if args.environment:
        body["environment"] = args.environment
    response = request(
        "POST",
        f"/v1/ai-systems/{args.system_id}/deployments/gate",
        token=args.token,
        api_url=_api_url(args.api_url),
        json=body,
    )
    payload = response.json()
    _print_json(payload)
    if response.status_code != 200:
        return 1
    return gate_exit_code(str(payload.get("outcome") or "BLOCK"))


def cmd_migrate(_args: argparse.Namespace) -> int:
    from aigov.infrastructure.migrate import upgrade_sync

    get_settings.cache_clear()
    settings = get_settings()
    upgrade_sync(settings.database_url)
    print("migrated to head")
    return 0


def cmd_outbox_publish(args: argparse.Namespace) -> int:
    return asyncio.run(_publish_outbox(args.limit))


async def _publish_outbox(limit: int) -> int:
    from aigov.domains.outbox.service import publish_unpublished
    from aigov.infrastructure.db import dispose_engine, init_engine, require_sessionmaker
    from aigov.infrastructure.outbox import sink_from_settings

    get_settings.cache_clear()
    settings = get_settings()
    init_engine(settings)
    try:
        async with require_sessionmaker()() as session:
            sink = sink_from_settings(settings.kafka_bootstrap_servers, settings.kafka_topic)
            count = await publish_unpublished(session, sink, limit=limit)
            print(f"published {count}")
            return 0
    finally:
        await dispose_engine()


def cmd_github_check(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {"sha": args.sha}
    if args.repo:
        body["repo"] = args.repo
    response = request(
        "POST",
        f"/v1/ai-systems/{args.system_id}/github-checks",
        token=args.token,
        api_url=_api_url(args.api_url),
        json=body,
    )
    _print_json(response.json())
    return 0 if response.status_code in {200, 201} else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aigov",
        description="Operator and CI surface for the AI governance control plane.",
    )
    parser.add_argument("--token", default=os.environ.get("AIGOV_TOKEN", "demo"))
    parser.add_argument("--api-url", default=os.environ.get("AIGOV_API_URL"))
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("health", help="GET /health")
    sub.add_parser("me", help="GET /v1/me")
    sub.add_parser("systems", help="List AI systems for the token tenant")

    gate = sub.add_parser(
        "gate", help="Evaluate the deployment gate; exit 0/1/2 for ALLOW/BLOCK/REVIEW"
    )
    gate.add_argument("system_id")
    gate.add_argument("--environment", default=None)

    sub.add_parser("migrate", help="Apply Alembic migrations to head")

    outbox = sub.add_parser("outbox", help="Transactional outbox commands")
    outbox_sub = outbox.add_subparsers(dest="outbox_command")
    publish = outbox_sub.add_parser("publish", help="Publish unpublished audit events")
    publish.add_argument("--limit", type=int, default=100)

    github = sub.add_parser("github", help="GitHub check commands")
    github_sub = github.add_subparsers(dest="github_command")
    check = github_sub.add_parser(
        "check", help="Record the latest gate outcome against a commit SHA"
    )
    check.add_argument("system_id")
    check.add_argument("--sha", required=True)
    check.add_argument("--repo", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "health":
        return cmd_health(args)
    if args.command == "me":
        return cmd_me(args)
    if args.command == "systems":
        return cmd_systems(args)
    if args.command == "gate":
        return cmd_gate(args)
    if args.command == "migrate":
        return cmd_migrate(args)
    if args.command == "outbox":
        if args.outbox_command == "publish":
            return cmd_outbox_publish(args)
        parser.error("outbox requires a subcommand")
    if args.command == "github":
        if args.github_command == "check":
            return cmd_github_check(args)
        parser.error("github requires a subcommand")
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
