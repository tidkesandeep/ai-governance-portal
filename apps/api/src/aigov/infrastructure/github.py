from __future__ import annotations

from typing import Any

import httpx

from aigov.domains.integrations.github import CHECK_NAME


class GitHubApiError(Exception):
    def __init__(self, detail: str, code: str = "GITHUB_API_FAILED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


async def create_check_run(
    *,
    token: str,
    repo: str,
    sha: str,
    conclusion: str,
    title: str,
    summary: str,
    name: str = CHECK_NAME,
) -> str | None:
    url = f"https://api.github.com/repos/{repo}/check-runs"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "name": name,
                    "head_sha": sha,
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {"title": title, "summary": summary},
                },
            )
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
    except httpx.HTTPError as exc:
        raise GitHubApiError("GitHub Checks API failed", "GITHUB_API_FAILED") from exc
    html_url = payload.get("html_url")
    return str(html_url) if html_url else None
