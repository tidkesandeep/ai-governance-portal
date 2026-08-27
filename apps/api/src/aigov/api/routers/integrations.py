from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from aigov.api.deps import governance_service
from aigov.api.schemas import GitHubCheckOut
from aigov.api.serialize import github_check_out
from aigov.application.governance import GovernanceService, NotFoundError
from aigov.domains.integrations.github import GitHubWebhookError

router = APIRouter(prefix="/v1/integrations", tags=["Integrations"])


def _webhook_error(exc: GitHubWebhookError) -> HTTPException:
    status = 401
    if exc.code == "AUTH_UNAVAILABLE":
        status = 503
    elif exc.code not in {"INVALID_SIGNATURE"}:
        status = 422
    return HTTPException(
        status_code=status,
        detail={
            "type": "https://api.aigov.local/problems/github-webhook",
            "title": "GitHub webhook rejected",
            "status": status,
            "code": exc.code,
            "detail": exc.detail,
        },
    )


@router.post("/github/webhook", response_model=GitHubCheckOut, status_code=201)
async def github_webhook(
    request: Request,
    svc: GovernanceService = Depends(governance_service),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
) -> GitHubCheckOut:
    body = await request.body()
    try:
        row = await svc.handle_github_webhook(body=body, signature=x_hub_signature_256)
    except GitHubWebhookError as exc:
        raise _webhook_error(exc) from exc
    except NotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "type": "https://api.aigov.local/problems/not-found",
                "title": "AI system not found",
                "status": 404,
                "code": "NOT_FOUND",
            },
        ) from exc
    return github_check_out(row)
