from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aigov.api.routers import health, systems
from aigov.config import get_settings
from aigov.infrastructure.db import create_schema, dispose_engine, init_engine


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    init_engine(settings)
    last_error: Exception | None = None
    for attempt in range(10):
        try:
            await create_schema()
            last_error = None
            break
        except Exception as exc:  # noqa: BLE001 — retry compose/postgres races
            last_error = exc
            await asyncio.sleep(0.5 * (attempt + 1))
    if last_error is not None:
        raise last_error
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Governance Control Plane API",
        version="0.6.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(systems.router)

    @app.exception_handler(HTTPException)
    async def http_problem(_request: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict):
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": "https://api.aigov.local/problems/http",
                "title": "Request failed",
                "status": exc.status_code,
                "code": "HTTP_ERROR",
                "detail": str(exc.detail),
            },
        )

    return app


app = create_app()
