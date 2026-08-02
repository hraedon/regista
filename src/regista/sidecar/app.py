from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from regista._errors import RegistaError

from .auth import TokenRegistry
from .errors import error_to_status
from .routes import register_routes
from .routes_hooks import register_hook_routes

if TYPE_CHECKING:
    from regista import Regista


def create_app(
    regista: Regista,
    tokens: TokenRegistry,
    *,
    docs_url: str | None = None,
    openapi_url: str | None = None,
    workflow_dir: str | Path | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Regista Sidecar",
        version="0.1.0",
        docs_url=docs_url,
        openapi_url=openapi_url,
    )

    max_body_size = 10 * 1024 * 1024

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    async def ready() -> dict[str, str] | JSONResponse:
        try:
            mgr = regista._mgr
            if mgr is None:
                return JSONResponse(
                    status_code=503,
                    content={"status": "unavailable", "detail": "Connection closed"},
                )
            with mgr.connect() as conn:
                conn.execute("SELECT 1")
            return {"status": "ok"}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "unavailable"},
            )

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        output = generate_latest(regista.prometheus_registry)
        return PlainTextResponse(content=output, media_type=CONTENT_TYPE_LATEST)

    @app.middleware("http")
    async def sole_signer_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/v1"):
            body_bytes = b""
            async for chunk in request.stream():
                body_bytes += chunk
                if len(body_bytes) > max_body_size:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "INVALID_ARGUMENT",
                                "message": "Payload too large",
                                "detail": None,
                            }
                        },
                    )
            request._body = body_bytes
            if body_bytes:
                try:
                    raw = json.loads(body_bytes)
                    if isinstance(raw, dict) and (
                        "signature" in raw or "payload_canonical_hash" in raw
                    ):
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": {
                                    "code": "LIBRARY_IS_SOLE_SIGNER",
                                    "message": (
                                        "Requests must not contain signature "
                                        "or payload_canonical_hash fields"
                                    ),
                                    "detail": None,
                                }
                            },
                        )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        return await call_next(request)

    register_routes(app, regista, tokens, workflow_dir=workflow_dir)
    register_hook_routes(app, regista, tokens)

    @app.exception_handler(RegistaError)
    async def regista_error_handler(request: Request, exc: RegistaError) -> JSONResponse:
        status = error_to_status(exc.code)
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": str(exc.code),
                    "message": exc.message,
                    "detail": exc.detail,
                }
            },
        )

    return app
