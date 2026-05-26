from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from substrate._errors import SubstrateError

from .auth import TokenRegistry
from .errors import error_to_status
from .routes import register_routes
from .routes_hooks import register_hook_routes


def create_app(
    substrate,
    tokens: TokenRegistry,
    *,
    docs_url: str | None = None,
    openapi_url: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Substrate Sidecar",
        version="0.1.0",
        docs_url=docs_url,
        openapi_url=openapi_url,
    )

    max_body_size = 10 * 1024 * 1024

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        try:
            with substrate._mgr.connect() as conn:
                conn.execute("SELECT 1")
            return {"status": "ok"}
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "unavailable", "detail": str(exc)[:200]},
            )

    @app.get("/metrics")
    async def metrics():
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        output = generate_latest(substrate.prometheus_registry)
        return PlainTextResponse(content=output, media_type=CONTENT_TYPE_LATEST)

    max_body_size = 10 * 1024 * 1024

    @app.middleware("http")
    async def sole_signer_middleware(request: Request, call_next):
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

    register_routes(app, substrate, tokens)
    register_hook_routes(app, substrate, tokens)

    @app.exception_handler(SubstrateError)
    async def substrate_error_handler(request: Request, exc: SubstrateError):
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
