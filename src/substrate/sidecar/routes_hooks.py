from __future__ import annotations

from fastapi import APIRouter, Request

from .auth import TokenRegistry, get_actor
from .models import ClaimHooksRequest, CompleteHookRequest, FailHookRequest, _serialize


def register_hook_routes(app, substrate, tokens: TokenRegistry):
    router = APIRouter(prefix="/v1/hooks")

    @router.post("/claim")
    async def claim_hooks(body: ClaimHooksRequest, request: Request):
        get_actor(request)
        result = substrate.claim_hooks(
            max_batch=body.max_batch,
            lease_seconds=body.lease_seconds,
        )
        return _serialize(result)

    @router.post("/{hook_id}/complete")
    async def complete_hook(hook_id: int, body: CompleteHookRequest, request: Request):
        get_actor(request)
        substrate.complete_hook(hook_id)
        return {"status": "ok"}

    @router.post("/{hook_id}/fail")
    async def fail_hook(hook_id: int, body: FailHookRequest, request: Request):
        get_actor(request)
        substrate.fail_hook(hook_id, body.error)
        return {"status": "ok"}

    app.include_router(router)
