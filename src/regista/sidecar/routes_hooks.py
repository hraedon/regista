from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request

from .auth import TokenRegistry, get_actor
from .models import ClaimHooksRequest, CompleteHookRequest, FailHookRequest, _serialize


def _hook_work_item_id(regista, hook_id: int) -> uuid.UUID | None:
    if hasattr(regista, "_hook_queue"):
        for entry in regista._hook_queue:
            if entry.get("id") == hook_id:
                raw = entry.get("work_item_id")
                if raw is not None:
                    return uuid.UUID(str(raw))
                return None
        return None
    with regista._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT payload->>'work_item_id' AS work_item_id FROM hook_queue WHERE id = %s",
            [hook_id],
        ).fetchone()
        if row is None or row["work_item_id"] is None:
            return None
        return uuid.UUID(row["work_item_id"])


def _filter_hooks_by_workflow_access(regista, actor, hooks):
    if actor.allowed_workflows is None:
        return hooks
    allowed = set(actor.allowed_workflows)
    workflows: dict[uuid.UUID, str | None] = {}
    result = []
    for ctx in hooks:
        if ctx.work_item_id not in workflows:
            wi = regista.get_work_item(ctx.work_item_id)
            workflows[ctx.work_item_id] = wi.workflow_name if wi is not None else None
        workflow_name = workflows[ctx.work_item_id]
        if workflow_name is not None and workflow_name in allowed:
            result.append(ctx)
        elif workflow_name is None:
            try:
                regista.fail_hook(ctx.hook_queue_id, "work_item_not_found")
            except Exception:
                _release_hook(regista, ctx.hook_queue_id)
        else:
            _release_hook(regista, ctx.hook_queue_id)
    return result


def _release_hook(regista, hook_id: int) -> None:
    if hasattr(regista, "_hook_queue"):
        for entry in regista._hook_queue:
            if entry.get("id") == hook_id:
                entry["status"] = "pending"
                entry["lease_expires_at"] = None
                entry["next_retry_at"] = None
                return
        return
    from datetime import UTC, datetime

    with regista._mgr.transaction() as conn:
        conn.execute(
            "UPDATE hook_queue SET status = 'pending', "
            "lease_expires_at = NULL, next_retry_at = NULL, "
            "updated_at = %s WHERE id = %s",
            [datetime.now(UTC), hook_id],
        )


def _authorize_hook_workflow_access(regista, actor, hook_id: int) -> None:
    work_item_id = _hook_work_item_id(regista, hook_id)
    if work_item_id is None:
        return
    wi = regista.get_work_item(work_item_id)
    if wi is None:
        return
    if not actor.can_access_workflow(wi.workflow_name):
        raise HTTPException(status_code=403, detail="Workflow access denied")


def register_hook_routes(app, regista, tokens: TokenRegistry):
    router = APIRouter(prefix="/v1/hooks")

    @router.post("/claim")
    def claim_hooks(body: ClaimHooksRequest, request: Request):
        actor = get_actor(request)
        result = regista.claim_hooks(
            max_batch=body.max_batch,
            lease_seconds=body.lease_seconds,
        )
        result = _filter_hooks_by_workflow_access(regista, actor, result)
        return _serialize(result)

    @router.post("/{hook_id}/complete")
    def complete_hook(hook_id: int, body: CompleteHookRequest, request: Request):
        actor = get_actor(request)
        _authorize_hook_workflow_access(regista, actor, hook_id)
        regista.complete_hook(hook_id)
        return {"status": "ok"}

    @router.post("/{hook_id}/fail")
    def fail_hook(hook_id: int, body: FailHookRequest, request: Request):
        actor = get_actor(request)
        _authorize_hook_workflow_access(regista, actor, hook_id)
        regista.fail_hook(hook_id, body.error)
        return {"status": "ok"}

    app.include_router(router)
