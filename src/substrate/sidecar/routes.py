from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from substrate._errors import ErrorCode, SubstrateError

from .auth import AuthenticatedActor, TokenRegistry
from .models import (
    AcquireClaimRequest,
    AppendEventRequest,
    CancelRecurrenceRuleRequest,
    CreateLinkRequest,
    CreateWorkItemRequest,
    FireRecurrenceRequest,
    HeartbeatClaimRequest,
    QueryWorkItemsRequest,
    ReadEventsRequest,
    ReadEventsSinceRequest,
    RegisterActorRoleRequest,
    RegisterRecurrenceRuleRequest,
    RegisterWitnessRequest,
    RegisterWorkflowRequest,
    ReleaseClaimRequest,
    RemoveLinkRequest,
    ReplayRequest,
    RequeueDeadLetteredHookRequest,
    TransitionRequest,
    UnregisterActorRoleRequest,
    UpdateNotBeforeRequest,
    UpdateRecurrenceRuleRequest,
    _serialize,
)
from .rate_limit import make_limiter

ADMIN_ROLE = "admin"


def _get_actor(request: Request) -> AuthenticatedActor:
    actor = getattr(request.state, "actor", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return actor


def _require_admin(request: Request) -> AuthenticatedActor:
    actor = _get_actor(request)
    if ADMIN_ROLE not in actor.allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Role {ADMIN_ROLE!r} required",
        )
    return actor


def _parse_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid UUID: {val!r}")


def _parse_datetime(val: str | None) -> datetime | None:
    if val is None:
        return None
    try:
        return datetime.fromisoformat(val)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {val!r}")


def register_routes(app, substrate, tokens: TokenRegistry):
    router = APIRouter(prefix="/v1")
    limiter = make_limiter()

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if not request.url.path.startswith("/v1"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )

        raw_token = auth_header[len("Bearer "):]
        actor = tokens.authenticate(raw_token)
        if actor is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token"},
            )

        import hashlib

        token_key = hashlib.sha256(raw_token.encode()).hexdigest()[:16]
        if not limiter.allow(token_key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
            )

        request.state.actor = actor

        return await call_next(request)

    @router.post("/register_workflow")
    async def register_workflow(body: RegisterWorkflowRequest, request: Request):
        _get_actor(request)
        result = substrate.register_workflow(body.yaml_content)
        return _serialize(result)

    @router.get("/workflows/{name}/{version}")
    async def get_workflow(name: str, version: int, request: Request):
        _get_actor(request)
        result = substrate.get_workflow(name, version)
        return _serialize(result)

    @router.post("/create_work_item")
    async def create_work_item(body: CreateWorkItemRequest, request: Request):
        actor = _get_actor(request)
        wi, evt = substrate.create_work_item(
            workflow_name=body.workflow_name,
            work_item_type=body.work_item_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            custom_fields=body.custom_fields,
            not_before=_parse_datetime(body.not_before),
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
        )
        return {"work_item": _serialize(wi), "event": _serialize(evt)}

    @router.get("/work_items/{work_item_id}")
    async def get_work_item(work_item_id: str, request: Request):
        _get_actor(request)
        result = substrate.get_work_item(_parse_uuid(work_item_id))
        if result is None:
            raise SubstrateError(
                ErrorCode.WORK_ITEM_NOT_FOUND,
                f"Work item {work_item_id} not found",
            )
        return _serialize(result)

    @router.post("/append_event")
    async def append_event(body: AppendEventRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.append_event(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            transition=body.transition,
            payload=body.payload,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            expected_event_seq=body.expected_event_seq,
            on_behalf_of=body.on_behalf_of,
        )
        return _serialize(result)

    @router.post("/transition")
    async def transition(body: TransitionRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.transition(
            work_item_id=_parse_uuid(body.work_item_id),
            transition_name=body.transition_name,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            payload=body.payload,
            custom_fields=body.custom_fields,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            expected_event_seq=body.expected_event_seq,
            on_behalf_of=body.on_behalf_of,
        )
        return _serialize(result)

    @router.post("/read_events")
    async def read_events(body: ReadEventsRequest, request: Request):
        _get_actor(request)
        result = substrate.read_events(
            work_item_id=_parse_uuid(body.work_item_id) if body.work_item_id else None,
            actor_id=body.actor_id,
            start=_parse_datetime(body.start),
            end=_parse_datetime(body.end),
            transition=body.transition,
            limit=body.limit,
            before_seq=body.before_seq,
        )
        return _serialize(result)

    @router.post("/read_events_since")
    async def read_events_since(body: ReadEventsSinceRequest, request: Request):
        _get_actor(request)
        result = substrate.read_events_since(
            work_item_id=_parse_uuid(body.work_item_id),
            after_seq=body.after_seq,
            limit=body.limit,
        )
        return _serialize(result)

    @router.post("/query_work_items")
    async def query_work_items(body: QueryWorkItemsRequest, request: Request):
        _get_actor(request)
        result = substrate.query_work_items(
            workflow_name=body.workflow_name,
            workflow_version=body.workflow_version,
            work_item_types=body.work_item_types,
            current_states=body.current_states,
            claimed_by=body.claimed_by,
            claimable_now=body.claimable_now,
            needs_review=body.needs_review,
            has_link_type=body.has_link_type,
            custom_field_filters=body.custom_field_filters,
            cursor=_parse_uuid(body.cursor) if body.cursor else None,
            page_size=body.page_size,
        )
        return _serialize(result)

    @router.post("/acquire_claim")
    async def acquire_claim(body: AcquireClaimRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.acquire_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            ttl_seconds=body.ttl_seconds,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            actor_kind=actor.actor_kind,
        )
        return _serialize(result)

    @router.post("/heartbeat_claim")
    async def heartbeat_claim(body: HeartbeatClaimRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.heartbeat_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            ttl_seconds=body.ttl_seconds,
            expected_attempt_number=body.expected_attempt_number,
            coalesce_threshold=body.coalesce_threshold,
        )
        return _serialize(result)

    @router.post("/release_claim")
    async def release_claim(body: ReleaseClaimRequest, request: Request):
        actor = _get_actor(request)
        substrate.release_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            actor_kind=actor.actor_kind,
        )
        return {"status": "ok"}

    @router.post("/sweep_expired_claims")
    async def sweep_expired_claims(request: Request):
        _require_admin(request)
        count = substrate.sweep_expired_claims()
        return {"swept": count}

    @router.post("/create_link")
    async def create_link(body: CreateLinkRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.create_link(
            from_work_item_id=_parse_uuid(body.from_work_item_id),
            to_work_item_id=_parse_uuid(body.to_work_item_id),
            link_type=body.link_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            payload=body.payload,
        )
        return _serialize(result)

    @router.post("/remove_link")
    async def remove_link(body: RemoveLinkRequest, request: Request):
        actor = _get_actor(request)
        substrate.remove_link(
            from_work_item_id=_parse_uuid(body.from_work_item_id),
            to_work_item_id=_parse_uuid(body.to_work_item_id),
            link_type=body.link_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
        )
        return {"status": "ok"}

    @router.post("/update_not_before")
    async def update_not_before(body: UpdateNotBeforeRequest, request: Request):
        actor = _get_actor(request)
        result = substrate.update_not_before(
            work_item_id=_parse_uuid(body.work_item_id),
            not_before=_parse_datetime(body.not_before),
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
        )
        return _serialize(result)

    @router.post("/replay")
    async def replay(body: ReplayRequest, request: Request):
        _require_admin(request)
        result = substrate.replay(
            continue_on_revoked=body.continue_on_revoked,
            verify_timestamps=body.verify_timestamps,
        )
        return _serialize(result)

    @router.get("/dead_lettered_hooks")
    async def list_dead_lettered_hooks(request: Request):
        _require_admin(request)
        result = substrate.list_dead_lettered_hooks()
        return _serialize(result)

    @router.post("/requeue_dead_lettered_hook")
    async def requeue_dead_lettered_hook(body: RequeueDeadLetteredHookRequest, request: Request):
        _require_admin(request)
        substrate.requeue_dead_lettered_hook(body.dead_letter_id)
        return {"status": "ok"}

    @router.post("/register_actor_role")
    async def register_actor_role(body: RegisterActorRoleRequest, request: Request):
        actor = _get_actor(request)
        if body.role not in actor.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Token not authorized for role {body.role!r}",
            )
        substrate.register_actor_role(actor.actor_id, body.role)
        return {"status": "ok"}

    @router.post("/unregister_actor_role")
    async def unregister_actor_role(body: UnregisterActorRoleRequest, request: Request):
        actor = _get_actor(request)
        if body.role not in actor.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Token not authorized for role {body.role!r}",
            )
        substrate.unregister_actor_role(actor.actor_id, body.role)
        return {"status": "ok"}

    @router.get("/actor_roles")
    async def list_actor_roles(request: Request):
        _get_actor(request)
        actor_id = request.query_params.get("actor_id")
        result = substrate.list_actor_roles(actor_id=actor_id)
        return _serialize(result)

    @router.post("/register_recurrence_rule")
    async def register_recurrence_rule(body: RegisterRecurrenceRuleRequest, request: Request):
        _get_actor(request)
        result = substrate.register_recurrence_rule(
            workflow_name=body.workflow_name,
            workflow_version=body.workflow_version,
            work_item_type=body.work_item_type,
            template=body.template,
            schedule_kind=body.schedule_kind,
            schedule_expr=body.schedule_expr,
            timezone=body.timezone,
            start_at=_parse_datetime(body.start_at),
            end_at=_parse_datetime(body.end_at),
            count=body.count,
            catchup_policy=body.catchup_policy,
            created_by=_get_actor(request).actor_id,
        )
        return _serialize(result)

    @router.get("/recurrence_rules")
    async def list_recurrence_rules(request: Request):
        _get_actor(request)
        status = request.query_params.get("status")
        result = substrate.list_recurrence_rules(status=status)
        return _serialize(result)

    @router.post("/fire_recurrence")
    async def fire_recurrence(body: FireRecurrenceRequest, request: Request):
        _require_admin(request)
        rule, wi = substrate.fire_recurrence(_parse_uuid(body.rule_id))
        return {"rule": _serialize(rule), "work_item": _serialize(wi)}

    @router.post("/cancel_recurrence_rule")
    async def cancel_recurrence_rule(body: CancelRecurrenceRuleRequest, request: Request):
        _require_admin(request)
        substrate.cancel_recurrence_rule(_parse_uuid(body.rule_id))
        return {"status": "ok"}

    @router.post("/update_recurrence_rule")
    async def update_recurrence_rule(body: UpdateRecurrenceRuleRequest, request: Request):
        _require_admin(request)
        result = substrate.update_recurrence_rule(
            rule_id=_parse_uuid(body.rule_id),
            status=body.status,
            schedule_expr=body.schedule_expr,
            template=body.template,
        )
        return _serialize(result)

    @router.post("/sweep_expired_hook_leases")
    async def sweep_expired_hook_leases(request: Request):
        _require_admin(request)
        count = substrate.sweep_expired_hook_leases()
        return {"swept": count}

    @router.post("/timestamp/trigger")
    async def trigger_timestamp(request: Request):
        _require_admin(request)
        result = substrate.timestamping.trigger()
        return _serialize(result)

    @router.get("/timestamp/batches")
    async def list_timestamp_batches(request: Request):
        _require_admin(request)
        status = request.query_params.get("status")
        result = substrate.timestamping.list_batches(status=status)
        return _serialize(result)

    @router.post("/timestamp/batches/{batch_id}/verify")
    async def verify_timestamp_batch(batch_id: str, request: Request):
        _require_admin(request)
        result = substrate.timestamping.verify_batch(_parse_uuid(batch_id))
        return {"verified": result}

    @router.post("/witnesses")
    async def register_witness(body: RegisterWitnessRequest, request: Request):
        _require_admin(request)
        witness_id = substrate.register_witness(
            url=body.url,
            headers=body.headers,
            event_filter=body.event_filter,
            max_failures=body.max_failures,
            max_retries=body.max_retries,
        )
        return {"witness_id": str(witness_id)}

    @router.delete("/witnesses/{witness_id}")
    async def unregister_witness(witness_id: str, request: Request):
        _require_admin(request)
        substrate.unregister_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.post("/witnesses/{witness_id}/pause")
    async def pause_witness(witness_id: str, request: Request):
        _require_admin(request)
        substrate.pause_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.post("/witnesses/{witness_id}/reactivate")
    async def reactivate_witness(witness_id: str, request: Request):
        _require_admin(request)
        substrate.reactivate_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.get("/witnesses")
    async def list_witnesses(request: Request):
        _get_actor(request)
        status = request.query_params.get("status")
        result = substrate.list_witnesses(status=status)
        return _serialize(result)

    @router.get("/witnesses/receipts")
    async def list_witness_receipts(request: Request):
        _get_actor(request)
        event_id = request.query_params.get("event_id")
        witness_id = request.query_params.get("witness_id")
        status = request.query_params.get("status")
        raw_limit = request.query_params.get("limit", "100")
        try:
            limit = int(raw_limit)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid limit: {raw_limit!r}")
        if limit < 1 or limit > 10000:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 10000")
        result = substrate.list_witness_receipts(
            event_id=_parse_uuid(event_id) if event_id else None,
            witness_id=_parse_uuid(witness_id) if witness_id else None,
            status=status,
            limit=limit,
        )
        return _serialize(result)

    @router.post("/witnesses/deliver")
    async def deliver_witness_receipts(request: Request):
        _require_admin(request)
        count = substrate.deliver_pending_witness_receipts()
        return {"delivered": count}

    @router.post("/archive_events")
    async def archive_events(request: Request):
        _require_admin(request)
        body = await request.json()
        raw_ts = body.get("before_timestamp")
        if not raw_ts:
            raise HTTPException(status_code=400, detail="before_timestamp is required")
        ts = _parse_datetime(raw_ts)
        dry_run = body.get("dry_run", False)
        count = substrate.archive_events(before_timestamp=ts, dry_run=dry_run)
        return {"archived": count, "dry_run": dry_run}

    @router.post("/create_work_items_batch")
    async def create_work_items_batch(request: Request):
        actor = _get_actor(request)
        body = await request.json()
        items = body.get("items", [])
        if not items:
            raise HTTPException(status_code=400, detail="items list is required")
        results = substrate.create_work_items_batch(
            items=items,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
        )
        return {
            "results": [
                {"work_item": _serialize(wi), "event": _serialize(evt)}
                for wi, evt in results
            ]
        }

    @router.post("/compose_workflow")
    async def compose_workflow(request: Request):
        _get_actor(request)
        body = await request.json()
        file_path = body.get("file_path")
        if not file_path:
            raise HTTPException(status_code=400, detail="file_path is required")
        from substrate._workflow_compose import compose_workflow as _compose
        composed, source_map = _compose(file_path)
        return {"composed": composed, "source_map": source_map}

    @router.post("/webhooks")
    async def register_webhook(request: Request):
        _require_admin(request)
        body = await request.json()
        url = body.get("url")
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        sign_secret = body.get("sign_secret")
        if sign_secret and isinstance(sign_secret, str):
            import base64
            sign_secret = base64.b64decode(sign_secret)
        result = substrate.register_webhook(
            url=url,
            headers=body.get("headers"),
            transitions=body.get("transitions"),
            work_item_types=body.get("work_item_types"),
            workflows=body.get("workflows"),
            max_failures=body.get("max_failures", 10),
            sign_secret=sign_secret,
        )
        return result

    @router.get("/webhooks")
    async def list_webhooks(request: Request):
        _get_actor(request)
        status = request.query_params.get("status")
        result = substrate.list_webhooks(status=status)
        return _serialize(result)

    @router.delete("/webhooks/{webhook_id}")
    async def unregister_webhook(webhook_id: str, request: Request):
        _require_admin(request)
        substrate.unregister_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    @router.post("/webhooks/{webhook_id}/pause")
    async def pause_webhook(webhook_id: str, request: Request):
        _require_admin(request)
        substrate.pause_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    @router.post("/webhooks/{webhook_id}/resume")
    async def resume_webhook(webhook_id: str, request: Request):
        _require_admin(request)
        substrate.resume_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    app.include_router(router)
