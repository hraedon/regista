from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from regista._errors import ErrorCode, RegistaError

from .auth import TokenRegistry, get_actor, require_admin
from .models import (
    AcquireClaimRequest,
    AppendEventRequest,
    ArchiveEventsRequest,
    CancelRecurrenceRuleRequest,
    ComposeWorkflowRequest,
    CreateLinkRequest,
    CreateWorkItemRequest,
    CreateWorkItemsBatchRequest,
    FireRecurrenceRequest,
    HeartbeatClaimRequest,
    QueryWorkItemsRequest,
    ReadEventsRequest,
    ReadEventsSinceRequest,
    RegisterActorRoleRequest,
    RegisterRecurrenceRuleRequest,
    RegisterWebhookRequest,
    RegisterWitnessRequest,
    RegisterWorkflowRequest,
    ReleaseClaimRequest,
    RemoveLinkRequest,
    ReplayRequest,
    RequeueDeadLetteredHookRequest,
    SignSpecRequest,
    TransitionRequest,
    UnregisterActorRoleRequest,
    UpdateNotBeforeRequest,
    UpdateRecurrenceRuleRequest,
    VerifyEventSignatureRequest,
    _serialize,
)
from .rate_limit import make_limiter


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


def register_routes(app, regista, tokens: TokenRegistry, *, workflow_dir: str | Path | None = None):
    router = APIRouter(prefix="/v1")
    limiter = make_limiter()
    _workflow_base = Path(workflow_dir).resolve() if workflow_dir else None

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

        token_key = hashlib.sha256(raw_token.encode()).hexdigest()[:16]
        if not limiter.allow(token_key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
            )

        request.state.actor = actor

        return await call_next(request)

    @router.post("/register_workflow")
    def register_workflow(body: RegisterWorkflowRequest, request: Request):
        get_actor(request)
        result = regista.register_workflow(body.yaml_content)
        return _serialize(result)

    @router.get("/workflows/{name}/{version}")
    def get_workflow(name: str, version: int, request: Request):
        get_actor(request)
        result = regista.get_workflow(name, version)
        return _serialize(result)

    @router.post("/create_work_item")
    def create_work_item(body: CreateWorkItemRequest, request: Request):
        actor = get_actor(request)
        wi, evt = regista.create_work_item(
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
    def get_work_item(work_item_id: str, request: Request):
        get_actor(request)
        result = regista.get_work_item(_parse_uuid(work_item_id))
        if result is None:
            raise RegistaError(
                ErrorCode.WORK_ITEM_NOT_FOUND,
                f"Work item {work_item_id} not found",
            )
        return _serialize(result)

    @router.post("/append_event")
    def append_event(body: AppendEventRequest, request: Request):
        actor = get_actor(request)
        result = regista.append_event(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            transition=body.transition,
            payload=body.payload,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            expected_event_seq=body.expected_event_seq,
            on_behalf_of=body.on_behalf_of,
            entity_kind=body.entity_kind,
        )
        return _serialize(result)

    @router.post("/transition")
    def transition(body: TransitionRequest, request: Request):
        actor = get_actor(request)
        result = regista.transition(
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
    def read_events(body: ReadEventsRequest, request: Request):
        get_actor(request)
        result = regista.read_events(
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
    def read_events_since(body: ReadEventsSinceRequest, request: Request):
        get_actor(request)
        result = regista.read_events_since(
            work_item_id=_parse_uuid(body.work_item_id),
            after_seq=body.after_seq,
            limit=body.limit,
        )
        return _serialize(result)

    @router.post("/query_work_items")
    def query_work_items(body: QueryWorkItemsRequest, request: Request):
        get_actor(request)
        result = regista.query_work_items(
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
    def acquire_claim(body: AcquireClaimRequest, request: Request):
        actor = get_actor(request)
        result = regista.acquire_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            ttl_seconds=body.ttl_seconds,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
        )
        return _serialize(result)

    @router.post("/heartbeat_claim")
    def heartbeat_claim(body: HeartbeatClaimRequest, request: Request):
        actor = get_actor(request)
        result = regista.heartbeat_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            ttl_seconds=body.ttl_seconds,
            expected_attempt_number=body.expected_attempt_number,
            coalesce_threshold=body.coalesce_threshold,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
        )
        return _serialize(result)

    @router.post("/release_claim")
    def release_claim(body: ReleaseClaimRequest, request: Request):
        actor = get_actor(request)
        regista.release_claim(
            work_item_id=_parse_uuid(body.work_item_id),
            actor_id=actor.actor_id,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
        )
        return {"status": "ok"}

    @router.post("/sweep_expired_claims")
    def sweep_expired_claims(request: Request):
        require_admin(request)
        count = regista.sweep_expired_claims()
        return {"swept": count}

    @router.post("/create_link")
    def create_link(body: CreateLinkRequest, request: Request):
        actor = get_actor(request)
        result = regista.create_link(
            from_work_item_id=_parse_uuid(body.from_work_item_id),
            to_work_item_id=_parse_uuid(body.to_work_item_id),
            link_type=body.link_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            payload=body.payload,
            target_project=body.target_project,
            target_entity_kind=body.target_entity_kind,
            content_hash=body.content_hash,
        )
        return _serialize(result)

    @router.post("/remove_link")
    def remove_link(body: RemoveLinkRequest, request: Request):
        actor = get_actor(request)
        regista.remove_link(
            from_work_item_id=_parse_uuid(body.from_work_item_id),
            to_work_item_id=_parse_uuid(body.to_work_item_id),
            link_type=body.link_type,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
            target_project=body.target_project,
        )
        return {"status": "ok"}

    @router.post("/update_not_before")
    def update_not_before(body: UpdateNotBeforeRequest, request: Request):
        actor = get_actor(request)
        result = regista.update_not_before(
            work_item_id=_parse_uuid(body.work_item_id),
            not_before=_parse_datetime(body.not_before),
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=body.actor_metadata,
            event_id=_parse_uuid(body.event_id) if body.event_id else None,
        )
        return _serialize(result)

    @router.post("/replay")
    def replay(body: ReplayRequest, request: Request):
        require_admin(request)
        result = regista.replay(
            continue_on_revoked=body.continue_on_revoked,
            verify_timestamps=body.verify_timestamps,
            verify_principal_binding=body.verify_principal_binding,
            work_item_id=_parse_uuid(body.work_item_id) if body.work_item_id else None,
        )
        return _serialize(result)

    @router.get("/dead_lettered_hooks")
    def list_dead_lettered_hooks(request: Request, limit: int = 100):
        require_admin(request)
        limit = max(1, min(limit, 1000))
        result = regista.list_dead_lettered_hooks(limit=limit)
        return _serialize(result)

    @router.post("/requeue_dead_lettered_hook")
    def requeue_dead_lettered_hook(body: RequeueDeadLetteredHookRequest, request: Request):
        require_admin(request)
        regista.requeue_dead_lettered_hook(body.dead_letter_id)
        return {"status": "ok"}

    @router.post("/register_actor_role")
    def register_actor_role(body: RegisterActorRoleRequest, request: Request):
        actor = get_actor(request)
        if body.role not in actor.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Token not authorized for role {body.role!r}",
            )
        regista.register_actor_role(actor.actor_id, body.role)
        return {"status": "ok"}

    @router.post("/unregister_actor_role")
    def unregister_actor_role(body: UnregisterActorRoleRequest, request: Request):
        actor = get_actor(request)
        if body.role not in actor.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Token not authorized for role {body.role!r}",
            )
        regista.unregister_actor_role(actor.actor_id, body.role)
        return {"status": "ok"}

    @router.get("/actor_roles")
    def list_actor_roles(request: Request):
        get_actor(request)
        actor_id = request.query_params.get("actor_id")
        result = regista.list_actor_roles(actor_id=actor_id)
        return _serialize(result)

    @router.post("/register_recurrence_rule")
    def register_recurrence_rule(body: RegisterRecurrenceRuleRequest, request: Request):
        get_actor(request)
        result = regista.register_recurrence_rule(
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
            created_by=get_actor(request).actor_id,
        )
        return _serialize(result)

    @router.get("/recurrence_rules")
    def list_recurrence_rules(request: Request):
        get_actor(request)
        status = request.query_params.get("status")
        result = regista.list_recurrence_rules(status=status)
        return _serialize(result)

    @router.post("/fire_recurrence")
    def fire_recurrence(body: FireRecurrenceRequest, request: Request):
        require_admin(request)
        rule, wi = regista.fire_recurrence(_parse_uuid(body.rule_id))
        return {"rule": _serialize(rule), "work_item": _serialize(wi)}

    @router.post("/cancel_recurrence_rule")
    def cancel_recurrence_rule(body: CancelRecurrenceRuleRequest, request: Request):
        require_admin(request)
        regista.cancel_recurrence_rule(_parse_uuid(body.rule_id))
        return {"status": "ok"}

    @router.post("/update_recurrence_rule")
    def update_recurrence_rule(body: UpdateRecurrenceRuleRequest, request: Request):
        require_admin(request)
        result = regista.update_recurrence_rule(
            rule_id=_parse_uuid(body.rule_id),
            status=body.status,
            schedule_expr=body.schedule_expr,
            template=body.template,
        )
        return _serialize(result)

    @router.post("/sweep_expired_hook_leases")
    def sweep_expired_hook_leases(request: Request):
        require_admin(request)
        count = regista.sweep_expired_hook_leases()
        return {"swept": count}

    @router.post("/timestamp/trigger")
    def trigger_timestamp(request: Request):
        require_admin(request)
        result = regista.timestamping.trigger()
        return _serialize(result)

    @router.get("/timestamp/batches")
    def list_timestamp_batches(request: Request):
        require_admin(request)
        status = request.query_params.get("status")
        result = regista.timestamping.list_batches(status=status)
        return _serialize(result)

    @router.post("/timestamp/batches/{batch_id}/verify")
    def verify_timestamp_batch(batch_id: str, request: Request):
        require_admin(request)
        result = regista.timestamping.verify_batch(_parse_uuid(batch_id))
        return {"verified": result}

    @router.post("/witnesses")
    def register_witness(body: RegisterWitnessRequest, request: Request):
        require_admin(request)
        try:
            pub_key = base64.b64decode(body.public_key) if body.public_key else None
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 public_key")
        witness_id = regista.register_witness(
            url=body.url,
            headers=body.headers,
            event_filter=body.event_filter,
            max_failures=body.max_failures,
            max_retries=body.max_retries,
            public_key=pub_key,
            key_scheme=body.key_scheme,
        )
        return {"witness_id": str(witness_id)}

    @router.delete("/witnesses/{witness_id}")
    def unregister_witness(witness_id: str, request: Request):
        require_admin(request)
        regista.unregister_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.post("/witnesses/{witness_id}/pause")
    def pause_witness(witness_id: str, request: Request):
        require_admin(request)
        regista.pause_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.post("/witnesses/{witness_id}/reactivate")
    def reactivate_witness(witness_id: str, request: Request):
        require_admin(request)
        regista.reactivate_witness(_parse_uuid(witness_id))
        return {"status": "ok"}

    @router.get("/witnesses")
    def list_witnesses(request: Request):
        get_actor(request)
        status = request.query_params.get("status")
        result = regista.list_witnesses(status=status)
        return _serialize(result)

    @router.get("/witnesses/receipts")
    def list_witness_receipts(request: Request):
        get_actor(request)
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
        result = regista.list_witness_receipts(
            event_id=_parse_uuid(event_id) if event_id else None,
            witness_id=_parse_uuid(witness_id) if witness_id else None,
            status=status,
            limit=limit,
        )
        return _serialize(result)

    @router.post("/witnesses/deliver")
    def deliver_witness_receipts(request: Request):
        require_admin(request)
        count = regista.deliver_pending_witness_receipts()
        return {"delivered": count}

    @router.post("/archive_events")
    def archive_events_route(body: ArchiveEventsRequest, request: Request):
        require_admin(request)
        ts = _parse_datetime(body.before_timestamp)
        count = regista.archive_events(before_timestamp=ts, dry_run=body.dry_run)
        return {"archived": count, "dry_run": body.dry_run}

    @router.post("/create_work_items_batch")
    def create_work_items_batch(body: CreateWorkItemsBatchRequest, request: Request):
        actor = get_actor(request)
        if not body.items:
            raise HTTPException(status_code=400, detail="items list is required")
        results = regista.create_work_items_batch(
            items=body.items,
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
    def compose_workflow_route(body: ComposeWorkflowRequest, request: Request):
        require_admin(request)
        file_path = Path(body.file_path).resolve()
        if _workflow_base is None:
            raise HTTPException(
                status_code=403,
                detail="workflow_dir not configured; compose_workflow is disabled",
            )
        try:
            file_path.relative_to(_workflow_base)
        except ValueError:
            raise HTTPException(
                status_code=403,
                detail="file_path must be within the configured workflow directory",
            )
        if not file_path.exists():
            raise HTTPException(status_code=400, detail=f"File not found: {body.file_path}")
        if file_path.suffix not in (".yaml", ".yml"):
            raise HTTPException(status_code=400, detail="Only .yaml/.yml files are allowed")
        from regista._workflow_compose import compose_workflow as _compose
        composed, source_map = _compose(str(file_path))
        return {"composed": composed, "source_map": source_map}

    @router.post("/webhooks")
    def register_webhook(body: RegisterWebhookRequest, request: Request):
        require_admin(request)
        sign_secret = None
        if body.sign_secret:
            import base64
            try:
                sign_secret = base64.b64decode(body.sign_secret)
            except Exception:
                raise HTTPException(status_code=400, detail="sign_secret must be valid base64")
        result = regista.register_webhook(
            url=body.url,
            headers=body.headers,
            transitions=body.transitions,
            work_item_types=body.work_item_types,
            workflows=body.workflows,
            max_failures=body.max_failures,
            sign_secret=sign_secret,
        )
        return _serialize(result)

    @router.get("/webhooks")
    def list_webhooks(request: Request):
        get_actor(request)
        status = request.query_params.get("status")
        result = regista.list_webhooks(status=status)
        return _serialize(result)

    @router.delete("/webhooks/{webhook_id}")
    def unregister_webhook(webhook_id: str, request: Request):
        require_admin(request)
        regista.unregister_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    @router.post("/webhooks/{webhook_id}/pause")
    def pause_webhook(webhook_id: str, request: Request):
        require_admin(request)
        regista.pause_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    @router.post("/webhooks/{webhook_id}/resume")
    def resume_webhook(webhook_id: str, request: Request):
        require_admin(request)
        regista.resume_webhook(_parse_uuid(webhook_id))
        return {"status": "ok"}

    @router.get("/keys/public")
    def export_public_keys(request: Request):
        get_actor(request)
        return _serialize(regista.export_public_keys())

    @router.post("/events/verify-signature")
    def verify_event_signature(req: VerifyEventSignatureRequest, request: Request):
        get_actor(request)
        from regista._types import Event as _Event

        try:
            evt = _Event.from_dict(req.event)
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event data: {e}",
            )
        import base64

        pub_key = base64.b64decode(req.public_key) if req.public_key else None
        result = regista.verify_event_signature(evt, public_key=pub_key)
        return {"valid": result}

    @router.post("/spec/sign")
    def sign_spec(req: SignSpecRequest, request: Request):
        actor = get_actor(request)
        spec_id = _parse_uuid(req.spec_id) if req.spec_id else None
        evt = regista.sign_spec(
            spec_yaml=req.spec_yaml,
            spec_md_hash=req.spec_md_hash,
            spec_schema_version=req.spec_schema_version,
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            actor_metadata=req.actor_metadata,
            spec_id=spec_id,
        )
        return _serialize(evt)

    @router.get("/spec/events")
    def read_spec_events(
        request: Request,
        spec_id: str | None = None,
        limit: int = 100,
    ):
        get_actor(request)
        sid = _parse_uuid(spec_id) if spec_id else None
        events = regista.read_spec_events(spec_id=sid, limit=limit)
        return _serialize(events)

    @router.get("/work-items/{work_item_id}/assurance")
    def get_assurance(work_item_id: str, request: Request):
        get_actor(request)
        wi_id = _parse_uuid(work_item_id)
        profile = request.query_params.get("profile", "relaxed")
        level = regista.compute_assurance(wi_id)
        rationale = regista.gate_rationale(wi_id, profile=profile)
        return {
            "assurance_level": level.value,
            "rationale": _serialize(rationale),
        }

    app.include_router(router)
