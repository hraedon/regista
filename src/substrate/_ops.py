from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import structlog

from ._connection import ConnectionManager
from ._contract import Jsonb as _Jsonb
from ._contract import validate_mutation_params as _validate_mutation_params
from ._errors import ErrorCode, SubstrateError
from ._keys import KeySet
from ._observability import Metrics, OpTimer
from ._types import (
    Claim,
    DeadLetterEntry,
    Event,
    HookContext,
    Link,
    QueryPage,
    WorkflowDefinition,
    WorkflowVersion,
    WorkItem,
)

log = structlog.get_logger()


class WorkflowOps:
    def __init__(self, mgr: ConnectionManager, metrics: Metrics, project: str) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def register(self, yaml_content: str) -> WorkflowVersion:
        from ._workflow_api import register_workflow as _impl

        return _impl(self._mgr, self._metrics, self._project, yaml_content)

    def register_file(self, path: str | Path) -> WorkflowVersion:
        import yaml as _yaml

        from ._workflow import parse_workflow_yaml
        from ._workflow_api import register_workflow_file as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            parse_workflow_yaml, _yaml.dump, path,
        )

    def get(self, workflow_name: str, version: int) -> WorkflowDefinition:
        from ._workflow_api import get_workflow as _impl

        return _impl(self._mgr, self._project, workflow_name, version)


class WorkItemOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
        validators: dict[str, Callable],
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project
        self._validators = validators

    def create(
        self,
        workflow_name: str,
        work_item_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        custom_fields: dict | None = None,
        not_before: datetime | None = None,
        event_id: uuid.UUID | None = None,
    ) -> tuple[WorkItem, Event]:
        from ._work_items_api import create_work_item as _impl

        return _impl(
            self._mgr, self._keys, self._metrics, self._project,
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )

    def query(
        self,
        *,
        workflow_name: str | None = None,
        workflow_version: int | None = None,
        work_item_types: list[str] | None = None,
        current_states: list[str] | None = None,
        claimed_by: str | None = None,
        claimable_now: bool | None = None,
        needs_review: bool | None = None,
        has_link_type: str | None = None,
        custom_field_filters: dict[str, object] | None = None,
        cursor: uuid.UUID | None = None,
        page_size: int = 100,
    ) -> QueryPage[WorkItem]:
        from ._work_items_api import query_work_items as _impl

        return _impl(
            self._mgr,
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            work_item_types=work_item_types,
            current_states=current_states,
            claimed_by=claimed_by,
            claimable_now=claimable_now,
            needs_review=needs_review,
            has_link_type=has_link_type,
            custom_field_filters=custom_field_filters,
            cursor=cursor,
            page_size=page_size,
        )

    def get(self, work_item_id: uuid.UUID) -> WorkItem | None:
        from ._work_items_api import get_work_item as _impl

        return _impl(self._mgr, work_item_id)

    def update_not_before(
        self,
        work_item_id: uuid.UUID,
        not_before: datetime | None,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
    ) -> Event:
        from psycopg.sql import SQL

        from ._events import append_event as _append_event
        from ._events import check_idempotency as _check_idem
        from ._events import lock_work_item as _lock

        timer = OpTimer(self._project, "update_not_before")
        try:
            if event_id is None:
                event_id = uuid.uuid4()
            _validate_mutation_params(
                actor_kind=actor_kind,
                event_id=event_id,
                not_before=not_before,
            )

            with self._mgr.transaction() as conn:
                wi = _lock(conn, work_item_id)
                if wi is None:
                    raise SubstrateError(
                        ErrorCode.WORK_ITEM_NOT_FOUND,
                        f"Work item {work_item_id} not found",
                    )

                existing = _check_idem(
                    conn, event_id, actor_id=actor_id, transition="not_before_set",
                    work_item_id=work_item_id,
                )
                if existing is not None:
                    return existing

                evt = _append_event(
                    conn,
                    work_item_id=work_item_id,
                    actor_id=actor_id,
                    actor_kind=actor_kind,
                    actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                    key_set=self._keys,
                    workflow_name=wi["workflow_name"],
                    workflow_version=wi["workflow_version"],
                    transition="not_before_set",
                    payload=_Jsonb({"not_before": not_before.isoformat() if not_before else None}),
                    event_id=event_id,
                    _prelocked_wi=wi,
                )

                conn.execute(
                    SQL("UPDATE work_items_current SET not_before = %s WHERE work_item_id = %s"),
                    [not_before, work_item_id],
                )

            self._metrics.inc("events_appended", self._project)
            timer.log("ok", work_item_id=str(work_item_id))
            return evt
        except SubstrateError:
            timer.log("error")
            raise


class EventOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project

    def append(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        transition: str | None = None,
        payload: dict | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
    ) -> Event:
        from ._events_api import append_event as _impl

        return _impl(
            self._mgr, self._keys, self._metrics, self._project,
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
        )

    def read(
        self,
        *,
        work_item_id: uuid.UUID | None = None,
        actor_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        transition: str | None = None,
        limit: int = 100,
        before_seq: int | None = None,
    ) -> list[Event]:
        from ._events_api import read_events as _impl

        return _impl(
            self._mgr,
            work_item_id=work_item_id,
            actor_id=actor_id,
            start=start,
            end=end,
            transition=transition,
            limit=limit,
            before_seq=before_seq,
        )

    def read_since(
        self,
        work_item_id: uuid.UUID,
        after_seq: int,
        *,
        limit: int = 100,
    ) -> list[Event]:
        from ._events_api import read_events_since as _impl

        return _impl(self._mgr, work_item_id, after_seq, limit=limit)


class ClaimOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project

    def acquire(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
    ) -> Claim:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
            ttl_seconds=ttl_seconds,
        )
        from ._claims_api import acquire_claim as _impl

        return _impl(
            self._mgr, self._keys, self._metrics, self._project,
            work_item_id, actor_id, ttl_seconds,
            event_id=event_id, actor_kind=actor_kind,
        )

    def heartbeat(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        expected_attempt_number: int | None = None,
        coalesce_threshold: float | None = None,
    ) -> Claim:
        _validate_mutation_params(actor_id=actor_id, ttl_seconds=ttl_seconds)
        from ._claims_api import heartbeat_claim as _impl

        return _impl(
            self._mgr, self._keys, self._project,
            work_item_id, actor_id, ttl_seconds,
            expected_attempt_number=expected_attempt_number,
            coalesce_threshold=coalesce_threshold,
        )

    def release(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
    ) -> None:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        from ._claims_api import release_claim as _impl

        _impl(
            self._mgr, self._keys, self._metrics, self._project,
            work_item_id, actor_id,
            event_id=event_id, actor_kind=actor_kind,
        )

    def sweep_expired(self) -> int:
        from ._claims_api import sweep_expired_claims as _impl

        swept = _impl(self._mgr, self._keys, self._metrics, self._project)
        if swept:
            self._metrics.inc("maintenance_claims_swept", self._project, amount=swept)
        return swept


class LinkOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project

    def create(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
        payload: dict | None = None,
    ) -> Link:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        from ._links_api import create_link as _impl

        return _impl(
            self._mgr, self._keys, self._metrics, self._project,
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id, payload=payload,
        )

    def remove(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
    ) -> None:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        from ._links_api import remove_link as _impl

        _impl(
            self._mgr, self._keys, self._metrics, self._project,
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id,
        )


class HookOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
        validators: dict[str, Callable],
        hook_handlers: dict[str, Callable],
        hook_channel: str,
        hook_consumer,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project
        self._validators = validators
        self._hook_handlers = hook_handlers
        self._hook_channel = hook_channel
        self._hook_consumer = hook_consumer

    def register_validator(self, name: str, handler: Callable) -> None:
        self._validators[name] = handler

    def register_handler(self, name: str, handler: Callable) -> None:
        self._hook_handlers[name] = handler
        self._hook_consumer._handlers = self._hook_handlers

    def start_consumer(self) -> None:
        self._hook_consumer.start()

    def stop_consumer(self) -> None:
        self._hook_consumer.stop()

    def poll(self) -> int:
        from ._hooks import poll_and_process_hooks

        with self._mgr.transaction() as conn:
            return poll_and_process_hooks(
                conn, self._hook_handlers, self._keys, self._metrics, self._project,
            )

    def claim(self, max_batch: int = 10, lease_seconds: int = 60) -> list[HookContext]:
        from ._hooks import claim_hooks as _claim

        with self._mgr.transaction() as conn:
            return _claim(conn, max_batch, lease_seconds)

    def complete(self, hook_queue_id: int) -> None:
        from ._hooks import complete_hook as _complete

        with self._mgr.transaction() as conn:
            _complete(conn, hook_queue_id)

    def fail(self, hook_queue_id: int, error: str) -> None:
        from ._hooks import fail_hook as _fail

        with self._mgr.transaction() as conn:
            _fail(conn, hook_queue_id, error, self._keys, self._metrics, self._project)

    def sweep_expired_leases(self) -> int:
        from ._hooks import sweep_expired_hook_leases as _sweep

        with self._mgr.transaction() as conn:
            swept = _sweep(conn)
        if swept:
            self._metrics.inc("maintenance_hook_leases_swept", self._project, amount=swept)
        return swept

    def list_dead_lettered(self) -> list[DeadLetterEntry]:
        from psycopg.sql import SQL

        with self._mgr.transaction() as conn:
            rows = conn.execute(
                SQL(
                    "SELECT id, event_id, hook_name, hook_type, payload, "
                    "retry_count, error_message, dead_lettered_at, "
                    "original_hook_queue_id "
                    "FROM hook_dead_letter ORDER BY dead_lettered_at DESC"
                ),
            ).fetchall()

        return [
            DeadLetterEntry(
                id=r["id"],
                event_id=r["event_id"],
                hook_name=r["hook_name"],
                hook_type=r["hook_type"],
                payload=r["payload"],
                retry_count=r["retry_count"],
                error_message=r["error_message"],
                dead_lettered_at=r["dead_lettered_at"],
                original_hook_queue_id=r.get("original_hook_queue_id"),
            )
            for r in rows
        ]

    def requeue_dead_lettered(self, dead_letter_id: int) -> None:
        from ._hooks import requeue_dead_lettered_hook as _requeue

        timer = OpTimer(self._project, "requeue_dead_lettered_hook")
        try:
            with self._mgr.transaction() as conn:
                _requeue(conn, dead_letter_id, self._hook_channel, self._keys)

            timer.log("ok", detail=str(dead_letter_id))
        except SubstrateError:
            timer.log("error")
            raise

    def refresh_queue_metrics(self) -> None:
        from psycopg.sql import SQL

        with self._mgr.transaction() as conn:
            rows = conn.execute(
                SQL(
                    "SELECT status, count(*) AS n "
                    "FROM hook_queue "
                    "GROUP BY status"
                )
            ).fetchall()
            dead_row = conn.execute(
                SQL("SELECT count(*) AS n FROM hook_dead_letter")
            ).fetchone()

        counts = {r["status"]: int(r["n"]) for r in rows}
        for status in ("pending", "in_progress", "completed"):
            self._metrics.set_hook_queue_depth(
                self._project, status, float(counts.get(status, 0))
            )
        self._metrics.set_hook_queue_depth(
            self._project, "dead_letter", float(dead_row["n"] if dead_row else 0)
        )


class RecurrenceOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project

    def register_rule(
        self,
        workflow_name: str,
        workflow_version: int,
        work_item_type: str,
        template: dict,
        schedule_kind: str,
        schedule_expr: str,
        *,
        timezone: str = "UTC",
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        count: int | None = None,
        catchup_policy: str = "fire_once",
        created_by: str = "system",
    ) -> dict:
        from ._recurrence_api import register_recurrence_rule as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            workflow_name, workflow_version, work_item_type, template,
            schedule_kind, schedule_expr,
            timezone=timezone, start_at=start_at, end_at=end_at,
            count=count, catchup_policy=catchup_policy, created_by=created_by,
        )

    def list_rules(self, status: str | None = None) -> list[dict]:
        from ._recurrence_api import list_recurrence_rules as _impl

        return _impl(self._mgr, status=status)

    def due(self, now: datetime | None = None) -> list[dict]:
        from ._recurrence_api import due_recurrences as _impl

        return _impl(self._mgr, now=now)

    def fire(self, rule_id) -> tuple[dict, dict]:
        from ._recurrence_api import fire_recurrence as _impl

        result = _impl(self._mgr, self._keys, self._metrics, self._project, rule_id)
        self._metrics.inc("maintenance_recurrences_fired", self._project)
        return result

    def cancel_rule(self, rule_id) -> None:
        from ._recurrence_api import cancel_recurrence_rule as _impl

        _impl(self._mgr, rule_id)

    def update_rule(
        self,
        rule_id,
        *,
        status: str | None = None,
        schedule_expr: str | None = None,
        template: dict | None = None,
    ) -> dict:
        from ._recurrence_api import update_recurrence_rule as _impl

        return _impl(
            self._mgr, rule_id,
            status=status, schedule_expr=schedule_expr, template=template,
        )
