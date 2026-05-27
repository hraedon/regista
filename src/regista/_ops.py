from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from ._connection import ConnectionManager
from ._contract import Jsonb as _Jsonb
from ._contract import validate_delegation_chain as _validate_delegation_chain
from ._contract import validate_mutation_params as _validate_mutation_params
from ._errors import ErrorCode, RegistaError
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
from ._witness import (
    create_receipts as _create_receipts,
)
from ._witness import (
    deliver_pending_receipts as _deliver_pending_receipts,
)
from ._witness import (
    event_matches_filter as _event_matches_filter,
)
from ._witness import (
    list_witness_receipts as _list_witness_receipts,
)
from ._witness import (
    list_witnesses as _list_witnesses,
)
from ._witness import (
    pause_witness as _pause_witness,
)
from ._witness import (
    reactivate_witness as _reactivate_witness,
)
from ._witness import (
    register_witness as _register_witness,
)
from ._witness import (
    unregister_witness as _unregister_witness,
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

    def create_batch(
        self,
        items: list[dict],
        actor_id: str,
        actor_kind: str = "agent",
    ) -> list[tuple[WorkItem, Event]]:
        from ._work_items import create_work_item as _create

        _validate_mutation_params(actor_id=actor_id, actor_kind=actor_kind)
        results = []
        with self._mgr.transaction() as conn:
            for item in items:
                wi, evt = _create(
                    conn,
                    workflow_name=item["workflow_name"],
                    work_item_type=item["work_item_type"],
                    actor_id=actor_id,
                    actor_kind=actor_kind,
                    actor_metadata=(
                        _Jsonb(item.get("actor_metadata"))
                        if item.get("actor_metadata") else None
                    ),
                    key_set=self._keys,
                    custom_fields=item.get("custom_fields"),
                    not_before=item.get("not_before"),
                    event_id=item.get("event_id"),
                )
                results.append((wi, evt))
        return results

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
        on_behalf_of: dict | None = None,
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
            _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())

            with self._mgr.transaction() as conn:
                wi = _lock(conn, work_item_id)
                if wi is None:
                    raise RegistaError(
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
                    on_behalf_of=on_behalf_of,
                    _prelocked_wi=wi,
                )

                conn.execute(
                    SQL("UPDATE work_items_current SET not_before = %s WHERE work_item_id = %s"),
                    [not_before, work_item_id],
                )

            self._metrics.inc("events_appended", self._project)
            timer.log("ok", work_item_id=str(work_item_id))
            return evt
        except RegistaError:
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
        key_id: str | None = None,
        transition: str | None = None,
        payload: dict | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict | None = None,
    ) -> Event:
        from ._events_api import append_event as _impl

        return _impl(
            self._mgr, self._keys, self._metrics, self._project,
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
            key_id=key_id,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
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


class TimestampOps:
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
        self._tsa_config: Any = None

    def set_config(self, config: Any) -> None:
        self._tsa_config = config

    def trigger(self) -> Any | None:
        if self._tsa_config is None:
            raise RegistaError(
                ErrorCode.TSA_NOT_CONFIGURED,
                "TSA is not configured",
            )
        from ._timestamping import trigger_timestamping

        with self._mgr.transaction() as conn:
            return trigger_timestamping(conn, self._tsa_config)

    def list_batches(self, status: str | None = None) -> list[Any]:
        from ._timestamping import list_batches

        with self._mgr.transaction() as conn:
            return list_batches(conn, status)

    def verify_batch(self, batch_id: uuid.UUID) -> bool:
        from ._timestamping import list_batches, verify_tsa_token

        with self._mgr.transaction() as conn:
            batches = list_batches(conn)
            for b in batches:
                if b.batch_id == batch_id:
                    if b.tsa_token is None:
                        return False
                    if self._tsa_config is None:
                        raise RegistaError(
                            ErrorCode.TSA_NOT_CONFIGURED,
                            "TSA is not configured",
                        )
                    return verify_tsa_token(b.tsa_token, b.merkle_root, self._tsa_config)
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Batch {batch_id} not found",
            )


class HookOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        keys: KeySet,
        metrics: Metrics,
        project: str,
        validators: dict[str, Callable],
        handlers: dict[str, Callable],
        channel: str,
        consumer,
    ) -> None:
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._project = project
        self._validators = validators
        self._handlers = handlers
        self._channel = channel
        self._hook_channel = channel
        self._consumer = consumer

    def register_validator(self, name: str, handler: Callable) -> None:
        self._validators = {**self._validators, name: handler}

    def register_handler(self, name: str, handler: Callable) -> None:
        updated = {**self._handlers, name: handler}
        self._handlers = updated
        if self._consumer is not None:
            self._consumer._handlers = updated

    def start_consumer(self) -> None:
        if self._consumer is None:
            return
        self._consumer._handlers = self._handlers
        if not self._consumer.is_running:
            self._consumer.start()

    def stop_consumer(self) -> None:
        if self._consumer is None:
            return
        if self._consumer.is_running:
            self._consumer.stop()

    def poll(self) -> int:
        from ._hooks import poll_and_process_hooks as _poll

        with self._mgr.transaction() as conn:
            count = _poll(
                conn,
                self._handlers,
                self._keys,
                self._metrics,
                self._project,
            )
        if count > 0:
            self._metrics.inc("hooks_drain", self._project, amount=count)
        return count

    def claim(self, max_batch: int, lease_seconds: int) -> list[HookContext]:
        from ._hooks import claim_hooks

        with self._mgr.transaction() as conn:
            return claim_hooks(conn, max_batch, lease_seconds)

    def complete(self, hook_queue_id: int) -> None:
        from ._hooks import complete_hook

        with self._mgr.transaction() as conn:
            complete_hook(conn, hook_queue_id)

    def fail(self, hook_queue_id: int, error: str) -> None:
        from ._hooks import fail_hook

        with self._mgr.transaction() as conn:
            fail_hook(conn, hook_queue_id, error, self._keys, self._metrics, self._project)

    def sweep_expired_leases(self) -> int:
        from ._hooks import sweep_expired_hook_leases

        with self._mgr.transaction() as conn:
            swept = sweep_expired_hook_leases(conn)
        if swept and self._metrics:
            self._metrics.inc("maintenance_hook_leases_swept", self._project, amount=swept)
        return swept

    def refresh_queue_metrics(self) -> None:
        from ._hooks_api import refresh_hook_queue_metrics

        return refresh_hook_queue_metrics(self._mgr, self._metrics, self._project)

    def list_dead_letter(self, limit: int = 100) -> list[DeadLetterEntry]:
        from ._hooks_api import list_dead_lettered_hooks

        return list_dead_lettered_hooks(self._mgr, limit)

    def requeue_dead_letter(self, hook_id: int) -> None:
        from ._hooks_api import requeue_dead_lettered_hook

        return requeue_dead_lettered_hook(
            self._mgr, self._hook_channel, self._keys, self._metrics, self._project, hook_id,
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


class WitnessOps:
    def __init__(self, mgr: ConnectionManager, metrics: Metrics, project: str) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def register(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        mode: str = "witness",
        sign_secret: bytes | None = None,
    ) -> uuid.UUID:
        return _register_witness(
            self._mgr, self._project, url, headers, event_filter,
            max_failures, max_retries, mode=mode, sign_secret=sign_secret,
        )

    def unregister(self, witness_id: uuid.UUID) -> None:
        _unregister_witness(self._mgr, self._project, witness_id)

    def pause(self, witness_id: uuid.UUID) -> None:
        _pause_witness(self._mgr, self._project, witness_id)

    def reactivate(self, witness_id: uuid.UUID) -> None:
        _reactivate_witness(self._mgr, self._project, witness_id)

    def list(self, status: str | None = None, mode: str | None = None) -> list[dict]:
        return _list_witnesses(self._mgr, status=status, mode=mode)

    def receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        return _list_witness_receipts(
            self._mgr,
            event_id=event_id, witness_id=witness_id,
            status=status, limit=limit,
        )

    def deliver(self) -> int:
        return _deliver_pending_receipts(self._mgr, self._project)

    def create_receipts_for_event(self, event_dict: dict) -> int:
        return _create_receipts(self._mgr, event_dict)

    @staticmethod
    def event_matches_filter(event_dict: dict, event_filter: dict | None) -> bool:
        return _event_matches_filter(event_dict, event_filter)


class ArchiveOps:
    def __init__(self, mgr: ConnectionManager, project: str) -> None:
        self._mgr = mgr
        self._project = project

    def archive_events(self, before_timestamp: datetime, *, dry_run: bool = False) -> int:
        from ._archive import archive_events as _impl

        return _impl(self._mgr, self._project, before_timestamp, dry_run=dry_run)


class WebhookOps:
    def __init__(self, mgr: ConnectionManager, project: str) -> None:
        self._mgr = mgr
        self._project = project

    def register(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        transitions: list[str] | None = None,
        work_item_types: list[str] | None = None,
        workflows: list[str] | None = None,
        max_failures: int = 10,
        sign_secret: bytes | None = None,
    ) -> dict:
        from ._webhooks import register_webhook as _impl

        return _impl(
            self._mgr, url, headers=headers,
            transitions=transitions, work_item_types=work_item_types,
            workflows=workflows, max_failures=max_failures,
            sign_secret=sign_secret, project=self._project,
        )

    def list(self, status: str | None = None) -> list[dict]:
        from ._webhooks import list_webhooks as _impl

        return _impl(self._mgr, status=status)

    def unregister(self, webhook_id: uuid.UUID) -> None:
        from ._webhooks import unregister_webhook as _impl

        _impl(self._mgr, webhook_id)

    def pause(self, webhook_id: uuid.UUID) -> None:
        from ._webhooks import pause_webhook as _impl

        _impl(self._mgr, webhook_id)

    def resume(self, webhook_id: uuid.UUID) -> None:
        from ._webhooks import resume_webhook as _impl

        _impl(self._mgr, webhook_id)
