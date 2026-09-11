from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from ._connection import ConnectionManager
from ._contract import Jsonb as _Jsonb
from ._contract import validate_content_hash as _validate_content_hash
from ._contract import validate_delegation_chain as _validate_delegation_chain
from ._contract import validate_mutation_params as _validate_mutation_params
from ._errors import ErrorCode, RegistaError
from ._observability import Metrics, OpTimer
from ._types import (
    Claim,
    Event,
    Link,
    QueryPage,
    WorkflowDefinition,
    WorkflowVersion,
    WorkItem,
)

log = structlog.get_logger()


class WorkflowOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def register(self, yaml_content: str) -> WorkflowVersion:
        from ._workflow_api import register_workflow as _impl

        return _impl(self._mgr, self._metrics, self._project, yaml_content)

    def register_file(self, path: str | Path) -> WorkflowVersion:
        from ._workflow_api import register_workflow_file as _impl

        return _impl(self._mgr, self._metrics, self._project, path)

    def get(self, workflow_name: str, version: int) -> WorkflowDefinition:
        from ._workflow_api import get_workflow as _impl

        return _impl(self._mgr, self._project, workflow_name, version)


class WorkItemOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def create(
        self,
        workflow_name: str,
        work_item_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        custom_fields: dict[str, Any] | None = None,
        not_before: datetime | None = None,
        event_id: uuid.UUID | None = None,
    ) -> tuple[WorkItem, Event]:
        from ._work_items_api import create_work_item as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )

    def create_batch(
        self,
        items: list[dict[str, Any]],
        actor_id: str,
        actor_kind: str = "agent",
    ) -> list[tuple[WorkItem, Event]]:
        from ._work_items import create_work_item as _create

        _validate_mutation_params(actor_id=actor_id, actor_kind=actor_kind)
        results = []
        with self._mgr.transaction() as conn:
            for item in items:
                _validate_mutation_params(actor_metadata=item.get("actor_metadata"))
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
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        on_behalf_of: dict[str, Any] | None = None,
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
                actor_metadata=actor_metadata,
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
                    payload={"not_before": not_before.isoformat() if not_before else None},
                )
                if existing is not None:
                    return existing

                evt = _append_event(
                    conn,
                    work_item_id=work_item_id,
                    actor_id=actor_id,
                    actor_kind=actor_kind,
                    actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
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
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def append(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        transition: str | None = None,
        payload: dict[str, Any] | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        entity_kind: str = "work_item",
    ) -> Event:
        from ._events_api import append_event as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            entity_kind=entity_kind,
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
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
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
        actor_metadata: dict[str, Any] | None = None,
    ) -> Claim:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        from ._claims_api import acquire_claim as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            work_item_id, actor_id, ttl_seconds,
            event_id=event_id, actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    def heartbeat(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        expected_attempt_number: int | None = None,
        coalesce_threshold: float | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
    ) -> Claim:
        _validate_mutation_params(actor_id=actor_id, actor_kind=actor_kind, ttl_seconds=ttl_seconds)
        from ._claims_api import heartbeat_claim as _impl

        return _impl(
            self._mgr, self._project,
            work_item_id, actor_id, ttl_seconds,
            expected_attempt_number=expected_attempt_number,
            coalesce_threshold=coalesce_threshold,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    def release(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        expected_attempt_number: int | None = None,
    ) -> None:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        from ._claims_api import release_claim as _impl

        _impl(
            self._mgr, self._metrics, self._project,
            work_item_id, actor_id,
            event_id=event_id, actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            expected_attempt_number=expected_attempt_number,
        )

    def sweep_expired(self) -> int:
        from ._claims_api import sweep_expired_claims as _impl

        swept = _impl(self._mgr, self._metrics, self._project)
        if swept:
            self._metrics.inc("maintenance_claims_swept", self._project, amount=swept)
        return swept


class LinkOps:
    def __init__(
        self,
        mgr: ConnectionManager,
        metrics: Metrics,
        project: str,
    ) -> None:
        self._mgr = mgr
        self._metrics = metrics
        self._project = project

    def create(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        payload: dict[str, Any] | None = None,
        target_project: str | None = None,
        target_entity_kind: str | None = None,
        content_hash: str | None = None,
    ) -> Link:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            event_id=event_id,
        )
        _validate_content_hash(content_hash)
        from ._links_api import create_link as _impl

        return _impl(
            self._mgr, self._metrics, self._project,
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id, payload=payload,
            target_project=target_project,
            target_entity_kind=target_entity_kind,
            content_hash=content_hash,
        )

    def remove(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        target_project: str | None = None,
    ) -> None:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            event_id=event_id,
        )
        from ._links_api import remove_link as _impl

        _impl(
            self._mgr, self._metrics, self._project,
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id,
            target_project=target_project,
        )

    def list(
        self,
        work_item_id: uuid.UUID,
    ) -> list[Link]:
        """Return all live (non-removed) links from *work_item_id*."""
        from ._links_api import list_links as _impl

        return _impl(self._mgr, work_item_id)
