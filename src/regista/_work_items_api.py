from __future__ import annotations

import uuid
from datetime import datetime

from ._contract import Jsonb as _Jsonb
from ._contract import validate_mutation_params as _validate_mutation_params
from ._errors import RegistaError
from ._observability import Metrics, OpTimer
from ._types import Event, QueryPage, WorkItem


def create_work_item(
    mgr,
    keys,
    metrics: Metrics,
    project: str,
    workflow_name: str,
    work_item_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    custom_fields: dict | None = None,
    not_before: datetime | None = None,
    event_id: uuid.UUID | None = None,
    key_id: str | None = None,
) -> tuple[WorkItem, Event]:
    timer = OpTimer(project, "create_work_item")
    try:
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            event_id=event_id,
            not_before=not_before,
        )
        from ._work_items import create_work_item as _create

        with mgr.transaction() as conn:
            wi, evt = _create(
                conn,
                workflow_name=workflow_name,
                work_item_type=work_item_type,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                key_set=keys,
                custom_fields=custom_fields,
                not_before=not_before,
                event_id=event_id,
                key_id=key_id,
            )

        metrics.inc("work_items_created", project)
        metrics.inc("events_appended", project)
        timer.log("ok", work_item_id=str(wi.work_item_id))
        return wi, evt
    except RegistaError:
        timer.log("error")
        raise


def query_work_items(
    mgr,
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
    from ._work_items import query_work_items as _query

    with mgr.transaction() as conn:
        return _query(
            conn,
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


def get_work_item(
    mgr,
    work_item_id: uuid.UUID,
) -> WorkItem | None:
    from ._work_items import get_work_item as _get

    with mgr.transaction() as conn:
        return _get(conn, work_item_id)
