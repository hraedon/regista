from __future__ import annotations

import uuid
from datetime import datetime

from ._contract import (
    Jsonb,
    check_append_blocked,
    check_reserved_transition,
    validate_mutation_params,
    validate_read_events_filters,
    validate_work_item_exists,
)
from ._event_store import append_event as _store_append
from ._types import Event


def in_memory_append_event(
    store,
    work_items: dict,
    workflows: dict,
    key_set,
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
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
    )

    wi = work_items.get(work_item_id)
    validate_work_item_exists(wi, work_item_id)

    if transition is not None:
        check_reserved_transition(transition)
        wf_data = workflows.get((wi["workflow_name"], wi["workflow_version"]))
        if wf_data is not None:
            check_append_blocked(
                wf_data.get("transitions", []),
                transition,
                wi["workflow_name"],
            )

    return _store_append(
        store,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition=transition,
        payload=Jsonb(payload) if payload is not None else None,
        event_id=event_id,
        expected_event_seq=expected_event_seq,
        key_set=key_set,
        on_behalf_of=on_behalf_of,
        _key_id=key_id,
    )


def in_memory_read_events(
    store,
    *,
    work_item_id: uuid.UUID | None = None,
    actor_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    transition: str | None = None,
    limit: int = 100,
    before_seq: int | None = None,
) -> list[Event]:
    validate_read_events_filters(before_seq, work_item_id, start, end)
    return store.read(
        work_item_id=work_item_id,
        actor_id=actor_id,
        start=start,
        end=end,
        transition=transition,
        limit=limit,
        before_seq=before_seq,
    )


def in_memory_read_events_since(
    store,
    work_item_id: uuid.UUID,
    after_seq: int,
    *,
    limit: int = 100,
) -> list[Event]:
    evts = store.events.get(work_item_id, [])
    result = [e for e in evts if e.event_seq > after_seq]
    result.sort(key=lambda e: e.event_seq)
    return result[:limit]
