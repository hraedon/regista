from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from ._contract import (
    Jsonb,
    check_append_blocked,
    check_reserved_transition,
    validate_event_entity_kind,
    validate_mutation_params,
    validate_read_events_filters,
    validate_work_item_exists,
)
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._keys import KeySet
from ._types import Event


def in_memory_append_event(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    workflows: dict[tuple[str, int], dict[str, Any]],
    key_set: KeySet | None,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    *,
    key_id: str | None = None,
    transition: str | None = None,
    payload: dict[str, Any] | None = None,
    event_id: uuid.UUID | None = None,
    expected_event_seq: int | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    action_delegation_credentials: tuple[dict[str, Any] | bytes, ...] = (),
) -> Event:
    validate_event_entity_kind(entity_kind, transition)
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        event_id=event_id,
    )

    if entity_kind == "work_item":
        wi = work_items.get(work_item_id)
        validate_work_item_exists(wi, work_item_id)
        assert wi is not None
        wf_name = wi["workflow_name"]
        wf_version = wi["workflow_version"]
    else:
        wf_name = ""
        wf_version = 0

    if transition is not None:
        check_reserved_transition(transition)
        if entity_kind == "work_item":
            wf_data = workflows.get((wf_name, wf_version))
            if wf_data is not None:
                check_append_blocked(
                    wf_data.get("transitions", []),
                    transition,
                    wf_name,
                )

    return _store_append(
        store,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=wf_name,
        workflow_version=wf_version,
        transition=transition,
        payload=Jsonb(payload) if payload is not None else None,
        event_id=event_id,
        expected_event_seq=expected_event_seq,
        key_set=key_set,
        on_behalf_of=on_behalf_of,
        _key_id=key_id,
        entity_kind=entity_kind,
        hash_alg=hash_alg,
        action_delegation_credentials=action_delegation_credentials,
    )


def in_memory_read_events(
    store: InMemoryEventStore,
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
    store: InMemoryEventStore,
    work_item_id: uuid.UUID,
    after_seq: int,
    *,
    limit: int = 100,
) -> list[Event]:
    evts = store.events.get(work_item_id, [])
    result = [e for e in evts if e.event_seq > after_seq]
    result.sort(key=lambda e: e.event_seq)
    return result[:limit]
