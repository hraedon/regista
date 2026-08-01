from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ._contract import (
    Jsonb as _Jsonb,
)
from ._contract import (
    check_append_blocked as _check_append_blocked,
)
from ._contract import (
    check_reserved_transition as _check_reserved_transition,
)
from ._contract import (
    validate_delegation_chain as _validate_delegation_chain,
)
from ._contract import (
    validate_entity_kind,
)
from ._contract import (
    validate_mutation_params as _validate_mutation_params,
)
from ._contract import (
    validate_read_events_filters as _validate_read_events_filters,
)
from ._errors import ErrorCode, RegistaError
from ._event_store import PostgresEventStore as _PostgresEventStore
from ._event_store import append_event as _store_append_event
from ._observability import Metrics, OpTimer
from ._types import Event


def append_event(
    mgr,
    keys,
    metrics: Metrics,
    project: str,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    transition: str | None = None,
    payload: dict | None = None,
    event_id: uuid.UUID | None = None,
    expected_event_seq: int | None = None,
    on_behalf_of: dict | None = None,
    key_id: str | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
) -> Event:
    timer = OpTimer(project, "append_event")
    try:
        validate_entity_kind(entity_kind)
        if event_id is None:
            event_id = uuid.uuid4()
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            event_id=event_id,
        )
        _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())

        with mgr.transaction() as conn:
            if entity_kind == "work_item":
                wi_row = conn.execute(
                    "SELECT workflow_name, workflow_version FROM work_items_current "
                    "WHERE work_item_id = %s",
                    [work_item_id],
                ).fetchone()
                if wi_row is None:
                    raise RegistaError(
                        ErrorCode.WORK_ITEM_NOT_FOUND,
                        f"Work item {work_item_id} not found",
                    )
                wf_name = wi_row["workflow_name"]
                wf_version = wi_row["workflow_version"]
            else:
                wf_name = ""
                wf_version = 0

            if transition is not None:
                _check_reserved_transition(transition)
                if entity_kind == "work_item":
                    wf_data = conn.execute(
                        "SELECT definition FROM workflow_registry "
                        "WHERE workflow_name = %s AND version = %s",
                        [wf_name, wf_version],
                    ).fetchone()
                    if wf_data is not None:
                        _check_append_blocked(
                            wf_data["definition"].get("transitions", []),
                            transition,
                            wf_name,
                        )

            store = _PostgresEventStore(conn, keys)
            evt = _store_append_event(
                store,
                work_item_id=work_item_id,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                workflow_name=wf_name,
                workflow_version=wf_version,
                transition=transition,
                payload=_Jsonb(payload) if payload is not None else None,
                event_id=event_id,
                expected_event_seq=expected_event_seq,
                key_set=keys,
                on_behalf_of=on_behalf_of,
                _key_id=key_id,
                entity_kind=entity_kind,
                hash_alg=hash_alg,
            )

        metrics.inc("events_appended", project)
        timer.log("ok", work_item_id=str(work_item_id))
        return evt
    except RegistaError as e:
        if e.code == ErrorCode.CONCURRENT_MODIFICATION:
            metrics.inc("expected_seq_mismatches", project)
        timer.log("rejected", work_item_id=str(work_item_id))
        raise


def read_events(
    mgr,
    *,
    work_item_id: uuid.UUID | None = None,
    actor_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    transition: str | None = None,
    limit: int = 100,
    before_seq: int | None = None,
) -> list[Event]:
    _validate_read_events_filters(before_seq, work_item_id, start, end)
    from ._events import read_events_composite

    with mgr.transaction() as conn:
        return read_events_composite(
            conn,
            work_item_id=work_item_id,
            actor_id=actor_id,
            start=start,
            end=end,
            transition=transition,
            limit=limit,
            before_seq=before_seq,
        )


def read_events_since(
    mgr,
    work_item_id: uuid.UUID,
    after_seq: int,
    *,
    limit: int = 100,
) -> list[Event]:
    from ._events import read_events_by_work_item as _read

    with mgr.transaction() as conn:
        return _read(conn, work_item_id, limit=limit, after_seq=after_seq)
