from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

import psycopg
import psycopg.types.json
from psycopg.sql import SQL

from ._connection import DictConn
from ._contract import (
    _RESERVED_TRANSITIONS,
    Jsonb,
    check_expected_seq,
    validate_actor_metadata,
    validate_event_entity_kind,
    validate_json_safe_value,
)
from ._errors import ErrorCode, RegistaError
from ._types import Event

_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, event_seq, actor_id, actor_kind, "
    "actor_metadata, workflow_name, workflow_version, timestamp, transition, payload, "
    "on_behalf_of"
)


def _row_to_event(row: dict[str, Any]) -> Event:
    return Event(
        event_id=row["event_id"],
        work_item_id=row["work_item_id"],
        entity_kind=row.get("entity_kind", "work_item"),
        entity_id=row.get("entity_id"),
        event_seq=row["event_seq"],
        actor_id=row["actor_id"],
        actor_kind=row["actor_kind"],
        actor_metadata=row["actor_metadata"],
        workflow_name=row["workflow_name"],
        workflow_version=row["workflow_version"],
        timestamp=row["timestamp"],
        transition=row["transition"],
        payload=row["payload"],
        on_behalf_of=row.get("on_behalf_of"),
    )


def lock_work_item(
    conn: DictConn,
    work_item_id: uuid.UUID,
) -> dict[str, Any] | None:
    row = conn.execute(
        SQL(
            "SELECT work_item_id, workflow_name, workflow_version, work_item_type, "
            "current_state, custom_fields, needs_review, not_before, "
            "last_event_seq, last_event_at, next_event_seq, "
            "claimed_by, claim_expires_at, attempt_number "
            "FROM work_items_current WHERE work_item_id = %s FOR UPDATE"
        ),
        [work_item_id],
    ).fetchone()
    return row


def check_idempotency(
    conn: DictConn,
    event_id: uuid.UUID,
    actor_id: str | None = None,
    transition: str | None = None,
    work_item_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
    entity_kind: str | None = None,
) -> Event | None:
    from ._contract import check_idempotency as _contract_check

    row = conn.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events WHERE event_id = %s"),
        [event_id],
    ).fetchone()
    if row is None:
        return None
    return _contract_check(
        _row_to_event(row), actor_id, transition, work_item_id, payload=payload,
        entity_kind=entity_kind,
    )


def _next_entity_seq(
    conn: DictConn,
    entity_kind: str,
    entity_id: uuid.UUID,
    locked_seq: int | None,
) -> int:
    if locked_seq is not None:
        return locked_seq
    entity_bytes = entity_id.bytes
    key1 = int.from_bytes(entity_bytes[:8], "big", signed=False)
    key2 = int.from_bytes(entity_bytes[8:], "big", signed=False)
    if key1 >= 2**63:
        key1 -= 2**64
    if key2 >= 2**63:
        key2 -= 2**64
    conn.execute("SELECT pg_advisory_xact_lock(%s, %s)", [key1, key2])
    row = conn.execute(
        SQL(
            "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq "
            "FROM events WHERE entity_kind = %s AND entity_id = %s"
        ),
        [entity_kind, entity_id],
    ).fetchone()
    assert row is not None
    return int(row["next_seq"])


def _insert_event(
    conn: DictConn,
    *,
    event_id: uuid.UUID,
    work_item_id: uuid.UUID,
    entity_kind: str,
    event_seq: int,
    actor_id: str,
    actor_kind: str,
    actor_metadata: dict[str, Any] | None,
    workflow_name: str | None,
    workflow_version: int | None,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None,
) -> None:
    try:
        conn.execute(
            SQL(
                "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, "
                "event_seq, actor_id, actor_kind, actor_metadata, workflow_name, "
                "workflow_version, timestamp, transition, payload, on_behalf_of) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            [
                event_id,
                work_item_id,
                entity_kind,
                work_item_id,
                event_seq,
                actor_id,
                actor_kind,
                psycopg.types.json.Jsonb(actor_metadata) if actor_metadata is not None else None,
                workflow_name,
                workflow_version,
                timestamp,
                transition,
                psycopg.types.json.Jsonb(payload) if payload is not None else None,
                psycopg.types.json.Jsonb(on_behalf_of) if on_behalf_of is not None else None,
            ],
        )
    except psycopg.errors.UniqueViolation as exc:
        constraint = exc.diag.constraint_name or ""
        if constraint == "events_entity_event_seq_key":
            raise RegistaError(
                ErrorCode.CONCURRENT_MODIFICATION,
                f"Concurrent event_seq collision for entity_kind={entity_kind}, "
                f"entity_id={work_item_id}",
            ) from exc
        existing = check_idempotency(
            conn,
            event_id,
            actor_id=actor_id,
            transition=transition,
            work_item_id=work_item_id,
            payload=payload,
            entity_kind=entity_kind,
        )
        if existing is not None:
            return
        raise RegistaError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {event_id} already exists",
        ) from exc


def append_event(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    workflow_name: str | None,
    workflow_version: int | None,
    transition: str | None,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    _prelocked_wi: dict[str, Any] | None = None,
    entity_kind: str = "work_item",
) -> Event:
    am = actor_metadata.value if actor_metadata is not None else None
    validate_actor_metadata(am)
    validate_event_entity_kind(entity_kind, transition)

    wi_row = None
    if entity_kind == "work_item":
        wi_row = _prelocked_wi if _prelocked_wi is not None else lock_work_item(conn, work_item_id)
        if wi_row is None:
            raise RegistaError(
                ErrorCode.WORK_ITEM_NOT_FOUND,
                f"Work item {work_item_id} not found",
            )

    _idem_payload = None if transition in _RESERVED_TRANSITIONS else (
        payload.value if payload is not None else None
    )
    existing = check_idempotency(
        conn,
        event_id,
        actor_id=actor_id,
        transition=transition,
        work_item_id=work_item_id,
        payload=_idem_payload,
        entity_kind=entity_kind,
    )
    if existing is not None:
        return existing

    next_seq = _next_entity_seq(
        conn,
        entity_kind,
        work_item_id,
        int(wi_row["next_event_seq"]) if wi_row is not None else None,
    )
    check_expected_seq(next_seq, expected_event_seq)

    pl = payload.value if payload is not None else None
    if on_behalf_of is not None:
        validate_json_safe_value(on_behalf_of, "on_behalf_of")

    now = datetime.now(UTC)
    _insert_event(
        conn,
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        event_seq=next_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition,
        payload=pl,
        on_behalf_of=on_behalf_of,
    )

    if entity_kind == "work_item":
        conn.execute(
            SQL(
                "UPDATE work_items_current SET "
                "last_event_seq = %s, last_event_at = %s, next_event_seq = %s "
                "WHERE work_item_id = %s"
            ),
            [next_seq, now, next_seq + 1, work_item_id],
        )

    return Event(
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        entity_id=work_item_id,
        event_seq=next_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition,
        payload=pl,
        on_behalf_of=on_behalf_of,
    )


def append_transition_event(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    transition_name: str,
    new_state: str,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None = None,
    custom_fields_update: dict[str, Any] | None = None,
    release_claim: bool = True,
    on_behalf_of: dict[str, Any] | None = None,
    _prelocked_wi: dict[str, Any] | None = None,
) -> Event:
    am = actor_metadata.value if actor_metadata is not None else None
    validate_actor_metadata(am)

    wi_row = _prelocked_wi if _prelocked_wi is not None else lock_work_item(conn, work_item_id)
    if wi_row is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    stored_payload = dict(cast(dict[str, Any], payload.value)) if payload is not None else {}
    if custom_fields_update:
        stored_payload["custom_fields_update"] = custom_fields_update

    existing = check_idempotency(
        conn,
        event_id,
        actor_id=actor_id,
        transition=transition_name,
        work_item_id=work_item_id,
        payload=stored_payload if payload is not None else None,
        entity_kind="work_item",
    )
    if existing is not None:
        return existing

    next_seq = int(wi_row["next_event_seq"])
    check_expected_seq(next_seq, expected_event_seq)

    if on_behalf_of is not None:
        validate_json_safe_value(on_behalf_of, "on_behalf_of")

    now = datetime.now(UTC)
    workflow_name = wi_row["workflow_name"]
    workflow_version = wi_row["workflow_version"]

    _insert_event(
        conn,
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind="work_item",
        event_seq=next_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition_name,
        payload=stored_payload if stored_payload else None,
        on_behalf_of=on_behalf_of,
    )

    merged_fields = wi_row["custom_fields"]
    if custom_fields_update:
        if merged_fields is None:
            merged_fields = {}
        merged_fields = {**merged_fields, **custom_fields_update}

    claim_clear = SQL("")
    if release_claim:
        claim_clear = SQL(", claimed_by = NULL, claim_expires_at = NULL")

    conn.execute(
        SQL(
            "UPDATE work_items_current SET "
            "current_state = %s, custom_fields = %s, "
            "last_event_seq = %s, last_event_at = %s, next_event_seq = %s"
        )
        + claim_clear
        + SQL(" WHERE work_item_id = %s"),
        [
            new_state,
            psycopg.types.json.Jsonb(merged_fields),
            next_seq,
            now,
            next_seq + 1,
            work_item_id,
        ],
    )

    if release_claim:
        conn.execute(
            SQL("DELETE FROM claims WHERE work_item_id = %s"),
            [work_item_id],
        )

    return Event(
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind="work_item",
        entity_id=work_item_id,
        event_seq=next_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition_name,
        payload=stored_payload,
        on_behalf_of=on_behalf_of,
    )


def read_events_by_work_item(
    conn: DictConn,
    work_item_id: uuid.UUID,
    limit: int = 100,
    before_seq: int | None = None,
    after_seq: int | None = None,
) -> list[Event]:
    if before_seq is not None:
        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM events "
                "WHERE work_item_id = %s AND event_seq < %s"
                " ORDER BY event_seq DESC LIMIT %s"
            ),
            [work_item_id, before_seq, limit],
        ).fetchall()
    elif after_seq is not None:
        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM events "
                "WHERE work_item_id = %s AND event_seq > %s"
                " ORDER BY event_seq ASC LIMIT %s"
            ),
            [work_item_id, after_seq, limit],
        ).fetchall()
    else:
        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM events "
                "WHERE work_item_id = %s"
                " ORDER BY event_seq DESC LIMIT %s"
            ),
            [work_item_id, limit],
        ).fetchall()
    if after_seq is not None:
        return [_row_to_event(r) for r in rows]
    return [_row_to_event(r) for r in reversed(rows)]


def read_events_composite(
    conn: DictConn,
    *,
    work_item_id: uuid.UUID | None = None,
    actor_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    transition: str | None = None,
    limit: int = 100,
    before_seq: int | None = None,
) -> list[Event]:
    clauses: list[str] = []
    params: list[Any] = []

    if work_item_id is not None:
        clauses.append("work_item_id = %s")
        params.append(work_item_id)
    if actor_id is not None:
        clauses.append("actor_id = %s")
        params.append(actor_id)
    if transition is not None:
        clauses.append("transition = %s")
        params.append(transition)
    if start is not None and end is not None:
        clauses.append("timestamp >= %s AND timestamp <= %s")
        params.extend([start, end])
    if before_seq is not None and work_item_id is not None:
        clauses.append("event_seq < %s")
        params.append(before_seq)

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    if work_item_id is not None:
        order_sql = "ORDER BY event_seq DESC LIMIT %s"
    elif start is not None and end is not None:
        order_sql = "ORDER BY timestamp, event_seq LIMIT %s"
    else:
        order_sql = "ORDER BY timestamp DESC, event_seq DESC LIMIT %s"

    params.append(limit)

    rows = conn.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events {where_sql} {order_sql}"),
        params,
    ).fetchall()

    if work_item_id is not None:
        return [_row_to_event(r) for r in reversed(rows)]
    return [_row_to_event(r) for r in rows]
