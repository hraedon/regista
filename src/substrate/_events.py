from __future__ import annotations

import uuid
from datetime import datetime

import psycopg
from psycopg.sql import SQL

from ._contract import Jsonb
from ._errors import ErrorCode, SubstrateError
from ._keys import KeySet
from ._signing import sign_event
from ._types import Event

_EVENT_FIELDS = (
    "event_id, work_item_id, event_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, canonical_envelope, "
    "on_behalf_of"
)


def _row_to_event(row: dict) -> Event:
    return Event(
        event_id=row["event_id"],
        work_item_id=row["work_item_id"],
        event_seq=row["event_seq"],
        actor_id=row["actor_id"],
        actor_kind=row["actor_kind"],
        actor_metadata=row["actor_metadata"],
        key_id=row["key_id"],
        workflow_name=row["workflow_name"],
        workflow_version=row["workflow_version"],
        timestamp=row["timestamp"],
        transition=row["transition"],
        payload=row["payload"],
        payload_canonical_hash=bytes(row["payload_canonical_hash"]),
        signature=bytes(row["signature"]),
        canonical_envelope=bytes(row["canonical_envelope"]) if row["canonical_envelope"] else None,
        on_behalf_of=row.get("on_behalf_of"),
    )


def lock_work_item(
    conn: psycopg.Connection,
    work_item_id: uuid.UUID,
) -> dict | None:
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
    conn: psycopg.Connection,
    event_id: uuid.UUID,
    actor_id: str | None = None,
    transition: str | None = None,
    work_item_id: uuid.UUID | None = None,
) -> Event | None:
    from ._contract import check_idempotency as _contract_check

    row = conn.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events WHERE event_id = %s"),
        [event_id],
    ).fetchone()
    if row is None:
        return None
    return _contract_check(_row_to_event(row), actor_id, transition, work_item_id)


def check_expected_seq(
    current_next_seq: int,
    expected_event_seq: int | None,
) -> None:
    if expected_event_seq is not None and current_next_seq != expected_event_seq:
        raise SubstrateError(
            ErrorCode.CONCURRENT_MODIFICATION,
            f"Expected event_seq {expected_event_seq}, but current next is {current_next_seq}",
        )


def append_event(
    conn: psycopg.Connection,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    workflow_name: str,
    workflow_version: int,
    transition: str | None,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None = None,
    on_behalf_of: dict | None = None,
    _prelocked_wi: dict | None = None,
) -> Event:
    key_entry = key_set.active_key()
    key_id = key_entry.key_id

    wi_row = _prelocked_wi if _prelocked_wi is not None else lock_work_item(conn, work_item_id)
    if wi_row is None:
        raise SubstrateError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    existing = check_idempotency(
        conn, event_id, actor_id=actor_id, transition=transition,
        work_item_id=work_item_id,
    )
    if existing is not None:
        return existing

    next_seq = wi_row["next_event_seq"]
    check_expected_seq(next_seq, expected_event_seq)

    am = actor_metadata.value if actor_metadata is not None else None
    pl = payload.value if payload is not None else None

    signature, canonical_hash, canonical_envelope = sign_event(
        event_id=event_id,
        work_item_id=work_item_id,
        actor_id=actor_id,
        transition=transition,
        payload=pl,
        key=key_entry.secret,
        on_behalf_of=on_behalf_of,
    )

    event_seq = next_seq
    try:
        row = conn.execute(
            SQL(
                "INSERT INTO events (event_id, work_item_id, event_seq, actor_id, actor_kind, "
                "actor_metadata, key_id, workflow_name, workflow_version, "
                "transition, payload, payload_canonical_hash, signature, "
                "canonical_envelope, on_behalf_of) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING timestamp"
            ),
            [
                event_id,
                work_item_id,
                event_seq,
                actor_id,
                actor_kind,
                psycopg.types.json.Jsonb(am) if am is not None else None,
                key_id,
                workflow_name,
                workflow_version,
                transition,
                psycopg.types.json.Jsonb(pl) if pl is not None else None,
                canonical_hash,
                signature,
                canonical_envelope,
                psycopg.types.json.Jsonb(on_behalf_of) if on_behalf_of is not None else None,
            ],
        ).fetchone()
    except psycopg.errors.UniqueViolation:
        existing = check_idempotency(
            conn, event_id, actor_id=actor_id, transition=transition,
            work_item_id=work_item_id,
        )
        if existing is not None:
            return existing
        raise SubstrateError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {event_id} already exists",
        )

    conn.execute(
        SQL(
            "UPDATE work_items_current SET "
            "last_event_seq = %s, last_event_at = now(), next_event_seq = %s "
            "WHERE work_item_id = %s"
        ),
        [event_seq, event_seq + 1, work_item_id],
    )

    return Event(
        event_id=event_id,
        work_item_id=work_item_id,
        event_seq=event_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        key_id=key_id,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=row["timestamp"],
        transition=transition,
        payload=pl,
        payload_canonical_hash=canonical_hash,
        signature=signature,
        canonical_envelope=canonical_envelope,
        on_behalf_of=on_behalf_of,
    )


def append_transition_event(
    conn: psycopg.Connection,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    transition_name: str,
    new_state: str,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None = None,
    custom_fields_update: dict | None = None,
    release_claim: bool = True,
    on_behalf_of: dict | None = None,
    _prelocked_wi: dict | None = None,
) -> Event:
    key_entry = key_set.active_key()
    key_id = key_entry.key_id

    wi_row = _prelocked_wi if _prelocked_wi is not None else lock_work_item(conn, work_item_id)
    if wi_row is None:
        raise SubstrateError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    existing = check_idempotency(
        conn, event_id, actor_id=actor_id, transition=transition_name,
        work_item_id=work_item_id,
    )
    if existing is not None:
        return existing

    next_seq = wi_row["next_event_seq"]
    check_expected_seq(next_seq, expected_event_seq)

    am = actor_metadata.value if actor_metadata is not None else None

    stored_payload = dict(payload.value) if payload is not None else {}
    if custom_fields_update:
        stored_payload["custom_fields_update"] = custom_fields_update

    Jsonb(stored_payload)

    signature, canonical_hash, canonical_envelope = sign_event(
        event_id=event_id,
        work_item_id=work_item_id,
        actor_id=actor_id,
        transition=transition_name,
        payload=stored_payload,
        key=key_entry.secret,
        on_behalf_of=on_behalf_of,
    )

    event_seq = next_seq
    workflow_name = wi_row["workflow_name"]
    workflow_version = wi_row["workflow_version"]

    try:
        row = conn.execute(
            SQL(
                "INSERT INTO events (event_id, work_item_id, event_seq, actor_id, actor_kind, "
                "actor_metadata, key_id, workflow_name, workflow_version, "
                "transition, payload, payload_canonical_hash, signature, "
                "canonical_envelope, on_behalf_of) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING timestamp"
            ),
            [
                event_id,
                work_item_id,
                event_seq,
                actor_id,
                actor_kind,
                psycopg.types.json.Jsonb(am) if am is not None else None,
                key_id,
                workflow_name,
                workflow_version,
                transition_name,
                psycopg.types.json.Jsonb(stored_payload) if stored_payload is not None else None,
                canonical_hash,
                signature,
                canonical_envelope,
                psycopg.types.json.Jsonb(on_behalf_of) if on_behalf_of is not None else None,
            ],
        ).fetchone()
    except psycopg.errors.UniqueViolation:
        existing = check_idempotency(
            conn, event_id, actor_id=actor_id, transition=transition_name,
            work_item_id=work_item_id,
        )
        if existing is not None:
            return existing
        raise SubstrateError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {event_id} already exists",
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
            "last_event_seq = %s, last_event_at = now(), next_event_seq = %s"
        ) + claim_clear + SQL(" WHERE work_item_id = %s"),
        [
            new_state,
            psycopg.types.json.Jsonb(merged_fields),
            event_seq,
            event_seq + 1,
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
        event_seq=event_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        key_id=key_id,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=row["timestamp"],
        transition=transition_name,
        payload=stored_payload,
        payload_canonical_hash=canonical_hash,
        signature=signature,
        canonical_envelope=canonical_envelope,
        on_behalf_of=on_behalf_of,
    )


def read_events_by_work_item(
    conn: psycopg.Connection,
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
    conn: psycopg.Connection,
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
    params: list = []

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



