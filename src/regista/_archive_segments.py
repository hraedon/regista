from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._events import _advance_global_chain_head, _lock_global_chain_head
from ._keys import KeySet
from ._signing import sign_event, verify_event
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event

log = structlog.get_logger()

_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
    "event_seq, global_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, "
    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "prev_global_event_hash"
)


def _hash_event(event: Event) -> bytes | None:
    if event.canonical_envelope is None or event.signature is None:
        return None
    hash_fn = resolve_hash_function("sha-256")
    return hash_fn(bytes(event.canonical_envelope) + bytes(event.signature)).digest()


def _hash_event_dict(event: dict[str, Any]) -> bytes | None:
    env = event.get("canonical_envelope")
    sig = event.get("signature")
    if env is None or sig is None:
        return None
    hash_fn = resolve_hash_function("sha-256")
    return hash_fn(bytes(env) + bytes(sig)).digest()


def _verify_seal_event(
    conn: DictConn,
    seal_event_id: uuid.UUID | None,
    key_set: KeySet | None,
) -> bool:
    """Verify the cryptographic signature on the segment's seal event.

    Returns ``False`` if the event is missing, unsigned, or the signature does
    not validate against the key it names.  This is independent of the hash-chain
    checks and ensures the segment row was created by a trusted signer.
    """
    if seal_event_id is None:
        return False

    row = conn.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events WHERE event_id = %s"),
        [seal_event_id],
    ).fetchone()
    if row is None:
        return False

    evt = _row_to_event(row)
    if evt.signature is None or evt.canonical_envelope is None:
        return False

    try:
        key_entry = key_set.get_key(evt.key_id) if key_set else None
    except RegistaError:
        key_entry = None
    if key_entry is None:
        return False

    verify_key = key_entry.secret
    scheme = get_scheme(evt.scheme_id)
    if scheme.scheme_id == "ed25519" and key_entry.public_key:
        verify_key = key_entry.public_key

    return verify_event(
        event_id=evt.event_id,
        work_item_id=evt.work_item_id,
        actor_id=evt.actor_id,
        key_id=evt.key_id,
        event_seq=evt.event_seq,
        workflow_name=evt.workflow_name,
        workflow_version=evt.workflow_version,
        timestamp=evt.timestamp,
        transition=evt.transition,
        payload=evt.payload,
        signature=evt.signature,
        canonical_hash=evt.payload_canonical_hash,
        key=verify_key,
        stored_envelope=evt.canonical_envelope,
        on_behalf_of=evt.on_behalf_of,
        scheme=scheme,
        prev_event_hash=evt.prev_event_hash,
        global_seq=evt.global_seq,
        prev_global_event_hash=evt.prev_global_event_hash,
        entity_kind=evt.entity_kind,
        hash_alg=evt.hash_alg,
        actor_kind=evt.actor_kind,
        actor_metadata=evt.actor_metadata,
    )


def _verify_global_chain(
    events: list[Event],
    anchor_hash: bytes | None = None,
) -> tuple[bool, str, Event | None]:
    """Verify the global hash chain within *events*.

    When *anchor_hash* is ``None``, the chain must start with an event whose
    ``prev_global_event_hash`` is ``None`` (the global genesis).  Otherwise the
    first event (by ``global_seq``) must have ``prev_global_event_hash`` equal
    to *anchor_hash*.

    With terminal-only sealing (Finding 2), the selected events may not form a
    single contiguous global chain — events from non-terminal work-items are
    excluded, creating gaps.  This function handles non-contiguous chains by
    accepting *bridge points*: events whose ``prev_global_event_hash`` does not
    match any event within the set are treated as chain-fragment starts that
    link from outside the segment.

    Returns ``(ok, error, tail)`` where *tail* is the event with the highest
    ``global_seq`` among all chain-fragment tails (or ``None`` if empty).
    """
    if not events:
        return True, "", None

    link_map: dict[str, list[Event]] = {}
    event_hashes: set[bytes] = set()
    for evt in events:
        head = _hash_event(evt)
        if head is not None:
            event_hashes.add(head)
        prev = evt.prev_global_event_hash
        prev_hex = bytes(prev).hex() if prev is not None else ""
        link_map.setdefault(prev_hex, []).append(evt)

    if anchor_hash is not None:
        sorted_by_seq = sorted(events, key=lambda e: e.global_seq or 0)
        first_evt = sorted_by_seq[0]
        if first_evt.prev_global_event_hash is None:
            return False, "anchor expected but first event has null prev_global_event_hash", None
        if not _hmac.compare_digest(bytes(first_evt.prev_global_event_hash), anchor_hash):
            return False, "first event's prev_global_event_hash does not match anchor", None

    entry_points: list[Event] = []
    for evt in events:
        prev = evt.prev_global_event_hash
        if prev is None:
            if anchor_hash is not None:
                continue
            entry_points.append(evt)
        elif bytes(prev) not in event_hashes:
            entry_points.append(evt)

    if not entry_points:
        return False, "no chain entry points found (no genesis or bridge events)", None

    visited: set[uuid.UUID] = set()
    tails: list[Event] = []

    for entry in entry_points:
        current: Event | None = entry
        while current is not None:
            if current.event_id in visited:
                break
            visited.add(current.event_id)
            head = _hash_event(current)
            if head is None:
                return (
                    False,
                    f"event {current.event_id} missing canonical_envelope or signature",
                    None,
                )
            successors = link_map.get(head.hex(), [])
            if not successors:
                tails.append(current)
                break
            if len(successors) > 1:
                return False, f"fork detected at event {current.event_id}", None
            current = successors[0]

    if len(visited) != len(events):
        unvisited = [e for e in events if e.event_id not in visited]
        return (
            False,
            f"{len(unvisited)} event(s) not reachable from any entry point",
            None,
        )

    tails.sort(key=lambda e: e.global_seq or 0, reverse=True)
    return True, "", tails[0] if tails else None


def _verify_work_item_chains(events: list[Event]) -> tuple[bool, str]:
    from collections import defaultdict

    by_entity: dict[tuple[str, uuid.UUID], list[Event]] = defaultdict(list)
    for evt in events:
        entity_key = (evt.entity_kind, evt.effective_entity_id)
        by_entity[entity_key].append(evt)

    for (ek, eid), entity_events in by_entity.items():
        entity_events.sort(key=lambda e: e.event_seq)

        entity_event_hashes: set[bytes] = set()
        for evt in entity_events:
            head = _hash_event(evt)
            if head is not None:
                entity_event_hashes.add(head)

        prev_hash: bytes | None = None
        for i, evt in enumerate(entity_events):
            if i == 0:
                if evt.prev_event_hash is not None:
                    if bytes(evt.prev_event_hash) in entity_event_hashes:
                        return False, (
                            f"first event for {ek}/{eid} references an event "
                            f"within the segment — slice is incomplete"
                        )
            else:
                if evt.prev_event_hash is None:
                    return False, (
                        f"event {evt.event_id} (seq {evt.event_seq}) "
                        f"for {ek}/{eid} has null prev_event_hash"
                    )
                if prev_hash is not None:
                    if not _hmac.compare_digest(prev_hash, bytes(evt.prev_event_hash)):
                        return False, (
                            f"hash chain mismatch for {ek}/{eid} at seq {evt.event_seq}"
                        )
            head = _hash_event(evt)
            prev_hash = head

    return True, ""


def _segment_chain_links(
    prev_head_hash: bytes,
    curr_first_prev_hash: bytes,
    intermediate_events: list[Event],
) -> bool:
    """Return True if ``curr_first_prev_hash`` is reachable from
    ``prev_head_hash`` by walking the global chain through the intermediate
    events.

    Two consecutive segments are NOT adjacent in the global chain: sealing
    inserts a ``segment_sealed`` event (the seal of the earlier segment)
    between them, and any other events created between the two seals sit there
    too. So the linkage check must walk forward from ``prev_head_hash`` (the
    head hash of the earlier segment's last event) through the intermediate
    events until it reaches ``curr_first_prev_hash`` (the
    ``prev_global_event_hash`` of the later segment's first event).

    Direct adjacency (no intermediate events) is the fast path: the hashes
    match exactly. A tampered ``prev_head_hash`` — no event chains from it —
    walks nowhere and correctly returns False.

    Precondition: ``True`` means the segments are linked ONLY if
    ``intermediate_events`` holds the COMPLETE set of events whose
    ``global_seq`` lies strictly between the two segments. If the caller
    supplies an incomplete set (e.g. gap events that were archived into
    ``events_archive`` and therefore omitted), the walk can fall short of
    ``curr_first_prev_hash`` and correctly return False — but that False is
    a false failure of an intact store, not a real break. The caller is
    responsible for supplying every gap event regardless of which table it
    lives in.
    """
    if prev_head_hash == curr_first_prev_hash:
        return True

    by_prev: dict[str, Event] = {}
    for evt in intermediate_events:
        prev = evt.prev_global_event_hash
        if prev is not None:
            by_prev[bytes(prev).hex()] = evt

    target = bytes(curr_first_prev_hash).hex()
    current = by_prev.get(bytes(prev_head_hash).hex())
    visited: set[uuid.UUID] = set()
    while current is not None:
        if current.event_id in visited:
            return False
        visited.add(current.event_id)
        head = _hash_event(current)
        if head is None:
            return False
        if head.hex() == target:
            return True
        current = by_prev.get(head.hex())
    return False


def _row_to_event(row: dict[str, Any]) -> Event:
    return Event(
        event_id=row["event_id"],
        work_item_id=row["work_item_id"],
        entity_kind=row.get("entity_kind", "work_item"),
        entity_id=row.get("entity_id"),
        hash_alg=row.get("hash_alg", "sha-256"),
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
        scheme_id=row.get("scheme_id", "hmac-sha256"),
        prev_event_hash=(bytes(row["prev_event_hash"]) if row.get("prev_event_hash") else None),
        global_seq=row.get("global_seq"),
        prev_global_event_hash=(
            bytes(row["prev_global_event_hash"]) if row.get("prev_global_event_hash") else None
        ),
    )


def seal_segment(
    mgr: ConnectionManager,
    key_set: KeySet,
    before_timestamp: datetime,
    *,
    dry_run: bool = False,
    actor_id: str = "system",
    archive_path: str | None = None,
) -> dict[str, Any]:
    with mgr.transaction() as conn:
        conn.execute(SQL("LOCK TABLE event_segments IN EXCLUSIVE MODE"))

        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM events e "
                "WHERE e.timestamp < %s "
                "AND e.entity_kind != 'segment' "
                "AND e.work_item_id IN ("
                "  SELECT wic.work_item_id FROM work_items_current wic "
                "  JOIN workflow_registry wr "
                "    ON wr.workflow_name = wic.workflow_name "
                "    AND wr.version = wic.workflow_version "
                "  WHERE wic.current_state IN ("
                "    SELECT jsonb_array_elements_text(wr.definition -> 'terminal_states')"
                "  ) "
                "  AND wic.work_item_id IN ("
                "    SELECT work_item_id FROM events "
                "    GROUP BY work_item_id HAVING max(timestamp) < %s"
                "  )"
                ") "
                "AND e.work_item_id NOT IN ("
                "  SELECT UNNEST(work_item_ids) FROM event_segments"
                "  WHERE work_item_ids != '{}'"
                ") "
                "ORDER BY e.global_seq"
            ),
            [before_timestamp, before_timestamp],
        ).fetchall()

        if not rows:
            return {
                "segment_id": None,
                "event_count": 0,
                "first_global_seq": None,
                "last_global_seq": None,
                "head_hash": None,
                "dry_run": dry_run,
            }

        events = [_row_to_event(r) for r in rows]

        if not events:
            return {
                "segment_id": None,
                "event_count": 0,
                "first_global_seq": None,
                "last_global_seq": None,
                "head_hash": None,
                "dry_run": dry_run,
            }

        first_event = events[0]
        first_event_prev_hash = first_event.prev_global_event_hash

        ok_global, err_global, tail_event = _verify_global_chain(
            events, anchor_hash=first_event_prev_hash,
        )
        if not ok_global:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Global chain verification failed for segment: {err_global}",
            )
        if tail_event is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "Global chain verification produced no tail event",
            )

        ok_wi, err_wi = _verify_work_item_chains(events)
        if not ok_wi:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Work-item chain verification failed for segment: {err_wi}",
            )

        last_event = tail_event
        head_hash = _hash_event(last_event)
        if head_hash is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "Tail event in segment missing canonical_envelope or signature",
            )

        work_item_ids = sorted(set(
            e.work_item_id for e in events if e.entity_kind != "segment"
        ))
        event_ids = [e.event_id for e in events]

        segment_id = uuid.uuid4()
        seal_event_id = uuid.uuid4()
        now = datetime.now(UTC)

        seal_payload = {
            "segment_id": str(segment_id),
            "first_global_seq": first_event.global_seq,
            "last_global_seq": last_event.global_seq,
            "first_event_id": str(first_event.event_id),
            "last_event_id": str(last_event.event_id),
            "event_count": len(events),
            "min_timestamp": first_event.timestamp.isoformat(),
            "max_timestamp": last_event.timestamp.isoformat(),
            "head_hash": head_hash.hex(),
            "first_event_prev_hash": (
                first_event_prev_hash.hex() if first_event_prev_hash else None
            ),
            "archive_path": archive_path,
            "work_item_ids": [str(wi) for wi in work_item_ids],
        }

        key_entry = key_set.active_key()
        scheme = get_scheme(key_entry.scheme)

        prev_global_event_hash = _lock_global_chain_head(conn)

        seal_signature, canonical_hash, canonical_envelope = sign_event(
            event_id=seal_event_id,
            work_item_id=segment_id,
            actor_id=actor_id,
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="",
            workflow_version=0,
            timestamp=now,
            transition="segment_sealed",
            payload=seal_payload,
            key=key_entry.secret,
            scheme=scheme,
            prev_event_hash=None,
            prev_global_event_hash=prev_global_event_hash,
            entity_kind="segment",
            hash_alg="sha-256",
            actor_kind="system",
            actor_metadata=None,
        )

        if dry_run:
            return {
                "segment_id": str(segment_id),
                "event_count": len(events),
                "first_global_seq": first_event.global_seq,
                "last_global_seq": last_event.global_seq,
                "first_event_id": str(first_event.event_id),
                "last_event_id": str(last_event.event_id),
                "head_hash": head_hash.hex(),
                "first_event_prev_hash": (
                    first_event_prev_hash.hex() if first_event_prev_hash else None
                ),
                "seal_event_id": str(seal_event_id),
                "seal_signature": seal_signature.hex(),
                "dry_run": True,
                "archive_path": archive_path,
                "work_item_ids": [str(wi) for wi in work_item_ids],
            }

        conn.execute(
            SQL(
                "INSERT INTO event_segments "
                "(segment_id, first_global_seq, last_global_seq, "
                "first_event_id, last_event_id, first_event_prev_hash, "
                "head_hash, event_count, min_timestamp, max_timestamp, "
                "seal_signature, seal_event_id, archive_path, archived, created_at, "
                "work_item_ids, event_ids) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s, %s, %s)"
            ),
            [
                segment_id,
                first_event.global_seq,
                last_event.global_seq,
                first_event.event_id,
                last_event.event_id,
                first_event_prev_hash,
                head_hash,
                len(events),
                first_event.timestamp,
                last_event.timestamp,
                seal_signature,
                seal_event_id,
                archive_path,
                now,
                work_item_ids,
                event_ids,
            ],
        )

        import psycopg.types.json as _pg_json

        conn.execute(
            SQL(
                "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                "event_seq, actor_id, actor_kind, "
                "actor_metadata, key_id, workflow_name, workflow_version, "
                "timestamp, transition, payload, payload_canonical_hash, signature, "
                "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
                "prev_global_event_hash) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                "%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            [
                seal_event_id,
                segment_id,
                "segment",
                segment_id,
                "sha-256",
                1,
                actor_id,
                "system",
                None,
                key_entry.key_id,
                "",
                0,
                now,
                "segment_sealed",
                _pg_json.Jsonb(seal_payload),
                canonical_hash,
                seal_signature,
                canonical_envelope,
                None,
                scheme.scheme_id,
                None,
                prev_global_event_hash,
            ],
        )

        new_head_hash = resolve_hash_function("sha-256")(
            bytes(canonical_envelope) + bytes(seal_signature)
        ).digest()
        _advance_global_chain_head(conn, seal_event_id, new_head_hash)

        log.info(
            "archive.segment_sealed",
            segment_id=str(segment_id),
            event_count=len(events),
            first_global_seq=first_event.global_seq,
            last_global_seq=last_event.global_seq,
            dry_run=dry_run,
        )

        return {
            "segment_id": str(segment_id),
            "event_count": len(events),
            "first_global_seq": first_event.global_seq,
            "last_global_seq": last_event.global_seq,
            "first_event_id": str(first_event.event_id),
            "last_event_id": str(last_event.event_id),
            "head_hash": head_hash.hex(),
            "first_event_prev_hash": (
                first_event_prev_hash.hex() if first_event_prev_hash else None
            ),
            "seal_event_id": str(seal_event_id),
            "seal_signature": seal_signature.hex(),
            "dry_run": False,
            "archive_path": archive_path,
            "work_item_ids": [str(wi) for wi in work_item_ids],
        }


def verify_segment(
    mgr: ConnectionManager,
    segment_id: uuid.UUID,
    key_set: KeySet | None = None,
) -> dict[str, Any]:
    with mgr.transaction() as conn:
        seg_row = conn.execute(
            SQL(
                "SELECT segment_id, first_global_seq, last_global_seq, "
                "first_event_id, last_event_id, first_event_prev_hash, "
                "head_hash, event_count, min_timestamp, max_timestamp, "
                "seal_signature, seal_event_id, archive_path, archived, created_at, "
                "work_item_ids, event_ids "
                "FROM event_segments WHERE segment_id = %s"
            ),
            [segment_id],
        ).fetchone()

        if seg_row is None:
            raise RegistaError(
                ErrorCode.SEGMENT_NOT_FOUND,
                f"Segment {segment_id} not found",
            )

        # Read the segment's events from BOTH tables. Archival moves
        # work-item events to events_archive per work-item, so a segment's
        # events can be split across the two tables (and the segment's
        # `archived` flag is set at seal time, not updated by archival, so
        # it cannot be relied on to pick a single table). The tables share
        # an identical schema; archive_events moves rows (INSERT+DELETE), so
        # an event_id lives in exactly one table and UNION ALL cannot
        # produce duplicates.
        stored_event_ids = seg_row["event_ids"]
        if stored_event_ids:
            rows = conn.execute(
                SQL(
                    f"SELECT {_EVENT_FIELDS} FROM events "
                    "WHERE event_id = ANY(%s) "
                    "UNION ALL "
                    f"SELECT {_EVENT_FIELDS} FROM events_archive "
                    "WHERE event_id = ANY(%s) "
                    "ORDER BY global_seq"
                ),
                [stored_event_ids, stored_event_ids],
            ).fetchall()
        else:
            rows = conn.execute(
                SQL(
                    f"SELECT {_EVENT_FIELDS} FROM events "
                    "WHERE global_seq >= %s AND global_seq <= %s "
                    "UNION ALL "
                    f"SELECT {_EVENT_FIELDS} FROM events_archive "
                    "WHERE global_seq >= %s AND global_seq <= %s "
                    "ORDER BY global_seq"
                ),
                [
                    seg_row["first_global_seq"], seg_row["last_global_seq"],
                    seg_row["first_global_seq"], seg_row["last_global_seq"],
                ],
            ).fetchall()

        events = [_row_to_event(r) for r in rows]

        anchor = (
            bytes(seg_row["first_event_prev_hash"])
            if seg_row["first_event_prev_hash"]
            else None
        )
        ok_global, err_global, tail_event = _verify_global_chain(
            events, anchor_hash=anchor,
        )
        ok_wi, err_wi = _verify_work_item_chains(events)

        recomputed_head: bytes | None = None
        if tail_event is not None:
            recomputed_head = _hash_event(tail_event)

        head_matches = (
            recomputed_head is not None
            and _hmac.compare_digest(bytes(recomputed_head), bytes(seg_row["head_hash"]))
        )

        seal_event_verified = _verify_seal_event(conn, seg_row["seal_event_id"], key_set)

        verified = (
            ok_global
            and ok_wi
            and head_matches
            and seal_event_verified
            and len(events) == seg_row["event_count"]
        )

        return {
            "segment_id": str(seg_row["segment_id"]),
            "verified": verified,
            "event_count": len(events),
            "expected_count": seg_row["event_count"],
            "global_chain_ok": ok_global,
            "global_chain_error": err_global if not ok_global else None,
            "work_item_chain_ok": ok_wi,
            "work_item_chain_error": err_wi if not ok_wi else None,
            "head_hash_matches": head_matches,
            "stored_head_hash": bytes(seg_row["head_hash"]).hex(),
            "recomputed_head_hash": recomputed_head.hex() if recomputed_head else None,
            "first_global_seq": seg_row["first_global_seq"],
            "last_global_seq": seg_row["last_global_seq"],
            "archived": seg_row["archived"],
            "seal_event_id": str(seg_row["seal_event_id"]) if seg_row["seal_event_id"] else None,
            "seal_event_verified": seal_event_verified,
        }


def list_segments(
    mgr: ConnectionManager,
    archived: bool | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    with mgr.transaction() as conn:
        if archived is not None:
            rows = conn.execute(
                SQL(
                    "SELECT segment_id, first_global_seq, last_global_seq, "
                    "first_event_id, last_event_id, first_event_prev_hash, "
                    "head_hash, event_count, min_timestamp, max_timestamp, "
                    "seal_signature, seal_event_id, archive_path, archived, created_at, "
                    "work_item_ids "
                    "FROM event_segments WHERE archived = %s "
                    "ORDER BY first_global_seq LIMIT %s"
                ),
                [archived, limit],
            ).fetchall()
        else:
            rows = conn.execute(
                SQL(
                    "SELECT segment_id, first_global_seq, last_global_seq, "
                    "first_event_id, last_event_id, first_event_prev_hash, "
                    "head_hash, event_count, min_timestamp, max_timestamp, "
                    "seal_signature, seal_event_id, archive_path, archived, created_at, "
                    "work_item_ids "
                    "FROM event_segments ORDER BY first_global_seq LIMIT %s"
                ),
                [limit],
            ).fetchall()

        result: list[dict[str, Any]] = []
        for r in rows:
            result.append({
                "segment_id": str(r["segment_id"]),
                "first_global_seq": r["first_global_seq"],
                "last_global_seq": r["last_global_seq"],
                "first_event_id": str(r["first_event_id"]),
                "last_event_id": str(r["last_event_id"]),
                "first_event_prev_hash": (
                    bytes(r["first_event_prev_hash"]).hex()
                    if r["first_event_prev_hash"] else None
                ),
                "head_hash": bytes(r["head_hash"]).hex(),
                "event_count": r["event_count"],
                "min_timestamp": r["min_timestamp"].isoformat(),
                "max_timestamp": r["max_timestamp"].isoformat(),
                "seal_event_id": str(r["seal_event_id"]) if r["seal_event_id"] else None,
                "archive_path": r["archive_path"],
                "archived": r["archived"],
                "created_at": r["created_at"].isoformat(),
                "work_item_ids": (
                    [str(wi) for wi in r["work_item_ids"]]
                    if r["work_item_ids"] else []
                ),
            })
        return result


def verify_archive_chain(
    mgr: ConnectionManager,
    key_set: KeySet | None = None,
) -> dict[str, Any]:
    with mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                "SELECT segment_id, first_global_seq, last_global_seq, "
                "first_event_id, last_event_id, first_event_prev_hash, "
                "head_hash, event_count, min_timestamp, max_timestamp, "
                "seal_signature, seal_event_id, archive_path, archived, created_at, "
                "work_item_ids, event_ids "
                "FROM event_segments ORDER BY first_global_seq"
            ),
        ).fetchall()

        if not rows:
            return {
                "verified": True,
                "segment_count": 0,
                "chain_breaks": [],
                "segment_results": [],
            }

        segment_results: list[dict[str, Any]] = []
        chain_breaks: list[dict[str, Any]] = []

        for r in rows:
            seg_id = r["segment_id"]
            seg_result = verify_segment(mgr, seg_id, key_set)
            segment_results.append(seg_result)
            if not seg_result["verified"]:
                chain_breaks.append({
                    "segment_id": str(seg_id),
                    "type": "segment_verification_failed",
                    "detail": (
                        f"global_chain_ok={seg_result['global_chain_ok']}, "
                        f"work_item_chain_ok={seg_result['work_item_chain_ok']}, "
                        f"head_hash_matches={seg_result['head_hash_matches']}, "
                        f"seal_event_verified={seg_result['seal_event_verified']}"
                    ),
                })

        for i in range(1, len(rows)):
            prev_seg = rows[i - 1]
            curr_seg = rows[i]

            prev_head = prev_seg["head_hash"]
            curr_first_prev = curr_seg["first_event_prev_hash"]

            if prev_head is None:
                continue
            if curr_first_prev is None:
                chain_breaks.append({
                    "segment_id": str(curr_seg["segment_id"]),
                    "type": "missing_first_event_prev_hash",
                    "detail": (
                        f"segment {curr_seg['segment_id']} has no "
                        f"first_event_prev_hash but is not the first segment"
                    ),
                })
                continue

            # Consecutive segments are not adjacent in the global chain: the
            # seal event of the earlier segment (and any other events created
            # between the two seals) sits between them. Fetch those
            # intermediate events and walk the chain through them instead of
            # comparing the boundary hashes directly (WI-249).
            prev_last = prev_seg["last_global_seq"]
            curr_first = curr_seg["first_global_seq"]
            intermediate: list[Event] = []
            if prev_last is not None and curr_first is not None:
                # The gap between two sealed segments can contain work-item
                # events that were archived after the segments were sealed
                # (the inter-segment seal event itself stays in `events`
                # because entity_kind='segment'). Read from BOTH tables so
                # the chain walk sees the complete gap event set. The tables
                # share an identical schema and an event_id lives in exactly
                # one table, so UNION ALL cannot produce duplicates.
                gap_rows = conn.execute(
                    SQL(
                        f"SELECT {_EVENT_FIELDS} FROM events "
                        "WHERE global_seq > %s AND global_seq < %s "
                        "UNION ALL "
                        f"SELECT {_EVENT_FIELDS} FROM events_archive "
                        "WHERE global_seq > %s AND global_seq < %s "
                        "ORDER BY global_seq"
                    ),
                    [prev_last, curr_first, prev_last, curr_first],
                ).fetchall()
                intermediate = [_row_to_event(r) for r in gap_rows]

            if not _segment_chain_links(
                bytes(prev_head), bytes(curr_first_prev), intermediate
            ):
                chain_breaks.append({
                    "segment_id": str(curr_seg["segment_id"]),
                    "type": "chain_link_mismatch",
                    "detail": (
                        f"head_hash of segment {prev_seg['segment_id']} "
                        f"does not link to first_event_prev_hash of "
                        f"segment {curr_seg['segment_id']} through the "
                        f"inter-segment events"
                    ),
                })

        verified = len(chain_breaks) == 0 and all(s["verified"] for s in segment_results)

        return {
            "verified": verified,
            "segment_count": len(rows),
            "chain_breaks": chain_breaks,
            "segment_results": segment_results,
        }
