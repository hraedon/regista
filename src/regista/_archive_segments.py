from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import UTC, datetime

import psycopg
import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager
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


def _hash_event_dict(event: dict) -> bytes | None:
    env = event.get("canonical_envelope")
    sig = event.get("signature")
    if env is None or sig is None:
        return None
    hash_fn = resolve_hash_function("sha-256")
    return hash_fn(bytes(env) + bytes(sig)).digest()


def _verify_seal_event(
    conn: psycopg.Connection,
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
    )


def _verify_global_chain(
    events: list[Event],
    anchor_hash: bytes | None = None,
) -> tuple[bool, str, Event | None]:
    """Verify that *events* form a single chain starting from *anchor_hash*.

    If *anchor_hash* is ``None``, the chain must start with an event whose
    ``prev_global_event_hash`` is ``None`` (the global genesis).  Otherwise it
    must start with the one event whose ``prev_global_event_hash`` equals
    *anchor_hash*.  Returns the chain-tail event so callers can use the real
    chain end rather than an arbitrary ordering.
    """
    if not events:
        return True, "", None

    link_map: dict[str, list[Event]] = {}
    heads: list[Event] = []
    for evt in events:
        prev = evt.prev_global_event_hash
        prev_hex = bytes(prev).hex() if prev is not None else ""
        link_map.setdefault(prev_hex, []).append(evt)

        if anchor_hash is None:
            if prev is None:
                heads.append(evt)
        else:
            if prev is not None and _hmac.compare_digest(bytes(prev), anchor_hash):
                heads.append(evt)

    if not heads:
        return False, "no event chains from the given anchor", None
    if len(heads) > 1:
        return False, f"expected one chain start, found {len(heads)} forks", None

    current = heads[0]
    visited: set[uuid.UUID] = set()

    while True:
        if current.event_id in visited:
            return False, f"cycle detected at event {current.event_id}", None
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
            break
        current = successors[0]

    if len(visited) != len(events):
        unvisited = [e for e in events if e.event_id not in visited]
        return (
            False,
            f"{len(unvisited)} event(s) not reachable from chain start",
            None,
        )

    return True, "", current


def _verify_work_item_chains(events: list[Event]) -> tuple[bool, str]:
    from collections import defaultdict

    by_entity: dict[tuple[str, uuid.UUID], list[Event]] = defaultdict(list)
    for evt in events:
        entity_key = (evt.entity_kind, evt.effective_entity_id)
        by_entity[entity_key].append(evt)

    for (ek, eid), entity_events in by_entity.items():
        entity_events.sort(key=lambda e: e.event_seq)
        prev_hash: bytes | None = None
        for i, evt in enumerate(entity_events):
            if i == 0:
                if evt.prev_event_hash is not None:
                    return False, (
                        f"first event for {ek}/{eid} has non-null prev_event_hash"
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


def _row_to_event(row: dict) -> Event:
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
) -> dict:
    with mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM events "
                "WHERE timestamp < %s ORDER BY global_seq"
            ),
            [before_timestamp],
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

        # Skip events already covered by an existing segment.  This keeps
        # successive seals from producing overlapping ranges.  Note: this is
        # best-effort when chain order and global_seq order diverge; see
        # docs/retention.md for the operational trade-off.
        max_seg_row = conn.execute(
            SQL("SELECT COALESCE(MAX(last_global_seq), 0) AS m FROM event_segments")
        ).fetchone()
        max_last_global_seq = max_seg_row["m"] if max_seg_row else 0
        events = [
            e for e in events
            if e.global_seq is not None and e.global_seq > max_last_global_seq
        ]

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
            }

        conn.execute(
            SQL(
                "INSERT INTO event_segments "
                "(segment_id, first_global_seq, last_global_seq, "
                "first_event_id, last_event_id, first_event_prev_hash, "
                "head_hash, event_count, min_timestamp, max_timestamp, "
                "seal_signature, seal_event_id, archive_path, archived, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s)"
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
        }


def verify_segment(
    mgr: ConnectionManager,
    segment_id: uuid.UUID,
    key_set: KeySet | None = None,
) -> dict:
    with mgr.transaction() as conn:
        seg_row = conn.execute(
            SQL(
                "SELECT segment_id, first_global_seq, last_global_seq, "
                "first_event_id, last_event_id, first_event_prev_hash, "
                "head_hash, event_count, min_timestamp, max_timestamp, "
                "seal_signature, seal_event_id, archive_path, archived, created_at "
                "FROM event_segments WHERE segment_id = %s"
            ),
            [segment_id],
        ).fetchone()

        if seg_row is None:
            raise RegistaError(
                ErrorCode.SEGMENT_NOT_FOUND,
                f"Segment {segment_id} not found",
            )

        table_name = "events_archive" if seg_row["archived"] else "events"

        rows = conn.execute(
            SQL(
                f"SELECT {_EVENT_FIELDS} FROM {table_name} "
                "WHERE global_seq >= %s AND global_seq <= %s "
                "ORDER BY global_seq"
            ),
            [seg_row["first_global_seq"], seg_row["last_global_seq"]],
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
) -> list[dict]:
    with mgr.transaction() as conn:
        if archived is not None:
            rows = conn.execute(
                SQL(
                    "SELECT segment_id, first_global_seq, last_global_seq, "
                    "first_event_id, last_event_id, first_event_prev_hash, "
                    "head_hash, event_count, min_timestamp, max_timestamp, "
                    "seal_signature, seal_event_id, archive_path, archived, created_at "
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
                    "seal_signature, seal_event_id, archive_path, archived, created_at "
                    "FROM event_segments ORDER BY first_global_seq LIMIT %s"
                ),
                [limit],
            ).fetchall()

        result: list[dict] = []
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
            })
        return result
