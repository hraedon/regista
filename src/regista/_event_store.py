from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from ._contract import Jsonb, check_expected_seq, check_idempotency, check_key_role_policy
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._signing import sign_event
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event

_DUMMY_KEY_ID = "in-memory"
_DUMMY_SIG = b"\x00" * 32
_DUMMY_HASH = b"\x00" * 32


@runtime_checkable
class EventStore(Protocol):
    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int:
        ...

    def lock_global_chain_head(self) -> bytes | None:
        ...

    def find_by_event_id(self, event_id: uuid.UUID) -> Event | None:
        ...

    def append(self, event: Event) -> Event:
        ...

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
        ...


def append_event(
    store: EventStore,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    workflow_name: str,
    workflow_version: int,
    transition: str | None,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None = None,
    key_set: KeySet | None = None,
    on_behalf_of: dict | None = None,
    _key_id: str | None = None,
    entity_kind: str = "work_item",
) -> Event:
    event_seq = store.allocate_seq(work_item_id, entity_kind=entity_kind)

    existing_evt = store.find_by_event_id(event_id)
    existing = check_idempotency(existing_evt, actor_id, transition, work_item_id)
    if existing is not None:
        return existing

    check_expected_seq(event_seq, expected_event_seq)

    am = actor_metadata.value if actor_metadata is not None else None
    pl = payload.value if payload is not None else None

    now = datetime.now(UTC)

    prev_event_hash: bytes | None = None
    if event_seq > 1:
        prev_evts = store.read(work_item_id=work_item_id, limit=1, before_seq=event_seq)
        if prev_evts:
            prev_evt = prev_evts[0]
            if prev_evt.canonical_envelope and prev_evt.signature:
                chain_hash_fn = resolve_hash_function("sha-256")
                prev_event_hash = chain_hash_fn(
                    prev_evt.canonical_envelope + prev_evt.signature
                ).digest()

    prev_global_event_hash = store.lock_global_chain_head()

    if key_set is not None:
        key_entry = key_set.resolve_signing_key(actor_id, key_id=_key_id)
        key_id = key_entry.key_id
        check_key_role_policy(key_entry.role, transition)
        scheme = get_scheme(key_entry.scheme)
        signature, canonical_hash, canonical_envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id=actor_id,
            key_id=key_id,
            event_seq=event_seq,
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            timestamp=now,
            transition=transition,
            payload=pl,
            key=key_entry.secret,
            on_behalf_of=on_behalf_of,
            scheme=scheme,
            prev_event_hash=prev_event_hash,
            prev_global_event_hash=prev_global_event_hash,
            entity_kind=entity_kind,
            hash_alg="sha-256",
        )
        _scheme_id = scheme.scheme_id
    else:
        key_id = _DUMMY_KEY_ID
        signature = _DUMMY_SIG
        canonical_hash = _DUMMY_HASH
        canonical_envelope = _DUMMY_SIG
        _scheme_id = "hmac-sha256"

    evt = Event(
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        entity_id=work_item_id,
        hash_alg="sha-256",
        event_seq=event_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        key_id=key_id,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition,
        payload=pl,
        payload_canonical_hash=canonical_hash,
        signature=signature,
        canonical_envelope=canonical_envelope,
        on_behalf_of=on_behalf_of,
        scheme_id=_scheme_id,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=prev_global_event_hash,
    )

    return store.append(evt)


class InMemoryEventStore:
    def __init__(self) -> None:
        self.events: dict[uuid.UUID, list[Event]] = {}
        self.event_id_index: dict[uuid.UUID, Event] = {}
        self._work_items: dict[uuid.UUID, dict] = {}
        self._entity_seqs: dict[tuple[str, uuid.UUID], dict] = {}
        self._next_global_seq: int = 1
        self._global_seq_by_event_id: dict[uuid.UUID, int] = {}
        self._global_chain_head: bytes | None = None

    def bind(self, work_items: dict[uuid.UUID, dict]) -> None:
        self._work_items = work_items

    def lock_global_chain_head(self) -> bytes | None:
        return self._global_chain_head

    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int:
        if entity_kind == "work_item":
            wi = self._work_items.get(work_item_id)
            if wi is not None:
                return wi["next_event_seq"]
        ent_key = (entity_kind, work_item_id)
        ent = self._entity_seqs.get(ent_key)
        if ent is not None:
            return ent["next_event_seq"]
        self._entity_seqs[ent_key] = {
            "next_event_seq": 1,
            "last_event_seq": 0,
        }
        return 1

    def find_by_event_id(self, event_id: uuid.UUID) -> Event | None:
        return self.event_id_index.get(event_id)

    def append(self, event: Event) -> Event:
        wid = event.work_item_id
        wi = self._work_items.get(wid)
        if wi is not None:
            self.events.setdefault(wid, []).append(event)
            self.event_id_index[event.event_id] = event
            self._global_seq_by_event_id[event.event_id] = self._next_global_seq
            self._next_global_seq += 1
            wi["last_event_seq"] = event.event_seq
            wi["last_event_at"] = event.timestamp
            wi["next_event_seq"] = event.event_seq + 1
            if event.canonical_envelope and event.signature:
                import hashlib

                self._global_chain_head = hashlib.sha256(
                    bytes(event.canonical_envelope) + bytes(event.signature)
                ).digest()
            return event
        ent_key = (getattr(event, "entity_kind", "work_item"), wid)
        ent = self._entity_seqs.setdefault(ent_key, {
            "next_event_seq": 1,
            "last_event_seq": 0,
        })
        self.events.setdefault(wid, []).append(event)
        self.event_id_index[event.event_id] = event
        self._global_seq_by_event_id[event.event_id] = self._next_global_seq
        self._next_global_seq += 1
        ent["last_event_seq"] = event.event_seq
        ent["next_event_seq"] = event.event_seq + 1
        if event.canonical_envelope and event.signature:
            import hashlib

            self._global_chain_head = hashlib.sha256(
                bytes(event.canonical_envelope) + bytes(event.signature)
            ).digest()
        return event

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
        if work_item_id is not None:
            evts = list(self.events.get(work_item_id, []))
            if transition is not None:
                evts = [e for e in evts if e.transition == transition]
            if actor_id is not None:
                evts = [e for e in evts if e.actor_id == actor_id]
            if start is not None and end is not None:
                evts = [e for e in evts if start <= e.timestamp <= end]
            if before_seq is not None:
                evts = [e for e in evts if e.event_seq < before_seq]
                evts.sort(key=lambda e: e.event_seq, reverse=True)
                return list(reversed(evts[:limit]))
            evts.sort(key=lambda e: e.event_seq, reverse=True)
            return list(reversed(evts[:limit]))
        if actor_id is not None:
            evts = [e for el in self.events.values() for e in el]
            evts = [e for e in evts if e.actor_id == actor_id]
            if transition is not None:
                evts = [e for e in evts if e.transition == transition]
            if start is not None and end is not None:
                evts = [e for e in evts if start <= e.timestamp <= end]
            if start is not None and end is not None:
                evts.sort(key=lambda e: (e.timestamp, e.event_seq))
            else:
                evts.sort(key=lambda e: (e.timestamp, e.event_seq), reverse=True)
            return evts[:limit]
        if start is not None and end is not None:
            evts = [e for el in self.events.values() for e in el]
            evts = [e for e in evts if start <= e.timestamp <= end]
            if transition is not None:
                evts = [e for e in evts if e.transition == transition]
            evts.sort(key=lambda e: (e.timestamp, e.event_seq))
            return evts[:limit]
        if transition is not None:
            evts = [e for el in self.events.values() for e in el]
            evts = [e for e in evts if e.transition == transition]
            evts.sort(key=lambda e: (e.timestamp, e.event_seq), reverse=True)
            return evts[:limit]
        evts = [e for el in self.events.values() for e in el]
        evts.sort(key=lambda e: (e.timestamp, e.event_seq), reverse=True)
        return evts[:limit]


class PostgresEventStore:
    _EVENT_FIELDS = (
        "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
        "event_seq, actor_id, actor_kind, "
        "actor_metadata, key_id, workflow_name, workflow_version, "
        "timestamp, transition, payload, payload_canonical_hash, signature, "
        "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, global_seq"
    )

    def __init__(self, conn, key_set: KeySet) -> None:
        self._conn = conn
        self._key_set = key_set
        self._locked_wis: dict[uuid.UUID, dict | None] = {}
        self._prev_global_event_hash: bytes | None = None

    def lock_global_chain_head(self) -> bytes | None:
        from ._events import _lock_global_chain_head

        self._prev_global_event_hash = _lock_global_chain_head(self._conn)
        return self._prev_global_event_hash

    def prepare(
        self,
        work_item_id: uuid.UUID,
        prelocked_wi: dict | None = None,
    ) -> dict | None:
        from ._events import lock_work_item

        wi = prelocked_wi if prelocked_wi is not None else lock_work_item(self._conn, work_item_id)
        self._locked_wis[work_item_id] = wi
        return wi

    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int:
        if entity_kind != "work_item":
            entity_bytes = work_item_id.bytes
            key1 = int.from_bytes(entity_bytes[:8], "big", signed=False)
            key2 = int.from_bytes(entity_bytes[8:], "big", signed=False)
            if key1 >= 2**63:
                key1 -= 2**64
            if key2 >= 2**63:
                key2 -= 2**64
            self._conn.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                [key1, key2],
            )
            row = self._conn.execute(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq "
                "FROM events WHERE entity_kind = %s AND entity_id = %s",
                [entity_kind, work_item_id],
            ).fetchone()
            return row["next_seq"]

        from ._events import lock_work_item

        wi = self._locked_wis.get(work_item_id)
        if wi is None:
            wi = lock_work_item(self._conn, work_item_id)
            self._locked_wis[work_item_id] = wi
        if wi is None:
            raise RegistaError(
                ErrorCode.WORK_ITEM_NOT_FOUND,
                f"Work item {work_item_id} not found",
            )
        return wi["next_event_seq"]

    def find_by_event_id(self, event_id: uuid.UUID) -> Event | None:
        from psycopg.sql import SQL

        from ._events import _row_to_event

        row = self._conn.execute(
            SQL(f"SELECT {self._EVENT_FIELDS} FROM events WHERE event_id = %s"),
            [event_id],
        ).fetchone()
        return _row_to_event(row) if row else None

    def append(self, event: Event) -> Event:
        import psycopg.types.json
        from psycopg.sql import SQL

        am = event.actor_metadata
        pl = event.payload

        try:
            self._conn.execute(
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
                    event.event_id,
                    event.work_item_id,
                    event.entity_kind,
                    event.effective_entity_id,
                    event.hash_alg,
                    event.event_seq,
                    event.actor_id,
                    event.actor_kind,
                    psycopg.types.json.Jsonb(am) if am is not None else None,
                    event.key_id,
                    event.workflow_name,
                    event.workflow_version,
                    event.timestamp,
                    event.transition,
                    psycopg.types.json.Jsonb(pl) if pl is not None else None,
                    event.payload_canonical_hash,
                    event.signature,
                    event.canonical_envelope,
                    psycopg.types.json.Jsonb(
                        event.on_behalf_of
                    ) if event.on_behalf_of is not None else None,
                    event.scheme_id,
                    event.prev_event_hash,
                    event.prev_global_event_hash,
                ],
            )
        except psycopg.errors.UniqueViolation:
            existing = self.find_by_event_id(event.event_id)
            if existing is not None:
                from ._contract import check_idempotency as _contract_check
                match = _contract_check(
                    existing,
                    actor_id=event.actor_id,
                    transition=event.transition,
                    work_item_id=event.work_item_id,
                )
                if match is not None:
                    return match
            raise RegistaError(
                ErrorCode.EVENT_ID_GLOBAL_COLLISION,
                f"event_id {event.event_id} already exists",
            )

        from ._events import _advance_global_chain_head

        if event.canonical_envelope and event.signature:
            new_head = resolve_hash_function("sha-256")(
                bytes(event.canonical_envelope) + bytes(event.signature)
            ).digest()
            _advance_global_chain_head(self._conn, event.event_id, new_head)

        if event.entity_kind == "work_item":
            self._conn.execute(
                SQL(
                    "UPDATE work_items_current SET "
                    "last_event_seq = %s, last_event_at = %s, next_event_seq = %s "
                    "WHERE work_item_id = %s"
                ),
                [event.event_seq, event.timestamp, event.event_seq + 1, event.work_item_id],
            )

        return event

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
        from ._events import read_events_composite

        return read_events_composite(
            self._conn,
            work_item_id=work_item_id,
            actor_id=actor_id,
            start=start,
            end=end,
            transition=transition,
            limit=limit,
            before_seq=before_seq,
        )
