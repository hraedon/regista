from __future__ import annotations

import dataclasses
import hashlib
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, cast, runtime_checkable

from ._connection import DictConn
from ._contract import (
    _RESERVED_TRANSITIONS,
    Jsonb,
    check_expected_seq,
    check_idempotency,
    check_key_role_policy,
    validate_actor_metadata,
    validate_delegation_chain,
    validate_entity_kind,
    validate_json_safe_value,
)
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._signing import sign_event
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ._in_memory_v6 import InMemoryV6ConnectionManager, InMemoryV6Rows

_DUMMY_KEY_ID = "in-memory"
_DUMMY_SIG = b"\x00" * 32
_DUMMY_HASH = b"\x00" * 32


@runtime_checkable
class EventStore(Protocol):
    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int: ...

    def lock_global_chain_head(self) -> bytes | None: ...

    def admit_legacy_append(self) -> bytes | None: ...

    def check_legacy_append(self) -> None: ...

    def v6_epoch_open(self) -> bool: ...

    def append_v6(self, request: V6AppendRequest) -> Event: ...

    def find_by_event_id(self, event_id: uuid.UUID) -> Event | None: ...

    def append(self, event: Event) -> Event: ...

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
    ) -> list[Event]: ...


@dataclasses.dataclass(frozen=True)
class V6AppendRequest:
    """What the legacy call signature carries, translated for the v6 writer.

    A dataclass rather than a long kwargs list so the EventStore protocol stays
    readable and so the legacy->v6 translation happens in exactly one place, where it
    can be argued rather than assumed.
    """

    work_item_id: uuid.UUID
    entity_kind: str
    actor_id: str
    actor_kind: str
    actor_metadata: dict[str, Any] | None
    transition: str
    payload: dict[str, Any] | None
    event_id: uuid.UUID
    workflow_name: str | None
    workflow_version: int | None
    expected_event_seq: int | None
    key_id: str | None


def _v6_request(
    *,
    work_item_id: uuid.UUID,
    entity_kind: str,
    actor_id: str,
    actor_kind: str,
    actor_metadata: dict[str, Any] | None,
    workflow_name: str,
    workflow_version: int,
    transition: str | None,
    payload: dict[str, Any] | None,
    event_id: uuid.UUID,
    expected_event_seq: int | None,
    on_behalf_of: dict[str, Any] | None,
    key_id: str | None,
) -> V6AppendRequest:
    """Translate the legacy append signature into the v6 one, or refuse.

    Two translations, both deliberate and both confined to this function:

    **The ``""`` / ``0`` workflow sentinel becomes ``None``.** In the v1-v5 vocabulary
    those columns were ``NOT NULL``, so ``""``/``0`` was the only way to spell "this
    event is not evaluated against a workflow". In v6 that spelling is
    ``workflow: null`` and the sentinel is refused, because the envelope would *sign*
    the falsehood (``V6-ENVELOPE.md`` §1.6). Translating here — at the one boundary
    where the old vocabulary is being read — is migration. The v6 writer keeps
    refusing the sentinel for direct callers, which is what stops this from becoming a
    silent normalisation everywhere.

    **``on_behalf_of`` is refused, not dropped.** v6 has no such field at all (§1.5,
    "Historical ``on_behalf_of`` is not authorization"). Silently discarding it would
    lose a signed assertion the caller believed it was recording; the caller has to
    move to ``authorization.credentials``, and a named refusal is how it finds out.
    """

    if on_behalf_of is not None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "on_behalf_of has no v6 home and is not silently dropped: v6 carries "
            "delegation as authorization.credentials, and a historical on_behalf_of "
            "is reported as legacy_delegation_assertion, never as verified delegation "
            "(V6-ENVELOPE.md §1.5)",
            detail={"reason": "on_behalf_of_has_no_v6_field"},
        )
    if transition is None or not str(transition).strip():
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "every v6 event carries a non-empty transition; there are no "
            "transitionless v6 events in 0.6.0 (RECONCILIATION.md Resolution 3)",
            detail={"reason": "transition_empty"},
        )
    has_workflow = bool(workflow_name) and bool(workflow_version)
    return V6AppendRequest(
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        transition=str(transition),
        payload=payload,
        event_id=event_id,
        workflow_name=workflow_name if has_workflow else None,
        workflow_version=workflow_version if has_workflow else None,
        expected_event_seq=expected_event_seq,
        key_id=key_id,
    )


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
    on_behalf_of: dict[str, Any] | None = None,
    _key_id: str | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
) -> Event:
    # The epoch fork. Before genesis this raises GENESIS_REQUIRED exactly as it did
    # on main — which is what keeps every epoch_blocked manifest entry's recorded
    # failure form true for a project that has not opened an epoch. Once genesis has
    # opened the epoch, the append goes through the v6 writer instead of being
    # refused with V6_EPOCH_OPEN.
    if store.v6_epoch_open():
        return store.append_v6(
            _v6_request(
                work_item_id=work_item_id,
                entity_kind=entity_kind,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=actor_metadata.value if actor_metadata is not None else None,
                workflow_name=workflow_name,
                workflow_version=workflow_version,
                transition=transition,
                payload=payload.value if payload is not None else None,
                event_id=event_id,
                expected_event_seq=expected_event_seq,
                on_behalf_of=on_behalf_of,
                key_id=_key_id,
            )
        )
    store.check_legacy_append()
    am = actor_metadata.value if actor_metadata is not None else None
    validate_actor_metadata(am)
    validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
    validate_entity_kind(entity_kind)
    event_seq = store.allocate_seq(work_item_id, entity_kind=entity_kind)

    existing_evt = store.find_by_event_id(event_id)
    _idem_payload = None if transition in _RESERVED_TRANSITIONS else (
        payload.value if payload is not None else None
    )
    existing = check_idempotency(
        existing_evt, actor_id, transition, work_item_id,
        payload=_idem_payload,
    )
    if existing is not None:
        return existing

    check_expected_seq(event_seq, expected_event_seq)

    previous_global_event_hash = store.admit_legacy_append()

    pl = payload.value if payload is not None else None
    if on_behalf_of is not None:
        validate_json_safe_value(on_behalf_of, "on_behalf_of")

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
            prev_global_event_hash=previous_global_event_hash,
            entity_kind=entity_kind,
            hash_alg=hash_alg,
            actor_kind=actor_kind,
            actor_metadata=am,
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
        hash_alg=hash_alg,
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
        prev_global_event_hash=previous_global_event_hash,
    )

    return store.append(evt)


class InMemoryEventStore:
    """In-process event store for tests and local development.

    Single-threaded contract: unlike the Postgres store (which serializes
    global-chain appends via the `event_chain_head` FOR UPDATE row lock plus the
    genesis sentinel), this store has no real cross-call lock. `lock_global_chain_head`
    is a plain read and `append` does a non-atomic read-modify-write of
    `_global_chain_head` / `_next_global_seq`. Concurrent use from multiple
    threads can therefore still produce the genesis race that migration 035
    closes for Postgres. Do not use InMemoryRegista from multiple threads.

    Since WI-287 this store also backs a real v6 epoch: `v6_rows` holds
    `project_identity` and the chain-head sentinel, and `_in_memory_v6` exposes
    them through a connection-shaped facade so `_genesis` and `_v6_writer` run
    unmodified over them. The single-threaded contract above is exactly the half
    of `SUITE-RECONCILIATION.md` §2.3(a) that stays Postgres-only — locking,
    rollback, persistence and concurrency are refused by name
    (`PARITY_BOUNDARY_POSTGRES_ONLY`) rather than faked, so an in-memory pass
    cannot satisfy a Postgres-gated acceptance criterion.
    """

    def __init__(self) -> None:
        self.events: dict[uuid.UUID, list[Event]] = {}
        self.event_id_index: dict[uuid.UUID, Event] = {}
        self._work_items: dict[uuid.UUID, dict[str, Any]] = {}
        self._entity_seqs: dict[tuple[str, uuid.UUID], dict[str, Any]] = {}
        self._next_global_seq: int = 1
        self._global_seq_by_event_id: dict[uuid.UUID, int] = {}
        self._global_chain_head: bytes | None = None
        self._v6_rows: InMemoryV6Rows | None = None
        self._key_set: KeySet | None = None

    def bind(self, work_items: dict[uuid.UUID, dict[str, Any]]) -> None:
        self._work_items = work_items

    # -- v6 epoch (WI-287 / SUITE-RECONCILIATION.md §2.3(a)) ----------------

    @property
    def v6_rows(self) -> InMemoryV6Rows:
        """The v6 relations (``project_identity``, ``event_chain_head``).

        Created on first use rather than in ``__init__`` so a legacy-only
        in-memory store carries no v6 state at all, and so importing the v6
        facade stays lazy.
        """
        if self._v6_rows is None:
            from ._in_memory_v6 import InMemoryV6Rows

            self._v6_rows = InMemoryV6Rows(self)
        return self._v6_rows

    def v6_epoch_open(self) -> bool:
        """True once an in-memory v6 genesis has recorded ``project_identity``.

        A **method**, not a property, because ``EventStore`` declares it as one and
        the legacy funnel calls ``store.v6_epoch_open()``. The two branches of this
        work were written independently — P1.7 declared the protocol member, WI-287
        implemented the state behind it as a property — and a property under a
        method-shaped protocol is not a type error at either call site: the funnel's
        ``store.v6_epoch_open()`` would call the *bool*, and the internal
        ``if self.v6_epoch_open`` would test a bound method for truthiness, which is
        always true. Both were observed on the merge. One shape, asserted by
        ``TestInMemoryGenesis`` and ``TestParityBoundary``.
        """
        return self._v6_rows is not None and self._v6_rows.project_identity is not None

    @property
    def v6_manager(self) -> InMemoryV6ConnectionManager:
        """A connection manager over this store's v6 relations.

        Stateless over ``v6_rows`` (the state lives there), so the handle's ``_mgr``
        and this one are interchangeable views of the same relations rather than two
        competing transaction scopes.
        """
        from ._in_memory_v6 import InMemoryV6ConnectionManager

        return InMemoryV6ConnectionManager(self.v6_rows)

    def all_events(self) -> list[Event]:
        """Every stored event, for the v6 row projection."""
        return [event for bucket in self.events.values() for event in bucket]

    def append_v6_row(self, event: Event) -> int:
        """Store one v6 event and return its assigned ``global_seq``.

        Deliberately separate from :meth:`append`, which advances the global
        chain head with the **v5** ``sha256(envelope || signature)`` formula. A v6
        append's head is ``compute_v6_event_hash`` and is advanced explicitly by
        the writer through ``_advance_global_chain_head``; reusing :meth:`append`
        would silently fork the chain at event 2 while every row still looked
        well-formed — the exact failure ``TestPostgresOnly`` pins for Postgres.
        """
        seq = self._next_global_seq
        self._next_global_seq += 1
        event = dataclasses.replace(event, global_seq=seq)
        self.events.setdefault(event.work_item_id, []).append(event)
        self.event_id_index[event.event_id] = event
        self._global_seq_by_event_id[event.event_id] = seq
        wi = self._work_items.get(event.work_item_id)
        if wi is not None:
            wi["last_event_seq"] = event.event_seq
            wi["last_event_at"] = event.timestamp
            wi["next_event_seq"] = event.event_seq + 1
        else:
            ent = self._entity_seqs.setdefault(
                (event.entity_kind, event.work_item_id),
                {"next_event_seq": 1, "last_event_seq": 0},
            )
            ent["last_event_seq"] = event.event_seq
            ent["next_event_seq"] = event.event_seq + 1
        return seq

    def lock_global_chain_head(self) -> bytes | None:
        return self._global_chain_head

    def _refuse_legacy_append(self) -> NoReturn:
        """Mirror ``_genesis.check_legacy_append``: refuse on BOTH sides of genesis.

        The two doors are exclusive on this backend for the same reason they are
        on Postgres (``EPOCH-RESET.md`` §5.1): before genesis a legacy append has
        no epoch to belong to, and after genesis it would create a silent v5/v6
        mixed region. The pre-genesis code and message are unchanged from the
        original unconditional refusal, because the epoch-blocked manifest pins
        that exact refusal form for 217 nodes (``SUITE-RECONCILIATION.md`` §2.1;
        217 is the causally-measured figure — see NOTES-WI287.md §4)
        and a changed form must be a triage, not a quiet swap.
        """
        if self.v6_epoch_open():
            raise RegistaError(
                ErrorCode.V6_EPOCH_OPEN,
                "in-memory legacy append refused: legacy event writers cannot "
                "extend the opened v6 epoch",
                detail={"writer": "in_memory_event_store.append"},
            )
        raise RegistaError(
            ErrorCode.GENESIS_REQUIRED,
            "in-memory legacy append refused: the clean v6 epoch is not supported by this backend",
        )

    def admit_legacy_append(self) -> bytes | None:
        self._refuse_legacy_append()

    def check_legacy_append(self) -> None:
        self._refuse_legacy_append()

    def bind_keys(self, key_set: KeySet | None) -> None:
        """Publish the handle's keyset to the store, as the Postgres store carries one.

        A v6 append must be signed, and :meth:`append_v6` is reached through the
        backend-agnostic funnel, which passes ``key_set`` to the *legacy* path only.
        Rather than widen the ``EventStore.append_v6`` signature (and hand Postgres a
        keyset it would ignore in favour of its own), the in-memory store holds the
        same reference its handle does — which is also what makes
        ``instance._keys`` and the store agree by construction rather than by luck.
        """
        self._key_set = key_set

    def append_v6(self, request: V6AppendRequest) -> Event:
        """Route a legacy-shaped append through the real v6 writer, in memory.

        Mirrors ``PostgresEventStore.append_v6`` step for step, and for the same
        reasons: the idempotency and ``expected_event_seq`` preflights run *before*
        any key material is touched, so a duplicate append is answered identically
        on both backends. The writer itself is the shared
        ``_v6_writer.append_v6_event`` over the ``_in_memory_v6`` facade — there is
        no second implementation of any admission gate, key binding or chain link.
        """
        from ._in_mem_genesis import _as_conn
        from ._v6_writer import append_v6_event, resolve_producer

        if self._key_set is None:
            raise RegistaError(
                ErrorCode.GENESIS_INVALID,
                "in-memory v6 append refused: this store has no keyset, and a v6 "
                "event must be signed by an Ed25519 actor-role key bound to "
                "actor.principal_id (construct InMemoryRegista with a key path)",
            )

        existing_evt = self.find_by_event_id(request.event_id)
        _idem_payload = None if request.transition in _RESERVED_TRANSITIONS else request.payload
        existing = check_idempotency(
            existing_evt,
            request.actor_id,
            request.transition,
            request.work_item_id,
            payload=_idem_payload,
        )
        if existing is not None:
            return existing
        if request.expected_event_seq is not None:
            check_expected_seq(
                self.allocate_seq(request.work_item_id, entity_kind=request.entity_kind),
                request.expected_event_seq,
            )
        validate_actor_metadata(request.actor_metadata)
        validate_entity_kind(request.entity_kind)

        with self.v6_manager.transaction() as conn:
            append_v6_event(
                _as_conn(conn),
                self._key_set,
                entity_kind=request.entity_kind,
                entity_id=request.work_item_id,
                transition=request.transition,
                actor_id=request.actor_id,
                actor_kind=request.actor_kind,
                producer=resolve_producer(),
                payload=request.payload,
                actor_metadata=request.actor_metadata,
                event_id=request.event_id,
                key_id=request.key_id,
                workflow_name=request.workflow_name,
                workflow_version=request.workflow_version,
            )
        appended = self.find_by_event_id(request.event_id)
        if appended is None:
            raise RegistaError(
                ErrorCode.GENESIS_INVALID,
                "the in-memory v6 append did not produce a readable event row",
            )
        return appended

    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int:
        if entity_kind == "work_item":
            wi = self._work_items.get(work_item_id)
            if wi is not None:
                return cast(int, wi["next_event_seq"])
        ent_key = (entity_kind, work_item_id)
        ent = self._entity_seqs.get(ent_key)
        if ent is not None:
            return cast(int, ent["next_event_seq"])
        self._entity_seqs[ent_key] = {
            "next_event_seq": 1,
            "last_event_seq": 0,
        }
        return 1

    def find_by_event_id(self, event_id: uuid.UUID) -> Event | None:
        return self.event_id_index.get(event_id)

    def append(self, event: Event) -> Event:
        wid = event.work_item_id
        seq = self._next_global_seq
        self._next_global_seq += 1
        event = dataclasses.replace(event, global_seq=seq)
        wi = self._work_items.get(wid)
        if wi is not None:
            self.events.setdefault(wid, []).append(event)
            self.event_id_index[event.event_id] = event
            self._global_seq_by_event_id[event.event_id] = seq
            wi["last_event_seq"] = event.event_seq
            wi["last_event_at"] = event.timestamp
            wi["next_event_seq"] = event.event_seq + 1
            if event.canonical_envelope and event.signature:
                self._global_chain_head = hashlib.sha256(
                    bytes(event.canonical_envelope) + bytes(event.signature)
                ).digest()
            return event
        ent_key = (getattr(event, "entity_kind", "work_item"), wid)
        ent = self._entity_seqs.setdefault(
            ent_key,
            {
                "next_event_seq": 1,
                "last_event_seq": 0,
            },
        )
        self.events.setdefault(wid, []).append(event)
        self.event_id_index[event.event_id] = event
        self._global_seq_by_event_id[event.event_id] = seq
        ent["last_event_seq"] = event.event_seq
        ent["next_event_seq"] = event.event_seq + 1
        if event.canonical_envelope and event.signature:
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
        "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
        "global_seq, prev_global_event_hash"
    )

    def __init__(self, conn: DictConn, key_set: KeySet) -> None:
        self._conn = conn
        self._key_set = key_set
        self._locked_wis: dict[uuid.UUID, dict[str, Any] | None] = {}

    def lock_global_chain_head(self) -> bytes | None:
        from ._events import _lock_global_chain_head

        return _lock_global_chain_head(self._conn)

    def admit_legacy_append(self) -> bytes | None:
        from ._genesis import admit_legacy_append

        return admit_legacy_append(self._conn, writer="event_store.append")

    def check_legacy_append(self) -> None:
        from ._genesis import check_legacy_append

        check_legacy_append(self._conn, writer="event_store.append")

    def v6_epoch_open(self) -> bool:
        from ._v6_writer import read_project_identity

        return read_project_identity(self._conn) is not None

    def append_v6(self, request: V6AppendRequest) -> Event:
        """Route a legacy-shaped append through the real v6 writer.

        The seq/idempotency preflight still runs here so the two epochs behave the
        same way for a caller: a duplicate ``event_id`` returns the existing event
        rather than signing a second one, and ``expected_event_seq`` still guards
        optimistic concurrency. Both are decided *before* any key material is touched.
        """
        from ._v6_writer import append_v6_event, resolve_producer

        existing_evt = self.find_by_event_id(request.event_id)
        _idem_payload = (
            None if request.transition in _RESERVED_TRANSITIONS else request.payload
        )
        existing = check_idempotency(
            existing_evt,
            request.actor_id,
            request.transition,
            request.work_item_id,
            payload=_idem_payload,
        )
        if existing is not None:
            return existing
        if request.expected_event_seq is not None:
            check_expected_seq(
                self.allocate_seq(request.work_item_id, entity_kind=request.entity_kind),
                request.expected_event_seq,
            )
        validate_actor_metadata(request.actor_metadata)
        validate_entity_kind(request.entity_kind)

        append_v6_event(
            self._conn,
            self._key_set,
            entity_kind=request.entity_kind,
            entity_id=request.work_item_id,
            transition=request.transition,
            actor_id=request.actor_id,
            actor_kind=request.actor_kind,
            producer=resolve_producer(),
            payload=request.payload,
            actor_metadata=request.actor_metadata,
            event_id=request.event_id,
            key_id=request.key_id,
            workflow_name=request.workflow_name,
            workflow_version=request.workflow_version,
        )
        if request.entity_kind == "work_item":
            self._conn.execute(
                "UPDATE work_items_current SET last_event_seq = event_seq_src.seq, "
                "last_event_at = event_seq_src.ts, next_event_seq = event_seq_src.seq + 1 "
                "FROM (SELECT event_seq AS seq, timestamp AS ts FROM events "
                "WHERE event_id = %s) AS event_seq_src "
                "WHERE work_item_id = %s",
                [request.event_id, request.work_item_id],
            )
        appended = self.find_by_event_id(request.event_id)
        if appended is None:
            raise RegistaError(
                ErrorCode.GENESIS_INVALID,
                "the v6 append did not produce a readable event row",
            )
        return appended

    def prepare(
        self,
        work_item_id: uuid.UUID,
        prelocked_wi: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        from ._events import lock_work_item

        wi = prelocked_wi if prelocked_wi is not None else lock_work_item(self._conn, work_item_id)
        self._locked_wis[work_item_id] = wi
        return wi

    def allocate_seq(self, work_item_id: uuid.UUID, entity_kind: str = "work_item") -> int:
        self.check_legacy_append()
        if entity_kind != "work_item":
            entity_bytes = work_item_id.bytes
            key = int.from_bytes(entity_bytes[:8], "big", signed=False)
            if key >= 2**63:
                key -= 2**64
            self._conn.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                [key],
            )
            row = self._conn.execute(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq "
                "FROM events WHERE entity_kind = %s AND entity_id = %s",
                [entity_kind, work_item_id],
            ).fetchone()
            return cast(int, row["next_seq"])  # type: ignore[index]

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
        return cast(int, wi["next_event_seq"])

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

        self.admit_legacy_append()

        am = event.actor_metadata
        pl = event.payload

        try:
            inserted = self._conn.execute(
                SQL(
                    "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                    "event_seq, actor_id, actor_kind, "
                    "actor_metadata, key_id, workflow_name, workflow_version, "
                    "timestamp, transition, payload, payload_canonical_hash, signature, "
                    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
                    "prev_global_event_hash) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                    "%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                    "RETURNING global_seq"
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
                    psycopg.types.json.Jsonb(event.on_behalf_of)
                    if event.on_behalf_of is not None
                    else None,
                    event.scheme_id,
                    event.prev_event_hash,
                    event.prev_global_event_hash,
                ],
            )
            assigned_global_seq = inserted.fetchone()["global_seq"]  # type: ignore[index]
        except psycopg.errors.UniqueViolation as exc:
            constraint = exc.diag.constraint_name or ""
            if constraint == "events_entity_event_seq_key":
                raise RegistaError(
                    ErrorCode.CONCURRENT_MODIFICATION,
                    f"Concurrent event_seq collision for entity_id={event.work_item_id}",
                ) from exc
            existing = self.find_by_event_id(event.event_id)
            if existing is not None:
                from ._contract import check_idempotency as _contract_check

                _idem_pl = None if event.transition in _RESERVED_TRANSITIONS else event.payload
                match = _contract_check(
                    existing,
                    actor_id=event.actor_id,
                    transition=event.transition,
                    work_item_id=event.work_item_id,
                    payload=_idem_pl,
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

        # Return the event with the DB-assigned global_seq (cross-repo WI-010):
        # global_seq is allocated by the column's sequence DEFAULT, so the
        # in-memory event object never carries it. Read it back via RETURNING so
        # the Postgres store matches InMemoryEventStore.append, which returns the
        # assigned seq. prev_global_event_hash is already set on the event by the
        # caller (lock_global_chain_head) before this insert.
        return dataclasses.replace(event, global_seq=assigned_global_seq)

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
