from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import psycopg
import psycopg.types.json
from psycopg.sql import SQL

from ._connection import DictConn
from ._contract import (
    _RESERVED_TRANSITIONS,
    Jsonb,
    check_expected_seq,
    check_key_role_policy,
    validate_actor_metadata,
    validate_delegation_chain,
    validate_entity_kind,
    validate_json_safe_value,
)
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._signing import compute_chain_head_hash, sign_event
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ._event_store import InMemoryEventStore

_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
    "event_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, canonical_envelope, "
    "on_behalf_of, scheme_id, prev_event_hash, global_seq, prev_global_event_hash"
)


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


def _lock_global_chain_head(conn: DictConn) -> bytes | None:
    """Serialise global appends and return the hash the next event chains from.

    Locks the single ``event_chain_head`` row ``FOR UPDATE`` so concurrent
    appends across work items queue onto one line (no chain forks). Returns the
    current head hash, or ``None`` for the genesis event (empty log).

    A genesis sentinel row (head_hash = NULL, migration 035) guarantees the
    row always exists, so FOR UPDATE serialises even the very first append —
    closing the window where two concurrent first-events could both observe an
    empty table and both chain from NULL. ``head_hash`` is NULL only for that
    sentinel; once the first event lands it is non-NULL forever after.
    """
    row = conn.execute(
        SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE FOR UPDATE")
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.GENESIS_SENTINEL_MISSING,
            "event_chain_head sentinel is missing; refusing an append because "
            "the first-write lock cannot be established",
        )
    if row["head_hash"] is None:
        return None
    return bytes(row["head_hash"])


def _advance_global_chain_head(
    conn: DictConn, event_id: uuid.UUID, head_hash: bytes
) -> None:
    """Point the global chain head at the just-appended event."""
    conn.execute(
        SQL(
            "INSERT INTO event_chain_head (id, head_hash, head_event_id) "
            "VALUES (TRUE, %s, %s) "
            "ON CONFLICT (id) DO UPDATE SET "
            "head_hash = EXCLUDED.head_hash, "
            "head_event_id = EXCLUDED.head_event_id, updated_at = now()"
        ),
        [head_hash, event_id],
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
    )


def _v6_epoch_open(conn: DictConn) -> bool:
    """Whether this project has opened its clean v6 epoch.

    The fork every legacy funnel takes. Deliberately the *presence of
    ``project_identity``* rather than a flag: a project that has not opened an epoch
    keeps failing with exactly the ``GENESIS_REQUIRED`` form the epoch-blocked
    manifest records for it, so the fixture migration proceeds file by file instead
    of reddening 694 nodes at once with a changed failure mode
    (``SUITE-RECONCILIATION.md`` §2.1).
    """
    from ._v6_writer import read_project_identity

    return read_project_identity(conn) is not None


def resolve_system_actor_id(conn: DictConn, *, legacy_actor_id: str) -> str:
    """The principal a *system-authored* event is attributed to.

    Auto-escalation (``escalated``), claim expiry, hook dead-lettering and
    recurrence firing all append events nobody asked for: there is no calling
    actor, so the legacy writers used a bare literal (``"system"``,
    ``"system:scheduler"``). Neither is a canonical ``(human|agent|service):<subject>``
    principal per ``TRUST-DOMAIN.md`` §2.1, and — the part that actually breaks —
    neither can hold a key-binding anchor, so the v6 writer refuses the append with
    ``ACTOR_SIGNER_MISMATCH``. Those three features were therefore *impossible* in a
    clean v6 epoch, not merely awkward to set up in a test.

    In the open epoch a system-authored event is attributed to the project's own
    bootstrap principal — the ``service:`` id named by genesis, whose key-binding
    anchor is the genesis event itself. That is not a new convention: it is exactly
    what ``_workflow_api._append_workflow_registration_event`` already does for
    ``workflow_registered``, which is why that call site works today.

    Epoch-aware on purpose, and the ``None`` branch is load-bearing. A legacy
    (pre-genesis) project has no ``project_identity`` row, and the epoch-blocked
    manifest pins the exact pre-genesis refusal form for every node still inside it;
    a legacy path that started resolving a *different* actor id would redden those
    nodes with a **changed** failure form, which the manifest validator turns into
    honest red. So before genesis this returns ``legacy_actor_id`` byte for byte.

    One helper rather than the branch repeated at six call sites: a duplicated epoch
    check across two backends is how the Postgres and in-memory writers drift into
    disagreeing about the same project, and the shared conformance suite compares
    them.
    """
    from ._v6_writer import read_project_identity

    identity = read_project_identity(conn)
    if identity is None:
        return legacy_actor_id
    return identity.principal_id


def resolve_system_actor_id_in_memory(
    store: InMemoryEventStore, *, legacy_actor_id: str
) -> str:
    """:func:`resolve_system_actor_id` for the in-memory backend.

    Deliberately routes through the *same* :func:`resolve_system_actor_id` over the
    ``InMemoryV6Connection`` facade rather than reading
    ``store.v6_rows.project_identity`` directly, so the two backends cannot resolve
    different ids for the same project — a second reader of the same row is a second
    chance to disagree about it.

    The ``v6_epoch_open()`` pre-check is not just a fast path: it avoids
    materialising ``v6_rows`` on a store that has no v6 state at all, which is the
    property ``InMemoryEventStore.v6_rows`` documents.
    """
    if not store.v6_epoch_open():
        return legacy_actor_id
    with store.v6_manager.read_only_transaction() as conn:
        return resolve_system_actor_id(
            cast("DictConn", conn), legacy_actor_id=legacy_actor_id
        )


def _read_event_by_id(conn: DictConn, event_id: uuid.UUID) -> Event | None:
    row = conn.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events WHERE event_id = %s"),
        [event_id],
    ).fetchone()
    return None if row is None else _row_to_event(row)


def _append_v6_through_writer(
    conn: DictConn,
    key_set: KeySet,
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
    on_behalf_of: dict[str, Any] | None,
    key_id: str | None,
) -> Event:
    """Route one direct-SQL append through the real v6 writer.

    ``_event_store`` already owned this translation for the store-shaped funnel;
    ``_events`` is the *direct-SQL* sibling (``_work_items.create_work_item`` and the
    transition path go through here, not through the store), so it needs the same
    fork. The legacy-vocabulary translations — the ``''``/``0`` workflow sentinel
    becoming ``null``, and ``on_behalf_of`` being REFUSED rather than dropped — are
    not duplicated: ``_event_store._v6_request`` is the one place they live, and it
    is reused so the two funnels cannot drift into disagreeing about them.
    """
    from ._event_store import _v6_request
    from ._v6_writer import append_v6_event, resolve_producer

    request = _v6_request(
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        transition=transition,
        payload=payload,
        event_id=event_id,
        expected_event_seq=None,
        on_behalf_of=on_behalf_of,
        key_id=key_id,
    )
    append_v6_event(
        conn,
        key_set,
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
    appended = _read_event_by_id(conn, request.event_id)
    if appended is None:  # pragma: no cover - the writer inserted it or raised
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "the v6 append did not produce a readable event row",
        )
    return appended


def append_event(
    conn: DictConn,
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
    on_behalf_of: dict[str, Any] | None = None,
    _prelocked_wi: dict[str, Any] | None = None,
    _key_id: str | None = None,
    entity_kind: str = "work_item",
) -> Event:
    from ._genesis import admit_legacy_append, check_legacy_append

    if _v6_epoch_open(conn):
        # The work item must still exist and its expected_event_seq still hold: those
        # are contract checks the v6 writer knows nothing about, so they run here on
        # both sides of the fork rather than being lost with the legacy body.
        if entity_kind == "work_item":
            wi_row = (
                _prelocked_wi
                if _prelocked_wi is not None
                else lock_work_item(conn, work_item_id)
            )
            if wi_row is None:
                raise RegistaError(
                    ErrorCode.WORK_ITEM_NOT_FOUND,
                    f"Work item {work_item_id} not found",
                )
            check_expected_seq(wi_row["next_event_seq"], expected_event_seq)
        _idem = None if transition in _RESERVED_TRANSITIONS else (
            payload.value if payload is not None else None
        )
        existing = check_idempotency(
            conn,
            event_id,
            actor_id=actor_id,
            transition=transition,
            work_item_id=work_item_id,
            payload=_idem,
        )
        if existing is not None:
            return existing
        appended = _append_v6_through_writer(
            conn,
            key_set,
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
            on_behalf_of=on_behalf_of,
            key_id=_key_id,
        )
        if entity_kind == "work_item":
            conn.execute(
                SQL(
                    "UPDATE work_items_current SET "
                    "last_event_seq = %s, last_event_at = %s, next_event_seq = %s "
                    "WHERE work_item_id = %s"
                ),
                [appended.event_seq, appended.timestamp, appended.event_seq + 1, work_item_id],
            )
        return appended

    check_legacy_append(conn, writer="events.append_event")
    am = actor_metadata.value if actor_metadata is not None else None
    validate_actor_metadata(am)
    validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
    validate_entity_kind(entity_kind)
    key_entry = key_set.resolve_signing_key(actor_id, key_id=_key_id)
    key_id = key_entry.key_id
    check_key_role_policy(key_entry.role, transition)

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
    )
    if existing is not None:
        return existing

    if entity_kind == "work_item":
        next_seq = wi_row["next_event_seq"]  # type: ignore[index]
    else:
        entity_bytes = work_item_id.bytes
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
            [entity_kind, work_item_id],
        ).fetchone()
        next_seq = row["next_seq"]  # type: ignore[index]
    check_expected_seq(next_seq, expected_event_seq)

    pl = payload.value if payload is not None else None
    if on_behalf_of is not None:
        validate_json_safe_value(on_behalf_of, "on_behalf_of")

    now = datetime.now(UTC)

    prev_event_hash: bytes | None = None
    if next_seq > 1:
        prev_row = conn.execute(
            SQL(
                "SELECT canonical_envelope, signature FROM events "
                "WHERE entity_kind = %s AND entity_id = %s AND event_seq = %s"
            ),
            [entity_kind, work_item_id, next_seq - 1],
        ).fetchone()
        if prev_row is not None:
            prev_env = prev_row["canonical_envelope"]
            prev_sig = prev_row["signature"]
            if prev_env and prev_sig:
                _chain_fn = resolve_hash_function("sha-256")
                prev_event_hash = _chain_fn(bytes(prev_env) + bytes(prev_sig)).digest()

    previous_global_event_hash = admit_legacy_append(
        conn,
        writer="events.append_event",
    )
    scheme = get_scheme(key_entry.scheme)
    signature, canonical_hash, canonical_envelope = sign_event(
        event_id=event_id,
        work_item_id=work_item_id,
        actor_id=actor_id,
        key_id=key_id,
        event_seq=next_seq,
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
        hash_alg="sha-256",
        actor_kind=actor_kind,
        actor_metadata=am,
    )

    event_seq = next_seq
    try:
        inserted = conn.execute(
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
                event_id,
                work_item_id,
                entity_kind,
                work_item_id,
                "sha-256",
                event_seq,
                actor_id,
                actor_kind,
                psycopg.types.json.Jsonb(am) if am is not None else None,
                key_id,
                workflow_name,
                workflow_version,
                now,
                transition,
                psycopg.types.json.Jsonb(pl) if pl is not None else None,
                canonical_hash,
                signature,
                canonical_envelope,
                psycopg.types.json.Jsonb(on_behalf_of) if on_behalf_of is not None else None,
                scheme.scheme_id,
                prev_event_hash,
                previous_global_event_hash,
            ],
        )
        assigned_global_seq = inserted.fetchone()["global_seq"]  # type: ignore[index]
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
            payload=_idem_payload,
        )
        if existing is not None:
            return existing
        raise RegistaError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {event_id} already exists",
        ) from exc

    # The formula lives once, at `_signing.compute_chain_head_hash` (finding 16). This
    # is a legacy-only writer — post-genesis the funnel routes through the v6 writer,
    # so the envelope here is v1-v5 and the delegated dispatch returns the same bytes
    # the hand-copied `sha256(envelope || signature)` did. Delegating anyway is the
    # point of centralising it: a hand-copy that is *currently* only reached with
    # legacy envelopes is still a hand-copy, and the fifth one was found by a ceremony.
    _advance_global_chain_head(
        conn,
        event_id,
        compute_chain_head_hash(bytes(canonical_envelope), bytes(signature)),
    )

    if entity_kind == "work_item":
        conn.execute(
            SQL(
                "UPDATE work_items_current SET "
                "last_event_seq = %s, last_event_at = %s, next_event_seq = %s "
                "WHERE work_item_id = %s"
            ),
            [event_seq, now, event_seq + 1, work_item_id],
        )

    return Event(
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        entity_id=work_item_id,
        hash_alg="sha-256",
        event_seq=event_seq,
        global_seq=assigned_global_seq,
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
        scheme_id=scheme.scheme_id,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=previous_global_event_hash,
    )


def _append_v6_transition(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    transition_name: str,
    new_state: str,
    payload: Jsonb | None,
    event_id: uuid.UUID,
    *,
    expected_event_seq: int | None,
    custom_fields_update: dict[str, Any] | None,
    release_claim: bool,
    on_behalf_of: dict[str, Any] | None,
    _prelocked_wi: dict[str, Any] | None,
    _key_id: str | None,
) -> Event:
    """The v6 half of :func:`append_transition_event`.

    A transition is an append **plus** a projection update — the new state, merged
    custom fields, the claim release. Only the append changes in the clean epoch, so
    the state mutations are reproduced here verbatim rather than being reachable from
    the legacy body: sharing that tail would mean threading the legacy signing
    locals (``now``, ``event_seq``, ``canonical_envelope``) through a branch that does
    not have them, and the v6 writer is the authority on all three.
    """
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
    )
    if existing is not None:
        return existing

    check_expected_seq(wi_row["next_event_seq"], expected_event_seq)

    appended = _append_v6_through_writer(
        conn,
        key_set,
        work_item_id=work_item_id,
        entity_kind="work_item",
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata.value if actor_metadata is not None else None,
        workflow_name=wi_row["workflow_name"],
        workflow_version=wi_row["workflow_version"],
        transition=transition_name,
        payload=stored_payload if payload is not None or custom_fields_update else None,
        event_id=event_id,
        on_behalf_of=on_behalf_of,
        key_id=_key_id,
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
            appended.event_seq,
            appended.timestamp,
            appended.event_seq + 1,
            work_item_id,
        ],
    )

    if release_claim:
        conn.execute(
            SQL("DELETE FROM claims WHERE work_item_id = %s"),
            [work_item_id],
        )

    return appended


def append_transition_event(
    conn: DictConn,
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
    custom_fields_update: dict[str, Any] | None = None,
    release_claim: bool = True,
    on_behalf_of: dict[str, Any] | None = None,
    _prelocked_wi: dict[str, Any] | None = None,
    _key_id: str | None = None,
) -> Event:
    from ._genesis import admit_legacy_append, check_legacy_append

    if _v6_epoch_open(conn):
        return _append_v6_transition(
            conn,
            work_item_id,
            actor_id,
            actor_kind,
            actor_metadata,
            key_set,
            transition_name,
            new_state,
            payload,
            event_id,
            expected_event_seq=expected_event_seq,
            custom_fields_update=custom_fields_update,
            release_claim=release_claim,
            on_behalf_of=on_behalf_of,
            _prelocked_wi=_prelocked_wi,
            _key_id=_key_id,
        )

    check_legacy_append(conn, writer="events.append_transition_event")
    am = actor_metadata.value if actor_metadata is not None else None
    validate_actor_metadata(am)
    validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
    key_entry = key_set.resolve_signing_key(actor_id, key_id=_key_id)
    key_id = key_entry.key_id
    check_key_role_policy(key_entry.role, transition_name)

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
    )
    if existing is not None:
        return existing

    next_seq = wi_row["next_event_seq"]
    check_expected_seq(next_seq, expected_event_seq)

    if on_behalf_of is not None:
        validate_json_safe_value(on_behalf_of, "on_behalf_of")

    now = datetime.now(UTC)

    prev_event_hash: bytes | None = None
    if next_seq > 1:
        prev_row = conn.execute(
            SQL(
                "SELECT canonical_envelope, signature FROM events "
                "WHERE entity_kind = %s AND entity_id = %s AND event_seq = %s"
            ),
            ["work_item", work_item_id, next_seq - 1],
        ).fetchone()
        if prev_row is not None:
            prev_env = prev_row["canonical_envelope"]
            prev_sig = prev_row["signature"]
            if prev_env and prev_sig:
                _chain_fn = resolve_hash_function("sha-256")
                prev_event_hash = _chain_fn(bytes(prev_env) + bytes(prev_sig)).digest()

    previous_global_event_hash = admit_legacy_append(
        conn,
        writer="events.append_transition_event",
    )
    scheme = get_scheme(key_entry.scheme)
    signature, canonical_hash, canonical_envelope = sign_event(
        event_id=event_id,
        work_item_id=work_item_id,
        actor_id=actor_id,
        key_id=key_id,
        event_seq=next_seq,
        workflow_name=wi_row["workflow_name"],
        workflow_version=wi_row["workflow_version"],
        timestamp=now,
        transition=transition_name,
        payload=stored_payload,
        key=key_entry.secret,
        on_behalf_of=on_behalf_of,
        scheme=scheme,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=previous_global_event_hash,
        entity_kind="work_item",
        hash_alg="sha-256",
        actor_kind=actor_kind,
        actor_metadata=am,
    )

    event_seq = next_seq
    workflow_name = wi_row["workflow_name"]
    workflow_version = wi_row["workflow_version"]

    try:
        inserted = conn.execute(
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
                event_id,
                work_item_id,
                "work_item",
                work_item_id,
                "sha-256",
                event_seq,
                actor_id,
                actor_kind,
                psycopg.types.json.Jsonb(am) if am is not None else None,
                key_id,
                workflow_name,
                workflow_version,
                now,
                transition_name,
                psycopg.types.json.Jsonb(stored_payload) if stored_payload is not None else None,
                canonical_hash,
                signature,
                canonical_envelope,
                psycopg.types.json.Jsonb(on_behalf_of) if on_behalf_of is not None else None,
                scheme.scheme_id,
                prev_event_hash,
                previous_global_event_hash,
            ],
        )
        assigned_global_seq = inserted.fetchone()["global_seq"]  # type: ignore[index]
    except psycopg.errors.UniqueViolation as exc:
        constraint = exc.diag.constraint_name or ""
        if constraint == "events_entity_event_seq_key":
            raise RegistaError(
                ErrorCode.CONCURRENT_MODIFICATION,
                f"Concurrent event_seq collision for work_item_id={work_item_id}",
            ) from exc
        existing = check_idempotency(
            conn,
            event_id,
            actor_id=actor_id,
            transition=transition_name,
            work_item_id=work_item_id,
            payload=stored_payload if payload is not None else None,
        )
        if existing is not None:
            return existing
        raise RegistaError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {event_id} already exists",
        ) from exc

    # The formula lives once, at `_signing.compute_chain_head_hash` (finding 16). This
    # is a legacy-only writer — post-genesis the funnel routes through the v6 writer,
    # so the envelope here is v1-v5 and the delegated dispatch returns the same bytes
    # the hand-copied `sha256(envelope || signature)` did. Delegating anyway is the
    # point of centralising it: a hand-copy that is *currently* only reached with
    # legacy envelopes is still a hand-copy, and the fifth one was found by a ceremony.
    _advance_global_chain_head(
        conn,
        event_id,
        compute_chain_head_hash(bytes(canonical_envelope), bytes(signature)),
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
            event_seq,
            now,
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
        entity_kind="work_item",
        entity_id=work_item_id,
        hash_alg="sha-256",
        event_seq=event_seq,
        global_seq=assigned_global_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am,
        key_id=key_id,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=now,
        transition=transition_name,
        payload=stored_payload,
        payload_canonical_hash=canonical_hash,
        signature=signature,
        canonical_envelope=canonical_envelope,
        on_behalf_of=on_behalf_of,
        scheme_id=scheme.scheme_id,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=previous_global_event_hash,
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
