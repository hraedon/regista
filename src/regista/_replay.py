from __future__ import annotations

import contextlib
import hmac as _hmac
import uuid
from datetime import datetime
from typing import Any

import psycopg
import structlog
from psycopg.sql import SQL, Identifier

from ._connection import DictConn
from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._signing import verify_event_dict_principal_binding
from ._types import ReplayReport, ReplayReportEntry
from ._v6_referents import ReferentResolver, store_referents
from ._verification import (
    DEFAULT_POLICY,
    V6_ENTITY_KINDS,
    AbsentEnvelopeProbe,
    Applicability,
    EnvelopeVersion,
    EventRow,
    FailureReason,
    KeySetResolver,
    probe_absent_envelope,
    verify_event_strict,
)

log = structlog.get_logger()

_EXPECTED_UNPINNED_BOOTSTRAP_TARGETS = {
    "trust_domain_established": "trust_domain",
    "project_cryptographic_epoch_started": "project",
    "project_initialized": "project",
}


def _is_expected_unpinned_bootstrap(
    *,
    entity_kind: str | None,
    transition: str | None,
    applicability: Applicability,
    reasons: tuple[FailureReason, ...],
) -> bool:
    """Recognize only the three legal externally anchored bootstrap events."""

    return (
        transition is not None
        and _EXPECTED_UNPINNED_BOOTSTRAP_TARGETS.get(transition) == entity_kind
        and applicability is Applicability.UNVERIFIABLE
        and reasons == (FailureReason.KEY_BINDING_UNRESOLVED,)
    )


def drop_old_replay_tables(conn: DictConn, schema: str) -> None:
    """Drop stale replay tables from previous runs."""
    old_tables = conn.execute(
        SQL(
            "SELECT tablename FROM pg_tables WHERE schemaname = %s "
            "AND (tablename LIKE 'work_items_current_replay_%%' "
            "OR tablename LIKE 'replay_report_%%')"
        ),
        [schema],
    ).fetchall()
    for tbl in old_tables:
        conn.execute(SQL("DROP TABLE IF EXISTS {}").format(Identifier(tbl["tablename"])))


def _drop_replay_tables(conn: DictConn, *table_names: str) -> None:
    for name in table_names:
        conn.execute(SQL("DROP TABLE IF EXISTS {}").format(Identifier(name)))


class _ReplayStore:
    """Accumulates replay results and is the single source of truth for where
    those results live.

    In both modes the portable, post-return access path is
    :meth:`report_entries` → :attr:`ReplayReport.entries`. The temp tables are
    an implementation detail of the writable backend and are dropped in a
    ``finally`` when the replay completes, so they are NOT valid after
    :func:`replay` returns.

    * *Writable* (normal mode): per-item rows are written to ``CREATE TEMP
      TABLE`` tables (session-scoped, dropped in ``finally``) AND recorded in
      memory. :attr:`table_name` holds the projection table name for the span
      of the replay transaction only.

    * *Read-only* (verify path): results are held in memory. This is the only
      option that works against a read-only connection, because even
      ``CREATE TEMP TABLE`` is blocked under ``default_transaction_read_only``
      (creating any table writes to ``pg_class``). :attr:`table_name` is
      ``None``.
    """

    def __init__(self, conn: DictConn, *, read_only: bool) -> None:
        self._conn = conn
        self._read_only = read_only
        self._report_entries: list[ReplayReportEntry] = []
        tag = uuid.uuid4().hex[:8]
        self.replay_table = f"work_items_current_replay_{tag}"
        self.report_table = f"replay_report_{tag}"
        if read_only:
            self.table_name: str | None = None
        else:
            self.table_name = self.replay_table
            conn.execute(
                SQL("CREATE TEMP TABLE {} AS SELECT * FROM work_items_current WHERE 1=0").format(
                    Identifier(self.replay_table)
                )
            )
            conn.execute(
                SQL(
                    "CREATE TEMP TABLE {} ("
                    "work_item_id UUID PRIMARY KEY, "
                    "category TEXT NOT NULL, "
                    "detail TEXT, "
                    "warnings INTEGER NOT NULL DEFAULT 0, "
                    "chain_breaks INTEGER NOT NULL DEFAULT 0)"
                ).format(Identifier(self.report_table))
            )

    def add_report_entry(
        self,
        work_item_id: uuid.UUID,
        category: str,
        detail: str | None,
        warnings: int,
        chain_breaks: int = 0,
    ) -> None:
        # Always record the per-item result so `entries` is the portable access
        # path in both modes. In writable mode the same row is also persisted
        # to the (temporary) report table for the duration of the transaction.
        self._report_entries.append(
            ReplayReportEntry(work_item_id, category, detail, warnings, chain_breaks)
        )
        if self._read_only:
            return
        self._conn.execute(
            SQL(
                "INSERT INTO {} (work_item_id, category, detail, warnings, chain_breaks) "
                "VALUES (%s, %s, %s, %s, %s)"
            ).format(Identifier(self.report_table)),
            [work_item_id, category, detail, warnings, chain_breaks],
        )

    def add_replay_row(self, row: dict[str, Any]) -> None:
        # The replayed projection is written to the temp table only. It is NOT
        # retained in memory: a full materialization would unboundedly grow with
        # the log, and `entries` already carries the per-item report. The
        # projection is reachable via `table_name` for the transaction's span.
        if self._read_only:
            return
        self._conn.execute(
            SQL(
                "INSERT INTO {} (work_item_id, workflow_name, workflow_version, "
                "work_item_type, current_state, custom_fields, needs_review, "
                "not_before, last_event_seq, last_event_at, next_event_seq, "
                "claimed_by, claim_expires_at, attempt_number) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ).format(Identifier(self.replay_table)),
            [
                row["work_item_id"],
                row["workflow_name"],
                row["workflow_version"],
                row["work_item_type"],
                row["current_state"],
                psycopg.types.json.Jsonb(row["custom_fields"]),  # type: ignore[attr-defined]
                row["needs_review"],
                row["not_before"],
                row["last_event_seq"],
                None,
                row["last_event_seq"] + 1,
                row["claimed_by"],
                row["claim_expires_at"],
                row["attempt_number"],
            ],
        )

    def drop(self) -> None:
        if not self._read_only:
            _drop_replay_tables(self._conn, self.replay_table, self.report_table)

    def report_entries(self) -> tuple[ReplayReportEntry, ...]:
        return tuple(self._report_entries)


# AC-28: event hash chain verification (BC-233)
def _verify_hash_chain(
    event: dict[str, Any],
    prev_event: dict[str, Any] | None,
) -> tuple[bool, str]:
    expected = event.get("prev_event_hash")
    if expected is None:
        return True, ""
    if prev_event is None:
        return False, "prev_event_hash set[Any] but no previous event"
    prev_env = prev_event.get("canonical_envelope")
    prev_sig = prev_event.get("signature")
    if prev_env is None or prev_sig is None:
        return False, "previous event missing canonical_envelope or signature"
    computed = _event_head_hash(prev_event)
    if computed is None:
        return False, "previous event has no computable event hash"
    if not _hmac.compare_digest(computed, bytes(expected)):
        detail = f"hash chain mismatch: computed={computed.hex()} expected={bytes(expected).hex()}"
        return False, detail
    return True, ""


def _event_head_hash(evt: dict[str, Any]) -> bytes | None:
    """Return the chain head hash an event contributes, or ``None``.

    Accepts either a pre-computed ``head_hash`` (the compact chain-link
    records the streaming replay builds — WI-217) or the raw
    ``canonical_envelope``/``signature`` pair, so the chain walk can be
    driven either from link records or from full event rows (unit tests
    construct the latter directly).

    The formula itself is ``_signing.compute_chain_head_hash`` — one definition
    for the whole tree, because every hand-copy of it has been a bug (see that
    function's docstring for the two on the record).
    """
    precomputed = evt.get("head_hash")
    if precomputed is not None:
        return precomputed if isinstance(precomputed, bytes) else bytes(precomputed)
    env = evt.get("canonical_envelope")
    sig = evt.get("signature")
    if env is None or sig is None:
        return None
    from ._signing import compute_chain_head_hash

    return compute_chain_head_hash(bytes(env), bytes(sig))


def _chain_link(evt: dict[str, Any]) -> dict[str, Any]:
    """Reduce an event row to the fields the global chain walk needs.

    The head hash is computed here so the row's envelope, signature and
    payload can be released with the rest of its work item's group instead
    of being pinned until the whole project has been replayed (WI-217).

    The walk needs exactly four things per event: its identity (for cycle
    and reachability bookkeeping), its ``global_seq`` (warning detail, and
    the deterministic genesis tie-break in ``_verify_global_hash_chain``),
    the link it claims to chain from,
    and the link its successor must claim.  Everything else in the row —
    envelope, payload, signature, actor metadata — is per-work-item state
    that the group loop has already consumed by the time this returns.
    """
    prev = evt.get("prev_global_event_hash")
    return {
        "event_id": evt["event_id"],
        "global_seq": evt.get("global_seq"),
        "prev_global_event_hash": bytes(prev) if prev is not None else None,
        "head_hash": _event_head_hash(evt),
    }


def _verify_global_hash_chain(
    events: list[dict[str, Any]],
) -> tuple[int, dict[str, Any] | None]:
    """Verify the global event hash chain by walking ``prev_global_event_hash``
    links (BC-300 / Plan 024).

    Each entry in *events* must carry ``event_id``, ``global_seq``,
    ``prev_global_event_hash`` and enough material to derive its own head
    hash — either a pre-computed ``head_hash`` or the
    ``canonical_envelope``/``signature`` pair (see ``_event_head_hash``).

    The chain is walked from genesis (NULL ``prev_global_event_hash``) by
    following hash links, NOT by sorting on ``global_seq``.  The
    ``events_global_seq_seq`` sequence uses ``CACHE 100``, so under
    concurrent appends different sessions consume disjoint blocks of
    sequence values and ``global_seq`` order can diverge from actual
    append (chain-link) order.  A hash walk is immune to this: it follows
    the same links the append path established under the
    ``event_chain_head`` row lock.

    Returns ``(chain_breaks, chain_tail)``.  Every finding this walk can
    make is a structural chain failure (WI-266): a broken link, orphan,
    fork, multiple genesis, or cycle is a tampering verdict, not an
    advisory, so they all count as ``chain_breaks`` rather than warnings.
    *chain_tail* is the last live event reached by the walk (or ``None``
    if the event list is empty or no genesis exists).
    """
    from collections import defaultdict

    if not events:
        return 0, None

    link_map: dict[str, list[dict[str, Any]]] = defaultdict(list[Any])
    genesis_events: list[dict[str, Any]] = []
    for evt in events:
        expected = evt.get("prev_global_event_hash")
        if expected is None:
            genesis_events.append(evt)
        else:
            link_map[bytes(expected).hex()].append(evt)

    chain_breaks = 0

    # Multiple genesis events (NULL prev_global_event_hash) mean a fork or
    # corruption. Which one is the canonical chain start must not depend on the
    # arbitrary order of the input list[Any] (WI-219): pick the lowest global_seq,
    # breaking any remaining tie on event_id so the verdict is total and stable.
    genesis_events.sort(
        key=lambda e: (
            e.get("global_seq") is None,
            e.get("global_seq") or 0,
            str(e["event_id"]),
        )
    )

    if len(genesis_events) > 1:
        for g in genesis_events[1:]:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_multiple_genesis",
                event_id=str(g["event_id"]),
                global_seq=g.get("global_seq"),
            )

    if not genesis_events:
        for evt in events:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt["event_id"]),
                global_seq=evt.get("global_seq"),
                detail="no genesis event",
            )
        return chain_breaks, None

    visited_events: set[Any] = set[Any]()
    last_event: dict[str, Any] | None = None
    current: dict[str, Any] | None = genesis_events[0]

    while True:
        if current is None:
            break

        eid = current["event_id"]
        if eid in visited_events:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_cycle",
                event_id=str(eid),
                global_seq=current.get("global_seq"),
            )
            break

        visited_events.add(eid)
        last_event = current

        head_hash = _event_head_hash(current)
        if head_hash is None:
            break

        successors = link_map.get(head_hash.hex(), [])

        if not successors:
            break

        if len(successors) > 1:
            for s in successors[1:]:
                chain_breaks += 1
                log.warning(
                    "replay.global_chain_fork",
                    event_id=str(s["event_id"]),
                    global_seq=s.get("global_seq"),
                    detail=f"multiple events chain from event {eid}",
                )

        current = successors[0]

    for evt in events:
        if evt["event_id"] not in visited_events:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt["event_id"]),
                global_seq=evt.get("global_seq"),
                detail="event not reachable from genesis via prev_global_event_hash links",
            )

    return chain_breaks, last_event


class _ReplayHaltError(RegistaError):
    """A per-work-item halt, carrying the findings made before it fired.

    A halt aborts ``_replay_work_item`` mid-loop, so any counter it had
    accumulated would be discarded by the caller's ``except`` branch. That
    silently drops real findings: WI-267 verification and the WI-266 chain
    walk look at the *same* event, and a rewritten ``prev_event_hash`` is both
    a broken chain link and a signed-field mismatch. The halt must not erase
    the chain-break count on its way out — the two are distinct guarantees and
    a scripted reader may be watching either.
    """

    def __init__(
        self,
        message: str,
        *,
        chain_breaks: int = 0,
        warnings: int = 0,
        unverifiable: int = 0,
    ) -> None:
        super().__init__(ErrorCode.REPLAY_HALTED, message)
        self.chain_breaks = chain_breaks
        self.warnings = warnings
        self.unverifiable = unverifiable


def _verify_non_work_item_group(
    events: list[dict[str, Any]],
    *,
    key_set: KeySet,
    referents: ReferentResolver,
    continue_on_revoked: bool,
) -> tuple[int, int, int, bool]:
    """Verify every event in a legal non-work-item entity group.

    Non-work-item groups do not rebuild ``work_items_current``, but they are still
    signed v6 entities and may carry the complete action-delegation contract. A
    group is counted when every event survives strict row/envelope validation and
    every delegated authorization is verified against the complete store material.
    The expected unpinned bootstrap authority is the one deliberate exception:
    its bytes are checked, but the external trust root is outside a default replay.
    """

    warnings = 0
    chain_breaks = 0
    unverifiable = 0
    verified = True
    previous: dict[str, Any] | None = None
    for event in sorted(events, key=lambda item: item["event_seq"]):
        chain_ok, chain_error = _verify_hash_chain(event, previous)
        if not chain_ok:
            chain_breaks += 1
            verified = False
            log.warning(
                "replay.hash_chain_broken",
                entity_kind=event.get("entity_kind"),
                entity_id=str(event.get("entity_id")),
                event_id=str(event["event_id"]),
                event_seq=event["event_seq"],
                detail=chain_error,
            )

        key_entry = None
        unknown_key_skipped = False
        try:
            key_entry = key_set.verify_key_status(
                event["key_id"],
                event_timestamp=(
                    event["timestamp"].isoformat() if event.get("timestamp") else None
                ),
            )
        except RegistaError as exc:
            if exc.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                key_entry = key_set.get_key(event["key_id"])
                warnings += 1
            elif exc.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                unknown_key_skipped = True
                warnings += 1
            else:
                raise

        if key_entry is None:
            verified = False
            unverifiable += 1
        else:
            verification = verify_event_strict(
                EventRow.from_mapping(event),
                keys=KeySetResolver(key_set),
                referents=referents,
                policy=DEFAULT_POLICY,
            )
            if verification.applicability is Applicability.INVALID:
                raise _ReplayHaltError(
                    f"Signature verification failed for event {event['event_id']} "
                    f"at seq {event['event_seq']}: {verification.summary()}",
                    warnings=warnings,
                    chain_breaks=chain_breaks,
                    unverifiable=unverifiable,
                )
            if not verification.accepted:
                # A clean epoch's bootstrap event is intentionally not fully
                # authenticated until the caller supplies the external trust
                # and checkpoint pins.  That expected bootstrap gap is not an
                # evidentiary gap in the replay report: this counter describes
                # events that could not be checked at all, while the envelope,
                # row and chain checks above have all run here.  Any other
                # non-accepted result remains an unverified group finding.
                expected_unpinned_bootstrap = _is_expected_unpinned_bootstrap(
                    entity_kind=event.get("entity_kind"),
                    transition=event.get("transition"),
                    applicability=verification.applicability,
                    reasons=verification.reasons,
                )
                if not expected_unpinned_bootstrap:
                    verified = False
                if FailureReason.ENVELOPE_ABSENT in verification.reasons:
                    probe = probe_absent_envelope(
                        EventRow.from_mapping(event), keys=KeySetResolver(key_set)
                    )
                    if probe is AbsentEnvelopeProbe.INCONSISTENT:
                        raise _ReplayHaltError(
                            f"Event {event['event_id']} at seq {event['event_seq']} "
                            "has no canonical_envelope, and no envelope this row "
                            "could have carried reproduces its retained signature: "
                            "the row contradicts its own cryptographic material",
                            warnings=warnings,
                            chain_breaks=chain_breaks,
                            unverifiable=unverifiable,
                        )
                if not expected_unpinned_bootstrap:
                    unverifiable += 1
        if unknown_key_skipped:
            verified = False
        previous = event

    return warnings, chain_breaks, unverifiable, verified


_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
    "event_seq, global_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, "
    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "prev_global_event_hash"
)

# Rows pulled per FETCH from the server-side event cursor (WI-217).
#
# A client-side cursor is not an option here: libpq buffers the whole result
# set[Any] before psycopg sees row one, so `SELECT ... FROM events` costs the
# entire log in C heap no matter how the rows are consumed.  `cursor.stream()`
# is also out — it forbids other traffic on the connection, and the group loop
# has to write report rows as it goes.  That leaves a named (server-side)
# cursor, whose FETCH size this bounds.
#
# 100 matches psycopg's own ServerCursor default; the extra round trips are
# cheap next to per-event signature verification.  Note this bounds the block
# in ROWS, not bytes — on a project with very large event payloads the block's
# byte cost rises with the payload width.
#
# Client-side working set[Any]: one fetch block, plus the widest single entity's
# history, plus one compact chain link per event.
#
# The chain index is the term that still grows with the log, so it is worth
# being precise about, and the answer depends on what you charge to it.  A link
# allocates 258 B of fresh memory (measured: tracemalloc delta while building
# the index over 6000 real rows) — the dict[str, Any] plus the two 32-byte digests.  It
# also pins the row's `event_id` UUID and `global_seq` int, which would
# otherwise be freed with the row, taking the footprint to ~360 B by
# `sys.getsizeof`, or ~470 B if the four (interned, shared) key strings are
# charged per link as well.  At 227k events that is ~55-105 MiB depending on
# the accounting — the dominant term on a large log, and the reason this is a
# bound rather than an elimination.
_EVENT_STREAM_SIZE = 100

# Ordering for the streamed event scan (WI-217).
#
# This MUST stay on the columns of `idx_events_entity` / the
# `UNIQUE (entity_kind, entity_id, event_seq)` constraint, and it is load
# bearing for memory, not just for speed.  `DECLARE CURSOR` over a plan
# containing a Sort makes Postgres materialize the whole sorted result before
# it will yield row one, and hold it for the cursor's entire lifetime — which
# is now the whole replay rather than the few seconds a `fetchall()` took.
# Measured on a 6000-row / 8.3 MiB events table: ordering by
# `work_item_id, event_seq` plans as `Sort -> Seq Scan` and parks 6.1 MiB in
# `pgsql_tmp` after fetching a single row (a few hundred MB at production
# scale, which a deployment with `temp_file_limit` set[Any] would abort on);
# ordering by the index columns plans as `Index Scan using idx_events_entity`
# and uses zero temp space.  There is no index on `work_item_id` to order by —
# migration 031 dropped `UNIQUE (work_item_id, event_seq)` when it made
# `(entity_kind, entity_id, event_seq)` the event stream's identity and
# demoted `work_item_id` to a read-compat column.
#
# The trade is random heap access instead of a sequential scan.  That is the
# right side of the trade here: replay verifies a signature per event, so it is
# CPU bound, and the plan is fast-start rather than blocking on a full sort.
_EVENT_STREAM_ORDER = "ORDER BY entity_kind, entity_id, event_seq"


def replay(
    conn: DictConn,
    schema: str,
    project: str,
    key_set: KeySet,
    continue_on_revoked: bool = False,
    verify_principal_binding: bool = False,
    work_item_id: uuid.UUID | None = None,
    read_only: bool = False,
) -> ReplayReport:
    store = _ReplayStore(conn, read_only=read_only)
    try:
        return _replay_inner(
            conn,
            schema,
            project,
            key_set,
            store,
            continue_on_revoked=continue_on_revoked,
            verify_principal_binding=verify_principal_binding,
            work_item_id=work_item_id,
        )
    finally:
        # Drop the temp tables on BOTH success and failure. Without the
        # success-path drop, a long-lived pooled connection (the verify-loop
        # daemon use case, pool_max_lifetime=None) accumulates two temp tables
        # per replay for the process lifetime. After F1 the portable result
        # access is `entries`, so no caller needs these tables post-return.
        store.drop()


def _replay_inner(
    conn: DictConn,
    schema: str,
    project: str,
    key_set: KeySet,
    store: _ReplayStore,
    *,
    continue_on_revoked: bool = False,
    verify_principal_binding: bool = False,
    work_item_id: uuid.UUID | None = None,
) -> ReplayReport:
    scoped = work_item_id is not None

    # The presented material for every v6 verdict in this replay. It is the whole
    # store even for a *scoped* replay: scoping selects which work items are
    # rebuilt, not which events the verifier may see, and a key-binding anchor for a
    # work-item event is a `principal` event that no work-item scope would contain.
    # Narrowing the material to the scope would turn "the anchor is elsewhere in this
    # store" into "the anchor is missing", which is a false finding.
    referents = store_referents(conn, label=f"project store {project!r}")

    if scoped:
        wi_rows = conn.execute(
            SQL("SELECT work_item_id FROM work_items_current WHERE work_item_id = %s"),
            [work_item_id],
        ).fetchall()
    else:
        wi_rows = conn.execute(
            SQL("SELECT work_item_id FROM work_items_current ORDER BY work_item_id")
        ).fetchall()

    wi_ids = {row["work_item_id"] for row in wi_rows}
    # Only membership is needed from here on, and the stream below holds the
    # connection for the rest of the call — don't keep the row list[Any] alive
    # alongside it (WI-217).
    del wi_rows

    ok_count = 0
    drift_count = 0
    halted_count = 0
    total_warnings = 0
    total_chain_breaks = 0
    total_principal_binding_failures = 0
    total_unverifiable = 0
    v6_binding_checked = False
    v6_binding_verified = True
    legacy_binding_checked = False
    non_work_item_groups = 0

    # WI-217: the event log is streamed one entity at a time through a
    # server-side cursor, so the replay working set[Any] is bounded by the widest
    # single entity's history plus a fetch block, not by the size of the
    # project's whole event log.  The only per-event state that outlives a
    # group is the compact chain link below, which carries a pre-computed
    # head hash instead of the envelope, signature and payload.  See
    # _EVENT_STREAM_SIZE / _EVENT_STREAM_ORDER for the full cost, including
    # the server side — the ordering is load bearing for both.
    chain_links: list[dict[str, Any]] = []
    scoped_event_count = 0
    processed_wi_ids: set[Any] = set()

    def _handle_orphan_group(orphan_id: Any, orphan_evts: list[dict[str, Any]]) -> None:
        nonlocal halted_count, total_warnings, total_chain_breaks
        nonlocal total_unverifiable, non_work_item_groups

        kinds = {e.get("entity_kind", "work_item") for e in orphan_evts}
        # An entity kind outside the CLOSED eight-value registry (V6-ENVELOPE.md
        # §1.2) is a refusal, not an extension point. It halts, and it halts
        # BEFORE the spec-legal branch below so that a fabricated kind cannot
        # ride out on the tolerance that branch grants to legal non-work-item kinds.
        unknown = sorted(kinds - V6_ENTITY_KINDS)
        if unknown:
            halted_count += 1
            log.error(
                "replay.unknown_entity_kind",
                entity_id=str(orphan_id),
                entity_kinds=unknown,
                event_count=len(orphan_evts),
            )
            store.add_report_entry(
                orphan_id,
                "halted",
                "entity kind outside the closed v6 registry: " + ", ".join(unknown),
                0,
            )
            return
        if kinds != {"work_item"}:
            if "work_item" in kinds:
                # One entity id carrying BOTH work-item and non-work-item events.
                # `UNIQUE (entity_kind, entity_id, event_seq)` permits it, no
                # append path produces it, and no reading of it is safe: it is
                # neither a work item to rebuild nor a foreign entity to pass
                # over. Halt rather than pick one.
                halted_count += 1
                log.error(
                    "replay.mixed_entity_kind_group",
                    entity_id=str(orphan_id),
                    entity_kinds=sorted(kinds),
                    event_count=len(orphan_evts),
                )
                store.add_report_entry(
                    orphan_id,
                    "halted",
                    "one entity id carries several entity kinds: "
                    + ", ".join(sorted(kinds)),
                    0,
                )
                return
            # A spec-legal non-work-item entity group: `project`, `principal`,
            # `trust_domain`, `project_instance`, `workflow`, `spec` or `note`.
            # These events have no projection row, but they still pass the same
            # strict row/envelope/referent verifier as work-item events.
            try:
                group_warnings, group_breaks, group_unverifiable, verified = (
                    _verify_non_work_item_group(
                        orphan_evts,
                        key_set=key_set,
                        referents=referents,
                        continue_on_revoked=continue_on_revoked,
                    )
                )
            except _ReplayHaltError as exc:
                halted_count += 1
                total_warnings += exc.warnings
                total_chain_breaks += exc.chain_breaks
                total_unverifiable += exc.unverifiable
                log.error(
                    "replay.non_work_item_verification_failed",
                    entity_id=str(orphan_id),
                    entity_kinds=sorted(kinds),
                    error=str(exc),
                )
                store.add_report_entry(
                    orphan_id, "halted", str(exc), exc.warnings, exc.chain_breaks
                )
                return
            total_warnings += group_warnings
            total_chain_breaks += group_breaks
            total_unverifiable += group_unverifiable
            if verified:
                non_work_item_groups += 1
            log.info(
                "replay.non_work_item_entity",
                entity_id=str(orphan_id),
                entity_kinds=sorted(kinds),
                event_count=len(orphan_evts),
                verified=verified,
            )
            return
        # WI-266: a created work item whose projection row is gone is the same
        # structural finding scoped replay calls `projection_row_missing` and
        # halts on. It is a halt, not a warning, and it always gets a report
        # entry so the two paths cannot disagree about the corpus.
        is_created = len(orphan_evts) > 0 and orphan_evts[0]["transition"] == "created"
        if is_created:
            halted_count += 1
            log.error(
                "replay.orphan_work_item_missing_projection",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
            store.add_report_entry(
                orphan_id,
                "halted",
                "events exist but projection row missing from work_items_current",
                0,
            )
        else:
            halted_count += 1
            log.error(
                "replay.orphan_events",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
            store.add_report_entry(
                orphan_id,
                "halted",
                "Orphaned events with no work_item and no created event",
                0,
            )

    def _process_group(entity_kind: str, wi_id: Any, events: list[dict[str, Any]]) -> None:
        nonlocal ok_count, drift_count, halted_count
        nonlocal total_warnings, total_chain_breaks, total_principal_binding_failures
        nonlocal total_unverifiable
        nonlocal v6_binding_checked, v6_binding_verified, legacy_binding_checked

        # Only work-item entities have a projection row to rebuild.  Other
        # entity kinds (spec, principal) keep their own `event_seq` space —
        # `allocate_seq` keys on (entity_kind, entity_id) — so feeding them to
        # `_replay_work_item` would clobber `last_event_seq` with a foreign
        # sequence.  They take the orphan path, which reports them as
        # `replay.non_work_item_entity`, exactly as before.
        if entity_kind != "work_item" or wi_id not in wi_ids:
            # Scoped replay reports the missing projection row once, after
            # the stream is drained, so there is nothing to do here.
            if not scoped:
                _handle_orphan_group(wi_id, events)
            return

        processed_wi_ids.add(wi_id)

        try:
            (
                replayed_state,
                wi_warnings,
                wi_chain_breaks,
                wi_pb_failures,
                wi_unverifiable,
                wi_v6_binding_checked,
                wi_v6_binding_verified,
                wi_legacy_binding_checked,
            ) = _replay_work_item(
                conn,
                wi_id,
                events,
                key_set,
                continue_on_revoked,
                verify_principal_binding=verify_principal_binding,
                referents=referents,
            )
            total_warnings += wi_warnings
            total_chain_breaks += wi_chain_breaks
            total_principal_binding_failures += wi_pb_failures
            total_unverifiable += wi_unverifiable
            v6_binding_checked = v6_binding_checked or wi_v6_binding_checked
            v6_binding_verified = v6_binding_verified and wi_v6_binding_verified
            legacy_binding_checked = legacy_binding_checked or wi_legacy_binding_checked
        except _ReplayHaltError as e:
            halted_count += 1
            # Findings made before the halt survive it — see _ReplayHaltError.
            total_warnings += e.warnings
            total_chain_breaks += e.chain_breaks
            total_unverifiable += e.unverifiable
            log.error("replay.halted", work_item_id=str(wi_id), error=str(e))
            store.add_report_entry(wi_id, "halted", str(e), e.warnings, e.chain_breaks)
            return
        except Exception as e:
            halted_count += 1
            log.error(
                "replay.unexpected_error",
                work_item_id=str(wi_id),
                error=str(e),
                exc_info=True,
            )
            store.add_report_entry(wi_id, "halted", f"unexpected: {e}", 0)
            return

        live_row = conn.execute(
            SQL(
                "SELECT work_item_id, workflow_name, workflow_version, work_item_type, "
                "current_state, custom_fields, needs_review, not_before, "
                "last_event_seq, last_event_at, next_event_seq, "
                "claimed_by, claim_expires_at, attempt_number "
                "FROM work_items_current WHERE work_item_id = %s"
            ),
            [wi_id],
        ).fetchone()
        assert live_row is not None

        if _states_match(replayed_state, live_row):
            ok_count += 1
            store.add_report_entry(wi_id, "replayed_ok", None, wi_warnings, wi_chain_breaks)
        else:
            drift_count += 1
            diff_fields = _diff_fields(replayed_state, live_row)
            detail = (
                f"drift in: {', '.join(diff_fields)}. "
                f"live state={live_row['current_state']!r} "
                f"seq={live_row['last_event_seq']}, "
                f"replayed state={replayed_state['current_state']!r} "
                f"seq={replayed_state['last_event_seq']}"
            )
            store.add_report_entry(
                wi_id, "replayed_drift", detail, wi_warnings, wi_chain_breaks
            )

        store.add_replay_row(
            {
                "work_item_id": wi_id,
                "workflow_name": live_row["workflow_name"],
                "workflow_version": live_row["workflow_version"],
                "work_item_type": live_row["work_item_type"],
                "current_state": replayed_state["current_state"],
                "custom_fields": replayed_state["custom_fields"],
                "needs_review": replayed_state["needs_review"],
                "not_before": replayed_state["not_before"],
                "last_event_seq": replayed_state["last_event_seq"],
                "last_event_at": None,
                "next_event_seq": replayed_state["last_event_seq"] + 1,
                "claimed_by": replayed_state["claimed_by"],
                "claim_expires_at": replayed_state["claim_expires_at"],
                "attempt_number": replayed_state["attempt_number"],
            }
        )

    if scoped:
        # Filter on the entity identity columns, not the demoted `work_item_id`
        # read-compat column (WI-220).  There is no index on `work_item_id`
        # (migration 031 dropped `UNIQUE (work_item_id, event_seq)`), so
        # `WHERE work_item_id = %s ORDER BY event_seq` plans as a full
        # `Sort -> Seq Scan` no matter how few rows the work item has.
        # `idx_events_entity (entity_kind, entity_id, event_seq)` turns it into
        # an Index Scan whose key order already satisfies `ORDER BY event_seq`,
        # so there is no Sort at all.  For a work item `entity_id` equals
        # `work_item_id` (migration 031 backfill + the `events_set_entity_id`
        # trigger), so this matches exactly the rows the old predicate saw and
        # the reported `event_count` is unchanged.
        events_query = SQL(
            f"SELECT {_EVENT_FIELDS} FROM events "
            "WHERE entity_kind = 'work_item' AND entity_id = %s ORDER BY event_seq"
        )
        events_params: list[Any] | None = [work_item_id]
    else:
        events_query = SQL(f"SELECT {_EVENT_FIELDS} FROM events {_EVENT_STREAM_ORDER}")
        events_params = None

    # psycopg's named cursors are DECLARE ... WITHOUT HOLD, so the stream is
    # only valid inside a transaction and only until the next commit:
    #   * `_api_workflow.replay` runs this under
    #     `transaction_repeatable_read()`, so the usual path is covered, but
    #     `replay` is also re-exported as `regista.testing.replay_fn` and takes
    #     a caller-supplied connection.  An autocommit connection has no
    #     transaction block for DECLARE, so open one explicitly rather than
    #     failing with psycopg's bare `NoActiveSqlTransaction`.
    #   * Do NOT add a `conn.commit()` inside the group loop.  It would close
    #     this cursor (`InvalidCursorName`) after the first fetch block, which
    #     means it would pass every test — no fixture has more than 100 events
    #     — and fail only on real logs.  `_process_group` already writes two
    #     tables on this connection, so batching those writes is a natural next
    #     step; batch them without committing, or re-declare the cursor.
    txn = conn.transaction() if conn.autocommit else contextlib.nullcontext()

    with txn, conn.cursor(name=f"replay_events_{uuid.uuid4().hex[:8]}") as event_stream:
        event_stream.itersize = _EVENT_STREAM_SIZE
        event_stream.execute(events_query, events_params)

        group: list[dict[str, Any]] = []
        group_key = None
        group_wi_id = None
        for evt in event_stream:
            if scoped:
                scoped_event_count += 1
            else:
                chain_links.append(_chain_link(evt))
            # Group on the ordering key — that is what guarantees a group is
            # contiguous in the stream.  The work item id is carried alongside
            # for reporting; `entity_id` and `work_item_id` are the same value
            # for every event the append path can produce (migration 031
            # backfilled it and the `events_set_entity_id` trigger maintains
            # it), so these groups are the ones the previous
            # `ORDER BY work_item_id` produced.
            key = (evt["entity_kind"], evt["entity_id"])
            if group and key != group_key:
                assert group_key is not None
                _process_group(group_key[0], group_wi_id, group)
                group = []
            group_key = key
            group_wi_id = evt["work_item_id"]
            group.append(evt)
        if group:
            assert group_key is not None
            _process_group(group_key[0], group_wi_id, group)
        # Drop the last group before the global-chain phase, which only needs
        # the compact links.
        group = []

    if scoped and work_item_id not in wi_ids:
        halted_count += 1
        assert work_item_id is not None
        log.error(
            "replay.projection_row_missing",
            work_item_id=str(work_item_id),
            event_count=scoped_event_count,
        )
        store.add_report_entry(
            work_item_id,
            "halted",
            "events exist but projection row missing from work_items_current",
            0,
        )

    # WI-266: a projection row with NO rows in `events` was never visited by
    # the group loop — it was never compared at all, so a fabricated projection
    # row and a fully deleted event log both used to report a clean replay.
    # Diff the projection against the entity ids actually processed and halt on
    # every unvisited row.
    unvisited = wi_ids - processed_wi_ids
    for missing_id in sorted(unvisited, key=str):
        halted_count += 1
        log.error(
            "replay.projection_row_without_events",
            work_item_id=str(missing_id),
        )
        store.add_report_entry(
            missing_id,
            "halted",
            "projection row has no events in the event log",
            0,
        )

    if not scoped:
        head_row = conn.execute(
            SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE")
        ).fetchone()

        if not chain_links:
            # WI-266: no events at all, yet the head row still claims a head.
            # The head proves events were appended — a wholesale-deleted log
            # must be a hard halt, not a clean replay.
            if head_row is not None and head_row["head_hash"] is not None:
                halted_count += 1
                log.error(
                    "replay.global_chain_head_without_events",
                    detail=(
                        "event_chain_head.head_hash is set but the event log is "
                        "empty; the log was appended to and then deleted"
                    ),
                )
                store.add_report_entry(
                    uuid.UUID(int=0),
                    "halted",
                    "event_chain_head is set but no events remain in the log",
                    0,
                )
        else:
            chain_breaks, chain_tail = _verify_global_hash_chain(chain_links)
            total_chain_breaks += chain_breaks

            if chain_tail is not None:
                computed_head = _event_head_hash(chain_tail)
                if (
                    computed_head is not None
                    and head_row is not None
                    and head_row["head_hash"] is not None
                    and not _hmac.compare_digest(bytes(head_row["head_hash"]), computed_head)
                ):
                    total_chain_breaks += 1
                    log.warning(
                        "replay.global_chain_head_mismatch",
                        detail=(
                            "event_chain_head does not match the chain tail; "
                            "a tail event may have been deleted or the head tampered"
                        ),
                    )

    if scoped:
        log.info("replay.scoped_skips_global_verification", work_item_id=str(work_item_id))

    # NOTE (WI-217): nothing needs to be explicitly released here.  The
    # measured symptom — a container that grows ~2 GiB per replay and never
    # shrinks — is not a retained Python reference (tracemalloc shows ~0
    # net retention across successive replays, before and after this fix).
    # It is the allocator keeping a heap that replay's *peak* forced it to
    # grow: malloc_trim(0) after the fact returns it.  The fix is therefore
    # to never reach that peak, which the streaming above does; dropping
    # references at the end of this function would accomplish nothing.
    return ReplayReport(
        table_name=store.table_name,
        replayed_ok=ok_count,
        replayed_drift=drift_count,
        halted=halted_count,
        warnings=total_warnings,
        chain_breaks=total_chain_breaks,
        unverifiable=total_unverifiable,
        principal_binding_failures=total_principal_binding_failures,
        # A report may claim a binding check only when a verifier actually ran.
        # v6's acceptance-chain check is mandatory and independent of the legacy
        # principal_keys probe. A halt or an unresolved v6 binding invalidates the
        # claim even if an earlier work item verified cleanly.
        principal_binding_verified=(
            v6_binding_checked and v6_binding_verified and halted_count == 0
            if v6_binding_checked
            else verify_principal_binding and legacy_binding_checked and halted_count == 0
        ),
        non_work_item_groups_verified=non_work_item_groups,
        entries=store.report_entries(),
    )


def _parse_claim_expires(expires_str: str | None) -> datetime | None:
    if expires_str is None:
        return None
    try:
        return datetime.fromisoformat(expires_str)
    except (ValueError, TypeError):
        import structlog

        structlog.get_logger().warning(
            "replay.malformed_claim_expires",
            expires_str=expires_str,
        )
        return None


def _parse_not_before(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        import structlog

        structlog.get_logger().warning(
            "replay.malformed_not_before",
            value=str(value),
        )
        return None


def _requires_principal_registration(
    evt: dict[str, Any],
    asymmetric_schemes: frozenset[str],
    key_entry: Any = None,
) -> bool:
    """Does this event's scheme demand a registered principal key?

    Asymmetric schemes do: the whole point of a per-principal keypair is that
    the project's ``principal_keys`` names who may sign, and the offline
    verifier resolves signatures through that registry. Symmetric (HMAC)
    schemes do not — a shared HMAC key predates per-principal custody, and
    ``verify_principal_binding`` is documented as backward compatible with
    those deployments (WI-223).

    WI-267 / S2-interim: the scheme is taken from the **resolved key's**
    metadata, not from the row. ``scheme_id`` is outside every signed envelope
    version, so a row that relabels itself ``hmac-sha256`` used to opt itself
    out of the binding requirement entirely. The row's claim is now only a
    fallback for events whose key could not be resolved at all — and those are
    not verified either way.
    """
    derived = getattr(key_entry, "scheme", None)
    if derived is None:
        derived = evt.get("scheme_id") or "hmac-sha256"
    return derived in asymmetric_schemes


def _replay_work_item(
    conn: DictConn,
    wi_id: Any,
    events: list[dict[str, Any]],
    key_set: KeySet,
    continue_on_revoked: bool = False,
    *,
    verify_principal_binding: bool = False,
    referents: ReferentResolver,
) -> tuple[dict[str, Any], int, int, int, int, bool, bool, bool]:
    """Return replay state and binding-check outcomes.

    The tuple is ``(state, warnings, chain_breaks, principal_binding_failures,
    unverifiable, v6_binding_checked, v6_binding_verified,
    legacy_binding_checked)``. The counters remain deliberately distinct — see
    :class:`~regista._types.ReplayReport`. The two binding booleans prevent a caller
    from reporting a check merely because a project identity or a CLI flag exists.
    """
    state = None
    custom_fields: dict[str, Any] = {}
    needs_review = False
    not_before: datetime | None = None
    last_seq = 0
    attempt_number = 0
    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_coalesce_threshold: float = 0.0
    warnings = 0
    chain_breaks = 0
    principal_binding_failures = 0
    unverifiable = 0
    v6_binding_checked = False
    v6_binding_verified = True
    legacy_binding_checked = False

    _principal_key_cache: dict[str, list[Any]] = {}
    # Resolved once per work item rather than per event: the scheme registry is
    # mutable (tests register schemes), so this must not be a module constant,
    # but rebuilding it inside the event loop is needless work.
    if verify_principal_binding:
        from ._signing_scheme import asymmetric_scheme_ids

        _asym_schemes = asymmetric_scheme_ids()
    else:
        _asym_schemes = frozenset()

    prev_evt: dict[str, Any] | None = None
    for evt in events:
        transition = evt["transition"]
        last_seq = evt["event_seq"]

        ok, err = _verify_hash_chain(evt, prev_evt)
        if not ok:
            # WI-266: a broken per-work-item hash chain is a structural failure
            # (tampering verdict), counted as chain_breaks, not warnings.
            log.warning(
                "replay.hash_chain_broken",
                work_item_id=str(wi_id),
                event_id=str(evt["event_id"]),
                event_seq=evt["event_seq"],
                detail=err,
            )
            chain_breaks += 1

        key_entry = None
        unknown_key_skipped = False
        try:
            key_entry = key_set.verify_key_status(
                evt["key_id"],
                event_timestamp=(evt["timestamp"].isoformat() if evt.get("timestamp") else None),
            )
        except RegistaError as e:
            if e.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                key_entry = key_set.get_key(evt["key_id"])
                warnings += 1
                log.warning(
                    "replay.revoked_key_signature_verified",
                    work_item_id=str(wi_id),
                    event_id=str(evt["event_id"]),
                    event_seq=evt["event_seq"],
                    key_id=evt["key_id"],
                )
            elif e.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                unknown_key_skipped = True
                warnings += 1
                log.warning(
                    "replay.unknown_key_skipped",
                    work_item_id=str(wi_id),
                    event_id=str(evt["event_id"]),
                    event_seq=evt["event_seq"],
                    key_id=evt["key_id"],
                )
            else:
                raise

        if key_entry is not None:
            # WI-267: one primitive. The stored envelope is verified as-is and
            # every field it signs must agree with the row column replay is
            # about to apply — replay used to certify a history whose
            # transition/payload had been rewritten under an intact signature.
            verification = verify_event_strict(
                EventRow.from_mapping(evt),
                keys=KeySetResolver(key_set),
                referents=referents,
                policy=DEFAULT_POLICY,
            )
            if verification.envelope_version is EnvelopeVersion.V6:
                v6_binding_checked = True
                v6_binding_verified = (
                    v6_binding_verified and verification.principal_binding_verified
                )
            if verification.applicability is Applicability.INVALID:
                raise _ReplayHaltError(
                    f"Signature verification failed for event {evt['event_id']} "
                    f"at seq {evt['event_seq']}: {verification.summary()}",
                    chain_breaks=chain_breaks,
                    warnings=warnings,
                    unverifiable=unverifiable,
                )
            if not verification.accepted:
                # UNVERIFIABLE is an evidentiary gap, not an attack: a pre-002
                # row has no envelope to check against, so nothing *failed*.
                # Collapsing it into a halt would conflate "investigate a
                # database write attack" with "this record predates the
                # envelope column" — the exact collapse the result model
                # exists to prevent (CUTOVER-POLICY §2 vs §4).
                #
                # But a NULL envelope is also what `UPDATE events SET
                # canonical_envelope = NULL` produces, and the row still
                # carries the `signature` and `payload_canonical_hash` its
                # original envelope produced. Before WI-267 that attack halted
                # replay, because the rebuild-from-row candidate's signature
                # did not match; classifying it UNVERIFIABLE and continuing
                # would be strictly WEAKER than the code being replaced. So we
                # ask the retained crypto whether it can still be reconciled
                # with these column values at all. The probe convicts only —
                # it can never turn a failure into a pass (see
                # AbsentEnvelopeProbe) — so this branch can only ever make the
                # verdict stricter.
                if FailureReason.ENVELOPE_ABSENT in verification.reasons:
                    probe = probe_absent_envelope(
                        EventRow.from_mapping(evt), keys=KeySetResolver(key_set),
                    )
                    if probe is AbsentEnvelopeProbe.INCONSISTENT:
                        raise _ReplayHaltError(
                            f"Event {evt['event_id']} at seq {evt['event_seq']} "
                            "has no canonical_envelope, and no envelope this "
                            "row could have carried reproduces its retained "
                            "signature: the row contradicts its own "
                            "cryptographic material",
                            chain_breaks=chain_breaks,
                            warnings=warnings,
                            unverifiable=unverifiable,
                        )
                    unverifiable += 1
                    log.warning(
                        # Distinct and greppable: an auditor alerting on
                        # "part of the log was replayed with no cryptographic
                        # check" wants this event, not the warning bucket.
                        "replay.event_envelope_absent",
                        work_item_id=str(wi_id),
                        event_id=str(evt["event_id"]),
                        event_seq=evt["event_seq"],
                        probe=probe.value,
                        detail=verification.summary(),
                    )
                else:
                    unverifiable += 1
                    log.warning(
                        "replay.event_unverifiable",
                        work_item_id=str(wi_id),
                        event_id=str(evt["event_id"]),
                        event_seq=evt["event_seq"],
                        detail=verification.summary(),
                    )

        if unknown_key_skipped:
            # `continue_on_revoked` is a salvage option, not a verification result.
            # A skipped event leaves its signer/binding unresolved. Mark the v6
            # aggregate as evaluated-but-unverified so an epoch whose every event was
            # skipped cannot fall through to the legacy binding branch.
            v6_binding_checked = True
            v6_binding_verified = False

        # The legacy registry probe is a v1-v5 compatibility path. A v6 event's
        # principal binding is established by verify_event_strict over the
        # acceptance chain, never by consulting principal_keys.
        if verify_principal_binding and (
            key_entry is None or verification.envelope_version is not EnvelopeVersion.V6
        ):
            from ._principal_keys import list_principal_keys_for_conn

            actor_id = evt["actor_id"]
            if actor_id not in _principal_key_cache:
                try:
                    _principal_key_cache[actor_id] = list_principal_keys_for_conn(
                        conn, actor_id,
                    )
                except psycopg.errors.UndefinedTable:
                    _principal_key_cache[actor_id] = []
                    warnings += 1
                    log.warning(
                        "replay.principal_keys_table_missing",
                        work_item_id=str(wi_id),
                        event_id=str(evt["event_id"]),
                        event_seq=evt["event_seq"],
                        actor_id=actor_id,
                        detail="principal_keys table missing; principal binding skipped",
                    )
            pk_entries = _principal_key_cache[actor_id]
            # WI-223: "this actor has no keys registered at all" (skip, the
            # documented HMAC-only backward compatibility) and "this event was
            # signed with an asymmetric key this project never registered"
            # (fail) must not collapse into the same branch. A symmetric
            # (HMAC) event from an actor with no principal keys is a legacy
            # deployment; an asymmetric event from such an actor is an
            # unregistered signer — the chain is not attributable to anyone
            # this project can name, which is exactly what the offline bundle
            # verifier rejects.
            if pk_entries or _requires_principal_registration(
                evt, _asym_schemes, key_entry,
            ):
                legacy_binding_checked = True
                pb_result = verify_event_dict_principal_binding(evt, pk_entries)
                if not pb_result.verified:
                    warnings += 1
                    principal_binding_failures += 1
                    log.warning(
                        "replay.principal_binding_failed",
                        work_item_id=str(wi_id),
                        event_id=str(evt["event_id"]),
                        event_seq=evt["event_seq"],
                        actor_id=actor_id,
                        scheme_id=evt.get("scheme_id") or "hmac-sha256",
                        error=pb_result.error,
                    )

        if transition == "created":
            payload = evt["payload"] or {}
            state = payload.get("initial_state")
            custom_fields = payload.get("custom_fields", {})
            not_before = _parse_not_before(payload.get("not_before"))
        elif transition in (
            "link_created",
            "link_removed",
            "claim_acquired",
            "claim_stolen",
            "claim_released",
            "claim_expired",
            "claim_heartbeat",
            "hook_dead_lettered",
        ):
            if transition in ("claim_acquired", "claim_stolen"):
                attempt_number += 1
            if transition == "claim_acquired":
                payload = evt["payload"] or {}
                claimed_by = payload.get("actor_id")
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = _parse_claim_expires(expires_str)
            elif transition == "claim_stolen":
                payload = evt["payload"] or {}
                claimed_by = payload.get("new_actor_id")
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = _parse_claim_expires(expires_str)
            elif transition == "claim_heartbeat":
                payload = evt["payload"] or {}
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = _parse_claim_expires(expires_str)
                claim_coalesce_threshold = payload.get("coalesce_threshold") or 0.0
            elif transition in ("claim_released", "claim_expired"):
                claimed_by = None
                claim_expires_at = None
                claim_coalesce_threshold = 0.0
        elif transition == "escalated":
            needs_review = True
        elif transition == "not_before_set":
            payload = evt["payload"] or {}
            not_before = _parse_not_before(payload.get("not_before"))
        else:
            wf_row = conn.execute(
                SQL(
                    "SELECT definition FROM workflow_registry "
                    "WHERE workflow_name = %s AND version = %s"
                ),
                [evt["workflow_name"], evt["workflow_version"]],
            ).fetchone()
            if wf_row is None:
                raise _ReplayHaltError(
                    f"Missing workflow {evt['workflow_name']!r} v{evt['workflow_version']}",
                    chain_breaks=chain_breaks,
                    warnings=warnings,
                    unverifiable=unverifiable,
                )

            defn = wf_row["definition"]
            found = False
            for t in defn.get("transitions", []):
                if t["name"] == transition and t["from_state"] == state:
                    state = t["to_state"]
                    found = True
                    break
            if not found:
                name_matches = any(t["name"] == transition for t in defn.get("transitions", []))
                if name_matches:
                    raise _ReplayHaltError(
                        f"Transition {transition!r} exists but not valid from state {state!r}",
                        chain_breaks=chain_breaks,
                        warnings=warnings,
                        unverifiable=unverifiable,
                    )
                warnings += 1
                log.warning(
                    "replay.unknown_transition",
                    work_item_id=str(wi_id),
                    event_id=str(evt["event_id"]),
                    event_seq=evt["event_seq"],
                    transition=transition,
                )

            if found:
                payload = evt["payload"] or {}
                if payload.get("custom_fields_update"):
                    custom_fields = {**custom_fields, **payload["custom_fields_update"]}
                claimed_by = None
                claim_expires_at = None

        prev_evt = evt

    return (
        {
            "current_state": state,
            "custom_fields": custom_fields,
            "needs_review": needs_review,
            "not_before": not_before,
            "last_event_seq": last_seq,
            "attempt_number": attempt_number,
            "claimed_by": claimed_by,
            "claim_expires_at": claim_expires_at,
            "claim_coalesce_threshold": claim_coalesce_threshold,
        },
        warnings,
        chain_breaks,
        principal_binding_failures,
        unverifiable,
        v6_binding_checked,
        v6_binding_verified,
        legacy_binding_checked,
    )


def _states_match(replayed: dict[str, Any], live: dict[str, Any]) -> bool:
    if replayed["current_state"] != live["current_state"]:
        return False
    if replayed["last_event_seq"] != live["last_event_seq"]:
        return False
    if replayed["custom_fields"] != live["custom_fields"]:
        return False
    if replayed["needs_review"] != live["needs_review"]:
        return False
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        return False
    if replayed["attempt_number"] != live["attempt_number"]:
        return False
    if replayed["claimed_by"] != live["claimed_by"]:
        return False
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(
        replayed["claim_expires_at"],
        live["claim_expires_at"],
        threshold,
    ):
        return False
    return True


def _diff_fields(replayed: dict[str, Any], live: dict[str, Any]) -> list[str]:
    diffs: list[str] = []
    if replayed["current_state"] != live["current_state"]:
        diffs.append("current_state")
    if replayed["last_event_seq"] != live["last_event_seq"]:
        diffs.append("last_event_seq")
    if replayed["custom_fields"] != live["custom_fields"]:
        diffs.append("custom_fields")
    if replayed["needs_review"] != live["needs_review"]:
        diffs.append("needs_review")
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        diffs.append("not_before")
    if replayed["attempt_number"] != live["attempt_number"]:
        diffs.append("attempt_number")
    if replayed["claimed_by"] != live["claimed_by"]:
        diffs.append("claimed_by")
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(
        replayed["claim_expires_at"],
        live["claim_expires_at"],
        threshold,
    ):
        diffs.append("claim_expires_at")
    return diffs
