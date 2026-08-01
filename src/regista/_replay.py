from __future__ import annotations

import contextlib
import hmac as _hmac
import uuid
from datetime import datetime

import psycopg
import structlog
from psycopg.sql import SQL, Identifier

from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._signing import verify_event, verify_event_dict_principal_binding
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import ReplayReport

log = structlog.get_logger()


def drop_old_replay_tables(conn: psycopg.Connection, schema: str) -> None:
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


def _drop_replay_tables(conn: psycopg.Connection, *table_names: str) -> None:
    for name in table_names:
        conn.execute(SQL("DROP TABLE IF EXISTS {}").format(Identifier(name)))


# AC-28: event hash chain verification (BC-233)
def _verify_hash_chain(
    event: dict,
    prev_event: dict | None,
) -> tuple[bool, str]:
    expected = event.get("prev_event_hash")
    if expected is None:
        return True, ""
    if prev_event is None:
        return False, "prev_event_hash set but no previous event"
    prev_env = prev_event.get("canonical_envelope")
    prev_sig = prev_event.get("signature")
    if prev_env is None or prev_sig is None:
        return False, "previous event missing canonical_envelope or signature"
    from ._signing_scheme import resolve_hash_function

    hash_fn = resolve_hash_function("sha-256")
    computed = hash_fn(bytes(prev_env) + bytes(prev_sig)).digest()
    if not _hmac.compare_digest(computed, bytes(expected)):
        detail = f"hash chain mismatch: computed={computed.hex()} expected={bytes(expected).hex()}"
        return False, detail
    return True, ""


def _event_head_hash(evt: dict) -> bytes | None:
    """Return the chain head hash an event contributes, or ``None``.

    Accepts either a pre-computed ``head_hash`` (the compact chain-link
    records the streaming replay builds — WI-217) or the raw
    ``canonical_envelope``/``signature`` pair, so the chain walk can be
    driven either from link records or from full event rows (unit tests
    construct the latter directly).

    The chain-link digest is SHA-256 unconditionally — NOT the event's own
    ``hash_alg``.  ``hash_alg`` selects the digest used inside the signing
    envelope; the append path hard-codes SHA-256 for both chain links
    (``_event_store`` computes ``prev_event_hash`` and the global chain head
    that way), so the verifier must too or every link would mismatch on an
    event signed with a non-default ``hash_alg``.
    """
    precomputed = evt.get("head_hash")
    if precomputed is not None:
        return precomputed if isinstance(precomputed, bytes) else bytes(precomputed)
    env = evt.get("canonical_envelope")
    sig = evt.get("signature")
    if env is None or sig is None:
        return None
    return resolve_hash_function("sha-256")(bytes(env) + bytes(sig)).digest()


def _chain_link(evt: dict) -> dict:
    """Reduce an event row to the fields the global chain walk needs.

    The head hash is computed here so the row's envelope, signature and
    payload can be released with the rest of its work item's group instead
    of being pinned until the whole project has been replayed (WI-217).

    The walk needs exactly four things per event: its identity (for cycle
    and reachability bookkeeping), its ``global_seq`` (warning detail and
    the timestamp-coverage cross-check), the link it claims to chain from,
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
    events: list[dict],
    segments: list[dict] | None = None,
) -> tuple[int, dict | None]:
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

    When *segments* is provided, sealed segment records are used to bridge
    across archived ranges.  A segment whose ``first_event_prev_hash``
    matches the current head hash lets the walk jump to
    ``segment.head_hash`` and continue, preventing orphan warnings when
    older events have been sealed and potentially archived.  Segments can
    be chained iteratively, and a segment with a NULL
    ``first_event_prev_hash`` can stand in for an archived genesis event.

    Returns ``(warning_count, chain_tail)`` where *chain_tail* is the last
    live event reached by the walk (or ``None`` if the event list is empty).
    """
    from collections import defaultdict

    if not events:
        return 0, None

    seg_by_prev: dict[str, dict] = {}
    if segments:
        for seg in segments:
            feph = seg.get("first_event_prev_hash")
            key = bytes(feph).hex() if feph is not None else ""
            seg_by_prev[key] = seg

    link_map: dict[str, list[dict]] = defaultdict(list)
    genesis_events: list[dict] = []
    for evt in events:
        expected = evt.get("prev_global_event_hash")
        if expected is None:
            genesis_events.append(evt)
        else:
            link_map[bytes(expected).hex()].append(evt)

    warnings = 0

    # Multiple genesis events (NULL prev_global_event_hash) mean a fork or
    # corruption. Which one is the canonical chain start must not depend on the
    # arbitrary order of the input list (WI-219): pick the lowest global_seq,
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
            warnings += 1
            log.warning(
                "replay.global_chain_multiple_genesis",
                event_id=str(g["event_id"]),
                global_seq=g.get("global_seq"),
            )

    current_head_hex = ""
    start_from_segment = False

    if not genesis_events:
        genesis_seg = seg_by_prev.get("")
        if genesis_seg is None:
            for evt in events:
                warnings += 1
                log.warning(
                    "replay.global_chain_orphan",
                    event_id=str(evt["event_id"]),
                    global_seq=evt.get("global_seq"),
                    detail="no genesis event and no segment bridges from genesis",
                )
            return warnings, None
        current_head_hex = bytes(genesis_seg["head_hash"]).hex()
        start_from_segment = True

    visited_events: set = set()
    visited_segments: set = set()
    last_event: dict | None = None
    current: dict | None = genesis_events[0] if genesis_events else None

    while True:
        if start_from_segment:
            successors = link_map.get(current_head_hex, [])
            if not successors:
                bridging_seg = seg_by_prev.get(current_head_hex)
                if bridging_seg is None:
                    break
                seg_id = bridging_seg.get("segment_id")
                if seg_id in visited_segments:
                    warnings += 1
                    log.warning(
                        "replay.global_chain_segment_cycle",
                        segment_id=str(seg_id),
                    )
                    break
                visited_segments.add(seg_id)
                current_head_hex = bytes(bridging_seg["head_hash"]).hex()
                continue
            start_from_segment = False
            current = successors[0]
            if len(successors) > 1:
                for s in successors[1:]:
                    warnings += 1
                    log.warning(
                        "replay.global_chain_fork",
                        event_id=str(s["event_id"]),
                        global_seq=s.get("global_seq"),
                        detail="multiple events chain from segment head",
                    )

        if current is None:
            break

        eid = current["event_id"]
        if eid in visited_events:
            warnings += 1
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
            bridging_seg = seg_by_prev.get(head_hash.hex())
            if bridging_seg is None:
                break
            seg_id = bridging_seg.get("segment_id")
            if seg_id in visited_segments:
                warnings += 1
                log.warning(
                    "replay.global_chain_segment_cycle",
                    segment_id=str(seg_id),
                )
                break
            visited_segments.add(seg_id)
            current_head_hex = bytes(bridging_seg["head_hash"]).hex()
            start_from_segment = True
            continue

        if len(successors) > 1:
            for s in successors[1:]:
                warnings += 1
                log.warning(
                    "replay.global_chain_fork",
                    event_id=str(s["event_id"]),
                    global_seq=s.get("global_seq"),
                    detail=f"multiple events chain from event {eid}",
                )

        current = successors[0]

    for evt in events:
        if evt["event_id"] not in visited_events:
            warnings += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt["event_id"]),
                global_seq=evt.get("global_seq"),
                detail="event not reachable from genesis via prev_global_event_hash links",
            )

    return warnings, last_event


class _ReplayHaltError(RegistaError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.REPLAY_HALTED, message)


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
# set before psycopg sees row one, so `SELECT ... FROM events` costs the
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
# Client-side working set: one fetch block, plus the widest single entity's
# history, plus one compact chain link per event.
#
# The chain index is the term that still grows with the log, so it is worth
# being precise about, and the answer depends on what you charge to it.  A link
# allocates 258 B of fresh memory (measured: tracemalloc delta while building
# the index over 6000 real rows) — the dict plus the two 32-byte digests.  It
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
# scale, which a deployment with `temp_file_limit` set would abort on);
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
    conn: psycopg.Connection,
    schema: str,
    project: str,
    key_set: KeySet,
    continue_on_revoked: bool = False,
    verify_timestamps: bool = False,
    verify_principal_binding: bool = False,
    work_item_id: uuid.UUID | None = None,
) -> ReplayReport:
    import uuid as _uuid

    tag = _uuid.uuid4().hex[:8]
    replay_table = f"work_items_current_replay_{tag}"
    report_table = f"replay_report_{tag}"

    conn.execute(
        SQL("CREATE TABLE {} AS SELECT * FROM work_items_current WHERE 1=0").format(
            Identifier(replay_table)
        )
    )
    conn.execute(
        SQL(
            "CREATE TABLE {} ("
            "work_item_id UUID PRIMARY KEY, "
            "category TEXT NOT NULL, "
            "detail TEXT, "
            "warnings INTEGER NOT NULL DEFAULT 0)"
        ).format(Identifier(report_table))
    )

    try:
        return _replay_inner(
            conn,
            schema,
            project,
            key_set,
            replay_table,
            report_table,
            continue_on_revoked=continue_on_revoked,
            verify_timestamps=verify_timestamps,
            verify_principal_binding=verify_principal_binding,
            work_item_id=work_item_id,
        )
    except Exception:
        _drop_replay_tables(conn, replay_table, report_table)
        raise


def _replay_inner(
    conn: psycopg.Connection,
    schema: str,
    project: str,
    key_set: KeySet,
    replay_table: str,
    report_table: str,
    *,
    continue_on_revoked: bool = False,
    verify_timestamps: bool = False,
    verify_principal_binding: bool = False,
    work_item_id: uuid.UUID | None = None,
) -> ReplayReport:
    scoped = work_item_id is not None

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
    # connection for the rest of the call — don't keep the row list alive
    # alongside it (WI-217).
    del wi_rows

    ok_count = 0
    drift_count = 0
    halted_count = 0
    total_warnings = 0
    total_principal_binding_failures = 0

    # WI-217: the event log is streamed one entity at a time through a
    # server-side cursor, so the replay working set is bounded by the widest
    # single entity's history plus a fetch block, not by the size of the
    # project's whole event log.  The only per-event state that outlives a
    # group is the compact chain link below, which carries a pre-computed
    # head hash instead of the envelope, signature and payload.  See
    # _EVENT_STREAM_SIZE / _EVENT_STREAM_ORDER for the full cost, including
    # the server side — the ordering is load bearing for both.
    chain_links: list[dict] = []
    scoped_event_count = 0

    def _handle_orphan_group(orphan_id, orphan_evts: list[dict]) -> None:
        nonlocal halted_count, total_warnings

        is_non_work_item = any(
            e.get("entity_kind", "work_item") != "work_item"
            for e in orphan_evts
        )
        if is_non_work_item:
            total_warnings += 1
            log.info(
                "replay.non_work_item_entity",
                entity_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
            return
        is_created = len(orphan_evts) > 0 and orphan_evts[0]["transition"] == "created"
        if not is_created:
            halted_count += 1
            log.error(
                "replay.orphan_events",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [
                    orphan_id,
                    "halted",
                    "Orphaned events with no work_item and no created event",
                    0,
                ],
            )
        else:
            total_warnings += 1
            log.warning(
                "replay.orphan_work_item",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )

    def _process_group(entity_kind, wi_id, events: list[dict]) -> None:
        nonlocal ok_count, drift_count, halted_count
        nonlocal total_warnings, total_principal_binding_failures

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

        try:
            replayed_state, wi_warnings, wi_pb_failures = _replay_work_item(
                conn,
                wi_id,
                events,
                key_set,
                continue_on_revoked,
                verify_principal_binding=verify_principal_binding,
            )
            total_warnings += wi_warnings
            total_principal_binding_failures += wi_pb_failures
        except _ReplayHaltError as e:
            halted_count += 1
            log.error("replay.halted", work_item_id=str(wi_id), error=str(e))
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "halted", str(e), 0],
            )
            return
        except Exception as e:
            halted_count += 1
            log.error(
                "replay.unexpected_error",
                work_item_id=str(wi_id),
                error=str(e),
                exc_info=True,
            )
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "halted", f"unexpected: {e}", 0],
            )
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

        if _states_match(replayed_state, live_row):
            ok_count += 1
            conn.execute(
                SQL("INSERT INTO {} (work_item_id, category, warnings) VALUES (%s, %s, %s)").format(
                    Identifier(report_table)
                ),
                [wi_id, "replayed_ok", wi_warnings],
            )
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
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "replayed_drift", detail, wi_warnings],
            )

        conn.execute(
            SQL(
                "INSERT INTO {} (work_item_id, workflow_name, workflow_version, "
                "work_item_type, current_state, custom_fields, needs_review, "
                "not_before, last_event_seq, last_event_at, next_event_seq, "
                "claimed_by, claim_expires_at, attempt_number) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ).format(Identifier(replay_table)),
            [
                wi_id,
                live_row["workflow_name"],
                live_row["workflow_version"],
                live_row["work_item_type"],
                replayed_state["current_state"],
                psycopg.types.json.Jsonb(replayed_state["custom_fields"]),
                replayed_state["needs_review"],
                replayed_state["not_before"],
                replayed_state["last_event_seq"],
                None,
                replayed_state["last_event_seq"] + 1,
                replayed_state["claimed_by"],
                replayed_state["claim_expires_at"],
                replayed_state["attempt_number"],
            ],
        )

    if scoped:
        # A scoped replay's Sort is bounded by the one entity's history, which
        # the working set already accounts for, so it does not need the index
        # ordering.  It is left on `work_item_id` so the reported
        # `event_count` keeps counting exactly the rows the old query saw.
        events_query = SQL(
            f"SELECT {_EVENT_FIELDS} FROM events WHERE work_item_id = %s ORDER BY event_seq"
        )
        events_params: list | None = [work_item_id]
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

        group: list[dict] = []
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
                _process_group(group_key[0], group_wi_id, group)
                group = []
            group_key = key
            group_wi_id = evt["work_item_id"]
            group.append(evt)
        if group:
            _process_group(group_key[0], group_wi_id, group)
        # Drop the last group before the global-chain phase, which only needs
        # the compact links.
        group = []

    if scoped and work_item_id not in wi_ids:
        halted_count += 1
        log.error(
            "replay.projection_row_missing",
            work_item_id=str(work_item_id),
            event_count=scoped_event_count,
        )
        conn.execute(
            SQL(
                "INSERT INTO {} (work_item_id, category, detail, warnings) VALUES (%s, %s, %s, %s)"
            ).format(Identifier(report_table)),
            [
                work_item_id,
                "halted",
                "events exist but projection row missing from work_items_current",
                0,
            ],
        )

    if not scoped:
        segment_rows: list[dict] = []
        try:
            segment_rows = conn.execute(
                SQL(
                    "SELECT segment_id, first_event_prev_hash, head_hash "
                    "FROM event_segments ORDER BY first_global_seq"
                )
            ).fetchall()
        except psycopg.errors.UndefinedTable:
            pass

        chain_warnings, chain_tail = _verify_global_hash_chain(
            chain_links, segments=segment_rows if segment_rows else None,
        )
        total_warnings += chain_warnings

        if chain_tail is not None:
            computed_head = _event_head_hash(chain_tail)
            if computed_head is not None:
                head_row = conn.execute(
                    SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE")
                ).fetchone()
                if (
                    head_row is not None
                    and head_row["head_hash"] is not None
                    and not _hmac.compare_digest(bytes(head_row["head_hash"]), computed_head)
                ):
                    total_warnings += 1
                    log.warning(
                        "replay.global_chain_head_mismatch",
                        detail=(
                            "event_chain_head does not match the chain tail; "
                            "a tail event may have been deleted or the head tampered"
                        ),
                    )

    if verify_timestamps and not scoped:
        from ._timestamping import TSAConfig, compute_merkle_root, verify_tsa_token

        batch_rows = conn.execute(
            "SELECT first_global_seq, last_global_seq, merkle_root, tsa_token "
            "FROM tsp_batches WHERE status = 'confirmed'"
        ).fetchall()

        event_ids_by_global_seq: dict[int, uuid.UUID] = {
            link["global_seq"]: link["event_id"] for link in chain_links
        }

        _verify_cfg = TSAConfig(tsa_url="")
        covered: set[int] = set()
        for br in batch_rows:
            first_seq = br["first_global_seq"]
            last_seq = br["last_global_seq"]
            for seq in range(first_seq, last_seq + 1):
                covered.add(seq)

            stored_root = bytes(br["merkle_root"]) if br["merkle_root"] else None
            tsa_token = bytes(br["tsa_token"]) if br["tsa_token"] else None

            current_leaf_ids: list[uuid.UUID] = []
            for s in range(first_seq, last_seq + 1):
                if s in event_ids_by_global_seq:
                    current_leaf_ids.append(event_ids_by_global_seq[s])
            if stored_root is not None and current_leaf_ids:
                recomputed = compute_merkle_root(current_leaf_ids)
                if not _hmac.compare_digest(recomputed, stored_root):
                    total_warnings += 1
                    log.warning(
                        "replay.merkle_root_mismatch",
                        first_seq=first_seq,
                        last_seq=last_seq,
                        recomputed=recomputed.hex(),
                        stored=stored_root.hex(),
                    )

            if tsa_token and stored_root:
                if not verify_tsa_token(tsa_token, stored_root, _verify_cfg):
                    total_warnings += 1
                    log.warning(
                        "replay.invalid_tsa_token",
                        first_seq=first_seq,
                        last_seq=last_seq,
                    )
            else:
                total_warnings += 1
                log.warning(
                    "replay.missing_tsa_token",
                    first_seq=first_seq,
                    last_seq=last_seq,
                )
        uncovered = []
        for link in chain_links:
            seq = link["global_seq"]
            if seq not in covered:
                uncovered.append(seq)
        if uncovered:
            total_warnings += len(uncovered)
            log.warning(
                "replay.uncovered_events",
                count=len(uncovered),
                sample=uncovered[:10],
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
        table_name=replay_table,
        replayed_ok=ok_count,
        replayed_drift=drift_count,
        halted=halted_count,
        warnings=total_warnings,
        principal_binding_failures=total_principal_binding_failures,
        principal_binding_verified=verify_principal_binding,
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
    evt: dict, asymmetric_schemes: frozenset[str],
) -> bool:
    """Does this event's scheme demand a registered principal key?

    Asymmetric schemes do: the whole point of a per-principal keypair is that
    the project's ``principal_keys`` names who may sign, and the offline
    verifier resolves signatures through that registry. Symmetric (HMAC)
    schemes do not — a shared HMAC key predates per-principal custody, and
    ``verify_principal_binding`` is documented as backward compatible with
    those deployments (WI-223).
    """
    return (evt.get("scheme_id") or "hmac-sha256") in asymmetric_schemes


def _replay_work_item(
    conn: psycopg.Connection,
    wi_id,
    events: list[dict],
    key_set: KeySet,
    continue_on_revoked: bool = False,
    *,
    verify_principal_binding: bool = False,
) -> tuple[dict, int, int]:
    state = None
    custom_fields: dict = {}
    needs_review = False
    not_before: datetime | None = None
    last_seq = 0
    attempt_number = 0
    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_coalesce_threshold: float = 0.0
    warnings = 0
    principal_binding_failures = 0

    _principal_key_cache: dict[str, list] = {}
    # Resolved once per work item rather than per event: the scheme registry is
    # mutable (tests register schemes), so this must not be a module constant,
    # but rebuilding it inside the event loop is needless work.
    if verify_principal_binding:
        from ._signing_scheme import asymmetric_scheme_ids

        _asym_schemes = asymmetric_scheme_ids()
    else:
        _asym_schemes = frozenset()

    prev_evt: dict | None = None
    for evt in events:
        transition = evt["transition"]
        last_seq = evt["event_seq"]

        ok, err = _verify_hash_chain(evt, prev_evt)
        if not ok:
            log.warning(
                "replay.hash_chain_broken",
                work_item_id=str(wi_id),
                event_id=str(evt["event_id"]),
                event_seq=evt["event_seq"],
                detail=err,
            )
            warnings += 1

        key_entry = None
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
            scheme = get_scheme(evt.get("scheme_id", "hmac-sha256"))
            verify_key = key_entry.secret
            if scheme.scheme_id == "ed25519" and key_entry.public_key:
                verify_key = key_entry.public_key
            if not verify_event(
                event_id=evt["event_id"],
                work_item_id=evt["work_item_id"],
                actor_id=evt["actor_id"],
                key_id=evt["key_id"],
                event_seq=evt["event_seq"],
                workflow_name=evt["workflow_name"],
                workflow_version=evt["workflow_version"],
                timestamp=evt["timestamp"],
                transition=evt["transition"],
                payload=evt["payload"],
                signature=bytes(evt["signature"]),
                canonical_hash=bytes(evt["payload_canonical_hash"]),
                key=verify_key,
                stored_envelope=(
                    bytes(evt["canonical_envelope"]) if evt["canonical_envelope"] else None
                ),
                on_behalf_of=evt["on_behalf_of"],
                scheme=scheme,
                entity_kind=evt.get("entity_kind", "work_item"),
                hash_alg=evt.get("hash_alg", "sha-256"),
                prev_event_hash=(
                    bytes(evt["prev_event_hash"]) if evt.get("prev_event_hash") else None
                ),
                prev_global_event_hash=(
                    bytes(evt["prev_global_event_hash"])
                    if evt.get("prev_global_event_hash")
                    else None
                ),
                actor_kind=evt.get("actor_kind"),
                actor_metadata=evt.get("actor_metadata"),
            ):
                raise _ReplayHaltError(
                    f"Signature verification failed for event {evt['event_id']} "
                    f"at seq {evt['event_seq']}"
                )

        if verify_principal_binding:
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
            if pk_entries or _requires_principal_registration(evt, _asym_schemes):
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
                    f"Missing workflow {evt['workflow_name']!r} v{evt['workflow_version']}"
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
                        f"Transition {transition!r} exists but not valid from state {state!r}"
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

    return {
        "current_state": state,
        "custom_fields": custom_fields,
        "needs_review": needs_review,
        "not_before": not_before,
        "last_event_seq": last_seq,
        "attempt_number": attempt_number,
        "claimed_by": claimed_by,
        "claim_expires_at": claim_expires_at,
        "claim_coalesce_threshold": claim_coalesce_threshold,
    }, warnings, principal_binding_failures


def _states_match(replayed: dict, live: dict) -> bool:
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


def _diff_fields(replayed: dict, live: dict) -> list[str]:
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
