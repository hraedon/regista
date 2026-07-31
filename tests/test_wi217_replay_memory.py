"""WI-217 — a full replay must not materialize the whole event log.

The reported symptom was a container that grew ~2 GiB per full replay and
never gave it back (102 MiB -> 2.09 GiB -> 4.07 GiB over two rounds).  The
cause is not a retained reference: tracemalloc shows ~0 net retention across
successive replays both before and after the fix, and ``malloc_trim(0)``
hands the memory straight back.  It is the allocator holding a heap that
replay's *peak* forced it to grow, because replay loaded every event row for
the whole project at once.  So the property to defend is the peak, and these
tests measure exactly that.

Two assertions carry the weight:

1. **The peak does not track the log size.**  The same project is replayed at
   two log sizes an order of magnitude apart in one process.  Streaming keeps
   the peak roughly flat; materializing the log multiplies it by the growth
   factor.  This is dimensionless, so it does not depend on the row widths or
   the interpreter's allocation behaviour on any given machine.
2. **The peak stays under half of what materializing the log would cost.**
   Each event's payload is stored once in ``payload`` and again inside
   ``canonical_envelope``, so loading the log costs at least
   ``2 * PAYLOAD_BYTES`` per event; the bound below is half of that.

Measured on this seeding, pre-fix vs post-fix:

    (1) peak growth for an 8x log:  7.7x  ->  1.5x   (budget 3.0x)
    (2) peak on the 8x log:      13.56 MiB -> 2.59 MiB (budget 5.00 MiB)

so each limit sits ~2.6x below the pre-fix measurement and ~2x above the
post-fix one.

tracemalloc peaks are used rather than RSS on purpose: they count Python
allocations directly, so they are reproducible to within ~0.01 MiB run to run,
where RSS depends on glibc arena behaviour and is not a stable gate.

What these tests do NOT cover is the *server* side of the same bound. A
`DECLARE CURSOR` over a plan containing a Sort makes Postgres materialize the
whole sorted result and hold it in `pgsql_tmp` for the cursor's lifetime, so a
streaming client can be paid for out of server temp space instead. That is why
`_EVENT_STREAM_ORDER` is pinned to the columns of `idx_events_entity`; the
guard for it is a plan assertion, not a memory measurement, and lives in
`test_wi217_stream_plan_has_no_sort` below.

This module runs ~23s, which makes it the slowest test in the default gate,
and it is deliberately NOT marked `slow`: `addopts = -m 'not slow'` means a
marked test never runs in CI, and a memory guard that never runs is no guard.
`test_doctor` at ~17s is the existing unmarked precedent.
"""

from __future__ import annotations

import gc
import random
import tracemalloc
import uuid

import pytest
import structlog
from _helpers import DSN, KEY_PATH, WORKFLOW_PATH

from regista.testing import drop_project_schema

# 8 work items, then 64 — an 8x log with an unchanged widest work item, which
# is the dimension a streaming replay is supposed to be insensitive to.
ITEMS_SMALL = 8
ITEMS_BIG = 64
EVENTS_PER_ITEM = 20
PAYLOAD_BYTES = 4096
ROUNDS = 3

# The peak may grow by at most this factor when the log grows 8x. Streaming
# measures 1.5x (a fixed fetch block plus the compact chain index, which is
# ~0.5 KiB per event); loading the log measures 7.7x.
MAX_PEAK_GROWTH = 3.0

# Round-to-round peak variation. tracemalloc peaks are stable to ~0.01 MiB;
# 1.25 is loose enough never to flake and tight enough to catch a per-round
# accumulation.
MAX_PEAK_JITTER = 1.25

# Net tracemalloc retention allowed across all rounds. This has never been the
# failing property (it measures ~20 KiB pre-fix too) — it is a regression guard
# against someone parking the event log on a module or instance attribute.
MAX_RETAINED_BYTES = 1 << 20


def _append_events(sub, items, rng):
    """Append EVENTS_PER_ITEM - 1 raw events to each work item in *items*.

    Payloads are incompressible so the rows cost in memory what they claim to;
    the transition names are deliberately outside the workflow, which is the
    ordinary shape of a raw appended event (every reserved transition name is
    rejected by ``append_event``). Each such event costs one predictable
    ``replay.unknown_transition`` warning.
    """
    for wi_id in items:
        for j in range(EVENTS_PER_ITEM - 1):
            sub.append_event(
                wi_id,
                "agent-1",
                transition=f"wi217_note_{j}",
                payload={"note": rng.randbytes(PAYLOAD_BYTES // 2).hex(), "seq": j},
            )


def _create_items(sub, count, start):
    ids = []
    for i in range(count):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": f"wi217 item {start + i}"},
        )
        ids.append(wi.work_item_id)
    return ids


@pytest.fixture(scope="module")
def seeded():
    """A project seeded to ITEMS_SMALL, which tests grow to ITEMS_BIG.

    Growing one project in place (rather than seeding two) keeps the schema,
    connection pool, prepared statements and key set identical between the two
    measurements, so the only thing that changes is the size of the log.

    structlog is muted for the duration: replay emits one warning per raw
    event, and rendering ~5k log lines would both dominate the runtime and add
    allocation noise to the measurement.
    """
    from regista import Regista

    saved_log_config = structlog.get_config()
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(50))

    project = f"test_wi217_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        rng = random.Random(217)
        _append_events(sub, _create_items(sub, ITEMS_SMALL, 0), rng)
        state = {"sub": sub, "project": project, "rng": rng, "items": ITEMS_SMALL}
        yield state
    finally:
        sub.close()
        drop_project_schema(DSN, project)
        structlog.configure(**saved_log_config)


def _grow_to_big(state):
    """Grow the seeded project to ITEMS_BIG. Idempotent, so tests may order freely."""
    if state["items"] >= ITEMS_BIG:
        return
    extra = ITEMS_BIG - state["items"]
    _append_events(
        state["sub"], _create_items(state["sub"], extra, state["items"]), state["rng"]
    )
    state["items"] = ITEMS_BIG


def _replay_peaks(sub, rounds, expected_items):
    """Replay *rounds* times, returning (peak bytes per round, net retained).

    tracemalloc is stopped outside this call so seeding is not slowed by the
    allocation hook; peaks are per-round via reset_peak.
    """
    sub.replay()  # warm-up: lazy imports, pool, prepared statements
    gc.collect()

    tracemalloc.start(1)
    try:
        peaks = []
        baseline = None
        for _ in range(rounds):
            tracemalloc.reset_peak()
            report = sub.replay()
            assert report.halted == 0, f"replay halted: {report}"
            assert report.replayed_ok == expected_items, report
            assert report.replayed_drift == 0, report
            # One warning per raw appended event, and nothing else: proof the
            # streamed walk still sees every event and finds no chain damage.
            assert report.warnings == expected_items * (EVENTS_PER_ITEM - 1), report
            del report
            gc.collect()
            current, peak = tracemalloc.get_traced_memory()
            peaks.append(peak)
            if baseline is None:
                baseline = current
        return peaks, current - baseline
    finally:
        tracemalloc.stop()


class TestWI217ReplayMemory:
    def test_replay_peak_does_not_track_log_size(self, seeded):
        sub = seeded["sub"]

        if seeded["items"] != ITEMS_SMALL:
            pytest.skip("log already grown by another test; small measurement unavailable")

        small_peaks, _ = _replay_peaks(sub, ROUNDS, ITEMS_SMALL)

        _grow_to_big(seeded)
        big_peaks, retained = _replay_peaks(sub, ROUNDS, ITEMS_BIG)

        small_peak = max(small_peaks)
        big_peak = max(big_peaks)
        growth_factor = ITEMS_BIG / ITEMS_SMALL

        # (1) The peak must not scale with the log.
        assert big_peak < small_peak * MAX_PEAK_GROWTH, (
            f"log grew {growth_factor:.0f}x ({ITEMS_SMALL} -> {ITEMS_BIG} work items) and "
            f"replay's peak grew {big_peak / small_peak:.1f}x "
            f"({small_peak / 1048576:.2f} -> {big_peak / 1048576:.2f} MiB); "
            f"budget is {MAX_PEAK_GROWTH:.1f}x. The event log looks like it is being "
            "materialized rather than streamed (WI-217)"
        )

        # (2) The peak must stay well under the cost of holding the log. Each
        # payload is stored twice (in `payload` and inside `canonical_envelope`),
        # so materializing costs >= 2 * PAYLOAD_BYTES per event; allow half.
        n_events_big = ITEMS_BIG * EVENTS_PER_ITEM
        budget = n_events_big * PAYLOAD_BYTES
        assert big_peak < budget, (
            f"replay peaked at {big_peak / 1048576:.2f} MiB on a {n_events_big}-event log "
            f"whose payloads alone cost at least {2 * budget / 1048576:.2f} MiB to "
            f"materialize; budget is {budget / 1048576:.2f} MiB (WI-217)"
        )

        # (3) Per-round peaks must be flat: nothing carried between rounds.
        assert max(big_peaks) < min(big_peaks) * MAX_PEAK_JITTER, (
            f"per-round peaks vary more than {MAX_PEAK_JITTER}x: "
            f"{[round(p / 1048576, 2) for p in big_peaks]} MiB — replay appears to "
            "accumulate state across invocations (WI-217)"
        )

        # (4) Regression guard on retention proper. Not the original defect (see
        # module docstring), but the invariant the work item asks for.
        assert retained < MAX_RETAINED_BYTES, (
            f"{ROUNDS} replays retained {retained / 1048576:.2f} MiB of live Python "
            f"objects (budget {MAX_RETAINED_BYTES / 1048576:.2f} MiB); replay is holding "
            "onto its working set (WI-217)"
        )

    def test_stream_plan_has_no_sort(self, seeded):
        """The streamed scan must plan as an ordered index scan, not a Sort.

        This is the server half of the bound, and it is not visible to any
        client-side memory measurement. `DECLARE CURSOR` over a plan containing
        a Sort makes Postgres materialize the whole sorted result before it
        yields row one and hold it in `pgsql_tmp` until the cursor closes — for
        the entire replay, where `fetchall()` only held it for the drain. So a
        change to `_EVENT_STREAM_ORDER` that drops off the index columns would
        move the peak from the client to the server's temp volume, which is a
        worse failure (a deployment with `temp_file_limit` set aborts) and one
        that no assertion on tracemalloc could catch.

        Measured on a 6000-row / 8.3 MiB events table: ordering by
        `work_item_id, event_seq` plans as `Sort -> Seq Scan` and parks 6.1 MiB
        of `pgsql_tmp` after a single FETCH; the index ordering uses none.

        The log has to be grown first — on a table of a few pages the planner
        rightly prefers a sequential scan and a trivial in-memory sort, so the
        assertion is only meaningful once an index scan is the cheaper plan.
        """
        from regista._replay import _EVENT_FIELDS, _EVENT_STREAM_ORDER

        _grow_to_big(seeded)
        sub, project = seeded["sub"], seeded["project"]

        with sub._mgr.connect() as conn:
            conn.execute(f"SET search_path = {project}, public")
            conn.execute("ANALYZE events")
            rows = conn.execute(
                f"EXPLAIN (COSTS OFF) DECLARE _wi217 CURSOR FOR "
                f"SELECT {_EVENT_FIELDS} FROM events {_EVENT_STREAM_ORDER}"
            ).fetchall()
            conn.rollback()
        plan = "\n".join(r["QUERY PLAN"] for r in rows)

        assert "Sort" not in plan, (
            "the streamed event scan plans with a Sort, so DECLARE CURSOR will "
            "materialize the whole sorted log server-side and hold it in "
            f"pgsql_tmp for the entire replay (WI-217). Plan:\n{plan}"
        )
        assert "Index Scan" in plan, (
            "the streamed event scan is not using an ordered index scan; "
            f"_EVENT_STREAM_ORDER must stay on indexed columns. Plan:\n{plan}"
        )
