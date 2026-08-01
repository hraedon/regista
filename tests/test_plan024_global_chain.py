from __future__ import annotations

import hashlib
import itertools
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_p024_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_actor_role("agent-1", "agent")
    sub.register_actor_role("reviewer-1", "reviewer")
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestPlan024ConcurrentGlobalChain:
    """Plan 024: concurrent appends must replay with global_chain_broken == 0."""

    def test_concurrent_transitions_replay_clean(self, regista):
        num_workers = 10
        work_items = []
        for i in range(num_workers):
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"p024-{i}"},
            )
            work_items.append(wi)

        errors: list[Exception] = []

        def do_transitions(idx):
            try:
                wi = work_items[idx]
                regista.transition(
                    wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"}
                )
                regista.transition(
                    wi.work_item_id, "submit_review", "agent-1", actor_metadata={"role": "agent"}
                )
                regista.transition(
                    wi.work_item_id, "approve", "reviewer-1", actor_metadata={"role": "reviewer"}
                )
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(do_transitions, i) for i in range(num_workers)]
            for f in futures:
                f.result()

        assert not errors, f"Errors during concurrent transitions: {errors}"

        report = regista.replay()
        assert report.halted == 0
        assert report.warnings == 0, (
            f"Expected 0 warnings, got {report.warnings}. "
            f"ok={report.replayed_ok}, drift={report.replayed_drift}"
        )

    def test_concurrent_raw_appends_replay_clean(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "p024-raw"},
        )

        num_workers = 8
        events_per_worker = 3
        errors: list[Exception] = []

        def append_events(worker_id):
            try:
                for i in range(events_per_worker):
                    regista.append_event(
                        work_item_id=wi.work_item_id,
                        actor_id=f"worker-{worker_id}",
                        transition=f"raw_{worker_id}_{i}",
                    )
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(append_events, w) for w in range(num_workers)]
            for f in futures:
                f.result()

        assert not errors, f"Errors during concurrent appends: {errors}"

        with regista._mgr.connect() as conn:
            conn.execute(f"SET search_path = {regista._project}, public")
            chain_warnings, _ = _walk_global_chain(conn)

        assert chain_warnings == 0, (
            f"Global chain has {chain_warnings} broken/orphan/fork warnings "
            f"after concurrent appends"
        )


class TestPlan024VerifierHashWalk:
    """Plan 024: the verifier walks by prev_global_event_hash links, not global_seq sort."""

    def test_hash_walk_detects_orphan(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "p024-orphan"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        with regista._mgr.connect() as conn:
            conn.execute(f"SET search_path = {regista._project}, public")
            conn.execute(
                "UPDATE events SET prev_global_event_hash = decode("
                "'deadbeef00000000000000000000000000000000000000000000000000000000', 'hex') "
                "WHERE work_item_id = %s AND event_seq = 2",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.halted == 0
        assert report.warnings >= 1, (
            f"Expected >=1 warning for orphaned event, got {report.warnings}"
        )

    def test_hash_walk_no_genesis_reports_orphans(self, regista):
        # Corrupt the genesis event so it is no longer a root (prev != NULL).
        # The verifier then has no genesis to start from and must report every
        # event as an orphan. (A prior version of this test claimed to detect a
        # cycle, but corrupting the only genesis event removes the root the
        # walk needs to even reach a cycle — see test_unit_detects_cycle for a
        # genuine reachable-cycle case.)
        _wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "p024-noroot-1"},
        )
        _wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "p024-noroot-2"},
        )

        with regista._mgr.connect() as conn:
            conn.execute(f"SET search_path = {regista._project}, public")
            rows = conn.execute(
                "SELECT event_id, global_seq, prev_global_event_hash, "
                "canonical_envelope, signature FROM events ORDER BY global_seq"
            ).fetchall()

            if len(rows) >= 2:
                first = rows[0]
                first_head = hashlib.sha256(
                    bytes(first["canonical_envelope"]) + bytes(first["signature"])
                ).digest()
                conn.execute(
                    "UPDATE events SET prev_global_event_hash = %s WHERE event_id = %s",
                    [first_head, first["event_id"]],
                )

        report = regista.replay()
        assert report.halted == 0
        assert report.warnings >= 1, (
            f"Expected >=1 orphan warning with no genesis, got {report.warnings}"
        )

    def test_unit_detects_cycle(self):
        # Exercise the cycle branch directly. A cryptographically-reachable
        # cycle cannot arise from valid signed events (it needs two events with
        # the same head hash), so we feed the verifier a synthetic event list:
        # E1 genesis -> E2 -> E3, where E3 reuses E1's envelope/signature so
        # head(E3) == head(E1), making E2 a successor of E3 -> the walk revisits
        # E2 and trips the cycle guard.
        from regista._replay import _verify_global_hash_chain

        def mk(eid, prev, env, sig):
            return {
                "event_id": eid,
                "global_seq": 0,
                "prev_global_event_hash": prev,
                "canonical_envelope": env,
                "signature": sig,
            }

        env_a, sig_a = b"env-A", b"sig-A"
        head_a = hashlib.sha256(env_a + sig_a).digest()
        env_b, sig_b = b"env-B", b"sig-B"
        head_b = hashlib.sha256(env_b + sig_b).digest()

        events = [
            mk("e1", None, env_a, sig_a),  # genesis, head = head_a
            mk("e2", head_a, env_b, sig_b),  # chains from e1, head = head_b
            mk("e3", head_b, env_a, sig_a),  # chains from e2, head = head_a
            # e3's head (head_a) has successor e2 (prev=head_a) -> walk e1->e2->e3->e2 cycle
        ]
        warnings, _ = _verify_global_hash_chain(events)
        assert warnings >= 1, f"Expected cycle warning, got {warnings}"

    def test_unit_detects_fork(self):
        # Two events claiming the same predecessor hash -> fork warning.
        from regista._replay import _verify_global_hash_chain

        env_a, sig_a = b"env-A", b"sig-A"
        head_a = hashlib.sha256(env_a + sig_a).digest()

        events = [
            {
                "event_id": "e1",
                "global_seq": 0,
                "prev_global_event_hash": None,
                "canonical_envelope": env_a,
                "signature": sig_a,
            },
            {
                "event_id": "e2a",
                "global_seq": 1,
                "prev_global_event_hash": head_a,
                "canonical_envelope": b"B",
                "signature": b"s",
            },
            {
                "event_id": "e2b",
                "global_seq": 2,
                "prev_global_event_hash": head_a,
                "canonical_envelope": b"C",
                "signature": b"s",
            },
        ]
        warnings, _ = _verify_global_hash_chain(events)
        assert warnings >= 1, f"Expected fork warning, got {warnings}"

    def test_compact_links_verify_identically_to_full_rows(self):
        """WI-217: the streaming replay walks compact links, not event rows.

        `_replay_inner` no longer holds the event log while it walks the global
        chain — it reduces each row to a `_chain_link` (event_id, global_seq,
        prev link, precomputed head hash) and releases the envelope, signature
        and payload with the work item's group. That is only sound if the walk
        reaches the same verdict from links as from rows, so pin it on the
        tamper shapes the walk exists to catch.

        Order-independence is asserted at the same time: the walk follows hash
        links, so reversing the input must not change the verdict. That is what
        makes it immune to `global_seq` reordering.

        Equivalence is checked on the full ordered sequence of emitted log
        payloads, not just the warning count — a refactor that swapped one
        warning for a different one of the same cardinality would otherwise
        pass. Every event gets a distinct `global_seq`, because it rides in the
        compact link and is load bearing downstream (timestamp coverage and the
        Merkle recomputation in `_replay_inner` both index on it), so a
        `_chain_link` bug that dropped or scrambled it must not be invisible.
        """
        from structlog.testing import capture_logs

        from regista._replay import _chain_link, _verify_global_hash_chain

        seq = itertools.count(1)

        def mk(eid, prev, env, sig, global_seq=None):
            return {
                "event_id": eid,
                "global_seq": next(seq) if global_seq is None else global_seq,
                "prev_global_event_hash": prev,
                "canonical_envelope": env,
                "signature": sig,
            }

        def head(env, sig):
            return hashlib.sha256(env + sig).digest()

        head_a = head(b"env-A", b"sig-A")
        head_b = head(b"env-B", b"sig-B")

        e1 = mk("e1", None, b"env-A", b"sig-A")
        e2 = mk("e2", head_a, b"env-B", b"sig-B")
        e3 = mk("e3", head_b, b"env-C", b"sig-C")

        # A sealed segment standing in for an archived genesis: the walk has no
        # genesis event and must bridge from the segment's head to e2. Segment
        # dicts are NOT reduced by `_chain_link`, so this is the one shape where
        # the walk mixes compact links with raw rows.
        archived_genesis_segment = {
            "segment_id": "seg-1",
            "first_event_prev_hash": None,
            "head_hash": head_a,
        }

        cases = {
            "intact": ([e1, e2, e3], None),
            # e3 reuses e1's envelope/signature, so head(e3) == head(e1) and e2
            # becomes its own successor's successor.
            "cycle": ([e1, e2, mk("e3", head_b, b"env-A", b"sig-A")], None),
            # Two events claim the same predecessor.
            "fork": ([e1, e2, mk("e2b", head_a, b"env-D", b"sig-D")], None),
            # A forged prev link detaches e2 (and e3 behind it) from the chain.
            "forged_prev_link": (
                [e1, mk("e2", b"\xde\xad\xbe\xef" * 8, b"env-B", b"sig-B"), e3],
                None,
            ),
            # The middle event is gone: the walk stops at e1 and e3 is orphaned.
            "missing_event": ([e1, e3], None),
            # No genesis at all, and no segment to bridge from one.
            "no_genesis": ([e2, e3], None),
            # Two events with a NULL prev link.
            "multiple_genesis": ([e1, mk("e1b", None, b"env-E", b"sig-E"), e2], None),
            # Genesis is archived; the segment bridges to e2. Must be clean.
            "segment_bridged_genesis": ([e2, e3], [archived_genesis_segment]),
            # A segment that bridges nowhere leaves the events unreachable.
            "segment_bridges_nothing": (
                [e2, e3],
                [{"segment_id": "seg-x", "first_event_prev_hash": None, "head_hash": b"\x00" * 32}],
            ),
            # An event whose envelope/signature are NULL yields head_hash=None,
            # so the walk cannot compute its successor link and stops there.
            "null_envelope_tail": ([e1, mk("e2n", head_a, None, None), e3], None),
        }

        clean = {"intact", "segment_bridged_genesis"}

        for name, (rows, segments) in cases.items():
            with capture_logs() as row_logs:
                from_rows, tail_rows = _verify_global_hash_chain(rows, segments=segments)
            links = [_chain_link(r) for r in rows]
            with capture_logs() as link_logs:
                from_links, tail_links = _verify_global_hash_chain(links, segments=segments)

            assert from_links == from_rows, (
                f"{name}: compact links reported {from_links} warnings, "
                f"full rows reported {from_rows}"
            )
            assert link_logs == row_logs, (
                f"{name}: compact links emitted a different sequence of log "
                f"payloads than full rows:\n  links={link_logs}\n  rows={row_logs}"
            )
            assert (tail_links or {}).get("event_id") == (tail_rows or {}).get("event_id"), (
                f"{name}: chain tail differs between links and rows"
            )
            assert (tail_links or {}).get("global_seq") == (tail_rows or {}).get("global_seq"), (
                f"{name}: chain tail global_seq differs between links and rows"
            )

            # Order-independence for every case, multiple roots included (WI-219).
            # The walk follows hash links, so reversing the input must not change
            # the verdict. When several events carry a NULL prev link the walk
            # starts from the lowest-global_seq genesis (tie-broken on event_id),
            # so the chosen root — and therefore the warning set — is stable
            # regardless of row order.
            reversed_links, _ = _verify_global_hash_chain(
                list(reversed(links)), segments=segments
            )
            assert reversed_links == from_links, (
                f"{name}: verdict changed when the input order was reversed "
                f"({reversed_links} vs {from_links}) — the walk is order-sensitive"
            )

            # The links must carry global_seq through faithfully — the walk
            # itself only logs it, so a scrambled value would pass every
            # assertion above while corrupting timestamp coverage and Merkle
            # recomputation in `_replay_inner`.
            assert [ln["global_seq"] for ln in links] == [r["global_seq"] for r in rows], (
                f"{name}: _chain_link did not preserve global_seq"
            )
            assert len({ln["global_seq"] for ln in links}) == len(links), (
                f"{name}: global_seq values are not distinct — this test would "
                "not notice a _chain_link bug that scrambled them"
            )

            # Sanity: each case must land on the verdict it is named for, or the
            # equivalence above would be vacuous.
            if name in clean:
                assert from_links == 0, f"{name} should be clean, got {from_links} warnings"
            else:
                assert from_links >= 1, f"{name} not detected when walking compact links"

    def test_multiple_genesis_verdict_is_order_stable(self):
        # WI-219: with two NULL prev links the canonical root must be chosen by
        # global_seq (tie-broken on event_id), not by input order. Two disjoint
        # chains g1->s1 (seqs 1,3) and g2->s2 (seqs 2,4): the walk must always
        # start from g1 (lowest genesis seq), reach tail s1, and report the same
        # warning count under every input permutation.
        from regista._replay import _verify_global_hash_chain

        def head(env, sig):
            return hashlib.sha256(env + sig).digest()

        head_g1 = head(b"env-g1", b"sig-g1")
        head_g2 = head(b"env-g2", b"sig-g2")

        def mk(eid, seq, prev, env, sig):
            return {
                "event_id": eid,
                "global_seq": seq,
                "prev_global_event_hash": prev,
                "canonical_envelope": env,
                "signature": sig,
            }

        g1 = mk("g1", 1, None, b"env-g1", b"sig-g1")
        s1 = mk("s1", 3, head_g1, b"env-s1", b"sig-s1")
        g2 = mk("g2", 2, None, b"env-g2", b"sig-g2")
        s2 = mk("s2", 4, head_g2, b"env-s2", b"sig-s2")

        events = [g1, s1, g2, s2]

        reference_warnings, reference_tail = _verify_global_hash_chain(list(events))
        assert reference_tail is not None
        assert reference_tail["event_id"] == "s1", (
            "lowest-global_seq genesis (g1) must be the canonical root"
        )

        for perm in itertools.permutations(events):
            warnings, tail = _verify_global_hash_chain(list(perm))
            assert warnings == reference_warnings, (
                f"warning count changed under permutation {[e['event_id'] for e in perm]}: "
                f"{warnings} vs {reference_warnings}"
            )
            assert (tail or {}).get("event_id") == "s1", (
                f"chain tail changed under permutation {[e['event_id'] for e in perm]}"
            )

    def test_in_memory_replay_walks_chain(self):
        sub = InMemoryRegista(project="test_p024_im", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")

        items = []
        for i in range(5):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"im-{i}"},
            )
            items.append(wi)

        for wi in items:
            sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        report = sub.replay()
        assert report.halted == 0
        assert report.warnings == 0, (
            f"Expected 0 warnings for in-memory replay, got {report.warnings}"
        )

    def test_global_seq_matches_chain_order_with_cache1(self, regista):
        """With CACHE 1, global_seq order must match chain-link order."""
        num_workers = 6
        work_items = []
        for i in range(num_workers):
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"p024-seq-{i}"},
            )
            work_items.append(wi)

        errors: list[Exception] = []

        def do_transitions(idx):
            try:
                wi = work_items[idx]
                regista.transition(
                    wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"}
                )
                regista.transition(
                    wi.work_item_id, "submit_review", "agent-1", actor_metadata={"role": "agent"}
                )
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(do_transitions, i) for i in range(num_workers)]
            for f in futures:
                f.result()

        assert not errors, f"Errors: {errors}"

        with regista._mgr.connect() as conn:
            conn.execute(f"SET search_path = {regista._project}, public")
            chain_order_matches = _verify_chain_order_matches_global_seq(conn)

        assert chain_order_matches, (
            "global_seq order does not match chain-link order — CACHE 1 fix not working"
        )


class TestPlan024GenesisRace:
    """Plan 024 gap: concurrent first-events must not produce two genesis rows.

    The genesis sentinel (migration 035) ensures FOR UPDATE always has a row to
    lock, so only one event can chain from NULL even when multiple writers race
    on a fresh schema's first append.
    """

    def test_concurrent_genesis_single_root(self, regista):
        # Fresh schema: fire N create_work_item concurrently so their genesis
        # ("created") events race for the single NULL prev_global_event_hash
        # slot. The sentinel row (migration 035) guarantees FOR UPDATE always
        # has a row to lock, so only one event may chain from NULL.
        num_workers = 8
        errors: list[Exception] = []
        created: list = []

        def do_create(idx):
            try:
                wi, _ = regista.create_work_item(
                    workflow_name="test_workflow",
                    work_item_type="feature",
                    actor_id="agent-1",
                    custom_fields={"title": f"p024-gen-{idx}"},
                )
                created.append(wi.work_item_id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(do_create, i) for i in range(num_workers)]
            for f in futures:
                f.result()

        assert not errors, f"Errors during concurrent genesis: {errors}"
        assert len(created) == num_workers

        with regista._mgr.connect() as conn:
            conn.execute(f"SET search_path = {regista._project}, public")
            genesis_count = conn.execute(
                "SELECT count(*) AS n FROM events WHERE prev_global_event_hash IS NULL"
            ).fetchone()["n"]

        assert genesis_count == 1, (
            f"Expected exactly 1 genesis event (NULL prev_global_event_hash), "
            f"got {genesis_count} — genesis race not closed"
        )

        report = regista.replay()
        assert report.warnings == 0, (
            f"Replay reported warnings after concurrent genesis: {report.warnings}"
        )


def _walk_global_chain(conn) -> tuple[int, dict | None]:
    """Walk the global chain by prev_global_event_hash links. Returns (warnings, tail)."""
    from collections import defaultdict

    rows = conn.execute(
        "SELECT event_id, global_seq, canonical_envelope, signature, "
        "prev_global_event_hash FROM events ORDER BY global_seq"
    ).fetchall()

    if not rows:
        return 0, None

    link_map: dict[str, list] = defaultdict(list)
    genesis: list = []
    for r in rows:
        pgh = r["prev_global_event_hash"]
        if pgh is None:
            genesis.append(r)
        else:
            link_map[bytes(pgh).hex()].append(r)

    warnings = 0
    if not genesis:
        return len(rows), None

    current = genesis[0]
    visited = set()
    while True:
        eid = current["event_id"]
        if eid in visited:
            return warnings + 1, current
        visited.add(eid)

        env = current["canonical_envelope"]
        sig = current["signature"]
        if env is None or sig is None:
            break

        head = hashlib.sha256(bytes(env) + bytes(sig)).digest()
        succs = link_map.get(head.hex(), [])
        if not succs:
            break
        current = succs[0]

    warnings += sum(1 for r in rows if r["event_id"] not in visited)
    return warnings, current


def _verify_chain_order_matches_global_seq(conn) -> bool:
    """Check that walking the chain by links produces events in global_seq order."""
    from collections import defaultdict

    rows = conn.execute(
        "SELECT event_id, global_seq, canonical_envelope, signature, "
        "prev_global_event_hash FROM events ORDER BY global_seq"
    ).fetchall()

    if not rows:
        return True

    link_map: dict[str, list] = defaultdict(list)
    genesis = None
    for r in rows:
        pgh = r["prev_global_event_hash"]
        if pgh is None:
            genesis = r
        else:
            link_map[bytes(pgh).hex()].append(r)

    if genesis is None:
        return False

    chain_gseqs = []
    current = genesis
    visited = set()
    while current and current["event_id"] not in visited:
        visited.add(current["event_id"])
        chain_gseqs.append(current["global_seq"])
        env = current["canonical_envelope"]
        sig = current["signature"]
        if env is None or sig is None:
            break
        head = hashlib.sha256(bytes(env) + bytes(sig)).digest()
        succs = link_map.get(head.hex(), [])
        if not succs:
            break
        current = succs[0]

    return chain_gseqs == sorted(chain_gseqs)
