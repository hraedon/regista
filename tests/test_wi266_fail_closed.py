"""WI-266: replay must fail closed on structural chain failures (BC audit).

A correctness audit found that when replay detects tampering it does not fail.
Detection works; reporting does not — CI, cron and scripted verification read
success on a store whose log demonstrably is not the log that was signed. Three
coupled defects, shipped together because they share one definition of "what
counts as a structural failure":

(1) Chain breaks were advisory. hash_chain_broken, global_chain_orphan, fork,
    multiple-genesis and global_chain_head_mismatch all landed in `warnings`,
    and the CLI printed them and exited 0.
(2) Whole-store and scoped replay disagreed: a projection row deleted out from
    under the log was warning-only whole-store but `halted` scoped.
(3) Projection rows with NO rows in `events` were never compared at all, so a
    fabricated projection row and a fully deleted event log both reported a
    clean replay; and an empty log with a non-NULL event_chain_head was clean.

Every test here FAILS against the unfixed code (verified by reverting
src/regista via `git diff src/ > /tmp/p.patch && git apply -R /tmp/p.patch`).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista import Regista
from regista._testing import raw_transaction
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

#: Canonical per ``TRUST-DOMAIN.md`` §2.1; the bare legacy spelling is refused at the
#: v6 ingress.
ACTOR = "agent:worker"
#: The pre-epoch key file, used by exactly one node below — see its comment.
UNMIGRATED_KEY_PATH = str(TESTS_DIR / "test_keys.json")

_GARBAGE_HASH = (
    "deadbeef00000000000000000000000000000000000000000000000000000000"
)


@pytest.fixture
def keyset(tmp_path):
    return make_v6_keyset(tmp_path)


@pytest.fixture
def regista(keyset):
    project = f"test_wi266_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch before the registration: `register_workflow_file` emits the
    # signed `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to until `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_actor_role(ACTOR, "agent")
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _create_transitioned(sub, title="wi266"):
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", ACTOR, custom_fields={"title": title}
    )
    sub.transition(wi.work_item_id, "start", ACTOR, actor_metadata={"role": "agent"})
    return wi.work_item_id


def _run_cli(argv):
    """Invoke the CLI in-process, returning its exit code (0 when it returns)."""
    from regista._cli import main

    try:
        main(argv)
    except SystemExit as e:
        return e.code if e.code is not None else 0
    return 0


# ---------------------------------------------------------------------------
# (1) chain breaks are a tampering verdict, not a warning
# ---------------------------------------------------------------------------


class TestChainBreaksFailClosed:
    def test_per_work_item_hash_chain_break_counts_as_chain_breaks(self, regista):
        wid = _create_transitioned(regista)
        # NULL -> garbage prev_event_hash on the genesis: the walk cannot chain
        # to any predecessor, so this is a chain break.
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET prev_event_hash = decode(%s, 'hex') "
                "WHERE work_item_id = %s AND transition = 'created'",
                [_GARBAGE_HASH, wid],
            )

        report = regista.replay()
        # The WI-266 guarantee is intact: a chain break is counted as a chain
        # break and never folded into `warnings`.
        assert report.chain_breaks >= 1
        assert report.warnings == 0
        # It now ALSO halts. This assertion was `halted == 0`, on the stated
        # premise that "the stored envelope still verifies, so this must be a
        # chain break rather than a signature halt". WI-267 removed that
        # premise: the envelope does still verify, but `prev_event_hash` is a
        # signed field from envelope v3 on and the envelope for this event
        # omits it, so a row that *gains* a link the signature never covered is
        # a reconciliation mismatch. The chain walk was the only defence when
        # WI-266 was written; verification is now the first one and the walk
        # the second. Both fire, and both are asserted — the WI-266 signal is
        # preserved, not replaced (see _ReplayHaltError, which carries the
        # counters accumulated before the halt so they survive it).
        assert report.halted >= 1

    def test_global_chain_orphan_counts_as_chain_breaks(self, regista):
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET prev_global_event_hash = decode(%s, 'hex') "
                "WHERE work_item_id = %s AND event_seq = 2",
                [_GARBAGE_HASH, wid],
            )

        report = regista.replay()
        assert report.chain_breaks >= 1
        assert report.warnings == 0

    def test_global_chain_head_mismatch_counts_as_chain_breaks(self, regista):
        _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE event_chain_head SET head_hash = decode(%s, 'hex') "
                "WHERE id = TRUE",
                [_GARBAGE_HASH],
            )

        report = regista.replay()
        assert report.chain_breaks >= 1
        assert report.warnings == 0

    def test_clean_replay_reports_zero_chain_breaks(self, regista):
        _create_transitioned(regista)
        report = regista.replay()
        assert report.chain_breaks == 0
        assert report.warnings == 0
        assert report.halted == 0

    def test_cli_replay_exits_nonzero_and_prints_chain_breaks(self, regista, keyset, capsys):
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET prev_event_hash = decode(%s, 'hex') "
                "WHERE work_item_id = %s AND transition = 'created'",
                [_GARBAGE_HASH, wid],
            )

        project = regista._project
        code = _run_cli(
            ["--dsn", DSN, "--project", project, "--hmac-key-path", keyset.path, "replay"]
        )
        out = capsys.readouterr()
        assert "chain_breaks=1" in out.out
        assert code == 1, (
            "replay exited 0 while reporting chain_breaks=1 — a structural "
            "tampering verdict must exit non-zero so scripted verification "
            "cannot read success over a broken chain"
        )

    def test_cli_replay_json_serializes_chain_breaks(self, regista, keyset, capsys):
        import json

        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET prev_event_hash = decode(%s, 'hex') "
                "WHERE work_item_id = %s AND transition = 'created'",
                [_GARBAGE_HASH, wid],
            )

        project = regista._project
        code = _run_cli(
            [
                "--dsn", DSN, "--project", project, "--hmac-key-path", keyset.path,
                "--json", "replay",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["chain_breaks"] >= 1
        assert code == 1


# ---------------------------------------------------------------------------
# (2) whole-store and scoped replay must agree on the orphan verdict
# ---------------------------------------------------------------------------


class TestOrphanProjectionRowHaltsEverywhere:
    def test_whole_store_orphan_with_created_event_halts(self, regista):
        # A projection row deleted out from under its (created) log: the two
        # replay paths must return the same verdict — halted.
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "DELETE FROM work_items_current WHERE work_item_id = %s", [wid]
            )

        report = regista.replay()
        assert report.halted >= 1
        assert report.warnings == 0
        halted_entries = [e for e in report.entries if e.category == "halted"]
        assert any(e.work_item_id == wid for e in halted_entries)

    def test_scoped_orphan_with_created_event_halts(self, regista):
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "DELETE FROM work_items_current WHERE work_item_id = %s", [wid]
            )

        report = regista.replay(work_item_id=wid)
        assert report.halted == 1
        assert any(e.work_item_id == wid and e.category == "halted" for e in report.entries)

    def test_in_memory_orphan_with_created_event_halts(self, keyset):
        s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(s, keyset)
        s.register_workflow_file(WORKFLOW_PATH)
        wid = _create_transitioned(s)
        del s._work_items[wid]

        report = s.replay()
        assert report.halted >= 1
        assert report.warnings == 0


# ---------------------------------------------------------------------------
# (3) projection rows with no events must halt; an empty log with a head too
# ---------------------------------------------------------------------------


class TestUnvisitedProjectionRowsHalt:
    def test_work_item_with_deleted_events_halts(self, regista):
        # Fully deleted event log for one work item, sibling stays clean: the
        # unvisited projection row must be a halted entry, not silently skipped.
        #
        # The creation order is load-bearing on a v6 chain and was not before: every
        # event names its key-binding anchor, its workflow registration and its
        # genesis by hash and must be able to *reach* them along
        # `chain.previous_project_event_hash` (TRUST-DOMAIN.md §5.10 step 3). Deleting
        # a mid-chain entity's events therefore severs every LATER event from its
        # anchor, and the sibling halts too. Deleting the chain TAIL's events leaves
        # the sibling's path to genesis intact, which is what lets both halves of this
        # test — the halted orphan and the clean sibling — stay asserted as written.
        _create_transitioned(regista, "B")
        wid_a = _create_transitioned(regista, "A")
        with raw_transaction(regista) as conn:
            conn.execute("DELETE FROM events WHERE work_item_id = %s", [wid_a])

        report = regista.replay()
        assert report.halted >= 1
        halted_entries = [e for e in report.entries if e.category == "halted"]
        assert any(e.work_item_id == wid_a for e in halted_entries)
        # B still replayed cleanly.
        assert report.replayed_ok >= 1

    def test_scoped_replay_of_work_item_with_deleted_events_halts(self, regista):
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute("DELETE FROM events WHERE work_item_id = %s", [wid])

        report = regista.replay(work_item_id=wid)
        assert report.halted == 1
        assert any(e.work_item_id == wid and e.category == "halted" for e in report.entries)

    def test_fabricated_projection_row_halts(self, regista):
        # INSERT a projection row directly with no backing events: a fabricated
        # row used to report a clean replay.
        fake_id = uuid.uuid4()
        with raw_transaction(regista) as conn:
            conn.execute(
                "INSERT INTO work_items_current "
                "(work_item_id, workflow_name, workflow_version, work_item_type, "
                "current_state, custom_fields, needs_review, last_event_seq, "
                "last_event_at, next_event_seq) "
                "VALUES (%s, 'test_workflow', 1, 'feature', 'new', '{}', false, "
                "0, now(), 1)",
                [fake_id],
            )

        report = regista.replay()
        assert report.halted >= 1
        assert any(
            e.work_item_id == fake_id and e.category == "halted"
            for e in report.entries
        )

    def test_empty_log_with_head_set_is_a_hard_halt(self, regista):
        # Delete the entire event log AND the projection: nothing compares, but
        # event_chain_head.head_hash proves events were appended. That must be a
        # halt, not a clean replay.
        #
        # Unqualified DELETEs, because "the entire event log" is now more than one
        # work item's rows: a clean v6 epoch carries the project/principal/workflow
        # events too, and leaving those behind leaves a non-empty log — which is a
        # different scenario from the one this test names.
        _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM work_items_current")

        report = regista.replay()
        assert report.halted >= 1
        assert report.chain_breaks == 0

    def test_in_memory_work_item_with_deleted_events_halts(self, keyset):
        s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(s, keyset)
        s.register_workflow_file(WORKFLOW_PATH)
        # Tail-last, for the §5.10 reachability reason spelled out on the Postgres
        # sibling above; nothing here is backend-specific.
        _create_transitioned(s, "B")
        wid_a = _create_transitioned(s, "A")
        s._store.events.pop(wid_a)

        report = s.replay()
        assert report.halted >= 1
        assert report.replayed_ok >= 1

    def test_in_memory_empty_log_with_head_set_is_a_hard_halt(self):
        # NOT migrated, deliberately, and this is the one node in this file that is
        # not. `InMemoryEventStore.append_v6_row` does not advance
        # `_global_chain_head` — its docstring defers that to the writer's explicit
        # `_advance_global_chain_head`, which the in-memory v6 path never calls — so
        # after a v6 epoch the in-memory head is still `None` and the precondition
        # this test names ("head set, log empty") cannot be reached at all. Migrating
        # it would therefore assert a halt the backend cannot produce. Keeping it on
        # an unmigrated handle preserves the GENESIS_REQUIRED form the epoch-blocked
        # manifest records, so the other fourteen nodes here can leave the manifest
        # now. Filed as a v6 backend-parity gap for the owner of the in-memory writer.
        s = InMemoryRegista(project="test", hmac_key_path=UNMIGRATED_KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        _create_transitioned(s)
        # Wholesale deletion: events and projection both gone, but the in-memory
        # chain head survives.
        s._store.events.clear()
        s._work_items.clear()

        report = s.replay()
        assert report.halted >= 1

    def test_in_memory_clean_replay_reports_zero_chain_breaks(self, keyset):
        s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(s, keyset)
        s.register_workflow_file(WORKFLOW_PATH)
        _create_transitioned(s)

        report = s.replay()
        assert report.halted == 0
        assert report.warnings == 0
        assert report.chain_breaks == 0
