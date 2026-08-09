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

from regista import Regista
from regista._testing import raw_transaction
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

_GARBAGE_HASH = (
    "deadbeef00000000000000000000000000000000000000000000000000000000"
)


@pytest.fixture
def regista():
    project = f"test_wi266_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_actor_role("agent-1", "agent")
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _create_transitioned(sub, title="wi266"):
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "agent-1", custom_fields={"title": title}
    )
    sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})
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

    def test_cli_replay_exits_nonzero_and_prints_chain_breaks(self, regista, capsys):
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET prev_event_hash = decode(%s, 'hex') "
                "WHERE work_item_id = %s AND transition = 'created'",
                [_GARBAGE_HASH, wid],
            )

        project = regista._project
        code = _run_cli(
            ["--dsn", DSN, "--project", project, "--hmac-key-path", KEY_PATH, "replay"]
        )
        out = capsys.readouterr()
        assert "chain_breaks=1" in out.out
        assert code == 1, (
            "replay exited 0 while reporting chain_breaks=1 — a structural "
            "tampering verdict must exit non-zero so scripted verification "
            "cannot read success over a broken chain"
        )

    def test_cli_replay_json_serializes_chain_breaks(self, regista, capsys):
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
                "--dsn", DSN, "--project", project, "--hmac-key-path", KEY_PATH,
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

    def test_in_memory_orphan_with_created_event_halts(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
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
        wid_a = _create_transitioned(regista, "A")
        _create_transitioned(regista, "B")
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
        wid = _create_transitioned(regista)
        with raw_transaction(regista) as conn:
            conn.execute("DELETE FROM events WHERE work_item_id = %s", [wid])
            conn.execute(
                "DELETE FROM work_items_current WHERE work_item_id = %s", [wid]
            )

        report = regista.replay()
        assert report.halted >= 1
        assert report.chain_breaks == 0

    def test_in_memory_work_item_with_deleted_events_halts(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wid_a = _create_transitioned(s, "A")
        _create_transitioned(s, "B")
        s._store.events.pop(wid_a)

        report = s.replay()
        assert report.halted >= 1
        assert report.replayed_ok >= 1

    def test_in_memory_empty_log_with_head_set_is_a_hard_halt(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        _create_transitioned(s)
        # Wholesale deletion: events and projection both gone, but the in-memory
        # chain head survives.
        s._store.events.clear()
        s._work_items.clear()

        report = s.replay()
        assert report.halted >= 1

    def test_in_memory_clean_replay_reports_zero_chain_breaks(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        _create_transitioned(s)

        report = s.replay()
        assert report.halted == 0
        assert report.warnings == 0
        assert report.chain_breaks == 0
