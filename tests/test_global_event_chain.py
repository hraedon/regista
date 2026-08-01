"""Global hash chain across all events (migration 030 / AP-012).

global_seq is CACHE-100 and so non-contiguous under a pool; the per-work-item
prev_event_hash cannot detect deletion of a whole work item. Every event binds
prev_global_event_hash = sha256(prev.canonical_envelope || prev.signature) of
the immediately preceding event in append order, forming one tamper-evident
line across work items that is immune to global_seq gaps.
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from pathlib import Path

import pytest
from psycopg.sql import SQL

from regista import Regista
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    project = f"test_global_chain_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _all_events_in_global_order(regista):
    with regista._mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                "SELECT global_seq, canonical_envelope, signature, "
                "prev_global_event_hash FROM events ORDER BY global_seq"
            )
        ).fetchall()
    return rows


def _head(regista):
    with regista._mgr.transaction() as conn:
        return conn.execute(
            SQL("SELECT head_hash, head_event_id FROM event_chain_head WHERE id = TRUE")
        ).fetchone()


def test_global_chain_links_events_across_work_items(regista):
    # Three work items, each create emits an event -> three events in different
    # work items, so the per-WI chain cannot relate them; the global chain must.
    for i in range(3):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": f"wi-{i}"},
        )

    rows = _all_events_in_global_order(regista)
    assert len(rows) >= 3

    # (1) Genesis event has no global predecessor.
    assert rows[0]["prev_global_event_hash"] is None

    # (2) Every subsequent event chains to its immediate predecessor by hash,
    #     regardless of the numeric global_seq gap between them.
    for prev, cur in itertools.pairwise(rows):
        expected = hashlib.sha256(
            bytes(prev["canonical_envelope"]) + bytes(prev["signature"])
        ).digest()
        assert bytes(cur["prev_global_event_hash"]) == expected

    # (3) The head pointer tracks the last event in the chain.
    last = rows[-1]
    head = _head(regista)
    expected_head = hashlib.sha256(
        bytes(last["canonical_envelope"]) + bytes(last["signature"])
    ).digest()
    assert bytes(head["head_hash"]) == expected_head


def test_global_chain_survives_global_seq_gaps(regista):
    # The chain links by hash, not by numeric adjacency. In production gaps come
    # from CACHE 100 across the per-tool-call connections; here we force one
    # deterministically by burning sequence values between appends, then assert
    # the hash chain is still unbroken — the exact case the old global_seq
    # contiguity check wrongly flagged as "events deleted".
    regista.create_work_item(
        workflow_name="test_workflow", work_item_type="feature",
        actor_id="agent-1", custom_fields={"title": "before-gap"},
    )
    with regista._mgr.transaction() as conn:
        conn.execute(SQL("SELECT nextval('events_global_seq_seq')"))
        conn.execute(SQL("SELECT nextval('events_global_seq_seq')"))
    regista.create_work_item(
        workflow_name="test_workflow", work_item_type="feature",
        actor_id="agent-1", custom_fields={"title": "after-gap"},
    )

    rows = _all_events_in_global_order(regista)
    seqs = [r["global_seq"] for r in rows]
    assert any(b - a > 1 for a, b in itertools.pairwise(seqs)), (
        "expected a forced global_seq gap; test no longer exercises gap-immunity"
    )
    for prev, cur in itertools.pairwise(rows):
        expected = hashlib.sha256(
            bytes(prev["canonical_envelope"]) + bytes(prev["signature"])
        ).digest()
        assert bytes(cur["prev_global_event_hash"]) == expected


def test_bc298_public_append_event_persists_prev_global_event_hash(regista):
    wi, _ = regista.create_work_item(
        workflow_name="test_workflow", work_item_type="feature",
        actor_id="agent-1", custom_fields={"title": "bc298"},
    )
    regista.append_event(
        wi.work_item_id, "agent-1", transition="note", payload={"k": "v"},
    )
    regista.append_event(
        wi.work_item_id, "agent-1", transition="note2", payload={"k": "v2"},
    )

    rows = _all_events_in_global_order(regista)
    append_rows = [r for r in rows if r["global_seq"] > 1]
    assert len(append_rows) >= 2
    for r in append_rows:
        assert r["prev_global_event_hash"] is not None


def test_bc300_replay_detects_global_chain_tamper(regista):
    for i in range(3):
        regista.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": f"bc300-{i}"},
        )

    report = regista.replay()
    assert report.replayed_drift == 0
    assert report.warnings == 0

    with regista._mgr.transaction() as conn:
        conn.execute(
            SQL(
                "UPDATE events SET prev_global_event_hash = %s "
                "WHERE global_seq = (SELECT MIN(global_seq) FROM events "
                "WHERE prev_global_event_hash IS NOT NULL)"
            ),
            [b"\x00" * 32],
        )

    report = regista.replay()
    assert report.warnings >= 1, "replay must warn on corrupted global chain"


def test_bc300_replay_clean_global_chain_in_memory():
    from regista.testing import InMemoryRegista

    sub = InMemoryRegista(project="memory", hmac_key_path=KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    for i in range(3):
        sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": f"im-{i}"},
        )
    report = sub.replay()
    assert report.warnings == 0
    assert report.replayed_drift == 0


def test_bc300_in_memory_replay_detects_global_chain_tamper():
    import dataclasses

    from regista.testing import InMemoryRegista

    sub = InMemoryRegista(project="memory", hmac_key_path=KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    for i in range(3):
        sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": f"im-tamper-{i}"},
        )

    report = sub.replay()
    assert report.warnings == 0

    all_evts = []
    for wid in sub._store.events:
        all_evts.extend(sub._store.events[wid])
    all_evts.sort(key=lambda e: e.global_seq)
    target = all_evts[1]
    corrupted = dataclasses.replace(target, prev_global_event_hash=b"\xff" * 32)
    lst = sub._store.events[target.work_item_id]
    lst[lst.index(target)] = corrupted
    sub._store.event_id_index[target.event_id] = corrupted

    report = sub.replay()
    assert report.warnings >= 1, "InMemory replay must warn on corrupted global chain"


def test_append_returns_db_assigned_global_seq(regista):
    # Cross-repo WI-010: PostgresEventStore.append must return the event with
    # the DB-assigned global_seq (allocated by the column's sequence DEFAULT),
    # matching InMemoryEventStore.append. Before the fix the Postgres store
    # returned the in-memory object whose global_seq was still None.
    wi, created = regista.create_work_item(
        workflow_name="test_workflow", work_item_type="feature",
        actor_id="agent-1", custom_fields={"title": "wi010"},
    )
    assert created.global_seq is not None
    assert created.global_seq > 0

    appended = regista.append_event(
        work_item_id=wi.work_item_id, actor_id="agent-1", transition="wi010_note"
    )
    assert appended.global_seq is not None
    assert appended.global_seq > created.global_seq

    with regista._mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                "SELECT event_id, global_seq FROM events "
                "WHERE event_id IN (%s, %s)"
            ),
            [created.event_id, appended.event_id],
        ).fetchall()
    persisted = {r["event_id"]: r["global_seq"] for r in rows}
    assert persisted[created.event_id] == created.global_seq
    assert persisted[appended.event_id] == appended.global_seq
