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
