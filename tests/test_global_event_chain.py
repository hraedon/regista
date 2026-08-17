"""Global hash chain across all events (migration 030 / AP-012).

global_seq is CACHE-100 and so non-contiguous under a pool; the per-work-item
prev_event_hash cannot detect deletion of a whole work item. Every event binds
prev_global_event_hash = sha256(prev.canonical_envelope || prev.signature) of
the immediately preceding event in append order, forming one tamper-evident
line across work items that is immune to global_seq gaps.
"""

from __future__ import annotations

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
