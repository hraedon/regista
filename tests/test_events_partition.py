from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")

WORKFLOW = """\
name: partition_test
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: finish
    from: new
    to: done

roles:
  - name: agent

work_item_types:
  - name: task
    custom_fields: []

link_types: []
attempt_threshold: 99
"""


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_partition_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow(WORKFLOW)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _raw_conn(schema: str):
    conn = psycopg.connect(DSN, row_factory=dict_row)
    conn.execute(f'SET search_path TO "{schema}"')
    return conn


class TestEnsureEventPartitions:
    def test_idempotent_double_call(self, regista):
        result1 = regista.ensure_event_partitions(months_ahead=2)
        result2 = regista.ensure_event_partitions(months_ahead=2)
        assert result1 == []
        assert result2 == []

    def test_returns_empty_list(self, regista):
        names = regista.ensure_event_partitions(months_ahead=1)
        assert names == []


class TestEventStorage:
    def test_events_land_in_events_table(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="partition_test",
            work_item_type="task",
            actor_id="agent-1",
            custom_fields={},
        )
        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            rows = conn.execute(
                "SELECT tableoid::regclass::text AS table_name "
                "FROM events WHERE work_item_id = %s",
                [wi.work_item_id],
            ).fetchall()
        assert len(rows) >= 1
        for row in rows:
            assert row["table_name"] == "events"

    def test_far_future_event_lands_in_events_table(self, regista):
        far_future = datetime(2099, 12, 1, tzinfo=UTC)
        event_id = uuid.uuid4()
        schema = regista._mgr.schema

        wi, _ = regista.create_work_item(
            workflow_name="partition_test",
            work_item_type="task",
            actor_id="agent-1",
            custom_fields={},
        )

        with _raw_conn(schema) as conn:
            conn.execute(
                "INSERT INTO events ("
                "event_id, work_item_id, event_seq, actor_id, actor_kind, "
                "key_id, workflow_name, workflow_version, timestamp, transition, "
                "payload_canonical_hash, signature"
                ") VALUES (%s, %s, 999, 'agent-1', 'agent', 'test', "
                "'partition_test', 1, %s, 'test', %s, %s)",
                [event_id, wi.work_item_id, far_future, b"hash", b"sig"],
            )
            row = conn.execute(
                "SELECT tableoid::regclass::text AS table_name "
                "FROM events WHERE event_id = %s",
                [event_id],
            ).fetchone()
        assert row is not None
        assert row["table_name"] == "events"

    def test_read_events_by_time_range(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="partition_test",
            work_item_type="task",
            actor_id="agent-1",
            custom_fields={},
        )
        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="finish",
            actor_id="agent-1",
        )
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 12, 31, tzinfo=UTC)
        events = regista.read_events(
            work_item_id=wi.work_item_id,
            start=start,
            end=end,
        )
        assert len(events) >= 1
        for evt in events:
            assert evt.work_item_id == wi.work_item_id

    def test_events_table_is_not_partitioned(self, regista):
        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT pt.partstrat FROM pg_partitioned_table pt "
                "JOIN pg_class c ON c.oid = pt.partrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relname = 'events' AND n.nspname = %s",
                [schema],
            ).fetchone()
        assert row is None, "events table should not be partitioned"


class TestUnpartitionedInit:
    """Partitioning was removed; auto_partition is a no-op."""

    def test_no_partitions_created_on_create_project(self):
        """create_project does not create any partition tables."""
        from regista import Regista

        project = f"test_autopart_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        try:
            schema = sub._mgr.schema
            with _raw_conn(schema) as conn:
                rows = conn.execute(
                    """
                    SELECT c.relname
                    FROM pg_inherits i
                    JOIN pg_class c ON c.oid = i.inhrelid
                    JOIN pg_class p ON p.oid = i.inhparent
                    JOIN pg_namespace n ON n.oid = p.relnamespace
                    WHERE p.relname = 'events'
                      AND n.nspname = %s
                      AND c.relname ~ '^events_y[0-9]{4}_m[0-9]{2}$'
                    ORDER BY c.relname
                    """,
                    [schema],
                ).fetchall()
            partition_names = [r["relname"] for r in rows]
            assert partition_names == [], (
                f"Expected no partitions after init, got {partition_names}"
            )
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_auto_partition_false_is_functional(self):
        """auto_partition=False is still valid and functional."""
        from regista import Regista

        project = f"test_noautopart_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH, auto_partition=False)
        try:
            assert sub.regista_version is not None
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_partition_metrics_not_present_after_init(self):
        """Partition gauges are no longer emitted."""
        from prometheus_client import CollectorRegistry

        from regista import Regista

        project = f"test_metrics_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(DSN, project, KEY_PATH, prometheus_registry=registry)
        try:
            samples = {
                s.name: s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert "regista_events_default_rows" not in samples, (
                "regista_events_default_rows should not be present"
            )
            assert "regista_events_partition_horizon_days" not in samples, (
                "regista_events_partition_horizon_days should not be present"
            )
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestEscalationUniquePerWorkItem:
    def test_two_escalated_same_work_item_blocked_at_app_level(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="partition_test",
            work_item_type="task",
            actor_id="agent-1",
            custom_fields={},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)

        events = regista.read_events(work_item_id=wi.work_item_id)
        escalated_events = [e for e in events if e.transition == "escalated"]
        assert len(escalated_events) <= 1, "More than one escalated event per work item"
