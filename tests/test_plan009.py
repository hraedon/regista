from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista import Regista
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")
WORKFLOW_PATH = str(Path(__file__).parent / "test_workflow.yaml")

WORKFLOW_V2 = """\
name: test_workflow
version: 2
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: in_progress
  - name: review
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: in_progress
    allowed_roles: [agent]
    validator: validate_start
  - name: submit_review
    from: in_progress
    to: review
    allowed_roles: [agent]
    hooks: [notify_reviewer]
  - name: approve
    from: review
    to: done
    allowed_roles: [reviewer]

roles:
  - name: agent
  - name: reviewer

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true
        ui_visible: true

link_types: []

attempt_threshold: 3
"""


@pytest.fixture
def regista():
    project_name = f"plan009_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project_name, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project_name)


@pytest.fixture
def regista_v2():
    project_name = f"plan009v2_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project_name, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_workflow(WORKFLOW_V2)
    yield sub
    sub.close()
    drop_project_schema(DSN, project_name)


class TestMaintenanceStartStop:
    def test_start_stop(self, regista):
        assert regista.maintenance_healthy
        regista.start_maintenance(sweep_interval=5)
        assert regista._maintenance_thread.is_running
        regista.stop_maintenance()
        assert not regista._maintenance_thread.is_running

    def test_close_stops_maintenance(self, regista):
        regista.start_maintenance(sweep_interval=5)
        assert regista._maintenance_thread.is_running
        regista.close()
        assert not regista._maintenance_thread.is_running

    def test_maintenance_healthy_reflects_state(self, regista):
        assert regista.maintenance_healthy
        regista.start_maintenance(sweep_interval=1)
        time.sleep(0.3)
        assert regista.maintenance_healthy
        regista.stop_maintenance()
        assert not regista.maintenance_healthy


class TestMaintenanceSweeps:
    def test_sweeps_expired_claims(self, regista):
        wi, _ = regista.create_work_item("test_workflow", "feature", "actor-a",
                                           custom_fields={"title": "t", "priority": "low"})
        regista.acquire_claim(wi.work_item_id, "actor-a", ttl_seconds=1)
        claim = regista.get_work_item(wi.work_item_id)
        assert claim.claimed_by == "actor-a"

        regista.start_maintenance(sweep_interval=1)
        time.sleep(3)
        regista.stop_maintenance()

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None


class TestMaintenanceResilience:
    def test_error_does_not_kill_thread(self, regista):
        regista.start_maintenance(sweep_interval=1)
        time.sleep(0.3)
        assert regista._maintenance_thread.is_running
        assert regista._maintenance_thread.last_cycle_ok

        regista._mgr.close()
        regista._mgr = None
        time.sleep(2)

        assert regista._maintenance_thread.is_running
        assert not regista._maintenance_thread.last_cycle_ok

        regista._maintenance_thread.stop()


class TestMaintenanceHookLeaseSweep:
    def test_sweeps_expired_hook_leases(self, regista_v2):
        regista = regista_v2

        def fail_handler(ctx):
            raise RuntimeError("fail")

        regista.register_hook_handler("notify_reviewer", fail_handler)
        regista.register_validator("validate_start", lambda ctx: None)

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "hook lease sweep"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})
        regista.transition(wi.work_item_id, "submit_review", "agent-1",
                            actor_metadata={"role": "agent"})

        hooks = regista.claim_hooks(max_batch=10, lease_seconds=1)
        assert len(hooks) >= 1

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE hook_queue SET lease_expires_at = %s WHERE status = 'in_progress'",
                [datetime.now(UTC) - timedelta(seconds=10)],
            )

        regista.start_maintenance(sweep_interval=1, hook_poll_interval=1)
        time.sleep(3)
        regista.stop_maintenance()

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT status FROM hook_queue WHERE status = 'pending'"
            ).fetchall()
        assert len(rows) >= 1


class TestMaintenanceRecurrenceFiring:
    def test_fires_due_recurrence(self, regista):
        start = datetime.now(UTC) - timedelta(minutes=5)
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring via maintenance"}},
            schedule_kind="interval",
            schedule_expr="PT1M",
            start_at=start,
        )

        before = len(regista.query_work_items(workflow_name="test_workflow").items)

        regista.start_maintenance(sweep_interval=1, recurrence_interval=1)
        time.sleep(4)
        regista.stop_maintenance()

        after = len(regista.query_work_items(workflow_name="test_workflow").items)
        assert after > before


class TestMaintenanceWitnessReceiptSweep:
    def test_sweeps_stuck_in_progress_receipts(self, regista):
        regista.register_witness(
            "http://127.0.0.1:1",
            max_failures=100,
            max_retries=100,
        )

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "witness sweep test"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE witness_receipts SET status = 'in_progress', "
                "last_attempt_at = %s WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=600)],
            )

        count = regista.sweep_stuck_witness_receipts(max_age_seconds=300)
        assert count >= 1

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT status FROM witness_receipts WHERE status = 'pending'"
            ).fetchall()
        assert len(rows) >= 1

    def test_sweeps_stuck_receipts_from_maintenance(self, regista):
        regista.register_witness(
            "http://127.0.0.1:1",
            max_failures=100,
            max_retries=100,
        )

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "witness maint sweep"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE witness_receipts SET status = 'in_progress', "
                "last_attempt_at = %s WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=600)],
            )

        regista.start_maintenance(sweep_interval=1, witness_interval=1)
        time.sleep(3)
        regista.stop_maintenance()

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT status FROM witness_receipts WHERE status = 'pending'"
            ).fetchall()
        assert len(rows) >= 1


class TestMaintenanceTimestampBatchSweep:
    def test_sweeps_stale_pending_batches(self, regista):
        with raw_transaction(regista) as conn:
            conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, submitted_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    uuid.uuid4(), b"\x00" * 32, 1, 1,
                    datetime.now(UTC) - timedelta(seconds=600),
                    datetime.now(UTC) - timedelta(seconds=600),
                    1, "pending",
                    datetime.now(UTC) - timedelta(seconds=600),
                ],
            )

        count = regista.sweep_stale_timestamp_batches(max_age_seconds=300)
        assert count == 1

        with raw_transaction(regista) as conn:
            row = conn.execute(
                "SELECT status, error_message FROM tsp_batches "
                "WHERE status = 'failed'"
            ).fetchone()
        assert row is not None
        assert "stale" in row["error_message"]

    def test_does_not_sweep_recent_pending(self, regista):
        with raw_transaction(regista) as conn:
            conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, submitted_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())",
                [
                    uuid.uuid4(), b"\x00" * 32, 1, 1,
                    datetime.now(UTC), datetime.now(UTC),
                    1, "pending",
                ],
            )

        count = regista.sweep_stale_timestamp_batches(max_age_seconds=300)
        assert count == 0


class TestMaintenanceMetricsRefresh:
    def test_refresh_hook_queue_metrics(self, regista_v2):
        regista = regista_v2
        regista.register_validator("validate_start", lambda ctx: None)

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "metrics refresh"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})
        regista.transition(wi.work_item_id, "submit_review", "agent-1",
                            actor_metadata={"role": "agent"})

        regista.start_maintenance(sweep_interval=1, hook_poll_interval=1)
        time.sleep(3)
        regista.stop_maintenance()

        assert regista._maintenance_thread.last_cycle_ok
