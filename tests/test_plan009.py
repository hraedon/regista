from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from regista import Regista

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")
WORKFLOW_PATH = str(Path(__file__).parent / "test_workflow.yaml")


@pytest.fixture
def regista():
    project_name = f"plan009_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project_name, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()


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
