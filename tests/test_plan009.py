from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from substrate import Substrate

DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")
WORKFLOW_PATH = str(Path(__file__).parent / "test_workflow.yaml")


@pytest.fixture
def substrate():
    project_name = f"plan009_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project_name, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()


class TestMaintenanceStartStop:
    def test_start_stop(self, substrate):
        assert substrate.maintenance_healthy
        substrate.start_maintenance(sweep_interval=5)
        assert substrate._maintenance_thread.is_running
        substrate.stop_maintenance()
        assert not substrate._maintenance_thread.is_running

    def test_close_stops_maintenance(self, substrate):
        substrate.start_maintenance(sweep_interval=5)
        assert substrate._maintenance_thread.is_running
        substrate.close()
        assert not substrate._maintenance_thread.is_running

    def test_maintenance_healthy_reflects_state(self, substrate):
        assert substrate.maintenance_healthy
        substrate.start_maintenance(sweep_interval=1)
        time.sleep(0.3)
        assert substrate.maintenance_healthy
        substrate.stop_maintenance()
        assert not substrate.maintenance_healthy


class TestMaintenanceSweeps:
    def test_sweeps_expired_claims(self, substrate):
        wi, _ = substrate.create_work_item("test_workflow", "feature", "actor-a",
                                           custom_fields={"title": "t", "priority": "low"})
        substrate.acquire_claim(wi.work_item_id, "actor-a", ttl_seconds=1)
        claim = substrate.get_work_item(wi.work_item_id)
        assert claim.claimed_by == "actor-a"

        substrate.start_maintenance(sweep_interval=1)
        time.sleep(3)
        substrate.stop_maintenance()

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None


class TestMaintenanceResilience:
    def test_error_does_not_kill_thread(self, substrate):
        substrate.start_maintenance(sweep_interval=1)
        time.sleep(0.3)
        assert substrate._maintenance_thread.is_running
        assert substrate._maintenance_thread.last_cycle_ok

        substrate._mgr.close()
        substrate._mgr = None
        time.sleep(2)

        assert substrate._maintenance_thread.is_running
        assert not substrate._maintenance_thread.last_cycle_ok

        substrate._maintenance_thread.stop()
