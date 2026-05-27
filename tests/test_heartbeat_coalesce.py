from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._contract import compute_coalesce_threshold
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
WORKFLOW_YAML = Path(WORKFLOW_PATH).read_text()


class TestComputeCoalesceThreshold:
    def test_default_returns_max_of_60_and_half_ttl(self):
        assert compute_coalesce_threshold(60) == 60.0
        assert compute_coalesce_threshold(300) == 150.0
        assert compute_coalesce_threshold(100) == 60.0
        assert compute_coalesce_threshold(200) == 100.0

    def test_override_used_when_provided(self):
        assert compute_coalesce_threshold(300, override=10.0) == 10.0
        assert compute_coalesce_threshold(300, override=500.0) == 500.0

    def test_negative_override_clamped_to_zero(self):
        assert compute_coalesce_threshold(300, override=-5.0) == 0.0


@pytest.fixture(params=["real", "in_memory"])
def sub(request):
    if request.param == "real":
        from regista import Regista

        project = f"test_hbc_{uuid.uuid4().hex[:8]}"
        s = Regista.create_project(DSN, project, KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        yield s
        s.close()
        drop_project_schema(DSN, project)
    else:
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow(WORKFLOW_YAML)
        yield s


def _count_heartbeat_events(sub, work_item_id):
    events = sub.read_events(work_item_id=work_item_id)
    return sum(1 for e in events if e.transition == "claim_heartbeat")


class TestHeartbeatCoalescing:
    def test_first_heartbeat_always_emits_event(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "First heartbeat"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert _count_heartbeat_events(sub, wi.work_item_id) == 1

    def test_two_rapid_heartbeats_produce_one_event(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Rapid coalesce"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert _count_heartbeat_events(sub, wi.work_item_id) == 1

    def test_past_threshold_produces_second_event(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Threshold"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.heartbeat_claim(
            wi.work_item_id, "agent-1", ttl_seconds=300,
            coalesce_threshold=0.0,
        )
        sub.heartbeat_claim(
            wi.work_item_id, "agent-1", ttl_seconds=300,
            coalesce_threshold=0.0,
        )
        assert _count_heartbeat_events(sub, wi.work_item_id) == 2

    def test_coalesce_threshold_zero_always_emits(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Zero threshold"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        for _ in range(5):
            sub.heartbeat_claim(
                wi.work_item_id, "agent-1", ttl_seconds=300,
                coalesce_threshold=0.0,
            )
        assert _count_heartbeat_events(sub, wi.work_item_id) == 5

    def test_default_threshold_60_seconds_coalesces_rapid(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Default 60s"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        assert _count_heartbeat_events(sub, wi.work_item_id) == 1

    def test_coalesced_heartbeat_still_extends_claim(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Extend coalesced"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        c1 = sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        c2 = sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert c2.expires_at > c1.expires_at
        assert _count_heartbeat_events(sub, wi.work_item_id) == 1


class TestHeartbeatEventPayload:
    def test_event_contains_coalesce_threshold(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Payload check"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.heartbeat_claim(
            wi.work_item_id, "agent-1", ttl_seconds=300,
            coalesce_threshold=42.0,
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        hb = [e for e in events if e.transition == "claim_heartbeat"]
        assert len(hb) == 1
        assert hb[0].payload["coalesce_threshold"] == 42.0
