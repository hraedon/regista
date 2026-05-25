from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from substrate._errors import SubstrateError
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_wit_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWitnessRegistration:
    def test_register_witness(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        assert isinstance(wid, uuid.UUID)
        witnesses = substrate.list_witnesses()
        assert len(witnesses) == 1
        assert witnesses[0]["url"] == "https://example.com/webhook"
        assert witnesses[0]["status"] == "active"

    def test_register_witness_with_filter(self, substrate):
        substrate.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        witnesses = substrate.list_witnesses()
        assert witnesses[0]["event_filter"] == {"transitions": ["close"]}

    def test_register_witness_with_headers(self, substrate):
        substrate.register_witness(
            "https://example.com/webhook",
            headers={"Authorization": "Bearer token123"},
        )
        witnesses = substrate.list_witnesses()
        assert witnesses[0]["headers"] == {"Authorization": "Bearer token123"}

    def test_unregister_witness(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        substrate.unregister_witness(wid)
        assert len(substrate.list_witnesses()) == 0

    def test_unregister_nonexistent_raises(self, substrate):
        with pytest.raises(SubstrateError, match="WITNESS_NOT_FOUND"):
            substrate.unregister_witness(uuid.uuid4())

    def test_pause_witness(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        substrate.pause_witness(wid)
        witnesses = substrate.list_witnesses()
        assert witnesses[0]["status"] == "paused"

    def test_reactivate_witness(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        substrate.pause_witness(wid)
        substrate.reactivate_witness(wid)
        witnesses = substrate.list_witnesses()
        assert witnesses[0]["status"] == "active"

    def test_list_witnesses_filtered(self, substrate):
        substrate.register_witness("https://example.com/webhook1")
        wid2 = substrate.register_witness("https://example.com/webhook2")
        substrate.pause_witness(wid2)
        active = substrate.list_witnesses(status="active")
        assert len(active) == 1
        paused = substrate.list_witnesses(status="paused")
        assert len(paused) == 1

    def test_pause_nonexistent_raises(self, substrate):
        with pytest.raises(SubstrateError, match="WITNESS_NOT_FOUND"):
            substrate.pause_witness(uuid.uuid4())


class TestWitnessReceipts:
    def test_receipt_created_on_create_work_item(self, substrate):
        wid = substrate.register_witness(
            "https://example.com/webhook",
            event_filter=None,
        )
        _wi, evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = substrate.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid)
        assert receipts[0]["status"] == "pending"

    def test_filter_skips_event(self, substrate):
        substrate.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        _wi, evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = substrate.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 0

    def test_multiple_witnesses(self, substrate):
        wid1 = substrate.register_witness(
            "https://example.com/webhook1",
        )
        substrate.register_witness(
            "https://example.com/webhook2",
            event_filter={"transitions": ["start"]},
        )
        _wi, evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = substrate.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid1)

    def test_receipt_created_on_transition(self, substrate):
        substrate.register_witness("https://example.com/webhook")
        wi, _evt_create = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt_transition = substrate.transition(
            wi.work_item_id, "start", "actor-1",
            actor_metadata={"role": "agent"},
        )
        receipts = substrate.list_witness_receipts(event_id=evt_transition.event_id)
        assert len(receipts) == 1

    def test_receipt_created_on_append_event(self, substrate):
        substrate.register_witness("https://example.com/webhook")
        wi, _ = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt = substrate.append_event(
            wi.work_item_id, "actor-1",
            transition="note",
        )
        receipts = substrate.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1

    def test_list_receipts_by_witness(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        _wi, _evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = substrate.list_witness_receipts(witness_id=wid)
        assert len(receipts) == 1

    def test_deliver_pending_receipts_returns_zero(self, substrate):
        substrate.register_witness("https://unreachable.example.com/webhook")
        _wi, _evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        count = substrate.deliver_pending_witness_receipts()
        assert count == 0

    def test_unregister_abandons_pending_receipts(self, substrate):
        wid = substrate.register_witness("https://example.com/webhook")
        _wi, _evt = substrate.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        substrate.unregister_witness(wid)
        receipts = substrate.list_witness_receipts()
        assert len(receipts) == 0
