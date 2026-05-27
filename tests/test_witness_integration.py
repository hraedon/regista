from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_wit_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWitnessRegistration:
    def test_register_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        assert isinstance(wid, uuid.UUID)
        witnesses = regista.list_witnesses()
        assert len(witnesses) == 1
        assert witnesses[0]["url"] == "https://example.com/webhook"
        assert witnesses[0]["status"] == "active"

    def test_register_witness_with_filter(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        witnesses = regista.list_witnesses()
        assert witnesses[0]["event_filter"] == {"transitions": ["close"]}

    def test_register_witness_with_headers(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            headers={"Authorization": "Bearer token123"},
        )
        witnesses = regista.list_witnesses()
        assert witnesses[0]["headers"] == {"Authorization": "Bearer token123"}

    def test_unregister_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.unregister_witness(wid)
        assert len(regista.list_witnesses()) == 0

    def test_unregister_nonexistent_raises(self, regista):
        with pytest.raises(RegistaError, match="WITNESS_NOT_FOUND"):
            regista.unregister_witness(uuid.uuid4())

    def test_pause_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.pause_witness(wid)
        witnesses = regista.list_witnesses()
        assert witnesses[0]["status"] == "paused"

    def test_reactivate_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.pause_witness(wid)
        regista.reactivate_witness(wid)
        witnesses = regista.list_witnesses()
        assert witnesses[0]["status"] == "active"

    def test_list_witnesses_filtered(self, regista):
        regista.register_witness("https://example.com/webhook1")
        wid2 = regista.register_witness("https://example.com/webhook2")
        regista.pause_witness(wid2)
        active = regista.list_witnesses(status="active")
        assert len(active) == 1
        paused = regista.list_witnesses(status="paused")
        assert len(paused) == 1

    def test_pause_nonexistent_raises(self, regista):
        with pytest.raises(RegistaError, match="WITNESS_NOT_FOUND"):
            regista.pause_witness(uuid.uuid4())


class TestWitnessReceipts:
    def test_receipt_created_on_create_work_item(self, regista):
        wid = regista.register_witness(
            "https://example.com/webhook",
            event_filter=None,
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid)
        assert receipts[0]["status"] == "pending"

    def test_filter_skips_event(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 0

    def test_multiple_witnesses(self, regista):
        wid1 = regista.register_witness(
            "https://example.com/webhook1",
        )
        regista.register_witness(
            "https://example.com/webhook2",
            event_filter={"transitions": ["start"]},
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid1)

    def test_receipt_created_on_transition(self, regista):
        regista.register_witness("https://example.com/webhook")
        wi, _evt_create = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt_transition = regista.transition(
            wi.work_item_id, "start", "actor-1",
            actor_metadata={"role": "agent"},
        )
        receipts = regista.list_witness_receipts(event_id=evt_transition.event_id)
        assert len(receipts) == 1

    def test_receipt_created_on_append_event(self, regista):
        regista.register_witness("https://example.com/webhook")
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt = regista.append_event(
            wi.work_item_id, "actor-1",
            transition="note",
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1

    def test_list_receipts_by_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(witness_id=wid)
        assert len(receipts) == 1

    def test_deliver_pending_receipts_returns_zero(self, regista):
        regista.register_witness("https://unreachable.example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        count = regista.deliver_pending_witness_receipts()
        assert count == 0

    def test_unregister_abandons_pending_receipts(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        regista.unregister_witness(wid)
        receipts = regista.list_witness_receipts()
        assert len(receipts) == 0
