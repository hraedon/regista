from __future__ import annotations

import uuid

import pytest

from regista._errors import RegistaError
from regista._witness import (
    _validate_event_filter,
    _validate_url,
    event_matches_filter,
)


class TestValidateUrl:
    def test_valid_https(self):
        _validate_url("https://example.com/webhook")

    def test_valid_http(self):
        _validate_url("http://localhost:8080/webhook")

    def test_empty_rejected(self):
        with pytest.raises(RegistaError, match="must start with"):
            _validate_url("")

    def test_ftp_rejected(self):
        with pytest.raises(RegistaError, match="must start with"):
            _validate_url("ftp://example.com")


class TestValidateEventFilter:
    def test_none_passes(self):
        assert _validate_event_filter(None) is None

    def test_valid_filter(self):
        f = {"transitions": ["close", "verify"]}
        result = _validate_event_filter(f)
        assert result == f

    def test_all_fields(self):
        f = {
            "transitions": ["close"],
            "work_item_types": ["finding"],
            "workflows": ["pen-test"],
        }
        result = _validate_event_filter(f)
        assert result == f

    def test_unknown_key_rejected(self):
        with pytest.raises(RegistaError, match="not allowed"):
            _validate_event_filter({"unknown_key": ["value"]})

    def test_non_list_value_rejected(self):
        with pytest.raises(RegistaError, match="must be a list"):
            _validate_event_filter({"transitions": "close"})

    def test_non_string_element_rejected(self):
        with pytest.raises(RegistaError, match="must be a list of strings"):
            _validate_event_filter({"transitions": [1, 2]})


class TestEventMatchesFilter:
    def test_none_filter_matches_all(self):
        event = {"transition": "close", "workflow_name": "pen-test"}
        assert event_matches_filter(event, None) is True

    def test_transition_filter_match(self):
        event = {"transition": "close", "workflow_name": "pen-test"}
        assert event_matches_filter(event, {"transitions": ["close"]}) is True

    def test_transition_filter_no_match(self):
        event = {"transition": "verify", "workflow_name": "pen-test"}
        assert event_matches_filter(event, {"transitions": ["close"]}) is False

    def test_null_transition_excluded_when_filter_set(self):
        event = {"transition": None, "workflow_name": "pen-test"}
        assert event_matches_filter(event, {"transitions": ["close"]}) is False

    def test_workflows_filter(self):
        event = {"transition": "close", "workflow_name": "pen-test"}
        assert event_matches_filter(event, {"workflows": ["pen-test"]}) is True
        assert event_matches_filter(event, {"workflows": ["other"]}) is False

    def test_work_item_types_filter(self):
        event = {"transition": "close", "work_item_type": "finding"}
        assert event_matches_filter(
            event, {"work_item_types": ["finding"]}
        ) is True
        assert event_matches_filter(
            event, {"work_item_types": ["report"]}
        ) is False

    def test_and_semantics(self):
        event = {
            "transition": "close",
            "workflow_name": "pen-test",
            "work_item_type": "finding",
        }
        assert event_matches_filter(
            event,
            {"transitions": ["close"], "workflows": ["pen-test"]},
        ) is True
        assert event_matches_filter(
            event,
            {"transitions": ["close"], "workflows": ["other"]},
        ) is False

    def test_null_transition_works_with_workflow_only_filter(self):
        event = {"transition": None, "workflow_name": "pen-test"}
        assert event_matches_filter(
            event, {"workflows": ["pen-test"]}
        ) is True


class TestInMemoryWitness:
    def test_register_witness(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        wid = sub.register_witness("https://example.com/webhook")
        assert isinstance(wid, uuid.UUID)
        witnesses = sub.list_witnesses()
        assert len(witnesses) == 1
        assert witnesses[0]["url"] == "https://example.com/webhook"
        assert witnesses[0]["status"] == "active"

    def test_register_witness_with_filter(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        sub.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        witnesses = sub.list_witnesses()
        assert witnesses[0]["event_filter"] == {"transitions": ["close"]}

    def test_unregister_witness(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        wid = sub.register_witness("https://example.com/webhook")
        sub.unregister_witness(wid)
        assert len(sub.list_witnesses()) == 0

    def test_unregister_nonexistent_raises(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        with pytest.raises(RegistaError, match="WITNESS_NOT_FOUND"):
            sub.unregister_witness(uuid.uuid4())

    def test_pause_witness(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        wid = sub.register_witness("https://example.com/webhook")
        sub.pause_witness(wid)
        assert sub.list_witnesses()[0]["status"] == "paused"

    def test_reactivate_witness(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        wid = sub.register_witness("https://example.com/webhook")
        sub.pause_witness(wid)
        sub.reactivate_witness(wid)
        assert sub.list_witnesses()[0]["status"] == "active"

    def test_list_witnesses_filtered(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        wid1 = sub.register_witness("https://example.com/webhook1")
        wid2 = sub.register_witness("https://example.com/webhook2")
        sub.pause_witness(wid2)
        active = sub.list_witnesses(status="active")
        assert len(active) == 1
        assert active[0]["witness_id"] == str(wid1)

    def test_witness_receipts_created_on_event(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()


        import os

        key_path = os.path.join(
            os.path.dirname(__file__), "test_keys.json"
        )
        sub = InMemoryRegista(hmac_key_path=key_path)
        wid = sub.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["created"]},
        )
        wf_yaml = """
name: test
version: 1
regista_version: "0.1.0"

states:
  - name: open
    initial: true
  - name: closed
    terminal: true

transitions:
  - name: close
    from: open
    to: closed
    allowed_roles: []

work_item_types:
  - name: task
    custom_fields: []

roles: []
"""
        sub.register_workflow(wf_yaml)
        _wi, evt = sub.create_work_item("test", "task", "actor-1")
        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid)
        assert receipts[0]["status"] == "pending"

    def test_filter_skips_event(self):
        import os

        from regista._in_memory import InMemoryRegista

        key_path = os.path.join(
            os.path.dirname(__file__), "test_keys.json"
        )
        sub = InMemoryRegista(hmac_key_path=key_path)
        sub.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        wf_yaml = """
name: test
version: 1
regista_version: "0.1.0"

states:
  - name: open
    initial: true
  - name: closed
    terminal: true

transitions:
  - name: close
    from: open
    to: closed
    allowed_roles: []

work_item_types:
  - name: task
    custom_fields: []

roles: []
"""
        sub.register_workflow(wf_yaml)
        _wi, evt = sub.create_work_item("test", "task", "actor-1")
        receipts = sub.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 0

    def test_deliver_pending_witness_receipts_noop(self):
        from regista._in_memory import InMemoryRegista

        sub = InMemoryRegista()
        assert sub.deliver_pending_witness_receipts() == 0
