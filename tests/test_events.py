from __future__ import annotations

import uuid

import pytest
from conftest import WORKFLOW_NAME

from regista import RegistaError
from regista._errors import ErrorCode


def test_free_form_append(sub, make_feature) -> None:
    work_item = make_feature()
    event = sub.append_event(
        work_item.work_item_id,
        "alice",
        transition="note",
        payload={"text": "hello"},
    )

    assert event.transition == "note"
    assert event.payload == {"text": "hello"}
    assert event.work_item_id == work_item.work_item_id


def test_append_workflow_transition_name_is_blocked(sub, make_feature) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.append_event(work_item.work_item_id, "alice", transition="start")
    assert exc.value.code is ErrorCode.TRANSITION_VIA_APPEND_BLOCKED


def test_reserved_transition_name_is_blocked(sub, make_feature) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.append_event(work_item.work_item_id, "alice", transition="claim_acquired")
    assert exc.value.code is ErrorCode.TRANSITION_VIA_APPEND_BLOCKED


def test_event_seq_is_gap_free_and_monotonic(sub, make_feature) -> None:
    work_item = make_feature()
    sub.append_event(work_item.work_item_id, "alice", transition="note")
    sub.append_event(work_item.work_item_id, "alice", transition="note")
    sub.append_event(work_item.work_item_id, "alice", transition="note")

    events = sub.read_events(work_item_id=work_item.work_item_id)
    seqs = [e.event_seq for e in events]
    assert seqs == [1, 2, 3, 4]


def test_event_seq_is_per_work_item(sub, make_feature) -> None:
    first = make_feature()
    second = make_feature()

    first_event = sub.append_event(first.work_item_id, "alice", transition="note")
    second_event = sub.append_event(second.work_item_id, "alice", transition="note")

    assert first_event.event_seq == 2
    assert second_event.event_seq == 2


def test_idempotent_create_retry_returns_same_work_item(sub) -> None:
    event_id = uuid.uuid4()
    fields = {"title": "idem", "priority": "low", "metadata": {}}

    first, first_event = sub.create_work_item(
        WORKFLOW_NAME, "feature", "alice", custom_fields=fields, event_id=event_id
    )
    second, second_event = sub.create_work_item(
        WORKFLOW_NAME, "feature", "alice", custom_fields=fields, event_id=event_id
    )

    assert first.work_item_id == second.work_item_id
    assert first_event.event_id == second_event.event_id

    page = sub.query_work_items(work_item_types=["feature"])
    assert [w.work_item_id for w in page.items] == [first.work_item_id]


def test_read_events_filters_and_ordering(sub, make_feature) -> None:
    work_item = make_feature()
    sub.append_event(work_item.work_item_id, "alice", transition="note", payload={"n": 1})
    sub.append_event(work_item.work_item_id, "bob", transition="comment", payload={"n": 2})
    sub.append_event(work_item.work_item_id, "alice", transition="note", payload={"n": 3})

    all_events = sub.read_events(work_item_id=work_item.work_item_id)
    assert [e.event_seq for e in all_events] == [1, 2, 3, 4]
    assert [e.transition for e in all_events] == ["created", "note", "comment", "note"]

    by_actor = sub.read_events(actor_id="bob")
    assert [e.transition for e in by_actor] == ["comment"]

    by_transition = sub.read_events(transition="note")
    assert [e.payload for e in by_transition] == [{"n": 3}, {"n": 1}]

    limited = sub.read_events(work_item_id=work_item.work_item_id, limit=2)
    assert [e.event_seq for e in limited] == [3, 4]

    before = sub.read_events(work_item_id=work_item.work_item_id, before_seq=3)
    assert [e.event_seq for e in before] == [1, 2]


def test_read_events_limit_default_ordering_without_work_item(sub, make_feature) -> None:
    first = make_feature()
    second = make_feature()
    sub.append_event(first.work_item_id, "alice", transition="note")
    sub.append_event(second.work_item_id, "alice", transition="note")

    events = sub.read_events(transition="note")
    assert len(events) == 2


def test_expected_event_seq_mismatch_rejected(sub, make_feature) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.append_event(
            work_item.work_item_id,
            "alice",
            transition="note",
            expected_event_seq=99,
        )
    assert exc.value.code is ErrorCode.CONCURRENT_MODIFICATION


def test_expected_event_seq_match_accepted(sub, make_feature) -> None:
    work_item = make_feature()

    event = sub.append_event(
        work_item.work_item_id,
        "alice",
        transition="note",
        expected_event_seq=work_item.next_event_seq,
    )
    assert event.event_seq == work_item.next_event_seq
