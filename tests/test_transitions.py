from __future__ import annotations

import uuid

import pytest

from regista import RegistaError
from regista._errors import ErrorCode


def test_happy_path_through_terminal(sub, make_feature, agent_meta, reviewer_meta) -> None:
    work_item = make_feature()

    sub.transition(work_item.work_item_id, "start", "alice", actor_metadata=agent_meta)
    assert sub.get_work_item(work_item.work_item_id).current_state == "in_progress"

    sub.transition(
        work_item.work_item_id, "submit_review", "alice", actor_metadata=agent_meta
    )
    assert sub.get_work_item(work_item.work_item_id).current_state == "review"

    sub.transition(
        work_item.work_item_id, "approve", "bob", actor_metadata=reviewer_meta
    )
    final = sub.get_work_item(work_item.work_item_id)
    assert final is not None
    assert final.current_state == "done"


def test_back_edge_returns_to_in_progress(sub, make_feature, agent_meta, reviewer_meta) -> None:
    work_item = make_feature()
    sub.transition(work_item.work_item_id, "start", "alice", actor_metadata=agent_meta)
    sub.transition(
        work_item.work_item_id, "submit_review", "alice", actor_metadata=agent_meta
    )
    sub.transition(
        work_item.work_item_id, "request_changes", "bob", actor_metadata=reviewer_meta
    )
    assert sub.get_work_item(work_item.work_item_id).current_state == "in_progress"


def test_invalid_transition_from_wrong_state(sub, make_feature, reviewer_meta) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.transition(
            work_item.work_item_id, "approve", "bob", actor_metadata=reviewer_meta
        )
    assert exc.value.code is ErrorCode.INVALID_TRANSITION


@pytest.mark.parametrize("metadata", [None, {"role": "reviewer"}])
def test_role_gating_refuses_missing_or_wrong_role(sub, make_feature, metadata) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.transition(work_item.work_item_id, "start", "alice", actor_metadata=metadata)
    assert exc.value.code is ErrorCode.ROLE_NOT_PERMITTED


def test_strict_roles_require_registration(
    strict_sub, make_feature, register_role
) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        strict_sub.transition(
            work_item.work_item_id,
            "start",
            "dave",
            actor_metadata={"role": "agent", "role_source": "config"},
        )
    assert exc.value.code is ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED


def test_strict_roles_reject_role_not_registered_for_actor(
    strict_sub, make_feature, register_role
) -> None:
    register_role("carol", "reviewer")
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        strict_sub.transition(
            work_item.work_item_id,
            "start",
            "carol",
            actor_metadata={"role": "agent", "role_source": "config"},
        )
    assert exc.value.code is ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED


def test_strict_roles_reject_untrusted_role_source(
    strict_sub, make_feature, register_role
) -> None:
    register_role("dave", "agent")
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        strict_sub.transition(
            work_item.work_item_id,
            "start",
            "dave",
            actor_metadata={"role": "agent", "role_source": "prompt"},
        )
    assert exc.value.code is ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED


def test_strict_roles_allow_registered_actor(
    strict_sub, make_feature, register_role
) -> None:
    register_role("dave", "agent")
    work_item = make_feature()

    event = strict_sub.transition(
        work_item.work_item_id,
        "start",
        "dave",
        actor_metadata={"role": "agent", "role_source": "config"},
    )
    assert event.transition == "start"


def test_custom_field_update_is_validated_and_applied(
    sub, make_feature, agent_meta
) -> None:
    work_item = make_feature(priority="low")

    sub.transition(
        work_item.work_item_id,
        "start",
        "alice",
        actor_metadata=agent_meta,
        custom_fields={"priority": "high"},
    )
    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.custom_fields["priority"] == "high"


@pytest.mark.parametrize(
    "custom_fields",
    [
        {"priority": "urgent"},
        {"ghost": "value"},
        {"title": 42},
    ],
)
def test_custom_field_update_violations(
    sub, make_feature, agent_meta, custom_fields
) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.transition(
            work_item.work_item_id,
            "start",
            "alice",
            actor_metadata=agent_meta,
            custom_fields=custom_fields,
        )
    assert exc.value.code is ErrorCode.CUSTOM_FIELD_VIOLATION


def test_transition_releases_claim(sub, make_feature, agent_meta) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    sub.transition(work_item.work_item_id, "start", "alice", actor_metadata=agent_meta)

    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.claimed_by is None

    claim = sub.acquire_claim(work_item.work_item_id, "bob", ttl_seconds=300)
    assert claim.actor_id == "bob"


def test_transition_expected_attempt_number_mismatch(
    sub, make_feature, agent_meta
) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    with pytest.raises(RegistaError) as exc:
        sub.transition(
            work_item.work_item_id,
            "start",
            "alice",
            actor_metadata=agent_meta,
            expected_attempt_number=99,
        )
    assert exc.value.code is ErrorCode.CLAIM_LOST

    event = sub.transition(
        work_item.work_item_id,
        "start",
        "alice",
        actor_metadata=agent_meta,
        expected_attempt_number=1,
    )
    assert event.transition == "start"


def test_idempotent_transition_returns_same_event(sub, make_feature, agent_meta) -> None:
    work_item = make_feature()
    event_id = uuid.uuid4()

    first = sub.transition(
        work_item.work_item_id,
        "start",
        "alice",
        actor_metadata=agent_meta,
        event_id=event_id,
    )
    second = sub.transition(
        work_item.work_item_id,
        "start",
        "alice",
        actor_metadata=agent_meta,
        event_id=event_id,
    )

    assert first.event_id == second.event_id
    assert first.event_seq == second.event_seq

    starts = [
        e
        for e in sub.read_events(work_item_id=work_item.work_item_id)
        if e.transition == "start"
    ]
    assert len(starts) == 1


def test_transition_same_event_id_different_payload_collides(
    sub, make_feature, agent_meta
) -> None:
    work_item = make_feature()
    event_id = uuid.uuid4()

    sub.transition(
        work_item.work_item_id,
        "start",
        "alice",
        actor_metadata=agent_meta,
        event_id=event_id,
        payload={"a": 1},
    )

    with pytest.raises(RegistaError) as exc:
        sub.transition(
            work_item.work_item_id,
            "start",
            "alice",
            actor_metadata=agent_meta,
            event_id=event_id,
            payload={"a": 2},
        )
    assert exc.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD
