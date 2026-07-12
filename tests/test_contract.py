from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from regista._contract import (
    check_actor_role_authorized,
    check_append_blocked,
    check_expected_seq,
    check_idempotency,
    check_role_gating,
    resolve_claim_acquire,
    resolve_heartbeat,
    resolve_transition,
    should_escalate,
    validate_actor_id,
    validate_actor_kind,
    validate_json_safe_value,
    validate_link_type,
    validate_not_before,
    validate_read_events_filters,
    validate_release,
    validate_ttl,
    validate_work_item_exists,
)
from regista._errors import ErrorCode, RegistaError
from regista._types import Event


def _make_event(
    event_id: uuid.UUID | None = None,
    actor_id: str = "actor-1",
    transition: str | None = "approve",
    work_item_id: uuid.UUID | None = None,
) -> Event:
    return Event(
        event_id=event_id or uuid.uuid4(),
        work_item_id=work_item_id or uuid.uuid4(),
        event_seq=1,
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata=None,
        key_id="key-1",
        workflow_name="wf",
        workflow_version=1,
        timestamp=datetime.now(UTC),
        transition=transition,
        payload=None,
        payload_canonical_hash=b"",
        signature=b"",
    )


NOW = datetime.now(UTC)


class TestValidateActorKind:
    def test_accepts_agent(self):
        validate_actor_kind("agent")

    def test_accepts_human(self):
        validate_actor_kind("human")

    def test_accepts_system(self):
        validate_actor_kind("system")

    def test_rejects_unknown(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_actor_kind("bot")
        assert exc_info.value.code == ErrorCode.INVALID_ACTOR_KIND

    def test_rejects_empty(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_actor_kind("")
        assert exc_info.value.code == ErrorCode.INVALID_ACTOR_KIND


class TestValidateTtl:
    def test_accepts_positive(self):
        validate_ttl(1)
        validate_ttl(300)

    def test_rejects_zero(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_ttl(0)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_negative(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_ttl(-1)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestValidateNotBefore:
    def test_none_passes(self):
        validate_not_before(None, NOW)

    def test_past_passes(self):
        validate_not_before(NOW - timedelta(hours=1), NOW)

    def test_equal_to_now_passes(self):
        validate_not_before(NOW, NOW)

    def test_future_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_not_before(NOW + timedelta(seconds=1), NOW)
        assert exc_info.value.code == ErrorCode.NOT_BEFORE_FUTURE


class TestResolveTransition:
    TRANSITIONS: ClassVar[list[dict]] = [
        {"name": "approve", "from_state": "pending", "to_state": "approved"},
        {"name": "reject", "from_state": "pending", "to_state": "rejected"},
        {"name": "approve", "from_state": "review", "to_state": "approved"},
    ]

    def test_finds_matching(self):
        t = resolve_transition(self.TRANSITIONS, "pending", "approve", "wf", 1)
        assert t["to_state"] == "approved"

    def test_matches_on_name_and_from_state(self):
        t = resolve_transition(self.TRANSITIONS, "review", "approve", "wf", 1)
        assert t["to_state"] == "approved"

    def test_rejects_wrong_from_state(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_transition(self.TRANSITIONS, "approved", "approve", "wf", 1)
        assert exc_info.value.code == ErrorCode.INVALID_TRANSITION

    def test_rejects_unknown_name(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_transition(self.TRANSITIONS, "pending", "unknown", "wf", 1)
        assert exc_info.value.code == ErrorCode.INVALID_TRANSITION

    def test_error_includes_workflow_context(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_transition([], "s", "t", "my_workflow", 3)
        assert "my_workflow" in exc_info.value.message
        assert "v3" in exc_info.value.message


class TestCheckRoleGating:
    def test_no_roles_returns_none(self):
        assert check_role_gating([], {"role": "admin"}, "do_thing") is None

    def test_matching_role_returns_role(self):
        assert check_role_gating(["admin"], {"role": "admin"}, "do_thing") == "admin"

    def test_mismatched_role_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_role_gating(["admin"], {"role": "viewer"}, "do_thing")
        assert exc_info.value.code == ErrorCode.ROLE_NOT_PERMITTED

    def test_none_metadata_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_role_gating(["admin"], None, "do_thing")
        assert exc_info.value.code == ErrorCode.ROLE_NOT_PERMITTED

    def test_metadata_without_role_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_role_gating(["admin"], {}, "do_thing")
        assert exc_info.value.code == ErrorCode.ROLE_NOT_PERMITTED


class TestCheckActorRoleAuthorized:
    def test_empty_registered_roles_passes(self):
        check_actor_role_authorized(set(), "a1", "admin")

    def test_matching_role_passes(self):
        check_actor_role_authorized({"admin", "viewer"}, "a1", "admin")

    def test_mismatched_role_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_actor_role_authorized({"admin"}, "a1", "viewer")
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED
        assert exc_info.value.detail is not None
        assert "allowed_roles" in exc_info.value.detail


class TestCheckAppendBlocked:
    TRANSITIONS: ClassVar[list[dict]] = [
        {"name": "approve", "from_state": "pending", "to_state": "approved"},
    ]

    def test_none_transition_passes(self):
        check_append_blocked(self.TRANSITIONS, None, "wf")

    def test_non_matching_passes(self):
        check_append_blocked(self.TRANSITIONS, "custom_note", "wf")

    def test_matching_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_append_blocked(self.TRANSITIONS, "approve", "wf")
        assert exc_info.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_empty_transitions_passes(self):
        check_append_blocked([], "approve", "wf")


class TestCheckIdempotency:
    def test_none_existing_returns_none(self):
        assert check_idempotency(None, "a1", "approve") is None

    def test_matching_returns_existing(self):
        evt = _make_event(actor_id="a1", transition="approve")
        result = check_idempotency(evt, "a1", "approve")
        assert result is evt

    def test_actor_mismatch_raises(self):
        evt = _make_event(actor_id="a1", transition="approve")
        with pytest.raises(RegistaError) as exc_info:
            check_idempotency(evt, "a2", "approve")
        assert exc_info.value.code == ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD

    def test_transition_mismatch_raises(self):
        evt = _make_event(actor_id="a1", transition="approve")
        with pytest.raises(RegistaError) as exc_info:
            check_idempotency(evt, "a1", "reject")
        assert exc_info.value.code == ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD

    def test_matching_with_none_transition_and_none_actor(self):
        evt = _make_event(actor_id="a1", transition="approve")
        result = check_idempotency(evt, None, None)
        assert result is evt

    def test_work_item_id_mismatch_raises(self):
        wi1 = uuid.uuid4()
        wi2 = uuid.uuid4()
        evt = _make_event(actor_id="a1", transition="approve", work_item_id=wi1)
        with pytest.raises(RegistaError) as exc_info:
            check_idempotency(evt, "a1", "approve", work_item_id=wi2)
        assert exc_info.value.code == ErrorCode.EVENT_ID_GLOBAL_COLLISION
        assert str(wi2) in exc_info.value.message

    def test_work_item_id_match_passes(self):
        wi1 = uuid.uuid4()
        evt = _make_event(actor_id="a1", transition="approve", work_item_id=wi1)
        result = check_idempotency(evt, "a1", "approve", work_item_id=wi1)
        assert result is evt

    def test_work_item_id_none_skips_check(self):
        evt = _make_event(actor_id="a1", transition="approve")
        result = check_idempotency(evt, "a1", "approve", work_item_id=None)
        assert result is evt


class TestCheckExpectedSeq:
    def test_none_expected_passes(self):
        check_expected_seq(5, None)

    def test_matching_passes(self):
        check_expected_seq(5, 5)

    def test_mismatching_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            check_expected_seq(5, 3)
        assert exc_info.value.code == ErrorCode.CONCURRENT_MODIFICATION


class TestValidateLinkType:
    LINK_TYPES: ClassVar[list[dict]] = [
        {"name": "depends_on", "source_type": "task", "target_type": "task"},
        {"name": "blocks", "source_type": "task", "target_type": "task"},
    ]

    def test_matching_passes(self):
        validate_link_type(self.LINK_TYPES, "task", "task", "depends_on")

    def test_wrong_name_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_link_type(self.LINK_TYPES, "task", "task", "related_to")
        assert exc_info.value.code == ErrorCode.LINK_TYPE_NOT_ALLOWED

    def test_wrong_source_type_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_link_type(self.LINK_TYPES, "bug", "task", "depends_on")
        assert exc_info.value.code == ErrorCode.LINK_TYPE_NOT_ALLOWED

    def test_wrong_target_type_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_link_type(self.LINK_TYPES, "task", "bug", "depends_on")
        assert exc_info.value.code == ErrorCode.LINK_TYPE_NOT_ALLOWED


class TestShouldEscalate:
    def test_none_threshold_returns_false(self):
        assert should_escalate(None, False, 5) is False

    def test_below_threshold_returns_false(self):
        assert should_escalate(3, False, 2) is False

    def test_at_threshold_returns_true(self):
        assert should_escalate(3, False, 3) is True

    def test_above_threshold_returns_true(self):
        assert should_escalate(3, False, 5) is True

    def test_already_escalated_returns_false(self):
        assert should_escalate(3, True, 3) is False


class TestValidateReadEventsFilters:
    def test_all_none_passes(self):
        validate_read_events_filters(None, None, None, None)

    def test_before_seq_with_work_item_id_passes(self):
        validate_read_events_filters(5, uuid.uuid4(), None, None)

    def test_before_seq_without_work_item_id_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_read_events_filters(5, None, None, None)
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_start_without_end_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_read_events_filters(None, None, NOW, None)
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_end_without_start_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_read_events_filters(None, None, None, NOW)
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_start_and_end_together_passes(self):
        validate_read_events_filters(None, None, NOW, NOW + timedelta(hours=1))


class TestResolveClaimAcquire:
    def test_fresh_acquire(self):
        r = resolve_claim_acquire(
            wi_not_before=None,
            claim_actor_id=None,
            claim_expires_at=None,
            claim_acquired_at=None,
            claim_attempt_number=None,
            wi_attempt_number=0,
            actor_id="a1",
            ttl_seconds=300,
            now=NOW,
        )
        assert r.action == "acquire"
        assert r.attempt_number == 1
        assert r.event_transition == "claim_acquired"
        assert r.prior_actor_id is None

    def test_extend_same_actor(self):
        acquired = NOW - timedelta(minutes=5)
        r = resolve_claim_acquire(
            wi_not_before=None,
            claim_actor_id="a1",
            claim_expires_at=NOW + timedelta(minutes=5),
            claim_acquired_at=acquired,
            claim_attempt_number=1,
            wi_attempt_number=1,
            actor_id="a1",
            ttl_seconds=300,
            now=NOW,
        )
        assert r.action == "extend"
        assert r.attempt_number == 1
        assert r.acquired_at == acquired
        assert r.event_transition is None

    def test_steal_expired_claim(self):
        r = resolve_claim_acquire(
            wi_not_before=None,
            claim_actor_id="a2",
            claim_expires_at=NOW - timedelta(seconds=1),
            claim_acquired_at=NOW - timedelta(minutes=10),
            claim_attempt_number=1,
            wi_attempt_number=1,
            actor_id="a1",
            ttl_seconds=300,
            now=NOW,
        )
        assert r.action == "steal"
        assert r.attempt_number == 2
        assert r.prior_actor_id == "a2"
        assert r.event_transition == "claim_stolen"

    def test_contested_active_claim_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_claim_acquire(
                wi_not_before=None,
                claim_actor_id="a2",
                claim_expires_at=NOW + timedelta(minutes=5),
                claim_acquired_at=NOW,
                claim_attempt_number=1,
                wi_attempt_number=1,
                actor_id="a1",
                ttl_seconds=300,
                now=NOW,
            )
        assert exc_info.value.code == ErrorCode.CLAIM_CONTESTED

    def test_not_before_future_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_claim_acquire(
                wi_not_before=NOW + timedelta(hours=1),
                claim_actor_id=None,
                claim_expires_at=None,
                claim_acquired_at=None,
                claim_attempt_number=None,
                wi_attempt_number=0,
                actor_id="a1",
                ttl_seconds=300,
                now=NOW,
            )
        assert exc_info.value.code == ErrorCode.NOT_BEFORE_FUTURE

    def test_zero_ttl_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_claim_acquire(
                wi_not_before=None,
                claim_actor_id=None,
                claim_expires_at=None,
                claim_acquired_at=None,
                claim_attempt_number=None,
                wi_attempt_number=0,
                actor_id="a1",
                ttl_seconds=0,
                now=NOW,
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_negative_ttl_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_claim_acquire(
                wi_not_before=None,
                claim_actor_id=None,
                claim_expires_at=None,
                claim_acquired_at=None,
                claim_attempt_number=None,
                wi_attempt_number=0,
                actor_id="a1",
                ttl_seconds=-1,
                now=NOW,
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_attempt_number_increments_from_wi(self):
        r = resolve_claim_acquire(
            wi_not_before=None,
            claim_actor_id=None,
            claim_expires_at=None,
            claim_acquired_at=None,
            claim_attempt_number=None,
            wi_attempt_number=5,
            actor_id="a1",
            ttl_seconds=300,
            now=NOW,
        )
        assert r.attempt_number == 6


class TestResolveHeartbeat:
    def test_valid_heartbeat(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW,
            "expires_at": NOW + timedelta(seconds=300),
            "attempt_number": 1,
        }
        r = resolve_heartbeat(claim, "a1", 300, None, uuid.uuid4(), NOW)
        assert r.attempt_number == 1
        assert r.new_expires_at == NOW + timedelta(seconds=300)

    def test_no_claim_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(None, "a1", 300, None, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND

    def test_wrong_actor_raises(self):
        claim = {
            "actor_id": "a2",
            "acquired_at": NOW,
            "expires_at": NOW + timedelta(minutes=5),
            "attempt_number": 1,
        }
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(claim, "a1", 300, None, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_expired_claim_raises(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW - timedelta(minutes=10),
            "expires_at": NOW - timedelta(seconds=1),
            "attempt_number": 1,
        }
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(claim, "a1", 300, None, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_active_claim_heartbeat_passes(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW - timedelta(minutes=5),
            "expires_at": NOW + timedelta(minutes=5),
            "attempt_number": 1,
        }
        r = resolve_heartbeat(claim, "a1", 300, None, uuid.uuid4(), NOW)
        assert r.attempt_number == 1

    def test_stale_attempt_number_raises(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW,
            "expires_at": NOW + timedelta(minutes=5),
            "attempt_number": 2,
        }
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(claim, "a1", 300, 1, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_matching_attempt_number_passes(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW,
            "expires_at": NOW + timedelta(minutes=5),
            "attempt_number": 2,
        }
        r = resolve_heartbeat(claim, "a1", 300, 2, uuid.uuid4(), NOW)
        assert r.attempt_number == 2

    def test_invalid_ttl_raises(self):
        claim = {
            "actor_id": "a1",
            "acquired_at": NOW,
            "expires_at": NOW + timedelta(minutes=5),
            "attempt_number": 1,
        }
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(claim, "a1", 0, None, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_null_expires_at_raises(self):
        claim = {"actor_id": "a1", "acquired_at": NOW, "attempt_number": 1}
        with pytest.raises(RegistaError) as exc_info:
            resolve_heartbeat(claim, "a1", 300, None, uuid.uuid4(), NOW)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST


class TestValidateRelease:
    def test_valid_release(self):
        claim = {"actor_id": "a1"}
        validate_release(claim, "a1", uuid.uuid4())

    def test_no_claim_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_release(None, "a1", uuid.uuid4())
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND

    def test_wrong_actor_raises(self):
        claim = {"actor_id": "a2"}
        with pytest.raises(RegistaError) as exc_info:
            validate_release(claim, "a1", uuid.uuid4())
        assert exc_info.value.code == ErrorCode.CLAIM_LOST


class TestValidateJsonSafeValue:
    def test_clean_string_passes(self):
        validate_json_safe_value("hello world", "test")

    def test_empty_string_passes(self):
        validate_json_safe_value("", "test")

    def test_null_byte_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value("abc\x00def", "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert "\\u0000" in exc_info.value.message

    def test_unpaired_surrogate_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value("abc\uD800def", "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_high_surrogate_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value("\uDBFF", "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_clean_dict_passes(self):
        validate_json_safe_value({"key": "value", "num": 42}, "test")

    def test_dict_with_null_byte_key_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({"bad\x00key": "value"}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_dict_with_null_byte_value_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({"key": "bad\x00value"}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_nested_dict_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({"outer": {"inner": "\u0000"}}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_clean_list_passes(self):
        validate_json_safe_value(["a", "b", "c"], "test")

    def test_list_with_null_byte_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value(["ok", "bad\x00"], "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_int_passes(self):
        validate_json_safe_value(42, "test")

    def test_none_passes(self):
        validate_json_safe_value(None, "test")

    def test_float_passes(self):
        validate_json_safe_value(3.14, "test")

    def test_bool_passes(self):
        validate_json_safe_value(True, "test")

    def test_deeply_nested_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({"a": [{"b": "\u0000"}]}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_set_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({1, 2, 3}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_bytes_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value(b"hello", "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_tuple_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value((1, 2), "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_nan_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value(float("nan"), "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_inf_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value(float("inf"), "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_neg_inf_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value(float("-inf"), "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_nan_in_dict_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_json_safe_value({"v": float("nan")}, "test")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestValidateActorId:
    def test_short_passes(self):
        validate_actor_id("a")

    def test_exact_255_passes(self):
        validate_actor_id("x" * 255)

    def test_over_255_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_actor_id("x" * 256)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert "255" in exc_info.value.message

    def test_detail_includes_length(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_actor_id("y" * 300)
        assert exc_info.value.detail is not None
        assert exc_info.value.detail["actor_id_length"] == 300


class TestValidateWorkItemExists:
    def test_exists_passes(self):
        validate_work_item_exists("something", uuid.uuid4())

    def test_none_raises(self):
        wid = uuid.uuid4()
        with pytest.raises(RegistaError) as exc_info:
            validate_work_item_exists(None, wid)
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND
        assert str(wid) in exc_info.value.message


class TestBC301JsonbSizeLimit:
    def test_normal_payload_accepted(self):
        from regista._contract import Jsonb

        Jsonb({"key": "value" * 100})

    def test_oversized_payload_rejected(self):
        from regista._contract import MAX_JSONB_BYTES, Jsonb

        big = {"data": "x" * (MAX_JSONB_BYTES + 100)}
        with pytest.raises(RegistaError) as exc_info:
            Jsonb(big)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert exc_info.value.detail is not None
        assert exc_info.value.detail["max"] == MAX_JSONB_BYTES

    def test_none_value_accepted(self):
        from regista._contract import Jsonb

        Jsonb(None)


class TestAsymmetricSchemeDerivation:
    def test_ed25519_is_asymmetric_hmac_is_not(self):
        from regista._signing_scheme import (
            Ed25519Scheme,
            HMACSHA256Scheme,
            asymmetric_scheme_ids,
        )

        ids = asymmetric_scheme_ids()
        assert "ed25519" in ids
        assert "hmac-sha256" not in ids
        assert Ed25519Scheme.is_asymmetric is True
        assert HMACSHA256Scheme.is_asymmetric is False

    def test_dynamically_registered_asymmetric_scheme_included(self):
        from regista._signing_scheme import (
            asymmetric_scheme_ids,
            register_scheme,
            unregister_scheme,
        )

        class MockPQCScheme:
            scheme_id = "mock-pqc"
            is_asymmetric = True

            def sign(self, envelope, key_material, hash_alg="sha-256"):
                return (b"\x00", b"\x00")

            def verify(self, envelope, signature, envelope_hash, key_material, hash_alg="sha-256"):
                return False

        register_scheme(MockPQCScheme)
        try:
            assert "mock-pqc" in asymmetric_scheme_ids()
        finally:
            unregister_scheme("mock-pqc")
        assert "mock-pqc" not in asymmetric_scheme_ids()
