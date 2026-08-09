from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from regista._contract import validate_delegation_chain
from regista._errors import ErrorCode, RegistaError
from regista._signing import (
    build_signing_envelope,
    sign_event,
    verify_event,
)


def _key() -> bytes:
    return b"x" * 32


class TestDelegationChainValidation:
    def test_none_is_no_op(self) -> None:
        validate_delegation_chain(None)

    def test_valid_minimal(self) -> None:
        validate_delegation_chain({"principal_id": "alice"})

    def test_valid_with_scope(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "scope": ["read", "write"]}
        )

    def test_valid_with_authenticated_at(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "authenticated_at": "2024-01-01T00:00:00Z"}
        )

    def test_valid_with_session_id(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "session_id": "550e8400-e29b-41d4-a716-446655440000"}
        )

    def test_rejects_empty_session_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain({"principal_id": "alice", "session_id": ""})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_dict(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain("not-a-dict")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_missing_principal_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain({})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_empty_principal_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain({"principal_id": ""})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_principal_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain({"principal_id": 123})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_list_scope(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "scope": "read"}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_scope_items(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "scope": ["read", 123]}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_authenticated_at(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "authenticated_at": 123}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_null_scope_is_allowed(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "scope": None}
        )

    def test_null_authenticated_at_is_allowed(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "authenticated_at": None}
        )


class TestSigningEnvelope:
    def test_build_signing_envelope_includes_on_behalf_of(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        env = build_signing_envelope(
            eid, wid, "actor", "t1", {"k": "v"},
            on_behalf_of={"principal_id": "alice"},
        )
        assert b"on_behalf_of" in env
        assert b"alice" in env

    def test_build_signing_envelope_with_none(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        env = build_signing_envelope(
            eid, wid, "actor", "t1", {"k": "v"},
            on_behalf_of=None,
        )
        assert b"on_behalf_of" in env
        assert b"null" in env

    def test_sign_verify_round_trip_with_on_behalf_of(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        now = datetime.now(UTC)
        sig, ch, env = sign_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        # WI-267: the stored envelope must be supplied. Verification no longer
        # rebuilds a candidate from the arguments when none is given.
        assert verify_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"},
            sig, ch, key,
            stored_envelope=env,
            on_behalf_of={"principal_id": "alice"},
        )

    def test_sign_with_on_behalf_of_verify_without_fails(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        now = datetime.now(UTC)
        sig, ch, _env = sign_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert not verify_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of=None,
        )

    def test_backward_compat_old_event_verifies(self) -> None:
        """Event signed without on_behalf_of verifies with on_behalf_of=None."""
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        now = datetime.now(UTC)
        sig, ch, env = sign_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"}, key,
        )
        assert verify_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"},
            sig, ch, key,
            stored_envelope=env,
            on_behalf_of=None,
        )

    def test_tamper_detection_wrong_on_behalf_of(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        now = datetime.now(UTC)
        sig, ch, _env = sign_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert not verify_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of={"principal_id": "bob"},
        )

    def test_stored_envelope_does_not_excuse_a_rewritten_on_behalf_of(self) -> None:
        """WI-267: this test used to assert the opposite, and was the defect.

        Its old name was ``test_verify_with_stored_envelope_ignores_on_behalf_of``
        and it asserted that an event whose envelope signs a delegation to
        *alice* verifies while the row says *bob*. ``on_behalf_of`` is what
        promotes a self-review to an independently-reviewed one, so "the stored
        envelope makes the row's delegation irrelevant" was a live
        privilege-escalation path, not a convenience.
        """
        from regista._signing import verify_event_result

        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        now = datetime.now(UTC)
        sig, ch, env = sign_event(
            eid, wid, "actor", "k1", 1, "wf", 1, now,
            "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        result = verify_event_result(
            event_id=eid, work_item_id=wid, actor_id="actor", key_id="k1",
            event_seq=1, workflow_name="wf", workflow_version=1, timestamp=now,
            transition="t1", payload={"k": "v"},
            signature=sig, canonical_hash=ch, key=key,
            stored_envelope=env,
            on_behalf_of={"principal_id": "bob"},
        )
        assert not result.accepted
        assert "on_behalf_of" in result.mismatched_field_names
