from __future__ import annotations

import uuid

import pytest

from substrate._contract import validate_delegation_chain
from substrate._errors import ErrorCode, SubstrateError
from substrate._signing import (
    build_signing_envelope,
    compute_canonical_hash,
    compute_hmac,
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
            {"principal_id": "alice", "session_id": "sess-123"}
        )

    def test_rejects_non_dict(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain("not-a-dict")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_missing_principal_id(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain({})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_empty_principal_id(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain({"principal_id": ""})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_principal_id(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain({"principal_id": 123})
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_list_scope(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "scope": "read"}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_scope_items(self) -> None:
        with pytest.raises(SubstrateError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "scope": ["read", 123]}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_authenticated_at(self) -> None:
        with pytest.raises(SubstrateError) as exc:
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
        sig, ch, env = sign_event(
            eid, wid, "actor", "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert verify_event(
            eid, wid, "actor", "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of={"principal_id": "alice"},
        )

    def test_sign_with_on_behalf_of_verify_without_fails(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        sig, ch, env = sign_event(
            eid, wid, "actor", "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert not verify_event(
            eid, wid, "actor", "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of=None,
        )

    def test_backward_compat_old_event_verifies(self) -> None:
        """Event signed without on_behalf_of verifies with on_behalf_of=None."""
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        sig, ch, env = sign_event(
            eid, wid, "actor", "t1", {"k": "v"}, key,
        )
        assert verify_event(
            eid, wid, "actor", "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of=None,
        )

    def test_tamper_detection_wrong_on_behalf_of(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        sig, ch, env = sign_event(
            eid, wid, "actor", "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert not verify_event(
            eid, wid, "actor", "t1", {"k": "v"},
            sig, ch, key,
            on_behalf_of={"principal_id": "bob"},
        )

    def test_verify_with_stored_envelope_ignores_on_behalf_of(self) -> None:
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        key = _key()
        sig, ch, env = sign_event(
            eid, wid, "actor", "t1", {"k": "v"}, key,
            on_behalf_of={"principal_id": "alice"},
        )
        assert verify_event(
            eid, wid, "actor", "t1", {"k": "v"},
            sig, ch, key,
            stored_envelope=env,
            on_behalf_of={"principal_id": "bob"},
        )
