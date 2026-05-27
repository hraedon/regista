from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._contract import (
    ErrorCode,
    RegistaError,
    check_reserved_transition,
    validate_delegation_chain,
)
from regista._keys import KeySet
from regista._types import DelegationChain

SECRET = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl"


def _write_key_file(path: Path, keys: list[dict]) -> Path:
    path.write_text(json.dumps({"keys": keys}))
    return path


class TestBC215RevokedAtBoundary:
    def test_revoked_at_predates_event(self, tmp_path: Path) -> None:
        """Event before revocation is accepted with warning."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
        ])
        ks = KeySet(str(kf))
        entry = ks.verify_key_status("old", event_timestamp="2026-05-01T00:00:00Z")
        assert entry.key_id == "old"

    def test_revoked_at_exact_boundary_rejected(self, tmp_path: Path) -> None:
        """event_timestamp == revoked_at is rejected (≥ semantics)."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc:
            ks.verify_key_status("old", event_timestamp="2026-06-01T00:00:00Z")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_at_after_event_rejected(self, tmp_path: Path) -> None:
        """event_timestamp > revoked_at is rejected."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc:
            ks.verify_key_status("old", event_timestamp="2026-07-01T00:00:00Z")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_at_none_without_timestamp_rejected(self, tmp_path: Path) -> None:
        """No revoked_at and no timestamp: current behavior preserved (fail closed)."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
            },
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc:
            ks.verify_key_status("old")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_at_none_with_timestamp_rejected(self, tmp_path: Path) -> None:
        """revoked_at absent but timestamp provided: fail closed."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
            },
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc:
            ks.verify_key_status("old", event_timestamp="2026-04-01T00:00:00Z")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID

    # BC-019/BC-022: revoke_at with timestamp absent rejects (fail closed)
    def test_revoked_at_present_timestamp_none_rejected(self, tmp_path: Path) -> None:
        """revoked_at present but event_timestamp omitted: fail closed."""
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc:
            ks.verify_key_status("old")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID


class TestBC219DelegationChainFields:
    def test_valid_with_expires_at(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "expires_at": "2026-12-31T23:59:59Z"}
        )

    def test_rejects_empty_expires_at(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "expires_at": ""}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_expires_at(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "expires_at": 123}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_null_expires_at_allowed(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "expires_at": None}
        )

    def test_valid_with_session_grant_event_id(self) -> None:
        validate_delegation_chain(
            {
                "principal_id": "alice",
                "session_grant_event_id": "550e8400-e29b-41d4-a716-446655440000",
            }
        )

    def test_rejects_empty_session_grant_event_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "session_grant_event_id": ""}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rejects_non_string_session_grant_event_id(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "session_grant_event_id": 123}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_null_session_grant_event_id_allowed(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "session_grant_event_id": None}
        )

    def test_delegation_chain_expires_at_roundtrip(self) -> None:
        dc = DelegationChain(
            principal_id="alice",
            expires_at="2026-12-31T23:59:59Z",
        )
        d = dc.to_dict()
        assert d["expires_at"] == "2026-12-31T23:59:59Z"
        restored = DelegationChain.from_dict(d)
        assert restored == dc

    def test_delegation_chain_session_grant_event_id_roundtrip(self) -> None:
        dc = DelegationChain(
            principal_id="alice",
            session_grant_event_id="550e8400-e29b-41d4-a716-446655440000",
        )
        d = dc.to_dict()
        assert d["session_grant_event_id"] == "550e8400-e29b-41d4-a716-446655440000"
        restored = DelegationChain.from_dict(d)
        assert restored == dc

    def test_full_session_grant_fields_roundtrip(self) -> None:
        dc = DelegationChain(
            principal_id="alice",
            session_id="550e8400-e29b-41d4-a716-446655440000",
            authenticated_at="2026-01-01T00:00:00Z",
            scope=["read"],
            expires_at="2026-12-31T23:59:59Z",
            session_grant_event_id="550e8400-e29b-41d4-a716-446655440001",
        )
        restored = DelegationChain.from_dict(dc.to_dict())
        assert restored == dc

    def test_valid_full_on_behalf_of(self) -> None:
        validate_delegation_chain(
            {
                "principal_id": "alice",
                "session_id": "550e8400-e29b-41d4-a716-446655440000",
                "authenticated_at": "2026-01-01T00:00:00Z",
                "scope": ["read"],
                "expires_at": "2026-12-31T23:59:59Z",
                "session_grant_event_id": "550e8400-e29b-41d4-a716-446655440001",
            }
        )

    def test_rejects_invalid_session_id_uuid(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "session_id": "not-a-uuid"}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "session_id must be a valid UUID" in exc.value.message

    def test_rejects_invalid_session_grant_event_id_uuid(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "session_grant_event_id": "not-a-uuid"}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "session_grant_event_id must be a valid UUID" in exc.value.message

    def test_rejects_invalid_expires_at_format(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {"principal_id": "alice", "expires_at": "tomorrow"}
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "RFC 3339" in exc.value.message

    def test_rejects_invalid_authenticated_at_format(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {
                    "principal_id": "alice",
                    "authenticated_at": "yesterday",
                },
                event_timestamp="2026-06-01T00:00:00Z",
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "RFC 3339" in exc.value.message

    def test_expires_at_before_event_timestamp_raises_delegation_chain_expired(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {
                    "principal_id": "alice",
                    "expires_at": "2026-01-01T00:00:00Z",
                },
                event_timestamp="2026-06-01T00:00:00Z",
            )
        assert exc.value.code == ErrorCode.DELEGATION_CHAIN_EXPIRED

    def test_expires_at_equal_to_event_timestamp_raises_delegation_chain_expired(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {
                    "principal_id": "alice",
                    "expires_at": "2026-06-01T00:00:00Z",
                },
                event_timestamp="2026-06-01T00:00:00Z",
            )
        assert exc.value.code == ErrorCode.DELEGATION_CHAIN_EXPIRED

    def test_expires_at_after_event_timestamp_accepted(self) -> None:
        validate_delegation_chain(
            {
                "principal_id": "alice",
                "expires_at": "2026-12-31T23:59:59Z",
            },
            event_timestamp="2026-06-01T00:00:00Z",
        )

    def test_authenticated_at_after_event_timestamp_rejected(self) -> None:
        with pytest.raises(RegistaError) as exc:
            validate_delegation_chain(
                {
                    "principal_id": "alice",
                    "authenticated_at": "2026-07-01T00:00:00Z",
                },
                event_timestamp="2026-06-01T00:00:00Z",
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "after event timestamp" in exc.value.message

    def test_authenticated_at_equal_to_event_timestamp_accepted(self) -> None:
        validate_delegation_chain(
            {
                "principal_id": "alice",
                "authenticated_at": "2026-06-01T00:00:00Z",
            },
            event_timestamp="2026-06-01T00:00:00Z",
        )

    def test_session_id_validation_without_timestamp(self) -> None:
        validate_delegation_chain(
            {"principal_id": "alice", "session_id": "550e8400-e29b-41d4-a716-446655440000"}
        )

    def test_session_grant_event_id_validation_without_timestamp(self) -> None:
        validate_delegation_chain(
            {
                "principal_id": "alice",
                "session_grant_event_id": "550e8400-e29b-41d4-a716-446655440000",
            }
        )


class TestBC220ClientTimestamp:
    def test_client_timestamp_set_in_event(self, tmp_path: Path) -> None:
        from regista._event_store import InMemoryEventStore, append_event
        store = InMemoryEventStore()
        work_item_id = uuid.uuid4()
        store.bind({
            work_item_id: {
                "next_event_seq": 1,
                "last_event_seq": 0,
                "last_event_at": datetime.now(UTC),
            },
        })
        evt = append_event(
            store, work_item_id, "actor", "agent", None,
            "wf", 1, "t", None, uuid.uuid4(),
            key_set=None, on_behalf_of=None,
        )
        assert evt.timestamp is not None

    def test_postgres_appends_client_timestamp(self, tmp_path: Path) -> None:
        from regista import Regista
        from regista._testing import drop_project_schema

        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        dsn = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
        project_name = f"ts_test_{uuid.uuid4().hex[:12]}"
        sub = Regista.create_project(dsn, project_name, hmac_key_path=str(kf))
        sub.register_workflow(
            "name: wf\n"
            "version: 1\n"
            "regista_version: 5.0.0\n"
            "states:\n"
            "  - name: s1\n"
            "    initial: true\n"
            "  - name: s2\n"
            "    terminal: true\n"
            "transitions:\n"
            "  - name: done\n"
            "    from: s1\n"
            "    to: s2\n"
            "    allowed_roles: [admin]\n"
            "roles:\n"
            "  - name: admin\n"
            "work_item_types:\n"
            "  - name: t\n"
            "    custom_fields: []\n"
            "link_types: []\n"
        )
        _wi, _event = sub.create_work_item("wf", "t", "actor", actor_kind="agent")
        client_before = datetime.now(UTC)
        evt = sub.append_event(
            _wi.work_item_id, "actor", actor_kind="agent",
            transition="note", payload={"k": "v"},
        )
        client_after = datetime.now(UTC)
        mgr = sub._mgr
        sub.close()
        drop_project_schema(mgr.dsn, project_name)
        # The returned timestamp must be the client-side value, not a DB server value.
        assert client_before <= evt.timestamp <= client_after


class TestBC221CheckpointReservation:
    def test_checkpoint_in_reserved_transitions(self) -> None:
        with pytest.raises(RegistaError) as exc:
            check_reserved_transition("checkpoint")
        assert exc.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_checkpoint_blocked_in_append(self) -> None:
        from regista._contract import check_append_blocked
        transitions = [{"name": "checkpoint", "from_state": "a", "to_state": "b"}]
        with pytest.raises(RegistaError) as exc:
            check_append_blocked(transitions, "checkpoint", "wf")
        assert exc.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_checkpoint_payload_shape(self) -> None:
        payload = {
            "checkpoint_id": str(uuid.uuid4()),
            "covers_event_seq_from": 1000,
            "covers_event_seq_to": 5000,
            "merkle_root": "sha256:abcd",
            "previous_checkpoint_id": None,
            "tsa_token": "base64token",
            "checkpoint_at": "2026-05-23T00:00:00Z",
        }
        # Payload shape is reserved for v2; we simply assert it serializes safely
        import json
        serialized = json.dumps(payload)
        assert len(serialized) > 0

    def test_checkpoint_transition_name_reserved(self) -> None:
        # Directly assert membership in the frozenset via the contract function
        with pytest.raises(RegistaError) as exc:
            check_reserved_transition("checkpoint")
        assert exc.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_checkpoint_workflow_registration_rejected(self) -> None:
        """Workflow YAML with transition named 'checkpoint' is rejected at registration."""
        from regista._workflow import parse_and_validate
        yaml = (
            "name: wf\n"
            "version: 1\n"
            "regista_version: 5.0.0\n"
            "states:\n"
            "  - name: s1\n"
            "    initial: true\n"
            "  - name: s2\n"
            "    terminal: true\n"
            "transitions:\n"
            "  - name: checkpoint\n"
            "    from: s1\n"
            "    to: s2\n"
            "roles:\n"
            "  - name: admin\n"
            "work_item_types:\n"
            "  - name: t\n"
            "    custom_fields: []\n"
            "link_types: []\n"
        )
        with pytest.raises(RegistaError) as exc:
            parse_and_validate(yaml)
        assert exc.value.code == ErrorCode.RESERVED_TRANSITION_NAME
        assert "checkpoint" in exc.value.message
