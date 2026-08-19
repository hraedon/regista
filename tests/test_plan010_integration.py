"""WI-008 in-memory counterparts for the retired pre-v6 delegation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from regista._action_delegation import action_delegation_hash
from regista._errors import ErrorCode, RegistaError
from tests._wi008_fixtures import (
    ACTION_SUBJECT,
    action_delegation_document,
    copy_action_delegation_document,
    in_memory_action_project,
)


@pytest.fixture
def action_project(tmp_path: Path):
    project = in_memory_action_project(tmp_path)
    try:
        yield project
    finally:
        project.instance.close()


class TestInMemoryActionDelegation:
    def test_append_event_with_verified_credential(self, action_project) -> None:
        document = action_delegation_document(action_project)
        event = action_project.instance.append_event(
            action_project.work_item.work_item_id,
            ACTION_SUBJECT,
            transition="note_added",
            payload={"note": "delegated"},
            action_delegation_credentials=(document,),
        )

        envelope = json.loads(bytes(event.canonical_envelope))
        assert envelope["authorization"]["mode"] == "delegated"
        assert envelope["authorization"]["credentials"] == [
            {
                "credential_id": document["credential_id"],
                "credential_hash": action_delegation_hash(document),
            }
        ]

    def test_transition_with_verified_credential(self, action_project) -> None:
        document = action_delegation_document(
            action_project,
            transition="delegated_transition",
        )
        event = action_project.instance.transition(
            action_project.work_item.work_item_id,
            "delegated_transition",
            ACTION_SUBJECT,
            action_delegation_credentials=(document,),
        )

        assert event.transition == "delegated_transition"
        assert action_project.instance.get_work_item(
            action_project.work_item.work_item_id
        ).current_state == "done"

    def test_read_round_trip_preserves_credential_reference(self, action_project) -> None:
        document = action_delegation_document(action_project)
        action_project.instance.append_event(
            action_project.work_item.work_item_id,
            ACTION_SUBJECT,
            transition="note_added",
            payload={"note": "round trip"},
            action_delegation_credentials=(document,),
        )

        event = action_project.instance.read_events(
            work_item_id=action_project.work_item.work_item_id
        )[-1]
        envelope = json.loads(bytes(event.canonical_envelope))
        assert envelope["authorization"]["credentials"] == [
            {
                "credential_id": document["credential_id"],
                "credential_hash": action_delegation_hash(document),
            }
        ]
        assert "signature" not in envelope["authorization"]["credentials"][0]

    def test_replay_signature_still_verifies(self, action_project) -> None:
        document = action_delegation_document(action_project)
        event = action_project.instance.append_event(
            action_project.work_item.work_item_id,
            ACTION_SUBJECT,
            transition="note_added",
            payload={"note": "verify"},
            action_delegation_credentials=(document,),
        )

        assert action_project.instance.verify_event_signature(event)
        verification = action_project.instance.verify_event_result(event)
        assert verification.delegated_authorization is True
        assert verification.delegation_verification.value == "verified"

    def test_replay_with_verified_credential_has_no_drift(self, action_project) -> None:
        document = action_delegation_document(action_project)
        action_project.instance.append_event(
            action_project.work_item.work_item_id,
            ACTION_SUBJECT,
            transition="note_added",
            payload={"note": "replay"},
            action_delegation_credentials=(document,),
        )

        report = action_project.instance.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0

    def test_append_rejects_malformed_credential(self, action_project) -> None:
        document = action_delegation_document(action_project)
        malformed = copy_action_delegation_document(document)
        malformed["principal_kind"] = "agent"

        with pytest.raises(RegistaError) as exc_info:
            action_project.instance.append_event(
                action_project.work_item.work_item_id,
                ACTION_SUBJECT,
                transition="note_added",
                payload={"note": "must reject"},
                action_delegation_credentials=(malformed,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
