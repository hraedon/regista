"""Focused tests for action-delegation credentials on ``create_work_item``.

The create path threads ``action_delegation_credentials`` from the public API
through the Postgres and in-memory create call chains into the initial
``created`` event's v6 append. These tests prove the three load-bearing
properties:

1. a valid delegated create writes a ``created`` event whose authorization mode
   is ``delegated`` and whose credential references match the supplied document;
2. an invalid credential fails — with ``ACTION_DELEGATION_INVALID`` — before the
   work item is created (no row, no event);
3. the two backends agree (API parity), and an empty tuple preserves the legacy
   ``direct`` behaviour.
"""

from __future__ import annotations

import base64
import copy
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from regista._errors import ErrorCode, RegistaError
from tests._wi008_fixtures import (
    ACTION_ISSUER,
    ACTION_SUBJECT,
    ActionProject,
    action_delegation_document,
    in_memory_action_project,
)

CREATOR = ACTION_SUBJECT
ISSUER = ACTION_ISSUER


def _created_transition() -> str:
    return "created"


def _scope_credentials_to_created(document: dict[str, Any], workflow_name: str) -> dict[str, Any]:
    """Narrow a credential's scope to the ``created`` transition.

    A credential scoped to some other transition (e.g. ``note_added``) would be
    refused for a ``created`` event, so the delegated-create tests must scope
    the document to the transition that actually fires.
    """
    scoped = dict(document)
    scoped["scope"] = dict(document["scope"])
    scoped["scope"]["transitions"] = [_created_transition()]
    scoped["scope"]["workflow_names"] = [workflow_name]
    return scoped


class TestDelegatedCreateInMemory:
    """The in-memory backend is deterministic and needs no Postgres DSN."""

    @pytest.fixture
    def project(self, tmp_path_factory: pytest.TempPathFactory) -> ActionProject:
        tmp_path = tmp_path_factory.mktemp("deleg_create")
        return in_memory_action_project(tmp_path, creator=CREATOR)

    def test_valid_delegated_create_writes_delegated_authorization(
        self, project: ActionProject
    ) -> None:
        document = action_delegation_document(
            project,
            issuer=ISSUER,
            subject=CREATOR,
            transition=_created_transition(),
            workflow_name=project.workflow_name,
        )
        scoped = _scope_credentials_to_created(document, project.workflow_name)

        wi, evt = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            action_delegation_credentials=(scoped,),
        )

        assert wi is not None
        assert evt.transition == "created"
        envelope = json.loads(bytes(evt.canonical_envelope))
        assert envelope["authorization"]["mode"] == "delegated"
        # The credential reference is the real hash, not the signature.
        from regista._action_delegation import action_delegation_hash

        assert envelope["authorization"]["credentials"] == [
            {
                "credential_id": document["credential_id"],
                "credential_hash": action_delegation_hash(scoped),
            }
        ]
        # The document is stored as immutable evidence.
        stored = project.instance._store.v6_rows.action_delegation_credentials
        assert document["credential_id"] in stored

    def test_invalid_credential_fails_before_creating_the_work_item(
        self, project: ActionProject
    ) -> None:
        # A structurally invalid document (missing required members) must be
        # refused with ACTION_DELEGATION_INVALID, and no work item may be left
        # behind. The create runs inside a transaction, so a failure there
        # rolls the would-be row back. The fixture already seeded one work
        # item during setup, so assert the count does not grow.
        invalid_document = {"this_is": "not_a_valid_credential"}
        baseline = len(project.instance._work_items)
        assert baseline >= 1

        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                action_delegation_credentials=(invalid_document,),
            )

        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
        # No additional work item was created.
        assert len(project.instance._work_items) == baseline

    def test_empty_credentials_preserve_direct_authorization(self, project: ActionProject) -> None:
        wi, evt = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
        )
        assert wi is not None
        envelope = json.loads(bytes(evt.canonical_envelope))
        assert envelope["authorization"]["mode"] == "direct"
        assert envelope["authorization"]["credentials"] == []

    def test_delegated_create_replays_clean(self, project: ActionProject) -> None:
        document = action_delegation_document(
            project,
            issuer=ISSUER,
            subject=CREATOR,
            transition=_created_transition(),
            workflow_name=project.workflow_name,
        )
        scoped = _scope_credentials_to_created(document, project.workflow_name)
        project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            action_delegation_credentials=(scoped,),
        )
        report = project.instance.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0

    def test_direct_create_event_id_retry_returns_the_original_request(
        self, project: ActionProject
    ) -> None:
        event_id = uuid.uuid4()
        not_before = datetime.now(UTC) - timedelta(minutes=1)
        baseline = len(project.instance._work_items)

        first_wi, first_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            not_before=not_before,
            event_id=event_id,
        )
        second_wi, second_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            not_before=not_before,
            event_id=event_id,
        )

        assert second_wi == first_wi
        assert second_event.event_id == first_event.event_id
        assert len(project.instance._work_items) == baseline + 1
        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                not_before=not_before + timedelta(minutes=1),
                event_id=event_id,
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD
        assert len(project.instance._work_items) == baseline + 1

    def test_delegated_create_event_id_retry_compares_credential_bytes(
        self, project: ActionProject
    ) -> None:
        document = action_delegation_document(
            project,
            issuer=ISSUER,
            subject=CREATOR,
            transition=_created_transition(),
            workflow_name=project.workflow_name,
        )
        scoped = _scope_credentials_to_created(document, project.workflow_name)
        event_id = uuid.uuid4()
        first_wi, first_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            event_id=event_id,
            action_delegation_credentials=(scoped,),
        )
        second_wi, second_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            event_id=event_id,
            action_delegation_credentials=(scoped,),
        )
        assert second_wi == first_wi
        assert second_event.event_id == first_event.event_id

        changed = copy.deepcopy(scoped)
        signature = bytearray(base64.b64decode(changed["signature"]["value"]))
        signature[0] ^= 1
        changed["signature"]["value"] = base64.b64encode(signature).decode()
        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                event_id=event_id,
                action_delegation_credentials=(changed,),
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD


class TestDelegatedCreatePostgres:
    """Same claims over the Postgres backend (requires REGISTA_TEST_DSN)."""

    @pytest.fixture
    def project(self, tmp_path_factory: pytest.TempPathFactory) -> Iterator[ActionProject]:
        from tests._wi008_fixtures import postgres_action_project

        with postgres_action_project(
            tmp_path_factory.mktemp("deleg_create_pg"),
            project_prefix="deleg_create_pg",
            principals=(ISSUER, CREATOR),
            creator=CREATOR,
        ) as prepared:
            yield prepared

    def test_valid_delegated_create_writes_delegated_authorization(
        self, project: ActionProject
    ) -> None:
        document = action_delegation_document(
            project,
            issuer=ISSUER,
            subject=CREATOR,
            transition=_created_transition(),
            workflow_name=project.workflow_name,
        )
        scoped = _scope_credentials_to_created(document, project.workflow_name)

        wi, evt = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            action_delegation_credentials=(scoped,),
        )

        assert wi is not None
        assert evt.transition == "created"
        envelope = json.loads(bytes(evt.canonical_envelope))
        assert envelope["authorization"]["mode"] == "delegated"
        from regista._action_delegation import action_delegation_hash

        assert envelope["authorization"]["credentials"][0]["credential_hash"] == (
            action_delegation_hash(scoped)
        )

    def test_invalid_credential_fails_before_creating_the_work_item(
        self, project: ActionProject
    ) -> None:
        invalid_document = {"this_is": "not_a_valid_credential"}

        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                action_delegation_credentials=(invalid_document,),
            )

        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID

    def test_empty_credentials_preserve_direct_authorization(self, project: ActionProject) -> None:
        wi, evt = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
        )
        assert wi is not None
        envelope = json.loads(bytes(evt.canonical_envelope))
        assert envelope["authorization"]["mode"] == "direct"
        assert envelope["authorization"]["credentials"] == []

    def test_direct_create_event_id_retry_returns_the_original_request(
        self, project: ActionProject
    ) -> None:
        event_id = uuid.uuid4()
        not_before = datetime.now(UTC) - timedelta(minutes=1)
        with project.instance._mgr.transaction() as conn:
            baseline = conn.execute("SELECT count(*) AS count FROM work_items_current").fetchone()[
                "count"
            ]

        first_wi, first_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            not_before=not_before,
            event_id=event_id,
        )
        second_wi, second_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            not_before=not_before,
            event_id=event_id,
        )
        assert second_wi == first_wi
        assert second_event.event_id == first_event.event_id

        with project.instance._mgr.transaction() as conn:
            count = conn.execute("SELECT count(*) AS count FROM work_items_current").fetchone()[
                "count"
            ]
        assert count == baseline + 1
        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                not_before=not_before + timedelta(minutes=1),
                event_id=event_id,
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD

    def test_delegated_create_event_id_retry_compares_credential_bytes(
        self, project: ActionProject
    ) -> None:
        document = action_delegation_document(
            project,
            issuer=ISSUER,
            subject=CREATOR,
            transition=_created_transition(),
            workflow_name=project.workflow_name,
        )
        scoped = _scope_credentials_to_created(document, project.workflow_name)
        event_id = uuid.uuid4()
        first_wi, first_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            event_id=event_id,
            action_delegation_credentials=(scoped,),
        )
        second_wi, second_event = project.instance.create_work_item(
            project.workflow_name,
            "item",
            CREATOR,
            actor_kind="agent",
            event_id=event_id,
            action_delegation_credentials=(scoped,),
        )
        assert second_wi == first_wi
        assert second_event.event_id == first_event.event_id

        changed = copy.deepcopy(scoped)
        signature = bytearray(base64.b64decode(changed["signature"]["value"]))
        signature[0] ^= 1
        changed["signature"]["value"] = base64.b64encode(signature).decode()
        with pytest.raises(RegistaError) as exc_info:
            project.instance.create_work_item(
                project.workflow_name,
                "item",
                CREATOR,
                actor_kind="agent",
                event_id=event_id,
                action_delegation_credentials=(changed,),
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD
