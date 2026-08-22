from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from regista._action_delegation import action_delegation_hash
from regista._datetime_utils import v6_occurred_at
from regista._errors import ErrorCode, RegistaError
from regista._jcs import canonicalize
from regista._signing import compute_v6_event_hash
from tests._wi008_fixtures import (
    ACTION_AUTHOR,
    ACTION_ISSUER,
    ACTION_REVIEW_ISSUER,
    ACTION_REVIEWER,
    ACTION_SUBJECT,
    REVIEW_PRINCIPALS,
    REVIEW_WORKFLOW,
    action_delegation_document,
    postgres_action_project,
    review_to_in_review,
    set_review_producer,
)


@pytest.fixture
def postgres_v6_action_delegation(tmp_path):
    from _helpers import DSN

    from regista import Regista
    from regista.testing import drop_project_schema
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    principals = ("human:delegating-owner", "agent:delegated-worker")
    keyset = make_v6_keyset(tmp_path, principals=principals)
    project = f"test_wi008_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    try:
        genesis = open_v6_epoch(sub, keyset, principals=(principals[1],))
        yield sub, keyset, genesis
    finally:
        sub.close()
        drop_project_schema(DSN, project)


def _postgres_credential_document(keyset, genesis, issuer_acceptance, now):
    import nacl.signing

    issuer = "human:delegating-owner"
    subject = "agent:delegated-worker"
    issuer_key = keyset.key_for(issuer)
    unsigned = {
        "type": "regista.action-delegation",
        "version": 1,
        "credential_id": str(uuid.uuid4()),
        "trust_domain_id": str(genesis.trust_domain_id),
        "issuer_principal_id": issuer,
        "subject_principal_id": subject,
        "issuer_key_id": issuer_key.key_id,
        "issuer_key_binding_event_hash": "sha256:" + issuer_acceptance.event_hash.hex(),
        "parent_credential_hash": None,
        "scope": {
            "project_instance_ids": [str(genesis.project_instance_id)],
            "entity_kinds": ["work_item"],
            "workflow_names": ["delegated"],
            "transitions": ["note_added"],
        },
        "not_before": v6_occurred_at(now - timedelta(hours=1)),
        "not_after": v6_occurred_at(now + timedelta(hours=1)),
        "max_uses": None,
        "delegation_allowed": False,
    }
    unsigned_bytes = canonicalize(unsigned)
    signing_input = (
        b"regista.action-delegation.v1\x00"
        + len(unsigned_bytes).to_bytes(8, "big")
        + unsigned_bytes
    )
    signature = nacl.signing.SigningKey(issuer_key.seed).sign(signing_input).signature
    return {
        **unsigned,
        "signature": {
            "scheme_id": "ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def test_credential_evidence_is_immutable_and_not_live_event_fk_bound(
    regista_instance,
) -> None:
    credential_id = uuid.uuid4()
    first_event_id = uuid.uuid4()
    credential_hash = "sha256:" + "1" * 64
    first_event_hash = "sha256:" + "2" * 64
    with regista_instance._mgr.transaction() as conn:
        foreign_keys = conn.execute(
            "SELECT conname FROM pg_constraint "
            "WHERE conrelid = 'action_delegation_credentials'::regclass "
            "AND contype = 'f'"
        ).fetchall()
        assert foreign_keys == []
        conn.execute(
            "INSERT INTO action_delegation_credentials "
            "(credential_id, credential_hash, document, canonical_document, "
            "first_event_id, first_event_hash) VALUES (%s, %s, %s, %s, %s, %s)",
            [
                credential_id,
                credential_hash,
                psycopg.types.json.Jsonb({"credential_id": str(credential_id)}),
                b"{}",
                first_event_id,
                first_event_hash,
            ],
        )

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        with regista_instance._mgr.transaction() as conn:
            conn.execute(
                "UPDATE action_delegation_credentials SET document = '{}'::jsonb "
                "WHERE credential_id = %s",
                [credential_id],
            )

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        with regista_instance._mgr.transaction() as conn:
            conn.execute(
                "DELETE FROM action_delegation_credentials WHERE credential_id = %s",
                [credential_id],
            )

    with regista_instance._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT first_event_id, first_event_hash "
            "FROM action_delegation_credentials WHERE credential_id = %s",
            [credential_id],
        ).fetchone()
    assert row == {
        "first_event_id": first_event_id,
        "first_event_hash": first_event_hash,
    }


def test_postgres_append_persists_only_hash_references_in_the_event(
    postgres_v6_action_delegation,
) -> None:
    from tests._v6_fixtures import accept_key

    sub, keyset, genesis = postgres_v6_action_delegation
    issuer = "human:delegating-owner"
    worker = "agent:delegated-worker"
    issuer_acceptance = accept_key(
        sub,
        keyset,
        genesis,
        issuer,
        trust_event_hash="sha256:" + "22" * 32,
    )
    sub.register_workflow(
        "name: delegated\nversion: 1\nregista_version: 5.0.0\n"
        "states:\n  - name: open\n    initial: true\n    terminal: true\n"
        "work_item_types:\n  - name: item\n    custom_fields: []\n"
        "transitions: []\nroles: []\nlink_types: []\n"
    )
    work_item, _ = sub.create_work_item("delegated", "item", worker)
    now = datetime.now(UTC)
    document = _postgres_credential_document(keyset, genesis, issuer_acceptance, now)
    event = sub.append_event(
        work_item.work_item_id,
        worker,
        transition="note_added",
        payload={"note": "delegated"},
        action_delegation_credentials=(document,),
    )

    import json

    envelope = json.loads(bytes(event.canonical_envelope))
    assert envelope["authorization"]["mode"] == "delegated"
    assert envelope["authorization"]["credentials"] == [
        {
            "credential_id": document["credential_id"],
            "credential_hash": action_delegation_hash(document),
        }
    ]
    with sub._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT document, canonical_document, first_event_id, first_event_hash "
            "FROM action_delegation_credentials WHERE credential_id = %s",
            [uuid.UUID(document["credential_id"])],
        ).fetchone()
    assert row["document"] == document
    assert bytes(row["canonical_document"]) == canonicalize(document)
    assert row["first_event_id"] == event.event_id
    assert row["first_event_hash"] == "sha256:" + compute_v6_event_hash(
        bytes(event.canonical_envelope), bytes(event.signature)
    ).hex()


def test_postgres_delegated_note_verifies_and_replays(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_note_postgres") as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        event = project.instance.append_event(
            uuid.uuid4(),
            ACTION_SUBJECT,
            entity_kind="note",
            transition="note_added",
            payload={"note": "delegated note"},
            action_delegation_credentials=(document,),
        )
        envelope = json.loads(bytes(event.canonical_envelope))

        assert event.entity_kind == "note"
        assert envelope["workflow"] is None
        assert envelope["authorization"]["mode"] == "delegated"
        verification = project.instance.verify_event_result(event)
        assert verification.delegation_verification.value == "verified"
        report = project.instance.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0


def test_postgres_note_namespace_does_not_mutate_work_item_stream(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_collision_postgres") as project:
        work_item_id = project.work_item.work_item_id
        before = project.instance.get_work_item(work_item_id)
        assert before is not None
        event_id = uuid.uuid4()
        note_event = project.instance.append_event(
            work_item_id,
            ACTION_SUBJECT,
            entity_kind="note",
            transition="note_added",
            payload={"note": "same UUID, separate entity stream"},
            event_id=event_id,
        )
        after = project.instance.get_work_item(work_item_id)
        assert after == before
        with project.instance._mgr.transaction() as conn:
            rows = conn.execute(
                "SELECT entity_kind, entity_id FROM events "
                "WHERE entity_id = %s ORDER BY entity_kind, event_seq",
                [work_item_id],
            ).fetchall()
        assert any(row["entity_kind"] == "note" for row in rows)
        assert any(
            event.event_id == note_event.event_id
            for event in project.instance.read_events(work_item_id=work_item_id)
        )

        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                work_item_id,
                ACTION_SUBJECT,
                transition="note_added",
                payload={"note": "event id belongs to note"},
                event_id=event_id,
            )
        assert exc_info.value.code is ErrorCode.EVENT_ID_GLOBAL_COLLISION
        report = project.instance.replay()
        assert report.halted == 0


def test_postgres_replay_rejects_tampered_delegated_note(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_note_tamper_postgres") as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        event = project.instance.append_event(
            uuid.uuid4(),
            ACTION_SUBJECT,
            entity_kind="note",
            transition="note_added",
            payload={"note": "delegated note"},
            action_delegation_credentials=(document,),
        )
        with project.instance._mgr.transaction() as conn:
            conn.execute(
                "UPDATE events SET payload = %s WHERE event_id = %s",
                [psycopg.types.json.Jsonb({"note": "tampered"}), event.event_id],
            )

        report = project.instance.replay()
        assert report.halted >= 1
        assert report.unverifiable == 0


def _sidecar_client_for_action_project(project, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

    raw_token = "wi008-sidecar-token"
    token_path = tmp_path / "tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "token_sha256": hashlib.sha256(raw_token.encode()).hexdigest(),
                        "actor_id": ACTION_SUBJECT,
                        "actor_kind": "agent",
                        "allowed_roles": ["agent"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return TestClient(create_app(project.instance, TokenRegistry.from_file(token_path))), {
        "Authorization": f"Bearer {raw_token}",
    }


def test_sidecar_direct_note_append_accepts_entity_kind(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_note_sidecar_direct") as project:
        client, headers = _sidecar_client_for_action_project(project, tmp_path)
        response = client.post(
            "/v1/append_event",
            json={
                "work_item_id": str(uuid.uuid4()),
                "entity_kind": "note",
                "transition": "note_added",
                "payload": {"note": "direct"},
            },
            headers=headers,
        )

        assert response.status_code == 200, response.text
        assert response.json()["entity_kind"] == "note"


def test_sidecar_delegated_note_append_accepts_credentials(tmp_path) -> None:
    with postgres_action_project(
        tmp_path, project_prefix="wi008_note_sidecar_delegated"
    ) as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        client, headers = _sidecar_client_for_action_project(project, tmp_path)
        response = client.post(
            "/v1/append_event",
            json={
                "work_item_id": str(uuid.uuid4()),
                "entity_kind": "note",
                "transition": "note_added",
                "payload": {"note": "delegated"},
                "action_delegation_credentials": [document],
            },
            headers=headers,
        )

        assert response.status_code == 200, response.text
        assert response.json()["entity_kind"] == "note"


def test_postgres_delegated_note_respects_max_uses(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_note_max_postgres") as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
            max_uses=1,
        )
        project.instance.append_event(
            uuid.uuid4(),
            ACTION_SUBJECT,
            entity_kind="note",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        with pytest.raises(RegistaError, match="max_uses"):
            project.instance.append_event(
                uuid.uuid4(),
                ACTION_SUBJECT,
                entity_kind="note",
                transition="note_added",
                action_delegation_credentials=(document,),
            )


def test_postgres_delegated_note_revocation_is_enforced(tmp_path) -> None:
    with postgres_action_project(tmp_path, project_prefix="wi008_note_revoke_postgres") as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        project.instance.append_event(
            uuid.uuid4(),
            ACTION_SUBJECT,
            entity_kind="note",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        project.instance.revoke_action_delegation(
            uuid.UUID(document["credential_id"]),
            action_delegation_hash(document),
            ACTION_ISSUER,
            reason="note authority withdrawn",
        )
        with pytest.raises(RegistaError, match="revoked"):
            project.instance.append_event(
                uuid.uuid4(),
                ACTION_SUBJECT,
                entity_kind="note",
                transition="note_added",
                action_delegation_credentials=(document,),
            )


@pytest.mark.parametrize(
    ("credential_entity_kind", "event_entity_kind"),
    [("note", "work_item"), ("work_item", "note")],
)
def test_postgres_delegation_rejects_another_workflow_axis(
    tmp_path, credential_entity_kind: str, event_entity_kind: str
) -> None:
    with postgres_action_project(
        tmp_path, project_prefix="wi008_axis_postgres"
    ) as project:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind=credential_entity_kind,
        )
        event_id = (
            project.work_item.work_item_id
            if event_entity_kind == "work_item"
            else uuid.uuid4()
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                event_id,
                ACTION_SUBJECT,
                entity_kind=event_entity_kind,
                transition="note_added",
                payload={"note": "axis mismatch"},
                action_delegation_credentials=(document,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID


class TestPostgresActionDelegationCounterparts:
    def test_append_event_round_trips_via_read(self, tmp_path) -> None:
        with postgres_action_project(tmp_path) as project:
            document = action_delegation_document(project)
            project.instance.append_event(
                project.work_item.work_item_id,
                ACTION_SUBJECT,
                transition="note_added",
                payload={"note": "round trip"},
                action_delegation_credentials=(document,),
            )

            event = project.instance.read_events(
                work_item_id=project.work_item.work_item_id
            )[-1]
            envelope = json.loads(bytes(event.canonical_envelope))
            assert envelope["authorization"]["credentials"] == [
                {
                    "credential_id": document["credential_id"],
                    "credential_hash": action_delegation_hash(document),
                }
            ]

    def test_append_event_with_verified_credential(self, tmp_path) -> None:
        with postgres_action_project(tmp_path) as project:
            document = action_delegation_document(project)
            event = project.instance.append_event(
                project.work_item.work_item_id,
                ACTION_SUBJECT,
                transition="note_added",
                payload={"note": "persist"},
                action_delegation_credentials=(document,),
            )

            with project.instance._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT document, canonical_document, first_event_id "
                    "FROM action_delegation_credentials WHERE credential_id = %s",
                    [uuid.UUID(document["credential_id"])],
                ).fetchone()
            assert row["document"] == document
            assert bytes(row["canonical_document"]) == canonicalize(document)
            assert row["first_event_id"] == event.event_id

    def test_append_event_without_delegation_is_direct(self, tmp_path) -> None:
        with postgres_action_project(tmp_path) as project:
            event = project.instance.append_event(
                project.work_item.work_item_id,
                ACTION_SUBJECT,
                transition="note_added",
                payload={"note": "direct"},
            )

            envelope = json.loads(bytes(event.canonical_envelope))
            assert envelope["authorization"] == {
                "mode": "direct",
                "credentials": [],
            }

    def test_transition_rejects_invalid_credential(self, tmp_path) -> None:
        with postgres_action_project(tmp_path) as project:
            document = action_delegation_document(
                project,
                transition="delegated_transition",
            )
            malformed = copy.deepcopy(document)
            malformed["principal_kind"] = "agent"

            with pytest.raises(RegistaError) as exc_info:
                project.instance.transition(
                    project.work_item.work_item_id,
                    "delegated_transition",
                    ACTION_SUBJECT,
                    action_delegation_credentials=(malformed,),
                )
            assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID

    def test_transition_with_verified_credential(self, tmp_path) -> None:
        with postgres_action_project(tmp_path) as project:
            document = action_delegation_document(
                project,
                transition="delegated_transition",
            )
            event = project.instance.transition(
                project.work_item.work_item_id,
                "delegated_transition",
                ACTION_SUBJECT,
                action_delegation_credentials=(document,),
            )

            assert event.transition == "delegated_transition"
            refreshed = project.instance.get_work_item(project.work_item.work_item_id)
            assert refreshed is not None
            assert refreshed.current_state == "done"


def _review_payload() -> dict[str, object]:
    set_review_producer()
    return {
        "review_note": "delegated review checked the item",
    }


def _review_credential(project, *, issuer: str = ACTION_REVIEW_ISSUER):
    return action_delegation_document(
        project,
        issuer=issuer,
        subject=ACTION_REVIEWER,
        transition="adversarial_pass",
        workflow_name="wi008_review",
    )


class TestPostgresReviewActionDelegation:
    def test_review_accepts_disjoint_verified_delegation_participants(
        self, tmp_path
    ) -> None:
        with postgres_action_project(
            tmp_path,
            project_prefix="wi008_review_postgres",
            principals=REVIEW_PRINCIPALS,
            workflow=REVIEW_WORKFLOW,
            workflow_name="wi008_review",
            creator=ACTION_AUTHOR,
        ) as project:
            review_to_in_review(project)
            event = project.instance.transition(
                project.work_item.work_item_id,
                "adversarial_pass",
                ACTION_REVIEWER,
                payload=_review_payload(),
                action_delegation_credentials=(_review_credential(project),),
            )

            assert event.transition == "adversarial_pass"
            refreshed = project.instance.get_work_item(project.work_item.work_item_id)
            assert refreshed is not None
            assert refreshed.current_state == "done"

    def test_review_rejects_a_verified_delegation_participant_who_is_an_author(
        self, tmp_path
    ) -> None:
        with postgres_action_project(
            tmp_path,
            project_prefix="wi008_review_postgres",
            principals=REVIEW_PRINCIPALS,
            workflow=REVIEW_WORKFLOW,
            workflow_name="wi008_review",
            creator=ACTION_AUTHOR,
        ) as project:
            review_to_in_review(project)
            with pytest.raises(RegistaError) as exc_info:
                project.instance.transition(
                    project.work_item.work_item_id,
                    "adversarial_pass",
                    ACTION_REVIEWER,
                    payload=_review_payload(),
                    action_delegation_credentials=(
                        _review_credential(project, issuer=ACTION_AUTHOR),
                    ),
                )

            assert exc_info.value.code is ErrorCode.VALIDATOR_FAILED
            assert "participant is an author" in exc_info.value.message

    def test_validator_cannot_mutate_signed_authorization_reference(
        self, tmp_path
    ) -> None:
        with postgres_action_project(
            tmp_path,
            project_prefix="wi008_review_postgres",
            principals=REVIEW_PRINCIPALS,
            workflow=REVIEW_WORKFLOW,
            workflow_name="wi008_review",
            creator=ACTION_AUTHOR,
        ) as project:
            document = _review_credential(project)
            original = copy.deepcopy(document)
            observed = []

            def inspect_context(context) -> None:
                observed.append(context.authorization_evidence)
                serialized = context.to_dict()
                serialized["authorization_evidence"]["credential_hashes"].append(
                    "sha256:" + "ff" * 32
                )
                from regista._review_validators import adversarial_review

                adversarial_review(context)

            project.instance.register_validator("adversarial_review", inspect_context)
            review_to_in_review(project)
            event = project.instance.transition(
                project.work_item.work_item_id,
                "adversarial_pass",
                ACTION_REVIEWER,
                payload=_review_payload(),
                action_delegation_credentials=(document,),
            )

            assert observed[0].credential_hashes == (action_delegation_hash(document),)
            assert document == original
            envelope = json.loads(bytes(event.canonical_envelope))
            assert envelope["authorization"]["credentials"] == [
                {
                    "credential_id": document["credential_id"],
                    "credential_hash": action_delegation_hash(document),
                }
            ]
