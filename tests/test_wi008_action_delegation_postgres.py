from __future__ import annotations

import base64
import copy
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
    ACTION_REVIEW_ISSUER,
    ACTION_REVIEWER,
    ACTION_SUBJECT,
    REVIEW_PRINCIPALS,
    REVIEW_WORKFLOW,
    action_delegation_document,
    postgres_action_project,
    review_to_in_review,
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
    return {
        "review_note": "delegated review checked the item",
        "reviewer_claims": {"model_lineage": "kimi"},
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
