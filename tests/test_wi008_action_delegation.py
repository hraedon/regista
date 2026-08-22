from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _trust_log_fixtures import (
    TrustLogKey,
    make_authorized_by,
    make_enrollment_payload,
)

from regista._action_delegation import (
    ActionDelegationError,
    action_delegation_hash,
    parse_action_delegation,
    verify_action_delegation_chain,
    verify_action_delegation_signature,
)
from regista._datetime_utils import v6_occurred_at
from regista._errors import ErrorCode, RegistaError
from regista._jcs import canonicalize
from regista._review_validators import ReviewRejected, adversarial_review
from regista._types import AuthorizationEvidence
from tests._wi008_fixtures import (
    ACTION_AUTHOR,
    ACTION_ISSUER,
    ACTION_REVIEW_ISSUER,
    ACTION_REVIEWER,
    ACTION_SUBJECT,
    REVIEW_PRINCIPALS,
    REVIEW_WORKFLOW,
    action_delegation_document,
    copy_action_delegation_document,
    in_memory_action_project,
    review_to_in_review,
    set_review_producer,
)

VECTORS = Path(__file__).parent / "vectors" / "v6"


def delegation_vector() -> dict:
    return json.loads((VECTORS / "delegation-credential.json").read_text())


def _delegation_context() -> tuple[Any, Any, Any, dict[str, Any], list[dict[str, Any]], Any]:
    vector = delegation_vector()
    credential = parse_action_delegation(vector["expected"]["signed_document"])
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    public_key = bytes.fromhex(manifest["test_public_key_hex"])
    fingerprint = "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()
    project_instance_id = next(iter(credential.scope.project_instance_ids))
    binding = SimpleNamespace(
        event_hash=credential.issuer_key_binding_event_hash,
        project_instance_id=project_instance_id,
        transition="principal_key_accepted",
        payload={
            "principal_id": credential.issuer_principal_id,
            "key_id": credential.issuer_key_id,
            "project_instance_id": project_instance_id,
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "fingerprint": fingerprint,
            "trust_event_hash": "sha256:" + "11" * 32,
        },
        envelope={
            "project_instance_id": project_instance_id,
            "authorization": {"mode": "direct", "credentials": []},
        },
    )
    trust_key = TrustLogKey(
        key_id=credential.issuer_key_id,
        seed=b"\x00" * 32,
        public_key=public_key,
        fingerprint=fingerprint,
    )
    trust_event = SimpleNamespace(
        event_hash="sha256:" + "11" * 32,
        project_instance_id="trust-log-project",
        trust_domain_id=str(credential.trust_domain_id),
        transition="principal_key_enrolled",
        actor_principal_id=credential.issuer_principal_id,
        payload=make_enrollment_payload(
            trust_domain_id=str(credential.trust_domain_id),
            principal_id=credential.issuer_principal_id,
            key=trust_key,
            authorized_by=make_authorized_by(
                authority="root",
                principal_id=credential.issuer_principal_id,
                key_id=credential.issuer_key_id,
            ),
        ),
        envelope={
            "project_instance_id": "trust-log-project",
            "authorization": {"mode": "direct", "credentials": []},
            "signing": {"key_id": credential.issuer_key_id},
        },
    )
    envelope = {
        "project_instance_id": project_instance_id,
        "trust_domain_id": str(credential.trust_domain_id),
        "actor": {"principal_id": credential.subject_principal_id},
        "entity": {"kind": "work_item"},
        "workflow": {"name": "agent-notes"},
        "transition": "note_added",
        "occurred_at": "2026-08-09T12:00:00.000000Z",
    }
    references = [
        {
            "credential_id": str(credential.credential_id),
            "credential_hash": credential.credential_hash,
        }
    ]
    referents = SimpleNamespace(
        resolve_referent=lambda event_hash: trust_event
        if event_hash == trust_event.event_hash
        else None
    )
    return credential, binding, trust_event, envelope, references, referents


def test_base64_vector_parses_hashes_and_verifies() -> None:
    vector = delegation_vector()
    document = vector["expected"]["signed_document"]
    credential = parse_action_delegation(document)
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    assert credential.signature == base64.b64decode(
        vector["expected"]["signature_base64"], validate=True
    )
    assert credential.credential_hash == vector["expected"]["credential_hash"]
    assert action_delegation_hash(document) == credential.credential_hash
    assert verify_action_delegation_signature(
        credential, bytes.fromhex(manifest["test_public_key_hex"])
    )


@pytest.mark.parametrize(
    "axis",
    ["project_instance_ids", "entity_kinds", "workflow_names", "transitions"],
)
def test_scope_axes_are_nonempty_exact_allowlists(axis: str) -> None:
    document = delegation_vector()["expected"]["signed_document"]
    document = copy.deepcopy(document)
    document["scope"][axis] = []
    expected = (
        "workflow-bound work_item scopes"
        if axis == "workflow_names"
        else "non-empty array"
    )
    with pytest.raises(ActionDelegationError, match=expected):
        parse_action_delegation(document)


def test_note_scope_uses_an_empty_workflow_axis() -> None:
    document = delegation_vector()["expected"]["signed_document"]
    document = copy.deepcopy(document)
    document["scope"]["entity_kinds"] = ["note"]
    document["scope"]["workflow_names"] = []

    credential = parse_action_delegation(document)

    assert credential.scope.workflow_names == frozenset()
    assert credential.scope.permits(
        project_instance_id=next(iter(credential.scope.project_instance_ids)),
        entity_kind="note",
        workflow_name=None,
        transition="note_added",
    )
    assert not credential.scope.permits(
        project_instance_id=next(iter(credential.scope.project_instance_ids)),
        entity_kind="note",
        workflow_name="agent-notes",
        transition="note_added",
    )


@pytest.mark.parametrize(
    ("entity_kinds", "workflow_names", "message"),
    [
        (["work_item"], [], "workflow-bound work_item"),
        (["note"], ["agent-notes"], "non-workflow note"),
        (["work_item", "note"], [], "mixed work_item and note"),
        (["principal"], ["agent-notes"], "authorizable v1 kinds"),
    ],
)
def test_scope_rejects_ambiguous_workflow_axes(
    entity_kinds: list[str], workflow_names: list[str], message: str
) -> None:
    document = delegation_vector()["expected"]["signed_document"]
    document = copy.deepcopy(document)
    document["scope"]["entity_kinds"] = entity_kinds
    document["scope"]["workflow_names"] = workflow_names

    with pytest.raises(ActionDelegationError, match=message):
        parse_action_delegation(document)


def test_signature_value_rejects_hex_encoding() -> None:
    document = delegation_vector()["expected"]["signed_document"]
    document = copy.deepcopy(document)
    document["signature"]["value"] = "00" * 64
    with pytest.raises(ActionDelegationError, match="decode"):
        parse_action_delegation(document)


def test_unknown_document_member_is_refused() -> None:
    document = delegation_vector()["expected"]["signed_document"]
    document = copy.deepcopy(document)
    document["principal_kind"] = "human"
    with pytest.raises(ActionDelegationError, match="unknown or missing"):
        parse_action_delegation(document)


def test_action_delegation_has_no_principal_kind_or_lineage_claim() -> None:
    document = delegation_vector()["expected"]["signed_document"]
    credential = parse_action_delegation(document)
    assert "principal_kind" not in document
    assert not hasattr(credential, "principal_kind")
    assert not hasattr(credential, "model_lineage")


def test_chain_rejects_a_reference_with_extra_members() -> None:
    credential, binding, _trust_event, envelope, references, referents = _delegation_context()
    references[0]["signature"] = "must-not-be-carried-in-the-event"
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[credential],
        ancestors=[binding],
        referents=referents,
    )
    assert not result.verified
    assert "unknown or missing" in (result.reason or "")


def test_chain_rejects_an_out_of_scope_transition() -> None:
    credential, binding, _trust_event, envelope, references, referents = _delegation_context()
    envelope["transition"] = "delete_item"
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[credential],
        ancestors=[binding],
        referents=referents,
    )
    assert not result.verified
    assert "scope does not authorize" in (result.reason or "")


def test_chain_rejects_trust_evidence_from_the_project_chain() -> None:
    credential, binding, trust_event, envelope, references, referents = _delegation_context()
    trust_event.project_instance_id = envelope["project_instance_id"]
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[credential],
        ancestors=[binding],
        referents=referents,
    )
    assert not result.verified
    assert "separate trust-log chain" in (result.reason or "")


def test_chain_rejects_a_preceding_revocation() -> None:
    credential, binding, _trust_event, envelope, references, referents = _delegation_context()
    revocation = SimpleNamespace(
        event_hash="sha256:" + "33" * 32,
        transition="action_delegation_revoked",
        actor_principal_id=credential.issuer_principal_id,
        payload={
            "type": "regista.action-delegation-revocation",
            "version": 1,
            "credential_id": str(credential.credential_id),
            "credential_hash": credential.credential_hash,
            "reason": "policy",
        },
        envelope={},
    )
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[credential],
        ancestors=[binding, revocation],
        referents=referents,
    )
    assert not result.verified
    assert "revoked" in (result.reason or "")


def test_chain_charges_preceding_uses_against_max_uses() -> None:
    credential, binding, _trust_event, envelope, references, referents = _delegation_context()
    limited = dataclasses.replace(credential, max_uses=1)
    prior = SimpleNamespace(
        event_hash="sha256:" + "44" * 32,
        transition="note_added",
        envelope={
            "authorization": {
                "mode": "delegated",
                "credentials": references,
            }
        },
        payload={},
    )
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[limited],
        ancestors=[binding, prior],
        referents=referents,
    )
    assert not result.verified
    assert "max_uses" in (result.reason or "")


def test_verified_chain_authorizes_exact_action() -> None:
    vector = delegation_vector()
    document = vector["expected"]["signed_document"]
    credential = parse_action_delegation(document)
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    public_key = bytes.fromhex(manifest["test_public_key_hex"])
    fingerprint = "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()
    binding = SimpleNamespace(
        event_hash=credential.issuer_key_binding_event_hash,
        transition="principal_key_accepted",
        payload={
            "principal_id": credential.issuer_principal_id,
            "key_id": credential.issuer_key_id,
            "project_instance_id": next(iter(credential.scope.project_instance_ids)),
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "fingerprint": fingerprint,
            "trust_event_hash": "sha256:" + "11" * 32,
        },
        envelope={
            "project_instance_id": next(iter(credential.scope.project_instance_ids)),
            "authorization": {"mode": "direct", "credentials": []},
        },
    )
    trust_key = TrustLogKey(
        key_id=credential.issuer_key_id,
        seed=b"\x00" * 32,
        public_key=public_key,
        fingerprint=fingerprint,
    )
    registration = SimpleNamespace(
        event_hash="sha256:" + "11" * 32,
        project_instance_id="trust-log-project",
        trust_domain_id=str(credential.trust_domain_id),
        transition="principal_key_enrolled",
        actor_principal_id=credential.issuer_principal_id,
        payload=make_enrollment_payload(
            trust_domain_id=str(credential.trust_domain_id),
            principal_id=credential.issuer_principal_id,
            key=trust_key,
            authorized_by=make_authorized_by(
                authority="root",
                principal_id=credential.issuer_principal_id,
                key_id=credential.issuer_key_id,
            ),
        ),
        envelope={
            "project_instance_id": "trust-log-project",
            "authorization": {"mode": "direct", "credentials": []},
            "signing": {"key_id": credential.issuer_key_id},
        },
    )
    envelope = {
        "project_instance_id": next(iter(credential.scope.project_instance_ids)),
        "trust_domain_id": str(credential.trust_domain_id),
        "actor": {"principal_id": credential.subject_principal_id},
        "entity": {"kind": "work_item"},
        "workflow": {"name": "agent-notes"},
        "transition": "note_added",
        "occurred_at": "2026-08-09T12:00:00.000000Z",
    }
    references = [
        {
            "credential_id": str(credential.credential_id),
            "credential_hash": credential.credential_hash,
        }
    ]
    result = verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[credential],
        ancestors=[binding, registration],
        referents=SimpleNamespace(
            resolve_referent=lambda event_hash: registration
            if event_hash == registration.event_hash
            else None,
        ),
    )
    assert result.verified
    assert result.participating_principals == {
        credential.issuer_principal_id,
        credential.subject_principal_id,
    }


def test_review_separation_counts_every_verified_chain_principal() -> None:
    author = SimpleNamespace(
        transition="created",
        actor_id="agent:author",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm"},
        on_behalf_of=None,
    )
    context = SimpleNamespace(
        prior_events=(author,),
        actor_id="agent:reviewer",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        on_behalf_of=None,
        payload={"review_note": "reviewed"},
        validator_params={},
        current_state="in_review",
        new_state="done",
        transition_name="adversarial_pass",
        authorization_evidence=AuthorizationEvidence(
            mode="delegated",
            status="verified",
            credential_hashes=("sha256:" + "22" * 32,),
            participating_principals=frozenset(
                {"agent:author", "agent:reviewer"}
            ),
        ),
    )
    with pytest.raises(ReviewRejected, match="delegation participant is an author"):
        adversarial_review(context)


def test_review_allows_disjoint_verified_chain_principals() -> None:
    author = SimpleNamespace(
        transition="created",
        actor_id="agent:author",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm"},
        on_behalf_of=None,
    )
    context = SimpleNamespace(
        prior_events=(author,),
        actor_id="agent:reviewer",
        actor_kind="agent",
        actor_metadata={"model_lineage": "kimi"},
        on_behalf_of=None,
        payload={"review_note": "reviewed"},
        validator_params={},
        current_state="in_review",
        new_state="done",
        transition_name="adversarial_pass",
        authorization_evidence=AuthorizationEvidence(
            mode="delegated",
            status="verified",
            credential_hashes=("sha256:" + "22" * 32,),
            participating_principals=frozenset({"human:issuer", "agent:reviewer"}),
        ),
    )
    adversarial_review(context)


@pytest.fixture
def in_memory_review_project(tmp_path: Path):
    project = in_memory_action_project(
        tmp_path,
        project="wi008_review_in_memory",
        principals=REVIEW_PRINCIPALS,
        workflow=REVIEW_WORKFLOW,
        workflow_name="wi008_review",
        creator=ACTION_AUTHOR,
    )
    try:
        yield project
    finally:
        project.instance.close()


def _review_payload() -> dict[str, Any]:
    set_review_producer()
    return {
        "review_note": "delegated review checked the item",
    }


def _review_credential(
    project: Any, *, issuer: str = ACTION_REVIEW_ISSUER
) -> dict[str, Any]:
    return action_delegation_document(
        project,
        issuer=issuer,
        subject=ACTION_REVIEWER,
        transition="adversarial_pass",
        workflow_name="wi008_review",
    )


class TestInMemoryReviewActionDelegation:
    def test_review_accepts_disjoint_verified_delegation_participants(
        self, in_memory_review_project
    ) -> None:
        review_to_in_review(in_memory_review_project)
        event = in_memory_review_project.instance.transition(
            in_memory_review_project.work_item.work_item_id,
            "adversarial_pass",
            ACTION_REVIEWER,
            payload=_review_payload(),
            action_delegation_credentials=(
                _review_credential(in_memory_review_project),
            ),
        )

        assert event.transition == "adversarial_pass"
        refreshed = in_memory_review_project.instance.get_work_item(
            in_memory_review_project.work_item.work_item_id
        )
        assert refreshed is not None
        assert refreshed.current_state == "done"

    def test_review_rejects_a_verified_delegation_participant_who_is_an_author(
        self, in_memory_review_project
    ) -> None:
        review_to_in_review(in_memory_review_project)
        with pytest.raises(RegistaError) as exc_info:
            in_memory_review_project.instance.transition(
                in_memory_review_project.work_item.work_item_id,
                "adversarial_pass",
                ACTION_REVIEWER,
                payload=_review_payload(),
                action_delegation_credentials=(
                    _review_credential(
                        in_memory_review_project,
                        issuer=ACTION_AUTHOR,
                    ),
                ),
            )

        assert exc_info.value.code is ErrorCode.VALIDATOR_FAILED
        assert "participant is an author" in exc_info.value.message

    def test_validator_cannot_mutate_signed_authorization_reference(
        self, in_memory_review_project
    ) -> None:
        document = _review_credential(in_memory_review_project)
        original = copy_action_delegation_document(document)
        observed: list[AuthorizationEvidence] = []

        def inspect_context(context: Any) -> None:
            observed.append(context.authorization_evidence)
            serialized = context.to_dict()
            serialized["authorization_evidence"]["credential_hashes"].append(
                "sha256:" + "ff" * 32
            )
            adversarial_review(context)

        in_memory_review_project.instance.register_validator(
            "adversarial_review", inspect_context
        )
        review_to_in_review(in_memory_review_project)
        event = in_memory_review_project.instance.transition(
            in_memory_review_project.work_item.work_item_id,
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


def _append_delegated_note(project: Any, document: dict[str, Any]) -> Any:
    return project.instance.append_event(
        uuid.uuid4(),
        ACTION_SUBJECT,
        entity_kind="note",
        transition="note_added",
        payload={"note": "delegated note"},
        action_delegation_credentials=(document,),
    )


def test_in_memory_delegated_note_verifies_and_replays(tmp_path: Path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        event = _append_delegated_note(project, document)
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
    finally:
        project.instance.close()


def test_in_memory_note_namespace_does_not_mutate_work_item_stream(
    tmp_path: Path,
) -> None:
    project = in_memory_action_project(tmp_path)
    try:
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
        assert project.instance._store.events_for("work_item", work_item_id)
        assert project.instance._store.events_for("note", work_item_id) == [note_event]
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
    finally:
        project.instance.close()


def test_in_memory_delegated_note_respects_max_uses(tmp_path: Path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
            max_uses=1,
        )
        _append_delegated_note(project, document)
        with pytest.raises(RegistaError, match="max_uses"):
            _append_delegated_note(project, document)
    finally:
        project.instance.close()


def test_in_memory_delegated_note_revocation_is_enforced(tmp_path: Path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        _append_delegated_note(project, document)
        project.instance.revoke_action_delegation(
            uuid.UUID(document["credential_id"]),
            action_delegation_hash(document),
            ACTION_ISSUER,
            reason="note authority withdrawn",
        )
        with pytest.raises(RegistaError, match="revoked"):
            _append_delegated_note(project, document)
    finally:
        project.instance.close()


def test_in_memory_replay_rejects_tampered_note_credential_evidence(
    tmp_path: Path,
) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(
            project,
            issuer=ACTION_ISSUER,
            subject=ACTION_SUBJECT,
            entity_kind="note",
        )
        _append_delegated_note(project, document)
        stored = project.instance._store.v6_rows.action_delegation_credentials[
            document["credential_id"]
        ]
        tampered = copy.deepcopy(stored["document"])
        tampered["scope"]["transitions"] = ["other_transition"]
        stored["document"] = tampered

        report = project.instance.replay()
        assert report.halted >= 1
        assert report.unverifiable == 0
    finally:
        project.instance.close()


@pytest.mark.parametrize(
    ("credential_entity_kind", "event_entity_kind"),
    [("note", "work_item"), ("work_item", "note")],
)
def test_in_memory_delegation_rejects_another_workflow_axis(
    tmp_path: Path, credential_entity_kind: str, event_entity_kind: str
) -> None:
    project = in_memory_action_project(tmp_path)
    try:
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
    finally:
        project.instance.close()


def test_in_memory_writer_stores_evidence_and_signs_only_references(tmp_path: Path) -> None:
    import nacl.signing

    from regista._in_mem_genesis import _as_conn
    from regista._v6_writer import append_v6_event, resolve_producer
    from regista.testing import InMemoryRegista
    from tests._v6_fixtures import (
        BOOTSTRAP_PRINCIPAL,
        accept_key,
        make_v6_keyset,
        open_v6_epoch,
    )

    worker = "agent:delegated-worker"
    issuer = "human:delegating-owner"
    keyset = make_v6_keyset(tmp_path, principals=(issuer, worker))
    sub = InMemoryRegista(project="wi008_writer", hmac_key_path=keyset.path)
    genesis = open_v6_epoch(sub, keyset, principals=(worker,))
    issuer_key = keyset.key_for(issuer)
    trust_key = TrustLogKey(
        key_id=issuer_key.key_id,
        seed=issuer_key.seed,
        public_key=issuer_key.public_key,
        fingerprint=issuer_key.fingerprint,
    )
    enrollment_payload = make_enrollment_payload(
        trust_domain_id=str(genesis.trust_domain_id),
        principal_id=issuer,
        key=trust_key,
        principal_kind="human",
        authorized_by=make_authorized_by(
            authority="root",
            principal_id=BOOTSTRAP_PRINCIPAL,
            key_id=keyset.bootstrap.key_id,
        ),
    )
    with sub._store.v6_manager.transaction() as connection:
        append_v6_event(
            _as_conn(connection),
            sub._key_set,
            entity_kind="principal",
            entity_id=uuid.uuid4(),
            transition="principal_key_enrolled",
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="human",
            producer=resolve_producer(),
            payload=enrollment_payload,
        )
    issuer_acceptance = accept_key(
        sub,
        keyset,
        genesis,
        issuer,
        # The online writer has only the project-chain material. The external
        # trust-log referent is deliberately absent, which is the documented
        # bundled-only state; it must not be replaced with a fake project event.
        trust_event_hash="sha256:" + "22" * 32,
    )
    sub.register_workflow(
        "name: delegated\nversion: 1\nregista_version: 5.0.0\n"
        "states:\n  - name: open\n    initial: true\n    terminal: true\n"
        "work_item_types:\n  - name: item\n    custom_fields: []\n"
        "transitions: []\nroles: []\nlink_types: []\n"
    )
    wi, _ = sub.create_work_item("delegated", "item", worker)
    now = datetime.now(UTC)
    unsigned = {
        "type": "regista.action-delegation",
        "version": 1,
        "credential_id": str(uuid.uuid4()),
        "trust_domain_id": str(genesis.trust_domain_id),
        "issuer_principal_id": issuer,
        "subject_principal_id": worker,
        "issuer_key_id": issuer_key.key_id,
        "issuer_key_binding_event_hash": "sha256:" + issuer_acceptance.event_hash.hex(),
        "parent_credential_hash": None,
        "scope": {
            "project_instance_ids": [str(genesis.project_instance_id)],
            "entity_kinds": ["work_item"],
            "workflow_names": ["delegated"],
            "transitions": ["note_added"],
        },
        "not_before": v6_occurred_at(now - timedelta(minutes=1)),
        "not_after": v6_occurred_at(now + timedelta(minutes=1)),
        "max_uses": None,
        "delegation_allowed": False,
    }
    signing_input = (
        b"regista.action-delegation.v1\x00"
        + len(canonicalize(unsigned)).to_bytes(8, "big")
        + canonicalize(unsigned)
    )
    signature = nacl.signing.SigningKey(issuer_key.seed).sign(
        signing_input
    ).signature
    document = {
        **unsigned,
        "signature": {
            "scheme_id": "ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    event = sub.append_event(
        wi.work_item_id,
        worker,
        transition="note_added",
        payload={"note": "delegated"},
        action_delegation_credentials=(document,),
    )
    envelope = json.loads(bytes(event.canonical_envelope))
    assert envelope["authorization"]["mode"] == "delegated"
    assert "signature" not in envelope["authorization"]["credentials"][0]
    stored = sub._store.v6_rows.action_delegation_credentials
    assert str(document["credential_id"]) in stored
    replay_report = sub.replay()
    assert replay_report.replayed_drift == 0
    same = sub.append_event(
        wi.work_item_id,
        worker,
        transition="note_added",
        payload={"note": "delegated"},
        event_id=event.event_id,
        action_delegation_credentials=(document,),
    )
    assert same.event_id == event.event_id
    with pytest.raises(RegistaError, match="different action-delegation references"):
        sub.append_event(
            wi.work_item_id,
            worker,
            transition="note_added",
            payload={"note": "delegated"},
            event_id=event.event_id,
        )
    verification = sub.verify_event_result(event)
    assert verification.delegated_authorization is True
    assert verification.delegation_verification.value == "verified"
    assert issuer in verification.authorization_principals
    assert worker in verification.authorization_principals
    assert stored[str(document["credential_id"])]["document"] == document

    with pytest.raises(RegistaError) as unauthorized:
        sub.revoke_action_delegation(
            uuid.UUID(str(document["credential_id"])),
            action_delegation_hash(document),
            worker,
            reason="subject may not revoke issuer authority",
            actor_kind="agent",
        )
    assert unauthorized.value.code is ErrorCode.ACTION_DELEGATION_INVALID

    revocation = sub.revoke_action_delegation(
        uuid.UUID(str(document["credential_id"])),
        action_delegation_hash(document),
        issuer,
        reason="owner withdrew delegation",
    )
    assert revocation.transition == "action_delegation_revoked"
    with pytest.raises(RegistaError) as revoked:
        sub.append_event(
            wi.work_item_id,
            worker,
            transition="note_added",
            payload={"note": "must remain refused"},
            action_delegation_credentials=(document,),
        )
    assert revoked.value.code is ErrorCode.ACTION_DELEGATION_INVALID
    assert "revoked" in revoked.value.message
