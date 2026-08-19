"""Round-two WI-008 regressions over the real v6 writer and verifier."""

from __future__ import annotations

import base64
import copy
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from regista._action_delegation import (
    DelegationVerificationStatus,
    action_delegation_hash,
    parse_action_delegation,
    verify_action_delegation_chain,
)
from regista._datetime_utils import v6_occurred_at
from regista._errors import ErrorCode, RegistaError
from tests._wi008_fixtures import (
    ACTION_AUTHOR,
    ACTION_FINAL_ACCEPTOR,
    ACTION_REVIEW_ISSUER,
    ACTION_REVIEWER,
    REVIEW_PRINCIPALS,
    TWO_STAGE_REVIEW_WORKFLOW,
    action_delegation_document,
    in_memory_action_project,
    review_to_in_review,
)

CHAIN_ROOT = "human:chain-root"
CHAIN_MIDDLE = "agent:chain-middle"
CHAIN_SUBJECT = "agent:chain-subject"
CHAIN_WORKER = "agent:chain-worker"
CHAIN_PRINCIPALS = (CHAIN_ROOT, CHAIN_MIDDLE, CHAIN_SUBJECT, CHAIN_WORKER)


TWO_STAGE_PRINCIPALS = (*REVIEW_PRINCIPALS, ACTION_FINAL_ACCEPTOR)


def _two_stage_project(tmp_path, *, postgres: bool = False):
    if postgres:
        from tests._wi008_fixtures import postgres_action_project

        return postgres_action_project(
            tmp_path,
            project_prefix="wi008_two_stage",
            principals=TWO_STAGE_PRINCIPALS,
            workflow=TWO_STAGE_REVIEW_WORKFLOW,
            workflow_name="wi008_two_stage_review",
            creator=ACTION_AUTHOR,
        )
    return in_memory_action_project(
        tmp_path,
        project="wi008_two_stage_memory",
        principals=TWO_STAGE_PRINCIPALS,
        workflow=TWO_STAGE_REVIEW_WORKFLOW,
        workflow_name="wi008_two_stage_review",
        creator=ACTION_AUTHOR,
    )


def _two_stage_credential(project: Any) -> dict[str, Any]:
    return action_delegation_document(
        project,
        issuer=ACTION_REVIEW_ISSUER,
        subject=ACTION_REVIEWER,
        transition="adversarial_pass",
        workflow_name="wi008_two_stage_review",
    )


def _review_payload() -> dict[str, Any]:
    return {
        "review_note": "round-two adversarial review",
        "reviewer_claims": {"model_lineage": "kimi"},
    }


def _accept_payload() -> dict[str, Any]:
    return {"review_note": "round-two final acceptance"}


def _run_two_stage_review(project: Any) -> dict[str, Any]:
    review_to_in_review(project)
    credential = _two_stage_credential(project)
    project.instance.transition(
        project.work_item.work_item_id,
        "adversarial_pass",
        ACTION_REVIEWER,
        payload=_review_payload(),
        action_delegation_credentials=(credential,),
    )
    return credential


def test_in_memory_two_stage_accept_rejects_prior_delegation_issuer(tmp_path) -> None:
    project = _two_stage_project(tmp_path)
    try:
        _run_two_stage_review(project)
        with pytest.raises(RegistaError) as exc_info:
            project.instance.transition(
                project.work_item.work_item_id,
                "accept",
                ACTION_REVIEW_ISSUER,
                actor_kind="human",
                payload=_accept_payload(),
            )
        assert exc_info.value.code is ErrorCode.VALIDATOR_FAILED
        assert "adversarial pass" in exc_info.value.message

        project.instance.transition(
            project.work_item.work_item_id,
            "accept",
            ACTION_FINAL_ACCEPTOR,
            actor_kind="human",
            payload=_accept_payload(),
        )
        assert project.instance.get_work_item(
            project.work_item.work_item_id
        ).current_state == "done"
    finally:
        project.instance.close()


def test_postgres_two_stage_accept_rejects_prior_delegation_issuer(tmp_path) -> None:
    with _two_stage_project(tmp_path, postgres=True) as project:
        _run_two_stage_review(project)
        with pytest.raises(RegistaError) as exc_info:
            project.instance.transition(
                project.work_item.work_item_id,
                "accept",
                ACTION_REVIEW_ISSUER,
                actor_kind="human",
                payload=_accept_payload(),
            )
        assert exc_info.value.code is ErrorCode.VALIDATOR_FAILED

        project.instance.transition(
            project.work_item.work_item_id,
            "accept",
            ACTION_FINAL_ACCEPTOR,
            actor_kind="human",
            payload=_accept_payload(),
        )
        assert project.instance.get_work_item(
            project.work_item.work_item_id
        ).current_state == "done"


def test_verification_result_to_dict_preserves_delegated_fields(tmp_path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        event = project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        result = project.instance.verify_event_result(event)
        serialized = result.to_dict()
    finally:
        project.instance.close()
    assert serialized["delegated_authorization"] is True
    assert serialized["delegation_verification"] == "verified"
    assert serialized["authorization_principals"] == sorted(
        {"human:delegating-owner", "agent:delegated-worker"}
    )


def test_in_memory_writer_rejects_revocation_id_hash_mismatch(tmp_path) -> None:
    from regista._action_delegation import action_delegation_hash

    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.revoke_action_delegation(
                uuid.uuid4(),
                action_delegation_hash(document),
                "human:delegating-owner",
                reason="wrong id must fail",
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
    finally:
        project.instance.close()


def test_postgres_writer_rejects_revocation_id_hash_mismatch(tmp_path) -> None:
    from regista._action_delegation import action_delegation_hash
    from tests._wi008_fixtures import postgres_action_project

    with postgres_action_project(tmp_path) as project:
        document = action_delegation_document(project)
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.revoke_action_delegation(
                uuid.uuid4(),
                action_delegation_hash(document),
                "human:delegating-owner",
                reason="wrong id must fail",
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID


def test_verifier_rejects_revocation_id_hash_mismatch() -> None:
    from regista._verification import (
        MaterialCompleteness,
        _check_v6_action_revocation_authority,
        _Findings,
    )

    credential = SimpleNamespace(
        credential_id=uuid.uuid4(),
        credential_hash="sha256:" + "11" * 32,
        issuer_principal_id="human:delegating-owner",
    )
    wrong_id = str(uuid.uuid4())
    envelope = {
        "transition": "action_delegation_revoked",
        "payload": {
            "type": "regista.action-delegation-revocation",
            "version": 1,
            "credential_id": wrong_id,
            "credential_hash": credential.credential_hash,
            "reason": "wrong id",
        },
        "actor": {"principal_id": credential.issuer_principal_id},
    }
    referents = SimpleNamespace(
        resolve_action_credential=lambda credential_hash: credential
        if credential_hash == credential.credential_hash
        else None,
        describe=lambda: "test referents",
    )
    findings = _Findings()
    _check_v6_action_revocation_authority(
        envelope,
        referents=referents,
        completeness=MaterialCompleteness.COMPLETE_STORE,
        findings=findings,
    )
    assert findings.invalid is True
    assert any("credential_id" in detail for detail in findings.details)


def _different_signature_document(document: dict[str, Any], *, valid: bool) -> dict[str, Any]:
    import nacl.signing

    from regista._action_delegation import action_delegation_signature_input

    changed = copy.deepcopy(document)
    signature = (
        nacl.signing.SigningKey.generate().sign(
            action_delegation_signature_input(changed)
        ).signature
        if valid
        else b"\x01" * 64
    )
    changed["signature"]["value"] = base64.b64encode(signature).decode("ascii")
    return changed


@pytest.mark.parametrize("valid_signature", [False, True])
def test_in_memory_event_id_retry_compares_credential_bytes(
    tmp_path, valid_signature: bool
) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        event_id = uuid.uuid4()
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            event_id=event_id,
            action_delegation_credentials=(document,),
        )
        changed = _different_signature_document(document, valid=valid_signature)
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                event_id=event_id,
                action_delegation_credentials=(changed,),
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD
    finally:
        project.instance.close()


@pytest.mark.parametrize("valid_signature", [False, True])
def test_postgres_event_id_retry_compares_credential_bytes(
    tmp_path, valid_signature: bool
) -> None:
    from tests._wi008_fixtures import postgres_action_project

    with postgres_action_project(tmp_path) as project:
        document = action_delegation_document(project)
        event_id = uuid.uuid4()
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            event_id=event_id,
            action_delegation_credentials=(document,),
        )
        changed = _different_signature_document(document, valid=valid_signature)
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                event_id=event_id,
                action_delegation_credentials=(changed,),
            )
        assert exc_info.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD


def test_in_memory_writer_rejects_second_use_after_max_uses(tmp_path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project, max_uses=1)
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            event_id=uuid.uuid4(),
            action_delegation_credentials=(document,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                event_id=uuid.uuid4(),
                action_delegation_credentials=(document,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
        assert "max_uses" in exc_info.value.message
    finally:
        project.instance.close()


def test_postgres_writer_rejects_second_use_after_max_uses(tmp_path) -> None:
    from tests._wi008_fixtures import postgres_action_project

    with postgres_action_project(tmp_path) as project:
        document = action_delegation_document(project, max_uses=1)
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            event_id=uuid.uuid4(),
            action_delegation_credentials=(document,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                event_id=uuid.uuid4(),
                action_delegation_credentials=(document,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
        assert "max_uses" in exc_info.value.message


def test_in_memory_rejects_same_credential_id_with_different_bytes(tmp_path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        first = action_delegation_document(project)
        second = action_delegation_document(
            project,
            credential_id=first["credential_id"],
            delegation_allowed=True,
        )
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(first,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                action_delegation_credentials=(second,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_CREDENTIAL_CONFLICT
    finally:
        project.instance.close()


def test_postgres_rejects_same_credential_id_with_different_bytes(tmp_path) -> None:
    from tests._wi008_fixtures import postgres_action_project

    with postgres_action_project(tmp_path) as project:
        first = action_delegation_document(project)
        second = action_delegation_document(
            project,
            credential_id=first["credential_id"],
            delegation_allowed=True,
        )
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(first,),
        )
        with pytest.raises(RegistaError) as exc_info:
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                action_delegation_credentials=(second,),
            )
        assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_CREDENTIAL_CONFLICT


def test_partial_material_missing_issuer_binding_is_unverifiable(tmp_path) -> None:
    from regista._action_delegation import verify_action_delegation_chain

    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        parsed, _binding, envelope, references, referents = _minimal_chain_context(
            project, document
        )
        partial = verify_action_delegation_chain(
            envelope=envelope,
            references=references,
            credentials=[parsed],
            ancestors=[],
            referents=referents,
            material_complete=False,
        )
        complete = verify_action_delegation_chain(
            envelope=envelope,
            references=references,
            credentials=[parsed],
            ancestors=[],
            referents=referents,
            material_complete=True,
        )
        assert partial.status is DelegationVerificationStatus.UNVERIFIABLE
        assert complete.status is DelegationVerificationStatus.INVALID
    finally:
        project.instance.close()


def test_chain_rejects_bootstrap_acceptance_spoofed_on_ordinary_event(tmp_path) -> None:
    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        parsed, binding, envelope, references, _referents = _minimal_chain_context(
            project, document
        )
        spoofed_binding = SimpleNamespace(
            event_hash=binding.event_hash,
            project_instance_id=binding.project_instance_id,
            transition="note_added",
            payload={"bootstrap_key_acceptance": binding.payload},
            envelope={},
        )
        result = verify_action_delegation_chain(
            envelope=envelope,
            references=references,
            credentials=[parsed],
            ancestors=[spoofed_binding],
            referents=SimpleNamespace(
                resolve_referent=lambda event_hash: spoofed_binding
                if event_hash == spoofed_binding.event_hash
                else None
            ),
        )
        assert result.status is DelegationVerificationStatus.INVALID
        assert "binding" in (result.reason or "")
    finally:
        project.instance.close()


def _minimal_chain_context(project: Any, credential: dict[str, Any]):
    parsed = parse_action_delegation(credential)
    binding = SimpleNamespace(
        event_hash=parsed.issuer_key_binding_event_hash,
        project_instance_id=str(project.genesis.project_instance_id),
        transition="principal_key_accepted",
        payload={
            "principal_id": parsed.issuer_principal_id,
            "key_id": parsed.issuer_key_id,
            "project_instance_id": str(project.genesis.project_instance_id),
            "public_key": base64.b64encode(
                project.keyset.key_for(parsed.issuer_principal_id).public_key
            ).decode("ascii"),
            "fingerprint": project.keyset.key_for(
                parsed.issuer_principal_id
            ).fingerprint,
            "trust_event_hash": "sha256:" + "11" * 32,
        },
        envelope={},
    )
    envelope = {
        "project_instance_id": str(project.genesis.project_instance_id),
        "trust_domain_id": str(project.genesis.trust_domain_id),
        "actor": {"principal_id": parsed.subject_principal_id},
        "entity": {"kind": "work_item"},
        "workflow": {"name": project.workflow_name},
        "transition": "note_added",
        "occurred_at": parsed.not_before.isoformat().replace("+00:00", "Z"),
    }
    refs = [{"credential_id": str(parsed.credential_id), "credential_hash": parsed.credential_hash}]
    referents = SimpleNamespace(
        resolve_referent=lambda event_hash: binding
        if event_hash == binding.event_hash
        else None
    )
    return parsed, binding, envelope, refs, referents


def _chain_project(tmp_path, *, principals: tuple[str, ...] = CHAIN_PRINCIPALS):
    return in_memory_action_project(
        tmp_path,
        project="wi008_chain_memory",
        principals=principals,
        creator=principals[0],
    )


def _chain_documents(project: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    root = action_delegation_document(
        project,
        issuer=CHAIN_ROOT,
        subject=CHAIN_MIDDLE,
        delegation_allowed=True,
    )
    child = action_delegation_document(
        project,
        issuer=CHAIN_MIDDLE,
        subject=CHAIN_WORKER,
        parent_credential_hash=action_delegation_hash(root),
    )
    return root, child


def _chain_material(
    project: Any,
    documents: list[dict[str, Any]],
    *,
    actor: str = CHAIN_WORKER,
    transition: str = "note_added",
    ancestors: list[Any] | None = None,
    referent_overrides: dict[str, Any] | None = None,
) -> tuple[list[Any], list[dict[str, str]], dict[str, Any], Any]:
    parsed = [parse_action_delegation(document) for document in documents]
    from tests._v6_fixtures import BOOTSTRAP_PRINCIPAL, acceptance_payload

    references = [
        {
            "credential_id": str(credential.credential_id),
            "credential_hash": credential.credential_hash,
        }
        for credential in parsed
    ]
    acceptance_events = []
    for credential in parsed:
        acceptance = project.acceptances[credential.issuer_principal_id]
        event_hash = acceptance.event_hash
        if not isinstance(event_hash, str):
            event_hash = "sha256:" + event_hash.hex()
        payload = acceptance_payload(
            project.keyset,
            principal_id=credential.issuer_principal_id,
            accepted_by=BOOTSTRAP_PRINCIPAL,
            accepted_by_anchor="sha256:" + project.genesis.event_hash.hex(),
            project_instance_id=str(project.genesis.project_instance_id),
            trust_domain_id=str(project.genesis.trust_domain_id),
            trust_event_hash="sha256:" + "11" * 32,
        )
        acceptance_events.append(
            SimpleNamespace(
                event_hash=event_hash,
                project_instance_id=str(project.genesis.project_instance_id),
                trust_domain_id=str(project.genesis.trust_domain_id),
                transition=acceptance.transition,
                payload=payload,
                envelope={},
            )
        )
    referents_by_hash = {
        event.event_hash: event for event in acceptance_events
    }
    if referent_overrides:
        referents_by_hash.update(referent_overrides)
    envelope = {
        "project_instance_id": str(project.genesis.project_instance_id),
        "trust_domain_id": str(project.genesis.trust_domain_id),
        "actor": {"principal_id": actor},
        "entity": {"kind": "work_item"},
        "workflow": {"name": project.workflow_name},
        "transition": transition,
        "occurred_at": v6_occurred_at(datetime.now(UTC)),
    }
    referents = SimpleNamespace(
        resolve_referent=lambda event_hash: referents_by_hash.get(event_hash),
        describe=lambda: "round-two chain material",
    )
    return (
        list(ancestors if ancestors is not None else acceptance_events),
        references,
        envelope,
        referents,
    )


def _verify_chain(
    project: Any,
    documents: list[dict[str, Any]],
    **kwargs: Any,
):
    ancestors, references, envelope, referents = _chain_material(
        project, documents, **kwargs
    )
    return verify_action_delegation_chain(
        envelope=envelope,
        references=references,
        credentials=[parse_action_delegation(document) for document in documents],
        ancestors=ancestors,
        referents=referents,
    )


def test_chain_happy_path_allows_depth_two(tmp_path) -> None:
    project = _chain_project(tmp_path)
    try:
        root, child = _chain_documents(project)
        result = _verify_chain(project, [root, child])
        assert result.verified
        assert result.participating_principals == frozenset(
            {CHAIN_ROOT, CHAIN_MIDDLE, CHAIN_WORKER}
        )
    finally:
        project.instance.close()


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        (
            "parent_hash_mismatch",
            lambda project, root, child: child.update(
                {"parent_credential_hash": "sha256:" + "ff" * 32}
            ),
        ),
        (
            "delegation_not_allowed",
            lambda project, root, child: root.update({"delegation_allowed": False}),
        ),
        (
            "child_issuer_mismatch",
            lambda project, root, child: child.update(
                {"issuer_principal_id": CHAIN_ROOT}
            ),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_chain_rejects_invalid_parent_continuity(tmp_path, name, mutate) -> None:
    del name
    project = _chain_project(tmp_path)
    try:
        root, child = _chain_documents(project)
        mutate(project, root, child)
        result = _verify_chain(project, [root, child])
        assert not result.verified
        assert result.status is DelegationVerificationStatus.INVALID
    finally:
        project.instance.close()


@pytest.mark.parametrize(
    ("axis", "value"),
    [
        ("project_instance_ids", [str(uuid.uuid4())]),
        ("entity_kinds", ["principal"]),
        ("workflow_names", ["other-workflow"]),
        ("transitions", ["other-transition"]),
    ],
)
def test_chain_rejects_candidate_scope_mismatch_each_axis(
    tmp_path, axis: str, value: list[str]
) -> None:
    project = _chain_project(tmp_path)
    try:
        _root, _child = _chain_documents(project)
        # Keep the credential validly signed while changing the scope under test.
        document = action_delegation_document(
            project,
            issuer=CHAIN_ROOT,
            subject=CHAIN_WORKER,
            delegation_allowed=True,
            scope={
                "project_instance_ids": [str(project.genesis.project_instance_id)]
                if axis != "project_instance_ids"
                else value,
                "entity_kinds": ["work_item"] if axis != "entity_kinds" else value,
                "workflow_names": [project.workflow_name]
                if axis != "workflow_names"
                else value,
                "transitions": ["note_added"] if axis != "transitions" else value,
            },
        )
        result = _verify_chain(project, [document])
        assert not result.verified
        assert "scope" in (result.reason or "")
    finally:
        project.instance.close()


def test_chain_rejects_duplicate_hash_cycle(tmp_path) -> None:
    project = _chain_project(tmp_path)
    try:
        root, _child = _chain_documents(project)
        result = _verify_chain(project, [root, root])
        assert result.status is DelegationVerificationStatus.INVALID
        assert "cycle" in (result.reason or "")
    finally:
        project.instance.close()


def test_chain_rejects_depth_nine(tmp_path) -> None:
    principals = tuple(f"agent:chain-{index}" for index in range(10))
    project = _chain_project(tmp_path, principals=principals)
    try:
        documents: list[dict[str, Any]] = []
        parent_hash: str | None = None
        for index in range(9):
            document = action_delegation_document(
                project,
                issuer=principals[index],
                subject=principals[index + 1],
                parent_credential_hash=parent_hash,
                delegation_allowed=True,
            )
            documents.append(document)
            parent_hash = action_delegation_hash(document)
        result = _verify_chain(
            project,
            documents,
            actor=principals[-1],
        )
        assert result.status is DelegationVerificationStatus.INVALID
        assert "depth" in (result.reason or "")
    finally:
        project.instance.close()
