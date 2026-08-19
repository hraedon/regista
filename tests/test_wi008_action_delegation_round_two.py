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
from regista._review_validators import ReviewRejected
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


ACCEPT_ISSUER = "human:accept-issuer"
DELEGATED_ACCEPT_PRINCIPALS = (*TWO_STAGE_PRINCIPALS, ACCEPT_ISSUER)


def _delegated_accept_project(tmp_path, *, postgres: bool = False):
    if postgres:
        from tests._wi008_fixtures import postgres_action_project

        return postgres_action_project(
            tmp_path,
            project_prefix="wi008_delegated_accept",
            principals=DELEGATED_ACCEPT_PRINCIPALS,
            workflow=TWO_STAGE_REVIEW_WORKFLOW,
            workflow_name="wi008_two_stage_review",
            creator=ACTION_AUTHOR,
        )
    return in_memory_action_project(
        tmp_path,
        project="wi008_delegated_accept_memory",
        principals=DELEGATED_ACCEPT_PRINCIPALS,
        workflow=TWO_STAGE_REVIEW_WORKFLOW,
        workflow_name="wi008_two_stage_review",
        creator=ACTION_AUTHOR,
    )


def _accept_credential(project: Any, *, issuer: str) -> dict[str, Any]:
    return action_delegation_document(
        project,
        issuer=issuer,
        subject=ACTION_FINAL_ACCEPTOR,
        transition="accept",
        workflow_name="wi008_two_stage_review",
    )


def _assert_delegated_accept_independence(project: Any) -> None:
    """Two-stage independence must hold through the accepting event's OWN chain.

    The bypass this pins: `on_behalf_of` cannot be written inside a v6 epoch, so a
    WI-008 credential is the only surviving delegation vehicle — and the accept gate
    compared `pass_ids` against `actor_id` and `on_behalf_of` alone. One principal could
    therefore issue the credential authorizing the adversarial pass AND the credential
    authorizing the acceptance, through two different terminal subjects, and reach
    `done` with a two-stage review that had one authorizing principal.
    """

    _run_two_stage_review(project)
    with pytest.raises(RegistaError) as exc_info:
        project.instance.transition(
            project.work_item.work_item_id,
            "accept",
            ACTION_FINAL_ACCEPTOR,
            actor_kind="human",
            payload=_accept_payload(),
            action_delegation_credentials=(
                _accept_credential(project, issuer=ACTION_REVIEW_ISSUER),
            ),
        )
    assert exc_info.value.code is ErrorCode.VALIDATOR_FAILED
    assert "adversarial pass" in exc_info.value.message
    # Named in the refusal's detail, which is the part that shows the conflict was found
    # through the accepting event's own delegation chain: this principal is neither the
    # actor nor an `on_behalf_of` subject, and those two were all the gate compared.
    cause = exc_info.value.__cause__
    assert isinstance(cause, ReviewRejected)
    assert cause.detail["conflicting_identities"] == [ACTION_REVIEW_ISSUER]
    assert project.instance.get_work_item(
        project.work_item.work_item_id
    ).current_state == "post_review"

    # The gate refuses the *overlap*, not delegation: an independent issuer authorizing
    # the same acceptor still accepts. Without this half the check above would pass
    # equally well for a gate that had simply stopped allowing delegated acceptances.
    project.instance.transition(
        project.work_item.work_item_id,
        "accept",
        ACTION_FINAL_ACCEPTOR,
        actor_kind="human",
        payload=_accept_payload(),
        action_delegation_credentials=(
            _accept_credential(project, issuer=ACCEPT_ISSUER),
        ),
    )
    assert project.instance.get_work_item(
        project.work_item.work_item_id
    ).current_state == "done"


def test_in_memory_two_stage_accept_rejects_delegated_accept_by_pass_issuer(
    tmp_path,
) -> None:
    project = _delegated_accept_project(tmp_path)
    try:
        _assert_delegated_accept_independence(project)
    finally:
        project.instance.close()


def test_postgres_two_stage_accept_rejects_delegated_accept_by_pass_issuer(
    tmp_path,
) -> None:
    with _delegated_accept_project(tmp_path, postgres=True) as project:
        _assert_delegated_accept_independence(project)


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


def _delegated_append_envelope_loads(tmp_path, monkeypatch, *, filler: int) -> int:
    """Envelope re-reads charged to one delegated append over a ``filler``-event chain."""

    from regista import _v6_referents as referents_module

    loads = {"count": 0}
    original = referents_module.StoreReferents.load_envelope

    def counted(self, event_hash):
        loads["count"] += 1
        return original(self, event_hash)

    monkeypatch.setattr(referents_module.StoreReferents, "load_envelope", counted)

    project = in_memory_action_project(
        tmp_path, project=f"wi008_append_cost_{filler}"
    )
    try:
        for index in range(filler):
            project.instance.append_event(
                project.work_item.work_item_id,
                "agent:delegated-worker",
                transition="note_added",
                payload={"n": index},
            )
        document = action_delegation_document(project)
        loads["count"] = 0
        project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            transition="note_added",
            action_delegation_credentials=(document,),
        )
        return loads["count"]
    finally:
        project.instance.close()


def test_delegated_append_envelope_loads_do_not_track_the_chain(
    tmp_path, monkeypatch
) -> None:
    """One delegated append must not re-read an envelope per ancestor.

    The `uses` counter asks every ancestor which credentials it consumed, and reading
    that through `ReferentEvent.envelope` made each question a full store re-scan: one
    append cost O(N) envelope loads and O(N²) row hashing, twice over, with the global
    chain-head lock held (measured at 6.2 s for a single append on an 805-event
    project). Counting loads rather than timing is the point — the defect is the load
    per ancestor, and a wall-clock assertion would be a flake with a threshold.
    """

    small_dir = tmp_path / "small"
    large_dir = tmp_path / "large"
    small_dir.mkdir()
    large_dir.mkdir()
    small = _delegated_append_envelope_loads(small_dir, monkeypatch, filler=40)
    large = _delegated_append_envelope_loads(large_dir, monkeypatch, filler=160)
    assert small == large, (
        f"envelope loads track the chain length: {small} at 40 filler events, "
        f"{large} at 160"
    )
    # A handful of trust-plane referents (the issuer's key acceptance) are legitimately
    # materialized per verification pass; an ancestor-shaped term is not.
    assert large <= 8


def _authorization_envelope(*credential_hashes: str, mode: str = "delegated") -> dict[str, Any]:
    """A minimal event envelope carrying an authorization block, shaped for both the
    eager ``ReferentSummary.from_envelope`` read and the envelope fallback."""

    return {
        "transition": "note_added",
        "project_instance_id": "proj-uses-equivalence",
        "trust_domain_id": "trust-uses-equivalence",
        "actor": {"principal_id": "agent:delegated-worker"},
        "signing": {"key_id": "key-uses-equivalence"},
        "chain": {"previous_project_event_hash": "sha256:" + "ab" * 32},
        "authorization": {
            "mode": mode,
            "credentials": [{"credential_hash": h} for h in credential_hashes],
        },
    }


@pytest.mark.parametrize(
    "hashes",
    [
        (),
        ("sha256:" + "11" * 32,),
        ("sha256:" + "11" * 32, "sha256:" + "22" * 32),
    ],
    ids=["direct-no-credentials", "single-credential", "multiple-credentials"],
)
def test_consumed_hashes_agree_between_eager_summary_and_envelope_fallback(hashes) -> None:
    """The B2 fix reads uses from an eagerly-carried frozenset instead of re-parsing
    each ancestor envelope. Pin the load-bearing invariant the perf test does not:
    the eager summary counts exactly the credential hashes the envelope names, so the
    summary-backed path and the fallback path can never disagree on a use count.
    """
    from regista._action_delegation import _consumed_credential_hashes
    from regista._v6_referents import ReferentEvent, ReferentSummary

    envelope = _authorization_envelope(*hashes)
    expected = frozenset(hashes)

    summary = ReferentSummary.from_envelope(envelope)
    assert summary.authorization_credential_hashes == expected

    eager = ReferentEvent(
        event_hash="sha256:" + "cd" * 32, envelope=envelope, summary=summary
    )
    fallback = ReferentEvent(event_hash="sha256:" + "cd" * 32, envelope=envelope)

    assert _consumed_credential_hashes(eager) == expected
    assert _consumed_credential_hashes(fallback) == expected
    assert _consumed_credential_hashes(eager) == _consumed_credential_hashes(fallback)


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


def _bundle_delegation_verdict(project: Any, event: Any, **from_bundle_kwargs: Any):
    from regista._v6_referents import BundleReferents
    from regista._verification import (
        DEFAULT_POLICY,
        EventRow,
        KeySetResolver,
        verify_event_strict,
    )

    referents = BundleReferents.from_bundle(
        {}, list(project.instance._store.all_events()), **from_bundle_kwargs
    )
    result = verify_event_strict(
        EventRow.from_event(event),
        keys=KeySetResolver(project.instance._keys),
        referents=referents,
        policy=DEFAULT_POLICY,
    )
    return referents, result


def test_bundle_without_credential_section_is_unverifiable_not_invalid(tmp_path) -> None:
    """A bundle v2 cannot transport credentials, so it cannot condemn one either.

    ``BUNDLE-V3.md`` §9 item 6 and the CHANGELOG both say what the verdict must be:
    "bundle v2 does not transport credentials, and delegated audit from bundle-v2
    evidence is therefore unverifiable rather than silently trusted". Reading the
    event-side ``complete-store`` claim for a credential question instead made an intact
    delegated event ``INVALID``, which `_bundle.py` then reported to an operator as
    "Signature verification failed" — about a signature that verified.
    """

    from regista._v6_referents import MaterialCompleteness
    from regista._verification import Applicability, FailureReason

    project = in_memory_action_project(tmp_path)
    try:
        document = action_delegation_document(project)
        event = project.instance.append_event(
            project.work_item.work_item_id,
            "agent:delegated-worker",
            actor_kind="agent",
            transition="note_added",
            action_delegation_credentials=(document,),
        )

        referents, result = _bundle_delegation_verdict(project, event)
        assert referents.completeness is MaterialCompleteness.COMPLETE_STORE
        assert referents.credential_completeness is MaterialCompleteness.UNDECLARED
        assert result.applicability is Applicability.UNVERIFIABLE
        assert result.delegation_verification is (
            DelegationVerificationStatus.UNVERIFIABLE
        )
        assert FailureReason.DELEGATION_CHAIN_INVALID in result.reasons
        assert result.accepted is False

        # A transported section is a claim, and an empty one is a false claim about a
        # credential the event references — the v3 row of the same table, and the reason
        # "not transported" has to be a distinct state from "transported and empty".
        _empty, strict = _bundle_delegation_verdict(
            project, event, action_delegation_credentials=[]
        )
        assert strict.applicability is Applicability.INVALID
        assert strict.delegation_verification is DelegationVerificationStatus.INVALID

        # And a section carrying the credential verifies, which is what makes the
        # unverifiable verdict above a statement about the artifact's format rather
        # than about this event.
        _carried, verified = _bundle_delegation_verdict(
            project, event, action_delegation_credentials=[document]
        )
        assert verified.delegation_verification is (
            DelegationVerificationStatus.VERIFIED
        )
    finally:
        project.instance.close()


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


def _delegation_check_material(project: Any, document: dict[str, Any], **kwargs: Any):
    """A `_check_v6_delegation` call's four arguments, over one real credential."""

    from regista._v6_referents import MaterialCompleteness
    from regista._verification import _ChainContext

    parsed = parse_action_delegation(document)
    ancestors, references, envelope, referents = _chain_material(
        project, [document], **kwargs
    )
    envelope = {
        **envelope,
        "authorization": {"mode": "delegated", "credentials": references},
    }
    material = SimpleNamespace(
        resolve_referent=referents.resolve_referent,
        resolve_action_credential=lambda credential_hash: (
            parsed if credential_hash == parsed.credential_hash else None
        ),
        describe=lambda: "windowed replay material",
        completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
    )
    chain = _ChainContext(
        reachable=tuple(event.event_hash for event in ancestors),
        revoked_acceptances=frozenset(),
        bootstrap=None,
        latest_checkpoint_observation=None,
        truncated=False,
    )
    return envelope, material, chain


def test_delegation_check_downgrades_verified_on_truncated_material(tmp_path) -> None:
    """WI-308: a delegation sub-verdict may not read `verified` off a gapped chain.

    Every question the chain answers beyond the credential's signature is answered from
    ancestors — that the issuer's binding precedes the use, that no revocation does,
    that `max_uses` is not exhausted — and an unpresented prefix is exactly where a
    prior use or a revocation would sit. `_check_v6_workflow_referent` already made this
    distinction for its own referent; this check ignored `chain.truncated` entirely.
    """

    import dataclasses

    from regista._v6_referents import MaterialCompleteness
    from regista._verification import _check_v6_delegation, _Findings

    project = _chain_project(tmp_path)
    try:
        document = action_delegation_document(
            project, issuer=CHAIN_ROOT, subject=CHAIN_WORKER
        )
        envelope, material, intact = _delegation_check_material(
            project, document, actor=CHAIN_WORKER
        )
        gapped = dataclasses.replace(intact, truncated=True)

        findings = _Findings()
        whole = _check_v6_delegation(
            envelope,
            chain=intact,
            referents=material,
            completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
            findings=findings,
        )
        assert whole.status is DelegationVerificationStatus.VERIFIED
        assert findings.applicability.value == "fully_authenticated"

        findings = _Findings()
        truncated = _check_v6_delegation(
            envelope,
            chain=gapped,
            referents=material,
            completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
            findings=findings,
        )
        assert truncated.status is DelegationVerificationStatus.UNVERIFIABLE
        assert findings.unverifiable is True
        assert findings.invalid is False
        assert "truncated" in (truncated.reason or "")

        # The completeness half of the same branch: material that claims to be the whole
        # store contradicts itself by being truncated, and that contradiction is
        # `_walk_chain_context`'s to report, not a reason to withhold this verdict.
        findings = _Findings()
        complete = _check_v6_delegation(
            envelope,
            chain=gapped,
            referents=material,
            completeness=MaterialCompleteness.COMPLETE_STORE,
            findings=findings,
        )
        assert complete.status is DelegationVerificationStatus.VERIFIED
    finally:
        project.instance.close()


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            ErrorCode.SIGNING_SCHEME_NOT_FOUND,
            DelegationVerificationStatus.UNVERIFIABLE,
        ),
        (
            ErrorCode.MATERIAL_CHANGED_UNDER_VERIFICATION,
            DelegationVerificationStatus.UNVERIFIABLE,
        ),
        (ErrorCode.ACTION_DELEGATION_INVALID, DelegationVerificationStatus.INVALID),
    ],
    ids=lambda value: value.value if hasattr(value, "value") else None,
)
def test_chain_reports_regista_error_instead_of_raising(
    tmp_path, monkeypatch, code: ErrorCode, expected: DelegationVerificationStatus
) -> None:
    """WI-309: every outcome is a verdict, including the ones from the machinery.

    `get_scheme("ed25519")` raises `SIGNING_SCHEME_NOT_FOUND` when the extra is absent,
    and `StoreReferents.load_envelope` raises `MATERIAL_CHANGED_UNDER_VERIFICATION` when
    the material moves under the pass. Neither was in the except tuple, so both escaped
    the chain walk and halted a replay; and neither is a statement about the credential,
    so neither may arrive as INVALID — a missing dependency would otherwise condemn
    every delegated event in the log. Both codes are injected at the scheme lookup, the
    one place inside the walk that is reachable synchronously; what is pinned is the
    code → status mapping and that nothing escapes.
    """

    import regista._action_delegation as action_delegation

    def raising(*_args: Any, **_kwargs: Any):
        raise RegistaError(code, "injected")

    monkeypatch.setattr(action_delegation, "get_scheme", raising)

    project = _chain_project(tmp_path)
    try:
        document = action_delegation_document(
            project, issuer=CHAIN_ROOT, subject=CHAIN_WORKER
        )
        result = _verify_chain(project, [document], actor=CHAIN_WORKER)
        assert result.status is expected
        assert "injected" in (result.reason or "")
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
