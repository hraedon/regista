from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import nacl.signing
import pytest

import regista
from regista import (
    Approval,
    CustodyMode,
    EffectiveReceipt,
    EffectiveReceiptStatus,
    EnrollmentRequest,
    LifecycleContractError,
    LifecycleErrorCode,
    LifecycleState,
    PossessionProof,
    PrincipalKind,
    PrincipalLifecycle,
    ProofFormat,
    ReconciliationStatus,
    RegistryReceiptStatus,
    RevocationRequest,
    RotationRequest,
)

NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture
def keypair() -> tuple[nacl.signing.SigningKey, bytes]:
    private_key = nacl.signing.SigningKey.generate()
    return private_key, bytes(private_key.verify_key)


@pytest.fixture
def enrollment(keypair: tuple[nacl.signing.SigningKey, bytes]) -> EnrollmentRequest:
    _private_key, public_key = keypair
    return EnrollmentRequest(
        principal_id="entra:tenant:object-123",
        principal_kind=PrincipalKind.HUMAN,
        actor_id="entra:tenant:admin-456",
        public_key=public_key,
        scheme="ed25519",
        custody_mode=CustodyMode.WINDOWS_LOCAL,
        reason="Initial project enrollment",
        requested_authority="project-signer",
        policy_version="policy-2026-07",
        identity_binding_digest="sha256:identity-binding",
        protected_options=(("ticket", "KEY-42"),),
    )


def _proof(
    private_key: nacl.signing.SigningKey,
    operation_digest: str,
    challenge: regista.PossessionChallenge,
) -> PossessionProof:
    signature = private_key.sign(challenge.signing_bytes()).signature
    return PossessionProof(
        format=ProofFormat.SIGNATURE_V1,
        challenge_id=challenge.challenge_id,
        operation_id=challenge.operation_id,
        operation_digest=operation_digest,
        signature=signature,
    )


def _full_enrollment_flow(
    lifecycle: PrincipalLifecycle,
    private_key: nacl.signing.SigningKey,
    enrollment: EnrollmentRequest,
    *,
    idempotency_key: str = "idem-durable",
    operation_id: str | None = None,
) -> regista.LifecycleOperation:
    operation = lifecycle.prepare_enrollment(
        enrollment,
        idempotency_key=idempotency_key,
        operation_id=operation_id,
    )
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    proof = _proof(private_key, operation.digest.value, challenge)
    return lifecycle.submit_possession(operation.operation_id, proof)


# ---------------------------------------------------------------------------
# Non-durable mode tests
# ---------------------------------------------------------------------------


def test_non_durable_commit_raises() -> None:
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit("op-1", expected_digest="x")
    assert exc_info.value.code is LifecycleErrorCode.DURABLE_OPERATION_REQUIRED


def test_non_durable_record_approval_raises() -> None:
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    approval = Approval(
        approver_id="admin",
        approver_kind="human",
        approval_digest="x",
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.record_approval("op-1", approval)
    assert exc_info.value.code is LifecycleErrorCode.DURABLE_OPERATION_REQUIRED


def test_non_durable_describe_returns_draft() -> None:
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    desc = lifecycle.describe("service:example")
    assert desc.lifecycle_state is LifecycleState.DRAFT
    assert desc.active_key_fingerprint is None
    assert desc.required_next_action == "prepare_enrollment"


def test_non_durable_cancel_works(
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    _private_key, _ = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-cancel"
    )
    cancelled = lifecycle.cancel(
        operation.operation_id, expected_digest=operation.digest.value
    )
    assert cancelled.state is LifecycleState.CANCELLED


def test_non_durable_cancel_rejects_digest_mismatch(
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-cancel-mismatch"
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.cancel(operation.operation_id, expected_digest="wrong")
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH


def test_non_durable_cancel_rejects_committed_state(
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    _private_key, _ = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-cancel-committed"
    )
    lifecycle.cancel(
        operation.operation_id, expected_digest=operation.digest.value
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.cancel(
            operation.operation_id, expected_digest=operation.digest.value
        )
    assert exc_info.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE


def test_approval_dataclass_is_frozen() -> None:
    approval = Approval(
        approver_id="admin",
        approver_kind="human",
        approval_digest="sha256:abc",
    )
    with pytest.raises(AttributeError):
        approval.approver_id = "changed"  # type: ignore[misc]


def test_approval_exported_from_regista() -> None:
    assert regista.Approval is Approval


# ---------------------------------------------------------------------------
# Durable mode tests (require a database)
# ---------------------------------------------------------------------------


def _enroll_and_approve(
    reg: regista.Regista,
    private_key: nacl.signing.SigningKey,
    enrollment: EnrollmentRequest,
    *,
    idempotency_key: str = "idem-durable",
) -> regista.LifecycleOperation:
    lifecycle = reg.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle,
        private_key,
        enrollment,
        idempotency_key=idempotency_key,
    )
    approval = Approval(
        approver_id="entra:tenant:approver-789",
        approver_kind="human",
        approval_digest=operation.digest.value,
        reason="Approved by security admin",
    )
    return lifecycle.record_approval(operation.operation_id, approval)


@pytest.fixture
def regista_instance():
    import uuid

    from _helpers import DSN, KEY_PATH

    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"test_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


_durable_test = pytest.mark.skipif(
    True,
    reason="requires a running PostgreSQL database",
)


@_durable_test
def test_durable_prepare_persists(
    regista_instance: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-prepare"
    )
    assert operation.state is LifecycleState.AWAITING_PROOF
    assert lifecycle.is_durable
    fetched = lifecycle.get_operation(operation.operation_id)
    assert fetched == operation


@_durable_test
def test_durable_possession_challenge_lifecycle(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle, private_key, enrollment, idempotency_key="idem-challenge"
    )
    assert operation.state is LifecycleState.AWAITING_APPROVAL


@_durable_test
def test_durable_approval_recording(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-approval"
    )
    assert operation.state is LifecycleState.APPROVED


@_durable_test
def test_durable_approval_rejects_digest_mismatch(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle, private_key, enrollment, idempotency_key="idem-approval-mismatch"
    )
    approval = Approval(
        approver_id="admin",
        approver_kind="human",
        approval_digest="wrong-digest",
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.record_approval(operation.operation_id, approval)
    assert exc_info.value.code is LifecycleErrorCode.APPROVAL_DIGEST_MISMATCH


@_durable_test
def test_durable_commit_enrollment(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-commit"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    assert receipt.status is RegistryReceiptStatus.COMMITTED
    assert receipt.key_id
    assert receipt.fingerprint
    committed = lifecycle.get_operation(operation.operation_id)
    assert committed.state is LifecycleState.COMMITTED


@_durable_test
def test_durable_commit_rotation(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-rotate-1"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    old_key_id = receipt.key_id
    new_private_key = nacl.signing.SigningKey.generate()
    new_public_key = bytes(new_private_key.verify_key)
    rotation = RotationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id=enrollment.actor_id,
        public_key=new_public_key,
        scheme="ed25519",
        custody_mode=CustodyMode.WINDOWS_LOCAL,
        reason="Key rotation",
        requested_authority="project-signer",
        policy_version="policy-2026-07",
        old_key_id=old_key_id,
    )
    rot_op = lifecycle.prepare_rotation(
        rotation, idempotency_key="idem-rotate-2"
    )
    challenge = lifecycle.issue_possession_challenge(rot_op.operation_id)
    proof = _proof(new_private_key, rot_op.digest.value, challenge)
    lifecycle.submit_possession(rot_op.operation_id, proof)
    approval = Approval(
        approver_id="entra:tenant:approver-789",
        approver_kind="human",
        approval_digest=rot_op.digest.value,
    )
    approved = lifecycle.record_approval(rot_op.operation_id, approval)
    rot_receipt = lifecycle.commit(
        approved.operation_id, expected_digest=approved.digest.value
    )
    assert rot_receipt.status is RegistryReceiptStatus.COMMITTED
    assert rot_receipt.key_id != old_key_id


@_durable_test
def test_durable_commit_revocation(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-revoke-1"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    revocation = RevocationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id=enrollment.actor_id,
        key_id=receipt.key_id,
        reason="Reported compromise",
        requested_authority="security-admin",
        policy_version="policy-2026-07",
    )
    rev_op = lifecycle.prepare_revocation(
        revocation, idempotency_key="idem-revoke-2"
    )
    assert rev_op.state is LifecycleState.AWAITING_APPROVAL
    approval = Approval(
        approver_id="entra:tenant:approver-789",
        approver_kind="human",
        approval_digest=rev_op.digest.value,
    )
    approved = lifecycle.record_approval(rev_op.operation_id, approval)
    rev_receipt = lifecycle.commit(
        approved.operation_id, expected_digest=approved.digest.value
    )
    assert rev_receipt.status is RegistryReceiptStatus.COMMITTED


@_durable_test
def test_durable_effective_receipt(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-effective"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    effective = EffectiveReceipt(
        operation_id=operation.operation_id,
        operation_digest=operation.digest.value,
        project=operation.project,
        principal_id=operation.principal_id,
        fingerprint=receipt.fingerprint,
        client_type="windows-helper",
        client_version="1.0",
        status=EffectiveReceiptStatus.EFFECTIVE,
        observed_at=NOW,
    )
    updated = lifecycle.record_effective_receipt(
        operation.operation_id, effective
    )
    assert updated.state is LifecycleState.EFFECTIVE


@_durable_test
def test_durable_effective_receipt_partial(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-partial"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    effective = EffectiveReceipt(
        operation_id=operation.operation_id,
        operation_digest=operation.digest.value,
        project=operation.project,
        principal_id=operation.principal_id,
        fingerprint=receipt.fingerprint,
        client_type="windows-helper",
        client_version="1.0",
        status=EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE,
        observed_at=NOW,
    )
    updated = lifecycle.record_effective_receipt(
        operation.operation_id, effective
    )
    assert updated.state is LifecycleState.PARTIALLY_EFFECTIVE


@_durable_test
def test_durable_describe(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-describe"
    )
    lifecycle = regista_instance.principal_lifecycle
    lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    desc = lifecycle.describe(enrollment.principal_id)
    assert desc.principal_id == enrollment.principal_id
    assert desc.active_key_fingerprint is not None
    assert desc.lifecycle_state is LifecycleState.COMMITTED
    assert desc.required_next_action == "record_effective_receipt"


@_durable_test
def test_durable_describe_unknown_principal(
    regista_instance: Any,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    desc = lifecycle.describe("unknown:principal")
    assert desc.active_key_fingerprint is None
    assert desc.lifecycle_state is LifecycleState.DRAFT


@_durable_test
def test_durable_reconcile_consistent(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-reconcile"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    effective = EffectiveReceipt(
        operation_id=operation.operation_id,
        operation_digest=operation.digest.value,
        project=operation.project,
        principal_id=operation.principal_id,
        fingerprint=receipt.fingerprint,
        client_type="windows-helper",
        client_version="1.0",
        status=EffectiveReceiptStatus.EFFECTIVE,
        observed_at=NOW,
    )
    lifecycle.record_effective_receipt(operation.operation_id, effective)
    report = lifecycle.reconcile(enrollment.principal_id)
    assert report.status is ReconciliationStatus.CONSISTENT
    assert len(report.findings) == 0


@_durable_test
def test_durable_reconcile_detects_drift(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-drift"
    )
    lifecycle = regista_instance.principal_lifecycle
    lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    report = lifecycle.reconcile(enrollment.principal_id)
    assert report.status is ReconciliationStatus.DRIFTED
    assert "missing_effective_receipt" in report.findings


@_durable_test
def test_durable_cancel(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle, private_key, enrollment, idempotency_key="idem-durable-cancel"
    )
    cancelled = lifecycle.cancel(
        operation.operation_id, expected_digest=operation.digest.value
    )
    assert cancelled.state is LifecycleState.CANCELLED


@_durable_test
def test_durable_idempotent_commit(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-idempotent"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt1 = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    receipt2 = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    assert receipt1.key_id == receipt2.key_id
    assert receipt1.fingerprint == receipt2.fingerprint


@_durable_test
def test_durable_commit_rejects_digest_mismatch(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-mismatch"
    )
    lifecycle = regista_instance.principal_lifecycle
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(operation.operation_id, expected_digest="wrong")
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH


@_durable_test
def test_durable_commit_rejects_expired(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    clock = MutableClock()
    lifecycle = PrincipalLifecycle(
        regista_instance._project,
        mgr=regista_instance._mgr,
        keys=regista_instance._keys,
        metrics=regista_instance._metrics,
        clock=clock,
    )
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-expired", ttl=timedelta(seconds=1)
    )
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    proof = _proof(keypair[0], operation.digest.value, challenge)
    lifecycle.submit_possession(operation.operation_id, proof)
    approval = Approval(
        approver_id="admin",
        approver_kind="human",
        approval_digest=operation.digest.value,
    )
    lifecycle.record_approval(operation.operation_id, approval)
    clock.value += timedelta(hours=1)
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_EXPIRED


@_durable_test
def test_durable_commit_rejects_unapproved(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle, private_key, enrollment, idempotency_key="idem-unapproved"
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(
            operation.operation_id, expected_digest=operation.digest.value
        )
    assert exc_info.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE


@_durable_test
def test_durable_idempotent_prepare(
    regista_instance: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    first = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-repeat"
    )
    second = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-repeat"
    )
    assert first == second
