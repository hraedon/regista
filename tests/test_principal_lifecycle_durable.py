from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

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
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-cancel")
    cancelled = lifecycle.cancel(operation.operation_id, expected_digest=operation.digest.value)
    assert cancelled.state is LifecycleState.CANCELLED


def test_non_durable_cancel_rejects_digest_mismatch(
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-cancel-mismatch")
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.cancel(operation.operation_id, expected_digest="wrong")
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH


def test_non_durable_cancel_rejects_committed_state(
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    _private_key, _ = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-cancel-committed")
    lifecycle.cancel(operation.operation_id, expected_digest=operation.digest.value)
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.cancel(operation.operation_id, expected_digest=operation.digest.value)
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


def _db_operation_state(reg: regista.Regista, operation_id: str) -> str:
    with reg._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT state FROM lifecycle_operations WHERE operation_id = %s",
            [operation_id],
        ).fetchone()
        assert row is not None
        return cast(str, row["state"])


_ALLOWED_TABLES = frozenset(
    {
        "lifecycle_approvals",
        "lifecycle_challenges",
        "lifecycle_effective_receipts",
        "lifecycle_operations",
        "events",
        "principal_keys",
    }
)


def _db_count(
    reg: regista.Regista,
    table: str,
    where: str | None = None,
    params: list[Any] | None = None,
) -> int:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"unexpected table {table!r}")
    params = params or []
    with reg._mgr.transaction() as conn:
        if where:
            query = f"SELECT count(*) AS n FROM {table} WHERE {where}"
        else:
            query = f"SELECT count(*) AS n FROM {table}"
        row = conn.execute(query, params).fetchone()
        assert row is not None
        return cast(int, row["n"])


def _db_key_status(reg: regista.Regista, key_id: str) -> str:
    with reg._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT status FROM principal_keys WHERE key_id = %s",
            [key_id],
        ).fetchone()
        assert row is not None
        return cast(str, row["status"])


def _open_fresh_instance(reg: regista.Regista) -> regista.Regista:
    from _helpers import DSN, KEY_PATH

    return regista.Regista(DSN, reg.project, KEY_PATH)


def test_durable_prepare_persists(
    regista_instance: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-prepare")
    assert operation.state is LifecycleState.AWAITING_PROOF
    assert lifecycle.is_durable
    fetched = lifecycle.get_operation(operation.operation_id)
    assert fetched == operation
    assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_proof"
    assert _db_count(regista_instance, "lifecycle_approvals") == 0
    assert _db_count(regista_instance, "lifecycle_effective_receipts") == 0


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
    assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"
    assert _db_count(regista_instance, "lifecycle_challenges", "used = %s", [True]) == 1


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
    assert _db_operation_state(regista_instance, operation.operation_id) == "approved"
    assert (
        _db_count(
            regista_instance,
            "lifecycle_approvals",
            "operation_id = %s",
            [operation.operation_id],
        )
        == 1
    )


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    assert receipt.status is RegistryReceiptStatus.COMMITTED
    assert receipt.key_id
    assert receipt.fingerprint
    committed = lifecycle.get_operation(operation.operation_id)
    assert committed.state is LifecycleState.COMMITTED
    assert _db_operation_state(regista_instance, operation.operation_id) == "committed"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 1
    assert (
        _db_count(
            regista_instance,
            "principal_keys",
            "principal_id = %s AND status = 'active'",
            [enrollment.principal_id],
        )
        == 1
    )


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
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
    rot_op = lifecycle.prepare_rotation(rotation, idempotency_key="idem-rotate-2")
    challenge = lifecycle.issue_possession_challenge(rot_op.operation_id)
    proof = _proof(new_private_key, rot_op.digest.value, challenge)
    lifecycle.submit_possession(rot_op.operation_id, proof)
    approval = Approval(
        approver_id="entra:tenant:approver-789",
        approver_kind="human",
        approval_digest=rot_op.digest.value,
    )
    approved = lifecycle.record_approval(rot_op.operation_id, approval)
    rot_receipt = lifecycle.commit(approved.operation_id, expected_digest=approved.digest.value)
    assert rot_receipt.status is RegistryReceiptStatus.COMMITTED
    assert rot_receipt.key_id != old_key_id
    assert _db_operation_state(regista_instance, approved.operation_id) == "committed"
    assert _db_key_status(regista_instance, old_key_id) != "active"
    assert (
        _db_count(
            regista_instance,
            "principal_keys",
            "principal_id = %s AND status = 'active'",
            [enrollment.principal_id],
        )
        == 1
    )


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    revocation = RevocationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id=enrollment.actor_id,
        key_id=receipt.key_id,
        reason="Reported compromise",
        requested_authority="security-admin",
        policy_version="policy-2026-07",
    )
    rev_op = lifecycle.prepare_revocation(revocation, idempotency_key="idem-revoke-2")
    assert rev_op.state is LifecycleState.AWAITING_APPROVAL
    approval = Approval(
        approver_id="entra:tenant:approver-789",
        approver_kind="human",
        approval_digest=rev_op.digest.value,
    )
    approved = lifecycle.record_approval(rev_op.operation_id, approval)
    rev_receipt = lifecycle.commit(approved.operation_id, expected_digest=approved.digest.value)
    assert rev_receipt.status is RegistryReceiptStatus.COMMITTED
    assert _db_operation_state(regista_instance, approved.operation_id) == "committed"
    assert _db_key_status(regista_instance, rev_receipt.key_id) == "revoked"
    assert (
        _db_count(
            regista_instance,
            "principal_keys",
            "principal_id = %s AND status = 'active'",
            [enrollment.principal_id],
        )
        == 0
    )
    desc = lifecycle.describe(enrollment.principal_id)
    assert desc.required_next_action is None


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    challenge = lifecycle.issue_effective_challenge(operation.operation_id)
    envelope = challenge.signing_bytes()
    signature = private_key.sign(envelope).signature
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
        challenge_id=challenge.challenge_id,
        signature=signature,
    )
    updated = lifecycle.record_effective_receipt(operation.operation_id, effective)
    assert updated.state is LifecycleState.EFFECTIVE
    assert _db_operation_state(regista_instance, operation.operation_id) == "effective"
    assert _db_count(regista_instance, "lifecycle_effective_receipts") == 1


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
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
    updated = lifecycle.record_effective_receipt(operation.operation_id, effective)
    assert updated.state is LifecycleState.PARTIALLY_EFFECTIVE
    assert _db_operation_state(regista_instance, operation.operation_id) == "partially_effective"
    assert _db_count(regista_instance, "lifecycle_effective_receipts") == 1


def test_durable_unsigned_receipt_does_not_burn_challenge(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    """A proof-less receipt carrying a challenge_id must not consume it.

    An unsigned COMMITTED_NOT_EFFECTIVE report carries no proof, so it must
    not burn the challenge — the in-memory and durable single-use marks must
    agree (previously the DB marked used while memory did not). The operation
    is nonetheless terminal at PARTIALLY_EFFECTIVE: a later signed receipt on
    the same operation is rejected by the state guard, which is the current
    documented contract (no recovery path for transient provider outages —
    reconcile/repair is Plan 031 WI-2.2 territory).
    """
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-noburn"
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    challenge = lifecycle.issue_effective_challenge(operation.operation_id)

    unsigned = EffectiveReceipt(
        operation_id=operation.operation_id,
        operation_digest=operation.digest.value,
        project=operation.project,
        principal_id=operation.principal_id,
        fingerprint=receipt.fingerprint,
        client_type="windows-helper",
        client_version="1.0",
        status=EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE,
        observed_at=NOW,
        challenge_id=challenge.challenge_id,
        signature=None,
    )
    updated = lifecycle.record_effective_receipt(operation.operation_id, unsigned)
    assert updated.state is LifecycleState.PARTIALLY_EFFECTIVE
    assert (
        _db_count(
            regista_instance,
            "lifecycle_challenges",
            "challenge_id = %s AND used = true",
            [challenge.challenge_id],
        )
        == 0
    )

    # PARTIALLY_EFFECTIVE is terminal for this operation: a later signed
    # receipt is rejected by the state guard, and the challenge stays unburned.
    envelope = challenge.signing_bytes()
    signature = private_key.sign(envelope).signature
    signed = EffectiveReceipt(
        operation_id=operation.operation_id,
        operation_digest=operation.digest.value,
        project=operation.project,
        principal_id=operation.principal_id,
        fingerprint=receipt.fingerprint,
        client_type="windows-helper",
        client_version="1.0",
        status=EffectiveReceiptStatus.EFFECTIVE,
        observed_at=NOW,
        challenge_id=challenge.challenge_id,
        signature=signature,
    )
    with pytest.raises(LifecycleContractError) as excinfo:
        lifecycle.record_effective_receipt(operation.operation_id, signed)
    assert excinfo.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE
    assert (
        _db_count(
            regista_instance,
            "lifecycle_challenges",
            "challenge_id = %s AND used = true",
            [challenge.challenge_id],
        )
        == 0
    )


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
    lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    desc = lifecycle.describe(enrollment.principal_id)
    assert desc.principal_id == enrollment.principal_id
    assert desc.active_key_fingerprint is not None
    assert desc.lifecycle_state is LifecycleState.COMMITTED
    assert desc.required_next_action == "record_effective_receipt"
    assert (
        _db_count(
            regista_instance,
            "principal_keys",
            "principal_id = %s AND status = 'active'",
            [enrollment.principal_id],
        )
        == 1
    )


def test_durable_describe_unknown_principal(
    regista_instance: Any,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    desc = lifecycle.describe("unknown:principal")
    assert desc.active_key_fingerprint is None
    assert desc.lifecycle_state is LifecycleState.DRAFT


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
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    challenge = lifecycle.issue_effective_challenge(operation.operation_id)
    envelope = challenge.signing_bytes()
    signature = private_key.sign(envelope).signature
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
        challenge_id=challenge.challenge_id,
        signature=signature,
    )
    lifecycle.record_effective_receipt(operation.operation_id, effective)
    report = lifecycle.reconcile(enrollment.principal_id)
    assert report.status is ReconciliationStatus.CONSISTENT
    assert len(report.findings) == 0


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
    lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    report = lifecycle.reconcile(enrollment.principal_id)
    assert report.status is ReconciliationStatus.DRIFTED
    assert "missing_effective_receipt" in report.findings


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
    cancelled = lifecycle.cancel(operation.operation_id, expected_digest=operation.digest.value)
    assert cancelled.state is LifecycleState.CANCELLED
    assert _db_operation_state(regista_instance, operation.operation_id) == "cancelled"


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
    receipt1 = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    receipt2 = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    assert receipt1 == receipt2
    assert _db_operation_state(regista_instance, operation.operation_id) == "committed"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 1
    assert (
        _db_count(
            regista_instance,
            "principal_keys",
            "principal_id = %s AND status = 'active'",
            [enrollment.principal_id],
        )
        == 1
    )


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
    assert _db_operation_state(regista_instance, operation.operation_id) == "approved"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 0


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
    assert _db_operation_state(regista_instance, operation.operation_id) == "approved"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 0


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
        lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    assert exc_info.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE
    assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 0


def test_durable_idempotent_prepare(
    regista_instance: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle = regista_instance.principal_lifecycle
    first = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-repeat")
    second = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-repeat")
    assert first == second
    assert _db_count(regista_instance, "lifecycle_operations") == 1


def test_durable_commit_revocation_rejects_unapproved(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance,
        private_key,
        enrollment,
        idempotency_key="idem-revoke-unapproved-base",
    )
    lifecycle = regista_instance.principal_lifecycle
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    revocation = RevocationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id=enrollment.actor_id,
        key_id=receipt.key_id,
        reason="Reported compromise",
        requested_authority="security-admin",
        policy_version="policy-2026-07",
    )
    rev_op = lifecycle.prepare_revocation(revocation, idempotency_key="idem-revoke-unapproved")
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(rev_op.operation_id, expected_digest=rev_op.digest.value)
    assert exc_info.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE
    assert _db_operation_state(regista_instance, rev_op.operation_id) == "awaiting_approval"
    assert _db_count(regista_instance, "events", "entity_kind = 'principal'", []) == 1


def test_durable_cross_instance_get_operation(
    regista_instance: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle_a = regista_instance.principal_lifecycle
    operation = lifecycle_a.prepare_enrollment(enrollment, idempotency_key="idem-cross-get")
    reg_b = _open_fresh_instance(regista_instance)
    try:
        lifecycle_b = reg_b.principal_lifecycle
        op_b = lifecycle_b.get_operation(operation.operation_id)
        assert op_b == operation
        assert op_b.state is LifecycleState.AWAITING_PROOF
    finally:
        reg_b.close()


def test_durable_cross_instance_approval_and_commit(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle_a = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle_a, private_key, enrollment, idempotency_key="idem-cross-approval"
    )
    reg_b = _open_fresh_instance(regista_instance)
    try:
        lifecycle_b = reg_b.principal_lifecycle
        op_b = lifecycle_b.get_operation(operation.operation_id)
        assert op_b.state is LifecycleState.AWAITING_APPROVAL
        approval = Approval(
            approver_id="entra:tenant:approver-789",
            approver_kind="human",
            approval_digest=op_b.digest.value,
        )
        approved = lifecycle_b.record_approval(operation.operation_id, approval)
        assert approved.state is LifecycleState.APPROVED
        receipt = lifecycle_b.commit(operation.operation_id, expected_digest=op_b.digest.value)
        assert receipt.status is RegistryReceiptStatus.COMMITTED
        assert _db_operation_state(reg_b, operation.operation_id) == "committed"
        assert _db_count(reg_b, "events", "entity_kind = 'principal'", []) == 1
    finally:
        reg_b.close()


def test_durable_cross_instance_commit_idempotency(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    operation = _enroll_and_approve(
        regista_instance,
        private_key,
        enrollment,
        idempotency_key="idem-cross-idempotent",
    )
    lifecycle_a = regista_instance.principal_lifecycle
    receipt_a = lifecycle_a.commit(operation.operation_id, expected_digest=operation.digest.value)
    reg_b = _open_fresh_instance(regista_instance)
    try:
        lifecycle_b = reg_b.principal_lifecycle
        receipt_b = lifecycle_b.commit(
            operation.operation_id, expected_digest=operation.digest.value
        )
        assert receipt_b == receipt_a
        assert _db_count(reg_b, "events", "entity_kind = 'principal'", []) == 1
    finally:
        reg_b.close()
