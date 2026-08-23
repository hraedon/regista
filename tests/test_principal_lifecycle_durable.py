from __future__ import annotations

import base64
import json
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import nacl.signing
import pytest
from _trust_fixtures import mint_genesis
from _trust_log_fixtures import TrustLogKey, _ts, make_registrar_delegation_payload

import regista
from regista import (
    Approval,
    ChallengeStorageScope,
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
from regista._trust_log_writer import append_trust_log_event, write_trust_genesis
from regista.principal_lifecycle import EffectiveChallenge

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
    # Canonical ids per `TRUST-DOMAIN.md` §2.1. The durable fixture provisions a
    # live registrar delegation below; lifecycle authority is never an arbitrary
    # caller-supplied label.
    return EnrollmentRequest(
        principal_id="human:enrollee",
        principal_kind=PrincipalKind.HUMAN,
        actor_id="service:registrar",
        public_key=public_key,
        scheme="ed25519",
        custody_mode=CustodyMode.WINDOWS_LOCAL,
        reason="Initial project enrollment",
        requested_authority="registrar",
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


def _sign_receipt(
    private_key: nacl.signing.SigningKey,
    receipt: EffectiveReceipt,
    challenge: EffectiveChallenge,
) -> EffectiveReceipt:
    """Sign an effective receipt over its full envelope (challenge + metadata)."""
    envelope = receipt.signing_bytes(challenge)
    return replace(receipt, signature=private_key.sign(envelope).signature)


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
def v6_keyset(tmp_path):
    from tests._v6_fixtures import make_v6_keyset

    return make_v6_keyset(tmp_path)


@pytest.fixture
def regista_instance(v6_keyset):
    import uuid

    from _helpers import DSN

    from regista import Regista
    from regista.testing import drop_project_schema
    from tests._v6_fixtures import ACTOR_PRINCIPALS, make_v6_keyset, set_v6_producer_env

    project = f"test_{uuid.uuid4().hex[:8]}"
    # The lifecycle event store is a trust-log project for this focused durable
    # fixture.  Its first event must be trust_domain_established; a regular v6
    # project epoch cannot be mistaken for the authority chain.
    root_principal = "service:root"
    registrar_principal = "service:registrar"
    principals = (*ACTOR_PRINCIPALS, root_principal, registrar_principal)
    if not all(principal in v6_keyset.keys for principal in principals):
        v6_keyset = make_v6_keyset(
            Path(v6_keyset.path).parent,
            principals=principals,
            filename=Path(v6_keyset.path).name,
        )
    root = v6_keyset.key_for(root_principal)
    registrar = v6_keyset.key_for(registrar_principal)
    genesis = mint_genesis(
        threshold=1,
        signer_count=1,
        seeds=[root.seed],
        project_instance_id=str(uuid.uuid4()),
        project_name_hint="test-trust-log",
        # WI-320 (a-prime): the genesis writer custody-binds root_principal_id.
        declared_holder=root_principal,
    )
    genesis_path = Path(v6_keyset.path).parent / "trust-genesis.json"
    genesis_path.write_text(json.dumps(genesis.document), encoding="utf-8")
    sub = Regista.create_project(
        DSN,
        project,
        v6_keyset.path,
        trust_genesis_path=str(genesis_path),
    )
    set_v6_producer_env()
    root_log_key = TrustLogKey(
        key_id=root.key_id,
        seed=root.seed,
        public_key=root.public_key,
        fingerprint=root.fingerprint,
    )
    registrar_log_key = TrustLogKey(
        key_id=registrar.key_id,
        seed=registrar.seed,
        public_key=registrar.public_key,
        fingerprint=registrar.fingerprint,
    )
    write_trust_genesis(
        sub._mgr,
        keys=sub._keys,
        genesis_document=genesis.document,
        root_principal_id=root_principal,
    )
    delegation = make_registrar_delegation_payload(
        trust_domain_id=genesis.trust_domain_id,
        registrar_principal_id=registrar_principal,
        key=registrar_log_key,
        root_keys=[root_log_key],
        max_operations=None,
        not_before=_ts(-24 * 60 * 60),
        not_after=_ts(365 * 24 * 60 * 60),
    )
    append_trust_log_event(
        sub._mgr,
        keys=sub._keys,
        genesis_document=genesis.document,
        transition="registrar_delegated",
        payload=delegation,
        entity_kind="trust_domain",
        entity_id=uuid.UUID(genesis.trust_domain_id),
        principal_id=root_principal,
        authority="root",
    )
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


#: The ceremony's own §5.3 transitions, named rather than counted by entity kind.
#: A clean v6 epoch already carries one ``principal_key_accepted`` per accepted actor
#: principal (``TRUST-DOMAIN.md`` §5.8, appended by ``open_v6_epoch``), and those share
#: ``entity_kind = 'principal'`` with the lifecycle events. Naming the three §5.3
#: transitions keeps "how many events did this commit append" exact — and pins the
#: transition as well as the entity kind, which the bare entity-kind count did not.
_CEREMONY_EVENTS = (
    "entity_kind = 'principal' AND transition IN "
    "('principal_key_enrolled', 'principal_key_rotated', 'principal_key_revoked')"
)


def _db_key_status(reg: regista.Regista, key_id: str) -> str:
    with reg._mgr.transaction() as conn:
        row = conn.execute(
            "SELECT status FROM principal_keys WHERE key_id = %s",
            [key_id],
        ).fetchone()
        assert row is not None
        return cast(str, row["status"])


def _open_fresh_instance(reg: regista.Regista, keyset: Any) -> regista.Regista:
    from _helpers import DSN

    # The v6 keyset, not `KEY_PATH`: a second handle on the same project has to
    # sign with keys the project's epoch has accepted, and the committed
    # `tests/test_keys.json` holds one HMAC key with no `principal_id`.
    return regista.Regista(
        DSN,
        reg.project,
        keyset.path,
        trust_genesis_path=str(Path(keyset.path).parent / "trust-genesis.json"),
    )


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
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 1
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
        requested_authority="registrar",
        policy_version="policy-2026-07",
        old_key_id=old_key_id,
    )
    rot_op = lifecycle.prepare_rotation(rotation, idempotency_key="idem-rotate-2")
    challenge = lifecycle.issue_possession_challenge(rot_op.operation_id)
    proof = _proof(new_private_key, rot_op.digest.value, challenge)
    lifecycle.submit_possession(rot_op.operation_id, proof)
    old_key_signature = private_key.sign(
        lifecycle.rotation_authorization_bytes(rot_op.operation_id)
    ).signature
    lifecycle.submit_rotation_authorization(rot_op.operation_id, old_key_signature)
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


def test_rotation_approval_requires_outgoing_or_root_authorization(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    enrollment_operation = _enroll_and_approve(
        regista_instance,
        private_key,
        enrollment,
        idempotency_key="idem-rotation-approval-enroll",
    )
    lifecycle = regista_instance.principal_lifecycle
    enrollment_receipt = lifecycle.commit(
        enrollment_operation.operation_id,
        expected_digest=enrollment_operation.digest.value,
    )
    new_private_key = nacl.signing.SigningKey.generate()
    rotation = RotationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id=enrollment.actor_id,
        public_key=bytes(new_private_key.verify_key),
        scheme="ed25519",
        custody_mode=CustodyMode.FILE,
        reason="rotation authorization ordering",
        requested_authority="registrar",
        policy_version="policy-2026-07",
        old_key_id=enrollment_receipt.key_id,
    )
    operation = lifecycle.prepare_rotation(rotation, idempotency_key="idem-rotation-approval")
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    lifecycle.submit_possession(
        operation.operation_id,
        _proof(new_private_key, operation.digest.value, challenge),
    )

    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.record_approval(
            operation.operation_id,
            Approval(
                approver_id="entra:tenant:approver-789",
                approver_kind="human",
                approval_digest=operation.digest.value,
            ),
        )
    assert exc_info.value.code is LifecycleErrorCode.AUTHORITY_MISMATCH
    assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"


def test_durable_recovery_rotation_uses_root_threshold(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle = regista_instance.principal_lifecycle
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key="idem-recovery-enroll"
    )
    receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)

    new_private_key = nacl.signing.SigningKey.generate()
    rotation = RotationRequest(
        principal_id=enrollment.principal_id,
        principal_kind=enrollment.principal_kind,
        actor_id="service:root",
        public_key=bytes(new_private_key.verify_key),
        scheme="ed25519",
        custody_mode=CustodyMode.WINDOWS_LOCAL,
        reason="Recovery after outgoing-key loss",
        requested_authority="root",
        policy_version="policy-2026-07",
        old_key_id=receipt.key_id,
    )
    rot_op = lifecycle.prepare_rotation(rotation, idempotency_key="idem-recovery-rotate")
    challenge = lifecycle.issue_possession_challenge(rot_op.operation_id)
    lifecycle.submit_possession(
        rot_op.operation_id,
        _proof(new_private_key, rot_op.digest.value, challenge),
    )

    root = regista_instance._keys.resolve_signing_key("service:root")
    root_signature = nacl.signing.SigningKey(root.secret).sign(
        lifecycle.root_authorization_bytes(rot_op.operation_id)
    ).signature
    lifecycle.submit_root_authorization(
        rot_op.operation_id,
        [
            {
                "signer_id": "service:root",
                "fingerprint": root.fingerprint(),
                "signature": base64.b64encode(root_signature).decode("ascii"),
            }
        ],
    )
    approved = lifecycle.record_approval(
        rot_op.operation_id,
        Approval(
            approver_id="entra:tenant:approver-789",
            approver_kind="human",
            approval_digest=rot_op.digest.value,
        ),
    )
    recovery_receipt = lifecycle.commit(
        approved.operation_id,
        expected_digest=approved.digest.value,
    )
    assert recovery_receipt.status is RegistryReceiptStatus.COMMITTED
    assert recovery_receipt.key_id != receipt.key_id
    assert _db_key_status(regista_instance, receipt.key_id) != "active"


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
        requested_authority="registrar",
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
    effective = _sign_receipt(
        private_key,
        EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=receipt.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at,
            challenge_id=challenge.challenge_id,
            signature=None,
        ),
        challenge,
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
        observed_at=challenge.issued_at,
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
    signed = _sign_receipt(
        private_key,
        EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=receipt.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at,
            challenge_id=challenge.challenge_id,
            signature=None,
        ),
        challenge,
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
    effective = _sign_receipt(
        private_key,
        EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=receipt.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at,
            challenge_id=challenge.challenge_id,
            signature=None,
        ),
        challenge,
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
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 1
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
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 0


def test_durable_commit_rejects_expired(
    regista_instance: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    clock = MutableClock(datetime.now(UTC))
    lifecycle = PrincipalLifecycle(
        regista_instance._project,
        mgr=regista_instance._mgr,
        keys=regista_instance._keys,
        metrics=regista_instance._metrics,
        clock=clock,
        trust_genesis_document=regista_instance._trust_genesis_document,
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
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 0


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
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 0


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
        requested_authority="registrar",
        policy_version="policy-2026-07",
    )
    rev_op = lifecycle.prepare_revocation(revocation, idempotency_key="idem-revoke-unapproved")
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(rev_op.operation_id, expected_digest=rev_op.digest.value)
    assert exc_info.value.code is LifecycleErrorCode.INVALID_OPERATION_STATE
    assert _db_operation_state(regista_instance, rev_op.operation_id) == "awaiting_approval"
    assert _db_count(regista_instance, "events", _CEREMONY_EVENTS, []) == 1


def test_durable_cross_instance_get_operation(
    regista_instance: Any,
    v6_keyset: Any,
    enrollment: EnrollmentRequest,
) -> None:
    lifecycle_a = regista_instance.principal_lifecycle
    operation = lifecycle_a.prepare_enrollment(enrollment, idempotency_key="idem-cross-get")
    reg_b = _open_fresh_instance(regista_instance, v6_keyset)
    try:
        lifecycle_b = reg_b.principal_lifecycle
        op_b = lifecycle_b.get_operation(operation.operation_id)
        assert op_b == operation
        assert op_b.state is LifecycleState.AWAITING_PROOF
    finally:
        reg_b.close()


def test_durable_cross_instance_approval_and_commit(
    regista_instance: Any,
    v6_keyset: Any,
    keypair: tuple[nacl.signing.SigningKey, bytes],
    enrollment: EnrollmentRequest,
) -> None:
    private_key, _ = keypair
    lifecycle_a = regista_instance.principal_lifecycle
    operation = _full_enrollment_flow(
        lifecycle_a, private_key, enrollment, idempotency_key="idem-cross-approval"
    )
    reg_b = _open_fresh_instance(regista_instance, v6_keyset)
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
        assert _db_count(reg_b, "events", _CEREMONY_EVENTS, []) == 1
    finally:
        reg_b.close()


def test_durable_cross_instance_commit_idempotency(
    regista_instance: Any,
    v6_keyset: Any,
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
    reg_b = _open_fresh_instance(regista_instance, v6_keyset)
    try:
        lifecycle_b = reg_b.principal_lifecycle
        receipt_b = lifecycle_b.commit(
            operation.operation_id, expected_digest=operation.digest.value
        )
        assert receipt_b == receipt_a
        assert _db_count(reg_b, "events", _CEREMONY_EVENTS, []) == 1
    finally:
        reg_b.close()


# ---------------------------------------------------------------------------
# Concurrency + cross-instance durability (Plan 031 hardening)
# ---------------------------------------------------------------------------


def _fresh_lifecycle(reg: regista.Regista) -> PrincipalLifecycle:
    """A second lifecycle sharing the DB pool but with empty process-local
    caches — models a separate worker process or a restart."""
    return PrincipalLifecycle(
        reg._project,
        mgr=reg._mgr,
        keys=reg._keys,
        metrics=reg._metrics,
        trust_genesis_document=reg._trust_genesis_document,
    )


class TestDurablePrepareIdempotencyRace:
    def test_concurrent_prepare_same_digest_collapses_to_one_row(
        self,
        regista_instance: Any,
        enrollment: EnrollmentRequest,
    ) -> None:
        # A shared clock and explicit operation_id make both workers compute an
        # identical digest, so this is a genuine idempotency collision (same
        # idempotency key + same digest), not two distinct requests.
        clock = MutableClock(datetime.now(UTC))
        shared_op_id = "11111111-1111-4111-8111-111111111111"
        barrier = threading.Barrier(2, timeout=10)
        results: list[Any] = [None, None]
        errors: list[BaseException | None] = [None, None]

        def worker(idx: int) -> None:
            lifecycle = PrincipalLifecycle(
                regista_instance._project,
                mgr=regista_instance._mgr,
                keys=regista_instance._keys,
                metrics=regista_instance._metrics,
                clock=clock,
                trust_genesis_document=regista_instance._trust_genesis_document,
            )
            try:
                barrier.wait()
                results[idx] = lifecycle.prepare_enrollment(
                    enrollment,
                    idempotency_key="idem-race-same",
                    operation_id=shared_op_id,
                )
            except BaseException as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [None, None], f"concurrent prepare raised: {errors}"
        assert results[0] is not None and results[1] is not None
        assert results[0].operation_id == results[1].operation_id == shared_op_id
        assert results[0].digest.value == results[1].digest.value
        assert _db_count(regista_instance, "lifecycle_operations") == 1

    def test_concurrent_prepare_never_raises_raw_unique_violation(
        self,
        regista_instance: Any,
        enrollment: EnrollmentRequest,
    ) -> None:
        # Four workers race on one idempotency key. Their independent clocks and
        # operation ids yield distinct digests, so exactly one wins and the rest
        # must fail with the stable contract error -- never a raw UniqueViolation.
        import psycopg.errors

        barrier = threading.Barrier(4, timeout=10)
        outcomes: list[Any] = [None] * 4

        def worker(idx: int) -> None:
            lifecycle = _fresh_lifecycle(regista_instance)
            try:
                barrier.wait()
                outcomes[idx] = lifecycle.prepare_enrollment(
                    enrollment, idempotency_key="idem-race-uv"
                )
            except BaseException as exc:
                outcomes[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not any(
            isinstance(o, psycopg.errors.UniqueViolation) for o in outcomes
        ), f"a raw UniqueViolation escaped: {outcomes}"
        mismatches = [
            o
            for o in outcomes
            if isinstance(o, LifecycleContractError)
            and o.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH
        ]
        successes = [o for o in outcomes if not isinstance(o, BaseException)]
        assert len(successes) == 1, f"expected exactly one success: {outcomes}"
        assert len(mismatches) == 3, f"expected three digest mismatches: {outcomes}"
        assert _db_count(regista_instance, "lifecycle_operations") == 1

    def test_concurrent_prepare_different_digest_fails_closed(
        self,
        regista_instance: Any,
        enrollment: EnrollmentRequest,
    ) -> None:
        other = replace(enrollment, reason="A different, conflicting request")
        barrier = threading.Barrier(2, timeout=10)
        outcomes: list[Any] = [None, None]

        def worker(idx: int, request: EnrollmentRequest) -> None:
            lifecycle = _fresh_lifecycle(regista_instance)
            try:
                barrier.wait()
                outcomes[idx] = lifecycle.prepare_enrollment(
                    request, idempotency_key="idem-race-diff"
                )
            except LifecycleContractError as exc:
                outcomes[idx] = exc

        threads = [
            threading.Thread(target=worker, args=(0, enrollment)),
            threading.Thread(target=worker, args=(1, other)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        mismatches = [
            o
            for o in outcomes
            if isinstance(o, LifecycleContractError)
            and o.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH
        ]
        successes = [o for o in outcomes if not isinstance(o, BaseException)]
        assert len(mismatches) == 1, f"expected exactly one digest mismatch: {outcomes}"
        assert len(successes) == 1, f"expected exactly one success: {outcomes}"
        assert _db_count(regista_instance, "lifecycle_operations") == 1


class TestDurableCrossInstanceChallenges:
    def test_cross_instance_possession_submit(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle_a = regista_instance.principal_lifecycle
        operation = lifecycle_a.prepare_enrollment(
            enrollment, idempotency_key="idem-xi-poss"
        )
        challenge = lifecycle_a.issue_possession_challenge(operation.operation_id)

        lifecycle_b = _fresh_lifecycle(regista_instance)
        proof = _proof(private_key, operation.digest.value, challenge)
        verified = lifecycle_b.submit_possession(operation.operation_id, proof)
        assert verified.state is LifecycleState.AWAITING_APPROVAL
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )

    def test_cross_instance_replay_does_not_reprocess(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle_a = regista_instance.principal_lifecycle
        operation = lifecycle_a.prepare_enrollment(
            enrollment, idempotency_key="idem-xi-replay"
        )
        challenge = lifecycle_a.issue_possession_challenge(operation.operation_id)
        proof = _proof(private_key, operation.digest.value, challenge)

        lifecycle_b = _fresh_lifecycle(regista_instance)
        lifecycle_b.submit_possession(operation.operation_id, proof)

        # A second instance replaying the same proof is rejected at the
        # single-use check (the durable used mark is authoritative), so the
        # replay neither succeeds nor double-processes.
        lifecycle_c = _fresh_lifecycle(regista_instance)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle_c.submit_possession(operation.operation_id, proof)
        assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )

    def test_cross_instance_challenge_single_use_at_consume_layer(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        # Isolates the durable single-use guarantee from the operation-state
        # guard: a challenge consumed by one instance cannot be consumed by
        # another, even though the operation is still awaiting proof.
        _private_key, _ = keypair
        lifecycle_a = regista_instance.principal_lifecycle
        operation = lifecycle_a.prepare_enrollment(
            enrollment, idempotency_key="idem-xi-consume"
        )
        challenge = lifecycle_a.issue_possession_challenge(operation.operation_id)

        lifecycle_b = _fresh_lifecycle(regista_instance)
        lifecycle_b._consume_challenge(
            challenge.challenge_id,
            expected_kind="possession",
            expected_operation_digest=operation.digest.value,
            operation_id=operation.operation_id,
        )

        lifecycle_c = _fresh_lifecycle(regista_instance)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle_c._consume_challenge(
                challenge.challenge_id,
                expected_kind="possession",
                expected_operation_digest=operation.digest.value,
                operation_id=operation.operation_id,
            )
        assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED

    def test_concurrent_possession_submit_single_use(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle_a = regista_instance.principal_lifecycle
        operation = lifecycle_a.prepare_enrollment(
            enrollment, idempotency_key="idem-xi-concurrent"
        )
        challenge = lifecycle_a.issue_possession_challenge(operation.operation_id)
        proof = _proof(private_key, operation.digest.value, challenge)

        barrier = threading.Barrier(2, timeout=10)
        outcomes: list[Any] = [None, None]

        def worker(idx: int) -> None:
            lifecycle = _fresh_lifecycle(regista_instance)
            try:
                barrier.wait()
                outcomes[idx] = lifecycle.submit_possession(operation.operation_id, proof)
            except LifecycleContractError as exc:
                outcomes[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        used_errors = [
            o
            for o in outcomes
            if isinstance(o, LifecycleContractError)
            and o.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED
        ]
        successes = [o for o in outcomes if not isinstance(o, BaseException)]
        assert len(used_errors) == 1, f"expected exactly one already-used: {outcomes}"
        assert len(successes) == 1, f"expected exactly one success: {outcomes}"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )

    def test_cross_instance_effective_receipt(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        operation = _enroll_and_approve(
            regista_instance, private_key, enrollment, idempotency_key="idem-xi-eff"
        )
        lifecycle_a = regista_instance.principal_lifecycle
        receipt = lifecycle_a.commit(
            operation.operation_id, expected_digest=operation.digest.value
        )
        challenge = lifecycle_a.issue_effective_challenge(operation.operation_id)

        lifecycle_b = _fresh_lifecycle(regista_instance)
        effective = _sign_receipt(
            private_key,
            EffectiveReceipt(
                operation_id=operation.operation_id,
                operation_digest=operation.digest.value,
                project=operation.project,
                principal_id=operation.principal_id,
                fingerprint=receipt.fingerprint,
                client_type="windows-helper",
                client_version="1.0",
                status=EffectiveReceiptStatus.EFFECTIVE,
                observed_at=challenge.issued_at,
                challenge_id=challenge.challenge_id,
                signature=None,
            ),
            challenge,
        )
        updated = lifecycle_b.record_effective_receipt(operation.operation_id, effective)
        assert updated.state is LifecycleState.EFFECTIVE
        assert _db_operation_state(regista_instance, operation.operation_id) == "effective"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )

    def test_effective_challenge_kind_cannot_be_consumed_as_possession(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        operation = _enroll_and_approve(
            regista_instance, private_key, enrollment, idempotency_key="idem-xi-kind"
        )
        lifecycle_a = regista_instance.principal_lifecycle
        lifecycle_a.commit(operation.operation_id, expected_digest=operation.digest.value)
        challenge = lifecycle_a.issue_effective_challenge(operation.operation_id)

        lifecycle_b = _fresh_lifecycle(regista_instance)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle_b._consume_challenge(
                challenge.challenge_id,
                expected_kind="possession",
                expected_operation_digest=operation.digest.value,
                operation_id=operation.operation_id,
            )
        assert exc_info.value.code is LifecycleErrorCode.PROOF_BINDING_MISMATCH
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 0
        )


class TestApprovalSeparationOfDuties:
    def test_approver_equal_actor_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle = regista_instance.principal_lifecycle
        operation = _full_enrollment_flow(
            lifecycle, private_key, enrollment, idempotency_key="idem-approver-actor"
        )
        approval = Approval(
            approver_id=enrollment.actor_id,
            approver_kind="human",
            approval_digest=operation.digest.value,
        )
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_approval(operation.operation_id, approval)
        assert exc_info.value.code is LifecycleErrorCode.APPROVER_IS_ACTOR
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"

    def test_verifier_can_reject_insufficient_evidence(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        class RequireStepUp:
            def verify_approval(self, operation, approval) -> bool:
                return approval.step_up_evidence is not None

        private_key, _ = keypair
        lifecycle = PrincipalLifecycle(
            regista_instance._project,
            mgr=regista_instance._mgr,
            keys=regista_instance._keys,
            metrics=regista_instance._metrics,
            approval_verifier=RequireStepUp(),
            trust_genesis_document=regista_instance._trust_genesis_document,
        )
        operation = _full_enrollment_flow(
            lifecycle, private_key, enrollment, idempotency_key="idem-verifier-reject"
        )
        no_evidence = Approval(
            approver_id="entra:tenant:approver-789",
            approver_kind="human",
            approval_digest=operation.digest.value,
        )
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_approval(operation.operation_id, no_evidence)
        assert exc_info.value.code is LifecycleErrorCode.APPROVAL_EVIDENCE_REQUIRED
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"

    def test_verifier_accepts_and_records_evidence_verified(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        class RequireStepUp:
            def verify_approval(self, operation, approval) -> bool:
                return approval.step_up_evidence is not None

        private_key, _ = keypair
        lifecycle = PrincipalLifecycle(
            regista_instance._project,
            mgr=regista_instance._mgr,
            keys=regista_instance._keys,
            metrics=regista_instance._metrics,
            approval_verifier=RequireStepUp(),
            trust_genesis_document=regista_instance._trust_genesis_document,
        )
        operation = _full_enrollment_flow(
            lifecycle, private_key, enrollment, idempotency_key="idem-verifier-accept"
        )
        with_evidence = Approval(
            approver_id="entra:tenant:approver-789",
            approver_kind="human",
            approval_digest=operation.digest.value,
            step_up_evidence="mfa:verified",
        )
        approved = lifecycle.record_approval(operation.operation_id, with_evidence)
        assert approved.state is LifecycleState.APPROVED
        assert (
            _db_count(
                regista_instance,
                "lifecycle_approvals",
                "operation_id = %s AND evidence_verified = true",
                [operation.operation_id],
            )
            == 1
        )


# ---------------------------------------------------------------------------
# Defect regressions: DB-authoritative one-use + atomic consume/transition
# ---------------------------------------------------------------------------


class _FaultAfterConn:
    """Connection proxy whose ``execute`` raises once, mid-transaction.

    Raising inside the transaction body (not in a wrapper ``__exit__``) is what
    makes psycopg roll the transaction back. ``skip`` lets the first N
    statements through (the challenge consume) and fails on a later one (the
    operation state advance), modelling a crash between them.
    """

    def __init__(self, conn, error, skip=0):
        self._conn = conn
        self._error = error
        self._skip = skip
        self._calls = 0

    def execute(self, *args, **kwargs):
        self._calls += 1
        if self._calls > self._skip:
            raise self._error
        return self._conn.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class _FaultAfterMgr:
    """ConnectionManager proxy that arms a fault on a chosen transaction.

    ``skip_txns`` lets that many transactions pass untouched (e.g. the
    operation rehydration and the challenge fetch reads) so the fault lands on
    the consume-and-transition transaction; ``skip`` then controls which
    statement within it raises.
    """

    def __init__(self, real, error, skip=0, skip_txns=0):
        self._real = real
        self._error = error
        self._skip = skip
        self._skip_txns = skip_txns
        self.fail_next = False

    @contextmanager
    def transaction(self):
        if not self.fail_next:
            with self._real.transaction() as conn:
                yield conn
            return
        if self._skip_txns > 0:
            self._skip_txns -= 1
            with self._real.transaction() as conn:
                yield conn
            return
        self.fail_next = False
        with self._real.transaction() as conn:
            yield _FaultAfterConn(conn, self._error, self._skip)

    def __getattr__(self, name):
        return getattr(self._real, name)


class TestDurableIssuerStaleCacheReplay:
    def test_possession_replay_on_issuer_after_remote_consume(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        issuer = regista_instance.principal_lifecycle
        operation = issuer.prepare_enrollment(enrollment, idempotency_key="idem-stale-poss")
        challenge = issuer.issue_possession_challenge(operation.operation_id)
        proof = _proof(private_key, operation.digest.value, challenge)

        consumer = _fresh_lifecycle(regista_instance)
        consumer.submit_possession(operation.operation_id, proof)

        # The issuer still holds the challenge cached as used=False; durable
        # mode must consult the database (used=true) and reject the replay.
        with pytest.raises(LifecycleContractError) as exc_info:
            issuer.submit_possession(operation.operation_id, proof)
        assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED

    def test_effective_replay_on_issuer_after_remote_consume(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        operation = _enroll_and_approve(
            regista_instance, private_key, enrollment, idempotency_key="idem-stale-eff"
        )
        issuer = regista_instance.principal_lifecycle
        issuer.commit(operation.operation_id, expected_digest=operation.digest.value)
        challenge = issuer.issue_effective_challenge(operation.operation_id)

        consumer = _fresh_lifecycle(regista_instance)
        consumer._consume_challenge(
            challenge.challenge_id,
            expected_kind="effective",
            expected_operation_digest=operation.digest.value,
            operation_id=operation.operation_id,
        )

        # Issuer's cache says used=False; the database (used=true) is authority.
        with pytest.raises(LifecycleContractError) as exc_info:
            issuer._consume_challenge(
                challenge.challenge_id,
                expected_kind="effective",
                expected_operation_digest=operation.digest.value,
                operation_id=operation.operation_id,
            )
        assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED


class TestDurableConsumeTransitionAtomicity:
    def test_possession_crash_after_consume_rolls_back(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle = regista_instance.principal_lifecycle
        operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-atomic-poss")
        challenge = lifecycle.issue_possession_challenge(operation.operation_id)
        proof = _proof(private_key, operation.digest.value, challenge)

        faulty = _FaultAfterMgr(
            regista_instance._mgr, RuntimeError("crash after consume"), skip=1, skip_txns=1
        )
        crashy = PrincipalLifecycle(
            regista_instance._project,
            mgr=faulty,
            keys=regista_instance._keys,
            metrics=regista_instance._metrics,
            trust_genesis_document=regista_instance._trust_genesis_document,
        )
        # Prime the cache so the fault lands on the consume+transition
        # transaction (the fetch read is the skipped transaction), not on the
        # operation rehydration.
        crashy._operations[operation.operation_id] = operation
        faulty.fail_next = True
        with pytest.raises(RuntimeError, match="crash after consume"):
            crashy.submit_possession(operation.operation_id, proof)

        # The consume rolled back with the transaction: challenge reusable,
        # operation unchanged.
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 0
        )
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_proof"

        retry = _fresh_lifecycle(regista_instance)
        verified = retry.submit_possession(operation.operation_id, proof)
        assert verified.state is LifecycleState.AWAITING_APPROVAL
        assert _db_operation_state(regista_instance, operation.operation_id) == "awaiting_approval"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )

    def test_effective_crash_after_consume_rolls_back(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        operation = _enroll_and_approve(
            regista_instance, private_key, enrollment, idempotency_key="idem-atomic-eff"
        )
        lifecycle = regista_instance.principal_lifecycle
        receipt = lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
        challenge = lifecycle.issue_effective_challenge(operation.operation_id)
        effective = _sign_receipt(
            private_key,
            EffectiveReceipt(
                operation_id=operation.operation_id,
                operation_digest=operation.digest.value,
                project=operation.project,
                principal_id=operation.principal_id,
                fingerprint=receipt.fingerprint,
                client_type="windows-helper",
                client_version="1.0",
                status=EffectiveReceiptStatus.EFFECTIVE,
                observed_at=challenge.issued_at,
                challenge_id=challenge.challenge_id,
                signature=None,
            ),
            challenge,
        )

        faulty = _FaultAfterMgr(
            regista_instance._mgr, RuntimeError("crash after consume"), skip=1, skip_txns=1
        )
        crashy = PrincipalLifecycle(
            regista_instance._project,
            mgr=faulty,
            keys=regista_instance._keys,
            metrics=regista_instance._metrics,
            trust_genesis_document=regista_instance._trust_genesis_document,
        )
        # Prime the cache with the committed operation so the fault lands on the
        # consume+receipt+transition transaction, not the rehydration/fetch.
        crashy._operations[operation.operation_id] = lifecycle.get_operation(
            operation.operation_id
        )
        faulty.fail_next = True
        with pytest.raises(RuntimeError, match="crash after consume"):
            crashy.record_effective_receipt(operation.operation_id, effective)

        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 0
        )
        assert _db_operation_state(regista_instance, operation.operation_id) == "committed"
        assert _db_count(regista_instance, "lifecycle_effective_receipts") == 0

        retry = _fresh_lifecycle(regista_instance)
        updated = retry.record_effective_receipt(operation.operation_id, effective)
        assert updated.state is LifecycleState.EFFECTIVE
        assert _db_operation_state(regista_instance, operation.operation_id) == "effective"
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 1
        )


class TestChallengeStorageScope:
    def test_durable_reports_durable_one_use(self, regista_instance: Any) -> None:
        assert (
            regista_instance.principal_lifecycle.challenge_storage_scope
            is ChallengeStorageScope.DURABLE_ONE_USE
        )

    def test_non_durable_reports_process_local(self) -> None:
        lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
        assert (
            lifecycle.challenge_storage_scope
            is ChallengeStorageScope.PROCESS_LOCAL_FOUNDATION
        )


class TestApprovalVerifierPublicApi:
    class _AcceptAll:
        def verify_approval(self, operation, approval) -> bool:
            return True

    def test_constructor_passes_verifier_to_facade(
        self,
        regista_instance: Any,
        v6_keyset: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        from _helpers import DSN

        sub = regista.Regista(
            DSN,
            regista_instance.project,
            v6_keyset.path,
            approval_verifier=self._AcceptAll(),
            trust_genesis_path=str(Path(v6_keyset.path).parent / "trust-genesis.json"),
        )
        try:
            assert sub.principal_lifecycle._approval_verifier is not None
            private_key, _ = keypair
            operation = _full_enrollment_flow(
                sub.principal_lifecycle, private_key, enrollment, idempotency_key="idem-pubapi"
            )
            approval = Approval(
                approver_id="entra:tenant:approver-789",
                approver_kind="human",
                approval_digest=operation.digest.value,
            )
            approved = sub.principal_lifecycle.record_approval(operation.operation_id, approval)
            assert approved.state is LifecycleState.APPROVED
        finally:
            sub.close()

    def test_create_project_accepts_verifier_param(self) -> None:
        import inspect

        from regista import Regista

        assert "approval_verifier" in inspect.signature(Regista.create_project).parameters
        assert "approval_verifier" in inspect.signature(Regista.__init__).parameters


# ---------------------------------------------------------------------------
# Effective-receipt signing envelope: tamper + chronology + cross-protocol
# ---------------------------------------------------------------------------


def _committed_with_effective_challenge(
    regista_instance: Any,
    private_key: nacl.signing.SigningKey,
    enrollment: EnrollmentRequest,
    idem: str,
) -> tuple[PrincipalLifecycle, regista.LifecycleOperation, EffectiveChallenge, EffectiveReceipt]:
    operation = _enroll_and_approve(
        regista_instance, private_key, enrollment, idempotency_key=idem
    )
    lifecycle = regista_instance.principal_lifecycle
    reg_receipt = lifecycle.commit(
        operation.operation_id, expected_digest=operation.digest.value
    )
    challenge = lifecycle.issue_effective_challenge(operation.operation_id)
    receipt = _sign_receipt(
        private_key,
        EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=reg_receipt.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at,
            challenge_id=challenge.challenge_id,
            signature=None,
        ),
        challenge,
    )
    return lifecycle, operation, challenge, receipt


class TestEffectiveReceiptTamper:
    @pytest.mark.parametrize(
        "field,value",
        [
            ("client_type", "evil-helper"),
            ("client_version", "9.9.9"),
            ("operation_id", "00000000-0000-4000-8000-000000000000"),
        ],
    )
    def test_tampered_metadata_field_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
        field: str,
        value: str,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, receipt = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, f"idem-tamper-{field}"
        )
        tampered = replace(receipt, **{field: value})
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, tampered)
        assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 0
        )

    def test_tampered_status_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, _challenge, receipt = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-tamper-status"
        )
        tampered = replace(receipt, status=EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, tampered)
        assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED

    def test_tampered_observed_at_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, receipt = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-tamper-observed"
        )
        # Still inside the challenge window (chronology passes) but the signed
        # envelope no longer matches.
        tampered = replace(receipt, observed_at=challenge.issued_at + timedelta(seconds=1))
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, tampered)
        assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED

    def test_tampered_challenge_field_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, receipt = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-tamper-challenge"
        )
        # Re-sign over an altered challenge (different verifier_nonce) but present
        # the real challenge: the envelope the verifier rebuilds differs.
        forged_challenge = replace(challenge, verifier_nonce="forged-nonce")
        forged = _sign_receipt(private_key, replace(receipt, signature=None), forged_challenge)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, forged)
        assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED

    def test_cross_protocol_possession_signature_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        from regista.principal_lifecycle import PossessionChallenge

        private_key, _ = keypair
        lifecycle, operation, challenge, receipt = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-cross-protocol"
        )
        # A signature over a possession-domain envelope (same field values) must
        # not verify against the effective-receipt domain envelope.
        possession_envelope = PossessionChallenge(
            challenge_id=challenge.challenge_id,
            operation_id=challenge.operation_id,
            operation_digest=challenge.operation_digest,
            project=challenge.project,
            principal_id=challenge.principal_id,
            fingerprint=challenge.fingerprint,
            scheme=challenge.scheme,
            verifier_nonce=challenge.verifier_nonce,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
        ).signing_bytes()
        cross = replace(
            receipt, signature=private_key.sign(possession_envelope).signature
        )
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, cross)
        assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED


class TestEffectiveReceiptChronology:
    def test_future_observed_at_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, _ = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-chrono-future"
        )
        future = EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=challenge.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.expires_at + timedelta(hours=1),
            challenge_id=challenge.challenge_id,
            signature=None,
        )
        signed = _sign_receipt(private_key, future, challenge)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, signed)
        assert exc_info.value.code is LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID
        assert (
            _db_count(
                regista_instance,
                "lifecycle_challenges",
                "challenge_id = %s AND used = true",
                [challenge.challenge_id],
            )
            == 0
        )

    def test_stale_observed_at_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, _ = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-chrono-stale"
        )
        stale = EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=challenge.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at - timedelta(hours=1),
            challenge_id=challenge.challenge_id,
            signature=None,
        )
        signed = _sign_receipt(private_key, stale, challenge)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, signed)
        assert exc_info.value.code is LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID

    def test_naive_observed_at_rejected(
        self,
        regista_instance: Any,
        keypair: tuple[nacl.signing.SigningKey, bytes],
        enrollment: EnrollmentRequest,
    ) -> None:
        private_key, _ = keypair
        lifecycle, operation, challenge, _ = _committed_with_effective_challenge(
            regista_instance, private_key, enrollment, "idem-chrono-naive"
        )
        naive = EffectiveReceipt(
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=challenge.fingerprint,
            client_type="windows-helper",
            client_version="1.0",
            status=EffectiveReceiptStatus.EFFECTIVE,
            observed_at=challenge.issued_at.replace(tzinfo=None),
            challenge_id=challenge.challenge_id,
            signature=None,
        )
        signed = _sign_receipt(private_key, naive, challenge)
        with pytest.raises(LifecycleContractError) as exc_info:
            lifecycle.record_effective_receipt(operation.operation_id, signed)
        assert exc_info.value.code is LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID
