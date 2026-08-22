from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, cast

import nacl.signing
import pytest

import regista
from regista import (
    ChallengeStorageScope,
    CustodyMode,
    EnrollmentRequest,
    LifecycleContractError,
    LifecycleErrorCode,
    LifecycleOperationType,
    LifecycleState,
    PossessionProof,
    PrincipalKind,
    PrincipalLifecycle,
    ProofFormat,
    RevocationRequest,
    RotationRequest,
    canonical_lifecycle_digest,
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
        requested_authority="registrar",
        policy_version="policy-2026-07",
        identity_binding_digest="sha256:identity-binding",
        protected_options=(("ticket", "KEY-42"), ("requires_step_up", "true")),
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


def test_public_contract_types_are_closed_and_frozen(enrollment: EnrollmentRequest) -> None:
    assert issubclass(LifecycleState, StrEnum)
    assert {item.value for item in LifecycleOperationType} == {
        "enrollment",
        "rotation",
        "revocation",
    }
    with pytest.raises(FrozenInstanceError):
        enrollment.reason = "changed"  # type: ignore[misc]


def test_prepare_enrollment_is_deterministic_for_same_protected_fields(
    enrollment: EnrollmentRequest,
) -> None:
    reordered = EnrollmentRequest(
        **{
            **enrollment.__dict__,
            "protected_options": tuple(reversed(enrollment.protected_options)),
        }
    )
    first = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
        enrollment, idempotency_key="idem-fixed", operation_id="op-fixed"
    )
    second = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
        reordered, idempotency_key="idem-fixed", operation_id="op-fixed"
    )

    assert first.digest == second.digest
    assert first.state is LifecycleState.AWAITING_PROOF
    assert first.operation_type is LifecycleOperationType.ENROLLMENT
    assert first.project == "alpha"
    assert first.to_dict()["public_key"] is not None
    assert first.to_dict()["protected_options"] == {
        "requires_step_up": "true",
        "ticket": "KEY-42",
    }


def test_digest_changes_for_every_authorization_binding(enrollment: EnrollmentRequest) -> None:
    baseline = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
        enrollment, idempotency_key="idem-fixed", operation_id="op-fixed"
    )
    changed = EnrollmentRequest(**{**enrollment.__dict__, "reason": "Replacement enrollment"})
    other = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
        changed, idempotency_key="idem-fixed", operation_id="op-fixed"
    )

    assert baseline.digest.value != other.digest.value
    assert baseline.fingerprint is not None
    assert baseline.fingerprint in baseline.to_dict().values()


def test_canonical_digest_is_order_independent() -> None:
    left = canonical_lifecycle_digest({"b": 2, "a": 1})
    right = canonical_lifecycle_digest({"a": 1, "b": 2})
    assert left == right
    assert left.algorithm == "sha-256"
    assert len(left.value) == 64


def test_prepare_rotation_binds_old_and_new_key(
    enrollment: EnrollmentRequest,
) -> None:
    request = RotationRequest(**enrollment.__dict__, old_key_id="pk_old")
    operation = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_rotation(
        request, idempotency_key="idem-rotate", operation_id="op-rotate"
    )

    assert operation.operation_type is LifecycleOperationType.ROTATION
    assert operation.old_key_id == "pk_old"
    assert operation.public_key == enrollment.public_key


@pytest.mark.parametrize("submit", ["rotation", "root"])
def test_old_migration_row_without_new_key_id_is_typed_authority_mismatch(
    enrollment: EnrollmentRequest,
    submit: str,
) -> None:
    """Migration-050 legacy rows must not crash in detached authorization."""

    source = PrincipalLifecycle("alpha", clock=MutableClock())
    prepared = source.prepare_rotation(
        RotationRequest(**enrollment.__dict__, old_key_id="pk_old"),
        idempotency_key=f"idem-old-row-{submit}",
    )
    durable = PrincipalLifecycle("alpha", mgr=cast(Any, object()))
    durable._operations[prepared.operation_id] = replace(
        prepared,
        state=LifecycleState.AWAITING_APPROVAL,
        new_key_id=None,
    )

    with pytest.raises(LifecycleContractError) as exc_info:
        if submit == "rotation":
            durable.submit_rotation_authorization(prepared.operation_id, b"x" * 64)
        else:
            durable.submit_root_authorization(prepared.operation_id, [])

    assert exc_info.value.code is LifecycleErrorCode.AUTHORITY_MISMATCH


def test_prepare_revocation_requires_approval_but_not_possession() -> None:
    request = RevocationRequest(
        principal_id="service:deployer",
        principal_kind=PrincipalKind.SERVICE,
        actor_id="entra:tenant:admin-456",
        key_id="pk_compromised",
        reason="Reported compromise",
        requested_authority="registrar",
        policy_version="policy-2026-07",
    )
    operation = PrincipalLifecycle("alpha", clock=MutableClock()).prepare_revocation(
        request, idempotency_key="idem-revoke", operation_id="op-revoke"
    )

    assert operation.operation_type is LifecycleOperationType.REVOCATION
    assert operation.state is LifecycleState.AWAITING_APPROVAL
    assert operation.old_key_id == "pk_compromised"
    assert operation.public_key is None


def test_prepare_rejects_symmetric_scheme(enrollment: EnrollmentRequest) -> None:
    request = EnrollmentRequest(**{**enrollment.__dict__, "scheme": "hmac-sha256"})
    with pytest.raises(LifecycleContractError) as exc_info:
        PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
            request, idempotency_key="idem-symmetric"
        )
    assert exc_info.value.code is LifecycleErrorCode.UNSUPPORTED_SCHEME


def test_prepare_rejects_duplicate_protected_option(enrollment: EnrollmentRequest) -> None:
    request = EnrollmentRequest(
        **{
            **enrollment.__dict__,
            "protected_options": (("ticket", "one"), ("ticket", "two")),
        }
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        PrincipalLifecycle("alpha", clock=MutableClock()).prepare_enrollment(
            request, idempotency_key="idem-duplicate-option"
        )
    assert exc_info.value.code is LifecycleErrorCode.INVALID_REQUEST


def test_valid_possession_is_one_use_and_advances_only_ephemeral_state(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock(), nonce_factory=lambda: "nonce")
    operation = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-proof", operation_id="op-proof"
    )
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    proof = _proof(private_key, operation.digest.value, challenge)

    verified = lifecycle.submit_possession(operation.operation_id, proof)

    assert verified.state is LifecycleState.AWAITING_APPROVAL
    assert lifecycle.challenge_storage_scope is ChallengeStorageScope.PROCESS_LOCAL_FOUNDATION
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.commit(operation.operation_id, expected_digest=operation.digest.value)
    assert exc_info.value.code is LifecycleErrorCode.DURABLE_OPERATION_REQUIRED
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.submit_possession(operation.operation_id, proof)
    assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_ALREADY_USED


def test_invalid_signature_does_not_consume_challenge(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    wrong_key = nacl.signing.SigningKey.generate()
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-invalid")
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    bad_proof = _proof(wrong_key, operation.digest.value, challenge)

    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.submit_possession(operation.operation_id, bad_proof)
    assert exc_info.value.code is LifecycleErrorCode.PROOF_VERIFICATION_FAILED

    verified = lifecycle.submit_possession(
        operation.operation_id, _proof(private_key, operation.digest.value, challenge)
    )
    assert verified.state is LifecycleState.AWAITING_APPROVAL


def test_proof_substitution_fails_closed(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    first = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-one", operation_id="op-one"
    )
    second = lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-two", operation_id="op-two"
    )
    challenge = lifecycle.issue_possession_challenge(first.operation_id)
    proof = _proof(private_key, second.digest.value, challenge)

    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.submit_possession(second.operation_id, proof)
    assert exc_info.value.code is LifecycleErrorCode.PROOF_BINDING_MISMATCH


def test_expired_challenge_fails_closed(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    clock = MutableClock()
    lifecycle = PrincipalLifecycle("alpha", clock=clock)
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-expired")
    challenge = lifecycle.issue_possession_challenge(
        operation.operation_id, ttl=timedelta(seconds=30)
    )
    proof = _proof(private_key, operation.digest.value, challenge)
    clock.value += timedelta(seconds=30)

    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.submit_possession(operation.operation_id, proof)
    assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_EXPIRED


def test_restart_forgets_challenge_and_replay_fails_closed(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    before_restart = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = before_restart.prepare_enrollment(
        enrollment, idempotency_key="idem-restart", operation_id="op-restart"
    )
    challenge = before_restart.issue_possession_challenge(operation.operation_id)
    proof = _proof(private_key, operation.digest.value, challenge)

    after_restart = PrincipalLifecycle("alpha", clock=MutableClock())
    after_restart.prepare_enrollment(
        enrollment, idempotency_key="idem-restart", operation_id="op-restart"
    )
    with pytest.raises(LifecycleContractError) as exc_info:
        after_restart.submit_possession(operation.operation_id, proof)
    assert exc_info.value.code is LifecycleErrorCode.CHALLENGE_NOT_FOUND


def test_operation_id_collision_with_changed_digest_is_rejected(
    enrollment: EnrollmentRequest,
) -> None:
    clock = MutableClock()
    lifecycle = PrincipalLifecycle("alpha", clock=clock)
    lifecycle.prepare_enrollment(
        enrollment, idempotency_key="idem-first", operation_id="op-collision"
    )
    clock.value += timedelta(seconds=1)

    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.prepare_enrollment(
            enrollment, idempotency_key="idem-second", operation_id="op-collision"
        )
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH


def test_idempotency_returns_original_and_rejects_changed_intent(
    enrollment: EnrollmentRequest,
) -> None:
    clock = MutableClock()
    lifecycle = PrincipalLifecycle("alpha", clock=clock)
    original = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-stable")
    clock.value += timedelta(minutes=1)

    repeated = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-stable")
    assert repeated == original

    changed = EnrollmentRequest(**{**enrollment.__dict__, "reason": "Different authority"})
    with pytest.raises(LifecycleContractError) as exc_info:
        lifecycle.prepare_enrollment(changed, idempotency_key="idem-stable")
    assert exc_info.value.code is LifecycleErrorCode.OPERATION_DIGEST_MISMATCH


def test_public_exports_require_no_private_module_imports() -> None:
    expected = (
        regista.PrincipalLifecycle,
        regista.EnrollmentRequest,
        regista.RotationRequest,
        regista.RevocationRequest,
        regista.PossessionChallenge,
        regista.PossessionProof,
        regista.RegistryReceipt,
        regista.EffectiveReceipt,
        regista.PrincipalDescriptor,
        regista.ReconciliationReport,
    )
    assert all(item.__module__ == "regista.principal_lifecycle" for item in expected)


def test_public_serialization_contains_no_private_or_provider_credentials(
    keypair: tuple[nacl.signing.SigningKey, bytes], enrollment: EnrollmentRequest
) -> None:
    private_key, _public_key = keypair
    lifecycle = PrincipalLifecycle("alpha", clock=MutableClock())
    operation = lifecycle.prepare_enrollment(enrollment, idempotency_key="idem-public-only")
    challenge = lifecycle.issue_possession_challenge(operation.operation_id)
    proof = _proof(private_key, operation.digest.value, challenge)
    serialized = json.dumps(
        {
            "operation": operation.to_dict(),
            "challenge": challenge.to_dict(),
            "proof": proof.to_dict(),
        }
    )

    for forbidden in ("private_key", "wrapped_key", "bearer", "provider_credential", "secret"):
        assert forbidden not in serialized.lower()


def test_public_result_shapes_are_json_safe_and_versioned() -> None:
    registry = regista.RegistryReceipt(
        operation_id="op-1",
        operation_digest="digest-1",
        project="alpha",
        principal_id="service:example",
        key_id="pk-1",
        fingerprint="sha256:fingerprint",
        status=regista.RegistryReceiptStatus.COMMITTED,
        recorded_at=NOW,
    )
    effective = regista.EffectiveReceipt(
        operation_id="op-1",
        operation_digest="digest-1",
        project="alpha",
        principal_id="service:example",
        fingerprint="sha256:fingerprint",
        client_type="windows-helper",
        client_version="1.0",
        status=regista.EffectiveReceiptStatus.EFFECTIVE,
        observed_at=NOW,
    )
    descriptor = regista.PrincipalDescriptor(
        principal_id="service:example",
        principal_kind=PrincipalKind.SERVICE,
        project="alpha",
        identity_binding_digest=None,
        active_key_fingerprint="sha256:fingerprint",
        lifecycle_state=LifecycleState.EFFECTIVE,
        policy_version="policy-1",
        required_next_action=None,
    )
    reconciliation = regista.ReconciliationReport(
        principal_id="service:example",
        project="alpha",
        status=regista.ReconciliationStatus.CONSISTENT,
        findings=(),
        observed_at=NOW,
    )
    payload = [
        registry.to_dict(),
        effective.to_dict(),
        descriptor.to_dict(),
        reconciliation.to_dict(),
    ]
    encoded = json.dumps(payload)
    assert encoded.count("regista.principal-lifecycle.v1-draft.2") == 4
