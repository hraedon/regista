"""Public contracts for single-project principal key lifecycle workflows.

This module contains no custody implementation and never accepts private key
material.  Preparing an operation and verifying possession do not mutate the
principal key registry.  A later lifecycle phase will persist and atomically
commit prepared operations through the same public facade.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, assert_never, cast

import psycopg

from ._connection import ConnectionManager
from ._contract import (
    Jsonb as _Jsonb,
)
from ._contract import (
    check_reserved_transition as _check_reserved_transition,
)
from ._contract import (
    validate_entity_kind as _validate_entity_kind,
)
from ._contract import (
    validate_mutation_params as _validate_mutation_params,
)
from ._event_store import PostgresEventStore as _PostgresEventStore
from ._event_store import append_event as _store_append_event
from ._jcs import canonicalize
from ._keys import KeySet
from ._observability import Metrics
from ._principal_keys import (
    PrincipalKeyEntry,
)
from ._principal_keys import (
    list_principal_keys_for_conn as _list_principal_keys_for_conn,
)
from ._principal_keys import (
    principal_entity_id as _principal_entity_id,
)
from ._principal_keys import (
    register_principal_key_conn as _register_principal_key_conn,
)
from ._principal_keys import (
    revoke_principal_key_conn as _revoke_principal_key_conn,
)
from ._principal_keys import (
    rotate_principal_key_conn as _rotate_principal_key_conn,
)
from ._signing_scheme import asymmetric_scheme_ids, get_scheme

CONTRACT_VERSION: Final[str] = "regista.principal-lifecycle.v1-draft.1"
POSSESSION_DOMAIN: Final[str] = "regista.principal-possession.v1"
EFFECTIVE_DOMAIN: Final[str] = "regista.principal-effective.v1"


class PrincipalKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    BREAK_GLASS = "break_glass"


class LifecycleOperationType(StrEnum):
    ENROLLMENT = "enrollment"
    ROTATION = "rotation"
    REVOCATION = "revocation"


class LifecycleState(StrEnum):
    DRAFT = "draft"
    PREPARED = "prepared"
    AWAITING_PROOF = "awaiting_proof"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    COMMITTING = "committing"
    COMMITTED = "committed"
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    REPAIR_REQUIRED = "repair_required"
    SUPERSEDED = "superseded"


class CustodyMode(StrEnum):
    REMOTE_ORGANIZATIONAL = "remote_organizational"
    WINDOWS_LOCAL = "windows_local"
    FILE = "file"


class ChallengeStorageScope(StrEnum):
    PROCESS_LOCAL_FOUNDATION = "process_local_foundation"


class ProofFormat(StrEnum):
    SIGNATURE_V1 = "signature_v1"


class RegistryReceiptStatus(StrEnum):
    COMMITTED = "committed"
    REJECTED = "rejected"


class EffectiveReceiptStatus(StrEnum):
    EFFECTIVE = "effective"
    COMMITTED_NOT_EFFECTIVE = "committed_not_effective"
    REJECTED = "rejected"


class ReconciliationStatus(StrEnum):
    CONSISTENT = "consistent"
    DRIFTED = "drifted"
    UNAVAILABLE = "unavailable"


class LifecycleErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    OPERATION_NOT_FOUND = "operation_not_found"
    OPERATION_DIGEST_MISMATCH = "operation_digest_mismatch"
    CHALLENGE_NOT_FOUND = "challenge_not_found"
    CHALLENGE_EXPIRED = "challenge_expired"
    CHALLENGE_ALREADY_USED = "challenge_already_used"
    PROOF_BINDING_MISMATCH = "proof_binding_mismatch"
    PROOF_VERIFICATION_FAILED = "proof_verification_failed"
    INVALID_OPERATION_STATE = "invalid_operation_state"
    DURABLE_OPERATION_REQUIRED = "durable_operation_required"
    OPERATION_EXPIRED = "operation_expired"
    APPROVAL_DIGEST_MISMATCH = "approval_digest_mismatch"
    OPERATION_ALREADY_COMMITTED = "operation_already_committed"


class LifecycleContractError(Exception):
    """A fail-closed lifecycle contract validation error."""

    def __init__(self, code: LifecycleErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True)
class LifecycleDigest:
    version: str
    algorithm: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"version": self.version, "algorithm": self.algorithm, "value": self.value}


@dataclass(frozen=True)
class EnrollmentRequest:
    principal_id: str
    principal_kind: PrincipalKind
    actor_id: str
    public_key: bytes
    scheme: str
    custody_mode: CustodyMode
    reason: str
    requested_authority: str
    policy_version: str
    identity_binding_digest: str | None = None
    protected_options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RotationRequest(EnrollmentRequest):
    old_key_id: str = ""


@dataclass(frozen=True)
class RevocationRequest:
    principal_id: str
    principal_kind: PrincipalKind
    actor_id: str
    key_id: str
    reason: str
    requested_authority: str
    policy_version: str
    identity_binding_digest: str | None = None
    protected_options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Approval:
    approver_id: str
    approver_kind: str
    approval_digest: str
    step_up_evidence: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class LifecycleOperation:
    operation_id: str
    idempotency_key: str
    operation_type: LifecycleOperationType
    state: LifecycleState
    project: str
    principal_id: str
    principal_kind: PrincipalKind
    actor_id: str
    reason: str
    requested_authority: str
    policy_version: str
    created_at: datetime
    expires_at: datetime
    digest: LifecycleDigest
    public_key: bytes | None = None
    fingerprint: str | None = None
    scheme: str | None = None
    custody_mode: CustodyMode | None = None
    old_key_id: str | None = None
    identity_binding_digest: str | None = None
    protected_options: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "operation_id": self.operation_id,
            "idempotency_key": self.idempotency_key,
            "operation_type": self.operation_type.value,
            "state": self.state.value,
            "project": self.project,
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind.value,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "requested_authority": self.requested_authority,
            "policy_version": self.policy_version,
            "created_at": _format_time(self.created_at),
            "expires_at": _format_time(self.expires_at),
            "digest": self.digest.to_dict(),
            "public_key": _encode(self.public_key) if self.public_key is not None else None,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "custody_mode": self.custody_mode.value if self.custody_mode else None,
            "old_key_id": self.old_key_id,
            "identity_binding_digest": self.identity_binding_digest,
            "protected_options": dict(self.protected_options),
        }


@dataclass(frozen=True)
class PossessionChallenge:
    challenge_id: str
    operation_id: str
    operation_digest: str
    project: str
    principal_id: str
    fingerprint: str
    scheme: str
    verifier_nonce: str
    issued_at: datetime
    expires_at: datetime

    def signing_bytes(self) -> bytes:
        return canonicalize(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": POSSESSION_DOMAIN,
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "verifier_nonce": self.verifier_nonce,
            "issued_at": _format_time(self.issued_at),
            "expires_at": _format_time(self.expires_at),
        }


@dataclass(frozen=True)
class PossessionProof:
    format: ProofFormat
    challenge_id: str
    operation_id: str
    operation_digest: str
    signature: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "format": self.format.value,
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "signature": _encode(self.signature),
        }


@dataclass(frozen=True)
class EffectiveChallenge:
    """Post-commit challenge proving the client can use the committed key."""

    challenge_id: str
    operation_id: str
    operation_digest: str
    project: str
    principal_id: str
    fingerprint: str
    scheme: str
    verifier_nonce: str
    issued_at: datetime
    expires_at: datetime

    def signing_bytes(self) -> bytes:
        return canonicalize(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": EFFECTIVE_DOMAIN,
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "verifier_nonce": self.verifier_nonce,
            "issued_at": _format_time(self.issued_at),
            "expires_at": _format_time(self.expires_at),
        }


@dataclass(frozen=True)
class RegistryReceipt:
    operation_id: str
    operation_digest: str
    project: str
    principal_id: str
    key_id: str
    fingerprint: str
    status: RegistryReceiptStatus
    recorded_at: datetime

    def to_dict(self) -> dict[str, str]:
        return {
            "contract_version": CONTRACT_VERSION,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "status": self.status.value,
            "recorded_at": _format_time(self.recorded_at),
        }


@dataclass(frozen=True)
class EffectiveReceipt:
    operation_id: str
    operation_digest: str
    project: str
    principal_id: str
    fingerprint: str
    client_type: str
    client_version: str
    status: EffectiveReceiptStatus
    observed_at: datetime
    challenge_id: str | None = None
    signature: bytes | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "contract_version": CONTRACT_VERSION,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "client_type": self.client_type,
            "client_version": self.client_version,
            "status": self.status.value,
            "observed_at": _format_time(self.observed_at),
            "challenge_id": self.challenge_id,
            "signature": _encode(self.signature) if self.signature is not None else None,
        }


@dataclass(frozen=True)
class PrincipalDescriptor:
    principal_id: str
    principal_kind: PrincipalKind
    project: str
    identity_binding_digest: str | None
    active_key_fingerprint: str | None
    lifecycle_state: LifecycleState
    policy_version: str
    required_next_action: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "contract_version": CONTRACT_VERSION,
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind.value,
            "project": self.project,
            "identity_binding_digest": self.identity_binding_digest,
            "active_key_fingerprint": self.active_key_fingerprint,
            "lifecycle_state": self.lifecycle_state.value,
            "policy_version": self.policy_version,
            "required_next_action": self.required_next_action,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    principal_id: str
    project: str
    status: ReconciliationStatus
    findings: tuple[str, ...]
    observed_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "principal_id": self.principal_id,
            "project": self.project,
            "status": self.status.value,
            "findings": list(self.findings),
            "observed_at": _format_time(self.observed_at),
        }


@dataclass
class _ChallengeRecord:
    challenge: PossessionChallenge | EffectiveChallenge
    used: bool = False


class PrincipalLifecycle:
    """Prepare and verify public lifecycle operations for one project.

    When a ``ConnectionManager`` is supplied the class persists operations,
    challenges, approvals, and receipts to the database and can atomically
    commit registry changes.  Without one it operates as a process-local
    contract foundation: prepare and verify work, but commit is unavailable.
    """

    def __init__(
        self,
        project: str,
        *,
        mgr: ConnectionManager | None = None,
        keys: KeySet | None = None,
        metrics: Metrics | None = None,
        clock: Callable[[], datetime] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_text("project", project)
        self._project = project
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._durable = mgr is not None
        self._clock = clock or (lambda: datetime.now(UTC))
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(32))
        self._operations: dict[str, LifecycleOperation] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._challenges: dict[str, _ChallengeRecord] = {}
        self._receipts: dict[str, RegistryReceipt] = {}

    @property
    def challenge_storage_scope(self) -> ChallengeStorageScope:
        """Identify the verifier's storage scope."""

        return ChallengeStorageScope.PROCESS_LOCAL_FOUNDATION

    @property
    def is_durable(self) -> bool:
        """Whether this instance persists to a database backend."""

        return self._durable

    def prepare_enrollment(
        self,
        request: EnrollmentRequest,
        *,
        idempotency_key: str,
        operation_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
    ) -> LifecycleOperation:
        return self._prepare_key_operation(
            LifecycleOperationType.ENROLLMENT,
            request,
            idempotency_key=idempotency_key,
            operation_id=operation_id,
            ttl=ttl,
        )

    def prepare_rotation(
        self,
        request: RotationRequest,
        *,
        idempotency_key: str,
        operation_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
    ) -> LifecycleOperation:
        _require_text("old_key_id", request.old_key_id)
        return self._prepare_key_operation(
            LifecycleOperationType.ROTATION,
            request,
            idempotency_key=idempotency_key,
            operation_id=operation_id,
            ttl=ttl,
        )

    def prepare_revocation(
        self,
        request: RevocationRequest,
        *,
        idempotency_key: str,
        operation_id: str | None = None,
        ttl: timedelta = timedelta(minutes=10),
    ) -> LifecycleOperation:
        _validate_common(request)
        _require_text("key_id", request.key_id)
        _require_text("idempotency_key", idempotency_key)
        protected = _protected_options(request.protected_options)
        intent = _intent_digest(
            LifecycleOperationType.REVOCATION,
            self._project,
            request,
            old_key_id=request.key_id,
            protected_options=protected,
        )
        existing = self._existing_idempotent(idempotency_key, intent)
        if existing is not None:
            return existing
        created_at, expires_at = self._time_window(ttl)
        op_id = operation_id or str(uuid.uuid4())
        fields = _digest_fields(
            operation_id=op_id,
            idempotency_key=idempotency_key,
            operation_type=LifecycleOperationType.REVOCATION,
            project=self._project,
            request=request,
            created_at=created_at,
            expires_at=expires_at,
            old_key_id=request.key_id,
            public_key=None,
            scheme=None,
            custody_mode=None,
            protected_options=protected,
        )
        operation = LifecycleOperation(
            operation_id=op_id,
            idempotency_key=idempotency_key,
            operation_type=LifecycleOperationType.REVOCATION,
            state=LifecycleState.AWAITING_APPROVAL,
            project=self._project,
            principal_id=request.principal_id,
            principal_kind=request.principal_kind,
            actor_id=request.actor_id,
            reason=request.reason,
            requested_authority=request.requested_authority,
            policy_version=request.policy_version,
            created_at=created_at,
            expires_at=expires_at,
            digest=canonical_lifecycle_digest(fields),
            old_key_id=request.key_id,
            identity_binding_digest=request.identity_binding_digest,
            protected_options=protected,
        )
        return self._remember(operation, intent)

    def issue_possession_challenge(
        self,
        operation_id: str,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> PossessionChallenge:
        operation = self._operation(operation_id)
        if operation.state is not LifecycleState.AWAITING_PROOF:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting proof",
            )
        if (
            operation.public_key is None
            or operation.fingerprint is None
            or operation.scheme is None
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST, "Possession operation has no public key"
            )
        issued_at, expires_at = self._time_window(ttl)
        if expires_at > operation.expires_at:
            expires_at = operation.expires_at
        challenge = PossessionChallenge(
            challenge_id=str(uuid.uuid4()),
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=operation.fingerprint,
            scheme=operation.scheme,
            verifier_nonce=self._nonce_factory(),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self._challenges[challenge.challenge_id] = _ChallengeRecord(challenge)
        if self._durable:
            self._persist_challenge(challenge)
        return challenge

    def submit_possession(self, operation_id: str, proof: PossessionProof) -> LifecycleOperation:
        operation = self._operation(operation_id)
        record = self._challenges.get(proof.challenge_id)
        if record is None:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                f"Challenge {proof.challenge_id!r} was not issued by this verifier",
            )
        if record.used:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                f"Challenge {proof.challenge_id!r} has already been used",
            )
        challenge = record.challenge
        if self._now() >= challenge.expires_at:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_EXPIRED,
                f"Challenge {proof.challenge_id!r} has expired",
            )
        if (
            proof.format is not ProofFormat.SIGNATURE_V1
            or proof.operation_id != operation_id
            or challenge.operation_id != operation_id
            or not hmac.compare_digest(proof.operation_digest, operation.digest.value)
            or not hmac.compare_digest(challenge.operation_digest, operation.digest.value)
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Proof does not match the prepared operation and digest",
            )
        if operation.state is not LifecycleState.AWAITING_PROOF or operation.public_key is None:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting proof",
            )
        scheme = get_scheme(challenge.scheme)
        envelope = challenge.signing_bytes()
        envelope_hash = hashlib.sha256(envelope).digest()
        if not scheme.verify(envelope, proof.signature, envelope_hash, operation.public_key):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_VERIFICATION_FAILED,
                "Possession signature verification failed",
            )
        record.used = True
        # Challenges are process-local and one-use; marking happens inline in
        # the same transaction as the state update, not via a separate helper.
        verified = replace(operation, state=LifecycleState.AWAITING_APPROVAL)
        self._operations[operation_id] = verified
        if self._durable:
            assert self._mgr is not None
            with self._mgr.transaction() as conn:
                conn.execute(
                    "UPDATE lifecycle_challenges SET used = true WHERE challenge_id = %s",
                    [proof.challenge_id],
                )
                conn.execute(
                    "UPDATE lifecycle_operations SET state = 'awaiting_approval' "
                    "WHERE operation_id = %s",
                    [operation_id],
                )
        return verified

    def get_operation(self, operation_id: str) -> LifecycleOperation:
        return self._operation(operation_id)

    def record_approval(self, operation_id: str, approval: Approval) -> LifecycleOperation:
        self._require_durable("record_approval")
        operation = self._operation(operation_id)
        if self._now() >= operation.expires_at:
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_EXPIRED,
                f"Operation {operation_id!r} has expired",
            )
        if operation.state is not LifecycleState.AWAITING_APPROVAL:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting approval",
            )
        if not hmac.compare_digest(approval.approval_digest, operation.digest.value):
            raise LifecycleContractError(
                LifecycleErrorCode.APPROVAL_DIGEST_MISMATCH,
                "Approval digest does not match the operation digest",
            )
        approval_id = str(uuid.uuid4())
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            conn.execute(
                """
                INSERT INTO lifecycle_approvals
                    (approval_id, operation_id, operation_digest,
                     approver_id, approver_kind, approval_digest,
                     step_up_evidence, reason, approved_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    approval_id,
                    operation_id,
                    operation.digest.value,
                    approval.approver_id,
                    approval.approver_kind,
                    approval.approval_digest,
                    approval.step_up_evidence,
                    approval.reason,
                    self._now(),
                ],
            )
            conn.execute(
                "UPDATE lifecycle_operations SET state = 'approved' WHERE operation_id = %s",
                [operation_id],
            )
        verified = replace(operation, state=LifecycleState.APPROVED)
        self._operations[operation_id] = verified
        return verified

    def commit(self, operation_id: str, *, expected_digest: str) -> RegistryReceipt:
        self._require_durable("commit")
        operation = self._operation(operation_id)
        if not hmac.compare_digest(operation.digest.value, expected_digest):
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                "expected_digest does not match the operation digest",
            )
        if self._now() >= operation.expires_at:
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_EXPIRED,
                f"Operation {operation_id!r} has expired",
            )
        assert self._mgr is not None
        assert self._keys is not None
        transition = self._transition_for(operation.operation_type)
        entity_id = _principal_entity_id(operation.principal_id)
        event_id = uuid.uuid4()
        payload: dict[str, Any] = {
            "operation_id": operation.operation_id,
            "principal_id": operation.principal_id,
            "principal_kind": operation.principal_kind.value,
            "actor_id": operation.actor_id,
            "reason": operation.reason,
            "policy_version": operation.policy_version,
        }
        if operation.fingerprint is not None:
            payload["fingerprint"] = operation.fingerprint
        if operation.scheme is not None:
            payload["scheme"] = operation.scheme
        if operation.old_key_id is not None:
            payload["old_key_id"] = operation.old_key_id
        with self._mgr.transaction() as conn:
            existing_row = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT state, receipt_key_id, committed_at FROM lifecycle_operations "
                    "WHERE operation_id = %s FOR UPDATE",
                    [operation_id],
                ).fetchone(),
            )
            if existing_row is not None and existing_row["state"] == "committed":
                key_id = existing_row["receipt_key_id"] or ""
                recorded_at = existing_row["committed_at"] or self._now()
                receipt = RegistryReceipt(
                    operation_id=operation_id,
                    operation_digest=operation.digest.value,
                    project=operation.project,
                    principal_id=operation.principal_id,
                    key_id=key_id,
                    fingerprint=operation.fingerprint or "",
                    status=RegistryReceiptStatus.COMMITTED,
                    recorded_at=recorded_at,
                )
                self._receipts[operation_id] = receipt
                return receipt
            if operation.state is not LifecycleState.APPROVED:
                raise LifecycleContractError(
                    LifecycleErrorCode.INVALID_OPERATION_STATE,
                    f"Operation {operation_id!r} is not approved",
                )
            entry = self._commit_key(conn, operation)
            _validate_entity_kind("principal")
            _validate_mutation_params(
                actor_id=operation.actor_id,
                actor_kind="system",
                event_id=event_id,
            )
            _check_reserved_transition(transition)
            store = _PostgresEventStore(conn, self._keys)
            _store_append_event(
                store,
                work_item_id=entity_id,
                actor_id=operation.actor_id,
                actor_kind="system",
                actor_metadata=None,
                workflow_name="",
                workflow_version=0,
                transition=transition,
                payload=_Jsonb(payload),
                event_id=event_id,
                key_set=self._keys,
                entity_kind="principal",
            )
            now = self._now()
            conn.execute(
                "UPDATE lifecycle_operations SET state = 'committed', "
                "committed_at = %s, receipt_key_id = %s "
                "WHERE operation_id = %s",
                [now, entry.key_id, operation_id],
            )
            if self._metrics is not None:
                self._metrics.inc("events_appended", self._project)
        receipt = RegistryReceipt(
            operation_id=operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            key_id=entry.key_id,
            fingerprint=entry.fingerprint,
            status=RegistryReceiptStatus.COMMITTED,
            recorded_at=now,
        )
        committed = replace(operation, state=LifecycleState.COMMITTED)
        self._operations[operation_id] = committed
        self._receipts[operation_id] = receipt
        return receipt

    def issue_effective_challenge(
        self,
        operation_id: str,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> EffectiveChallenge:
        """Issue a post-commit challenge for effective-use proof.

        The client signs this challenge with the newly committed key to prove
        it can actually use the key. Without a valid effective receipt the
        operation stays ``committed_not_effective``.
        """
        operation = self._operation(operation_id)
        if operation.state is not LifecycleState.COMMITTED:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not committed",
            )
        if (
            operation.public_key is None
            or operation.fingerprint is None
            or operation.scheme is None
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "Committed operation has no public key",
            )
        issued_at, expires_at = self._time_window(ttl)
        if expires_at > operation.expires_at:
            expires_at = operation.expires_at
        challenge = EffectiveChallenge(
            challenge_id=str(uuid.uuid4()),
            operation_id=operation.operation_id,
            operation_digest=operation.digest.value,
            project=operation.project,
            principal_id=operation.principal_id,
            fingerprint=operation.fingerprint,
            scheme=operation.scheme,
            verifier_nonce=self._nonce_factory(),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self._challenges[challenge.challenge_id] = _ChallengeRecord(challenge)
        if self._durable:
            self._persist_challenge(challenge)
        return challenge

    def record_effective_receipt(
        self, operation_id: str, receipt: EffectiveReceipt
    ) -> LifecycleOperation:
        self._require_durable("record_effective_receipt")
        operation = self._operation(operation_id)
        if operation.state is not LifecycleState.COMMITTED:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not committed",
            )
        if not hmac.compare_digest(receipt.operation_digest, operation.digest.value):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Receipt operation_digest does not match the operation",
            )
        if receipt.principal_id != operation.principal_id:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Receipt principal_id does not match the operation",
            )
        if receipt.fingerprint != operation.fingerprint:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Receipt fingerprint does not match the committed key",
            )
        if receipt.project != operation.project:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Receipt project does not match the operation",
            )
        if receipt.status is EffectiveReceiptStatus.EFFECTIVE:
            if receipt.challenge_id is None or receipt.signature is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                    "An EFFECTIVE receipt requires a challenge_id and signature",
                )
        # A challenge is consumed only when a signed receipt actually verifies
        # against it. A receipt that carries a challenge_id without a signature
        # is treated as an unsigned report: it must not burn the challenge —
        # otherwise a proof-less receipt could DoS the real client's later
        # effective-use proof (in-memory and durable marks must agree).
        challenge_consumed = False
        if receipt.challenge_id is not None and receipt.signature is not None:
            record = self._challenges.get(receipt.challenge_id)
            if record is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                    f"Challenge {receipt.challenge_id!r} was not issued",
                )
            if record.used:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                    f"Challenge {receipt.challenge_id!r} has already been used",
                )
            challenge = record.challenge
            if self._now() >= challenge.expires_at:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_EXPIRED,
                    f"Challenge {receipt.challenge_id!r} has expired",
                )
            if not isinstance(challenge, EffectiveChallenge):
                raise LifecycleContractError(
                    LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                    "Challenge is not an effective-use challenge",
                )
            if not hmac.compare_digest(challenge.operation_digest, operation.digest.value):
                raise LifecycleContractError(
                    LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                    "Challenge does not bind to this operation",
                )
            scheme = get_scheme(challenge.scheme)
            envelope = challenge.signing_bytes()
            envelope_hash = hashlib.sha256(envelope).digest()
            if operation.public_key is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.INVALID_REQUEST,
                    "Committed operation has no public key",
                )
            if not scheme.verify(envelope, receipt.signature, envelope_hash, operation.public_key):
                raise LifecycleContractError(
                    LifecycleErrorCode.PROOF_VERIFICATION_FAILED,
                    "Effective-use signature verification failed",
                )
            record.used = True
            challenge_consumed = True
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            if challenge_consumed:
                conn.execute(
                    "UPDATE lifecycle_challenges SET used = true WHERE challenge_id = %s",
                    [receipt.challenge_id],
                )
            conn.execute(
                """
                INSERT INTO lifecycle_effective_receipts
                    (operation_id, operation_digest, project, principal_id,
                     fingerprint, client_type, client_version, status, observed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (operation_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    observed_at = EXCLUDED.observed_at
                """,
                [
                    receipt.operation_id,
                    receipt.operation_digest,
                    receipt.project,
                    receipt.principal_id,
                    receipt.fingerprint,
                    receipt.client_type,
                    receipt.client_version,
                    receipt.status.value,
                    receipt.observed_at,
                ],
            )
            if receipt.status is EffectiveReceiptStatus.EFFECTIVE:
                new_state = LifecycleState.EFFECTIVE
            elif receipt.status is EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE:
                new_state = LifecycleState.PARTIALLY_EFFECTIVE
            elif receipt.status is EffectiveReceiptStatus.REJECTED:
                new_state = LifecycleState.FAILED
            else:
                assert_never(receipt.status)
            conn.execute(
                "UPDATE lifecycle_operations SET state = %s WHERE operation_id = %s",
                [new_state.value, operation_id],
            )
        verified = replace(operation, state=new_state)
        self._operations[operation_id] = verified
        return verified

    def describe(self, principal_id: str) -> PrincipalDescriptor:
        if not self._durable:
            return PrincipalDescriptor(
                principal_id=principal_id,
                principal_kind=PrincipalKind.SERVICE,
                project=self._project,
                identity_binding_digest=None,
                active_key_fingerprint=None,
                lifecycle_state=LifecycleState.DRAFT,
                policy_version="",
                required_next_action="prepare_enrollment",
            )
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            keys = _list_principal_keys_for_conn(conn, principal_id, status="active")
            op_row = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT * FROM lifecycle_operations "
                    "WHERE principal_id = %s "
                    "ORDER BY created_at DESC LIMIT 1",
                    [principal_id],
                ).fetchone(),
            )
        active_fp: str | None = None
        principal_kind = PrincipalKind.SERVICE
        policy_version = ""
        identity_binding_digest: str | None = None
        if keys:
            active_fp = keys[0].fingerprint
        if op_row is not None:
            principal_kind = PrincipalKind(op_row["principal_kind"])
            policy_version = op_row["policy_version"]
            identity_binding_digest = op_row["identity_binding_digest"]
        latest_op_type: LifecycleOperationType | None = None
        if op_row is None:
            lifecycle_state = LifecycleState.DRAFT
            required_next_action = "prepare_enrollment" if active_fp is None else None
        else:
            lifecycle_state = LifecycleState(op_row["state"])
            latest_op_type = LifecycleOperationType(op_row["operation_type"])
            required_next_action = None
            if lifecycle_state is LifecycleState.AWAITING_PROOF:
                required_next_action = "issue_possession_challenge"
            elif lifecycle_state is LifecycleState.AWAITING_APPROVAL:
                required_next_action = "record_approval"
            elif lifecycle_state is LifecycleState.APPROVED:
                required_next_action = "commit"
            elif lifecycle_state is LifecycleState.COMMITTED:
                if latest_op_type is LifecycleOperationType.REVOCATION:
                    required_next_action = None
                else:
                    required_next_action = "record_effective_receipt"
            elif lifecycle_state is LifecycleState.DRAFT:
                required_next_action = None
            elif lifecycle_state is LifecycleState.EFFECTIVE:
                required_next_action = None
            elif lifecycle_state is LifecycleState.PARTIALLY_EFFECTIVE:
                required_next_action = None
            elif lifecycle_state is LifecycleState.FAILED:
                required_next_action = None
            elif lifecycle_state is LifecycleState.CANCELLED:
                required_next_action = None
            elif lifecycle_state is LifecycleState.EXPIRED:
                required_next_action = None
            elif lifecycle_state is LifecycleState.PREPARED:
                required_next_action = None
            elif lifecycle_state is LifecycleState.COMMITTING:
                required_next_action = None
            elif lifecycle_state is LifecycleState.REPAIR_REQUIRED:
                required_next_action = None
            elif lifecycle_state is LifecycleState.SUPERSEDED:
                required_next_action = None
            else:
                assert_never(lifecycle_state)
        return PrincipalDescriptor(
            principal_id=principal_id,
            principal_kind=principal_kind,
            project=self._project,
            identity_binding_digest=identity_binding_digest,
            active_key_fingerprint=active_fp,
            lifecycle_state=lifecycle_state,
            policy_version=policy_version,
            required_next_action=required_next_action,
        )

    def reconcile(self, principal_id: str) -> ReconciliationReport:
        self._require_durable("reconcile")
        assert self._mgr is not None
        findings: list[str] = []
        with self._mgr.transaction() as conn:
            keys = _list_principal_keys_for_conn(conn, principal_id)
            active_keys = [k for k in keys if k.status == "active"]
            op_row = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT * FROM lifecycle_operations "
                    "WHERE principal_id = %s AND state = 'committed' "
                    "ORDER BY created_at DESC LIMIT 1",
                    [principal_id],
                ).fetchone(),
            )
            receipt_row = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT * FROM lifecycle_effective_receipts "
                    "WHERE principal_id = %s ORDER BY observed_at DESC LIMIT 1",
                    [principal_id],
                ).fetchone(),
            )
        if len(active_keys) > 1:
            findings.append("multiple_active_keys")
        if not active_keys and op_row is not None:
            findings.append("committed_operation_without_active_key")
        if op_row is not None and receipt_row is None:
            findings.append("missing_effective_receipt")
        if (
            op_row is not None
            and receipt_row is not None
            and receipt_row["status"] == "committed_not_effective"
        ):
            findings.append("stale_effective_receipt")
        if not active_keys and op_row is None:
            findings.append("no_lifecycle_history")
        status = ReconciliationStatus.CONSISTENT if not findings else ReconciliationStatus.DRIFTED
        return ReconciliationReport(
            principal_id=principal_id,
            project=self._project,
            status=status,
            findings=tuple(findings),
            observed_at=self._now(),
        )

    def cancel(self, operation_id: str, *, expected_digest: str) -> LifecycleOperation:
        operation = self._operation(operation_id)
        if not hmac.compare_digest(operation.digest.value, expected_digest):
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                "expected_digest does not match the operation digest",
            )
        if operation.state in (
            LifecycleState.COMMITTED,
            LifecycleState.CANCELLED,
            LifecycleState.EFFECTIVE,
            LifecycleState.PARTIALLY_EFFECTIVE,
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is in a non-cancellable state: "
                f"{operation.state.value}",
            )
        if self._durable:
            assert self._mgr is not None
            with self._mgr.transaction() as conn:
                result = conn.execute(
                    "UPDATE lifecycle_operations SET state = 'cancelled' "
                    "WHERE operation_id = %s AND state NOT IN "
                    "('committed', 'cancelled', 'effective', 'partially_effective', 'failed')",
                    [operation_id],
                )
                if result.rowcount == 0:
                    raise LifecycleContractError(
                        LifecycleErrorCode.INVALID_OPERATION_STATE,
                        f"Operation {operation_id!r} cannot be cancelled (state may have changed)",
                    )
        cancelled = replace(operation, state=LifecycleState.CANCELLED)
        self._operations[operation_id] = cancelled
        return cancelled

    def _require_durable(self, method_name: str) -> None:
        if not self._durable:
            raise LifecycleContractError(
                LifecycleErrorCode.DURABLE_OPERATION_REQUIRED,
                f"{method_name} requires a durable backend (ConnectionManager)",
            )

    def _transition_for(self, op_type: LifecycleOperationType) -> str:
        if op_type is LifecycleOperationType.ENROLLMENT:
            return "principal_enrolled"
        if op_type is LifecycleOperationType.ROTATION:
            return "principal_rotated"
        if op_type is LifecycleOperationType.REVOCATION:
            return "principal_revoked"
        assert_never(op_type)

    def _commit_key(
        self, conn: psycopg.Connection, operation: LifecycleOperation
    ) -> PrincipalKeyEntry:
        if operation.operation_type is LifecycleOperationType.ENROLLMENT:
            assert operation.public_key is not None
            assert operation.scheme is not None
            return _register_principal_key_conn(
                conn,
                operation.principal_id,
                operation.public_key,
                operation.scheme,
                registered_by=operation.actor_id,
            )
        if operation.operation_type is LifecycleOperationType.ROTATION:
            assert operation.public_key is not None
            assert operation.scheme is not None
            return _rotate_principal_key_conn(
                conn,
                operation.principal_id,
                operation.public_key,
                operation.scheme,
                registered_by=operation.actor_id,
            )
        if operation.operation_type is LifecycleOperationType.REVOCATION:
            assert operation.old_key_id is not None
            return _revoke_principal_key_conn(
                conn,
                operation.principal_id,
                operation.old_key_id,
                reason=operation.reason,
            )
        assert_never(operation.operation_type)

    def _persist_operation(self, operation: LifecycleOperation, intent: str) -> None:
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            existing = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT operation_id, digest_value FROM lifecycle_operations "
                    "WHERE idempotency_key = %s",
                    [operation.idempotency_key],
                ).fetchone(),
            )
            if existing is not None:
                if existing["digest_value"] != operation.digest.value:
                    raise LifecycleContractError(
                        LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                        f"Idempotency key {operation.idempotency_key!r} "
                        "is bound to another request",
                    )
                return
            conn.execute(
                """
                INSERT INTO lifecycle_operations
                    (operation_id, idempotency_key, operation_type, state,
                     project, principal_id, principal_kind, actor_id,
                     reason, requested_authority, policy_version,
                     digest_value, digest_algorithm, digest_version,
                     public_key, fingerprint, scheme, custody_mode, old_key_id,
                     identity_binding_digest, protected_options,
                     created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    operation.operation_id,
                    operation.idempotency_key,
                    operation.operation_type.value,
                    operation.state.value,
                    operation.project,
                    operation.principal_id,
                    operation.principal_kind.value,
                    operation.actor_id,
                    operation.reason,
                    operation.requested_authority,
                    operation.policy_version,
                    operation.digest.value,
                    operation.digest.algorithm,
                    operation.digest.version,
                    operation.public_key,
                    operation.fingerprint,
                    operation.scheme,
                    operation.custody_mode.value if operation.custody_mode else None,
                    operation.old_key_id,
                    operation.identity_binding_digest,
                    psycopg.types.json.Jsonb(dict(operation.protected_options)),
                    operation.created_at,
                    operation.expires_at,
                ],
            )

    def _load_operation_from_db(self, operation_id: str) -> LifecycleOperation:
        """Rehydrate an operation from durable storage.

        Operations are durable and may be resumed by a fresh ``PrincipalLifecycle``
        instance.  Challenges are deliberately process-local and one-use, so this
        method does not rehydrate challenges.
        """
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            row = cast(
                dict[str, Any] | None,
                conn.execute(
                    "SELECT * FROM lifecycle_operations WHERE operation_id = %s AND project = %s",
                    [operation_id, self._project],
                ).fetchone(),
            )
        if row is None:
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_NOT_FOUND,
                f"Lifecycle operation {operation_id!r} was not prepared",
            )
        protected = row["protected_options"]
        if isinstance(protected, dict):
            protected_options = tuple(sorted((str(k), str(v)) for k, v in protected.items()))
        else:
            protected_options = ()
        custody_mode = row["custody_mode"]
        public_key = row["public_key"]
        operation = LifecycleOperation(
            operation_id=str(row["operation_id"]),
            idempotency_key=row["idempotency_key"],
            operation_type=LifecycleOperationType(row["operation_type"]),
            state=LifecycleState(row["state"]),
            project=row["project"],
            principal_id=row["principal_id"],
            principal_kind=PrincipalKind(row["principal_kind"]),
            actor_id=row["actor_id"],
            reason=row["reason"],
            requested_authority=row["requested_authority"],
            policy_version=row["policy_version"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            digest=LifecycleDigest(
                version=row["digest_version"],
                algorithm=row["digest_algorithm"],
                value=row["digest_value"],
            ),
            public_key=bytes(public_key) if public_key is not None else None,
            fingerprint=row["fingerprint"],
            scheme=row["scheme"],
            custody_mode=CustodyMode(custody_mode) if custody_mode is not None else None,
            old_key_id=row["old_key_id"],
            identity_binding_digest=row["identity_binding_digest"],
            protected_options=protected_options,
        )
        self._operations[operation_id] = operation
        return operation

    def _persist_challenge(
        self,
        challenge: PossessionChallenge | EffectiveChallenge,
    ) -> None:
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            conn.execute(
                """
                INSERT INTO lifecycle_challenges
                    (challenge_id, operation_id, operation_digest,
                     project, principal_id, fingerprint, scheme,
                     verifier_nonce, issued_at, expires_at, used)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, false)
                """,
                [
                    challenge.challenge_id,
                    challenge.operation_id,
                    challenge.operation_digest,
                    challenge.project,
                    challenge.principal_id,
                    challenge.fingerprint,
                    challenge.scheme,
                    challenge.verifier_nonce,
                    challenge.issued_at,
                    challenge.expires_at,
                ],
            )

    def _update_operation_state(self, operation_id: str, state: LifecycleState) -> None:
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            conn.execute(
                "UPDATE lifecycle_operations SET state = %s WHERE operation_id = %s",
                [state.value, operation_id],
            )

    def _prepare_key_operation(
        self,
        operation_type: LifecycleOperationType,
        request: EnrollmentRequest,
        *,
        idempotency_key: str,
        operation_id: str | None,
        ttl: timedelta,
    ) -> LifecycleOperation:
        _validate_common(request)
        _require_text("idempotency_key", idempotency_key)
        if not request.public_key:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST, "public_key is required"
            )
        if request.scheme not in asymmetric_scheme_ids():
            raise LifecycleContractError(
                LifecycleErrorCode.UNSUPPORTED_SCHEME,
                f"Possession requires a registered asymmetric scheme, got {request.scheme!r}",
            )
        protected = _protected_options(request.protected_options)
        old_key_id = request.old_key_id if isinstance(request, RotationRequest) else None
        intent = _intent_digest(
            operation_type,
            self._project,
            request,
            old_key_id=old_key_id,
            protected_options=protected,
        )
        existing = self._existing_idempotent(idempotency_key, intent)
        if existing is not None:
            return existing
        created_at, expires_at = self._time_window(ttl)
        op_id = operation_id or str(uuid.uuid4())
        fingerprint = _fingerprint(request.public_key, request.scheme)
        fields = _digest_fields(
            operation_id=op_id,
            idempotency_key=idempotency_key,
            operation_type=operation_type,
            project=self._project,
            request=request,
            created_at=created_at,
            expires_at=expires_at,
            old_key_id=old_key_id,
            public_key=request.public_key,
            scheme=request.scheme,
            custody_mode=request.custody_mode,
            protected_options=protected,
        )
        operation = LifecycleOperation(
            operation_id=op_id,
            idempotency_key=idempotency_key,
            operation_type=operation_type,
            state=LifecycleState.AWAITING_PROOF,
            project=self._project,
            principal_id=request.principal_id,
            principal_kind=request.principal_kind,
            actor_id=request.actor_id,
            reason=request.reason,
            requested_authority=request.requested_authority,
            policy_version=request.policy_version,
            created_at=created_at,
            expires_at=expires_at,
            digest=canonical_lifecycle_digest(fields),
            public_key=request.public_key,
            fingerprint=fingerprint,
            scheme=request.scheme,
            custody_mode=request.custody_mode,
            old_key_id=old_key_id,
            identity_binding_digest=request.identity_binding_digest,
            protected_options=protected,
        )
        return self._remember(operation, intent)

    def _remember(self, operation: LifecycleOperation, intent: str) -> LifecycleOperation:
        existing = self._operations.get(operation.operation_id)
        if existing is not None:
            if existing.digest != operation.digest:
                raise LifecycleContractError(
                    LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                    f"Operation ID {operation.operation_id!r} is already bound to another digest",
                )
            return existing
        if self._durable:
            self._persist_operation(operation, intent)
        self._operations[operation.operation_id] = operation
        self._idempotency[operation.idempotency_key] = (intent, operation.operation_id)
        return operation

    def _existing_idempotent(self, idempotency_key: str, intent: str) -> LifecycleOperation | None:
        existing = self._idempotency.get(idempotency_key)
        if existing is None:
            return None
        existing_intent, operation_id = existing
        if not hmac.compare_digest(existing_intent, intent):
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                f"Idempotency key {idempotency_key!r} is bound to another request",
            )
        return self._operations[operation_id]

    def _operation(self, operation_id: str) -> LifecycleOperation:
        """Return a prepared operation, rehydrating from the DB when durable.

        Operations rehydrate so a fresh instance can resume a lifecycle across
        HTTP requests.  Challenges are deliberately process-local and one-use,
        so they are never rehydrated.
        """
        operation = self._operations.get(operation_id)
        if operation is not None:
            return operation
        if self._durable:
            return self._load_operation_from_db(operation_id)
        raise LifecycleContractError(
            LifecycleErrorCode.OPERATION_NOT_FOUND,
            f"Lifecycle operation {operation_id!r} was not prepared",
        )

    def _time_window(self, ttl: timedelta) -> tuple[datetime, datetime]:
        if ttl <= timedelta(0):
            raise LifecycleContractError(LifecycleErrorCode.INVALID_REQUEST, "ttl must be positive")
        created_at = self._now()
        return created_at, created_at + ttl

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST, "clock must return a timezone-aware datetime"
            )
        return value.astimezone(UTC)


def canonical_lifecycle_digest(fields: Mapping[str, object]) -> LifecycleDigest:
    """Return the versioned SHA-256 digest of RFC 8785 canonical fields."""

    value = hashlib.sha256(canonicalize(dict(fields))).hexdigest()
    return LifecycleDigest(version=CONTRACT_VERSION, algorithm="sha-256", value=value)


def _digest_fields(
    *,
    operation_id: str,
    idempotency_key: str,
    operation_type: LifecycleOperationType,
    project: str,
    request: EnrollmentRequest | RevocationRequest,
    created_at: datetime,
    expires_at: datetime,
    old_key_id: str | None,
    public_key: bytes | None,
    scheme: str | None,
    custody_mode: CustodyMode | None,
    protected_options: tuple[tuple[str, str], ...],
) -> dict[str, object]:
    return {
        "contract_version": CONTRACT_VERSION,
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "operation_type": operation_type.value,
        "project": project,
        "principal_id": request.principal_id,
        "principal_kind": request.principal_kind.value,
        "actor_id": request.actor_id,
        "reason": request.reason,
        "requested_authority": request.requested_authority,
        "policy_version": request.policy_version,
        "created_at": _format_time(created_at),
        "expires_at": _format_time(expires_at),
        "public_key": _encode(public_key) if public_key is not None else None,
        "fingerprint": _fingerprint(public_key, scheme) if public_key and scheme else None,
        "scheme": scheme,
        "custody_mode": custody_mode.value if custody_mode else None,
        "old_key_id": old_key_id,
        "identity_binding_digest": request.identity_binding_digest,
        "protected_options": dict(protected_options),
    }


def _intent_digest(
    operation_type: LifecycleOperationType,
    project: str,
    request: EnrollmentRequest | RevocationRequest,
    *,
    old_key_id: str | None,
    protected_options: tuple[tuple[str, str], ...],
) -> str:
    public_key = request.public_key if isinstance(request, EnrollmentRequest) else None
    scheme = request.scheme if isinstance(request, EnrollmentRequest) else None
    custody_mode = request.custody_mode if isinstance(request, EnrollmentRequest) else None
    fields = {
        "contract_version": CONTRACT_VERSION,
        "operation_type": operation_type.value,
        "project": project,
        "principal_id": request.principal_id,
        "principal_kind": request.principal_kind.value,
        "actor_id": request.actor_id,
        "reason": request.reason,
        "requested_authority": request.requested_authority,
        "policy_version": request.policy_version,
        "public_key": _encode(public_key) if public_key is not None else None,
        "scheme": scheme,
        "custody_mode": custody_mode.value if custody_mode else None,
        "old_key_id": old_key_id,
        "identity_binding_digest": request.identity_binding_digest,
        "protected_options": dict(protected_options),
    }
    return hashlib.sha256(canonicalize(fields)).hexdigest()


def _validate_common(request: EnrollmentRequest | RevocationRequest) -> None:
    for name in (
        "principal_id",
        "actor_id",
        "reason",
        "requested_authority",
        "policy_version",
    ):
        _require_text(name, getattr(request, name))


def _protected_options(options: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    names = [name for name, _value in options]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_REQUEST,
            "protected_options names must be non-empty and unique",
        )
    return tuple(sorted(options))


def _require_text(name: str, value: str) -> None:
    if not value or value != value.strip():
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_REQUEST, f"{name} must be non-empty canonical text"
        )


def _fingerprint(public_key: bytes, scheme: str) -> str:
    return f"{scheme}:sha256:{hashlib.sha256(public_key).hexdigest()}"


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "CONTRACT_VERSION",
    "EFFECTIVE_DOMAIN",
    "Approval",
    "ChallengeStorageScope",
    "CustodyMode",
    "EffectiveChallenge",
    "EffectiveReceipt",
    "EffectiveReceiptStatus",
    "EnrollmentRequest",
    "LifecycleContractError",
    "LifecycleDigest",
    "LifecycleErrorCode",
    "LifecycleOperation",
    "LifecycleOperationType",
    "LifecycleState",
    "PossessionChallenge",
    "PossessionProof",
    "PrincipalDescriptor",
    "PrincipalKind",
    "PrincipalLifecycle",
    "ProofFormat",
    "ReconciliationReport",
    "ReconciliationStatus",
    "RegistryReceipt",
    "RegistryReceiptStatus",
    "RevocationRequest",
    "RotationRequest",
    "canonical_lifecycle_digest",
]
