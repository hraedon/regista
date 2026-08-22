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
import struct
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar, Final, Protocol, assert_never

import psycopg

from ._connection import ConnectionManager, DictConn
from ._errors import RegistaError
from ._jcs import canonicalize
from ._keys import KeySet
from ._observability import Metrics
from ._principal_keys import (
    PrincipalKeyEntry,
    _apply_enrollment_projection,
    _apply_revocation_projection,
    _apply_rotation_projection,
)
from ._principal_keys import (
    list_principal_keys_for_conn as _list_principal_keys_for_conn,
)
from ._principal_keys import (
    principal_entity_id as _principal_entity_id,
)
from ._signing_scheme import asymmetric_scheme_ids, get_scheme, is_v6_scheme
from ._trust_log import (
    PRINCIPAL_KEY_ENROLLED as _TRUST_LOG_PRINCIPAL_KEY_ENROLLED,
)
from ._trust_log import (
    PRINCIPAL_KEY_REVOKED as _TRUST_LOG_PRINCIPAL_KEY_REVOKED,
)
from ._trust_log import (
    PRINCIPAL_KEY_ROTATED as _TRUST_LOG_PRINCIPAL_KEY_ROTATED,
)
from ._trust_log_writer import (
    _append_trust_log_event_conn,
    replay_trust_state,
)

CONTRACT_VERSION: Final[str] = "regista.principal-lifecycle.v1-draft.2"
# §5.5: enrolment through the 0.6.0 contract requires the v2 possession domain.
POSSESSION_DOMAIN: Final[str] = "regista.principal-possession.v2"
EFFECTIVE_DOMAIN: Final[str] = "regista.principal-effective.v1"
EFFECTIVE_RECEIPT_DOMAIN: Final[str] = "regista.principal-effective-receipt.v1"
# Tolerated clock skew between a client's observed_at and the verifier-issued
# challenge window. Deliberately small (not dossier's 24h): just enough for
# realistic client/verifier clock drift, not a replay window.
EFFECTIVE_RECEIPT_CLOCK_SKEW: Final[timedelta] = timedelta(seconds=60)


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
    DURABLE_ONE_USE = "durable_one_use"


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
    APPROVER_IS_ACTOR = "approver_is_actor"
    APPROVAL_EVIDENCE_REQUIRED = "approval_evidence_required"
    RECEIPT_OBSERVED_AT_INVALID = "receipt_observed_at_invalid"
    OPERATION_ALREADY_COMMITTED = "operation_already_committed"
    AUTHORITY_REQUIRED = "authority_required"
    AUTHORITY_MISMATCH = "authority_mismatch"


class LifecycleContractError(Exception):
    """A fail-closed lifecycle contract validation error."""

    def __init__(self, code: LifecycleErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class LifecycleAuthorityKind(StrEnum):
    """The two authority roots permitted for principal lifecycle events."""

    ROOT = "root"
    REGISTRAR = "registrar"


@dataclass(frozen=True)
class LifecycleAuthority:
    """The signed authority binding captured by a prepared operation.

    ``key_binding_event_hash`` is the v6 envelope binding: the trust genesis
    hash for root authority, or the exact ``registrar_delegated`` event hash
    for registrar authority.  ``delegation_event_hash`` is the payload's
    ``authorized_by`` field and is intentionally ``None`` for root authority.
    """

    authority: LifecycleAuthorityKind
    principal_id: str
    key_id: str
    key_binding_event_hash: str
    delegation_event_hash: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "authority": self.authority.value,
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "key_binding_event_hash": self.key_binding_event_hash,
            "delegation_event_hash": self.delegation_event_hash,
        }


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
    root_signatures: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class RotationRequest(EnrollmentRequest):
    old_key_id: str = ""
    old_key_signature: bytes | None = None


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
    root_signatures: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class Approval:
    approver_id: str
    approver_kind: str
    approval_digest: str
    step_up_evidence: str | None = None
    reason: str = ""


class ApprovalVerifier(Protocol):
    """Typed step-up/approval-evidence policy (Plan 031 WI-1.2).

    A consumer supplies an implementation that encodes *who may approve* and
    *what evidence is sufficient*. Regista calls it from ``record_approval``
    and fails closed on a ``False`` verdict; it never interprets a free-form
    ``step_up_evidence`` string itself, and it never performs cryptographic
    validation on the consumer's behalf.

    When no verifier is registered the historical trust-the-consumer behavior is
    preserved and the durable verdict is recorded as ``NULL``
    (``evidence_verified=None``). ``None`` means *unverified*: the approval was
    accepted on consumer trust only, and is **not** sufficient for release
    qualification. A ``True``/``False`` verdict is the verifier's explicit
    judgment. Configuring a verifier is the consumer's responsibility; the
    default is deliberately the permissive historical mode.
    """

    def verify_approval(self, operation: LifecycleOperation, approval: Approval) -> bool:
        """Return ``True`` to accept the approval evidence, ``False`` to reject."""
        ...


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
    new_key_id: str | None = None
    identity_binding_digest: str | None = None
    protected_options: tuple[tuple[str, str], ...] = ()
    authority: LifecycleAuthority | None = None
    root_signatures: tuple[Mapping[str, Any], ...] = ()
    old_key_signature: bytes | None = None

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
            "new_key_id": self.new_key_id,
            "identity_binding_digest": self.identity_binding_digest,
            "protected_options": dict(self.protected_options),
            "authority": self.authority.to_dict() if self.authority is not None else None,
            "root_signatures": [dict(item) for item in self.root_signatures],
            "old_key_signature": _encode(self.old_key_signature)
            if self.old_key_signature is not None
            else None,
        }


@dataclass(frozen=True)
class PossessionChallenge:
    """Possession challenge, upgraded to **v2** framing (TRUST-DOMAIN.md §5.5).

    v2 keeps v1's object shape — including the in-object ``domain`` field, which
    D-9 deliberately retains — and adds ``trust_domain_id`` and
    ``enrollment_request_digest``, then changes the framing to the byte-prefix form
    used everywhere else in v6::

        p = JCS(challenge_object_including_domain_field)
        input = b"regista.principal-possession.v2\x00" || uint64be(len(p)) || p

    **Deliberate contract change (P2.2 review B1).** The v1 object had the domain
    inside the JCS payload only, with no prefix, and a ``token_urlsafe`` nonce.
    Neither satisfies §5.5, so a lifecycle commit could not produce a payload the
    §5.5 parsers accept — which is what left the sanctioned ceremony's events
    invisible to the rebuild. Both the verifier (``submit_possession``) and the
    shipped client (``client_signer``) obtain the bytes from ``signing_bytes()``
    rather than reconstructing them, so the framing change is transparent to
    callers that use the helper; a caller that hardcoded the v1 bytes must move.
    """

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
    trust_domain_id: str | None = None
    enrollment_request_digest: str | None = None

    def signing_bytes(self) -> bytes:
        from ._trust_log import POSSESSION_PREFIX_V2

        body = canonicalize(self.to_dict())
        return POSSESSION_PREFIX_V2 + struct.pack(">Q", len(body)) + body

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": POSSESSION_DOMAIN,
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "trust_domain_id": self.trust_domain_id,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "verifier_nonce": self.verifier_nonce,
            "enrollment_request_digest": self.enrollment_request_digest,
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

    def signing_dict(self, challenge: EffectiveChallenge) -> dict[str, object]:
        """Canonical envelope the client signs and the verifier checks.

        Binds the full effective challenge plus every mutable receipt field
        (client_type/version, status, observed_at), so none of them can be
        altered without invalidating the signature. The signature itself is
        excluded (it cannot sign itself); the challenge_id is bound via the
        embedded challenge.
        """
        return {
            "domain": EFFECTIVE_RECEIPT_DOMAIN,
            "contract_version": CONTRACT_VERSION,
            "challenge": challenge.to_dict(),
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "client_type": self.client_type,
            "client_version": self.client_version,
            "status": self.status.value,
            "observed_at": _format_time(self.observed_at),
        }

    def signing_bytes(self, challenge: EffectiveChallenge) -> bytes:
        return canonicalize(self.signing_dict(challenge))

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

    Durable commits are fail-closed against the pinned trust-domain document. Routine
    enrollment, rotation, and revocation resolve a live registrar delegation; recovery
    rotation additionally requires detached signatures meeting the current root
    threshold. The trust-log writer re-resolves that authority inside the commit
    transaction, so revocation, expiry, scope changes, and key drift between prepare and
    commit cannot be bypassed.
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
        approval_verifier: ApprovalVerifier | None = None,
        effective_receipt_clock_skew: timedelta | None = None,
        trust_genesis_document: Mapping[str, Any] | None = None,
    ) -> None:
        _require_text("project", project)
        self._project = project
        self._mgr = mgr
        self._keys = keys
        self._metrics = metrics
        self._approval_verifier = approval_verifier
        self._trust_genesis_document = (
            dict(trust_genesis_document) if trust_genesis_document is not None else None
        )
        self._effective_receipt_clock_skew = (
            EFFECTIVE_RECEIPT_CLOCK_SKEW
            if effective_receipt_clock_skew is None
            else effective_receipt_clock_skew
        )
        self._durable = mgr is not None
        self._clock = clock or (lambda: datetime.now(UTC))
        # 64 lowercase hex: the shape §5.5 fixes for possession_proof.verifier_nonce.
        self._nonce_factory = nonce_factory or (lambda: secrets.token_bytes(32).hex())
        self._operations: dict[str, LifecycleOperation] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._challenges: dict[str, _ChallengeRecord] = {}
        self._receipts: dict[str, RegistryReceipt] = {}
        # operation_id -> base64 possession signature, kept so the committed event
        # can name the proof submit_possession already verified (§5.5).
        self._possession_signatures: dict[str, str] = {}

    @property
    def challenge_storage_scope(self) -> ChallengeStorageScope:
        """Identify the verifier's challenge single-use authority.

        Durable instances enforce one-use atomically in the database, so a
        challenge survives restarts and is shared across instances. Non-durable
        instances are the process-local foundation: one-use is only guaranteed
        within the issuing process.
        """

        if self._durable:
            return ChallengeStorageScope.DURABLE_ONE_USE
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
        existing = self._existing_durable_for_request(
            LifecycleOperationType.REVOCATION,
            request,
            idempotency_key=idempotency_key,
            old_key_id=request.key_id,
            protected_options=protected,
        )
        if existing is not None:
            return existing
        created_at, expires_at = self._time_window(ttl)
        authority = self._resolve_authority_binding(
            LifecycleOperationType.REVOCATION,
            request,
            at=created_at,
        )
        intent = _intent_digest(
            LifecycleOperationType.REVOCATION,
            self._project,
            request,
            old_key_id=request.key_id,
            protected_options=protected,
            authority=authority,
        )
        existing = self._existing_idempotent(idempotency_key, intent)
        if existing is not None:
            return existing
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
            authority=authority,
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
            authority=authority,
            root_signatures=_normalize_root_signatures(request.root_signatures),
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
            # v2 additions (§5.5). trust_domain_id is the project's, read from
            # project_identity; it is None only before genesis, where commit()
            # cannot append anyway.
            trust_domain_id=self._trust_domain_id(),
            enrollment_request_digest=_enrollment_request_digest(operation),
        )
        self._challenges[challenge.challenge_id] = _ChallengeRecord(challenge)
        if self._durable:
            self._persist_challenge(challenge)
        return challenge

    def submit_possession(self, operation_id: str, proof: PossessionProof) -> LifecycleOperation:
        operation = self._operation(operation_id)
        if (
            proof.format is not ProofFormat.SIGNATURE_V1
            or proof.operation_id != operation_id
            or not hmac.compare_digest(proof.operation_digest, operation.digest.value)
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                "Proof does not match the prepared operation and digest",
            )
        challenge = self._fetch_challenge(
            proof.challenge_id,
            expected_kind="possession",
            expected_operation_digest=operation.digest.value,
            operation_id=operation_id,
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
        if self._durable:
            # Consume + state advance share one transaction so a failure after
            # the consume rolls the challenge back to used=false; in-memory
            # state is refreshed only once the commit succeeds.
            assert self._mgr is not None
            with self._mgr.transaction() as conn:
                consumed = self._consume_challenge_conn(
                    conn,
                    proof.challenge_id,
                    expected_kind="possession",
                    expected_operation_digest=operation.digest.value,
                    operation_id=operation_id,
                    # Recorded so a commit on another instance can name the proof.
                    proof_signature=_encode(proof.signature),
                )
                conn.execute(
                    "UPDATE lifecycle_operations SET state = 'awaiting_approval' "
                    "WHERE operation_id = %s",
                    [operation_id],
                )
            self._challenges[proof.challenge_id] = _ChallengeRecord(consumed, used=True)
        else:
            self._challenges[proof.challenge_id].used = True
        self._possession_signatures[operation_id] = _encode(proof.signature)
        verified = replace(operation, state=LifecycleState.AWAITING_APPROVAL)
        self._operations[operation_id] = verified
        return verified

    def rotation_authorization_bytes(self, operation_id: str) -> bytes:
        """Return the exact bytes the superseded key must sign for a dual rotation."""

        self._require_durable("rotation_authorization_bytes")
        operation = self._operation(operation_id)
        if operation.operation_type is not LifecycleOperationType.ROTATION:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "only rotation operations have old-key authorization bytes",
            )
        if operation.state not in {
            LifecycleState.AWAITING_PROOF,
            LifecycleState.AWAITING_APPROVAL,
        }:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting possession or approval",
            )
        if (
            operation.authority is None
            or operation.authority.authority is not LifecycleAuthorityKind.REGISTRAR
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "dual old-key authorization requires registrar authority",
            )
        if operation.new_key_id is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "rotation has no prepared new key id",
            )
        from ._trust_log import old_key_signature_input

        unsigned = replace(operation, old_key_signature=None)
        return old_key_signature_input(
            self._trust_log_payload(
                unsigned,
                key_id=operation.new_key_id,
                allow_unsigned_rotation=True,
            )
        )

    def submit_rotation_authorization(
        self,
        operation_id: str,
        old_key_signature: bytes,
    ) -> LifecycleOperation:
        """Persist and verify the outgoing-key half of a dual rotation."""

        self._require_durable("submit_rotation_authorization")
        operation = self._operation(operation_id)
        if operation.operation_type is not LifecycleOperationType.ROTATION:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "old-key authorization is valid only for rotation operations",
            )
        if operation.state is not LifecycleState.AWAITING_APPROVAL:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting approval",
            )
        if operation.new_key_id is None:
            # Migration-050 rows created before deterministic replacement-key
            # identity was added are still readable.  They must fail as a
            # contract mismatch, not reach _trust_log_payload's internal
            # assertion and crash the caller.
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "rotation has no prepared new key id",
            )
        if len(old_key_signature) != 64:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "old-key authorization must be a 64-byte Ed25519 signature",
            )
        if operation.old_key_signature is not None:
            if hmac.compare_digest(operation.old_key_signature, old_key_signature):
                return operation
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "the rotation already carries a different old-key authorization",
            )
        assert self._mgr is not None
        assert self._trust_genesis_document is not None
        assert operation.old_key_id is not None
        try:
            from ._trust_log import classify_rotation_authority, parse_principal_key_rotated

            candidate = replace(operation, old_key_signature=old_key_signature)
            payload = self._trust_log_payload(
                candidate,
                key_id=operation.new_key_id,
            )
            with self._mgr.transaction() as conn:
                state = replay_trust_state(conn, self._trust_genesis_document)
            old_public_key = state.principal_public_keys.get(
                (operation.principal_id, operation.old_key_id)
            )
            parsed = parse_principal_key_rotated(payload)
            classify_rotation_authority(
                parsed,
                governance=state.governance,
                root_public_keys=state.root_public_keys,
                payload=payload,
                superseded_public_key=old_public_key,
            )
        except (RegistaError, psycopg.Error) as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "the old-key rotation authorization was refused: "
                f"{type(exc).__name__}",
            ) from exc
        with self._mgr.transaction() as conn:
            updated_row = conn.execute(
                "UPDATE lifecycle_operations SET old_key_signature = %s "
                "WHERE operation_id = %s AND state = 'awaiting_approval' "
                "AND old_key_signature IS NULL",
                [old_key_signature, operation_id],
            )
            if updated_row.rowcount != 1:
                row = conn.execute(
                    "SELECT state, old_key_signature FROM lifecycle_operations "
                    "WHERE operation_id = %s FOR UPDATE",
                    [operation_id],
                ).fetchone()
                if row is None or row["state"] != "awaiting_approval":
                    raise LifecycleContractError(
                        LifecycleErrorCode.INVALID_OPERATION_STATE,
                        f"Operation {operation_id!r} is no longer awaiting approval",
                    )
                stored = row["old_key_signature"]
                if stored is None or not hmac.compare_digest(bytes(stored), old_key_signature):
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_MISMATCH,
                        "the rotation already carries a different old-key authorization",
                    )
        updated = replace(operation, old_key_signature=old_key_signature)
        self._operations[operation_id] = updated
        return updated

    def root_authorization_bytes(self, operation_id: str) -> bytes:
        """Return the bytes detached root signers must sign for recovery."""

        self._require_durable("root_authorization_bytes")
        operation = self._operation(operation_id)
        if operation.operation_type is not LifecycleOperationType.ROTATION:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "only recovery rotation operations have root authorization bytes",
            )
        if (
            operation.authority is None
            or operation.authority.authority is not LifecycleAuthorityKind.ROOT
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "root authorization bytes require root authority",
            )
        if operation.new_key_id is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "rotation has no prepared new key id",
            )
        from ._trust_log import root_signature_input

        unsigned = replace(operation, root_signatures=())
        return root_signature_input(
            self._trust_log_payload(
                unsigned,
                key_id=operation.new_key_id,
                allow_unsigned_rotation=True,
            )
        )

    def submit_root_authorization(
        self,
        operation_id: str,
        root_signatures: Sequence[Mapping[str, Any]],
    ) -> LifecycleOperation:
        """Persist detached root signatures for a recovery rotation."""

        self._require_durable("submit_root_authorization")
        operation = self._operation(operation_id)
        if operation.operation_type is not LifecycleOperationType.ROTATION:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "root authorization is valid only for rotation operations",
            )
        if operation.state is not LifecycleState.AWAITING_APPROVAL:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_OPERATION_STATE,
                f"Operation {operation_id!r} is not awaiting approval",
            )
        if operation.new_key_id is None:
            # See submit_rotation_authorization: old durable rows are a typed
            # authority mismatch, never an assertion failure in payload build.
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "rotation has no prepared new key id",
            )
        candidate_signatures = _normalize_root_signatures(root_signatures)
        if operation.root_signatures:
            if _normalize_root_signatures(operation.root_signatures) == candidate_signatures:
                return operation
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "the rotation already carries different root authorization",
            )
        if (
            operation.authority is None
            or operation.authority.authority is not LifecycleAuthorityKind.ROOT
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "root authorization requires root authority",
            )
        assert self._mgr is not None
        assert self._trust_genesis_document is not None
        try:
            from ._trust_log import verify_root_threshold

            candidate = replace(operation, root_signatures=candidate_signatures)
            payload = self._trust_log_payload(candidate, key_id=operation.new_key_id)
            with self._mgr.transaction() as conn:
                state = replay_trust_state(conn, self._trust_genesis_document)
            verify_root_threshold(payload, state.governance, state.root_public_keys)
        except (RegistaError, psycopg.Error) as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "the detached root authorization was refused: " f"{type(exc).__name__}",
            ) from exc
        with self._mgr.transaction() as conn:
            updated_row = conn.execute(
                "UPDATE lifecycle_operations SET root_signatures = %s "
                "WHERE operation_id = %s AND state = 'awaiting_approval' "
                "AND root_signatures = '[]'::jsonb",
                [psycopg.types.json.Jsonb(list(candidate_signatures)), operation_id],
            )
            if updated_row.rowcount != 1:
                row = conn.execute(
                    "SELECT state, root_signatures FROM lifecycle_operations "
                    "WHERE operation_id = %s FOR UPDATE",
                    [operation_id],
                ).fetchone()
                if row is None or row["state"] != "awaiting_approval":
                    raise LifecycleContractError(
                        LifecycleErrorCode.INVALID_OPERATION_STATE,
                        f"Operation {operation_id!r} is no longer awaiting approval",
                    )
                stored_raw = row["root_signatures"]
                stored = (
                    _normalize_root_signatures(stored_raw)
                    if isinstance(stored_raw, list)
                    and all(isinstance(item, dict) for item in stored_raw)
                    else ()
                )
                if stored != candidate_signatures:
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_MISMATCH,
                        "the rotation already carries different root authorization",
                    )
        updated = replace(operation, root_signatures=candidate_signatures)
        self._operations[operation_id] = updated
        return updated

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
        if operation.operation_type is LifecycleOperationType.ROTATION:
            authority = operation.authority
            if authority is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_REQUIRED,
                    "rotation approval requires a signed authority binding",
                )
            if (
                authority.authority is LifecycleAuthorityKind.REGISTRAR
                and operation.old_key_signature is None
            ):
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "submit the superseded key's authorization before approving a "
                    "registrar rotation",
                )
            if (
                authority.authority is LifecycleAuthorityKind.ROOT
                and not operation.root_signatures
            ):
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "submit detached root authorization before approving a recovery "
                    "rotation",
                )
        if not hmac.compare_digest(approval.approval_digest, operation.digest.value):
            raise LifecycleContractError(
                LifecycleErrorCode.APPROVAL_DIGEST_MISMATCH,
                "Approval digest does not match the operation digest",
            )
        if approval.approver_id == operation.actor_id:
            raise LifecycleContractError(
                LifecycleErrorCode.APPROVER_IS_ACTOR,
                f"Approver {approval.approver_id!r} cannot approve an operation "
                "they requested; separation of duties requires a distinct approver",
            )
        evidence_verified: bool | None = None
        if self._approval_verifier is not None:
            evidence_verified = self._approval_verifier.verify_approval(operation, approval)
            if not evidence_verified:
                raise LifecycleContractError(
                    LifecycleErrorCode.APPROVAL_EVIDENCE_REQUIRED,
                    "Approval evidence did not satisfy the configured approval policy",
                )
        approval_id = str(uuid.uuid4())
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            conn.execute(
                """
                INSERT INTO lifecycle_approvals
                    (approval_id, operation_id, operation_digest,
                     approver_id, approver_kind, approval_digest,
                     step_up_evidence, reason, approved_at, evidence_verified)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    evidence_verified,
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
        with self._mgr.transaction() as conn:
            existing_row = conn.execute(
                    "SELECT state, receipt_key_id, committed_at FROM lifecycle_operations "
                    "WHERE operation_id = %s FOR UPDATE",
                    [operation_id],
            ).fetchone()
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
            if self._trust_genesis_document is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_REQUIRED,
                    "a pinned trust-genesis document is required before a principal "
                    "lifecycle operation can commit",
                )
            authority = operation.authority
            if authority is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_REQUIRED,
                    "the prepared lifecycle operation has no signed authority binding",
                )
            new_key_id = operation.new_key_id
            if operation.operation_type is not LifecycleOperationType.REVOCATION:
                if new_key_id is None:
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_MISMATCH,
                        "the prepared lifecycle operation has no deterministic new key id",
                    )
            payload = self._trust_log_payload(operation, key_id=new_key_id)
            # The trust-log event is appended FIRST: its hash is the source
            # evidence the projection applier requires (§5.9 rule 2).  This
            # low-level seam deliberately shares this transaction, so a signed
            # authority event and its projection cannot diverge.
            try:
                appended = _append_trust_log_event_conn(
                    conn,
                    keys=self._keys,
                    genesis_document=self._trust_genesis_document,
                    transition=transition,
                    payload=payload,
                    entity_kind="principal",
                    entity_id=entity_id,
                    principal_id=operation.actor_id,
                    authority=authority.authority.value,
                    key_id=authority.key_id,
                    occurred_at=self._now(),
                )
            except RegistaError as exc:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "the signed lifecycle authority was refused by the trust log: "
                    f"{exc}",
                ) from exc
            entry = self._commit_key(
                conn,
                operation,
                source_event_hash=appended.event_hash,
                occurred_at=appended.occurred_at,
                payload=payload,
                key_id=new_key_id,
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
            if operation.public_key is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.INVALID_REQUEST,
                    "Committed operation has no public key",
                )
        # A challenge is consumed only when a signed receipt verifies against it
        # (verify-before-consume, so a bad signature never burns it). A receipt
        # carrying a challenge_id without a signature is an unsigned report that
        # must not burn the challenge, lest it DoS the client's later proof.
        signed = receipt.challenge_id is not None and receipt.signature is not None
        if signed:
            assert receipt.challenge_id is not None
            assert receipt.signature is not None
            challenge = self._fetch_challenge(
                receipt.challenge_id,
                expected_kind="effective",
                expected_operation_digest=operation.digest.value,
                operation_id=operation_id,
            )
            assert isinstance(challenge, EffectiveChallenge)
            self._validate_receipt_chronology(receipt, challenge)
            scheme = get_scheme(challenge.scheme)
            envelope = receipt.signing_bytes(challenge)
            envelope_hash = hashlib.sha256(envelope).digest()
            assert operation.public_key is not None
            if not scheme.verify(envelope, receipt.signature, envelope_hash, operation.public_key):
                raise LifecycleContractError(
                    LifecycleErrorCode.PROOF_VERIFICATION_FAILED,
                    "Effective-use signature verification failed",
                )
        elif receipt.challenge_id is not None:
            # Unsigned report referencing a challenge: enforce chronology (so a
            # stale/future/naive report is still rejected) without consuming.
            report_challenge = self._fetch_challenge(
                receipt.challenge_id,
                expected_kind="effective",
                expected_operation_digest=operation.digest.value,
                operation_id=operation_id,
            )
            assert isinstance(report_challenge, EffectiveChallenge)
            self._validate_receipt_chronology(receipt, report_challenge)
        if receipt.status is EffectiveReceiptStatus.EFFECTIVE:
            new_state = LifecycleState.EFFECTIVE
        elif receipt.status is EffectiveReceiptStatus.COMMITTED_NOT_EFFECTIVE:
            new_state = LifecycleState.PARTIALLY_EFFECTIVE
        elif receipt.status is EffectiveReceiptStatus.REJECTED:
            new_state = LifecycleState.FAILED
        else:
            assert_never(receipt.status)
        # Consume (when signed), receipt upsert, and state advance share one
        # transaction, so a failure after the consume rolls the challenge back to
        # used=false; in-memory state is refreshed only after commit.
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            consumed: PossessionChallenge | EffectiveChallenge | None = None
            if signed:
                assert receipt.challenge_id is not None
                consumed = self._consume_challenge_conn(
                    conn,
                    receipt.challenge_id,
                    expected_kind="effective",
                    expected_operation_digest=operation.digest.value,
                    operation_id=operation_id,
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
            conn.execute(
                "UPDATE lifecycle_operations SET state = %s WHERE operation_id = %s",
                [new_state.value, operation_id],
            )
        if consumed is not None and receipt.challenge_id is not None:
            self._challenges[receipt.challenge_id] = _ChallengeRecord(consumed, used=True)
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
            op_row = conn.execute(
                    "SELECT * FROM lifecycle_operations "
                    "WHERE principal_id = %s "
                    "ORDER BY created_at DESC LIMIT 1",
                    [principal_id],
            ).fetchone()
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
            op_row = conn.execute(
                    "SELECT * FROM lifecycle_operations "
                    "WHERE principal_id = %s AND state = 'committed' "
                    "ORDER BY created_at DESC LIMIT 1",
                    [principal_id],
            ).fetchone()
            receipt_row = conn.execute(
                    "SELECT * FROM lifecycle_effective_receipts "
                    "WHERE principal_id = %s ORDER BY observed_at DESC LIMIT 1",
                    [principal_id],
            ).fetchone()
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

    def _resolve_authority_binding(
        self,
        operation_type: LifecycleOperationType,
        request: EnrollmentRequest | RevocationRequest,
        *,
        at: datetime,
    ) -> LifecycleAuthority | None:
        """Resolve and pin the signed authority for a durable operation.

        The operation actor is also the signer of the trust-log event.  A
        registrar binding therefore has to resolve twice: first here, so the
        prepared digest names the exact credential, and again in the append
        transaction, so revocation/expiry/redelegation between prepare and
        commit fails closed.
        """

        if not self._durable:
            return None
        if self._trust_genesis_document is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                "a pinned trust-genesis document is required to prepare a durable "
                "principal lifecycle operation",
            )
        assert self._mgr is not None
        assert self._keys is not None
        try:
            authority_kind = LifecycleAuthorityKind(request.requested_authority)
        except ValueError as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.INVALID_REQUEST,
                "requested_authority must be 'root' or 'registrar'",
            ) from exc
        if (
            authority_kind is LifecycleAuthorityKind.ROOT
            and operation_type is not LifecycleOperationType.ROTATION
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "root authority is reserved for recovery rotation; enrollment and "
                "revocation require a scoped registrar",
            )
        try:
            key_entry = self._keys.resolve_signing_key(request.actor_id)
            with self._mgr.transaction() as conn:
                state = replay_trust_state(conn, self._trust_genesis_document)
        except (RegistaError, psycopg.Error) as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                "the live signed trust authority could not be resolved: "
                f"{type(exc).__name__}",
            ) from exc

        if key_entry.public_key is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                f"authority key {key_entry.key_id!r} has no public key",
            )
        key_fingerprint = key_entry.fingerprint()
        if authority_kind is LifecycleAuthorityKind.ROOT:
            if key_fingerprint not in state.governance.signer_fingerprints:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    f"actor {request.actor_id!r} is not signed by a current root key",
                )
            return LifecycleAuthority(
                authority=authority_kind,
                principal_id=request.actor_id,
                key_id=key_entry.key_id,
                key_binding_event_hash=state.genesis_event_hash,
                delegation_event_hash=None,
            )

        registrar = state.registrars.get(request.actor_id)
        if registrar is None or registrar.revoked:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                f"actor {request.actor_id!r} has no live signed registrar delegation",
            )
        if registrar.key_id != key_entry.key_id or registrar.public_key != key_entry.public_key:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                f"actor {request.actor_id!r} is not using the delegated registrar key",
            )
        transition = self._transition_for(operation_type)
        if transition not in registrar.scopes:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                f"registrar delegation does not cover {transition!r}",
            )
        if not registrar.not_before <= at < registrar.not_after:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                "the registrar delegation is outside its validity window",
            )
        if (
            registrar.max_operations is not None
            and registrar.operations_used >= registrar.max_operations
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                "the registrar delegation has exhausted max_operations",
            )
        return LifecycleAuthority(
            authority=authority_kind,
            principal_id=request.actor_id,
            key_id=key_entry.key_id,
            key_binding_event_hash=registrar.delegated_event_hash,
            delegation_event_hash=registrar.delegated_event_hash,
        )

    #: §5.5 custody.declared_backend for each lifecycle custody mode. An unmapped
    #: mode declares "operator" — an unverified claim either way (§11 obligation 2).
    _CUSTODY_BACKEND_BY_MODE: ClassVar[dict[CustodyMode, str]] = {
        CustodyMode.REMOTE_ORGANIZATIONAL: "vault",
        CustodyMode.WINDOWS_LOCAL: "windows",
        CustodyMode.FILE: "file",
    }

    def _trust_log_payload(
        self,
        operation: LifecycleOperation,
        *,
        key_id: str | None,
        allow_unsigned_rotation: bool = False,
    ) -> dict[str, Any]:
        """Build the §5.5 / §5.6 / §5.7 payload for a committed operation.

        Validated through the frozen parsers before it is returned, so an event this
        ceremony appends is one the §5.9 rebuild can replay. If it cannot be built
        validly the commit fails here rather than writing an event that would later
        read as divergence.

        Durable callers have already supplied and validated the pinned trust-genesis
        document during preparation. A non-durable caller has no commit path, so this
        helper remains useful only for the contract foundation and does not weaken
        durable authority admission.
        """
        from ._trust_log import (
            POSSESSION_DOMAIN_V2,
            parse_principal_key_enrolled,
            parse_principal_key_revoked,
            parse_principal_key_rotated,
        )

        trust_domain_id = self._trust_domain_id()
        # The prepared operation's creation time is part of its immutable digest.
        # Authorization bytes must remain stable between preparation and commit;
        # using a fresh clock value here would make an old-key/root signature
        # collected before commit unverifiable at commit time.
        now = _format_time(operation.created_at)

        if operation.operation_type is LifecycleOperationType.REVOCATION:
            assert operation.old_key_id is not None
            payload: dict[str, Any] = {
                "type": "regista.key-revocation",
                "version": 1,
                "trust_domain_id": trust_domain_id,
                "principal_id": operation.principal_id,
                "key_id": operation.old_key_id,
                "reason": (
                    operation.reason
                    if operation.reason
                    in {"compromised", "superseded", "decommissioned", "policy"}
                    else "unspecified"
                ),
                "revoked_at": now,
                "effective_from": {
                    "kind": "on_chain_position",
                    "trust_log_event_hash": "self",
                },
                "retroactive_suspicion": {
                    "declared": False,
                    "suspect_from_event_hash": None,
                    "note": None,
                },
                "authorized_by": self._authorized_by(operation),
            }
            parse_principal_key_revoked(payload)
            return payload

        assert operation.public_key is not None
        assert operation.scheme is not None
        assert key_id is not None
        challenge_id, verifier_nonce, signature = self._committed_possession(operation)
        payload = {
            "type": (
                "regista.key-rotation"
                if operation.operation_type is LifecycleOperationType.ROTATION
                else "regista.key-enrollment"
            ),
            "version": 1,
            "trust_domain_id": trust_domain_id,
            "principal_id": operation.principal_id,
            "principal_kind": operation.principal_kind.value,
            "key_id": key_id,
            "scheme_id": operation.scheme,
            # Defect A / WI-273: the bytes, mandatory, so the projection is
            # rebuildable from the event alone.
            "public_key": _encode(operation.public_key),
            "fingerprint": operation.fingerprint,
            "not_before": now,
            "not_after": None,
            "possession_proof": {
                "domain": POSSESSION_DOMAIN_V2,
                "challenge_id": challenge_id,
                "verifier_nonce": verifier_nonce,
                "enrollment_request_digest": _enrollment_request_digest(operation),
                "signature": signature,
            },
            "authorized_by": self._authorized_by(operation),
            "custody": {
                "declared_backend": self._CUSTODY_BACKEND_BY_MODE.get(
                    operation.custody_mode, "operator"
                )
                if operation.custody_mode is not None
                else "operator",
                "declared_policy_ref": operation.policy_version,
            },
            "supersedes_key_id": operation.old_key_id,
        }
        if operation.operation_type is LifecycleOperationType.ROTATION:
            authority = operation.authority
            if authority is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_REQUIRED,
                    "rotation has no signed authority binding",
                )
            if authority.authority is LifecycleAuthorityKind.REGISTRAR:
                if operation.old_key_signature is None and not allow_unsigned_rotation:
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_REQUIRED,
                        "registrar rotation requires a signature from the superseded key",
                    )
                payload["dual_authorization"] = {
                    "old_key_signature": (
                        _encode(operation.old_key_signature)
                        if operation.old_key_signature is not None
                        else None
                    ),
                    "mode": "dual",
                    "recovery_reason": None,
                }
                payload["root_signatures"] = []
            else:
                if not operation.root_signatures and not allow_unsigned_rotation:
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_REQUIRED,
                        "root recovery rotation requires detached root signatures",
                    )
                payload["dual_authorization"] = {
                    "old_key_signature": None,
                    "mode": "recovery",
                    "recovery_reason": "custody-migration",
                }
                payload["root_signatures"] = [
                    dict(item)
                    for item in _normalize_root_signatures(operation.root_signatures)
                ]
            validation_payload = payload
            if (
                allow_unsigned_rotation
                and authority.authority is LifecycleAuthorityKind.REGISTRAR
                and operation.old_key_signature is None
            ):
                # The frozen parser correctly requires a non-null signature in a
                # committed ``mode: dual`` payload.  Authorization bytes are
                # collected before that signature exists, however.  Validate the
                # same shape with a throwaway 64-byte value; the signing-input
                # helper canonicalizes this field back to null, so the placeholder
                # can never escape into a signed or persisted payload.
                validation_payload = dict(payload)
                dual = dict(validation_payload["dual_authorization"])
                dual["old_key_signature"] = _encode(b"\x00" * 64)
                validation_payload["dual_authorization"] = dual
            parse_principal_key_rotated(validation_payload)
        else:
            parse_principal_key_enrolled(payload)
        return payload

    def _authorized_by(self, operation: LifecycleOperation) -> dict[str, Any]:
        """Build ``authorized_by`` from the verified prepared binding."""
        binding = operation.authority
        if binding is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                "the lifecycle operation has no signed authority binding",
            )
        return {
            "authority": binding.authority.value,
            "principal_id": binding.principal_id,
            "key_id": binding.key_id,
            "delegation_event_hash": binding.delegation_event_hash,
        }

    def _committed_possession(
        self, operation: LifecycleOperation
    ) -> tuple[str, str, str]:
        """The consumed possession challenge's identifying fields plus the proof.

        Read from this instance's challenge record for the operation. The proof was
        already verified by ``submit_possession``; this repeats its identity into the
        event so a replayer can bind the two.
        """
        if self._durable and self._mgr is not None:
            # DB first: commit() may run on a different instance from the one that
            # issued and verified the challenge (Plan 031's durable cross-instance
            # property), so process-local state is not authoritative here.
            with self._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT challenge_id, verifier_nonce, proof_signature "
                    "FROM lifecycle_challenges "
                    "WHERE operation_id = %s AND kind = 'possession' AND used = true "
                    "ORDER BY issued_at DESC LIMIT 1",
                    [operation.operation_id],
                ).fetchone()
            if row is not None:
                return (
                    str(row["challenge_id"]),
                    row["verifier_nonce"],
                    row["proof_signature"] or "",
                )
        for record in self._challenges.values():
            challenge = record.challenge
            if (
                isinstance(challenge, PossessionChallenge)
                and challenge.operation_id == operation.operation_id
            ):
                proof_sig = self._possession_signatures.get(operation.operation_id, "")
                return challenge.challenge_id, challenge.verifier_nonce, proof_sig
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_OPERATION_STATE,
            f"no possession challenge is recorded for operation "
            f"{operation.operation_id!r}; the event could not name the proof it rests on",
        )

    def _trust_domain_id(self) -> str | None:
        """Return the operator-pinned trust-domain identity for lifecycle writes."""
        if self._trust_genesis_document is None:
            return None
        try:
            from ._trust_domain import parse_trust_genesis

            return parse_trust_genesis(self._trust_genesis_document).trust_domain_id
        except RegistaError as exc:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_REQUIRED,
                f"the pinned trust-genesis document is invalid: {exc}",
            ) from exc

    def _transition_for(self, op_type: LifecycleOperationType) -> str:
        """The §5.3 catalogue transition names.

        **Deliberate change (P2.2 review B1).** These were Plan 026's
        ``principal_enrolled`` / ``principal_rotated`` / ``principal_revoked``.
        ``TRUST-DOMAIN.md`` §5.3 fixes the catalogue as ``principal_key_enrolled`` /
        ``principal_key_rotated`` / ``principal_key_revoked``, and §5.9's rebuild
        replays exactly those. While this ceremony emitted the Plan-026 names its
        events were invisible to the rebuild, so the rows it wrote could not be
        reproduced — and an applied rebuild would have deleted them. §5.5-§5.7 is
        the frozen contract; the Plan-026 shape predates it.
        """
        if op_type is LifecycleOperationType.ENROLLMENT:
            return _TRUST_LOG_PRINCIPAL_KEY_ENROLLED
        if op_type is LifecycleOperationType.ROTATION:
            return _TRUST_LOG_PRINCIPAL_KEY_ROTATED
        if op_type is LifecycleOperationType.REVOCATION:
            return _TRUST_LOG_PRINCIPAL_KEY_REVOKED
        assert_never(op_type)

    def _commit_key(
        self,
        conn: DictConn,
        operation: LifecycleOperation,
        *,
        source_event_hash: str,
        occurred_at: datetime,
        payload: Mapping[str, Any],
        key_id: str | None = None,
    ) -> PrincipalKeyEntry:
        """Apply the committed operation to the ``principal_keys`` projection.

        ``source_event_hash`` is the hash of the signed lifecycle event appended
        immediately before this call, in the same transaction. The appliers require
        it (§5.9 rule 2), which is what makes the ordering — event first, then
        projection — structural rather than conventional.

        **Every per-row value is single-sourced from ``payload``, parsed with the
        same functions §5.9's rebuild uses** (P2.2 review B1-prime). Previously this
        method read its own values: ``trust_domain_id`` was never passed (so the row
        stored NULL while the payload carried the real UUID), ``valid_from`` came
        from a second, later clock read than the payload's ``not_before``, and the
        revocation used the raw ``operation.reason`` while the payload carried one
        mapped into the closed §5.7 set. Each was a permanent ``field_mismatch``
        against the rebuild — the same class B1 set out to close, displaced from
        transitions to values.

        The one column deliberately NOT taken from the payload is ``registered_at``,
        which is the event's own ``occurred_at``. The rebuild reads it from the
        stored row's ``timestamp``, so both sides take it from the event, not from
        the payload — and the append is what assigns it.
        """
        from ._trust_log import (
            parse_principal_key_enrolled,
            parse_principal_key_revoked,
            parse_principal_key_rotated,
        )

        if operation.operation_type is LifecycleOperationType.ENROLLMENT:
            parsed = parse_principal_key_enrolled(payload)
            assert key_id is None or parsed.key.key_id == key_id, (
                f"payload key_id {parsed.key.key_id!r} != minted {key_id!r}: the row "
                "and its source event would name different keys"
            )
            return _apply_enrollment_projection(
                conn,
                parsed.principal_id,
                parsed.key.public_key,
                parsed.key.scheme_id,
                source_event_hash=source_event_hash,
                valid_from=parsed.not_before,
                valid_to=parsed.not_after,
                registered_at=occurred_at,
                key_id=parsed.key.key_id,
                registered_by=parsed.authorized_by.principal_id,
                trust_domain_id=parsed.trust_domain_id,
            )
        if operation.operation_type is LifecycleOperationType.ROTATION:
            rotated = parse_principal_key_rotated(payload)
            assert key_id is None or rotated.key.key_id == key_id, (
                f"payload key_id {rotated.key.key_id!r} != minted {key_id!r}: the row "
                "and its source event would name different keys"
            )
            return _apply_rotation_projection(
                conn,
                rotated.principal_id,
                rotated.key.public_key,
                rotated.key.scheme_id,
                source_event_hash=source_event_hash,
                valid_from=rotated.not_before,
                valid_to=rotated.not_after,
                registered_at=occurred_at,
                key_id=rotated.key.key_id,
                registered_by=rotated.authorized_by.principal_id,
                trust_domain_id=rotated.trust_domain_id,
            )
        if operation.operation_type is LifecycleOperationType.REVOCATION:
            revoked = parse_principal_key_revoked(payload)
            return _apply_revocation_projection(
                conn,
                revoked.principal_id,
                revoked.key_id,
                source_event_hash=source_event_hash,
                revoked_at=revoked.revoked_at,
                reason=revoked.reason,
            )
        assert_never(operation.operation_type)

    def _persist_operation(
        self, operation: LifecycleOperation, intent: str
    ) -> LifecycleOperation | None:
        """Persist a prepared operation, race-safe on ``idempotency_key``.

        ``INSERT ... ON CONFLICT DO NOTHING`` lets the unique index arbitrate
        concurrent prepares, so no raw ``UniqueViolation`` escapes. Returns
        ``None`` when this call inserted the row; otherwise returns the winning
        row (same digest, for the caller to adopt) or raises
        ``OPERATION_DIGEST_MISMATCH`` (key bound to a different digest).
        """
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            inserted = conn.execute(
                """
                INSERT INTO lifecycle_operations
                    (operation_id, idempotency_key, operation_type, state,
                     project, principal_id, principal_kind, actor_id,
                     reason, requested_authority, policy_version,
                      digest_value, digest_algorithm, digest_version,
                      public_key, fingerprint, scheme, custody_mode, old_key_id,
                      new_key_id, identity_binding_digest, protected_options,
                      authority_binding, root_signatures, old_key_signature,
                      created_at, expires_at)
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING operation_id
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
                    operation.new_key_id,
                    operation.identity_binding_digest,
                    psycopg.types.json.Jsonb(dict(operation.protected_options)),
                    psycopg.types.json.Jsonb(
                        operation.authority.to_dict() if operation.authority is not None else None
                    ),
                    psycopg.types.json.Jsonb(
                        [
                            dict(item)
                            for item in _normalize_root_signatures(operation.root_signatures)
                        ]
                    ),
                    operation.old_key_signature,
                    operation.created_at,
                    operation.expires_at,
                ],
            ).fetchone()
            if inserted is not None:
                return None
            existing = conn.execute(
                    "SELECT * FROM lifecycle_operations WHERE idempotency_key = %s",
                    [operation.idempotency_key],
            ).fetchone()
            if existing is None or existing["digest_value"] != operation.digest.value:
                raise LifecycleContractError(
                    LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                    f"Idempotency key {operation.idempotency_key!r} "
                    "is bound to another request",
                )
            return self._operation_from_row(existing)

    @staticmethod
    def _operation_from_row(row: dict[str, Any]) -> LifecycleOperation:
        protected = row["protected_options"]
        if isinstance(protected, dict):
            protected_options = tuple(sorted((str(k), str(v)) for k, v in protected.items()))
        else:
            protected_options = ()
        custody_mode = row["custody_mode"]
        public_key = row["public_key"]
        raw_authority = row.get("authority_binding")
        authority: LifecycleAuthority | None = None
        if isinstance(raw_authority, dict):
            try:
                authority = LifecycleAuthority(
                    authority=LifecycleAuthorityKind(raw_authority["authority"]),
                    principal_id=str(raw_authority["principal_id"]),
                    key_id=str(raw_authority["key_id"]),
                    key_binding_event_hash=str(raw_authority["key_binding_event_hash"]),
                    delegation_event_hash=(
                        str(raw_authority["delegation_event_hash"])
                        if raw_authority.get("delegation_event_hash") is not None
                        else None
                    ),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "durable lifecycle operation contains an invalid authority binding",
                ) from exc
            if authority.principal_id != str(row["actor_id"]):
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "durable lifecycle authority is bound to a different actor",
                )
            if authority.authority.value != str(row["requested_authority"]):
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "durable lifecycle authority does not match requested authority",
                )
            if authority.authority is LifecycleAuthorityKind.ROOT:
                if authority.delegation_event_hash is not None:
                    raise LifecycleContractError(
                        LifecycleErrorCode.AUTHORITY_MISMATCH,
                        "root lifecycle authority cannot carry a delegation event",
                    )
            elif authority.delegation_event_hash != authority.key_binding_event_hash:
                raise LifecycleContractError(
                    LifecycleErrorCode.AUTHORITY_MISMATCH,
                    "registrar lifecycle authority must bind to its delegation event",
                )
        raw_root_signatures = row.get("root_signatures")
        root_signatures = (
            _normalize_root_signatures(raw_root_signatures)
            if isinstance(raw_root_signatures, list)
            and all(isinstance(item, dict) for item in raw_root_signatures)
            else ()
        )
        return LifecycleOperation(
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
            new_key_id=row.get("new_key_id"),
            identity_binding_digest=row["identity_binding_digest"],
            protected_options=protected_options,
            authority=authority,
            root_signatures=root_signatures,
            old_key_signature=(
                bytes(row["old_key_signature"])
                if row.get("old_key_signature") is not None
                else None
            ),
        )

    def _load_operation_from_db(self, operation_id: str) -> LifecycleOperation:
        """Rehydrate an operation from durable storage.

        Operations are durable and may be resumed by a fresh ``PrincipalLifecycle``
        instance.  Challenges are deliberately process-local and one-use, so this
        method does not rehydrate challenges.
        """
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            row = conn.execute(
                    "SELECT * FROM lifecycle_operations WHERE operation_id = %s AND project = %s",
                    [operation_id, self._project],
            ).fetchone()
        if row is None:
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_NOT_FOUND,
                f"Lifecycle operation {operation_id!r} was not prepared",
            )
        operation = self._operation_from_row(row)
        self._operations[operation_id] = operation
        return operation

    @staticmethod
    def _challenge_kind(challenge: PossessionChallenge | EffectiveChallenge) -> str:
        if isinstance(challenge, EffectiveChallenge):
            return "effective"
        if isinstance(challenge, PossessionChallenge):
            return "possession"
        assert_never(challenge)

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
                     verifier_nonce, issued_at, expires_at, used, kind,
                     trust_domain_id, enrollment_request_digest)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, false, %s, %s, %s)
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
                    self._challenge_kind(challenge),
                    getattr(challenge, "trust_domain_id", None),
                    getattr(challenge, "enrollment_request_digest", None),
                ],
            )

    @staticmethod
    def _challenge_from_row(row: dict[str, Any]) -> PossessionChallenge | EffectiveChallenge:
        common = {
            "challenge_id": str(row["challenge_id"]),
            "operation_id": str(row["operation_id"]),
            "operation_digest": row["operation_digest"],
            "project": row["project"],
            "principal_id": row["principal_id"],
            "fingerprint": row["fingerprint"],
            "scheme": row["scheme"],
            "verifier_nonce": row["verifier_nonce"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
        }
        if row["kind"] == "effective":
            return EffectiveChallenge(**common)
        # v2 fields are part of the SIGNED challenge body, so a rehydrated
        # challenge must reproduce them exactly or submit_possession would verify
        # against different bytes than the client signed (migration 047).
        trust_domain_id = row.get("trust_domain_id")
        return PossessionChallenge(
            **common,
            trust_domain_id=str(trust_domain_id) if trust_domain_id is not None else None,
            enrollment_request_digest=row.get("enrollment_request_digest"),
        )

    def _fetch_challenge(
        self,
        challenge_id: str,
        *,
        expected_kind: str,
        expected_operation_digest: str,
        operation_id: str,
    ) -> PossessionChallenge | EffectiveChallenge:
        """Validate a challenge without consuming it.

        Non-mutating, so a caller can verify a signature before burning the
        challenge. Durable mode reads the database authoritatively — a stale
        local record (the issuer's, after another instance consumed) never
        masks a committed consumption; non-durable mode uses the local record.
        """
        if not self._durable:
            record = self._challenges.get(challenge_id)
            if record is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                    f"Challenge {challenge_id!r} was not issued by this verifier",
                )
            if record.used:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                    f"Challenge {challenge_id!r} has already been used",
                )
            self._validate_challenge_binding(
                record.challenge,
                expected_kind=expected_kind,
                expected_operation_digest=expected_operation_digest,
                operation_id=operation_id,
            )
            return record.challenge
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            row = conn.execute(
                    "SELECT challenge_id, operation_id, operation_digest, project, "
                    "principal_id, fingerprint, scheme, verifier_nonce, "
                    "issued_at, expires_at, kind, used, "
                    # v2 fields are inside the SIGNED challenge body, so omitting
                    # them here would rehydrate a challenge whose signing bytes
                    # differ from the ones the client signed (migration 047).
                    "trust_domain_id, enrollment_request_digest "
                    "FROM lifecycle_challenges WHERE challenge_id = %s",
                    [challenge_id],
            ).fetchone()
        if row is None:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                f"Challenge {challenge_id!r} was not issued by this verifier",
            )
        if row["used"]:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                f"Challenge {challenge_id!r} has already been used",
            )
        challenge = self._challenge_from_row(row)
        self._validate_challenge_binding(
            challenge,
            expected_kind=expected_kind,
            expected_operation_digest=expected_operation_digest,
            operation_id=operation_id,
        )
        return challenge

    def _validate_challenge_binding(
        self,
        challenge: PossessionChallenge | EffectiveChallenge,
        *,
        expected_kind: str,
        expected_operation_digest: str,
        operation_id: str,
    ) -> None:
        if self._challenge_kind(challenge) != expected_kind:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                f"Challenge {challenge.challenge_id!r} is not a {expected_kind} challenge",
            )
        if self._now() >= challenge.expires_at:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_EXPIRED,
                f"Challenge {challenge.challenge_id!r} has expired",
            )
        if challenge.operation_id != operation_id:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                f"Challenge {challenge.challenge_id!r} does not bind to this operation",
            )
        if not hmac.compare_digest(challenge.operation_digest, expected_operation_digest):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                f"Challenge {challenge.challenge_id!r} does not bind to this operation",
            )

    def _validate_receipt_chronology(
        self, receipt: EffectiveReceipt, challenge: EffectiveChallenge
    ) -> None:
        """Enforce observed_at is timezone-aware and within the challenge window.

        The window is widened by the configured clock skew (a small constant,
        not an open-ended replay window) to tolerate realistic client/verifier
        clock drift. Applies to every effective receipt that carries a
        challenge — signed or an unsigned report — so direct API callers cannot
        bypass it.
        """
        if receipt.observed_at.tzinfo is None or receipt.observed_at.utcoffset() is None:
            raise LifecycleContractError(
                LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID,
                "Effective receipt observed_at must be timezone-aware",
            )
        skew = self._effective_receipt_clock_skew
        if receipt.observed_at < challenge.issued_at - skew:
            raise LifecycleContractError(
                LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID,
                f"Effective receipt observed_at {receipt.observed_at!r} predates "
                f"the challenge window (issued_at={challenge.issued_at!r}, skew={skew})",
            )
        if receipt.observed_at > challenge.expires_at + skew:
            raise LifecycleContractError(
                LifecycleErrorCode.RECEIPT_OBSERVED_AT_INVALID,
                f"Effective receipt observed_at {receipt.observed_at!r} is after "
                f"the challenge window (expires_at={challenge.expires_at!r}, skew={skew})",
            )

    def _consume_challenge(
        self,
        challenge_id: str,
        *,
        expected_kind: str,
        expected_operation_digest: str,
        operation_id: str,
    ) -> PossessionChallenge | EffectiveChallenge:
        """Atomically mark a one-use challenge consumed and return it.

        Durable mode always arbitrates via the atomic ``UPDATE ... WHERE used =
        false`` gate, even when a local record exists, so a replay landing on
        the issuer after another instance consumed is still rejected; the local
        cache is refreshed only after commit. Non-durable mode uses the local
        record. Callers pairing consumption with a state transition use
        :meth:`_consume_challenge_conn` inside their own transaction instead.
        """
        if not self._durable:
            record = self._challenges.get(challenge_id)
            if record is None:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                    f"Challenge {challenge_id!r} was not issued by this verifier",
                )
            if record.used:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                    f"Challenge {challenge_id!r} has already been used",
                )
            self._validate_challenge_binding(
                record.challenge,
                expected_kind=expected_kind,
                expected_operation_digest=expected_operation_digest,
                operation_id=operation_id,
            )
            record.used = True
            return record.challenge
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            challenge = self._consume_challenge_conn(
                conn,
                challenge_id,
                expected_kind=expected_kind,
                expected_operation_digest=expected_operation_digest,
                operation_id=operation_id,
            )
        self._challenges[challenge_id] = _ChallengeRecord(challenge, used=True)
        return challenge

    def _consume_challenge_conn(
        self,
        conn: DictConn,
        challenge_id: str,
        *,
        expected_kind: str,
        expected_operation_digest: str,
        operation_id: str,
        proof_signature: str | None = None,
    ) -> PossessionChallenge | EffectiveChallenge:
        """Atomically consume a challenge within the caller's transaction.

        Pairs with the caller's operation transition so both commit or roll back
        together. Does not commit and does not touch the local cache (the caller
        refreshes it after commit). Raises a stable contract error, via a
        diagnostic re-read, when the atomic update matches no row.
        """
        row =             conn.execute(
                """
                UPDATE lifecycle_challenges
                SET used = true, proof_signature = COALESCE(%s, proof_signature)
                WHERE challenge_id = %s
                  AND used = false
                  AND kind = %s
                  AND operation_id = %s
                  AND operation_digest = %s
                RETURNING challenge_id, operation_id, operation_digest, project,
                          principal_id, fingerprint, scheme, verifier_nonce,
                          issued_at, expires_at, kind,
                          trust_domain_id, enrollment_request_digest
                """,
                [
                    proof_signature,
                    challenge_id,
                    expected_kind,
                    operation_id,
                    expected_operation_digest,
                ],
        ).fetchone()
        if row is not None:
            challenge = self._challenge_from_row(row)
            if self._now() >= challenge.expires_at:
                raise LifecycleContractError(
                    LifecycleErrorCode.CHALLENGE_EXPIRED,
                    f"Challenge {challenge_id!r} has expired",
                )
            return challenge
        existing =             conn.execute(
                "SELECT used, kind, operation_id, operation_digest, expires_at "
                "FROM lifecycle_challenges WHERE challenge_id = %s",
                [challenge_id],
        ).fetchone()
        if existing is None:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_NOT_FOUND,
                f"Challenge {challenge_id!r} was not issued by this verifier",
            )
        if existing["used"]:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_ALREADY_USED,
                f"Challenge {challenge_id!r} has already been used",
            )
        if existing["kind"] != expected_kind:
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                f"Challenge {challenge_id!r} is not a {expected_kind} challenge",
            )
        if (
            str(existing["operation_id"]) != operation_id
            or not hmac.compare_digest(
                existing["operation_digest"], expected_operation_digest
            )
        ):
            raise LifecycleContractError(
                LifecycleErrorCode.PROOF_BINDING_MISMATCH,
                f"Challenge {challenge_id!r} does not bind to this operation",
            )
        if self._now() >= existing["expires_at"]:
            raise LifecycleContractError(
                LifecycleErrorCode.CHALLENGE_EXPIRED,
                f"Challenge {challenge_id!r} has expired",
            )
        raise LifecycleContractError(
            LifecycleErrorCode.CHALLENGE_ALREADY_USED,
            f"Challenge {challenge_id!r} could not be consumed",
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
        existing = self._existing_durable_for_request(
            operation_type,
            request,
            idempotency_key=idempotency_key,
            old_key_id=old_key_id,
            protected_options=protected,
        )
        if existing is not None:
            return existing
        created_at, expires_at = self._time_window(ttl)
        authority = self._resolve_authority_binding(operation_type, request, at=created_at)
        new_key_id = (
            None
            if operation_type is LifecycleOperationType.REVOCATION
            else _lifecycle_key_id(idempotency_key)
        )
        intent = _intent_digest(
            operation_type,
            self._project,
            request,
            old_key_id=old_key_id,
            protected_options=protected,
            authority=authority,
        )
        existing = self._existing_idempotent(idempotency_key, intent)
        if existing is not None:
            return existing
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
            authority=authority,
            new_key_id=new_key_id,
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
            new_key_id=new_key_id,
            identity_binding_digest=request.identity_binding_digest,
            protected_options=protected,
            authority=authority,
            root_signatures=_normalize_root_signatures(request.root_signatures),
            old_key_signature=(
                request.old_key_signature if isinstance(request, RotationRequest) else None
            ),
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
        canonical = operation
        if self._durable:
            persisted = self._persist_operation(operation, intent)
            if persisted is not None:
                canonical = persisted
        self._operations[canonical.operation_id] = canonical
        self._idempotency[canonical.idempotency_key] = (intent, canonical.operation_id)
        return canonical

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

    def _existing_durable_for_request(
        self,
        operation_type: LifecycleOperationType,
        request: EnrollmentRequest | RevocationRequest,
        *,
        idempotency_key: str,
        old_key_id: str | None,
        protected_options: tuple[tuple[str, str], ...],
    ) -> LifecycleOperation | None:
        """Load an idempotent operation before resolving live authority.

        A retry is a read of the original prepared intent. Re-resolving a
        registrar before checking the durable idempotency row would make an
        otherwise safe retry fail merely because that delegation expired or was
        revoked after the first request.
        """

        if not self._durable:
            return None
        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM lifecycle_operations "
                "WHERE idempotency_key = %s AND project = %s",
                [idempotency_key, self._project],
            ).fetchone()
        if row is None:
            return None
        existing = self._operation_from_row(row)
        existing_intent = _intent_digest(
            existing.operation_type,
            self._project,
            _request_from_operation(existing),
            old_key_id=existing.old_key_id,
            protected_options=existing.protected_options,
            authority=existing.authority,
        )
        candidate_intent = _intent_digest(
            operation_type,
            self._project,
            request,
            old_key_id=old_key_id,
            protected_options=protected_options,
            authority=existing.authority,
        )
        if not hmac.compare_digest(existing_intent, candidate_intent):
            raise LifecycleContractError(
                LifecycleErrorCode.OPERATION_DIGEST_MISMATCH,
                f"Idempotency key {idempotency_key!r} is bound to another request",
            )
        self._operations[existing.operation_id] = existing
        self._idempotency[idempotency_key] = (existing_intent, existing.operation_id)
        return existing

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


def _lifecycle_event_hash(event: Any) -> str:
    """``"sha256:" + hex`` of the appended lifecycle event, for the projection row.

    Uses the v6 construction when the event carries a v6 envelope, and the legacy
    ``sha256(canonical_envelope || signature)`` head-hash construction otherwise, so
    an estate still on HMAC signing gets a stable, honest provenance value rather
    than a fabricated one. Either way, the row names the event it came from.
    """
    envelope = getattr(event, "canonical_envelope", None)
    signature = getattr(event, "signature", None)
    if envelope is None or signature is None:
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_OPERATION_STATE,
            "committed lifecycle event has no canonical envelope or signature, so the "
            "projection row would have no source event to name",
        )
    # Scheme-class membership from the registry's own predicate (NB3). The rebuild
    # imports the same function, which is what guarantees the two hash
    # constructions cannot diverge.
    if is_v6_scheme(getattr(event, "scheme_id", None)):
        from ._signing import compute_v6_event_hash

        return "sha256:" + compute_v6_event_hash(bytes(envelope), bytes(signature)).hex()
    return "sha256:" + hashlib.sha256(bytes(envelope) + bytes(signature)).hexdigest()


def _enrollment_request_digest(operation: LifecycleOperation) -> str:
    """``sha256:`` over the canonical enrolment request the challenge binds to (§5.5).

    Derived from the operation's own identifying fields so it is reproducible from
    stored state — the challenge persists it (migration 047) and the payload repeats
    it, and the two must agree.
    """
    from ._trust_log import enrollment_request_digest

    return enrollment_request_digest(
        {
            "operation_id": operation.operation_id,
            "principal_id": operation.principal_id,
            "principal_kind": operation.principal_kind.value,
            "operation_type": operation.operation_type.value,
            "fingerprint": operation.fingerprint,
            "scheme": operation.scheme,
        }
    )


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
    authority: LifecycleAuthority | None,
    new_key_id: str | None = None,
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
        "new_key_id": new_key_id,
        "identity_binding_digest": request.identity_binding_digest,
        "protected_options": dict(protected_options),
        "authority": authority.to_dict() if authority is not None else None,
    }


def _intent_digest(
    operation_type: LifecycleOperationType,
    project: str,
    request: EnrollmentRequest | RevocationRequest,
    *,
    old_key_id: str | None,
    protected_options: tuple[tuple[str, str], ...],
    authority: LifecycleAuthority | None,
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
        "authority": authority.to_dict() if authority is not None else None,
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
    try:
        LifecycleAuthorityKind(request.requested_authority)
    except ValueError as exc:
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_REQUEST,
            "requested_authority must be 'root' or 'registrar'",
        ) from exc


def _lifecycle_key_id(idempotency_key: str) -> str:
    """Derive a stable new-key id without inventing a commit-time value."""

    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:24]
    return f"pk_lifecycle_{digest}"


def _request_from_operation(
    operation: LifecycleOperation,
) -> EnrollmentRequest | RevocationRequest:
    """Reconstruct the intent-bearing request fields from a durable operation."""

    if operation.operation_type is LifecycleOperationType.REVOCATION:
        if operation.old_key_id is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "durable revocation operation has no key id",
            )
        return RevocationRequest(
            principal_id=operation.principal_id,
            principal_kind=operation.principal_kind,
            actor_id=operation.actor_id,
            key_id=operation.old_key_id,
            reason=operation.reason,
            requested_authority=operation.requested_authority,
            policy_version=operation.policy_version,
            identity_binding_digest=operation.identity_binding_digest,
            protected_options=operation.protected_options,
        )
    if (
        operation.public_key is None
        or operation.scheme is None
        or operation.custody_mode is None
    ):
        raise LifecycleContractError(
            LifecycleErrorCode.AUTHORITY_MISMATCH,
            "durable key operation is missing public key material",
        )
    if operation.operation_type is LifecycleOperationType.ROTATION:
        if operation.old_key_id is None:
            raise LifecycleContractError(
                LifecycleErrorCode.AUTHORITY_MISMATCH,
                "durable rotation operation has no superseded key id",
            )
        return RotationRequest(
            principal_id=operation.principal_id,
            principal_kind=operation.principal_kind,
            actor_id=operation.actor_id,
            public_key=operation.public_key,
            scheme=operation.scheme,
            custody_mode=operation.custody_mode,
            reason=operation.reason,
            requested_authority=operation.requested_authority,
            policy_version=operation.policy_version,
            old_key_id=operation.old_key_id,
            identity_binding_digest=operation.identity_binding_digest,
            protected_options=operation.protected_options,
        )
    if operation.operation_type is LifecycleOperationType.ENROLLMENT:
        return EnrollmentRequest(
            principal_id=operation.principal_id,
            principal_kind=operation.principal_kind,
            actor_id=operation.actor_id,
            public_key=operation.public_key,
            scheme=operation.scheme,
            custody_mode=operation.custody_mode,
            reason=operation.reason,
            requested_authority=operation.requested_authority,
            policy_version=operation.policy_version,
            identity_binding_digest=operation.identity_binding_digest,
            protected_options=operation.protected_options,
        )
    assert_never(operation.operation_type)


def _protected_options(options: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    names = [name for name, _value in options]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise LifecycleContractError(
            LifecycleErrorCode.INVALID_REQUEST,
            "protected_options names must be non-empty and unique",
        )
    return tuple(sorted(options))


def _normalize_root_signatures(
    signatures: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], ...]:
    """Return detached root signatures in one deterministic order.

    The root-signature array is detached from the signed rotation core, so its
    authoring order carries no meaning. Sorting by the complete identifying
    fields makes retries with the same signature set idempotent even when
    signers respond in a different order. The parser remains responsible for
    rejecting malformed or duplicate records.
    """

    normalized = [dict(signature) for signature in signatures]
    normalized.sort(
        key=lambda signature: (
            str(signature.get("fingerprint", "")),
            str(signature.get("signer_id", "")),
            str(signature.get("signature", "")),
        )
    )
    return tuple(normalized)


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
    # Always six fractional digits + trailing Z, matching the verifier's reconstruction
    # (``_trust_log`` parses with ``%f`` and the CLI re-emits with the same form). Plain
    # ``isoformat()`` OMITS the fraction when microsecond == 0 (``...:56Z`` not
    # ``...:56.000000Z``), so a challenge issued at a µs==0 boundary framed one way here
    # and the other way at verification would never match — enrolment would always fail.
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


__all__ = [
    "CONTRACT_VERSION",
    "EFFECTIVE_DOMAIN",
    "EFFECTIVE_RECEIPT_CLOCK_SKEW",
    "EFFECTIVE_RECEIPT_DOMAIN",
    "Approval",
    "ApprovalVerifier",
    "ChallengeStorageScope",
    "CustodyMode",
    "EffectiveChallenge",
    "EffectiveReceipt",
    "EffectiveReceiptStatus",
    "EnrollmentRequest",
    "LifecycleAuthority",
    "LifecycleAuthorityKind",
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
