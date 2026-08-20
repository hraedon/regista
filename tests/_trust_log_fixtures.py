"""Test fixtures for trust-domain-log events and durable possession evidence.

The stored-row helpers use ephemeral Ed25519 keys and direct inserts for replay tests;
WI301/WI303 writer fixtures also persist the consumed challenge that backs each event.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import nacl.signing
import psycopg

from regista._principal_keys import _compute_fingerprint
from regista._signing import compute_v6_event_hash, sign_v6_envelope
from regista._trust_log import (
    POSSESSION_DOMAIN_V2,
    PossessionChallengeV2,
    enrollment_request_digest,
    expected_entity_kind,
    old_key_signature_input,
    root_signature_input,
)

_VECTOR = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"

TRUST_LOG_NAME_HINT = "regista_trust"


def _ts(offset_seconds: int = 0) -> str:
    """A fixture timestamp anchored to real ``now`` plus ``offset_seconds``.

    The trust-log writer admits a possession challenge only if its ``expires_at`` is
    still in the future relative to ``datetime.now(UTC)`` (``_trust_log_writer.py``
    :961 append admission, :1761 the append path's ``admission_at``). A *fixed* base
    (this was ``datetime(2026, 8, 20)``) therefore made every challenge a time bomb:
    once real wall-clock time passed base + 5 min, admission failed for the whole
    suite with ``possession_challenge_expired_at_admission``. Anchoring the base to
    ``now`` keeps each challenge "recently issued" relative to the admission moment,
    while the ``offset_seconds`` argument preserves the *relative* spacing the fixture
    chains rely on (issued_at at 0, expires_at at +300, revoked_at at +60, …). This
    clock never feeds a committed vector — the ``tests/vectors/`` envelopes carry
    their own fixed ``occurred_at`` — so relative time introduces no nondeterminism
    into any hash-pinned assertion. Deliberately-expired negative fixtures pass an
    explicit past ``expires_at`` and stay expired regardless of this anchor.
    """
    base = datetime.now(UTC) + timedelta(seconds=offset_seconds)
    return base.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# Anchored once at import so every event in a single fixture chain shares one
# ``occurred_at`` (deterministic within a run), while still moving with the clock
# across runs so it never falls behind a challenge's live admission window.
DEFAULT_OCCURRED_AT = _ts()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@dataclass
class TrustLogKey:
    """An ephemeral Ed25519 keypair with its wire identifiers."""

    key_id: str
    seed: bytes
    public_key: bytes
    fingerprint: str

    @classmethod
    def mint(cls, key_id: str) -> TrustLogKey:
        signing_key = nacl.signing.SigningKey.generate()
        public = bytes(signing_key.verify_key)
        return cls(
            key_id=key_id,
            seed=bytes(signing_key),
            public_key=public,
            fingerprint=_compute_fingerprint(public, "ed25519"),
        )

    def sign(self, message: bytes) -> bytes:
        return nacl.signing.SigningKey(self.seed).sign(message).signature


@dataclass
class StoredEvent:
    event_id: str
    transition: str
    entity_kind: str
    entity_id: str
    entity_seq: int
    payload: dict[str, Any]
    event_hash: str  # "sha256:<hex>"
    canonical_envelope: bytes
    signature: bytes
    occurred_at: str


@dataclass
class TrustLogStore:
    """A project schema holding stored, signed v6 trust-log events."""

    dsn: str
    project: str
    trust_domain_id: str
    project_instance_id: str
    events: list[StoredEvent] = field(default_factory=list)
    _next_seq: dict[tuple[str, str], int] = field(default_factory=dict)
    _entity_head: dict[tuple[str, str], str] = field(default_factory=dict)

    def next_entity_seq(self, entity_kind: str, entity_id: str) -> int:
        key = (entity_kind, entity_id)
        # entity_seq is per (entity_kind, entity_id) and starts at 1.
        self._next_seq[key] = self._next_seq.get(key, 0) + 1
        return self._next_seq[key]

    def entity_head(self, entity_kind: str, entity_id: str) -> str | None:
        """Previous event hash for this entity's chain, or None at entity_seq 1.

        The v6 envelope rules are strict about the pairing: entity_seq 1 REQUIRES a
        null previous_entity_event_hash, and anything above it requires a non-null
        one (_verification.py:619-627).
        """
        return self._entity_head.get((entity_kind, entity_id))

    def record_head(self, entity_kind: str, entity_id: str, event_hash: str) -> None:
        self._entity_head[(entity_kind, entity_id)] = event_hash


# ---------------------------------------------------------------------------
# Payload builders — spec-shaped by construction (§5.3-§5.7)
# ---------------------------------------------------------------------------


def make_possession_challenge(
    *,
    trust_domain_id: str,
    principal_id: str,
    fingerprint: str,
    project: str = TRUST_LOG_NAME_HINT,
    operation_id: str | None = None,
    operation_digest: str | None = None,
    request: dict[str, Any] | None = None,
    challenge_id: str | None = None,
    verifier_nonce: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
) -> PossessionChallengeV2:
    return PossessionChallengeV2(
        challenge_id=challenge_id or str(uuid.uuid4()),
        operation_id=operation_id or str(uuid.uuid4()),
        operation_digest=operation_digest or "sha256:" + "0" * 64,
        project=project,
        trust_domain_id=trust_domain_id,
        principal_id=principal_id,
        fingerprint=fingerprint,
        scheme="ed25519",
        verifier_nonce=verifier_nonce or hashlib.sha256(
            (challenge_id or principal_id).encode()
        ).hexdigest(),
        enrollment_request_digest=enrollment_request_digest(
            request if request is not None else {"principal_id": principal_id}
        ),
        issued_at=issued_at or _ts(),
        expires_at=expires_at or _ts(300),
    )


def make_authorized_by(
    *,
    authority: str = "registrar",
    principal_id: str = "service:registrar-1",
    key_id: str = "pk_registrar_1",
    delegation_event_hash: str | None = None,
) -> dict[str, Any]:
    if authority == "registrar" and delegation_event_hash is None:
        delegation_event_hash = "sha256:" + "a" * 64
    if authority == "root":
        delegation_event_hash = None
    return {
        "authority": authority,
        "principal_id": principal_id,
        "key_id": key_id,
        "delegation_event_hash": delegation_event_hash,
    }


def make_enrollment_payload(
    *,
    trust_domain_id: str,
    principal_id: str,
    key: TrustLogKey,
    principal_kind: str = "agent",
    not_before: str | None = None,
    not_after: str | None = None,
    authorized_by: dict[str, Any] | None = None,
    challenge: PossessionChallengeV2 | None = None,
    custody_backend: str = "file",
    omit_public_key: bool = False,
    fingerprint_override: str | None = None,
) -> dict[str, Any]:
    """A §5.5 ``principal_key_enrolled`` payload.

    ``omit_public_key`` drops the mandatory field, for §9 criterion 16.
    ``fingerprint_override`` states a fingerprint that disagrees with the bytes.
    """
    challenge = challenge or make_possession_challenge(
        trust_domain_id=trust_domain_id,
        principal_id=principal_id,
        fingerprint=key.fingerprint,
    )
    signature = key.sign(challenge.signing_input())
    payload: dict[str, Any] = {
        "type": "regista.key-enrollment",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "principal_id": principal_id,
        "principal_kind": principal_kind,
        "key_id": key.key_id,
        "scheme_id": "ed25519",
        "public_key": _b64(key.public_key),
        "fingerprint": fingerprint_override or key.fingerprint,
        "not_before": not_before or _ts(),
        "not_after": not_after,
        "possession_proof": {
            "domain": POSSESSION_DOMAIN_V2,
            "challenge_id": challenge.challenge_id,
            "verifier_nonce": challenge.verifier_nonce,
            "enrollment_request_digest": challenge.enrollment_request_digest,
            "signature": _b64(signature),
        },
        "authorized_by": authorized_by or make_authorized_by(),
        "custody": {
            "declared_backend": custody_backend,
            "declared_policy_ref": "policy://test/custody/v1",
        },
        "supersedes_key_id": None,
    }
    if omit_public_key:
        del payload["public_key"]
    return payload


def persist_consumed_possession_challenge(
    conn: Any,
    challenge: PossessionChallengeV2,
    proof_signature: str,
    *,
    used: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO lifecycle_operations "
        "(operation_id, idempotency_key, operation_type, state, project, principal_id, "
        "principal_kind, actor_id, reason, requested_authority, policy_version, "
        "digest_value, digest_algorithm, digest_version, public_key, fingerprint, "
        "scheme, custody_mode, old_key_id, identity_binding_digest, protected_options, "
        "created_at, expires_at) "
        "VALUES (%s, %s, 'enrollment', 'awaiting_approval', %s, %s, 'agent', "
        "'service:registrar-1', 'fixture', 'registrar', 'fixture', %s, 'sha-256', "
        "'fixture', NULL, %s, %s, 'file', NULL, NULL, '{}'::jsonb, %s, %s) "
        "ON CONFLICT (operation_id) DO NOTHING",
        [
            uuid.UUID(challenge.operation_id),
            "fixture-" + challenge.challenge_id,
            challenge.project,
            challenge.principal_id,
            challenge.operation_digest,
            challenge.fingerprint,
            challenge.scheme,
            challenge.issued_at,
            challenge.expires_at,
        ],
    )
    conn.execute(
        "INSERT INTO lifecycle_challenges "
        "(challenge_id, operation_id, operation_digest, project, principal_id, "
        "fingerprint, scheme, verifier_nonce, issued_at, expires_at, used, kind, "
        "trust_domain_id, enrollment_request_digest, proof_signature) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'possession', %s, %s, %s)",
        [
            uuid.UUID(challenge.challenge_id),
            uuid.UUID(challenge.operation_id),
            challenge.operation_digest,
            challenge.project,
            challenge.principal_id,
            challenge.fingerprint,
            challenge.scheme,
            challenge.verifier_nonce,
            challenge.issued_at,
            challenge.expires_at,
            used,
            uuid.UUID(challenge.trust_domain_id),
            challenge.enrollment_request_digest,
            proof_signature,
        ],
    )


def make_rotation_payload(
    *,
    trust_domain_id: str,
    principal_id: str,
    key: TrustLogKey,
    supersedes_key_id: str,
    superseded_key: TrustLogKey | None = None,
    mode: str = "dual",
    recovery_reason: str | None = None,
    root_keys: list[TrustLogKey] | None = None,
    principal_kind: str = "agent",
    not_before: str | None = None,
    authorized_by: dict[str, Any] | None = None,
    challenge: PossessionChallengeV2 | None = None,
) -> dict[str, Any]:
    """A §5.6 ``principal_key_rotated`` payload, correctly self-signed.

    ``mode="dual"`` signs with ``superseded_key``; ``mode="recovery"`` collects
    detached root signatures from ``root_keys`` instead (Resolution 5 / D-8). Both
    signatures are computed over the payload's authorisation core, so the fixture
    produces material that actually verifies rather than placeholder bytes.
    """
    base = make_enrollment_payload(
        trust_domain_id=trust_domain_id,
        principal_id=principal_id,
        key=key,
        principal_kind=principal_kind,
        not_before=not_before,
        authorized_by=authorized_by,
        challenge=challenge,
    )
    payload = dict(base)
    payload["type"] = "regista.key-rotation"
    payload["supersedes_key_id"] = supersedes_key_id
    payload["dual_authorization"] = {
        "old_key_signature": None,
        "mode": mode,
        "recovery_reason": recovery_reason if mode == "recovery" else None,
    }
    payload["root_signatures"] = []

    if mode == "dual":
        assert superseded_key is not None, "dual rotation needs the outgoing key"
        signature = superseded_key.sign(old_key_signature_input(payload))
        payload["dual_authorization"]["old_key_signature"] = _b64(signature)
    else:
        message = root_signature_input(payload)
        payload["root_signatures"] = [
            {
                "signer_id": f"root-{chr(ord('a') + i)}",
                "fingerprint": rk.fingerprint,
                "signature": _b64(rk.sign(message)),
            }
            for i, rk in enumerate(root_keys or [])
        ]
    return payload


def make_revocation_payload(
    *,
    trust_domain_id: str,
    principal_id: str,
    key_id: str,
    reason: str = "compromised",
    revoked_at: str | None = None,
    authorized_by: dict[str, Any] | None = None,
    retroactive: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A §5.7 ``principal_key_revoked`` payload."""
    return {
        "type": "regista.key-revocation",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "principal_id": principal_id,
        "key_id": key_id,
        "reason": reason,
        "revoked_at": revoked_at or _ts(60),
        "effective_from": {
            "kind": "on_chain_position",
            "trust_log_event_hash": "self",
        },
        "retroactive_suspicion": retroactive or {
            "declared": False,
            "suspect_from_event_hash": None,
            "note": None,
        },
        "authorized_by": authorized_by or make_authorized_by(),
    }


def make_registrar_delegation_payload(
    *,
    trust_domain_id: str,
    registrar_principal_id: str = "service:registrar-1",
    key: TrustLogKey | None = None,
    scopes: list[str] | None = None,
    not_before: str | None = None,
    not_after: str | None = None,
    max_operations: int | None = None,
    root_keys: list[TrustLogKey] | None = None,
) -> dict[str, Any]:
    """A §5.4 ``registrar_delegated`` payload, root-threshold signed."""
    key = key or TrustLogKey.mint("pk_registrar_1")
    payload: dict[str, Any] = {
        "type": "regista.registrar-delegation",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "registrar_principal_id": registrar_principal_id,
        "key_id": key.key_id,
        "scheme_id": "ed25519",
        "public_key": _b64(key.public_key),
        "fingerprint": key.fingerprint,
        "scopes": scopes or [
            "principal_key_enrolled",
            "principal_key_rotated",
            "principal_key_revoked",
        ],
        "not_before": not_before or _ts(),
        # 90 days ahead of the (now-anchored) base, so the delegation window stays
        # open across runs rather than expiring at a fixed 2026-11-18.
        "not_after": not_after or _ts(90 * 24 * 60 * 60),
        "max_operations": max_operations,
        "root_signatures": [],
    }
    message = root_signature_input(payload)
    payload["root_signatures"] = [
        {
            "signer_id": f"root-{chr(ord('a') + i)}",
            "fingerprint": rk.fingerprint,
            "signature": _b64(rk.sign(message)),
        }
        for i, rk in enumerate(root_keys or [])
    ]
    return payload


def make_registrar_revocation_payload(
    *,
    trust_domain_id: str,
    registrar_principal_id: str = "service:registrar-1",
    key_id: str = "pk_registrar_1",
    delegation_event_hash: str,
    reason: str = "compromised",
    root_keys: list[TrustLogKey] | None = None,
) -> dict[str, Any]:
    """A §5.4 ``registrar_revoked`` payload, root-threshold signed."""
    payload: dict[str, Any] = {
        "type": "regista.registrar-revocation",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "registrar_principal_id": registrar_principal_id,
        "key_id": key_id,
        "delegation_event_hash": delegation_event_hash,
        "reason": reason,
        "root_signatures": [],
    }
    message = root_signature_input(payload)
    payload["root_signatures"] = [
        {
            "signer_id": f"root-{chr(ord('a') + i)}",
            "fingerprint": root_key.fingerprint,
            "signature": _b64(root_key.sign(message)),
        }
        for i, root_key in enumerate(root_keys or [])
    ]
    return payload


def make_root_rotation_payload(
    *,
    trust_domain_id: str,
    added: list[TrustLogKey] | None = None,
    removed: list[str] | None = None,
    new_threshold: int,
    reason: str = "co-signer key replaced",
    effective_from_checkpoint_seq: int = 1,
    signing_root_keys: list[TrustLogKey] | None = None,
) -> dict[str, Any]:
    """A §5.4 ``trust_root_rotated`` payload signed by the *current* signer set."""
    payload: dict[str, Any] = {
        "type": "regista.trust-root-rotation",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "added": [
            {
                "signer_id": f"root-new-{i}",
                "scheme_id": "ed25519",
                "public_key": _b64(k.public_key),
                "fingerprint": k.fingerprint,
            }
            for i, k in enumerate(added or [])
        ],
        "removed": list(removed or []),
        "reason": reason,
        "effective_from_checkpoint_seq": effective_from_checkpoint_seq,
        "new_threshold": new_threshold,
        "root_signatures": [],
    }
    message = root_signature_input(payload)
    payload["root_signatures"] = [
        {
            "signer_id": f"root-{chr(ord('a') + i)}",
            "fingerprint": rk.fingerprint,
            "signature": _b64(rk.sign(message)),
        }
        for i, rk in enumerate(signing_root_keys or [])
    ]
    return payload


def make_trust_domain_established_payload(
    genesis_document: dict[str, Any],
    root_keys: list[TrustLogKey] | None = None,
) -> dict[str, Any]:
    """A §5.2 A-prime ``trust_domain_established`` payload restating the genesis.

    ``genesis_document_digest`` is the recomputed digest over the exact published
    genesis bytes (the shared ``genesis_document_digest``). When ``root_keys`` are
    supplied the payload carries detached root signatures over
    ``root_signature_input(payload)``; otherwise it ends with an empty
    ``root_signatures`` array (structurally valid; threshold is a verify-time rule).
    """
    from regista._trust_domain import genesis_document_digest
    from regista._trust_log import root_signature_input

    payload: dict[str, Any] = {
        "type": "regista.trust-domain-established",
        "version": 1,
        "trust_domain_id": genesis_document["trust_domain_id"],
        "trust_domain_core_digest": genesis_document["trust_domain_core_digest"],
        "binding_core": copy.deepcopy(genesis_document["binding_core"]),
        "initial_governance": copy.deepcopy(genesis_document["initial_governance"]),
        "genesis_document_digest": genesis_document_digest(genesis_document),
        "trust_log_project_instance_id": genesis_document["trust_log"][
            "project_instance_id"
        ],
    }
    signatures: list[dict[str, Any]] = []
    if root_keys:
        message = root_signature_input(payload)
        signatures = [
            {
                "signer_id": key.principal_id if hasattr(key, "principal_id") else key.key_id,
                "fingerprint": key.fingerprint,
                "signature": _b64(key.sign(message)),
            }
            for key in root_keys
        ]
    payload["root_signatures"] = signatures
    return payload


def make_custody_declaration_payload(
    *,
    trust_domain_id: str,
    fingerprints: list[str],
    declaration_seq: int = 1,
    supersedes_declaration_digest: str | None = None,
    reason: str = "initial custody declaration",
    root_keys: list[TrustLogKey] | None = None,
    declared_mode: str = "offline-host",
) -> dict[str, Any]:
    """A WI-292 ``trust_domain_custody_declared`` payload."""
    payload: dict[str, Any] = {
        "type": "regista.trust-domain-custody",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "declaration_seq": declaration_seq,
        "supersedes_declaration_digest": supersedes_declaration_digest,
        # Sorted ascending, matching the genesis `initial_custody` ordering rule.
        "custody": [
            {
                "fingerprint": fp,
                "declared_mode": declared_mode,
                "declared_holder": f"human:holder-{i}",
                "attestation": None,
            }
            for i, fp in enumerate(sorted(fingerprints))
        ],
        "reason": reason,
        "root_signatures": [],
    }
    message = root_signature_input(payload)
    payload["root_signatures"] = [
        {
            "signer_id": f"root-{chr(ord('a') + i)}",
            "fingerprint": rk.fingerprint,
            "signature": _b64(rk.sign(message)),
        }
        for i, rk in enumerate(root_keys or [])
    ]
    return payload


# ---------------------------------------------------------------------------
# Envelope construction and storage
# ---------------------------------------------------------------------------


def build_v6_envelope(
    *,
    transition: str,
    payload: dict[str, Any],
    trust_domain_id: str,
    project_instance_id: str,
    entity_id: str,
    entity_seq: int,
    signing_key: TrustLogKey,
    actor_principal_id: str,
    key_binding_event_hash: str | None,
    previous_entity_event_hash: str | None = None,
    previous_project_event_hash: str | None = None,
    occurred_at: str | None = None,
    entity_kind: str | None = None,
) -> dict[str, Any]:
    """A v6 envelope for a trust-log event, in the shape the Gate 0 vector fixes."""
    return {
        "type": "regista.event",
        "version": 6,
        "event_id": str(uuid.uuid4()),
        "project_instance_id": project_instance_id,
        "trust_domain_id": trust_domain_id,
        "entity": {
            "kind": entity_kind or expected_entity_kind(transition),
            "id": entity_id,
        },
        "entity_seq": entity_seq,
        "occurred_at": occurred_at or DEFAULT_OCCURRED_AT,
        # v6 envelope actor.kind is the closed execution-kind set
        # {agent, human, system} (_verification._V6_ACTOR_KINDS) — distinct from a
        # principal's kind. A trust-log writer is a system actor.
        "actor": {
            "kind": "system",
            "metadata": {},
            "principal_id": actor_principal_id,
        },
        "authorization": {"credentials": [], "mode": "direct"},
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": previous_entity_event_hash,
            "previous_project_event_hash": previous_project_event_hash,
        },
        "payload": payload,
        # producer.model_lineage must name a registered family (_lineage.py);
        # "none" is not one. These fixtures are authored by a Fable-lineage agent,
        # so the block says so rather than inventing a placeholder.
        "producer": {
            "harness": "pytest",
            "harness_version": "0",
            "model": "test-fixture",
            "model_lineage": "fable",
        },
        "signing": {
            "key_binding_event_hash": key_binding_event_hash,
            "key_id": signing_key.key_id,
            "scheme_id": "ed25519",
        },
        "transition": transition,
        "workflow": None,
    }


def store_trust_log_event(
    store: TrustLogStore,
    *,
    transition: str,
    payload: dict[str, Any],
    signing_key: TrustLogKey,
    entity_id: str | None = None,
    actor_principal_id: str = "service:trust-log-writer",
    key_binding_event_hash: str | None = None,
    occurred_at: str | None = None,
    entity_kind: str | None = None,
) -> StoredEvent:
    """Sign a trust-log event and INSERT it, the way test_genesis.py stores v6 rows.

    Returns the :class:`StoredEvent`, whose ``event_hash`` is exactly what the
    rebuild will recompute and stamp into ``principal_keys.source_event_hash``.
    """
    kind = entity_kind or expected_entity_kind(transition)
    resolved_entity_id = entity_id or store.project_instance_id
    if key_binding_event_hash is None and transition != "trust_domain_established":
        # RECONCILIATION.md Resolution 1: "The trust-log genesis event is the binding
        # anchor for subsequent root-authorised trust-log events." Every non-bootstrap
        # event must carry a non-null binding, and in the trust log the anchor is the
        # trust_domain_established hash until a standalone acceptance exists.
        if not store.events:
            raise AssertionError(
                "open_trust_log(store, ...) must write trust_domain_established "
                "before any other trust-log event: it is the binding anchor"
            )
        key_binding_event_hash = store.events[0].event_hash
    entity_seq = store.next_entity_seq(kind, resolved_entity_id)
    previous = store.events[-1].event_hash if store.events else None
    previous_entity = store.entity_head(kind, resolved_entity_id)
    envelope = build_v6_envelope(
        transition=transition,
        payload=payload,
        trust_domain_id=store.trust_domain_id,
        project_instance_id=store.project_instance_id,
        entity_id=resolved_entity_id,
        entity_seq=entity_seq,
        signing_key=signing_key,
        actor_principal_id=actor_principal_id,
        key_binding_event_hash=key_binding_event_hash,
        previous_entity_event_hash=previous_entity,
        previous_project_event_hash=previous,
        occurred_at=occurred_at,
        entity_kind=kind,
    )
    signed = sign_v6_envelope(envelope, signing_key.seed)
    event_hash = "sha256:" + compute_v6_event_hash(
        signed.canonical_envelope, signed.signature
    ).hex()
    timestamp = datetime.strptime(
        envelope["occurred_at"], "%Y-%m-%dT%H:%M:%S.%f%z"
    ).astimezone(UTC)

    with psycopg.connect(store.dsn, autocommit=True) as conn:
        conn.execute(f'SET search_path TO "{store.project}"')
        conn.execute(
            "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, "
            "hash_alg, event_seq, actor_id, actor_kind, actor_metadata, key_id, "
            "workflow_name, workflow_version, timestamp, transition, payload, "
            "payload_canonical_hash, signature, canonical_envelope, on_behalf_of, "
            "scheme_id, prev_event_hash, prev_global_event_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s)",
            [
                uuid.UUID(envelope["event_id"]),
                uuid.UUID(resolved_entity_id),
                kind,
                uuid.UUID(resolved_entity_id),
                "sha-256",
                entity_seq,
                actor_principal_id,
                "system",
                psycopg.types.json.Jsonb({}),
                signing_key.key_id,
                None,
                None,
                timestamp,
                transition,
                psycopg.types.json.Jsonb(payload),
                signed.payload_canonical_hash,
                signed.signature,
                signed.canonical_envelope,
                None,
                "ed25519",
                None,
                None,
            ],
        )

    stored = StoredEvent(
        event_id=envelope["event_id"],
        transition=transition,
        entity_kind=kind,
        entity_id=resolved_entity_id,
        entity_seq=entity_seq,
        payload=payload,
        event_hash=event_hash,
        canonical_envelope=signed.canonical_envelope,
        signature=signed.signature,
        occurred_at=envelope["occurred_at"],
    )
    store.events.append(stored)
    store.record_head(kind, resolved_entity_id, event_hash)
    return stored


def open_trust_log(
    store: TrustLogStore,
    genesis_document: dict[str, Any],
    root_key: TrustLogKey,
) -> StoredEvent:
    """Write the log's first event: ``trust_domain_established`` (Bootstrap A).

    This is the one event permitted a null ``previous_project_event_hash`` — and the
    one permitted a null ``signing.key_binding_event_hash`` (§5.2 AMENDED). Every
    later trust-log event chains from it, which is why the fixture writes it before
    anything else rather than starting a store mid-chain.
    """
    return store_trust_log_event(
        store,
        transition="trust_domain_established",
        payload=make_trust_domain_established_payload(
            genesis_document, root_keys=[root_key]
        ),
        signing_key=root_key,
        entity_id=store.trust_domain_id,
        key_binding_event_hash=None,
    )


def principal_entity_uuid(principal_id: str) -> str:
    """``principal_entity_id`` as canonical UUID text (§5.2 keeps the v1 derivation)."""
    from regista._principal_keys import principal_entity_id

    return str(principal_entity_id(principal_id))


def make_trust_log_project(
    dsn: str,
    project: str,
    key_path: Path,
    *,
    trust_domain_id: str | None = None,
) -> TrustLogStore:
    """Create a project schema with migrations applied, ready for stored v6 events.

    Uses ``Regista.create_project`` for the schema + migrations, then closes the
    handle: the tests here interact with the store through stored rows and the
    rebuild, not through a writer.
    """
    from regista import Regista

    signing_key = nacl.signing.SigningKey.generate()
    key_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "pk-trust-log",
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": _b64(bytes(signing_key)),
                        "encoding": "base64",
                        "public_key": _b64(bytes(signing_key.verify_key)),
                        "principal_id": "service:trust-log-writer",
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        )
    )
    handle = Regista.create_project(dsn, project, str(key_path))
    try:
        instance_id = str(uuid.uuid4())
        return TrustLogStore(
            dsn=dsn,
            project=project,
            trust_domain_id=trust_domain_id or str(uuid.uuid4()),
            project_instance_id=instance_id,
        )
    finally:
        handle.close()
