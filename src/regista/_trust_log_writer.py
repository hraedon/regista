"""Production trust-log append path and verified replay (WI-301).

The trust-domain log is a separate project chain whose identity comes from the
externally pinned genesis document, never from a ``project_identity`` row. Root
authority is threshold-rooted: a single event signature is transport attribution; the
authority proof for root-authorized transitions is the payload's detached
``root_signatures`` array verified at the *current* threshold over the signed core
(``verify_root_threshold``). Registrar authority is the exact ``registrar_delegated``
event: expired, revoked, out-of-scope or at-``max_operations`` is refused. Chain
position is predecessor-link traversal, never ``global_seq``. Every append runs in one
transaction under the ``event_chain_head`` lock; the replay verifies every stored
event's envelope signature, possession evidence, and authority before it contributes
state or an operation count.
"""

from __future__ import annotations

import base64
import hmac
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, assert_never

import psycopg

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._events import _advance_global_chain_head, _lock_global_chain_head
from ._keys import KeySet
from ._principal_keys import _compute_fingerprint
from ._signing import (
    compute_v6_event_hash,
    compute_v6_payload_canonical_hash,
    sign_v6_envelope,
)
from ._trust_domain import (
    GovernanceState,
    parse_trust_genesis,
    verify_trust_genesis,
)
from ._trust_log import (
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
    PRINCIPAL_REGISTERED,
    PROJECTION_DRIVING_TRANSITIONS,
    REGISTRAR_DELEGATED,
    REGISTRAR_REVOKED,
    TRUST_DOMAIN_CUSTODY_DECLARED,
    TRUST_DOMAIN_ESTABLISHED,
    TRUST_LOG_TRANSITIONS,
    TRUST_ROOT_ROTATED,
    PossessionChallengeV2,
    TrustDomainCustodyDeclared,
    admit_custody_declaration,
    apply_root_rotation,
    classify_rotation_authority,
    parse_registrar_delegated,
    parse_registrar_revoked,
    parse_trust_domain_custody_declared,
    parse_trust_root_rotated,
    replay_custody_declarations,
    validate_key_binding_bootstrap,
    verify_possession_proof_v2,
    verify_root_threshold,
)
from ._v6_writer import _EVENT_COLUMNS, Producer, _writer_key, resolve_producer
from ._verification import parse_v6_envelope_strict, validate_v6_envelope, verify_v6_signature

TRUST_DOMAIN_ENTITY = "trust_domain"

_ROOT = "root"
_REGISTRAR = "registrar"

_REGISTRAR_LIFECYCLE = frozenset(
    {
        PRINCIPAL_REGISTERED,
        PRINCIPAL_KEY_ENROLLED,
        PRINCIPAL_KEY_ROTATED,
        PRINCIPAL_KEY_REVOKED,
    }
)
_POSSESSION_LIFECYCLE = frozenset({PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED})
_ROOT_SIGNED_TRANSITIONS = frozenset(
    {TRUST_ROOT_ROTATED, REGISTRAR_DELEGATED, REGISTRAR_REVOKED}
)
_GENESIS_NAMESPACE = "regista.trust-domain-genesis:"
_POSSESSION_CHALLENGE_FIELDS = (
    "challenge_id",
    "operation_id",
    "operation_digest",
    "project",
    "principal_id",
    "fingerprint",
    "scheme",
    "verifier_nonce",
    "issued_at",
    "expires_at",
    "trust_domain_id",
    "enrollment_request_digest",
)


@dataclass(frozen=True)
class TrustLogIdentity:
    project_instance_id: str
    trust_domain_id: str


@dataclass(frozen=True)
class RegistrarState:
    registrar_principal_id: str
    delegated_event_hash: str
    public_key: bytes
    not_before: datetime
    not_after: datetime
    scopes: frozenset[str]
    max_operations: int | None
    operations_used: int
    revoked: bool
    key_id: str = ""


@dataclass(frozen=True)
class TrustState:
    identity: TrustLogIdentity
    governance: GovernanceState
    root_public_keys: Mapping[str, bytes]
    registrars: Mapping[str, RegistrarState]
    genesis_event_hash: str
    principal_public_keys: Mapping[tuple[str, str], bytes] = field(default_factory=dict)
    principal_key_status: Mapping[tuple[str, str], Literal["active", "revoked"]] = field(
        default_factory=dict
    )
    # WI-292 §9(iv) / WI-314: the current replayed custody correction and its own
    # event digest, so a correction's effect on custody is observable state and the
    # writer can admit the next correction against the current head at write time.
    current_custody: TrustDomainCustodyDeclared | None = None
    current_custody_digest: str | None = None


@dataclass(frozen=True)
class VerifiedLifecycle:
    event_id: str
    event_hash: str
    transition: str
    entity_kind: str
    entity_id: str
    entity_seq: int
    actor_id: str
    key_id: str
    occurred_at: datetime
    payload: Mapping[str, Any]
    authority: str
    governing_fingerprint: str


@dataclass(frozen=True)
class VerifiedChain:
    verified: tuple[VerifiedLifecycle, ...]
    state: TrustState


def _parse_envelope(row: Mapping[str, Any]) -> dict[str, Any]:
    envelope = row.get("canonical_envelope")
    if not envelope:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"a stored trust-log event ({row.get('transition')!r}) has no canonical "
            "envelope; a chain member that cannot be parsed cannot be skipped",
            {"reason": "chain_member_envelope_absent", "event_id": str(row.get("event_id"))},
        )
    try:
        return parse_v6_envelope_strict(bytes(envelope))
    except Exception as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "a stored trust-log envelope does not parse; it cannot be skipped",
            {"reason": "unparseable_envelope", "event_id": str(row.get("event_id"))},
        ) from exc


def _row_event_hash(row: Mapping[str, Any]) -> str:
    raw = compute_v6_event_hash(bytes(row["canonical_envelope"]), bytes(row["signature"]))
    return "sha256:" + raw.hex()


def _hash_text_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return None
    try:
        raw = bytes.fromhex(value.removeprefix("sha256:"))
        return raw if len(raw) == 32 else None
    except (TypeError, ValueError):
        return None


def _hash_column_matches(stored: Any, stated: Any) -> bool:
    if stated is None:
        return stored is None
    expected = _hash_text_bytes(stated)
    try:
        return expected is not None and stored is not None and bytes(stored) == expected
    except (TypeError, ValueError):
        return False


def _reconcile_row(row: Mapping[str, Any], envelope: Mapping[str, Any]) -> None:
    entity = envelope.get("entity")
    actor = envelope.get("actor")
    signing = envelope.get("signing")
    chain = envelope.get("chain")
    if not isinstance(entity, Mapping) or not isinstance(actor, Mapping):
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "a stored trust-log envelope has no usable entity or actor object",
            {"reason": "stored_row_envelope_mismatch", "fields": ["entity_or_actor"]},
        )
    if not isinstance(signing, Mapping) or not isinstance(chain, Mapping):
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "a stored trust-log envelope has no usable signing or chain object",
            {"reason": "stored_row_envelope_mismatch", "fields": ["signing_or_chain"]},
        )

    mismatches: list[str] = []
    scalar_pairs = (
        ("event_id", str(row.get("event_id")), envelope.get("event_id")),
        ("entity_kind", row.get("entity_kind"), entity.get("kind")),
        ("entity_id", str(row.get("entity_id")), entity.get("id")),
        ("event_seq", row.get("event_seq"), envelope.get("entity_seq")),
        ("actor_id", row.get("actor_id"), actor.get("principal_id")),
        ("actor_kind", row.get("actor_kind"), actor.get("kind")),
        ("actor_metadata", row.get("actor_metadata"), actor.get("metadata")),
        ("transition", row.get("transition"), envelope.get("transition")),
        ("scheme_id", row.get("scheme_id"), signing.get("scheme_id")),
        ("key_id", row.get("key_id"), signing.get("key_id")),
        ("hash_alg", row.get("hash_alg"), chain.get("hash_algorithm")),
        ("payload", row.get("payload"), envelope.get("payload")),
    )
    for field_name, stored, stated in scalar_pairs:
        if field_name == "event_seq":
            if stored is None or stated is None or int(stored) != int(stated):
                mismatches.append(field_name)
        elif field_name in {"event_id", "entity_id"}:
            if str(stored) != str(stated):
                mismatches.append(field_name)
        elif stored != stated:
            mismatches.append(field_name)

    try:
        row_timestamp = row.get("timestamp")
        if not isinstance(row_timestamp, datetime):
            mismatches.append("timestamp")
        elif row_timestamp.astimezone(UTC) != _envelope_occurred_at(envelope):
            mismatches.append("timestamp")
    except (AttributeError, TypeError, ValueError):
        mismatches.append("timestamp")

    canonical = bytes(row["canonical_envelope"])
    if not _hash_column_matches(
        row.get("payload_canonical_hash"),
        "sha256:" + compute_v6_payload_canonical_hash(canonical).hex(),
    ):
        mismatches.append("payload_canonical_hash")
    if not _hash_column_matches(
        row.get("prev_event_hash"), chain.get("previous_entity_event_hash")
    ):
        mismatches.append("prev_event_hash")
    if not _hash_column_matches(
        row.get("prev_global_event_hash"), chain.get("previous_project_event_hash")
    ):
        mismatches.append("prev_global_event_hash")

    if mismatches:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "a stored trust-log row disagrees with its signed envelope",
            {
                "reason": "stored_row_envelope_mismatch",
                "event_id": str(row.get("event_id")),
                "fields": sorted(set(mismatches)),
            },
        )


def _prev_hash(envelope: Mapping[str, Any]) -> str | None:
    chain = envelope.get("chain")
    if not isinstance(chain, Mapping):
        return None
    value = chain.get("previous_project_event_hash")
    return value if isinstance(value, str) and value else None


def _binding_hash(envelope: Mapping[str, Any]) -> str | None:
    signing = envelope.get("signing")
    if not isinstance(signing, Mapping):
        return None
    value = signing.get("key_binding_event_hash")
    return value if isinstance(value, str) and value else None


def _actor_id(envelope: Mapping[str, Any]) -> str:
    actor = envelope.get("actor")
    if isinstance(actor, Mapping):
        pid = actor.get("principal_id")
        if isinstance(pid, str):
            return pid
    return ""


def read_trust_log_rows(conn: DictConn) -> list[dict[str, Any]]:
    selected_by_event_id: dict[str, dict[str, Any]] = {}
    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        rows = conn.execute(
            "SELECT event_id, event_seq, entity_kind, entity_id, actor_id, actor_kind, "
            "actor_metadata, transition, payload, timestamp, payload_canonical_hash, "
            "canonical_envelope, signature, scheme_id, hash_alg, prev_event_hash, "
            "prev_global_event_hash, key_id "
            f"FROM {relation} "
            "WHERE canonical_envelope IS NOT NULL OR transition = ANY(%s)",
            [sorted(TRUST_LOG_TRANSITIONS)],
        ).fetchall()
        for raw in rows:
            row = dict(raw)
            envelope = _parse_envelope(row)
            _reconcile_row(row, envelope)
            if envelope.get("transition") not in TRUST_LOG_TRANSITIONS:
                continue
            if not row.get("signature"):
                raise RegistaError(
                    ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
                    "a stored trust-log event has no signature; it cannot be verified",
                    {
                        "reason": "chain_member_signature_absent",
                        "event_id": str(row.get("event_id")),
                    },
                )
            event_id = str(row["event_id"])
            previous = selected_by_event_id.get(event_id)
            if previous is not None:
                if _row_event_hash(previous) != _row_event_hash(row):
                    raise RegistaError(
                        ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
                        "the same trust-log event_id has conflicting live/archive material",
                        {
                            "reason": "duplicate_event_id_conflict",
                            "event_id": event_id,
                        },
                    )
                continue
            selected_by_event_id[event_id] = row
    return list(selected_by_event_id.values())


def chain_order(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_prev: dict[str, int] = {}
    genesis_idx: int | None = None
    for i, row in enumerate(rows):
        envelope = _parse_envelope(row)
        _reconcile_row(row, envelope)
        prev = _prev_hash(envelope)
        if prev is None:
            if row["transition"] == TRUST_DOMAIN_ESTABLISHED and genesis_idx is None:
                genesis_idx = i
            continue
        if prev in by_prev:
            raise RegistaError(
                ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
                "two trust-log events claim the same chain predecessor",
                {"reason": "duplicate_predecessor", "predecessor": prev},
            )
        by_prev[prev] = i
    if genesis_idx is None:
        raise RegistaError(
            ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED,
            "the trust-log chain has no trust_domain_established genesis",
            {"reason": "genesis_absent"},
        )
    order: list[dict[str, Any]] = []
    seen: set[int] = set()
    current: int | None = genesis_idx
    while current is not None:
        if current in seen:
            raise RegistaError(
                ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
                "the trust-log chain contains a cycle",
                {"reason": "chain_cycle"},
            )
        seen.add(current)
        order.append(dict(rows[current]))
        current = by_prev.get(_row_event_hash(rows[current]))
    if len(order) != len(rows):
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "the trust-log chain does not reach every stored event",
            {"reason": "unreachable_event", "reachable": len(order), "stored": len(rows)},
        )
    return order


def _envelope_ok(row: Mapping[str, Any], public_keys: Sequence[bytes]) -> bool:
    if not public_keys:
        return False
    canonical = bytes(row["canonical_envelope"])
    signature = bytes(row["signature"])
    for public_key in public_keys:
        verification = verify_v6_signature(
            canonical,
            signature,
            public_key,
            payload_canonical_hash=None,
            expected_event_hash=None,
            expected_project_instance_id=None,
            expected_trust_domain_id=None,
            trusted_scheme_id="ed25519",
        )
        if verification.signature_and_hashes_valid:
            return True
    return False


def _current_root_public_keys(
    governance: GovernanceState,
    root_keys: Mapping[str, bytes],
) -> list[bytes]:
    return [
        root_keys[fingerprint]
        for fingerprint in governance.signer_fingerprints
        if fingerprint in root_keys
    ]


def _verify_genesis_row(
    row: Mapping[str, Any],
    identity: TrustLogIdentity,
    root_keys: Mapping[str, bytes],
    genesis_document: Mapping[str, Any],
) -> str:
    envelope = _parse_envelope(row)
    if str(envelope["trust_domain_id"]) != identity.trust_domain_id:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
            "the stored genesis names a different trust domain than the pinned document",
            {"reason": "genesis_trust_domain_mismatch"},
        )
    signer_fingerprint = next(
        (
            fingerprint
            for fingerprint, public_key in root_keys.items()
            if _envelope_ok(row, [public_key])
        ),
        None,
    )
    if signer_fingerprint is None:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the stored trust_domain_established signature is not by a genesis root key",
            {"reason": "genesis_signer_not_root"},
        )
    validate_key_binding_bootstrap(
        TRUST_DOMAIN_ESTABLISHED,
        _binding_hash(envelope),
        event_seq=int(row["event_seq"]),
        payload=row.get("payload"),
        genesis_document=genesis_document,
        root_public_keys=root_keys,
        signer_fingerprint=signer_fingerprint,
    )
    return _row_event_hash(row)


def _treq(verified: Sequence[str], governance: GovernanceState) -> None:
    if len(verified) < governance.threshold:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"{len(verified)} verified root signature(s); {governance.threshold} required",
            {"reason": "root_threshold_not_met"},
        )


def replay_trust_state(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
) -> TrustState:
    return verify_trust_log_chain(conn, genesis_document).state


def verify_trust_log_chain(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
) -> VerifiedChain:
    """The single verified trust-log walk (WI-303).

    Returns the ordered, authority-verified lifecycle events and the final trust
    state in one predecessor-order pass. Any event that fails strict parsing, chain
    continuity or authority raises here — before any caller mutates state. Registrar
    liveness is evaluated at each event's own ``occurred_at``, never at wall-clock
    replay time.
    """
    doc = parse_trust_genesis(genesis_document)
    report = verify_trust_genesis(genesis_document)
    if report.signatures_verified < report.root_governance.threshold:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            "the pinned genesis document does not verify at root threshold",
            {"reason": "genesis_threshold_not_met"},
        )
    identity = TrustLogIdentity(
        project_instance_id=str(doc.trust_log.project_instance_id),
        trust_domain_id=str(doc.trust_domain_id),
    )
    rows = read_trust_log_rows(conn)
    if not rows:
        raise RegistaError(
            ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED,
            "the trust-log store is empty: no trust_domain_established genesis exists",
            {"reason": "empty_trust_log"},
        )
    order = chain_order(rows)
    genesis_row = order[0]
    if genesis_row["transition"] != TRUST_DOMAIN_ESTABLISHED:
        raise RegistaError(
            ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED,
            "the first trust-log event is not trust_domain_established",
            {"reason": "first_event_not_genesis"},
        )
    root_keys = {s.fingerprint: s.public_key for s in doc.signers}
    genesis_hash = _verify_genesis_row(
        genesis_row, identity, root_keys, genesis_document
    )
    governance = GovernanceState(
        threshold=doc.initial_governance.threshold,
        signer_fingerprints=tuple(s.fingerprint for s in doc.signers),
    )
    registrars: dict[str, RegistrarState] = {}
    ops: dict[str, int] = {}
    reg_keys: dict[str, bytes] = {}
    reg_binding: dict[str, str] = {}
    principal_public_keys: dict[tuple[str, str], bytes] = {}
    principal_key_status: dict[tuple[str, str], Literal["active", "revoked"]] = {}
    custody_declarations: list[tuple[Any, str]] = []
    verified_lifecycle: list[VerifiedLifecycle] = []
    entity_seq_ptr: dict[tuple[str, str], int] = {
        (TRUST_DOMAIN_ENTITY, str(_entity_id_value(_parse_envelope(genesis_row)))): 1
    }

    for row in order[1:]:
        envelope = _parse_envelope(row)
        transition = row["transition"]
        payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
        occurred_at = _envelope_occurred_at(envelope)
        entity_key = (_entity_kind_value(envelope), _entity_id_value(envelope))
        expected_seq = entity_seq_ptr.get(entity_key, 0) + 1
        entity_seq_ptr[entity_key] = expected_seq
        if int(row["event_seq"]) != expected_seq:
            raise RegistaError(
                ErrorCode.V6_CHAIN_LINK_MISSING,
                f"entity {entity_key[0]}:{entity_key[1]} has event_seq "
                f"{row['event_seq']}, expected {expected_seq}",
                {"reason": "lifecycle_entity_seq_gap"},
            )
        if (
            str(envelope.get("project_instance_id")) != identity.project_instance_id
            or str(envelope.get("trust_domain_id")) != identity.trust_domain_id
        ):
            raise RegistaError(
                ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
                "a trust-log event names a different project/trust domain than the "
                "pinned genesis",
                {"reason": "lifecycle_identity_mismatch"},
            )
        if transition == TRUST_ROOT_ROTATED:
            _require_genesis_binding(envelope, genesis_hash)
            _require_root_env(row, governance, root_keys, "rotation_signature_invalid")
            rotated = parse_trust_root_rotated(payload)
            _check_payload_trust_domain(rotated, identity.trust_domain_id)
            proposed = apply_root_rotation(governance, rotated)
            _treq(verify_root_threshold(payload, governance, root_keys), governance)
            governance = proposed
            for add in rotated.added:
                fingerprint = add.get("fingerprint")
                public_key_text = add.get("public_key")
                if isinstance(fingerprint, str) and isinstance(public_key_text, str):
                    root_keys[fingerprint] = base64.b64decode(public_key_text, validate=True)
        elif transition == TRUST_DOMAIN_CUSTODY_DECLARED:
            _require_genesis_binding(envelope, genesis_hash)
            _require_root_env(row, governance, root_keys, "custody_signature_invalid")
            custody = parse_trust_domain_custody_declared(payload)
            _check_payload_trust_domain(custody, identity.trust_domain_id)
            _treq(verify_root_threshold(payload, governance, root_keys), governance)
            custody_declarations.append((custody, _row_event_hash(row)))
        elif transition == REGISTRAR_DELEGATED:
            _require_genesis_binding(envelope, genesis_hash)
            _require_root_env(row, governance, root_keys, "delegation_signature_invalid")
            _treq(verify_root_threshold(payload, governance, root_keys), governance)
            delegated = parse_registrar_delegated(payload)
            _check_payload_trust_domain(delegated, identity.trust_domain_id)
            # B1 (PR #59 review): a forked log — a second LIVE registrar_delegated for the
            # same principal with no intervening registrar_revoked and differing terms — is
            # DETECTED here (named error) rather than silently resolved last-write-wins. A
            # revoked incumbent (registrars[pid].revoked) allows a fresh delegation, and
            # byte-identical terms are a no-op, so legitimate revoke -> re-delegate is
            # untouched. Runs before the state mutation below so the poison never lands.
            _check_registrar_delegation_no_live_fork(delegated, registrars)
            reg_keys[delegated.registrar_principal_id] = delegated.key.public_key
            reg_binding[delegated.registrar_principal_id] = _row_event_hash(row)
            ops.setdefault(delegated.registrar_principal_id, 0)
            registrars[delegated.registrar_principal_id] = RegistrarState(
                registrar_principal_id=delegated.registrar_principal_id,
                key_id=delegated.key.key_id,
                delegated_event_hash=_row_event_hash(row),
                public_key=delegated.key.public_key,
                not_before=delegated.not_before,
                not_after=delegated.not_after,
                scopes=frozenset(delegated.scopes),
                max_operations=delegated.max_operations,
                operations_used=0,
                revoked=False,
            )
        elif transition == REGISTRAR_REVOKED:
            _require_genesis_binding(envelope, genesis_hash)
            _require_root_env(row, governance, root_keys, "revocation_signature_invalid")
            _treq(verify_root_threshold(payload, governance, root_keys), governance)
            revoked = parse_registrar_revoked(payload)
            _check_payload_trust_domain(revoked, identity.trust_domain_id)
            entry = registrars.get(revoked.registrar_principal_id)
            if entry is None:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "registrar_revoked names no current registrar delegation",
                    {
                        "reason": "registrar_revocation_target_missing",
                        "registrar_principal_id": revoked.registrar_principal_id,
                    },
                )
            if entry.revoked:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "registrar_revoked names a delegation that is already revoked",
                    {
                        "reason": "registrar_revocation_target_not_live",
                        "registrar_principal_id": revoked.registrar_principal_id,
                    },
                )
            if entry.delegated_event_hash != revoked.delegation_event_hash:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "registrar_revoked does not name the current delegation event",
                    {
                        "reason": "registrar_revocation_delegation_mismatch",
                        "expected": entry.delegated_event_hash,
                        "stated": revoked.delegation_event_hash,
                    },
                )
            if entry.key_id != revoked.key_id:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "registrar_revoked does not name the current delegation key",
                    {
                        "reason": "registrar_revocation_key_mismatch",
                        "expected": entry.key_id,
                        "stated": revoked.key_id,
                    },
                )
            registrars[revoked.registrar_principal_id] = _revoke(entry)
        elif transition in _REGISTRAR_LIFECYCLE:
            actor = _actor_id(envelope)
            key_id = _signer_key_id(envelope)
            binding = _binding_hash(envelope)
            record = _verify_lifecycle(
                conn,
                row,
                envelope,
                identity,
                actor,
                key_id,
                binding,
                payload,
                transition,
                occurred_at,
                governance,
                root_keys,
                reg_keys,
                reg_binding,
                registrars,
                principal_public_keys,
                principal_key_status,
                ops,
                genesis_hash,
            )
            if record is not None:
                verified_lifecycle.append(record)

    current_custody = replay_custody_declarations(custody_declarations)
    current_custody_digest = custody_declarations[-1][1] if custody_declarations else None

    for principal_id, entry in registrars.items():
        registrars[principal_id] = RegistrarState(
            registrar_principal_id=entry.registrar_principal_id,
            key_id=entry.key_id,
            delegated_event_hash=entry.delegated_event_hash,
            public_key=entry.public_key,
            not_before=entry.not_before,
            not_after=entry.not_after,
            scopes=entry.scopes,
            max_operations=entry.max_operations,
            operations_used=ops.get(principal_id, 0),
            revoked=entry.revoked,
        )

    state = TrustState(
        identity=identity,
        governance=governance,
        root_public_keys=root_keys,
        registrars=registrars,
            principal_public_keys=principal_public_keys,
            principal_key_status=principal_key_status,
            genesis_event_hash=genesis_hash,
            current_custody=current_custody,
            current_custody_digest=current_custody_digest,
        )
    return VerifiedChain(verified=tuple(verified_lifecycle), state=state)


def _revoke(entry: RegistrarState) -> RegistrarState:
    return RegistrarState(
        registrar_principal_id=entry.registrar_principal_id,
        key_id=entry.key_id,
        delegated_event_hash=entry.delegated_event_hash,
        public_key=entry.public_key,
        not_before=entry.not_before,
        not_after=entry.not_after,
        scopes=entry.scopes,
        max_operations=entry.max_operations,
        operations_used=entry.operations_used,
        revoked=True,
    )


def _require_root_env(
    row: Mapping[str, Any],
    governance: GovernanceState,
    root_keys: Mapping[str, bytes],
    reason: str,
) -> None:
    if not _envelope_ok(row, _current_root_public_keys(governance, root_keys)):
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "a stored root-authorized envelope is not signed by a current root key",
            {"reason": reason, "event_id": str(row["event_id"])},
        )


def _require_genesis_binding(envelope: Mapping[str, Any], genesis_hash: str) -> None:
    if _binding_hash(envelope) != genesis_hash:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "a root-authorized trust-log event must bind to the trust-log genesis",
            {"reason": "root_binding_not_genesis", "expected": genesis_hash},
        )


def _envelope_occurred_at(envelope: Mapping[str, Any]) -> datetime:
    value = envelope.get("occurred_at")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("occurred_at has no timezone")
            return parsed.astimezone(UTC)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RegistaError(
                ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
                "a stored trust-log envelope carries a malformed occurred_at",
                {"reason": "occurred_at_malformed"},
            ) from exc
    raise RegistaError(
        ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
        "a stored trust-log envelope carries no parseable occurred_at",
        {"reason": "occurred_at_absent"},
    )


def _entity_kind_value(envelope: Mapping[str, Any]) -> str:
    entity = envelope.get("entity")
    return str(entity.get("kind")) if isinstance(entity, Mapping) else ""


def _entity_id_value(envelope: Mapping[str, Any]) -> str:
    entity = envelope.get("entity")
    return str(entity.get("id")) if isinstance(entity, Mapping) else ""


def _signer_key_id(envelope: Mapping[str, Any]) -> str:
    signing = envelope.get("signing")
    return str(signing.get("key_id")) if isinstance(signing, Mapping) else ""


def _challenge_timestamp(value: Any, field: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"possession challenge {field} has no timezone",
                {"reason": "possession_challenge_field_invalid", "field": field},
            )
        parsed = value.astimezone(UTC)
    elif isinstance(value, str):
        try:
            candidate = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if candidate.tzinfo is None or candidate.utcoffset() is None:
                raise ValueError("timestamp has no timezone")
            parsed = candidate.astimezone(UTC)
        except (TypeError, ValueError) as exc:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"possession challenge {field} is not a timestamp",
                {"reason": "possession_challenge_field_invalid", "field": field},
            ) from exc
    else:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"possession challenge {field} is not a timestamp",
            {"reason": "possession_challenge_field_invalid", "field": field},
        )
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), parsed


def _possession_challenge_from_row(
    row: Mapping[str, Any],
) -> tuple[PossessionChallengeV2, datetime, datetime]:
    missing = [
        field
        for field in _POSSESSION_CHALLENGE_FIELDS
        if row.get(field) is None
        or (isinstance(row.get(field), str) and not str(row.get(field)).strip())
    ]
    if missing:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the consumed possession challenge is missing v2 challenge fields",
            {"reason": "possession_challenge_fields_missing", "fields": missing},
        )
    issued_at, issued_at_dt = _challenge_timestamp(row["issued_at"], "issued_at")
    expires_at, expires_at_dt = _challenge_timestamp(row["expires_at"], "expires_at")
    if expires_at_dt <= issued_at_dt:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the possession challenge validity window is inverted",
            {"reason": "possession_challenge_window_invalid"},
        )
    return (
        PossessionChallengeV2(
            challenge_id=str(row["challenge_id"]),
            operation_id=str(row["operation_id"]),
            operation_digest=str(row["operation_digest"]),
            project=str(row["project"]),
            trust_domain_id=str(row["trust_domain_id"]),
            principal_id=str(row["principal_id"]),
            fingerprint=str(row["fingerprint"]),
            scheme=str(row["scheme"]),
            verifier_nonce=str(row["verifier_nonce"]),
            enrollment_request_digest=str(row["enrollment_request_digest"]),
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        issued_at_dt,
        expires_at_dt,
    )


def _verify_possession_evidence(
    conn: DictConn,
    payload: Mapping[str, Any] | None,
    transition: str,
    *,
    mode: Literal["admission", "replay"],
    at_time: datetime | None = None,
) -> None:
    """Verify the durable, consumed v2 challenge behind a lifecycle event."""
    if transition not in _POSSESSION_LIFECYCLE:
        return
    if not isinstance(payload, Mapping):
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "a principal key lifecycle event has no possession proof payload",
            {"reason": "possession_evidence_missing", "transition": transition},
        )
    parsed = _parse_lifecycle_payload(transition, payload)
    proof = parsed.possession_proof
    try:
        row = conn.execute(
            "SELECT challenge_id, operation_id, operation_digest, project, "
            "principal_id, fingerprint, scheme, verifier_nonce, issued_at, expires_at, "
            "used, kind, trust_domain_id, enrollment_request_digest, proof_signature "
            "FROM lifecycle_challenges WHERE challenge_id = %s FOR SHARE",
            [_uuid.UUID(proof.challenge_id)],
        ).fetchone()
    except (psycopg.errors.UndefinedColumn, psycopg.errors.UndefinedTable) as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the durable possession-challenge evidence store is unavailable",
            {"reason": "possession_challenge_table_missing", "transition": transition},
        ) from exc
    if row is None:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the possession proof names no durable challenge",
            {
                "reason": "possession_challenge_not_found",
                "challenge_id": proof.challenge_id,
            },
        )
    if row.get("kind") != "possession":
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the possession proof does not name a possession challenge",
            {
                "reason": "possession_challenge_kind_mismatch",
                "challenge_id": proof.challenge_id,
                "kind": row.get("kind"),
            },
        )
    if row.get("used") is not True:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the possession challenge has not been durably consumed",
            {"reason": "possession_challenge_not_consumed", "challenge_id": proof.challenge_id},
        )
    stored_signature = row.get("proof_signature")
    if not isinstance(stored_signature, str) or not stored_signature:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the consumed possession challenge has no verified proof signature",
            {"reason": "possession_proof_evidence_missing", "challenge_id": proof.challenge_id},
        )
    payload_signature = base64.b64encode(proof.signature).decode("ascii")
    if not hmac.compare_digest(stored_signature, payload_signature):
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the durable possession proof signature differs from the event payload",
            {"reason": "possession_proof_signature_mismatch", "challenge_id": proof.challenge_id},
        )
    challenge, _issued_at, expires_at = _possession_challenge_from_row(row)
    if challenge.scheme != payload.get("scheme_id"):
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the possession challenge scheme differs from the lifecycle payload",
            {
                "reason": "possession_challenge_binding_mismatch",
                "field": "scheme",
                "challenge": challenge.scheme,
                "payload": payload.get("scheme_id"),
            },
        )
    verify_possession_proof_v2(payload, challenge)
    if mode == "admission":
        admitted_at = at_time or datetime.now(UTC)
        if admitted_at.tzinfo is None or admitted_at.utcoffset() is None:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "possession proof admission time has no timezone",
                {"reason": "possession_admission_time_invalid"},
            )
        if admitted_at.astimezone(UTC) >= expires_at:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the possession challenge was expired at append admission",
                {
                    "reason": "possession_challenge_expired_at_admission",
                    "challenge_id": proof.challenge_id,
                },
            )
    elif mode == "replay":
        if at_time is not None and (
            at_time.tzinfo is None or at_time.utcoffset() is None
        ):
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "possession proof replay time has no timezone",
                {"reason": "possession_replay_time_invalid"},
            )
        if at_time is not None and at_time.astimezone(UTC) >= expires_at:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the possession challenge was expired at the lifecycle event",
                {
                    "reason": "possession_challenge_expired_at_event",
                    "challenge_id": proof.challenge_id,
                },
            )
    else:
        assert_never(mode)


def _parse_lifecycle_payload(transition: str, payload: Mapping[str, Any]) -> Any:
    from ._trust_log import (
        parse_principal_key_enrolled,
        parse_principal_key_revoked,
        parse_principal_key_rotated,
        parse_principal_registered,
    )

    if transition == PRINCIPAL_REGISTERED:
        return parse_principal_registered(payload)
    if transition == PRINCIPAL_KEY_ENROLLED:
        return parse_principal_key_enrolled(payload)
    if transition == PRINCIPAL_KEY_ROTATED:
        return parse_principal_key_rotated(payload)
    if transition == PRINCIPAL_KEY_REVOKED:
        return parse_principal_key_revoked(payload)
    raise RegistaError(
        ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
        f"lifecycle transition {transition!r} is not a projection-driving transition",
        {"reason": "transition_not_lifecycle"},
    )


def _check_authorized_by(
    parsed: Any,
    *,
    expected_authority: str,
    actor_id: str,
    key_id: str,
    expected_binding: str | None,
) -> None:
    authorized = getattr(parsed, "authorized_by", None)
    if authorized is None:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the lifecycle payload has no authorized_by object",
            {"reason": "authorized_by_missing"},
        )
    authority = getattr(authorized, "authority", None)
    if authority != expected_authority:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the lifecycle payload's authorized_by authority differs from the resolved "
            "authority",
            {
                "reason": "authorized_by_authority_mismatch",
                "expected": expected_authority,
                "stated": authority,
            },
        )
    principal = getattr(authorized, "principal_id", None)
    if principal != actor_id:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the lifecycle payload's authorized_by principal differs from the envelope "
            "actor",
            {
                "reason": "authorized_by_actor_mismatch",
                "expected": actor_id,
                "stated": principal,
            },
        )
    stated_key_id = getattr(authorized, "key_id", None)
    if stated_key_id != key_id:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the lifecycle payload's authorized_by key differs from the envelope "
            "signing key",
            {
                "reason": "authorized_by_key_id_mismatch",
                "expected": key_id,
                "stated": stated_key_id,
            },
        )
    delegation = getattr(authorized, "delegation_event_hash", None)
    if delegation != expected_binding:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "the lifecycle payload's authorized_by delegation differs from the envelope "
            "binding",
            {
                "reason": "authorized_by_delegation_mismatch",
                "expected": expected_binding,
                "stated": delegation,
            },
        )


def _check_payload_trust_domain(parsed: Any, expected: str) -> None:
    if str(getattr(parsed, "trust_domain_id", "")) != expected:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
            "a trust-log payload names a different trust domain than the pinned genesis",
            {"reason": "payload_trust_domain_mismatch", "expected": expected},
        )


def _classify_rotation(
    parsed: Any,
    payload: Mapping[str, Any],
    governance: GovernanceState,
    root_keys: Mapping[str, bytes],
    principal_public_keys: Mapping[tuple[str, str], bytes],
    principal_key_status: Mapping[tuple[str, str], Literal["active", "revoked"]],
) -> str:
    superseded = None
    if not parsed.is_recovery:
        superseded_key = (parsed.principal_id, parsed.supersedes_key_id)
        if principal_key_status.get(superseded_key) == "revoked":
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a dual rotation cannot use a revoked superseded key",
                {
                    "reason": "superseded_key_revoked",
                    "principal_id": parsed.principal_id,
                    "key_id": parsed.supersedes_key_id,
                },
            )
        superseded = principal_public_keys.get(
            superseded_key
        )
    return classify_rotation_authority(
        parsed,
        governance=governance,
        root_public_keys=root_keys,
        payload=payload,
        superseded_public_key=superseded,
    )


def _remember_principal_key(
    parsed: Any,
    principal_public_keys: dict[tuple[str, str], bytes],
    principal_key_status: dict[tuple[str, str], Literal["active", "revoked"]],
) -> None:
    key = getattr(parsed, "key", None)
    principal_id = getattr(parsed, "principal_id", None)
    if key is not None and isinstance(principal_id, str):
        principal_public_keys[(principal_id, key.key_id)] = key.public_key
        principal_key_status[(principal_id, key.key_id)] = "active"


def _check_enrollment_binds_fresh_key(
    parsed: Any,
    principal_public_keys: Mapping[tuple[str, str], bytes],
    principal_key_status: Mapping[tuple[str, str], Literal["active", "revoked"]],
) -> None:
    """Enrolment binds a principal's key where there is NONE (B1, PR #58).

    ``principal_key_enrolled`` must not silently displace an incumbent key. If the
    principal already has a live key whose bytes differ from the one offered, this is a
    key CHANGE, which §5.6 handles as a ROTATION carrying the outgoing key's dual
    authorization — never a bare enrolment. Enforced here, in the writer's admission
    path, so a direct ``append_trust_log_event`` caller cannot bypass the CLI guard.
    Re-enrolling the SAME bytes (same fingerprint) is left alone: it is an idempotent
    no-op, not a change. This guard is specific to the enrol transition; rotation
    (``principal_key_rotated``) legitimately supersedes and is untouched.
    """
    principal_id = getattr(parsed, "principal_id", None)
    key = getattr(parsed, "key", None)
    new_public = getattr(key, "public_key", None) if key is not None else None
    if not isinstance(principal_id, str):
        return
    for (p_id, k_id), pub in principal_public_keys.items():
        if p_id != principal_id:
            continue
        if principal_key_status.get((p_id, k_id)) != "active":
            continue
        if new_public is not None and pub == new_public:
            # Same key material already active — idempotent, not a change.
            continue
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"principal {principal_id!r} already has an active key (key_id {k_id}); "
            "principal_key_enrolled binds a key where there is none — changing an "
            "existing key is a rotation (§5.6, principal_key_rotated with dual "
            "authorization), which cannot be effected by an enrolment",
            {
                "reason": "enrollment_key_already_present",
                "principal_id": principal_id,
                "active_key_id": k_id,
            },
        )


def _check_registrar_delegation_no_live_fork(
    delegated: Any,
    registrars: Mapping[str, RegistrarState],
) -> None:
    """No two LIVE conflicting registrar delegations for one principal (B1, PR #59).

    ``registrar_delegated`` naming a principal that ALREADY holds a live delegation whose
    terms differ (key material/key_id, scopes, validity window, or ``max_operations``)
    forks the credential — two events, and a last-write-wins replay would silently pick
    the later term set (scope widening, key swap). §5.4's supported refresh path is to
    ``registrar_revoked`` the incumbent first, THEN delegate afresh. Enforced here so the
    invariant holds at the DURABLE layer — writer admission AND replay — not only in the
    CLI pre-check (which runs in a separate, already-closed transaction and cannot bind a
    direct ``append_trust_log_event`` caller or two honest concurrent delegations).

    Fail-closed policy, mirroring the CLI live-check exactly:

    * No incumbent, or the incumbent is REVOKED -> allowed (revoke -> re-delegate works).
    * A live incumbent with BYTE-IDENTICAL terms -> idempotent no-op, allowed.
    * A live incumbent with DIFFERING terms -> refused with ``registrar_already_delegated_live``.

    This guard is specific to ``registrar_delegated``; revocation, rotation and enrolment
    are untouched.
    """
    principal_id = getattr(delegated, "registrar_principal_id", None)
    if not isinstance(principal_id, str):
        return
    existing = registrars.get(principal_id)
    if existing is None or existing.revoked:
        return
    key = getattr(delegated, "key", None)
    new_public = getattr(key, "public_key", None) if key is not None else None
    new_key_id = getattr(key, "key_id", None) if key is not None else None
    identical = (
        existing.public_key == new_public
        and existing.key_id == new_key_id
        and existing.scopes == frozenset(getattr(delegated, "scopes", ()))
        and existing.max_operations == getattr(delegated, "max_operations", None)
        and existing.not_before == getattr(delegated, "not_before", None)
        and existing.not_after == getattr(delegated, "not_after", None)
    )
    if identical:
        return
    raise RegistaError(
        ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
        f"{principal_id!r} already has a live registrar delegation "
        f"(event {existing.delegated_event_hash}) whose terms differ from the requested "
        "ones; a registrar cannot be re-delegated while live (§5.4). Revoke the existing "
        "delegation (registrar_revoked) first, then delegate again.",
        {
            "reason": "registrar_already_delegated_live",
            "registrar_principal_id": principal_id,
            "existing_delegation_event_hash": existing.delegated_event_hash,
        },
    )


def _remember_principal_key_revocation(
    parsed: Any,
    principal_public_keys: Mapping[tuple[str, str], bytes],
    principal_key_status: dict[tuple[str, str], Literal["active", "revoked"]],
) -> None:
    principal_id = getattr(parsed, "principal_id", None)
    key_id = getattr(parsed, "key_id", None)
    if not isinstance(principal_id, str) or not isinstance(key_id, str):
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "a principal_key_revoked payload has no usable principal/key identity",
            {"reason": "revocation_key_identity_missing"},
        )
    key: tuple[str, str] = (principal_id, key_id)
    if key not in principal_public_keys:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "principal_key_revoked names no key previously established in the trust log",
            {
                "reason": "revoked_key_unavailable",
                "principal_id": principal_id,
                "key_id": key_id,
            },
        )
    if principal_key_status.get(key) == "revoked":
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            "principal_key_revoked names a key that is already revoked",
            {
                "reason": "principal_key_already_revoked",
                "principal_id": principal_id,
                "key_id": key_id,
            },
        )
    principal_key_status[key] = "revoked"


def _verify_lifecycle(
    conn: DictConn,
    row: Mapping[str, Any],
    envelope: Mapping[str, Any],
    identity: TrustLogIdentity,
    actor_id: str,
    key_id: str,
    binding: str | None,
    payload: Mapping[str, Any],
    transition: str,
    occurred_at: datetime,
    governance: GovernanceState,
    root_keys: Mapping[str, bytes],
    reg_keys: Mapping[str, bytes],
    reg_binding: Mapping[str, str],
    registrars: Mapping[str, RegistrarState],
    principal_public_keys: dict[tuple[str, str], bytes],
    principal_key_status: dict[tuple[str, str], Literal["active", "revoked"]],
    ops: dict[str, int],
    genesis_hash: str,
) -> VerifiedLifecycle | None:
    parsed = _parse_lifecycle_payload(transition, payload)
    _check_payload_trust_domain(parsed, identity.trust_domain_id)
    _verify_possession_evidence(
        conn,
        payload,
        transition,
        mode="replay",
        at_time=occurred_at,
    )
    if transition == PRINCIPAL_KEY_ENROLLED:
        # Defence in depth (B1, PR #58): the enrol transition may not displace an
        # incumbent live key — that is a rotation. Enforced across every authority path
        # (registrar and root) here, before any state mutation, so a non-CLI caller is
        # bound by the same invariant.
        _check_enrollment_binds_fresh_key(
            parsed, principal_public_keys, principal_key_status
        )
    if transition == PRINCIPAL_KEY_ROTATED and parsed.is_recovery:
        if binding != genesis_hash:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a recovery rotation must bind to the trust-log genesis and use root "
                "authority",
                {"reason": "recovery_requires_root_authority"},
            )
        if not _envelope_ok(row, _current_root_public_keys(governance, root_keys)):
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a recovery rotation envelope is not signed by a current root key",
                {"reason": "recovery_envelope_signer_not_current_root"},
            )
        _check_authorized_by(
            parsed,
            expected_authority=_ROOT,
            actor_id=actor_id,
            key_id=key_id,
            expected_binding=None,
        )
        _classify_rotation(
            parsed,
            payload,
            governance,
            root_keys,
            principal_public_keys,
            principal_key_status,
        )
        _remember_principal_key(parsed, principal_public_keys, principal_key_status)
        return VerifiedLifecycle(
            event_id=str(row["event_id"]),
            event_hash=_row_event_hash(row),
            transition=transition,
            entity_kind=_entity_kind_value(envelope),
            entity_id=_entity_id_value(envelope),
            entity_seq=int(row["event_seq"]),
            actor_id=actor_id,
            key_id=key_id,
            occurred_at=occurred_at,
            payload=payload,
            authority=_ROOT,
            governing_fingerprint="genesis",
        )
    delegated_hash = reg_binding.get(actor_id)
    if (
        binding is not None
        and delegated_hash is not None
        and binding == delegated_hash
        and actor_id in reg_keys
    ):
        entry = registrars.get(actor_id)
        if entry is None or entry.revoked:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"{actor_id!r} has no live registrar delegation at this chain position",
                {"reason": "registrar_revoked_or_missing"},
            )
        if key_id != entry.key_id:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the lifecycle envelope key is not the delegated registrar key",
                {
                    "reason": "registrar_signing_key_id_mismatch",
                    "expected": entry.key_id,
                    "stated": key_id,
                },
            )
        if occurred_at < entry.not_before or occurred_at > entry.not_after:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"registrar {actor_id!r} was not live at the event's occurred_at",
                {"reason": "registrar_not_live_at_event_time"},
            )
        if transition not in entry.scopes:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"transition {transition!r} is outside registrar {actor_id!r}'s scope",
                {"reason": "lifecycle_transition_out_of_scope"},
            )
        used = ops.get(actor_id, 0)
        if entry.max_operations is not None and used >= entry.max_operations:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"registrar {actor_id!r} has no operations left at this chain position",
                {"reason": "max_operations_exhausted"},
            )
        if not _envelope_ok(row, [entry.public_key]):
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the lifecycle envelope is not signed by the delegated registrar key",
                {"reason": "lifecycle_signature_invalid"},
            )
        _check_authorized_by(
            parsed,
            expected_authority=_REGISTRAR,
            actor_id=actor_id,
            key_id=key_id,
            expected_binding=delegated_hash,
        )
        if transition == PRINCIPAL_KEY_ROTATED:
            _classify_rotation(
                parsed,
                payload,
                governance,
                root_keys,
                principal_public_keys,
                principal_key_status,
            )
        if transition == PRINCIPAL_KEY_REVOKED:
            _remember_principal_key_revocation(
                parsed, principal_public_keys, principal_key_status
            )
        else:
            _remember_principal_key(parsed, principal_public_keys, principal_key_status)
        ops[actor_id] = used + 1
        if transition not in PROJECTION_DRIVING_TRANSITIONS:
            return None
        return VerifiedLifecycle(
            event_id=str(row["event_id"]),
            event_hash=_row_event_hash(row),
            transition=transition,
            entity_kind=_entity_kind_value(envelope),
            entity_id=_entity_id_value(envelope),
            entity_seq=int(row["event_seq"]),
            actor_id=actor_id,
            key_id=key_id,
            occurred_at=occurred_at,
            payload=payload,
            authority="registrar",
            governing_fingerprint=entry.delegated_event_hash,
        )
    if binding is not None and binding == genesis_hash:
        if transition == PRINCIPAL_KEY_ROTATED:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a dual rotation must use a live registrar delegation",
                {"reason": "dual_rotation_requires_registrar_authority"},
            )
        _treq(verify_root_threshold(payload, governance, root_keys), governance)
        if not _envelope_ok(row, _current_root_public_keys(governance, root_keys)):
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a root-authorized lifecycle envelope is not signed by a genesis root key",
                {"reason": "root_lifecycle_signature_invalid"},
            )
        _check_authorized_by(
            parsed,
            expected_authority=_ROOT,
            actor_id=actor_id,
            key_id=key_id,
            expected_binding=None,
        )
        if transition == PRINCIPAL_KEY_REVOKED:
            _remember_principal_key_revocation(
                parsed, principal_public_keys, principal_key_status
            )
        else:
            _remember_principal_key(parsed, principal_public_keys, principal_key_status)
        if transition not in PROJECTION_DRIVING_TRANSITIONS:
            return None
        return VerifiedLifecycle(
            event_id=str(row["event_id"]),
            event_hash=_row_event_hash(row),
            transition=transition,
            entity_kind=_entity_kind_value(envelope),
            entity_id=_entity_id_value(envelope),
            entity_seq=int(row["event_seq"]),
            actor_id=actor_id,
            key_id=key_id,
            occurred_at=occurred_at,
            payload=payload,
            authority="root",
            governing_fingerprint="genesis",
        )
    raise RegistaError(
        ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
        f"lifecycle event by {actor_id!r} binds to {binding!r}, which is neither the "
        "genesis nor an exact registrar_delegated event",
        {"reason": "lifecycle_binding_unresolved"},
    )


def _build_envelope(
    identity: TrustLogIdentity,
    *,
    event_id: _uuid.UUID,
    entity_kind: str,
    entity_id: _uuid.UUID,
    entity_seq: int,
    actor_id: str,
    key_id: str,
    key_binding_event_hash: str | None,
    transition: str,
    payload: Mapping[str, Any] | None,
    producer: Producer,
    occurred_at: datetime,
    previous_entity_event_hash: str | None,
    previous_project_event_hash: str | None,
) -> dict[str, Any]:
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": identity.project_instance_id,
        "trust_domain_id": identity.trust_domain_id,
        "event_id": str(event_id),
        "entity": {"kind": entity_kind, "id": str(entity_id)},
        "entity_seq": entity_seq,
        "actor": {"principal_id": actor_id, "kind": "system", "metadata": None},
        "signing": {
            "scheme_id": "ed25519",
            "key_id": key_id,
            "key_binding_event_hash": key_binding_event_hash,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "transition": transition,
        "payload": dict(payload) if payload is not None else None,
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": previous_entity_event_hash,
            "previous_project_event_hash": previous_project_event_hash,
        },
        "producer": producer.as_envelope_member(),
    }


def _max_entity_seq(conn: DictConn, entity_kind: str, entity_id: _uuid.UUID) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(event_seq), 0) AS n FROM events "
        "WHERE entity_kind = %s AND entity_id = %s",
        [entity_kind, entity_id],
    ).fetchone()
    return int(row["n"]) if row else 0


def _previous_entity_hash(
    conn: DictConn, entity_kind: str, entity_id: _uuid.UUID, entity_seq: int
) -> str | None:
    if entity_seq <= 1:
        return None
    row = conn.execute(
        "SELECT canonical_envelope, signature FROM events "
        "WHERE entity_kind = %s AND entity_id = %s AND event_seq = %s",
        [entity_kind, entity_id, entity_seq - 1],
    ).fetchone()
    if row is None or not row["canonical_envelope"] or not row["signature"]:
        raise RegistaError(
            ErrorCode.V6_CHAIN_LINK_MISSING,
            f"entity {entity_kind}:{entity_id} has no signed predecessor at "
            f"entity_seq {entity_seq - 1}",
            {"reason": "entity_predecessor_missing"},
        )
    raw = compute_v6_event_hash(bytes(row["canonical_envelope"]), bytes(row["signature"]))
    return "sha256:" + raw.hex()


def _write_row(
    conn: DictConn,
    *,
    envelope: Mapping[str, Any],
    signed: Any,
    entity_kind: str,
    entity_id: _uuid.UUID,
    entity_seq: int,
    previous_project_bytes: bytes | None,
) -> str:
    stored_time = datetime.strptime(
        envelope["occurred_at"], "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=UTC)
    chain = envelope.get("chain")
    previous_entity_bytes = _hash_text_bytes(
        chain.get("previous_entity_event_hash")
        if isinstance(chain, Mapping)
        else None
    )
    inserted = conn.execute(
        "INSERT INTO events (" + _EVENT_COLUMNS + ") VALUES "
        "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
        "%s, %s, %s, %s) RETURNING global_seq",
        [
            _uuid.UUID(envelope["event_id"]),
            entity_id,
            entity_kind,
            entity_id,
            "sha-256",
            entity_seq,
            envelope["actor"]["principal_id"],
            envelope["actor"]["kind"],
            None,
            envelope["signing"]["key_id"],
            None,
            None,
            stored_time,
            envelope["transition"],
            psycopg.types.json.Jsonb(envelope["payload"])
            if envelope["payload"] is not None
            else None,
            signed.payload_canonical_hash,
            signed.signature,
            signed.canonical_envelope,
            None,
            "ed25519",
            previous_entity_bytes,
            previous_project_bytes,
        ],
    )
    row = inserted.fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID, "the trust-log append returned no global_seq"
        )
    event_hash = compute_v6_event_hash(signed.canonical_envelope, signed.signature)
    _advance_global_chain_head(conn, _uuid.UUID(envelope["event_id"]), event_hash)
    return str(envelope["event_id"])


def _self_verify(signed: Any, identity: TrustLogIdentity, public_key: bytes | None) -> None:
    if public_key is None:
        raise RegistaError(
            ErrorCode.V6_ENVELOPE_INVALID,
            "the trust-log writer requires a public key to self-verify",
            {"reason": "no_public_key"},
        )
    verification = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        public_key,
        payload_canonical_hash=signed.payload_canonical_hash,
        expected_event_hash=signed.event_hash,
        expected_project_instance_id=str(identity.project_instance_id),
        expected_trust_domain_id=str(identity.trust_domain_id),
        trusted_scheme_id="ed25519",
    )
    if not (
        verification.signature_and_hashes_valid
        and verification.project_binding_valid is True
        and verification.trust_domain_binding_valid is True
    ):
        raise RegistaError(
            ErrorCode.V6_ENVELOPE_INVALID,
            "the trust-log writer produced bytes that do not verify under its own key",
            {"reason": "self_verification_failed"},
        )


def write_trust_genesis(
    mgr: ConnectionManager,
    *,
    keys: KeySet,
    genesis_document: dict[str, Any],
    root_principal_id: str,
    payload: Mapping[str, Any] | None = None,
    key_id: str | None = None,
    occurred_at: datetime | None = None,
) -> str:
    doc = parse_trust_genesis(genesis_document)
    verify_trust_genesis(genesis_document)
    identity = TrustLogIdentity(
        project_instance_id=str(doc.trust_log.project_instance_id),
        trust_domain_id=str(doc.trust_domain_id),
    )
    root_keys = {s.fingerprint: s.public_key for s in doc.signers}
    with mgr.transaction() as conn:
        existing = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE transition = ANY(%s)",
            [sorted(TRUST_LOG_TRANSITIONS)],
        ).fetchone()
        if existing and int(existing["n"]) > 0:
            raise RegistaError(
                ErrorCode.GENESIS_ALREADY_WRITTEN,
                "the trust-log store already has an event; genesis must be its first write",
                {"reason": "genesis_already_written"},
            )
        if _lock_global_chain_head(conn) is not None:
            raise RegistaError(
                ErrorCode.GENESIS_ALREADY_WRITTEN,
                "the trust-log global head is already set; genesis must be its first write",
                {"reason": "head_already_set"},
            )
        key = _writer_key(keys, principal_id=root_principal_id, key_id=key_id)
        if doc.signer_by_fingerprint(key.fingerprint()) is None:
            raise RegistaError(
                ErrorCode.ACTOR_SIGNER_MISMATCH,
                f"root principal {root_principal_id!r} signs with a key not in the "
                "pinned genesis document's signer set",
                {
                    "reason": "genesis_signer_not_in_document",
                    "fingerprint": key.fingerprint(),
                },
            )
        signed_payload = payload
        if signed_payload is None:
            if doc.initial_governance.threshold != 1:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "write_trust_genesis needs a fully-signed trust_domain_established "
                    "payload when the initial root threshold exceeds one; offline root "
                    "signatures must be collected and passed in (A-prime)",
                    {"reason": "payload_requires_offline_root_signatures"},
                )

            signed_payload = dict(_genesis_payload_template(genesis_document))
            signed_payload["root_signatures"] = [
                _root_signature_entry(
                    signed_payload, key.secret, key.fingerprint(), root_principal_id
                )
            ]
        from ._trust_log import validate_key_binding_bootstrap

        validate_key_binding_bootstrap(
            TRUST_DOMAIN_ESTABLISHED,
            None,
            event_seq=1,
            payload=signed_payload,
            genesis_document=genesis_document,
            root_public_keys=root_keys,
            signer_fingerprint=key.fingerprint(),
        )
        resolved_event_id = _uuid.uuid5(
            _uuid.NAMESPACE_OID, _GENESIS_NAMESPACE + doc.trust_domain_id
        )
        envelope = _build_envelope(
            identity,
            event_id=resolved_event_id,
            entity_kind=TRUST_DOMAIN_ENTITY,
            entity_id=_uuid.UUID(doc.trust_domain_id),
            entity_seq=1,
            actor_id=root_principal_id,
            key_id=key.key_id,
            key_binding_event_hash=None,
            transition=TRUST_DOMAIN_ESTABLISHED,
            payload=signed_payload,
            producer=resolve_producer(),
            occurred_at=occurred_at or _parse_ts(doc.created_at),
            previous_entity_event_hash=None,
            previous_project_event_hash=None,
        )
        try:
            validate_v6_envelope(envelope)
        except Exception as exc:
            raise RegistaError(
                ErrorCode.V6_ENVELOPE_INVALID,
                f"the trust-log writer refused to sign an invalid envelope: {exc}",
                {"reason": "envelope_invalid"},
            ) from exc
        signed = sign_v6_envelope(envelope, key.secret)
        _self_verify(signed, identity, key.public_key)
        return _write_row(
            conn,
            envelope=envelope,
            signed=signed,
            entity_kind=TRUST_DOMAIN_ENTITY,
            entity_id=_uuid.UUID(doc.trust_domain_id),
            entity_seq=1,
            previous_project_bytes=None,
        )


def build_trust_domain_established_payload(
    genesis_document: Mapping[str, Any],
) -> dict[str, Any]:
    """The unsigned ``trust_domain_established`` restatement for offline root signing.

    Pure: no database, no keys. A caller collects detached root signatures over
    ``root_signature_input(payload)`` and adds them as ``root_signatures`` before
    passing the payload to :func:`write_trust_genesis`.
    """
    return _genesis_payload_template(genesis_document)


def _genesis_payload_template(
    genesis_document: Mapping[str, Any],
) -> dict[str, Any]:
    from ._trust_domain import genesis_document_digest

    doc = parse_trust_genesis(genesis_document)
    binding_core = genesis_document.get("binding_core")
    if not isinstance(binding_core, Mapping):
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            "the genesis document carries no binding_core object",
            {"reason": "binding_core_absent"},
        )
    return {
        "type": "regista.trust-domain-established",
        "version": 1,
        "trust_domain_id": doc.trust_domain_id,
        "trust_domain_core_digest": doc.trust_domain_core_digest,
        "binding_core": dict(binding_core),
        "initial_governance": {
            "mode": doc.initial_governance.mode,
            "threshold": doc.initial_governance.threshold,
            "signer_count": doc.initial_governance.signer_count,
        },
        "genesis_document_digest": genesis_document_digest(genesis_document),
        "trust_log_project_instance_id": str(doc.trust_log.project_instance_id),
    }


def _root_signature_entry(
    payload: Mapping[str, Any], secret: bytes, fingerprint: str, signer_id: str
) -> dict[str, Any]:
    from ._signing_scheme import Ed25519Scheme
    from ._trust_log import root_signature_input

    signature, _payload_hash = Ed25519Scheme().sign(
        root_signature_input(payload), secret
    )
    return {
        "signer_id": signer_id,
        "fingerprint": fingerprint,
        "signature": base64.b64encode(bytes(signature)).decode("ascii"),
    }


def append_trust_log_event(
    mgr: ConnectionManager,
    *,
    keys: KeySet,
    genesis_document: dict[str, Any],
    transition: str,
    payload: Mapping[str, Any] | None,
    entity_kind: str,
    entity_id: _uuid.UUID,
    principal_id: str,
    authority: str,
    key_id: str | None = None,
    occurred_at: datetime | None = None,
) -> str:
    if transition not in TRUST_LOG_TRANSITIONS:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"transition {transition!r} is not a trust-log transition",
            {"reason": "transition_not_in_trust_log"},
        )
    if transition == TRUST_DOMAIN_ESTABLISHED:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            "trust_domain_established is the genesis write; use write_trust_genesis",
            {"reason": "genesis_requires_dedicated_write"},
        )
    with mgr.transaction() as conn:
        head = _lock_global_chain_head(conn)
        if head is None:
            raise RegistaError(
                ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED,
                "the trust-log chain has no genesis; an ordinary append cannot precede it",
                {"reason": "genesis_absent"},
            )
        key = _writer_key(keys, principal_id=principal_id, key_id=key_id)
        state = replay_trust_state(conn, genesis_document)
        admission_at = datetime.now(UTC)
        if (
            occurred_at is not None
            and occurred_at.tzinfo is not None
            and occurred_at.utcoffset() is not None
        ):
            admission_at = max(admission_at, occurred_at.astimezone(UTC))
        _verify_possession_evidence(
            conn,
            payload,
            transition,
            mode="admission",
            at_time=admission_at,
        )
        binding = _resolve_authority(
            state, principal_id, authority, transition, payload, key
        )
        entity_seq = _max_entity_seq(conn, entity_kind, entity_id) + 1
        previous_entity = _previous_entity_hash(conn, entity_kind, entity_id, entity_seq)
        envelope = _build_envelope(
            state.identity,
            event_id=_uuid.uuid4(),
            entity_kind=entity_kind,
            entity_id=entity_id,
            entity_seq=entity_seq,
            actor_id=principal_id,
            key_id=key.key_id,
            key_binding_event_hash=binding,
            transition=transition,
            payload=payload,
            producer=resolve_producer(),
            occurred_at=occurred_at or datetime.now(UTC),
            previous_entity_event_hash=previous_entity,
            previous_project_event_hash="sha256:" + head.hex(),
        )
        try:
            validate_v6_envelope(envelope)
        except Exception as exc:
            raise RegistaError(
                ErrorCode.V6_ENVELOPE_INVALID,
                f"the trust-log writer refused to sign an invalid envelope: {exc}",
                {"reason": "envelope_invalid"},
            ) from exc
        signed = sign_v6_envelope(envelope, key.secret)
        _self_verify(signed, state.identity, key.public_key)
        return _write_row(
            conn,
            envelope=envelope,
            signed=signed,
            entity_kind=entity_kind,
            entity_id=entity_id,
            entity_seq=entity_seq,
            previous_project_bytes=head,
        )


def _resolve_authority(
    state: TrustState,
    principal_id: str,
    authority: str,
    transition: str,
    payload: Mapping[str, Any] | None,
    key: Any,
) -> str:
    parsed = (
        _parse_lifecycle_payload(transition, payload or {})
        if transition in _REGISTRAR_LIFECYCLE
        else None
    )
    if parsed is not None:
        _check_payload_trust_domain(parsed, state.identity.trust_domain_id)
    elif transition == TRUST_ROOT_ROTATED:
        _check_payload_trust_domain(
            parse_trust_root_rotated(payload or {}), state.identity.trust_domain_id
        )
    elif transition == REGISTRAR_DELEGATED:
        _check_payload_trust_domain(
            parse_registrar_delegated(payload or {}), state.identity.trust_domain_id
        )
    elif transition == REGISTRAR_REVOKED:
        _check_payload_trust_domain(
            parse_registrar_revoked(payload or {}), state.identity.trust_domain_id
        )
    elif transition == TRUST_DOMAIN_CUSTODY_DECLARED:
        _check_payload_trust_domain(
            parse_trust_domain_custody_declared(payload or {}),
            state.identity.trust_domain_id,
        )
    if transition == PRINCIPAL_KEY_ENROLLED and parsed is not None:
        # Write-time admission of the B1 invariant (PR #58): enrolment binds a key where
        # there is none. Enforced here — the shared append path for BOTH root and
        # registrar authority — so a direct `append_trust_log_event` caller cannot write
        # an enrol that displaces a live key (which is a §5.6 rotation), and the poison
        # never reaches the durable log. Replay re-checks the same invariant.
        _check_enrollment_binds_fresh_key(
            parsed, state.principal_public_keys, state.principal_key_status
        )
    if transition == REGISTRAR_DELEGATED:
        # Write-time admission of the B1 fork invariant (PR #59 review): a second LIVE
        # registrar delegation for the same principal with differing terms forks the
        # credential — the writer previously admitted it and replay resolved it
        # last-write-wins (silent scope/key widening). Enforced here, in the shared
        # append path, in-transaction against the state replayed under the chain-head
        # lock, so a direct `append_trust_log_event` caller — and two honest concurrent
        # `delegate-registrar` runs — cannot bypass the CLI live-check. A revoked prior
        # delegation allows a fresh one (revoke -> re-delegate); byte-identical terms are
        # an idempotent no-op. Replay re-checks the same invariant.
        _check_registrar_delegation_no_live_fork(
            parse_registrar_delegated(payload or {}), state.registrars
        )
    if authority == _ROOT:
        if key.fingerprint() not in state.governance.signer_fingerprints:
            failure_reason = (
                "recovery_envelope_signer_not_current_root"
                if parsed is not None and parsed.is_recovery
                else "root_envelope_signer_not_current"
            )
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "a root-authorized event must be signed by a current root key",
                {"reason": failure_reason},
            )
        if transition == PRINCIPAL_KEY_ROTATED:
            assert parsed is not None
            if not parsed.is_recovery:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "a dual rotation must use a live registrar delegation",
                    {"reason": "dual_rotation_requires_registrar_authority"},
                )
            _check_authorized_by(
                parsed,
                expected_authority=_ROOT,
                actor_id=principal_id,
                key_id=key.key_id,
                expected_binding=None,
            )
            _classify_rotation(
                parsed,
                dict(payload or {}),
                state.governance,
                state.root_public_keys,
                state.principal_public_keys,
                state.principal_key_status,
            )
            return state.genesis_event_hash
        if transition == TRUST_ROOT_ROTATED:
            rotated = parse_trust_root_rotated(payload or {})
            _treq(
                verify_root_threshold(
                    dict(payload or {}), state.governance, state.root_public_keys
                ),
                state.governance,
            )
            apply_root_rotation(state.governance, rotated)
            return state.genesis_event_hash
        if transition == TRUST_DOMAIN_CUSTODY_DECLARED:
            # WI-314: admit the correction against the current replayed custody head
            # BEFORE it is durably appended, mirroring the root-rotation write-time
            # check above. This raises the same named error replay would raise for a
            # seq gap or a wrong-predecessor supersession, so a malformed correction is
            # refused fail-closed instead of wedging the log. Falls through to the
            # shared root-threshold check below.
            custody_head = (
                (state.current_custody, state.current_custody_digest)
                if state.current_custody is not None
                and state.current_custody_digest is not None
                else None
            )
            admit_custody_declaration(
                custody_head,
                parse_trust_domain_custody_declared(payload or {}),
            )
        if parsed is not None:
            _check_authorized_by(
                parsed,
                expected_authority=_ROOT,
                actor_id=principal_id,
                key_id=key.key_id,
                expected_binding=None,
            )
        _treq(
            verify_root_threshold(
                dict(payload or {}), state.governance, state.root_public_keys
            ),
            state.governance,
        )
        return state.genesis_event_hash
    if authority == _REGISTRAR:
        entry = state.registrars.get(principal_id)
        reason = _registrar_refusal(state, entry, transition, key)
        if reason is not None:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"{principal_id!r} is not authorised as a registrar: {reason}",
                {"reason": reason, "authority": _REGISTRAR},
            )
        assert entry is not None
        if parsed is not None:
            if transition == PRINCIPAL_KEY_ROTATED and parsed.is_recovery:
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    "a recovery rotation requires root authority",
                    {"reason": "recovery_requires_root_authority"},
                )
            _check_authorized_by(
                parsed,
                expected_authority=_REGISTRAR,
                actor_id=principal_id,
                key_id=key.key_id,
                expected_binding=entry.delegated_event_hash,
            )
            if transition == PRINCIPAL_KEY_ROTATED:
                _classify_rotation(
                    parsed,
                    dict(payload or {}),
                    state.governance,
                    state.root_public_keys,
                    state.principal_public_keys,
                    state.principal_key_status,
                )
        return entry.delegated_event_hash
    raise RegistaError(
        ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
        f"unknown authority {authority!r}",
        {"reason": "unknown_authority"},
    )


def _registrar_refusal(
    state: TrustState,
    entry: RegistrarState | None,
    transition: str,
    key: Any,
) -> str | None:
    if entry is None or entry.revoked:
        return "no_live_delegation"
    now = datetime.now(UTC)
    if now < entry.not_before or now > entry.not_after:
        return "delegation_not_valid_now"
    if transition not in entry.scopes:
        return "transition_out_of_scope"
    if entry.max_operations is not None and entry.operations_used >= entry.max_operations:
        return "max_operations_exhausted"
    if key.fingerprint() != _compute_fingerprint(entry.public_key, "ed25519"):
        return "signer_key_not_the_delegated_key"
    if key.key_id != entry.key_id:
        return "signer_key_id_not_the_delegated_key"
    return None


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
