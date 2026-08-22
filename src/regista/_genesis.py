"""The single clean-epoch v6 project-genesis write and recovery path."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg.types.json
from psycopg.sql import SQL, Identifier

from ._connection import DictConn
from ._errors import ErrorCode, RegistaError
from ._keys import KeyEntry, KeySet
from ._signing import compute_v6_event_hash, sign_v6_envelope
from ._v6_referents import store_referents
from ._verification import (
    V6_ENTITY_KINDS,
    EventRow,
    KeySetResolver,
    V6EnvelopeError,
    parse_v6_envelope_strict,
    validate_v6_envelope,
    verify_event_strict,
    verify_v6_signature,
)

GENESIS_TRANSITION = "project_initialized"
GENESIS_ENTITY_KIND = "project"
# Compatibility spelling used by early v6 conformance fixtures.
_GENESIS_TRANSITION = GENESIS_TRANSITION
_MISSING = object()
#: The closed eight-value registry, imported rather than restated — see
#: ``_verification.V6_ENTITY_KINDS``.
_V6_ENTITY_KINDS = V6_ENTITY_KINDS

_REQUIRED_LOAD_BEARING_PATHS: tuple[tuple[str, ...], ...] = (
    ("type",),
    ("version",),
    ("project_instance_id",),
    ("trust_domain_id",),
    ("event_id",),
    ("entity", "kind"),
    ("entity", "id"),
    ("entity_seq",),
    ("actor", "principal_id"),
    ("actor", "kind"),
    ("actor", "metadata"),
    ("signing", "scheme_id"),
    ("signing", "key_id"),
    ("signing", "key_binding_event_hash"),
    ("authorization", "mode"),
    ("authorization", "credentials"),
    ("workflow",),
    ("occurred_at",),
    ("transition",),
    ("payload",),
    ("chain", "hash_algorithm"),
    ("chain", "previous_entity_event_hash"),
    ("chain", "previous_project_event_hash"),
    ("producer", "harness"),
    ("producer", "harness_version"),
    ("producer", "model"),
    ("producer", "model_lineage"),
)

_REQUIRED_NONEMPTY_PATHS: tuple[tuple[str, ...], ...] = (
    ("type",),
    ("project_instance_id",),
    ("trust_domain_id",),
    ("event_id",),
    ("entity", "kind"),
    ("entity", "id"),
    ("actor", "principal_id"),
    ("actor", "kind"),
    ("signing", "scheme_id"),
    ("signing", "key_id"),
    ("authorization", "mode"),
    ("occurred_at",),
    ("transition",),
    ("chain", "hash_algorithm"),
    ("producer", "harness"),
    ("producer", "harness_version"),
)

LOAD_BEARING_FIELDS: tuple[str, ...] = tuple(
    ".".join(path) for path in _REQUIRED_LOAD_BEARING_PATHS
)

_GENESIS_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, event_seq, actor_id, "
    "actor_kind, actor_metadata, key_id, workflow_name, workflow_version, timestamp, "
    "transition, payload, payload_canonical_hash, signature, canonical_envelope, "
    "on_behalf_of, scheme_id, prev_event_hash, global_seq, prev_global_event_hash"
)


def _value_at(envelope: Mapping[str, Any], path: tuple[str, ...]) -> object:
    current: object = envelope
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def missing_load_bearing_fields(envelope: Mapping[str, Any]) -> tuple[str, ...]:
    missing: list[str] = []
    for path in _REQUIRED_LOAD_BEARING_PATHS:
        if _value_at(envelope, path) is _MISSING:
            missing.append(".".join(path))
    for path in _REQUIRED_NONEMPTY_PATHS:
        value = _value_at(envelope, path)
        if value is _MISSING:
            continue
        if not isinstance(value, str) or not value.strip():
            name = ".".join(path)
            if name not in missing:
                missing.append(name)
    return tuple(missing)


def validate_load_bearing_fields(envelope: Mapping[str, Any]) -> None:
    missing = missing_load_bearing_fields(envelope)
    if missing:
        raise RegistaError(
            ErrorCode.LOAD_BEARING_FIELD_MISSING,
            "v6 genesis refused: load-bearing fields are absent or blank: "
            + ", ".join(missing),
            detail={"fields": list(missing)},
        )


def first_write_admission(
    *,
    gate_passed: bool,
    event_count: int,
    head_hash: bytes | None,
    transition: str,
    archived_event_count: int = 0,
    identity_present: bool = False,
) -> None:
    if (
        type(event_count) is not int
        or event_count < 0
        or type(archived_event_count) is not int
        or archived_event_count < 0
        or (head_hash is not None and not isinstance(head_hash, bytes))
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "v6 genesis admission measurements have invalid types or values",
        )
    if gate_passed is not True:
        raise RegistaError(
            ErrorCode.GENESIS_GATE_NOT_PASSED,
            "v6 genesis refused: the genesis conformance gate has not passed",
        )
    if transition != GENESIS_TRANSITION:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"v6 project genesis requires transition {GENESIS_TRANSITION!r}",
        )
    if identity_present or event_count != 0 or archived_event_count != 0 or head_hash is not None:
        details: list[str] = []
        if identity_present:
            details.append("project identity is already established")
        if event_count:
            details.append(f"{event_count} live event(s) already exist")
        if archived_event_count:
            details.append(f"{archived_event_count} archived event(s) already exist")
        if head_hash is not None:
            details.append("the chain head is already populated")
        raise RegistaError(
            ErrorCode.GENESIS_ALREADY_WRITTEN,
            "v6 genesis refused: " + "; ".join(details),
            detail={
                "live_event_count": event_count,
                "archived_event_count": archived_event_count,
                "identity_present": identity_present,
                "head_present": head_hash is not None,
            },
        )


def _relation_exists(conn: DictConn, relation: str) -> bool:
    row = conn.execute(
        SQL("SELECT to_regclass(%s) AS relation"),
        [relation],
    ).fetchone()
    return row is not None and row["relation"] is not None


def _count_rows(conn: DictConn, relation: str) -> int:
    row = conn.execute(
        SQL("SELECT COUNT(*) AS event_count FROM {}").format(Identifier(relation))
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"could not measure {relation} during v6 genesis admission",
        )
    return int(row["event_count"])


def _identity_row(conn: DictConn, *, for_update: bool) -> dict[str, Any] | None:
    if not _relation_exists(conn, "project_identity"):
        raise RegistaError(
            ErrorCode.MIGRATION_REQUIRED,
            "v6 genesis requires the clean-epoch project_identity baseline; "
            "recreate this schema instead of importing legacy history",
        )
    suffix = " FOR UPDATE" if for_update else ""
    return conn.execute(
        SQL(
            "SELECT project_instance_id, trust_domain_id, genesis_event_id, "
            "genesis_event_hash, principal_id, key_id, scheme_id, key_fingerprint "
            f"FROM project_identity WHERE id = TRUE{suffix}"
        )
    ).fetchone()


def _archived_count(conn: DictConn) -> int:
    if not _relation_exists(conn, "events_archive"):
        return 0
    return _count_rows(conn, "events_archive")


def _admit_legacy_append_after_lock(conn: DictConn, *, writer: str) -> bytes | None:
    identity = _identity_row(conn, for_update=False)
    live_count = _count_rows(conn, "events")
    archived_count = _archived_count(conn)
    head_row = conn.execute(
        SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE")
    ).fetchone()
    head_hash = None if head_row is None or head_row["head_hash"] is None else bytes(
        head_row["head_hash"]
    )
    if identity is not None:
        raise RegistaError(
            ErrorCode.V6_EPOCH_OPEN,
            f"{writer} refused: legacy event writers cannot extend the opened v6 epoch",
            detail={"writer": writer},
        )
    raise RegistaError(
        ErrorCode.GENESIS_REQUIRED,
        f"{writer} refused: project genesis must be written before ordinary events",
        detail={
            "writer": writer,
            "live_event_count": live_count,
            "archived_event_count": archived_count,
            "head_present": head_hash is not None,
        },
    )


def check_legacy_append(conn: DictConn, *, writer: str) -> None:
    """Reject a legacy write outside the clean v6 genesis window.

    This is the lock-free preflight. Writers call :func:`admit_legacy_append`
    again after acquiring their entity/work-item lock so the final decision is
    made while holding the global chain sentinel lock, without introducing a
    global-lock-before-work-item-lock deadlock. Legacy writers are refused both
    before genesis and after the v6 epoch has opened; only the explicit v6
    genesis writer may cross this boundary.
    """
    identity = _identity_row(conn, for_update=False)
    if identity is not None:
        raise RegistaError(
            ErrorCode.V6_EPOCH_OPEN,
            f"{writer} refused: legacy event writers cannot extend the opened v6 epoch",
            detail={"writer": writer},
        )
    raise RegistaError(
        ErrorCode.GENESIS_REQUIRED,
        f"{writer} refused: project genesis must be written before ordinary events",
        detail={"writer": writer},
    )


def reject_legacy_append_after_genesis(conn: DictConn) -> None:
    """Compatibility guard for callers that only need the post-genesis check."""
    if not _relation_exists(conn, "project_identity"):
        return
    row = conn.execute(SQL("SELECT 1 FROM project_identity WHERE id = TRUE")).fetchone()
    if row is not None:
        raise RegistaError(
            ErrorCode.V6_EPOCH_OPEN,
            "legacy event append refused: the project already opened its v6 epoch",
        )


def admit_legacy_append(conn: DictConn, *, writer: str) -> bytes | None:
    from ._events import _lock_global_chain_head

    head_hash = _lock_global_chain_head(conn)
    _admit_legacy_append_after_lock(conn, writer=writer)
    return head_hash


def _digest_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise RegistaError(ErrorCode.GENESIS_INVALID, "invalid sha256 digest")
    try:
        return bytes.fromhex(value[7:])
    except ValueError as exc:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "invalid sha256 digest") from exc


def _require_digest(value: object, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or value[:7] != "sha256:"
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"project genesis field {field} must be sha256:<64 lowercase hex>",
        )


def _decode_public_key(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise RegistaError(ErrorCode.GENESIS_INVALID, f"{field} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RegistaError(ErrorCode.GENESIS_INVALID, f"{field} is not valid base64") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"{field} must be canonical base64 for exactly 32 raw bytes",
        )
    return decoded


def _validate_bootstrap_acceptance(envelope: Mapping[str, Any], key_entry: KeyEntry) -> str:
    payload = envelope["payload"]
    acceptance = payload.get("bootstrap_key_acceptance") if isinstance(payload, dict) else None
    required = {
        "principal_id",
        "key_id",
        "scheme_id",
        "public_key",
        "fingerprint",
        "trust_event_hash",
        "trust_log_checkpoint",
        "scopes",
    }
    if not isinstance(acceptance, dict) or set(acceptance) != required:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis requires the complete bootstrap_key_acceptance object",
        )

    actor_principal = envelope["actor"]["principal_id"]
    if acceptance["principal_id"] != actor_principal:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            "bootstrap_key_acceptance.principal_id must equal actor.principal_id",
        )
    if key_entry.principal_id != actor_principal:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            "the signing key principal must equal actor.principal_id",
        )
    if acceptance["key_id"] != envelope["signing"]["key_id"]:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.key_id must equal signing.key_id",
        )
    if acceptance["scheme_id"] != "ed25519":
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.scheme_id must be ed25519",
        )

    public_key = _decode_public_key(acceptance["public_key"], "bootstrap_key_acceptance.public_key")
    if key_entry.public_key is None or public_key != key_entry.public_key:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            "bootstrap_key_acceptance.public_key does not match the signing key",
        )
    expected_fingerprint = "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()
    if acceptance["fingerprint"] != expected_fingerprint:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.fingerprint does not match public_key",
        )
    _require_digest(acceptance["trust_event_hash"], "bootstrap_key_acceptance.trust_event_hash")

    checkpoint = acceptance["trust_log_checkpoint"]
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "checkpoint_seq", "head_event_hash", "document_digest",
    }:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.trust_log_checkpoint has the wrong shape",
        )
    checkpoint_seq = checkpoint["checkpoint_seq"]
    if (
        not isinstance(checkpoint_seq, int)
        or isinstance(checkpoint_seq, bool)
        or checkpoint_seq < 1
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.checkpoint_seq must be an integer >= 1",
        )
    _require_digest(
        checkpoint["head_event_hash"],
        "bootstrap_key_acceptance.trust_log_checkpoint.head_event_hash",
    )
    _require_digest(
        checkpoint["document_digest"],
        "bootstrap_key_acceptance.trust_log_checkpoint.document_digest",
    )

    scopes = acceptance["scopes"]
    if not isinstance(scopes, dict) or set(scopes) != {
        "entity_kinds",
        "transitions",
        "may_accept_keys",
        "may_sign_checkpoints",
        "may_sign_bundles",
    }:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.scopes has the wrong shape",
        )
    entity_kinds = scopes["entity_kinds"]
    if (
        not isinstance(entity_kinds, list)
        or not entity_kinds
        or not all(isinstance(kind, str) and kind in _V6_ENTITY_KINDS for kind in entity_kinds)
        or len(entity_kinds) != len(set(entity_kinds))
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.scopes.entity_kinds must be unique v6 entity kinds",
        )
    if GENESIS_ENTITY_KIND not in entity_kinds:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap key acceptance does not authorize project genesis",
        )
    transitions = scopes["transitions"]
    if transitions is not None and (
        not isinstance(transitions, list)
        or not all(isinstance(transition, str) and transition.strip() for transition in transitions)
        or len(transitions) != len(set(transitions))
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.scopes.transitions must be strings or null",
        )
    if transitions is not None and GENESIS_TRANSITION not in transitions:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap key acceptance does not authorize project_initialized",
        )
    if scopes["may_accept_keys"] is not True or scopes["may_sign_checkpoints"] is not True:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap key acceptance must permit key acceptance and checkpoints",
        )
    if not isinstance(scopes["may_sign_bundles"], bool):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "bootstrap_key_acceptance.scopes.may_sign_bundles must be boolean",
        )
    return expected_fingerprint


def _validate_genesis_envelope(envelope: Mapping[str, Any]) -> None:
    validate_load_bearing_fields(envelope)
    try:
        validate_v6_envelope(envelope)
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"invalid v6 genesis envelope: {exc}",
        ) from exc
    if envelope["transition"] != GENESIS_TRANSITION:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"v6 project genesis requires transition {GENESIS_TRANSITION!r}",
        )
    if envelope["entity"]["kind"] != GENESIS_ENTITY_KIND:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis entity.kind must be project",
        )
    if envelope["entity"]["id"] != envelope["project_instance_id"]:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis entity.id must equal project_instance_id",
        )
    if envelope["workflow"] is not None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "project genesis workflow must be null")
    if envelope["authorization"] != {"mode": "direct", "credentials": []}:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis authorization must be direct with no credentials",
        )
    if envelope["signing"]["key_binding_event_hash"] is not None:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis key binding must use the external bootstrap position",
        )
    chain = envelope["chain"]
    if (
        chain["previous_entity_event_hash"] is not None
        or chain["previous_project_event_hash"] is not None
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "project genesis must have null predecessor links",
        )
    if envelope["entity_seq"] != 1:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "project genesis entity_seq must be 1")


def _genesis_key(
    key_set: KeySet,
    envelope: Mapping[str, Any],
    *,
    for_recovery: bool = False,
) -> KeyEntry:
    principal_id = envelope["actor"]["principal_id"]
    key_id = envelope["signing"]["key_id"]
    if for_recovery:
        # Recovery authenticates a historical signed event. It must be able to
        # resolve the key after it has been deprecated or revoked, and must not
        # re-run the active-key/actor write policy used for a new genesis.
        entry = key_set.get_key(key_id)
    else:
        entry = key_set.resolve_signing_key(principal_id, key_id=key_id)
        if entry.status != "active":
            raise RegistaError(
                ErrorCode.KEY_ROLE_NOT_PERMITTED,
                f"v6 genesis requires an active signing key; {entry.key_id!r} is {entry.status!r}",
            )
        if entry.role != "actor":
            raise RegistaError(
                ErrorCode.KEY_ROLE_NOT_PERMITTED,
                f"v6 genesis requires an actor key; {entry.key_id!r} has role {entry.role!r}",
            )
    if entry.scheme != "ed25519":
        raise RegistaError(ErrorCode.GENESIS_INVALID, "v6 genesis requires an Ed25519 key")
    if entry.principal_id != principal_id:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"genesis key {entry.key_id!r} is not bound to actor {principal_id!r}",
        )
    if entry.public_key is None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "v6 genesis key has no public key")
    return entry


def _occurred_at(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "occurred_at is not a valid UTC time",
        ) from exc


@dataclass(frozen=True)
class V6GenesisWrite:
    event_id: UUID
    project_instance_id: UUID
    trust_domain_id: UUID
    entity_seq: int
    global_seq: int
    canonical_envelope: bytes
    signature: bytes
    payload_canonical_hash: bytes
    event_hash: bytes
    principal_id: str = ""
    key_id: str = ""
    key_fingerprint: str = ""

    @property
    def genesis_event_hash(self) -> bytes:
        return self.event_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "project_instance_id": str(self.project_instance_id),
            "trust_domain_id": str(self.trust_domain_id),
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "entity_seq": self.entity_seq,
            "global_seq": self.global_seq,
            "canonical_envelope": self.canonical_envelope.hex(),
            "signature": self.signature.hex(),
            "payload_canonical_hash": "sha256:" + self.payload_canonical_hash.hex(),
            "event_hash": "sha256:" + self.event_hash.hex(),
        }


@dataclass(frozen=True)
class GenesisRecovery:
    event_id: UUID
    project_instance_id: UUID
    trust_domain_id: UUID
    principal_id: str
    key_id: str
    key_fingerprint: str
    scheme_id: str
    global_seq: int
    event_hash: bytes
    canonical_envelope: bytes
    signature: bytes
    payload_canonical_hash: bytes
    source: str
    verified: bool = True

    @property
    def genesis_event_hash(self) -> bytes:
        return self.event_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "project_instance_id": str(self.project_instance_id),
            "trust_domain_id": str(self.trust_domain_id),
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "scheme_id": self.scheme_id,
            "global_seq": self.global_seq,
            "event_hash": "sha256:" + self.event_hash.hex(),
            "canonical_envelope": self.canonical_envelope.hex(),
            "signature": self.signature.hex(),
            "payload_canonical_hash": "sha256:" + self.payload_canonical_hash.hex(),
            "source": self.source,
            "verified": self.verified,
        }


def append_v6_genesis(
    conn: DictConn,
    key_set: KeySet,
    envelope: Mapping[str, Any],
    *,
    gate_passed: bool,
) -> V6GenesisWrite:
    _validate_genesis_envelope(envelope)
    if gate_passed is not True:
        first_write_admission(
            gate_passed=gate_passed,
            event_count=0,
            archived_event_count=0,
            head_hash=None,
            transition=str(envelope.get("transition", GENESIS_TRANSITION)),
        )

    from ._events import _advance_global_chain_head, _lock_global_chain_head

    head_hash = _lock_global_chain_head(conn)
    identity = _identity_row(conn, for_update=True)
    live_count = _count_rows(conn, "events")
    archived_count = _archived_count(conn)
    first_write_admission(
        gate_passed=gate_passed,
        event_count=live_count,
        archived_event_count=archived_count,
        head_hash=head_hash,
        identity_present=identity is not None,
        transition=envelope["transition"],
    )

    key_entry = _genesis_key(key_set, envelope)
    if key_entry.public_key is None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "v6 genesis key has no public key")
    key_fingerprint = _validate_bootstrap_acceptance(envelope, key_entry)
    signed = sign_v6_envelope(envelope, key_entry.secret)
    verification = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        key_entry.public_key,
        payload_canonical_hash=signed.payload_canonical_hash,
        expected_event_hash=signed.event_hash,
        expected_project_instance_id=envelope["project_instance_id"],
        expected_trust_domain_id=envelope["trust_domain_id"],
        trusted_scheme_id="ed25519",
    )
    if not (
        verification.signature_and_hashes_valid
        and verification.project_binding_valid is True
        and verification.trust_domain_binding_valid is True
    ):
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            "v6 genesis signature did not verify under its bound Ed25519 public key",
            detail={"errors": list(verification.errors)},
        )

    entity = envelope["entity"]
    actor = envelope["actor"]
    workflow_name: str | None = None
    workflow_version: int | None = None
    timestamp = _occurred_at(envelope["occurred_at"])
    inserted = conn.execute(
        SQL(
            "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, hash_alg, "
            "event_seq, actor_id, actor_kind, actor_metadata, key_id, workflow_name, "
            "workflow_version, timestamp, transition, payload, payload_canonical_hash, "
            "signature, canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
            "prev_global_event_hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING global_seq"
        ),
        [
            UUID(envelope["event_id"]),
            UUID(entity["id"]),
            entity["kind"],
            UUID(entity["id"]),
            "sha-256",
            envelope["entity_seq"],
            actor["principal_id"],
            actor["kind"],
            psycopg.types.json.Jsonb(actor["metadata"])
            if actor["metadata"] is not None
            else None,
            envelope["signing"]["key_id"],
            workflow_name,
            workflow_version,
            timestamp,
            envelope["transition"],
            psycopg.types.json.Jsonb(envelope["payload"])
            if envelope["payload"] is not None
            else None,
            signed.payload_canonical_hash,
            signed.signature,
            signed.canonical_envelope,
            None,
            "ed25519",
            None,
            None,
        ],
    )
    result_row = inserted.fetchone()
    if result_row is None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "genesis insert returned no global_seq")
    global_seq = int(result_row["global_seq"])

    conn.execute(
        SQL(
            "INSERT INTO project_identity "
            "(id, project_instance_id, trust_domain_id, genesis_event_id, genesis_event_hash, "
            "principal_id, key_id, scheme_id, key_fingerprint) "
            "VALUES (TRUE, %s, %s, %s, %s, %s, %s, %s, %s)"
        ),
        [
            UUID(envelope["project_instance_id"]),
            UUID(envelope["trust_domain_id"]),
            UUID(envelope["event_id"]),
            signed.event_hash,
            actor["principal_id"],
            envelope["signing"]["key_id"],
            "ed25519",
            key_fingerprint,
        ],
    )
    _advance_global_chain_head(conn, UUID(envelope["event_id"]), signed.event_hash)
    return V6GenesisWrite(
        event_id=UUID(envelope["event_id"]),
        project_instance_id=UUID(envelope["project_instance_id"]),
        trust_domain_id=UUID(envelope["trust_domain_id"]),
        principal_id=actor["principal_id"],
        key_id=envelope["signing"]["key_id"],
        key_fingerprint=key_fingerprint,
        entity_seq=int(envelope["entity_seq"]),
        global_seq=global_seq,
        canonical_envelope=signed.canonical_envelope,
        signature=signed.signature,
        payload_canonical_hash=signed.payload_canonical_hash,
        event_hash=signed.event_hash,
    )


def _find_genesis_event(conn: DictConn, event_id: UUID) -> tuple[dict[str, Any], str] | None:
    row = conn.execute(
        SQL(f"SELECT {_GENESIS_EVENT_FIELDS} FROM events WHERE event_id = %s"),
        [event_id],
    ).fetchone()
    if row is not None:
        return row, "events"
    if _relation_exists(conn, "events_archive"):
        row = conn.execute(
            SQL(f"SELECT {_GENESIS_EVENT_FIELDS} FROM events_archive WHERE event_id = %s"),
            [event_id],
        ).fetchone()
        if row is not None:
            return row, "events_archive"
    return None


def read_genesis_from_connection(conn: DictConn, key_set: KeySet) -> GenesisRecovery | None:
    identity = _identity_row(conn, for_update=False)
    if identity is None:
        if _count_rows(conn, "events") == 0 and _archived_count(conn) == 0:
            return None
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "events exist but project_identity has no genesis binding",
        )

    try:
        event_id = UUID(str(identity["genesis_event_id"]))
    except (TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "project_identity contains an invalid genesis event ID",
        ) from exc
    found = _find_genesis_event(conn, event_id)
    if found is None:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "project_identity points to a missing genesis event",
        )
    row, source = found
    try:
        canonical_envelope = bytes(row["canonical_envelope"])
    except (TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "stored genesis event has no usable canonical envelope",
        ) from exc
    try:
        envelope = parse_v6_envelope_strict(canonical_envelope)
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            f"stored genesis envelope is invalid: {exc}",
        ) from exc
    try:
        _validate_genesis_envelope(envelope)
        key_entry = _genesis_key(key_set, envelope, for_recovery=True)
        if key_entry.public_key is None:
            raise RegistaError(ErrorCode.GENESIS_INVALID, "stored genesis key has no public key")
        key_fingerprint = _validate_bootstrap_acceptance(envelope, key_entry)
    except RegistaError as exc:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "stored genesis identity validation failed",
            detail={"cause": str(exc.code)},
        ) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "stored genesis identity validation failed",
        ) from exc
    if key_fingerprint != identity["key_fingerprint"]:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "project_identity key fingerprint does not match the genesis acceptance",
        )
    if (
        str(identity["project_instance_id"]) != envelope["project_instance_id"]
        or str(identity["trust_domain_id"]) != envelope["trust_domain_id"]
        or identity["principal_id"] != envelope["actor"]["principal_id"]
        or identity["key_id"] != envelope["signing"]["key_id"]
        or identity["scheme_id"] != "ed25519"
        or str(row["event_id"]) != envelope["event_id"]
    ):
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "project_identity does not match the signed genesis identity",
        )

    signature = bytes(row["signature"])
    payload_hash = bytes(row["payload_canonical_hash"])
    event_hash = compute_v6_event_hash(canonical_envelope, signature)
    if event_hash != bytes(identity["genesis_event_hash"]):
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "project_identity genesis_event_hash does not match stored event bytes",
        )
    verification = verify_v6_signature(
        canonical_envelope,
        signature,
        key_entry.public_key,
        payload_canonical_hash=payload_hash,
        expected_event_hash=event_hash,
        expected_project_instance_id=envelope["project_instance_id"],
        expected_trust_domain_id=envelope["trust_domain_id"],
        trusted_scheme_id="ed25519",
    )
    if not verification.signature_and_hashes_valid:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "stored genesis signature or hash verification failed",
            detail={"errors": list(verification.errors)},
        )
    row_result = verify_event_strict(
        EventRow.from_mapping(row),
        keys=KeySetResolver(key_set),
        # The store itself is the presented material. Genesis recovery only reads
        # `signature_valid` and `row_reconciled` below — it deliberately does not
        # require the *verdict*, because a genesis event's authority is external by
        # construction and recovery must work for an operator who has not yet pinned
        # a trust policy (RECONCILIATION.md Resolution 1).
        referents=store_referents(conn, label="project store (genesis recovery)"),
    )
    if not row_result.signature_valid or not row_result.row_reconciled:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "stored genesis row does not reconcile with its signed envelope",
            detail={"mismatched_fields": list(row_result.mismatched_field_names)},
        )
    return GenesisRecovery(
        event_id=event_id,
        project_instance_id=UUID(envelope["project_instance_id"]),
        trust_domain_id=UUID(envelope["trust_domain_id"]),
        principal_id=envelope["actor"]["principal_id"],
        key_id=envelope["signing"]["key_id"],
        key_fingerprint=key_fingerprint,
        scheme_id="ed25519",
        global_seq=int(row["global_seq"]),
        event_hash=event_hash,
        canonical_envelope=canonical_envelope,
        signature=signature,
        payload_canonical_hash=payload_hash,
        source=source,
    )


def read_genesis(conn: DictConn, key_set: KeySet) -> GenesisRecovery | None:
    return read_genesis_from_connection(conn, key_set)


__all__ = [
    "GENESIS_ENTITY_KIND",
    "GENESIS_TRANSITION",
    "LOAD_BEARING_FIELDS",
    "GenesisRecovery",
    "V6GenesisWrite",
    "admit_legacy_append",
    "append_v6_genesis",
    "check_legacy_append",
    "first_write_admission",
    "missing_load_bearing_fields",
    "read_genesis",
    "read_genesis_from_connection",
    "reject_legacy_append_after_genesis",
    "validate_load_bearing_fields",
]
