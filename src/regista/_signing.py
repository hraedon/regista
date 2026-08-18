from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from ._jcs import canonicalize
from ._v6_referents import NO_REFERENTS, ReferentResolver

if TYPE_CHECKING:
    from ._verification import Backend, VerificationPolicy, VerificationResult


def build_signing_envelope(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None = None,
) -> bytes:
    envelope = {
        "event_id": str(event_id),
        "work_item_id": str(work_item_id),
        "actor_id": actor_id,
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    return canonicalize(envelope)


def build_signing_envelope_v2(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None = None,
) -> bytes:
    envelope = {
        "event_id": str(event_id),
        "work_item_id": str(work_item_id),
        "actor_id": actor_id,
        "key_id": key_id,
        "event_seq": event_seq,
        "workflow_name": workflow_name,
        "workflow_version": workflow_version,
        "timestamp": timestamp.isoformat(),
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    return canonicalize(envelope)


def build_signing_envelope_v3(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
) -> bytes:
    envelope: dict[str, object] = {
        "event_id": str(event_id),
        "work_item_id": str(work_item_id),
        "actor_id": actor_id,
        "key_id": key_id,
        "event_seq": event_seq,
        "workflow_name": workflow_name,
        "workflow_version": workflow_version,
        "timestamp": timestamp.isoformat(),
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    if prev_event_hash is not None:
        envelope["prev_event_hash"] = prev_event_hash.hex()
    if global_seq is not None:
        envelope["global_seq"] = global_seq
    if prev_global_event_hash is not None:
        envelope["prev_global_event_hash"] = prev_global_event_hash.hex()
    return canonicalize(envelope)


def build_signing_envelope_v4(
    event_id: UUID,
    entity_kind: str,
    entity_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    hash_alg: str,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
) -> bytes:
    envelope: dict[str, object] = {
        "event_id": str(event_id),
        "entity_kind": entity_kind,
        "entity_id": str(entity_id),
        "actor_id": actor_id,
        "key_id": key_id,
        "event_seq": event_seq,
        "workflow_name": workflow_name,
        "workflow_version": workflow_version,
        "timestamp": timestamp.isoformat(),
        "hash_alg": hash_alg,
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    if prev_event_hash is not None:
        envelope["prev_event_hash"] = prev_event_hash.hex()
    if global_seq is not None:
        envelope["global_seq"] = global_seq
    if prev_global_event_hash is not None:
        envelope["prev_global_event_hash"] = prev_global_event_hash.hex()
    return canonicalize(envelope)


def build_signing_envelope_v5(
    event_id: UUID,
    entity_kind: str,
    entity_id: UUID,
    actor_id: str,
    actor_kind: str,
    actor_metadata: dict[str, Any] | None,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    hash_alg: str,
    transition: str | None,
    payload: dict[str, Any] | None,
    on_behalf_of: dict[str, Any] | None = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
) -> bytes:
    """Envelope v5: adds actor_kind and actor_metadata to the signed scope.

    WI-208: the spec says actor_kind/actor_metadata are signed fields, but v4
    does not include them. An attacker with database write access could change
    ``actor_kind`` from ``"agent"`` to ``"human"`` (or vice versa) without
    invalidating the v4 signature. v5 closes this gap by including both fields
    in the canonical envelope.
    """
    envelope: dict[str, object] = {
        "event_id": str(event_id),
        "entity_kind": entity_kind,
        "entity_id": str(entity_id),
        "actor_id": actor_id,
        "actor_kind": actor_kind,
        "actor_metadata": actor_metadata,
        "key_id": key_id,
        "event_seq": event_seq,
        "workflow_name": workflow_name,
        "workflow_version": workflow_version,
        "timestamp": timestamp.isoformat(),
        "hash_alg": hash_alg,
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    if prev_event_hash is not None:
        envelope["prev_event_hash"] = prev_event_hash.hex()
    if global_seq is not None:
        envelope["global_seq"] = global_seq
    if prev_global_event_hash is not None:
        envelope["prev_global_event_hash"] = prev_global_event_hash.hex()
    return canonicalize(envelope)


def canonicalize_v6_envelope(envelope: Mapping[str, Any]) -> bytes:
    """Canonicalize a structurally valid v6 envelope with RFC 8785."""

    from ._verification import validate_v6_envelope

    validate_v6_envelope(envelope)
    return canonicalize(dict(envelope))


_V6_MISSING = object()


def _v6_take(fields: dict[str, Any], *names: str, default: Any = _V6_MISSING) -> Any:
    for name in names:
        if name in fields:
            return fields.pop(name)
    return default


def _v6_text(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return "sha256:" + value.hex()
    return value


def _v6_occurred_at(value: Any) -> Any:
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        raise ValueError("v6 occurred_at requires an aware datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _v6_flatten_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    remaining = dict(fields)
    result: dict[str, Any] = {
        "type": _v6_take(remaining, "type", default="regista.event"),
        "version": _v6_take(remaining, "version", default=6),
        "project_instance_id": _v6_text(_v6_take(remaining, "project_instance_id")),
        "trust_domain_id": _v6_text(_v6_take(remaining, "trust_domain_id")),
        "event_id": _v6_text(_v6_take(remaining, "event_id")),
        "entity_seq": _v6_take(remaining, "entity_seq", "event_seq"),
    }
    entity = _v6_take(remaining, "entity")
    if entity is _V6_MISSING:
        entity = {
            "kind": _v6_take(remaining, "entity_kind"),
            "id": _v6_text(_v6_take(remaining, "entity_id")),
        }
    result["entity"] = entity

    actor = _v6_take(remaining, "actor")
    if actor is _V6_MISSING:
        actor = {
            "principal_id": _v6_take(
                remaining, "actor_principal_id", "principal_id", "actor_id"
            ),
            "kind": _v6_take(remaining, "actor_kind"),
            "metadata": _v6_take(remaining, "actor_metadata", default=None),
        }
    result["actor"] = actor

    signing = _v6_take(remaining, "signing")
    if signing is _V6_MISSING:
        signing = {
            "scheme_id": _v6_take(remaining, "scheme_id", default="ed25519"),
            "key_id": _v6_take(remaining, "key_id"),
            "key_binding_event_hash": _v6_text(
                _v6_take(remaining, "key_binding_event_hash", default=None)
            ),
        }
    result["signing"] = signing

    authorization = _v6_take(remaining, "authorization")
    if authorization is _V6_MISSING:
        authorization = {
            "mode": _v6_take(remaining, "authorization_mode", "auth_mode", default="direct"),
            "credentials": _v6_take(
                remaining,
                "authorization_credentials",
                "auth_credentials",
                "credentials",
                default=[],
            ),
        }
    result["authorization"] = authorization

    workflow = _v6_take(remaining, "workflow")
    workflow_name = _v6_take(remaining, "workflow_name")
    workflow_version = _v6_take(remaining, "workflow_version")
    workflow_definition_hash = _v6_text(
        _v6_take(remaining, "workflow_definition_hash", "definition_hash")
    )
    workflow_registration_event_hash = _v6_text(
        _v6_take(remaining, "workflow_registration_event_hash", "registration_event_hash")
    )
    flattened_workflow = (
        workflow_name,
        workflow_version,
        workflow_definition_hash,
        workflow_registration_event_hash,
    )
    flattened_workflow_present = tuple(
        value is not _V6_MISSING for value in flattened_workflow
    )
    if workflow is not _V6_MISSING and any(flattened_workflow_present):
        raise TypeError("nested workflow cannot be combined with flattened workflow fields")
    if workflow is _V6_MISSING:
        if any(flattened_workflow_present) and not all(flattened_workflow_present):
            raise TypeError("flattened workflow requires all four workflow fields")
        workflow = None if not any(flattened_workflow_present) else {
            "name": workflow_name,
            "version": workflow_version,
            "definition_hash": workflow_definition_hash,
            "registration_event_hash": workflow_registration_event_hash,
        }
    result["workflow"] = workflow

    result["occurred_at"] = _v6_occurred_at(
        _v6_take(remaining, "occurred_at", "timestamp")
    )
    result["transition"] = _v6_take(remaining, "transition")
    result["payload"] = _v6_take(remaining, "payload", default=None)

    chain = _v6_take(remaining, "chain")
    if chain is _V6_MISSING:
        chain = {
            "hash_algorithm": _v6_take(
                remaining, "hash_algorithm", "hash_alg", default="sha-256"
            ),
            "previous_entity_event_hash": _v6_text(
                _v6_take(remaining, "previous_entity_event_hash", "prev_event_hash", default=None)
            ),
            "previous_project_event_hash": _v6_text(
                _v6_take(
                    remaining,
                    "previous_project_event_hash",
                    "prev_global_event_hash",
                    default=None,
                )
            ),
        }
    result["chain"] = chain

    producer = _v6_take(remaining, "producer")
    if producer is _V6_MISSING:
        producer = {
            "harness": _v6_take(remaining, "producer_harness", "harness"),
            "harness_version": _v6_take(
                remaining, "producer_harness_version", "harness_version"
            ),
            "model": _v6_take(remaining, "producer_model", "model"),
            "model_lineage": _v6_take(remaining, "producer_model_lineage", "model_lineage"),
        }
    result["producer"] = producer

    if remaining:
        result.update(remaining)
    return result


def build_signing_envelope_v6(
    envelope: Mapping[str, Any] | None = None,
    **fields: Any,
) -> bytes:
    """Build canonical v6 bytes without changing legacy signing defaults.

    The preferred input is the complete sixteen-member object. Keyword fields
    are accepted as a convenience for callers using the legacy flattened
    builder style; all resulting fields still pass the strict v6 validator.
    """

    if envelope is not None and fields:
        raise TypeError("pass either envelope or keyword fields, not both")
    value: Mapping[str, Any] = envelope if envelope is not None else _v6_flatten_fields(fields)
    return canonicalize_v6_envelope(value)


@dataclass(frozen=True)
class V6SignedEnvelope:
    canonical_envelope: bytes
    signature: bytes
    payload_canonical_hash: bytes
    event_hash: bytes

    @property
    def payload_canonical_hash_text(self) -> str:
        return "sha256:" + self.payload_canonical_hash.hex()

    @property
    def event_hash_text(self) -> str:
        return "sha256:" + self.event_hash.hex()


def v6_signature_input(canonical_envelope: bytes) -> bytes:
    """Return the domain-separated Ed25519 input for canonical v6 bytes."""

    return b"regista.event.v6\x00" + canonical_envelope


def compute_v6_payload_canonical_hash(canonical_envelope: bytes) -> bytes:
    """Hash the v6 signature input, as required by the row projection contract."""

    return hashlib.sha256(v6_signature_input(canonical_envelope)).digest()


def compute_v6_event_hash(canonical_envelope: bytes, signature: bytes) -> bytes:
    """Compute the domain-separated, length-framed v6 event hash."""

    return hashlib.sha256(
        b"regista.event.hash.v1\x00"
        + struct.pack(">Q", len(canonical_envelope))
        + canonical_envelope
        + signature
    ).digest()


def v6_payload_canonical_hash(canonical_envelope: bytes) -> str:
    return "sha256:" + compute_v6_payload_canonical_hash(canonical_envelope).hex()


def v6_event_hash(canonical_envelope: bytes, signature: bytes) -> str:
    return "sha256:" + compute_v6_event_hash(canonical_envelope, signature).hex()


compute_v6_payload_canonical_hash_text = v6_payload_canonical_hash
compute_v6_event_hash_text = v6_event_hash


def sign_v6_envelope(
    envelope: Mapping[str, Any] | bytes,
    private_key: bytes,
) -> V6SignedEnvelope:
    """Sign a v6 envelope with Ed25519 and return all production artifacts."""

    if isinstance(envelope, bytes):
        from ._verification import parse_v6_envelope_strict

        parsed = parse_v6_envelope_strict(envelope)
        canonical_envelope = canonicalize_v6_envelope(parsed)
    else:
        canonical_envelope = canonicalize_v6_envelope(envelope)
    signing_input = v6_signature_input(canonical_envelope)
    from ._signing_scheme import Ed25519Scheme

    signature, payload_hash = Ed25519Scheme().sign(signing_input, private_key)
    return V6SignedEnvelope(
        canonical_envelope=canonical_envelope,
        signature=signature,
        payload_canonical_hash=payload_hash,
        event_hash=compute_v6_event_hash(canonical_envelope, signature),
    )


build_v6_envelope = build_signing_envelope_v6
canonicalize_envelope_v6 = canonicalize_v6_envelope
canonicalize_v6 = canonicalize_v6_envelope
sign_v6_event = sign_v6_envelope
signature_input_v6 = v6_signature_input
compute_v6_signature_input = v6_signature_input
event_hash_v6 = v6_event_hash
payload_canonical_hash_v6 = v6_payload_canonical_hash


def sign_event(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    key: bytes,
    on_behalf_of: dict[str, Any] | None = None,
    scheme: Any = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    actor_kind: str | None = None,
    actor_metadata: dict[str, Any] | None = None,
) -> tuple[bytes, bytes, bytes]:
    from ._signing_scheme import HMACSHA256Scheme

    if scheme is None:
        scheme = HMACSHA256Scheme()

    if actor_kind is not None:
        envelope = build_signing_envelope_v5(
            event_id=event_id,
            entity_kind=entity_kind,
            entity_id=work_item_id,
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            key_id=key_id,
            event_seq=event_seq,
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            timestamp=timestamp,
            hash_alg=hash_alg,
            transition=transition,
            payload=payload,
            on_behalf_of=on_behalf_of,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
    else:
        envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind=entity_kind,
            entity_id=work_item_id,
            actor_id=actor_id,
            key_id=key_id,
            event_seq=event_seq,
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            timestamp=timestamp,
            hash_alg=hash_alg,
            transition=transition,
            payload=payload,
            on_behalf_of=on_behalf_of,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
    signature, canonical_hash = scheme.sign(envelope, key, hash_alg=hash_alg)
    return (signature, canonical_hash, envelope)


_VERSION_NUMBERS: dict[str, int] = {
    "v1": 1,
    "v2": 2,
    "v3": 3,
    "v4": 4,
    "v5": 5,
    "v6": 6,
}


def classify_envelope_version(envelope: bytes) -> int:
    """Classify stored envelope bytes strictly. ``0`` means "no known schema".

    WI-267: the classifier this replaced used ``issuperset``, so *any subset* of
    a version's fields — including ``{}`` and an attacker-authored object — fell
    through to ``return 1`` and was treated as a v1 envelope. Being classified
    v1 is the weakest possible claim (v1 signs six fields) and was therefore the
    most attractive target. Nothing falls through to v1 now: a missing required
    field or an unrecognised key is ``0``.
    """
    from ._verification import classify_envelope_bytes

    return _VERSION_NUMBERS.get(str(classify_envelope_bytes(envelope)), 0)


def compute_chain_head_hash(canonical_envelope: bytes, signature: bytes) -> bytes:
    """The hash-chain head an event contributes, under ITS OWN envelope version.

    v6 uses the domain-separated, length-framed :func:`compute_v6_event_hash`;
    v1-v5 use SHA-256 over the envelope/signature concatenation. ``hash_alg`` is
    not consulted: it selects a digest *inside* legacy signing envelopes, not the
    chain-link construction.

    This lives here, at the bottom of the import graph, because it is the formula
    the *whole tree* chains with and every hand-copy of it has been a bug. Two
    are on the record: mutation M20 (NOTES-P17 finding 15) reverted
    ``_bundle._hash_event`` to the legacy formula and the suite stayed green, and
    ``_in_memory_replay`` had the legacy formula hardcoded in both its chain
    walks — which made a healthy in-memory v6 epoch report five chain breaks. A
    version-aware formula that exists in four places is a formula that is
    version-aware in three.
    """

    if classify_envelope_version(canonical_envelope) == 6:
        return compute_v6_event_hash(canonical_envelope, signature)
    return hashlib.sha256(canonical_envelope + signature).digest()


def verify_event(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    signature: bytes,
    canonical_hash: bytes,
    key: bytes,
    stored_envelope: bytes | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    scheme: Any = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    actor_kind: str | None = None,
    actor_metadata: dict[str, Any] | None = None,
    scheme_id: str | None = None,
    backend: Backend | None = None,
    policy: VerificationPolicy | None = None,
    referents: ReferentResolver = NO_REFERENTS,
) -> bool:
    """Boolean bridge over :func:`regista._verification.verify_event_strict`.

    WI-267: this used to assemble up to six candidate envelopes **from the row
    columns under attack** and return ``True`` on the first that verified. That
    fallback is deleted, not disabled — there is no flag to re-enable it,
    because a flag would be the silent pass. The stored envelope is now the only
    envelope, and every field it signs must agree with the values passed here
    before this returns ``True``.

    Two consequences callers must know about:

    * ``stored_envelope=None`` is ``unverifiable``, not "try to rebuild one".
      Reconstructing a missing envelope is an explicit offline operator action.
    * The arguments describe the *row*. Passing fewer of them than the envelope
      signs (e.g. omitting ``actor_kind`` for a v5 event) is a disagreement with
      the signed bytes and fails.

    Prefer :func:`verify_event_strict`, which returns the structured result
    including *which* field disagreed.
    """
    return verify_event_result(
        event_id=event_id,
        work_item_id=work_item_id,
        actor_id=actor_id,
        key_id=key_id,
        event_seq=event_seq,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=timestamp,
        transition=transition,
        payload=payload,
        signature=signature,
        canonical_hash=canonical_hash,
        key=key,
        stored_envelope=stored_envelope,
        on_behalf_of=on_behalf_of,
        scheme=scheme,
        prev_event_hash=prev_event_hash,
        global_seq=global_seq,
        prev_global_event_hash=prev_global_event_hash,
        entity_kind=entity_kind,
        hash_alg=hash_alg,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        scheme_id=scheme_id,
        backend=backend,
        policy=policy,
        referents=referents,
    ).accepted


def verify_event_result(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    transition: str | None,
    payload: dict[str, Any] | None,
    signature: bytes,
    canonical_hash: bytes,
    key: bytes,
    stored_envelope: bytes | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    scheme: Any = None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    actor_kind: str | None = None,
    actor_metadata: dict[str, Any] | None = None,
    entity_id: UUID | None = None,
    scheme_id: str | None = None,
    backend: Backend | None = None,
    policy: VerificationPolicy | None = None,
    referents: ReferentResolver = NO_REFERENTS,
) -> VerificationResult:
    """Field-wise entry point to the one verification primitive."""
    from ._signing_scheme import HMACSHA256Scheme
    from ._verification import (
        DEFAULT_POLICY,
        Backend,
        EventRow,
        StaticKeyResolver,
        TrustedKeySource,
        verify_event_strict,
    )

    if scheme is None:
        scheme = HMACSHA256Scheme()

    row = EventRow(
        event_id=event_id,
        work_item_id=work_item_id,
        entity_kind=entity_kind,
        entity_id=entity_id if entity_id is not None else work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_id=key_id,
        event_seq=event_seq,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        timestamp=timestamp,
        hash_alg=hash_alg,
        on_behalf_of=on_behalf_of,
        transition=transition,
        payload=payload,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=prev_global_event_hash,
        global_seq=global_seq,
        canonical_envelope=stored_envelope,
        signature=signature,
        payload_canonical_hash=canonical_hash,
        row_scheme_id=scheme_id,
        backend=backend or Backend.POSTGRES,
    )
    resolver = StaticKeyResolver(
        material=key,
        scheme_id=getattr(scheme, "scheme_id", None),
        scheme_obj=scheme,
        source=TrustedKeySource.SUPPLIED_PUBLIC_KEY,
    )
    return verify_event_strict(
        row,
        keys=resolver,
        # This helper is handed *field values*, not a chain. For a v6 event that
        # means its key binding, workflow registration and chain position are
        # unestablished, and the verdict says exactly that (UNVERIFIABLE /
        # key_binding_unresolved) instead of guessing. A caller that holds material
        # passes it; the default is the honest answer for one row, and it is spelled
        # by name so a reader can see which it is.
        referents=referents,
        policy=policy or DEFAULT_POLICY,
    )


def verify_event_with_public_key(
    event: Any,
    public_key: bytes,
    *,
    scheme_id: str | None = None,
    backend: Backend | None = None,
    policy: VerificationPolicy | None = None,
) -> bool:
    """Verify ``event`` under caller-supplied key material.

    ``scheme_id`` names the scheme the *key* uses. When omitted the event row's
    self-declared ``scheme_id`` is used, which is trusted metadata only insofar
    as the caller vouched for the key: with no registry there is nothing else to
    derive it from. Callers that hold key metadata (a KeySet, the principal
    registry, a bundle registry) must pass it — that is the S2 binding.
    """
    return verify_event_result_with_public_key(
        event, public_key, scheme_id=scheme_id, backend=backend, policy=policy,
    ).accepted


def verify_event_result_with_public_key(
    event: Any,
    public_key: bytes,
    *,
    scheme_id: str | None = None,
    backend: Backend | None = None,
    policy: VerificationPolicy | None = None,
    referents: ReferentResolver = NO_REFERENTS,
) -> VerificationResult:
    from ._verification import (
        DEFAULT_POLICY,
        Backend,
        EventRow,
        StaticKeyResolver,
        TrustedKeySource,
        verify_event_strict,
    )

    row = EventRow.from_event(event, backend=backend or Backend.POSTGRES)
    resolver = StaticKeyResolver(
        material=public_key,
        scheme_id=scheme_id,
        source=TrustedKeySource.SUPPLIED_PUBLIC_KEY,
    )
    return verify_event_strict(
        row,
        keys=resolver,
        referents=referents,
        policy=policy or DEFAULT_POLICY,
    )



@dataclass(frozen=True)
class PrincipalVerificationResult:
    verified: bool
    principal_id: str | None
    key_id: str | None
    error: str | None


def _event_timestamp_for_binding(
    event_or_evt: object,
) -> datetime | None:
    ts = None
    if hasattr(event_or_evt, "timestamp"):
        ts = getattr(event_or_evt, "timestamp")
    elif isinstance(event_or_evt, dict):
        ts = event_or_evt.get("timestamp")
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return _ensure_aware(ts)
    try:
        return _ensure_aware(datetime.fromisoformat(str(ts)))
    except (ValueError, TypeError):
        return None


def _is_key_valid_at(entry: object, when: datetime | None) -> bool:
    if when is None:
        return False
    valid_from = None
    valid_to = None
    if hasattr(entry, "valid_from"):
        valid_from = getattr(entry, "valid_from")
        valid_to = getattr(entry, "valid_to")
    elif isinstance(entry, dict):
        valid_from = entry.get("valid_from")
        valid_to = entry.get("valid_to")
    if isinstance(valid_from, str):
        try:
            valid_from = datetime.fromisoformat(valid_from)
        except (ValueError, TypeError):
            return False
    if isinstance(valid_to, str):
        try:
            valid_to = datetime.fromisoformat(valid_to)
        except (ValueError, TypeError):
            return False
    if valid_from is not None:
        valid_from = _ensure_aware(valid_from)
    if valid_to is not None:
        valid_to = _ensure_aware(valid_to)
    if valid_from is not None and when < valid_from:
        return False
    if valid_to is not None and when > valid_to:
        return False
    return True


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        from datetime import UTC
        return value.replace(tzinfo=UTC)
    return value


def _derived_scheme_for_binding(
    entries: list[Any], event_key_id: str | None,
) -> str | None:
    """The scheme this event's key actually uses, per the trusted registry.

    WI-267 / S2-interim. ``scheme_id`` is outside every signed envelope version,
    so the row's claim is an assertion by whoever wrote the row. Where the
    principal-key registry names the key, the registry's scheme is the answer
    and the row's claim is advisory.
    """
    if event_key_id is None:
        return None
    for entry in entries:
        if entry.key_id == event_key_id:
            return str(entry.scheme)
    return None


def _any_asymmetric(entries: list[Any]) -> bool:
    from ._signing_scheme import asymmetric_scheme_ids

    asym = asymmetric_scheme_ids()
    return any(e.scheme in asym for e in entries)


def _verify_principal_binding_core(
    entries: list[Any],
    actor_id: str,
    scheme_id: str,
    verify_fn: Callable[[Any], bool],
    event_key_id: str | None = None,
    event_timestamp: datetime | None = None,
) -> PrincipalVerificationResult:
    """Bind an event's signature to a registered principal key.

    ``scheme_id`` is the **row's** self-declared scheme and is used only for
    reporting and as a last resort when the registry knows nothing about the
    key. Every decision that matters is taken from the registry entry's own
    ``scheme`` (WI-267 / S2-interim).
    """
    if not entries:
        return PrincipalVerificationResult(
            verified=False,
            principal_id=None,
            key_id=None,
            error=f"unregistered-signer: no key for actor {actor_id!r}",
        )

    non_revoked = [e for e in entries if e.status in ("active", "superseded")]
    if not non_revoked:
        return PrincipalVerificationResult(
            verified=False,
            principal_id=actor_id,
            key_id=None,
            error=f"key-revoked: all keys for principal {actor_id!r} have been revoked",
        )

    # The scheme comes from trusted key metadata, never from the row. A row
    # relabelled 'hmac-sha256' must not exempt an ed25519 key from anything.
    derived_scheme_id = _derived_scheme_for_binding(entries, event_key_id)
    if (
        derived_scheme_id is not None
        and scheme_id is not None
        and derived_scheme_id != scheme_id
    ):
        return PrincipalVerificationResult(
            verified=False,
            principal_id=next(
                (e.principal_id for e in entries if e.key_id == event_key_id), actor_id,
            ),
            key_id=event_key_id,
            error=(
                f"scheme-mismatch: event claims scheme_id={scheme_id!r} but "
                f"registered key {event_key_id!r} is {derived_scheme_id!r}; "
                f"the registry's scheme wins"
            ),
        )
    effective_scheme_id = derived_scheme_id or scheme_id

    if event_key_id is not None:
        matching = [e for e in non_revoked if e.key_id == event_key_id]
        if matching:
            non_revoked = matching
        elif not _any_asymmetric(non_revoked):
            # Legacy symmetric deployment: a shared HMAC key predates
            # per-principal custody, so an event key_id absent from the registry
            # is not evidence of anything (WI-223). The exemption is keyed on
            # the *registered keys being symmetric*, not on the row's claim —
            # otherwise an ed25519 event opts itself out by relabelling.
            pass
        else:
            revoked_match = [
                e for e in entries
                if e.key_id == event_key_id and e.status == "revoked"
            ]
            if revoked_match:
                return PrincipalVerificationResult(
                    verified=False,
                    principal_id=revoked_match[0].principal_id,
                    key_id=event_key_id,
                    error=(
                        f"key-revoked: event key_id={event_key_id!r} "
                        f"for principal {actor_id!r} has been revoked"
                    ),
                )
            return PrincipalVerificationResult(
                verified=False,
                principal_id=non_revoked[0].principal_id,
                key_id=event_key_id,
                error=(
                    f"key-id-mismatch: event key_id={event_key_id!r} "
                    f"not found among non-revoked keys for principal {actor_id!r}"
                ),
            )

    candidate_keys = non_revoked
    pre_filtered = False
    if len(non_revoked) > 1 and event_key_id is None:
        pre_filtered = True
        candidate_keys = [
            e for e in non_revoked
            if _is_key_valid_at(e, event_timestamp) and e.scheme == effective_scheme_id
        ]

    scheme_mismatch = False
    temporal_skip = False
    if pre_filtered and not candidate_keys:
        any_scheme_match = any(e.scheme == effective_scheme_id for e in non_revoked)
        any_valid = any(
            _is_key_valid_at(e, event_timestamp) for e in non_revoked
            if e.scheme == effective_scheme_id
        )
        if not any_scheme_match:
            scheme_mismatch = True
        elif not any_valid:
            temporal_skip = True
    for entry in candidate_keys:
        if entry.scheme != effective_scheme_id:
            scheme_mismatch = True
            continue

        if not _is_key_valid_at(entry, event_timestamp):
            temporal_skip = True
            continue

        if verify_fn(entry):
            return PrincipalVerificationResult(
                verified=True,
                principal_id=entry.principal_id,
                key_id=entry.key_id,
                error=None,
            )

    if temporal_skip:
        return PrincipalVerificationResult(
            verified=False,
            principal_id=non_revoked[0].principal_id,
            key_id=non_revoked[0].key_id,
            error=(
                f"key-not-valid-at-time: event timestamp "
                f"{event_timestamp.isoformat() if event_timestamp else None} "
                f"outside validity window for principal {actor_id!r}"
            ),
        )

    if scheme_mismatch and all(
        e.scheme != effective_scheme_id for e in non_revoked
    ):
        return PrincipalVerificationResult(
            verified=False,
            principal_id=non_revoked[0].principal_id,
            key_id=non_revoked[0].key_id,
            error=(
                f"scheme-mismatch: event scheme_id={effective_scheme_id!r} "
                f"but no registered key uses that scheme for principal {actor_id!r}"
            ),
        )

    return PrincipalVerificationResult(
        verified=False,
        principal_id=non_revoked[0].principal_id,
        key_id=non_revoked[0].key_id,
        error="signature-verification-failed: signature invalid under all registered public keys",
    )


def verify_event_with_principal_binding(
    event: Any,
    mgr: Any,
) -> PrincipalVerificationResult:
    from ._principal_keys import list_principal_keys

    entries = list_principal_keys(mgr, event.actor_id, status=None)

    def _verify_with_key(entry: Any) -> bool:
        # The scheme is taken from the registry entry, never from the event
        # row's self-declared scheme_id (WI-267 / S2-interim).
        try:
            return verify_event_with_public_key(
                event, entry.public_key, scheme_id=entry.scheme,
            )
        except Exception:
            return False

    return _verify_principal_binding_core(
        entries,
        actor_id=event.actor_id,
        scheme_id=event.scheme_id,
        verify_fn=_verify_with_key,
        event_key_id=event.key_id,
        event_timestamp=_event_timestamp_for_binding(event),
    )


def verify_event_dict_principal_binding(
    evt: dict[str, Any],
    entries: list[Any],
) -> PrincipalVerificationResult:
    scheme_id = evt.get("scheme_id") or "hmac-sha256"

    from ._v6_referents import NO_REFERENTS
    from ._verification import (
        DEFAULT_POLICY,
        EventRow,
        StaticKeyResolver,
        TrustedKeySource,
        verify_event_strict,
    )

    row = EventRow.from_mapping(evt)

    def _verify_with_key(entry: Any) -> bool:
        # The scheme is taken from the registry entry, never from the row's
        # self-declared scheme_id (WI-267 / S2-interim). Row reconciliation
        # runs inside verify_event_strict, so a principal binding can no longer
        # be asserted over an envelope whose row was rewritten.
        try:
            resolver = StaticKeyResolver(
                material=entry.public_key,
                scheme_id=entry.scheme,
                source=TrustedKeySource.PRINCIPAL_REGISTRY,
                principal_id=entry.principal_id,
            )
            return verify_event_strict(
                row,
                keys=resolver,
                # A principal-binding probe over the `principal_keys` registry is
                # LEGACY-ONLY by contract: §5.9 rule 1 makes registry resolution a
                # raise for a v6 event, and `verify_event_strict` raises. The
                # `except Exception` below is what turns that into "this entry does
                # not bind", which is the correct answer — a v6 event's binding is
                # decided by §5.10 over presented material, never by this table.
                referents=NO_REFERENTS,
                policy=DEFAULT_POLICY,
            ).accepted
        except Exception:
            return False

    return _verify_principal_binding_core(
        entries,
        actor_id=evt["actor_id"],
        scheme_id=scheme_id,
        verify_fn=_verify_with_key,
        event_key_id=evt.get("key_id"),
        event_timestamp=_event_timestamp_for_binding(evt),
    )
