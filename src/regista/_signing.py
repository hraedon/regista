from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from ._jcs import canonicalize


def build_signing_envelope(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    transition: str | None,
    payload: dict | None,
    on_behalf_of: dict | None = None,
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
    payload: dict | None,
    on_behalf_of: dict | None = None,
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
    payload: dict | None,
    on_behalf_of: dict | None = None,
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
    payload: dict | None,
    on_behalf_of: dict | None = None,
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
    actor_metadata: dict | None,
    key_id: str,
    event_seq: int,
    workflow_name: str,
    workflow_version: int,
    timestamp: datetime,
    hash_alg: str,
    transition: str | None,
    payload: dict | None,
    on_behalf_of: dict | None = None,
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
    payload: dict | None,
    key: bytes,
    on_behalf_of: dict | None = None,
    scheme=None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    actor_kind: str | None = None,
    actor_metadata: dict | None = None,
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


def _verify_once(
    envelope: bytes,
    signature: bytes,
    canonical_hash: bytes,
    scheme,
    key: bytes,
    hash_alg: str = "sha-256",
) -> bool:
    return scheme.verify(envelope, signature, canonical_hash, key, hash_alg=hash_alg)


_V5_FIELDS = frozenset(
    {"event_id", "entity_kind", "entity_id", "actor_id", "actor_kind",
     "actor_metadata", "key_id", "event_seq", "workflow_name",
     "workflow_version", "timestamp", "hash_alg", "on_behalf_of",
     "transition", "payload", "prev_event_hash", "global_seq",
     "prev_global_event_hash"}
)
_V4_FIELDS = frozenset(
    {"event_id", "entity_kind", "entity_id", "actor_id", "key_id", "event_seq",
     "workflow_name", "workflow_version", "timestamp", "hash_alg",
     "on_behalf_of", "transition", "payload", "prev_event_hash", "global_seq",
     "prev_global_event_hash"}
)
_V3_FIELDS = frozenset(
    {"event_id", "work_item_id", "actor_id", "key_id", "event_seq",
     "workflow_name", "workflow_version", "timestamp", "on_behalf_of",
     "transition", "payload", "prev_event_hash", "global_seq",
     "prev_global_event_hash"}
)
_V2_FIELDS = frozenset(
    {"event_id", "work_item_id", "actor_id", "key_id", "event_seq",
     "workflow_name", "workflow_version", "timestamp", "on_behalf_of",
     "transition", "payload"}
)


_V3_CHAIN_FIELDS = {"prev_event_hash", "global_seq", "prev_global_event_hash"}


def classify_envelope_version(envelope: bytes) -> int:
    import json

    try:
        obj = json.loads(envelope)
        keys = set(obj.keys())
        if "actor_kind" in keys and "actor_metadata" in keys and _V5_FIELDS.issuperset(keys):
            return 5
        if "entity_kind" in keys and "hash_alg" in keys and _V4_FIELDS.issuperset(keys):
            return 4
        if _V3_FIELDS.issuperset(keys) and (keys & _V3_CHAIN_FIELDS):
            return 3
        if keys == _V2_FIELDS:
            return 2
        return 1
    except json.JSONDecodeError:
        return 0
    except Exception:
        return 0


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
    payload: dict | None,
    signature: bytes,
    canonical_hash: bytes,
    key: bytes,
    stored_envelope: bytes | None = None,
    on_behalf_of: dict | None = None,
    scheme=None,
    prev_event_hash: bytes | None = None,
    global_seq: int | None = None,
    prev_global_event_hash: bytes | None = None,
    entity_kind: str = "work_item",
    hash_alg: str = "sha-256",
    actor_kind: str | None = None,
    actor_metadata: dict | None = None,
) -> bool:
    from ._signing_scheme import HMACSHA256Scheme

    if scheme is None:
        scheme = HMACSHA256Scheme()

    stored_ver = 0
    if stored_envelope is not None:
        stored_ver = classify_envelope_version(stored_envelope)

    has_chain_fields = (
        prev_event_hash is not None
        or prev_global_event_hash is not None
        or global_seq is not None
    )

    if has_chain_fields or stored_ver >= 3:
        candidate_envelopes: list[tuple[bytes, int]] = []

        # For v5 stored envelopes, do NOT try the stored envelope directly.
        # Instead, build the candidate from the provided actor_kind/actor_metadata
        # so that tampering with those fields in the database row is detected:
        # if the provided values differ from what was signed, the rebuilt
        # envelope won't match the signature. (WI-208)
        if stored_ver >= 3 and stored_ver < 5:
            candidate_envelopes.append((stored_envelope, stored_ver))

        if actor_kind is not None or stored_ver == 5:
            candidate_envelopes.append((
                build_signing_envelope_v5(
                    event_id=event_id,
                    entity_kind=entity_kind,
                    entity_id=work_item_id,
                    actor_id=actor_id,
                    actor_kind=actor_kind if actor_kind is not None else "agent",
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
                ),
                5,
            ))

        candidate_envelopes.append((
            build_signing_envelope_v4(
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
            ),
            4,
        ))

        candidate_envelopes.append((
            build_signing_envelope_v3(
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
                on_behalf_of=on_behalf_of,
                prev_event_hash=prev_event_hash,
                global_seq=global_seq,
                prev_global_event_hash=prev_global_event_hash,
            ),
            3,
        ))

        if stored_ver >= 5:
            candidate_envelopes = [
                (env, ver) for env, ver in candidate_envelopes if ver >= 5
            ]
        elif stored_ver == 4:
            candidate_envelopes = [
                (env, ver) for env, ver in candidate_envelopes if ver >= 4
            ]
        elif stored_ver == 3:
            candidate_envelopes = [
                (env, ver) for env, ver in candidate_envelopes if ver >= 3
            ]

        for envelope, ver in candidate_envelopes:
            candidate_hash_alg = hash_alg if ver >= 4 else "sha-256"
            if _verify_once(
                envelope, signature, canonical_hash, scheme, key,
                hash_alg=candidate_hash_alg,
            ):
                return True

        return False

    candidate_envelopes = []

    v4_envelope = build_signing_envelope_v4(
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
    )
    candidate_envelopes.append((v4_envelope, 4))

    if stored_ver == 2:
        candidate_envelopes.append((stored_envelope, stored_ver))

    v3_envelope = build_signing_envelope_v3(
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
        on_behalf_of=on_behalf_of,
    )
    candidate_envelopes.append((v3_envelope, 3))

    v2_envelope = build_signing_envelope_v2(
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
        on_behalf_of=on_behalf_of,
    )
    candidate_envelopes.append((v2_envelope, 2))

    old_envelope = build_signing_envelope(
        event_id, work_item_id, actor_id, transition, payload, on_behalf_of,
    )
    candidate_envelopes.append((old_envelope, 1))

    if on_behalf_of is not None:
        bare_envelope = build_signing_envelope(
            event_id, work_item_id, actor_id, transition, payload, on_behalf_of=None,
        )
        candidate_envelopes.append((bare_envelope, 1))

    if stored_ver == 2:
        candidate_envelopes = [
            (env, ver) for env, ver in candidate_envelopes if ver >= 2
        ]

    for envelope, ver in candidate_envelopes:
        candidate_hash_alg = hash_alg if ver >= 4 else "sha-256"
        if _verify_once(
            envelope, signature, canonical_hash, scheme, key,
            hash_alg=candidate_hash_alg,
        ):
            return True

    return False


def verify_event_with_public_key(event, public_key: bytes) -> bool:
    from ._signing_scheme import get_scheme

    try:
        scheme = get_scheme(event.scheme_id)
    except Exception:
        return False
    return verify_event(
        event_id=event.event_id,
        work_item_id=event.work_item_id,
        actor_id=event.actor_id,
        key_id=event.key_id,
        event_seq=event.event_seq,
        workflow_name=event.workflow_name,
        workflow_version=event.workflow_version,
        timestamp=event.timestamp,
        transition=event.transition,
        payload=event.payload,
        signature=event.signature,
        canonical_hash=event.payload_canonical_hash,
        key=public_key,
        stored_envelope=event.canonical_envelope,
        on_behalf_of=event.on_behalf_of,
        scheme=scheme,
        prev_event_hash=event.prev_event_hash,
        prev_global_event_hash=event.prev_global_event_hash,
        entity_kind=event.entity_kind,
        hash_alg=event.hash_alg,
        actor_kind=event.actor_kind,
        actor_metadata=event.actor_metadata,
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


def _verify_principal_binding_core(
    entries: list,
    actor_id: str,
    scheme_id: str,
    verify_fn: Callable[[bytes], bool],
    event_key_id: str | None = None,
    event_timestamp: datetime | None = None,
) -> PrincipalVerificationResult:
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

    if event_key_id is not None:
        matching = [e for e in non_revoked if e.key_id == event_key_id]
        if matching:
            non_revoked = matching
        elif scheme_id == "hmac-sha256":
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
            if _is_key_valid_at(e, event_timestamp) and e.scheme == scheme_id
        ]

    scheme_mismatch = False
    temporal_skip = False
    if pre_filtered and not candidate_keys:
        any_scheme_match = any(e.scheme == scheme_id for e in non_revoked)
        any_valid = any(
            _is_key_valid_at(e, event_timestamp) for e in non_revoked
            if e.scheme == scheme_id
        )
        if not any_scheme_match:
            scheme_mismatch = True
        elif not any_valid:
            temporal_skip = True
    for entry in candidate_keys:
        if entry.scheme != scheme_id:
            scheme_mismatch = True
            continue

        if not _is_key_valid_at(entry, event_timestamp):
            temporal_skip = True
            continue

        if verify_fn(entry.public_key):
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
        e.scheme != scheme_id for e in non_revoked
    ):
        return PrincipalVerificationResult(
            verified=False,
            principal_id=non_revoked[0].principal_id,
            key_id=non_revoked[0].key_id,
            error=(
                f"scheme-mismatch: event scheme_id={scheme_id!r} "
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
    event,
    mgr,
) -> PrincipalVerificationResult:
    from ._principal_keys import list_principal_keys

    entries = list_principal_keys(mgr, event.actor_id, status=None)

    def _verify_with_key(public_key: bytes) -> bool:
        try:
            return verify_event_with_public_key(event, public_key)
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
    evt: dict,
    entries: list,
) -> PrincipalVerificationResult:
    scheme_id = evt.get("scheme_id") or "hmac-sha256"
    entity_kind = evt.get("entity_kind") or "work_item"
    hash_alg = evt.get("hash_alg") or "sha-256"

    try:
        from ._signing_scheme import get_scheme

        scheme = get_scheme(scheme_id)
    except Exception:
        return PrincipalVerificationResult(
            verified=False,
            principal_id=None,
            key_id=None,
            error=f"unknown-scheme: cannot resolve scheme_id={scheme_id!r}",
        )

    def _verify_with_key(public_key: bytes) -> bool:
        try:
            return verify_event(
                event_id=evt["event_id"],
                work_item_id=evt["work_item_id"],
                actor_id=evt["actor_id"],
                key_id=evt["key_id"],
                event_seq=evt["event_seq"],
                workflow_name=evt["workflow_name"],
                workflow_version=evt["workflow_version"],
                timestamp=evt["timestamp"],
                transition=evt["transition"],
                payload=evt["payload"],
                signature=bytes(evt["signature"]),
                canonical_hash=bytes(evt["payload_canonical_hash"]),
                key=public_key,
                stored_envelope=(
                    bytes(evt["canonical_envelope"]) if evt.get("canonical_envelope") else None
                ),
                on_behalf_of=evt.get("on_behalf_of"),
                scheme=scheme,
                entity_kind=entity_kind,
                hash_alg=hash_alg,
                prev_event_hash=(
                    bytes(evt["prev_event_hash"]) if evt.get("prev_event_hash") else None
                ),
                prev_global_event_hash=(
                    bytes(evt["prev_global_event_hash"])
                    if evt.get("prev_global_event_hash")
                    else None
                ),
                actor_kind=evt.get("actor_kind"),
                actor_metadata=evt.get("actor_metadata"),
            )
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
