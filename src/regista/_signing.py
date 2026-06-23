from __future__ import annotations

import hashlib
import hmac
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


def compute_hmac(envelope_bytes: bytes, key: bytes) -> bytes:
    return hmac.new(key, envelope_bytes, hashlib.sha256).digest()


def compute_canonical_hash(envelope_bytes: bytes) -> bytes:
    return hashlib.sha256(envelope_bytes).digest()


def verify_hmac(envelope_bytes: bytes, signature: bytes, key: bytes) -> bool:
    return hmac.compare_digest(
        hmac.new(key, envelope_bytes, hashlib.sha256).digest(), signature
    )


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
) -> tuple[bytes, bytes, bytes]:
    from ._signing_scheme import HMACSHA256Scheme

    if scheme is None:
        scheme = HMACSHA256Scheme()

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
    signature, canonical_hash = scheme.sign(envelope, key)
    return (signature, canonical_hash, envelope)


def _verify_once(
    envelope: bytes,
    signature: bytes,
    canonical_hash: bytes,
    scheme,
    key: bytes,
) -> bool:
    return scheme.verify(envelope, signature, canonical_hash, key)


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


def classify_envelope_version(envelope: bytes) -> int:
    import json

    try:
        obj = json.loads(envelope)
        keys = set(obj.keys())
        if "entity_kind" in keys and "hash_alg" in keys:
            if _V4_FIELDS.issuperset(keys) and "prev_event_hash" in keys:
                return 4
            if _V4_FIELDS.issuperset(keys):
                return 4
        if _V3_FIELDS.issuperset(keys) and "prev_event_hash" in keys:
            return 3
        if _V2_FIELDS.issuperset(keys):
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

        if stored_ver >= 3:
            candidate_envelopes.append((stored_envelope, stored_ver))

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

        for envelope, _ver in candidate_envelopes:
            if _verify_once(envelope, signature, canonical_hash, scheme, key):
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

    if stored_ver == 4:
        candidate_envelopes.insert(0, (stored_envelope, stored_ver))

    for envelope, _ver in candidate_envelopes:
        if _verify_once(envelope, signature, canonical_hash, scheme, key):
            return True

    if stored_ver in (2, 3):
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

    for envelope, _ver in candidate_envelopes:
        if _verify_once(envelope, signature, canonical_hash, scheme, key):
            return True

    old_envelope = build_signing_envelope(
        event_id, work_item_id, actor_id, transition, payload, on_behalf_of,
    )
    if _verify_once(old_envelope, signature, canonical_hash, scheme, key):
        return True

    if on_behalf_of is not None:
        bare_envelope = build_signing_envelope(
            event_id, work_item_id, actor_id, transition, payload, on_behalf_of=None,
        )
        if _verify_once(bare_envelope, signature, canonical_hash, scheme, key):
            return True

    return False
