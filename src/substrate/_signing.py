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
) -> tuple[bytes, bytes, bytes]:
    from ._signing_scheme import HMACSHA256Scheme

    if scheme is None:
        scheme = HMACSHA256Scheme()
    envelope = build_signing_envelope_v2(
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
) -> bool:
    from ._signing_scheme import HMACSHA256Scheme

    if scheme is None:
        scheme = HMACSHA256Scheme()
    if stored_envelope is not None:
        envelope = stored_envelope
    else:
        envelope = build_signing_envelope_v2(
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
    if _verify_once(envelope, signature, canonical_hash, scheme, key):
        return True

    # Backward compat: retry with old envelope shape for pre-v2 events
    old_envelope = build_signing_envelope(
        event_id, work_item_id, actor_id, transition, payload, on_behalf_of,
    )
    if _verify_once(old_envelope, signature, canonical_hash, scheme, key):
        return True

    # Fallback: retry without on_behalf_of in old envelope (BC-197 compat)
    if on_behalf_of is not None:
        bare_envelope = build_signing_envelope(
            event_id, work_item_id, actor_id, transition, payload, on_behalf_of=None,
        )
        if _verify_once(bare_envelope, signature, canonical_hash, scheme, key):
            return True

    return False
