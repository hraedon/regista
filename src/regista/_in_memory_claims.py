from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from ._contract import (
    Jsonb,
    compute_coalesce_threshold,
    resolve_claim_acquire,
    resolve_heartbeat,
    should_escalate,
    validate_mutation_params,
    validate_release,
    validate_work_item_exists,
)
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._keys import KeySet
from ._types import Claim


def in_memory_acquire_claim(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    claims: dict[uuid.UUID, dict[str, Any]],
    workflows: dict[tuple[str, int], dict[str, Any]],
    key_set: KeySet | None,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int = 300,
    *,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> Claim:
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
        ttl_seconds=ttl_seconds,
        actor_metadata=actor_metadata,
    )

    wi = work_items.get(work_item_id)
    validate_work_item_exists(wi, work_item_id)
    assert wi is not None

    now = datetime.now(UTC)
    existing = claims.get(work_item_id)
    claim_state = existing if existing is not None else None

    result = resolve_claim_acquire(
        wi_not_before=wi.get("not_before"),
        claim_actor_id=claim_state["actor_id"] if claim_state else None,
        claim_expires_at=claim_state["expires_at"] if claim_state else None,
        claim_acquired_at=claim_state["acquired_at"] if claim_state else None,
        claim_attempt_number=claim_state["attempt_number"] if claim_state else None,
        wi_attempt_number=wi["attempt_number"],
        actor_id=actor_id,
        ttl_seconds=ttl_seconds,
        now=now,
    )

    claim_data = {
        "actor_id": actor_id,
        "acquired_at": result.acquired_at,
        "expires_at": result.expires_at,
        "attempt_number": result.attempt_number,
    }

    if result.event_transition is not None:
        eid = event_id or uuid.uuid4()
        _in_memory_append_claim_event(
            store, wi, key_set, eid, result.event_transition,
            result.event_payload,  # type: ignore[arg-type]
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    claims[work_item_id] = claim_data
    wi["attempt_number"] = result.attempt_number
    wi["claimed_by"] = actor_id
    wi["claim_expires_at"] = result.expires_at

    _in_memory_check_escalation(store, workflows, wi, result.attempt_number)

    return Claim(
        work_item_id=work_item_id,
        actor_id=actor_id,
        acquired_at=result.acquired_at,
        expires_at=result.expires_at,
        attempt_number=result.attempt_number,
    )


def in_memory_heartbeat_claim(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    claims: dict[uuid.UUID, dict[str, Any]],
    key_set: KeySet | None,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int = 300,
    *,
    expected_attempt_number: int | None = None,
    coalesce_threshold: float | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> Claim:
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        ttl_seconds=ttl_seconds,
        actor_metadata=actor_metadata,
    )
    wi = work_items.get(work_item_id)
    validate_work_item_exists(wi, work_item_id)
    assert wi is not None

    now = datetime.now(UTC)
    claim = claims.get(work_item_id)
    claim_state = claim if claim is not None else None

    result = resolve_heartbeat(
        claim_state=claim_state,
        actor_id=actor_id,
        ttl_seconds=ttl_seconds,
        expected_attempt_number=expected_attempt_number,
        work_item_id=work_item_id,
        now=now,
    )
    threshold = compute_coalesce_threshold(ttl_seconds, coalesce_threshold)
    assert claim is not None
    last_emitted = claim.get("last_heartbeat_emitted_at")
    should_emit = (
        last_emitted is None
        or (now - last_emitted).total_seconds() >= threshold
    )

    if should_emit and key_set is not None:
        _store_append(
            store,
            work_item_id=wi["work_item_id"],
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
            workflow_name=wi["workflow_name"],
            workflow_version=wi["workflow_version"],
            transition="claim_heartbeat",
            payload=Jsonb({
                "actor_id": actor_id,
                "expires_at": result.new_expires_at.isoformat(),
                "coalesce_threshold": threshold,
            }),
            event_id=uuid.uuid4(),
            key_set=key_set,
        )
        claim["last_heartbeat_emitted_at"] = now

    claim["expires_at"] = result.new_expires_at
    wi["claim_expires_at"] = result.new_expires_at

    return Claim(
        work_item_id=work_item_id,
        actor_id=actor_id,
        acquired_at=result.acquired_at,
        expires_at=result.new_expires_at,
        attempt_number=result.attempt_number,
    )


def in_memory_release_claim(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    claims: dict[uuid.UUID, dict[str, Any]],
    key_set: KeySet | None,
    work_item_id: uuid.UUID,
    actor_id: str,
    *,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> None:
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
        actor_metadata=actor_metadata,
    )
    wi = work_items.get(work_item_id)
    validate_work_item_exists(wi, work_item_id)
    assert wi is not None

    claim = claims.get(work_item_id)
    validate_release(claim, actor_id, work_item_id)

    _in_memory_append_claim_event(
        store, wi, key_set, event_id or uuid.uuid4(), "claim_released",
        {"actor_id": actor_id},
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
    )
    claims.pop(work_item_id, None)
    wi["claimed_by"] = None
    wi["claim_expires_at"] = None


def in_memory_sweep_expired_claims(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    claims: dict[uuid.UUID, dict[str, Any]],
    key_set: KeySet | None,
) -> int:
    now = datetime.now(UTC)
    expired = [
        (wid, c) for wid, c in list(claims.items())
        if c["expires_at"] < now
    ]
    for wid, claim in expired:
        current = claims.get(wid)
        if current is None:
            continue
        if current["expires_at"] != claim["expires_at"]:
            continue
        del claims[wid]
        wi = work_items.get(wid)
        if wi is not None:
            if (
                wi.get("claimed_by") == claim["actor_id"]
                and wi.get("claim_expires_at") == claim["expires_at"]
            ):
                wi["claimed_by"] = None
                wi["claim_expires_at"] = None
                _in_memory_append_claim_event(
                    store, wi, key_set, uuid.uuid4(), "claim_expired",
                    {"actor_id": claim["actor_id"], "expired_at": now.isoformat()},
                    actor_id=claim["actor_id"] or "system",
                )
    return len(expired)


def _in_memory_check_escalation(
    store: InMemoryEventStore,
    workflows: dict[tuple[str, int], dict[str, Any]],
    wi: dict[str, Any],
    attempt_number: int,
) -> bool:
    wf_data = workflows.get((wi["workflow_name"], wi["workflow_version"]))
    if wf_data is None:
        return False
    threshold = wf_data.get("attempt_threshold")
    has_escalated = any(
        e.transition == "escalated"
        for e in store.events.get(wi["work_item_id"], [])
    )
    if not should_escalate(threshold, has_escalated, attempt_number):
        return False
    wi["needs_review"] = True
    _in_memory_append_claim_event(
        store, wi, None, uuid.uuid4(), "escalated",
        {"attempt_number": attempt_number, "threshold": threshold},
    )
    return True


def _in_memory_append_claim_event(
    store: InMemoryEventStore,
    wi: dict[str, Any],
    key_set: KeySet | None,
    event_id: uuid.UUID,
    transition: str,
    payload: dict[str, Any],
    *,
    actor_id: str = "system",
    actor_kind: str = "system",
    actor_metadata: dict[str, Any] | None = None,
) -> None:
    _store_append(
        store,
        work_item_id=wi["work_item_id"],
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition=transition,
        payload=Jsonb(payload),
        event_id=event_id,
        key_set=key_set,
    )
