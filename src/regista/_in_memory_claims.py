from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

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
from ._errors import RegistaError
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._events import resolve_system_actor_id_in_memory
from ._keys import KeySet
from ._types import Claim

log = structlog.get_logger()


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
    swept = 0
    refused = 0
    for wid, claim in expired:
        current = claims.get(wid)
        if current is None:
            continue
        if current["expires_at"] != claim["expires_at"]:
            continue
        wi = work_items.get(wid)
        holds_claim = wi is not None and (
            wi.get("claimed_by") == claim["actor_id"]
            and wi.get("claim_expires_at") == claim["expires_at"]
        )
        if wi is not None and holds_claim:
            # The append FIRST, the mutation after — the in-memory shape of the
            # Postgres path's per-claim savepoint (NB5). Rollback is
            # PARITY_BOUNDARY_POSTGRES_ONLY, so ordering is the only mechanism this
            # backend has for "a refusal leaves the claim exactly as it was", and it
            # is the better mechanism anyway: there is nothing to undo.
            #
            # `RegistaError` only, matching the Postgres path deliberately (R2 NB2): a
            # refusal is this system deciding about one claim, and anything else is a
            # defect or an infrastructure failure that must reach the caller rather than
            # be flattened into a count.
            try:
                _in_memory_append_claim_event(
                    store, wi, key_set, uuid.uuid4(), "claim_expired",
                    {"actor_id": claim["actor_id"], "expired_at": now.isoformat()},
                    # `claim_expired` is a SYSTEM action: the holder did not act, a
                    # lease lapsed. Attributing it to the holder made the sweep
                    # depend on the holder still being appendable. The payload above
                    # keeps naming the holder, which is where that belongs.
                    actor_id=resolve_system_actor_id_in_memory(
                        store, legacy_actor_id=claim["actor_id"] or "system"
                    ),
                )
            except RegistaError as exc:
                refused += 1
                log.error(
                    "claims.sweep_claim_refused",
                    work_item_id=str(wid),
                    actor_id=claim["actor_id"],
                    error_code=getattr(exc.code, "value", str(exc.code)),
                    error=str(exc)[:500],
                    detail=(
                        "this claim was left intact and the sweep continued; a "
                        "refusal here must not stop the other claims from expiring"
                    ),
                )
                continue
            wi["claimed_by"] = None
            wi["claim_expires_at"] = None
        del claims[wid]
        swept += 1

    if refused:
        log.error(
            "claims.sweep_incomplete",
            expired=len(expired),
            swept=swept,
            refused=refused,
        )
    return swept


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
        for e in store.events_for("work_item", wi["work_item_id"])
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
    actor_id: str | None = None,
    actor_kind: str = "system",
    actor_metadata: dict[str, Any] | None = None,
) -> None:
    # ``actor_id=None`` means *system-authored* — escalation and hook dead-lettering
    # have no calling actor. The literal that used to be the default here
    # ("system") is not a canonical §2.1 principal and cannot hold a key-binding
    # anchor, so the v6 writer refuses it; resolve_system_actor_id_in_memory
    # attributes the event to the project's bootstrap principal once the epoch is
    # open, and returns the old literal unchanged before genesis.
    if actor_id is None:
        actor_id = resolve_system_actor_id_in_memory(store, legacy_actor_id="system")
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
