from __future__ import annotations

import uuid

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._observability import Metrics, OpTimer
from ._types import Claim


def acquire_claim(
    mgr: ConnectionManager,
    keys: KeySet,
    metrics: Metrics,
    project: str,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int = 300,
    *,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
) -> Claim:
    from ._claims import acquire_claim as _acquire

    timer = OpTimer(project, "acquire_claim")
    try:
        with mgr.transaction() as conn:
            claim, escalated, stolen = _acquire(
                conn, work_item_id, actor_id, ttl_seconds,
                keys, event_id, actor_kind, actor_metadata,
            )
        metrics.inc("claims_acquired", project)
        if stolen:
            metrics.inc("claims_stolen", project)
        if escalated:
            metrics.inc("escalations", project)
        timer.log("ok", work_item_id=str(work_item_id))
        return claim
    except RegistaError as e:
        if e.code == ErrorCode.CLAIM_CONTESTED:
            timer.log("rejected", work_item_id=str(work_item_id))
        else:
            timer.log("error")
        raise


def heartbeat_claim(
    mgr: ConnectionManager,
    keys: KeySet,
    project: str,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int = 300,
    *,
    expected_attempt_number: int | None = None,
    coalesce_threshold: float | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
) -> Claim:
    from ._claims import heartbeat_claim as _heartbeat

    timer = OpTimer(project, "heartbeat_claim")
    try:
        with mgr.transaction() as conn:
            claim = _heartbeat(
                conn, work_item_id, actor_id, ttl_seconds,
                expected_attempt_number=expected_attempt_number,
                key_set=keys,
                coalesce_threshold=coalesce_threshold,
                actor_kind=actor_kind,
                actor_metadata=actor_metadata,
            )
        timer.log("ok", work_item_id=str(work_item_id))
        return claim
    except RegistaError:
        timer.log("error")
        raise


def release_claim(
    mgr: ConnectionManager,
    keys: KeySet,
    metrics: Metrics,
    project: str,
    work_item_id: uuid.UUID,
    actor_id: str,
    *,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
) -> None:
    from ._claims import release_claim as _release

    timer = OpTimer(project, "release_claim")
    try:
        with mgr.transaction() as conn:
            _release(conn, work_item_id, actor_id, keys, event_id, actor_kind, actor_metadata)
        metrics.inc("claims_released", project)
        timer.log("ok", work_item_id=str(work_item_id))
    except RegistaError:
        timer.log("error")
        raise


def sweep_expired_claims(
    mgr: ConnectionManager, keys: KeySet, metrics: Metrics, project: str
) -> int:
    from ._claims import sweep_expired_claims as _sweep

    with mgr.transaction() as conn:
        count = _sweep(conn, keys)
    metrics.inc("claims_expired", project, amount=count)
    return count
