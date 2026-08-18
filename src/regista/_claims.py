from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from psycopg.sql import SQL

from ._connection import DictConn
from ._contract import (
    Jsonb,
    compute_coalesce_threshold,
    resolve_claim_acquire,
    resolve_heartbeat,
    should_escalate,
    validate_mutation_params,
    validate_release,
)
from ._errors import ErrorCode, RegistaError
from ._keys import KeySet
from ._types import Claim

log = structlog.get_logger()


def _row_to_claim(row: dict[str, Any]) -> Claim:
    return Claim(
        work_item_id=row["work_item_id"],
        actor_id=row["actor_id"],
        acquired_at=row["acquired_at"],
        expires_at=row["expires_at"],
        attempt_number=row["attempt_number"],
    )


def acquire_claim(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int,
    key_set: KeySet,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> tuple[Claim, bool, bool]:
    from ._events import append_event, lock_work_item

    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
        ttl_seconds=ttl_seconds,
        actor_metadata=actor_metadata,
    )

    wi = lock_work_item(conn, work_item_id)
    if wi is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    now = datetime.now(UTC)

    existing_claim = conn.execute(
        SQL("SELECT * FROM claims WHERE work_item_id = %s"),
        [work_item_id],
    ).fetchone()

    result = resolve_claim_acquire(
        wi_not_before=wi["not_before"],
        claim_actor_id=existing_claim["actor_id"] if existing_claim else None,
        claim_expires_at=existing_claim["expires_at"] if existing_claim else None,
        claim_acquired_at=existing_claim["acquired_at"] if existing_claim else None,
        claim_attempt_number=existing_claim["attempt_number"] if existing_claim else None,
        wi_attempt_number=wi["attempt_number"],
        actor_id=actor_id,
        ttl_seconds=ttl_seconds,
        now=now,
    )

    if result.action == "extend":
        conn.execute(
            SQL("UPDATE claims SET expires_at = %s WHERE work_item_id = %s"),
            [result.expires_at, work_item_id],
        )
        conn.execute(
            SQL("UPDATE work_items_current SET claim_expires_at = %s WHERE work_item_id = %s"),
            [result.expires_at, work_item_id],
        )
        return (
            Claim(
                work_item_id=work_item_id,
                actor_id=actor_id,
                acquired_at=result.acquired_at,
                expires_at=result.expires_at,
                attempt_number=result.attempt_number,
            ),
            False,
            False,
        )

    conn.execute(
        SQL(
            "INSERT INTO claims "
            "(work_item_id, actor_id, acquired_at, expires_at, attempt_number) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (work_item_id) DO UPDATE SET "
            "actor_id = EXCLUDED.actor_id, acquired_at = EXCLUDED.acquired_at, "
            "expires_at = EXCLUDED.expires_at, attempt_number = EXCLUDED.attempt_number"
        ),
        [work_item_id, actor_id, result.acquired_at, result.expires_at, result.attempt_number],
    )

    conn.execute(
        SQL(
            "UPDATE work_items_current SET claimed_by = %s, claim_expires_at = %s, "
            "attempt_number = %s WHERE work_item_id = %s"
        ),
        [actor_id, result.expires_at, result.attempt_number, work_item_id],
    )

    eid = event_id or uuid.uuid4()
    if result.event_transition is not None and result.event_payload is not None:
        append_event(
            conn=conn,
            work_item_id=work_item_id,
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
            key_set=key_set,
            workflow_name=wi["workflow_name"],
            workflow_version=wi["workflow_version"],
            transition=result.event_transition,
            payload=Jsonb(result.event_payload),
            event_id=eid,
            _prelocked_wi=wi,
        )

    stolen = result.action == "steal"
    escalated = _check_escalation(conn, wi, result.attempt_number, key_set)

    claim = Claim(
        work_item_id=work_item_id,
        actor_id=actor_id,
        acquired_at=result.acquired_at,
        expires_at=result.expires_at,
        attempt_number=result.attempt_number,
    )
    return claim, escalated, stolen


def _check_escalation(
    conn: DictConn,
    wi: dict[str, Any],
    attempt_number: int,
    key_set: KeySet,
) -> bool:
    from ._events import append_event, resolve_system_actor_id

    wf_row = conn.execute(
        SQL("SELECT definition FROM workflow_registry WHERE workflow_name = %s AND version = %s"),
        [wi["workflow_name"], wi["workflow_version"]],
    ).fetchone()
    if wf_row is None:
        return False

    threshold = wf_row["definition"].get("attempt_threshold")
    existing = conn.execute(
        SQL("SELECT 1 FROM events WHERE work_item_id = %s AND transition = 'escalated'"),
        [wi["work_item_id"]],
    ).fetchone()

    if not should_escalate(threshold, existing is not None, attempt_number):
        return False

    conn.execute(
        SQL("UPDATE work_items_current SET needs_review = true WHERE work_item_id = %s"),
        [wi["work_item_id"]],
    )

    append_event(
        conn=conn,
        work_item_id=wi["work_item_id"],
        actor_id=resolve_system_actor_id(conn, legacy_actor_id="system"),
        actor_kind="system",
        actor_metadata=None,
        key_set=key_set,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition="escalated",
        payload=Jsonb({"attempt_number": attempt_number, "threshold": threshold}),
        event_id=uuid.uuid4(),
    )

    return True


def heartbeat_claim(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    ttl_seconds: int,
    expected_attempt_number: int | None = None,
    key_set: KeySet | None = None,
    coalesce_threshold: float | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> Claim:
    from ._events import append_event, lock_work_item

    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        ttl_seconds=ttl_seconds,
        actor_metadata=actor_metadata,
    )

    wi = lock_work_item(conn, work_item_id)
    if wi is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    claim_row = conn.execute(
        SQL("SELECT * FROM claims WHERE work_item_id = %s"),
        [work_item_id],
    ).fetchone()

    now = datetime.now(UTC)
    result = resolve_heartbeat(
        claim_state=claim_row,
        actor_id=actor_id,
        ttl_seconds=ttl_seconds,
        expected_attempt_number=expected_attempt_number,
        work_item_id=work_item_id,
        now=now,
    )

    threshold = compute_coalesce_threshold(ttl_seconds, coalesce_threshold)
    last_emitted = claim_row["last_heartbeat_emitted_at"] if claim_row else None
    should_emit = last_emitted is None or (now - last_emitted).total_seconds() >= threshold

    if should_emit and wi is not None and key_set is not None:
        append_event(
            conn=conn,
            work_item_id=work_item_id,
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
            key_set=key_set,
            workflow_name=wi["workflow_name"],
            workflow_version=wi["workflow_version"],
            transition="claim_heartbeat",
            payload=Jsonb(
                {
                    "actor_id": actor_id,
                    "expires_at": result.new_expires_at.isoformat(),
                    "coalesce_threshold": threshold,
                }
            ),
            event_id=uuid.uuid4(),
            _prelocked_wi=wi,
        )
        conn.execute(
            SQL(
                "UPDATE claims SET expires_at = %s, last_heartbeat_emitted_at = %s "
                "WHERE work_item_id = %s"
            ),
            [result.new_expires_at, now, work_item_id],
        )
    else:
        conn.execute(
            SQL("UPDATE claims SET expires_at = %s WHERE work_item_id = %s"),
            [result.new_expires_at, work_item_id],
        )

    conn.execute(
        SQL("UPDATE work_items_current SET claim_expires_at = %s WHERE work_item_id = %s"),
        [result.new_expires_at, work_item_id],
    )

    return Claim(
        work_item_id=work_item_id,
        actor_id=actor_id,
        acquired_at=result.acquired_at,
        expires_at=result.new_expires_at,
        attempt_number=result.attempt_number,
    )


def release_claim(
    conn: DictConn,
    work_item_id: uuid.UUID,
    actor_id: str,
    key_set: KeySet,
    event_id: uuid.UUID | None = None,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
) -> None:
    from ._events import append_event, lock_work_item

    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
        actor_metadata=actor_metadata,
    )

    wi = lock_work_item(conn, work_item_id)
    if wi is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    claim_row = conn.execute(
        SQL("SELECT * FROM claims WHERE work_item_id = %s"),
        [work_item_id],
    ).fetchone()

    validate_release(claim_row, actor_id, work_item_id)

    conn.execute(
        SQL("DELETE FROM claims WHERE work_item_id = %s"),
        [work_item_id],
    )
    conn.execute(
        SQL(
            "UPDATE work_items_current SET claimed_by = NULL, claim_expires_at = NULL "
            "WHERE work_item_id = %s"
        ),
        [work_item_id],
    )

    append_event(
        conn=conn,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        key_set=key_set,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition="claim_released",
        payload=Jsonb({"actor_id": actor_id}),
        event_id=event_id or uuid.uuid4(),
        _prelocked_wi=wi,
    )


def sweep_expired_claims(conn: DictConn, key_set: KeySet) -> int:
    """Expire every lapsed claim, one savepoint at a time.

    Returns the number of claims actually swept. Two properties are load-bearing and
    were both fixed by the phase-4 ceremony's NB5:

    **``claim_expired`` is a SYSTEM action.** The holder did not act — a lease lapsed —
    so in an open v6 epoch the event is attributed to the project's own bootstrap
    principal through :func:`~regista._events.resolve_system_actor_id`, exactly like
    ``escalated``, hook dead-lettering and recurrence firing. Attributing it to the
    *holder* made the sweep depend on the holder still being appendable: a holder whose
    key acceptance had been revoked, or whose acceptance scopes do not cover
    ``claim_expired``, raised inside the sweep and the operator's expiry sweep stopped
    working — while the projection change had already been made. The holder is not
    lost: the payload names it, which is where "whose claim expired" belongs.
    ``legacy_actor_id`` keeps the pre-genesis attribution byte for byte, so a legacy
    project's events are unchanged.

    **One claim's refusal must not abort the batch.** Each claim is processed inside its
    own savepoint (``conn.transaction()``), so a refusal rolls that claim's ``DELETE``
    and projection ``UPDATE`` back and leaves the claim exactly as it was — fail-closed
    per claim rather than a committed projection change with no event, which is the
    shape replay reports as drift. The remaining claims are then swept. Refusals are
    reported as ``claims.sweep_claim_refused`` log lines carrying the work item and the
    error, plus one ``claims.sweep_incomplete`` summary; the return value counts
    successes only, so a caller that compares it against the number of expired claims
    can see that something was refused without parsing anything.
    """

    from ._events import append_event, lock_work_item, resolve_system_actor_id

    now = datetime.now(UTC)
    expired = conn.execute(
        SQL("SELECT work_item_id, actor_id FROM claims WHERE expires_at < %s"),
        [now],
    ).fetchall()

    swept = 0
    refused = 0
    for row in expired:
        wi_id = row["work_item_id"]
        prior_actor_id = row["actor_id"]

        try:
            with conn.transaction():
                wi = lock_work_item(conn, wi_id)

                still_expired = conn.execute(
                    SQL(
                        "SELECT actor_id FROM claims "
                        "WHERE work_item_id = %s AND expires_at < %s"
                    ),
                    [wi_id, now],
                ).fetchone()
                if still_expired is None:
                    continue

                if still_expired["actor_id"] != prior_actor_id:
                    continue

                conn.execute(
                    SQL("DELETE FROM claims WHERE work_item_id = %s AND actor_id = %s"),
                    [wi_id, prior_actor_id],
                )

                cur = conn.execute(
                    SQL(
                        "UPDATE work_items_current SET claimed_by = NULL, "
                        "claim_expires_at = NULL "
                        "WHERE work_item_id = %s AND claimed_by = %s"
                    ),
                    [wi_id, prior_actor_id],
                )

                if cur.rowcount > 0 and wi is not None:
                    append_event(
                        conn=conn,
                        work_item_id=wi_id,
                        actor_id=resolve_system_actor_id(
                            conn, legacy_actor_id=prior_actor_id or "system"
                        ),
                        actor_kind="system",
                        actor_metadata=None,
                        key_set=key_set,
                        workflow_name=wi["workflow_name"],
                        workflow_version=wi["workflow_version"],
                        transition="claim_expired",
                        payload=Jsonb(
                            {
                                "actor_id": prior_actor_id,
                                "expired_at": now.isoformat(),
                            }
                        ),
                        event_id=uuid.uuid4(),
                        _prelocked_wi=wi,
                    )
        except RegistaError as exc:
            refused += 1
            log.error(
                "claims.sweep_claim_refused",
                work_item_id=str(wi_id),
                actor_id=prior_actor_id,
                error_code=getattr(exc.code, "value", str(exc.code)),
                error=str(exc)[:500],
                detail=(
                    "this claim was left intact and the sweep continued; a refusal "
                    "here must not stop the other claims from expiring"
                ),
            )
            continue

        swept += 1

    if refused:
        log.error(
            "claims.sweep_incomplete",
            expired=len(expired),
            swept=swept,
            refused=refused,
        )

    return swept
