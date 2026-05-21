from __future__ import annotations

from datetime import UTC, datetime

import structlog

from ._errors import ErrorCode, SubstrateError
from ._signing import verify_event as _verify_event
from ._types import ReplayReport

log = structlog.get_logger()


def _ts_equal(a: datetime | None, b: datetime | None) -> bool:
    """Compare two timestamps in a timezone-safe way.

    Postgres returns tz-aware datetimes; replayed values come from
    datetime.fromisoformat() which may or may not include tzinfo depending
    on whether the stored string included an offset.  Normalise both to UTC
    before comparing so that +00:00-suffixed and naive values compare equal.
    """
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    a_aware = a.tzinfo is not None
    b_aware = b.tzinfo is not None
    if a_aware and b_aware:
        return a.astimezone(UTC) == b.astimezone(UTC)
    if not a_aware and not b_aware:
        return a == b
    # Mixed: strip tzinfo from the aware side for comparison
    if a_aware:
        a = a.astimezone(UTC).replace(tzinfo=None)
    else:
        b = b.astimezone(UTC).replace(tzinfo=None)
    return a == b


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _ts_equal_within(
    a: datetime | None, b: datetime | None, threshold_seconds: float,
) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    diff = abs((_to_utc(a) - _to_utc(b)).total_seconds())
    return diff <= threshold_seconds


def in_memory_replay(
    work_items: dict,
    workflows: dict,
    store,
    key_set,
    *,
    continue_on_revoked: bool = False,
) -> ReplayReport:
    ok = 0
    drift = 0
    halted = 0
    warnings = 0

    # Orphan-event detection: events whose work_item_id has no entry in work_items
    all_event_wi_ids = set(store.events.keys())
    wi_ids = set(work_items.keys())
    orphan_ids = all_event_wi_ids - wi_ids
    for orphan_id in orphan_ids:
        orphan_evts = sorted(store.events.get(orphan_id, []), key=lambda e: e.event_seq)
        is_created = len(orphan_evts) > 0 and orphan_evts[0].transition == "created"
        if not is_created:
            halted += 1
            log.error(
                "replay.orphan_events",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
        else:
            warnings += 1
            log.warning(
                "replay.orphan_work_item",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )

    for wi_id, wi in work_items.items():
        evts = store.events.get(wi_id, [])
        if not evts:
            continue
        try:
            derived_state = None
            derived_fields: dict = {}
            derived_needs_review = False
            derived_not_before = None
            derived_last_seq = 0
            derived_attempt_number = 0
            derived_claimed_by = None
            derived_claim_expires_at = None
            derived_coalesce_threshold = 0.0
            for evt in sorted(evts, key=lambda e: e.event_seq):
                if key_set is not None:
                    key_entry = None
                    try:
                        key_entry = key_set.verify_key_status(evt.key_id)
                    except SubstrateError as e:
                        if e.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                            key_entry = key_set.get_key(evt.key_id)
                            warnings += 1
                        elif e.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                            warnings += 1
                        else:
                            raise
                    if key_entry is not None:
                        if not _verify_event(
                            event_id=evt.event_id,
                            work_item_id=evt.work_item_id,
                            actor_id=evt.actor_id,
                            transition=evt.transition,
                            payload=evt.payload,
                            signature=evt.signature,
                            canonical_hash=evt.payload_canonical_hash,
                            key=key_entry.secret,
                            stored_envelope=evt.canonical_envelope,
                        ):
                            raise SubstrateError(
                                ErrorCode.REPLAY_HALTED,
                                f"Signature verification failed for event {evt.event_id} "
                                f"at seq {evt.event_seq}",
                            )
                derived_last_seq = evt.event_seq
                if evt.transition == "created":
                    p = evt.payload or {}
                    derived_state = p.get("initial_state")
                    derived_fields = p.get("custom_fields", {})
                    nb = p.get("not_before")
                    if nb:
                        derived_not_before = (
                            datetime.fromisoformat(nb)
                            if isinstance(nb, str) else nb
                        )
                elif evt.transition in (
                    "claim_acquired", "claim_released", "claim_expired",
                    "claim_stolen", "claim_heartbeat", "link_created", "link_removed",
                    "hook_dead_lettered",
                ):
                    if evt.transition in ("claim_acquired", "claim_stolen"):
                        derived_attempt_number += 1
                    if evt.transition == "claim_acquired":
                        p = evt.payload or {}
                        derived_claimed_by = p.get("actor_id")
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = datetime.fromisoformat(expires_str)
                    elif evt.transition == "claim_stolen":
                        p = evt.payload or {}
                        derived_claimed_by = p.get("new_actor_id")
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = datetime.fromisoformat(expires_str)
                    elif evt.transition == "claim_heartbeat":
                        p = evt.payload or {}
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = datetime.fromisoformat(expires_str)
                        derived_coalesce_threshold = p.get("coalesce_threshold") or 0.0
                    elif evt.transition in ("claim_released", "claim_expired"):
                        derived_claimed_by = None
                        derived_claim_expires_at = None
                        derived_coalesce_threshold = 0.0
                elif evt.transition == "escalated":
                    derived_needs_review = True
                elif evt.transition == "not_before_set":
                    p = evt.payload or {}
                    nb = p.get("not_before")
                    if nb:
                        derived_not_before = (
                            datetime.fromisoformat(nb)
                            if isinstance(nb, str) else nb
                        )
                    else:
                        derived_not_before = None
                else:
                    wf_data = workflows.get((wi["workflow_name"], wi["workflow_version"]))
                    if wf_data is None:
                        raise SubstrateError(
                            ErrorCode.REPLAY_HALTED,
                            f"Missing workflow {wi['workflow_name']!r} "
                            f"v{wi['workflow_version']}",
                        )
                    found = False
                    for t in wf_data.get("transitions", []):
                        if t["name"] == evt.transition and t["from_state"] == derived_state:
                            derived_state = t["to_state"]
                            found = True
                            break
                    if not found:
                        name_matches = any(
                            t["name"] == evt.transition for t in wf_data.get("transitions", [])
                        )
                        if name_matches:
                            raise SubstrateError(
                                ErrorCode.REPLAY_HALTED,
                                f"Transition {evt.transition!r} exists but not valid "
                                f"from state {derived_state!r}",
                            )
                    if found:
                        p = evt.payload or {}
                        if "custom_fields_update" in p:
                            derived_fields = {**derived_fields, **p["custom_fields_update"]}
                        derived_claimed_by = None
        except SubstrateError:
            halted += 1
        except Exception:
            halted += 1
        else:
            if derived_state is not None:
                live_expires = wi.get("claim_expires_at")
                expires_match = _ts_equal_within(
                    derived_claim_expires_at, live_expires, derived_coalesce_threshold,
                )
                if (
                    derived_state != wi["current_state"]
                    or derived_fields != (wi["custom_fields"] or {})
                    or derived_needs_review != wi.get("needs_review", False)
                    or not _ts_equal(derived_not_before, wi.get("not_before"))
                    or derived_last_seq != wi.get("last_event_seq", 0)
                    or derived_attempt_number != wi.get("attempt_number", 0)
                    or derived_claimed_by != wi.get("claimed_by")
                    or not expires_match
                ):
                    drift += 1
                else:
                    ok += 1

    return ReplayReport(
        table_name="in_memory_replay",
        replayed_ok=ok,
        replayed_drift=drift,
        halted=halted,
        warnings=warnings,
    )
