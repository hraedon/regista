from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import datetime

import structlog

from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, RegistaError
from ._signing import verify_event as _verify_event
from ._signing_scheme import get_scheme
from ._types import ReplayReport


def _try_fromisoformat(value):
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        structlog.get_logger().warning(
            "replay.malformed_timestamp_in_memory",
            value=value,
        )
        return None


log = structlog.get_logger()


def _verify_hash_chain_in_memory(
    event,
    prev_event,
) -> tuple[bool, str]:
    expected = event.prev_event_hash
    if expected is None:
        return True, ""
    if prev_event is None:
        return False, "prev_event_hash set but no previous event"
    prev_env = prev_event.canonical_envelope
    prev_sig = prev_event.signature
    if prev_env is None or prev_sig is None:
        return False, "previous event missing canonical_envelope or signature"
    from ._signing_scheme import resolve_hash_function

    hash_fn = resolve_hash_function("sha-256")
    computed = hash_fn(bytes(prev_env) + bytes(prev_sig)).digest()
    if not _hmac.compare_digest(computed, bytes(expected)):
        detail = f"hash chain mismatch: computed={computed.hex()} expected={bytes(expected).hex()}"
        return False, detail
    return True, ""


def _verify_global_hash_chain_in_memory(events: list) -> tuple[int, object | None]:
    """Walk the global hash chain by following ``prev_global_event_hash`` links
    (BC-300 / Plan 024).

    Immune to ``global_seq`` ordering issues (CACHE 100 interleaving).
    Returns ``(warning_count, chain_tail)``.
    """
    from collections import defaultdict

    from ._signing_scheme import resolve_hash_function

    if not events:
        return 0, None

    hash_fn = resolve_hash_function("sha-256")

    link_map: dict[str, list] = defaultdict(list)
    genesis_events: list = []
    for evt in events:
        if evt.prev_global_event_hash is None:
            genesis_events.append(evt)
        else:
            link_map[bytes(evt.prev_global_event_hash).hex()].append(evt)

    warnings = 0

    if len(genesis_events) > 1:
        for g in genesis_events[1:]:
            warnings += 1
            log.warning(
                "replay.global_chain_multiple_genesis",
                event_id=str(g.event_id),
                global_seq=g.global_seq,
            )

    if not genesis_events:
        for evt in events:
            warnings += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt.event_id),
                global_seq=evt.global_seq,
                detail="no genesis event",
            )
        return warnings, None

    current = genesis_events[0]
    visited: set = set()

    while True:
        eid = current.event_id
        if eid in visited:
            warnings += 1
            log.warning(
                "replay.global_chain_cycle",
                event_id=str(eid),
                global_seq=current.global_seq,
            )
            break

        visited.add(eid)

        env = current.canonical_envelope
        sig = current.signature
        if env is None or sig is None:
            break

        head_hash = hash_fn(bytes(env) + bytes(sig)).digest()
        successors = link_map.get(head_hash.hex(), [])

        if not successors:
            break

        if len(successors) > 1:
            for s in successors[1:]:
                warnings += 1
                log.warning(
                    "replay.global_chain_fork",
                    event_id=str(s.event_id),
                    global_seq=s.global_seq,
                    detail=f"multiple events chain from event {eid}",
                )

        current = successors[0]

    for evt in events:
        if evt.event_id not in visited:
            warnings += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt.event_id),
                global_seq=evt.global_seq,
                detail="event not reachable from genesis via prev_global_event_hash links",
            )

    return warnings, current


def in_memory_replay(
    work_items: dict,
    workflows: dict,
    store,
    key_set,
    *,
    continue_on_revoked: bool = False,
    work_item_id: uuid.UUID | None = None,
) -> ReplayReport:
    ok = 0
    drift = 0
    halted = 0
    warnings = 0
    scoped = work_item_id is not None

    if not scoped:
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

    if scoped:
        items = [(work_item_id, work_items[work_item_id])] if work_item_id in work_items else []
        if work_item_id not in work_items and work_item_id in store.events:
            halted += 1
            log.error(
                "replay.projection_row_missing",
                work_item_id=str(work_item_id),
                event_count=len(store.events.get(work_item_id, [])),
            )
    else:
        items = work_items.items()

    for wi_id, wi in items:
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
            prev_evt = None
            for evt in sorted(evts, key=lambda e: e.event_seq):
                chain_ok, chain_err = _verify_hash_chain_in_memory(evt, prev_evt)
                if not chain_ok:
                    log.warning(
                        "replay.hash_chain_broken",
                        work_item_id=str(wi_id),
                        event_id=str(evt.event_id),
                        event_seq=evt.event_seq,
                        detail=chain_err,
                    )
                    warnings += 1

                if key_set is not None:
                    key_entry = None
                    try:
                        key_entry = key_set.verify_key_status(
                            evt.key_id,
                            event_timestamp=evt.timestamp.isoformat() if evt.timestamp else None,
                        )
                    except RegistaError as e:
                        if e.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                            key_entry = key_set.get_key(evt.key_id)
                            warnings += 1
                        elif e.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                            warnings += 1
                        else:
                            raise
                    if key_entry is not None:
                        scheme = get_scheme(evt.scheme_id)
                        verify_key = key_entry.secret
                        if scheme.scheme_id == "ed25519" and key_entry.public_key:
                            verify_key = key_entry.public_key
                        if not _verify_event(
                            event_id=evt.event_id,
                            work_item_id=evt.work_item_id,
                            actor_id=evt.actor_id,
                            key_id=evt.key_id,
                            event_seq=evt.event_seq,
                            workflow_name=evt.workflow_name,
                            workflow_version=evt.workflow_version,
                            timestamp=evt.timestamp,
                            transition=evt.transition,
                            payload=evt.payload,
                            signature=evt.signature,
                            canonical_hash=evt.payload_canonical_hash,
                            key=verify_key,
                            stored_envelope=evt.canonical_envelope,
                            on_behalf_of=evt.on_behalf_of,
                            scheme=scheme,
                            entity_kind=evt.entity_kind,
                            hash_alg=evt.hash_alg,
                            prev_event_hash=evt.prev_event_hash,
                            prev_global_event_hash=evt.prev_global_event_hash,
                        ):
                            raise RegistaError(
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
                        derived_not_before = _try_fromisoformat(nb) if isinstance(nb, str) else nb
                elif evt.transition in (
                    "claim_acquired",
                    "claim_released",
                    "claim_expired",
                    "claim_stolen",
                    "claim_heartbeat",
                    "link_created",
                    "link_removed",
                    "hook_dead_lettered",
                ):
                    if evt.transition in ("claim_acquired", "claim_stolen"):
                        derived_attempt_number += 1
                    if evt.transition == "claim_acquired":
                        p = evt.payload or {}
                        derived_claimed_by = p.get("actor_id")
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = _try_fromisoformat(expires_str)
                    elif evt.transition == "claim_stolen":
                        p = evt.payload or {}
                        derived_claimed_by = p.get("new_actor_id")
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = _try_fromisoformat(expires_str)
                    elif evt.transition == "claim_heartbeat":
                        p = evt.payload or {}
                        expires_str = p.get("expires_at")
                        if expires_str:
                            derived_claim_expires_at = _try_fromisoformat(expires_str)
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
                        derived_not_before = _try_fromisoformat(nb) if isinstance(nb, str) else nb
                    else:
                        derived_not_before = None
                else:
                    wf_data = workflows.get((wi["workflow_name"], wi["workflow_version"]))
                    if wf_data is None:
                        raise RegistaError(
                            ErrorCode.REPLAY_HALTED,
                            f"Missing workflow {wi['workflow_name']!r} v{wi['workflow_version']}",
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
                            raise RegistaError(
                                ErrorCode.REPLAY_HALTED,
                                f"Transition {evt.transition!r} exists but not valid "
                                f"from state {derived_state!r}",
                            )
                        warnings += 1
                        log.warning(
                            "replay.unknown_transition",
                            work_item_id=str(wi_id),
                            event_id=str(evt.event_id),
                            event_seq=evt.event_seq,
                            transition=evt.transition,
                        )
                    if found:
                        p = evt.payload or {}
                        if "custom_fields_update" in p:
                            derived_fields = {**derived_fields, **p["custom_fields_update"]}
                        derived_claimed_by = None
                        derived_claim_expires_at = None
                prev_evt = evt
        except RegistaError as exc:
            halted += 1
            log.warning("in_memory_replay.halted", wi=str(wi_id), error=str(exc)[:500])
        except Exception as exc:
            halted += 1
            log.warning("in_memory_replay.halted", wi=str(wi_id), error=str(exc)[:500])
        else:
            if derived_state is not None:
                live_expires = wi.get("claim_expires_at")
                expires_match = _ts_equal_within(
                    derived_claim_expires_at,
                    live_expires,
                    derived_coalesce_threshold,
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

    if not scoped:
        all_global_events = []
        for wid in store.events:
            all_global_events.extend(store.events[wid])
        chain_warnings, chain_tail = _verify_global_hash_chain_in_memory(all_global_events)
        warnings += chain_warnings

        if chain_tail is not None:
            last = chain_tail
            if last.canonical_envelope is not None and last.signature is not None:
                from ._signing_scheme import resolve_hash_function

                computed_head = resolve_hash_function("sha-256")(
                    bytes(last.canonical_envelope) + bytes(last.signature)
                ).digest()
                stored_head = getattr(store, "_global_chain_head", None)
                if stored_head is not None and not _hmac.compare_digest(
                    bytes(stored_head), computed_head
                ):
                    warnings += 1
                    log.warning(
                        "replay.global_chain_head_mismatch",
                        detail=(
                            "global chain head does not match the chain tail; "
                            "a tail event may have been deleted or the head tampered"
                        ),
                    )
    else:
        log.info("replay.scoped_skips_global_verification", work_item_id=str(work_item_id))

    return ReplayReport(
        table_name="in_memory_replay",
        replayed_ok=ok,
        replayed_drift=drift,
        halted=halted,
        warnings=warnings,
    )
