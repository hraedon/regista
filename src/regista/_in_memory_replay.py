from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import datetime
from typing import Any

import structlog

from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, RegistaError
from ._event_store import InMemoryEventStore
from ._keys import KeySet
from ._replay import _is_expected_unpinned_bootstrap
from ._types import Event, ReplayReport
from ._v6_referents import MappingReferents, MaterialCompleteness
from ._verification import (
    V6_ENTITY_KINDS,
    AbsentEnvelopeProbe,
    Applicability,
    Backend,
    EventRow,
    FailureReason,
    KeySetResolver,
    VerificationPolicy,
    probe_absent_envelope,
    verify_event_strict,
)


def _try_fromisoformat(value: str | None) -> datetime | None:
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

#: The InMemory backend verifies under the same policy as Postgres: v5 is fully
#: authenticated, v4 is legacy-partial, everything else is invalid.
_IN_MEMORY_POLICY = VerificationPolicy()

#: Keyless replay. ``accept_unsigned_keyless`` permits an unsigned event to be
#: *processed*; it never manufactures authentication — the result's
#: applicability stays UNVERIFIABLE either way.
_KEYLESS_POLICY = VerificationPolicy(accept_unsigned_keyless=True)


class _NoKeyResolver:
    """No key material at all: keyless mode has none by construction."""

    def resolve(self, key_id: str | None) -> None:
        return None


_NO_KEY_RESOLVER = _NoKeyResolver()


def _verify_non_work_item_group(
    events: list[Event],
    *,
    key_set: KeySet | None,
    referents: MappingReferents,
    continue_on_revoked: bool,
) -> tuple[int, int, int, bool]:
    """Verify every event in a legal non-work-item entity group.

    Non-work-item groups do not rebuild ``work_items_current``, but they are still
    signed v6 entities and may carry the complete action-delegation contract.  A
    group is counted when every event survives strict row/envelope validation and
    every delegated authorization is verified against the complete store material.
    The expected unpinned bootstrap authority is the one deliberate exception:
    its bytes are checked, but the external trust root is outside a default replay.
    """

    warnings = 0
    chain_breaks = 0
    unverifiable = 0
    verified = True
    previous: Event | None = None
    for event in sorted(events, key=lambda item: item.event_seq):
        chain_ok, chain_error = _verify_hash_chain_in_memory(event, previous)
        if not chain_ok:
            chain_breaks += 1
            verified = False
            log.warning(
                "replay.hash_chain_broken",
                entity_kind=event.entity_kind,
                entity_id=str(event.effective_entity_id),
                event_id=str(event.event_id),
                event_seq=event.event_seq,
                detail=chain_error,
            )

        key_entry = None
        unknown_key_skipped = False
        if key_set is not None:
            try:
                key_entry = key_set.verify_key_status(
                    event.key_id,
                    event_timestamp=event.timestamp.isoformat() if event.timestamp else None,
                )
            except RegistaError as exc:
                if exc.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                    key_entry = key_set.get_key(event.key_id)
                    warnings += 1
                elif exc.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                    unknown_key_skipped = True
                    warnings += 1
                else:
                    raise

        if key_set is None:
            verification = verify_event_strict(
                EventRow.from_event(event, backend=Backend.IN_MEMORY),
                keys=_NO_KEY_RESOLVER,
                referents=referents,
                policy=_KEYLESS_POLICY,
            )
        elif key_entry is None:
            verification = None
        else:
            verification = verify_event_strict(
                EventRow.from_event(event, backend=Backend.IN_MEMORY),
                keys=KeySetResolver(key_set),
                referents=referents,
                policy=_IN_MEMORY_POLICY,
            )

        if verification is not None:
            if verification.applicability is Applicability.INVALID:
                raise RegistaError(
                    ErrorCode.REPLAY_HALTED,
                    f"Signature verification failed for event {event.event_id} "
                    f"at seq {event.event_seq}: {verification.summary()}",
                )
            if not verification.accepted:
                # See the Postgres replay path: a bootstrap event without an
                # external trust/checkpoint pin is an expected policy gap, not
                # an event that replay failed to inspect.  Keep the clean epoch
                # group count and report counters aligned across backends.
                expected_unpinned_bootstrap = _is_expected_unpinned_bootstrap(
                    entity_kind=event.entity_kind,
                    transition=event.transition,
                    applicability=verification.applicability,
                    reasons=verification.reasons,
                )
                if not expected_unpinned_bootstrap:
                    verified = False
                    unverifiable += 1
            if verification.delegated_authorization and (
                verification.delegation_verification.value != "verified"
            ):
                verified = False
                if verification.delegation_verification.value == "unverifiable":
                    unverifiable += 1
        else:
            verified = False
            unverifiable += 1
        if unknown_key_skipped:
            verified = False
            unverifiable += 1
        previous = event

    return warnings, chain_breaks, unverifiable, verified



def _head_hash(event: Event) -> bytes | None:
    """The chain head hash ``event`` contributes, under its own envelope version.

    Delegates to ``_signing.compute_chain_head_hash`` — the same call the Postgres
    path's ``_replay._event_head_hash`` makes. Both walks in this module used to
    hardcode the v1-v5 formula, which made every v6 event in an in-memory epoch
    unreachable from genesis: a healthy epoch reported one chain break per
    post-genesis event and the backends disagreed about a clean chain.
    """

    env = event.canonical_envelope
    sig = event.signature
    if env is None or sig is None:
        return None
    from ._signing import compute_chain_head_hash

    return compute_chain_head_hash(bytes(env), bytes(sig))


def _verify_hash_chain_in_memory(
    event: Event,
    prev_event: Event | None,
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
    computed = _head_hash(prev_event)
    if computed is None:
        return False, "previous event has no computable event hash"
    if not _hmac.compare_digest(computed, bytes(expected)):
        detail = f"hash chain mismatch: computed={computed.hex()} expected={bytes(expected).hex()}"
        return False, detail
    return True, ""


def _verify_global_hash_chain_in_memory(events: list[Event]) -> tuple[int, Event | None]:
    """Walk the global hash chain by following ``prev_global_event_hash`` links
    (BC-300 / Plan 024).

    Immune to ``global_seq`` ordering issues (CACHE 100 interleaving).
    Returns ``(chain_breaks, chain_tail)`` — every finding this walk makes is
    a structural chain failure (WI-266), so they count as chain breaks, not
    warnings.
    """
    from collections import defaultdict

    if not events:
        return 0, None

    link_map: dict[str, list[Event]] = defaultdict(list)
    genesis_events: list[Event] = []
    for evt in events:
        if evt.prev_global_event_hash is None:
            genesis_events.append(evt)
        else:
            link_map[bytes(evt.prev_global_event_hash).hex()].append(evt)

    chain_breaks = 0

    # Order-stable genesis selection (WI-219): the canonical chain start is the
    # lowest global_seq, tie-broken on event_id, so the verdict does not depend
    # on the arbitrary order of the input list.
    genesis_events.sort(
        key=lambda e: (
            e.global_seq is None,
            e.global_seq or 0,
            str(e.event_id),
        )
    )

    if len(genesis_events) > 1:
        for g in genesis_events[1:]:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_multiple_genesis",
                event_id=str(g.event_id),
                global_seq=g.global_seq,
            )

    if not genesis_events:
        for evt in events:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt.event_id),
                global_seq=evt.global_seq,
                detail="no genesis event",
            )
        return chain_breaks, None

    current = genesis_events[0]
    visited: set[uuid.UUID] = set()

    while True:
        eid = current.event_id
        if eid in visited:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_cycle",
                event_id=str(eid),
                global_seq=current.global_seq,
            )
            break

        visited.add(eid)

        head_hash = _head_hash(current)
        if head_hash is None:
            break

        successors = link_map.get(head_hash.hex(), [])

        if not successors:
            break

        if len(successors) > 1:
            for s in successors[1:]:
                chain_breaks += 1
                log.warning(
                    "replay.global_chain_fork",
                    event_id=str(s.event_id),
                    global_seq=s.global_seq,
                    detail=f"multiple events chain from event {eid}",
                )

        current = successors[0]

    for evt in events:
        if evt.event_id not in visited:
            chain_breaks += 1
            log.warning(
                "replay.global_chain_orphan",
                event_id=str(evt.event_id),
                global_seq=evt.global_seq,
                detail="event not reachable from genesis via prev_global_event_hash links",
            )

    return chain_breaks, current


def in_memory_replay(
    work_items: dict[uuid.UUID, dict[str, Any]],
    workflows: dict[tuple[str, int], dict[str, Any]],
    store: InMemoryEventStore,
    key_set: KeySet | None,
    *,
    continue_on_revoked: bool = False,
    verify_principal_binding: bool = False,
    work_item_id: uuid.UUID | None = None,
) -> ReplayReport:
    ok = 0
    drift = 0
    halted = 0
    warnings = 0
    chain_breaks = 0
    unverifiable = 0
    non_work_item_groups = 0
    scoped = work_item_id is not None

    # The presented material, built once (see `_replay.store_referents` for why once).
    # `COMPLETE_STORE`: this store IS the whole project, so an anchor it does not hold
    # is absent rather than out of scope — the same claim the Postgres backend makes,
    # which is what keeps the two backends' v6 verdicts identical.
    referents = MappingReferents.from_pairs(
        ((evt.canonical_envelope, evt.signature) for evt in store.all_events()),
        completeness=MaterialCompleteness.COMPLETE_STORE,
        label="in-memory project store",
        action_delegation_credentials=(
            row["document"]
            for row in store.v6_rows.action_delegation_credentials.values()
        ),
    )

    if verify_principal_binding:
        warnings += 1
        log.warning(
            "replay.in_memory_principal_binding_noop",
            detail="InMemory backend has no principal_keys registry; "
                   "verify_principal_binding is a no-op",
        )

    all_entity_groups: dict[tuple[str, uuid.UUID], list[Event]] = {}
    for event in store.all_events():
        all_entity_groups.setdefault(
            (event.entity_kind, event.effective_entity_id), []
        ).append(event)

    if not scoped:
        wi_ids = set(work_items.keys())
        for (entity_kind, entity_id), group_events in all_entity_groups.items():
            orphan_evts = sorted(group_events, key=lambda e: e.event_seq)
            if entity_kind not in V6_ENTITY_KINDS:
                halted += 1
                log.error(
                    "replay.unknown_entity_kind",
                    entity_id=str(entity_id),
                    entity_kinds=[entity_kind],
                    event_count=len(orphan_evts),
                )
                continue
            if entity_kind != "work_item":
                try:
                    group_warnings, group_breaks, group_unverifiable, verified = (
                        _verify_non_work_item_group(
                            orphan_evts,
                            key_set=key_set,
                            referents=referents,
                            continue_on_revoked=continue_on_revoked,
                        )
                    )
                except RegistaError as exc:
                    halted += 1
                    log.error(
                        "replay.non_work_item_verification_failed",
                        entity_kind=entity_kind,
                        entity_id=str(entity_id),
                        error=str(exc),
                    )
                    continue
                warnings += group_warnings
                chain_breaks += group_breaks
                unverifiable += group_unverifiable
                if verified:
                    non_work_item_groups += 1
                log.info(
                    "replay.non_work_item_entity",
                    entity_kind=entity_kind,
                    entity_id=str(entity_id),
                    event_count=len(orphan_evts),
                    verified=verified,
                )
                continue
            if entity_id in wi_ids:
                continue
            # WI-266: a created work item whose projection row is gone is the
            # same structural finding scoped replay halts on. Both the created
            # and non-created orphan are halts now, matching the Postgres path.
            is_created = len(orphan_evts) > 0 and orphan_evts[0].transition == "created"
            halted += 1
            if is_created:
                log.error(
                    "replay.orphan_work_item_missing_projection",
                    work_item_id=str(entity_id),
                    event_count=len(orphan_evts),
                )
            else:
                log.error(
                    "replay.orphan_events",
                    work_item_id=str(entity_id),
                    event_count=len(orphan_evts),
                )

    if scoped:
        assert work_item_id is not None
        wi_ids = {work_item_id} if work_item_id in work_items else set()
        items = (
            [(work_item_id, work_items[work_item_id])]
            if work_item_id in work_items
            else []
        )
        if work_item_id not in work_items and store.has_events_for_id(work_item_id):
            halted += 1
            log.error(
                "replay.projection_row_missing",
                work_item_id=str(work_item_id),
                event_count=sum(
                    len(events)
                    for key, events in store.events.items()
                    if key[1] == work_item_id
                ),
            )
    else:
        items = list(work_items.items())

    processed_wi_ids: set[uuid.UUID] = set()
    keyless_unsigned = 0

    for wi_id, wi in items:
        evts = store.events_for("work_item", wi_id)
        if not evts:
            continue
        processed_wi_ids.add(wi_id)
        try:
            derived_state = None
            derived_fields: dict[str, Any] = {}
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
                    # WI-266: structural failure — chain_breaks, not warnings.
                    log.warning(
                        "replay.hash_chain_broken",
                        work_item_id=str(wi_id),
                        event_id=str(evt.event_id),
                        event_seq=evt.event_seq,
                        detail=chain_err,
                    )
                    chain_breaks += 1

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
                            log.warning(
                                "replay.revoked_key_signature_verified",
                                work_item_id=str(wi_id),
                                event_id=str(evt.event_id),
                                event_seq=evt.event_seq,
                                key_id=evt.key_id,
                            )
                        elif e.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                            warnings += 1
                            log.warning(
                                "replay.unknown_key_skipped",
                                work_item_id=str(wi_id),
                                event_id=str(evt.event_id),
                                event_seq=evt.event_seq,
                                key_id=evt.key_id,
                            )
                        else:
                            raise
                    if key_entry is not None:
                        # WI-267: the InMemory backend runs the SAME
                        # reconciliation as Postgres, so the two backends cannot
                        # disagree about what "verified" means and a
                        # reconciliation bug cannot hide here until it reaches
                        # production.
                        verification = verify_event_strict(
                            EventRow.from_event(evt, backend=Backend.IN_MEMORY),
                            keys=KeySetResolver(key_set),
                            referents=referents,
                            policy=_IN_MEMORY_POLICY,
                        )
                        if verification.applicability is Applicability.INVALID:
                            raise RegistaError(
                                ErrorCode.REPLAY_HALTED,
                                f"Signature verification failed for event {evt.event_id} "
                                f"at seq {evt.event_seq}: {verification.summary()}",
                            )
                        if not verification.accepted:
                            # See _replay.py: an evidentiary gap is counted
                            # separately, never confused with an attack and
                            # never silently passed — and a NULL envelope whose
                            # retained signature cannot be reconciled with the
                            # row at all is not a gap, it is a contradiction.
                            # The probe convicts only; it can never acquit.
                            if FailureReason.ENVELOPE_ABSENT in verification.reasons:
                                probe = probe_absent_envelope(
                                    EventRow.from_event(
                                        evt, backend=Backend.IN_MEMORY,
                                    ),
                                    keys=KeySetResolver(key_set),
                                )
                                if probe is AbsentEnvelopeProbe.INCONSISTENT:
                                    raise RegistaError(
                                        ErrorCode.REPLAY_HALTED,
                                        f"Event {evt.event_id} at seq "
                                        f"{evt.event_seq} has no "
                                        "canonical_envelope, and no envelope "
                                        "this row could have carried "
                                        "reproduces its retained signature: "
                                        "the row contradicts its own "
                                        "cryptographic material",
                                    )
                                unverifiable += 1
                                log.warning(
                                    "replay.event_envelope_absent",
                                    work_item_id=str(wi_id),
                                    event_id=str(evt.event_id),
                                    event_seq=evt.event_seq,
                                    probe=probe.value,
                                    detail=verification.summary(),
                                )
                            else:
                                unverifiable += 1
                                log.warning(
                                    "replay.event_unverifiable",
                                    work_item_id=str(wi_id),
                                    event_id=str(evt.event_id),
                                    event_seq=evt.event_seq,
                                    detail=verification.summary(),
                                )
                else:
                    # Keyless mode. The store wrote zero-byte dummy crypto
                    # material, so there is nothing to verify — but "nothing was
                    # checked" must be *reported*, not silently equated with
                    # success (CUTOVER-POLICY §5.2).
                    #
                    # `accepted` is True for a genuine keyless dummy (the policy
                    # permits such an event to be *processed*), so branching on
                    # it would report nothing at all — which is the silence this
                    # comment exists to forbid. Branch on the applicability
                    # instead: `accept_unsigned_keyless` permits use, it never
                    # manufactures authentication, and the applicability stays
                    # UNVERIFIABLE either way.
                    verification = verify_event_strict(
                        EventRow.from_event(evt, backend=Backend.IN_MEMORY),
                        keys=_NO_KEY_RESOLVER,
                        referents=referents,
                        policy=_KEYLESS_POLICY,
                    )
                    if verification.applicability is not Applicability.FULLY_AUTHENTICATED:
                        unverifiable += 1
                        keyless_unsigned += 1
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

    # WI-266: a projection row with NO events was never compared above — the
    # group loop skips it. A fabricated projection row or a wholesale-deleted
    # event log must halt, exactly like the Postgres path.
    for missing_id in sorted(wi_ids - processed_wi_ids, key=str):
        halted += 1
        log.error(
            "replay.projection_row_without_events",
            work_item_id=str(missing_id),
        )

    if not scoped:
        all_global_events = store.all_events()
        stored_head = getattr(store, "_global_chain_head", None)

        if not all_global_events:
            # WI-266: no events at all, yet the chain head claims one — the
            # head proves events were appended and then deleted wholesale.
            if stored_head is not None:
                halted += 1
                log.error(
                    "replay.global_chain_head_without_events",
                    detail=(
                        "global chain head is set but the event log is empty; "
                        "the log was appended to and then deleted"
                    ),
                )
        else:
            chain_breaks_found, chain_tail = _verify_global_hash_chain_in_memory(
                all_global_events
            )
            chain_breaks += chain_breaks_found

            if chain_tail is not None:
                computed_head = _head_hash(chain_tail)
                if computed_head is not None:
                    if stored_head is not None and not _hmac.compare_digest(
                        bytes(stored_head), computed_head
                    ):
                        chain_breaks += 1
                        log.warning(
                            "replay.global_chain_head_mismatch",
                            detail=(
                                "global chain head does not match the chain tail; "
                                "a tail event may have been deleted or the head tampered"
                            ),
                        )
    else:
        log.info("replay.scoped_skips_global_verification", work_item_id=str(work_item_id))

    if keyless_unsigned:
        # One line per replay rather than one per event: the fact an operator
        # needs is "this replay checked no signatures at all", and the count.
        log.warning(
            "replay.keyless_no_signatures_verified",
            event_count=keyless_unsigned,
            detail=(
                "the InMemory store was opened without a key set, so these "
                "events were never signed and nothing was cryptographically "
                "verified; they are counted as unverifiable, not as replayed "
                "with an intact signature"
            ),
        )

    return ReplayReport(
        table_name="in_memory_replay",
        replayed_ok=ok,
        replayed_drift=drift,
        halted=halted,
        warnings=warnings,
        chain_breaks=chain_breaks,
        unverifiable=unverifiable,
        # Deliberately False even when verify_principal_binding was requested:
        # the InMemory backend has no principal_keys registry, so the check did
        # not run. WI-223 — never claim a binding was verified when it wasn't.
        principal_binding_verified=False,
        non_work_item_groups_verified=non_work_item_groups,
    )
