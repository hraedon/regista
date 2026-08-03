from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from types import SimpleNamespace
from typing import Any


class AssuranceLevel(StrEnum):
    NONE = "none"
    SELF_REVIEWED = "self_reviewed"
    INDEPENDENTLY_REVIEWED = "independently_reviewed"
    HUMAN_ACCEPTED = "human_accepted"
    INDEPENDENT_AND_ACCEPTED = "independently_and_accepted"


class GateProfile(StrEnum):
    RELAXED = "relaxed"
    STRICT = "strict"


class LineageRelation(StrEnum):
    """Three-state verdict on reviewer↔author lineage distinctness (WI-239).

    The two-state boolean (same vs not-same) conflated two very different
    outcomes: a confirmed cross-lineage reviewer and an *undeclared* one.
    ``same_lineage()`` returned ``False`` for both, so the human-gate
    escalation read unknown independence as proven independence — the
    opposite of the conservative default the docs claimed. An undeclared
    reviewer lineage must never satisfy a distinctness requirement.
    """

    SAME = "same"
    DISTINCT = "distinct"
    UNKNOWN = "unknown"


_REVIEW_VERDICTS = frozenset(
    {"accept", "request_changes", "adversarial_pass", "reject", "comment"}
)


def lineage_relation(
    author_lineages: set[str], reviewer_lineage: str | None
) -> LineageRelation:
    """Classify the reviewer's lineage against the author set (WI-239).

    Returns:
        ``SAME`` when the reviewer declared a lineage present among the
        authors; ``DISTINCT`` only when the reviewer declared a lineage that
        provably does not appear among the authors; ``UNKNOWN`` when the
        reviewer declared nothing (or there are no author lineages to compare
        against), so independence cannot be established.
    """
    if not reviewer_lineage:
        return LineageRelation.UNKNOWN
    if not author_lineages:
        return LineageRelation.UNKNOWN
    if reviewer_lineage in author_lineages:
        return LineageRelation.SAME
    return LineageRelation.DISTINCT


def same_lineage(author_lineages: set[str], reviewer_lineage: str | None) -> bool:
    """Backward-compatible boolean: True only for a confirmed same-lineage review.

    Kept for callers that predate the three-state distinction (WI-239). The
    gate paths that decide *escalation* must use :func:`lineage_relation` and
    treat ``UNKNOWN`` as needing escalation; this boolean cannot express that.
    """
    return lineage_relation(author_lineages, reviewer_lineage) == LineageRelation.SAME


def _event_lineage(event: Any) -> str | None:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict):
        lineage = meta.get("model_lineage")
        if lineage:
            return str(lineage)
    return None


def _lineage_verification(event: Any) -> str:
    # WI-215: the actor_kind / actor_metadata.model_lineage columns ride OUTSIDE
    # the v4 signed scope, so on an HMAC/v4 event a database-write attacker can
    # mutate them without invalidating the signature — that lineage is merely
    # "asserted". A per-actor asymmetric scheme (ed25519) signs the actor binding
    # to its principal, so the same mutation breaks the signature — that lineage
    # is "verified". This is the review-assurance.md upgrade path (per-actor
    # signing flips asserted -> verified). The signal is informational only; it
    # never changes a gate decision. An absent or unknown scheme fails to the
    # honest "asserted" label.
    scheme_id = getattr(event, "scheme_id", None)
    if not scheme_id:
        return "asserted"
    try:
        from ._signing_scheme import get_scheme

        return "verified" if get_scheme(scheme_id).is_asymmetric else "asserted"
    except Exception:
        return "asserted"


def _extract_author_lineages(events: Sequence[Any]) -> set[str]:
    author_lineages: set[str] = set()
    for event in events:
        transition = getattr(event, "transition", None)
        if transition in _REVIEW_VERDICTS:
            continue
        lineage = _event_lineage(event)
        if lineage:
            author_lineages.add(lineage)
        delegation = getattr(event, "on_behalf_of", None)
        if isinstance(delegation, dict):
            principal_lineage = delegation.get("principal_lineage")
            if principal_lineage:
                author_lineages.add(str(principal_lineage))
    return author_lineages


def compute_assurance_level(events: Sequence[Any]) -> AssuranceLevel:
    author_lineages = _extract_author_lineages(events)

    last_pass_idx = -1
    for i, e in enumerate(events):
        if getattr(e, "transition", None) == "adversarial_pass":
            last_pass_idx = i

    if last_pass_idx < 0:
        return AssuranceLevel.NONE

    last_pass = events[last_pass_idx]
    reviewer_lineage = _event_lineage(last_pass)
    relation = lineage_relation(author_lineages, reviewer_lineage)
    # WI-239: an undeclared reviewer lineage is UNKNOWN, not independent. The
    # assurance level must not claim INDEPENDENTLY_REVIEWED unless distinctness
    # is actually established, so UNKNOWN escalates exactly as SAME does.
    is_same = relation != LineageRelation.DISTINCT

    accept_events = [
        e for i, e in enumerate(events)
        if getattr(e, "transition", None) == "accept" and i > last_pass_idx
    ]
    if not accept_events:
        if is_same:
            return AssuranceLevel.SELF_REVIEWED
        return AssuranceLevel.INDEPENDENTLY_REVIEWED

    last_accept = accept_events[-1]
    accepter_kind = getattr(last_accept, "actor_kind", None)
    human_accepted = accepter_kind == "human"

    if human_accepted:
        if is_same:
            return AssuranceLevel.HUMAN_ACCEPTED
        return AssuranceLevel.INDEPENDENT_AND_ACCEPTED

    if is_same:
        return AssuranceLevel.SELF_REVIEWED
    return AssuranceLevel.INDEPENDENTLY_REVIEWED


def compute_assurance_level_from_dicts(
    events: Sequence[dict[str, Any]],
) -> AssuranceLevel:
    converted: list[SimpleNamespace] = []
    for e in events:
        converted.append(
            SimpleNamespace(
                transition=e.get("transition"),
                actor_id=e.get("actor_id", ""),
                actor_kind=e.get("actor_kind", ""),
                actor_metadata=e.get("actor_metadata"),
                on_behalf_of=e.get("on_behalf_of"),
                payload=e.get("payload"),
                scheme_id=e.get("scheme_id"),
            )
        )
    return compute_assurance_level(converted)


def gate_rationale(
    events: Sequence[Any],
    profile: GateProfile | str,
) -> dict[str, Any]:
    if isinstance(profile, str):
        try:
            profile = GateProfile(profile)
        except ValueError as exc:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Unknown gate profile: {profile!r}. Valid: {[p.value for p in GateProfile]}",
            ) from exc

    author_lineages = _extract_author_lineages(events)

    last_pass_idx = -1
    for i, e in enumerate(events):
        if getattr(e, "transition", None) == "adversarial_pass":
            last_pass_idx = i

    if last_pass_idx < 0:
        close_events = [
            e for e in events if getattr(e, "transition", None) == "close_from_open"
        ]
        if close_events:
            reason = "close_from_open"
        else:
            reason = "not_done"
        return {
            "profile": profile.value,
            "reason": reason,
            "assurance_level": AssuranceLevel.NONE,
            "reviewer_lineage": None,
            "author_lineages": sorted(author_lineages),
            "lineage_verification": None,
        }

    last_pass = events[last_pass_idx]
    reviewer_lineage = _event_lineage(last_pass)
    relation = lineage_relation(author_lineages, reviewer_lineage)
    # WI-239: UNKNOWN must not be read as proven independence.
    is_same = relation != LineageRelation.DISTINCT

    accept_events = [
        e for i, e in enumerate(events)
        if getattr(e, "transition", None) == "accept" and i > last_pass_idx
    ]

    if not accept_events:
        level = (
            AssuranceLevel.SELF_REVIEWED
            if is_same
            else AssuranceLevel.INDEPENDENTLY_REVIEWED
        )
        return {
            "profile": profile.value,
            "reason": "not_done",
            "assurance_level": level,
            "reviewer_lineage": reviewer_lineage,
            "author_lineages": sorted(author_lineages),
            "lineage_verification": _lineage_verification(last_pass),
            "lineage_relation": relation.value,
        }

    last_accept = accept_events[-1]
    accepter_kind = getattr(last_accept, "actor_kind", None)
    human_accepted = accepter_kind == "human"

    if not is_same:
        reason = "cross_lineage_review"
    elif human_accepted:
        reason = "human_accept_for_same_lineage"
    else:
        reason = "same_lineage_acknowledged"

    level = compute_assurance_level(events)

    return {
        "profile": profile.value,
        "reason": reason,
        "assurance_level": level,
        "reviewer_lineage": reviewer_lineage,
        "author_lineages": sorted(author_lineages),
        "lineage_verification": _lineage_verification(last_pass),
        "lineage_relation": relation.value,
    }


def gate_permits_done(rationale: dict[str, Any]) -> bool:
    reason = rationale.get("reason")
    profile = rationale.get("profile")

    if reason == "close_from_open":
        return True
    if reason == "not_done":
        return False
    if reason == "cross_lineage_review":
        return True
    if reason == "human_accept_for_same_lineage":
        return True
    if reason == "same_lineage_acknowledged":
        return profile == GateProfile.RELAXED.value
    return False
