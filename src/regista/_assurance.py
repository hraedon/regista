from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from types import SimpleNamespace
from typing import Any

from ._review_validators import declared_lineage, derive_authors, normalized_kind


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
        # declared_lineage strips before trusting: a whitespace-only or
        # non-string model_lineage declares nothing and must read as UNKNOWN
        # rather than as a lineage distinct from every real one.
        return declared_lineage(meta.get("model_lineage"))
    return None


def _weakest(first: LineageRelation, second: LineageRelation) -> LineageRelation:
    """Combine two lineage verdicts conservatively (WI-258).

    A review is only independent if EVERY identity behind it is provably
    distinct from the authors, so the combined verdict is the weakest of the
    two: any SAME makes the whole review same-lineage, any UNKNOWN leaves
    distinctness unestablished, and DISTINCT survives only when both agree.
    """
    if LineageRelation.SAME in (first, second):
        return LineageRelation.SAME
    if LineageRelation.UNKNOWN in (first, second):
        return LineageRelation.UNKNOWN
    return LineageRelation.DISTINCT


def review_lineage_relation(
    author_lineages: set[str], review_event: Any
) -> LineageRelation:
    """Classify a review event's *effective* lineage against the authors (WI-258).

    Reviewer lineage used to be read from the proxy actor's ``actor_metadata``
    alone, so a proxy declaring lineage B acting ``on_behalf_of`` a principal
    declaring lineage A reviewed A-authored work as "cross-lineage" — the
    delegation laundered a same-lineage review. When the review event carries a
    delegated **agent** principal, that principal is the mind doing the review,
    so its lineage must clear the distinctness bar too:

    * declared principal lineage — the verdict is the weakest of the proxy's
      and the principal's relation (same on either side ⇒ ``SAME``);
    * undeclared principal lineage — no better than ``UNKNOWN``, fail closed
      exactly as an undeclared reviewer lineage does (WI-239). "Undeclared"
      means empty *after stripping*: a whitespace-only or non-string value
      names no model, and ``principal_lineage`` is validated nowhere at the API
      boundary;
    * ``principal_kind`` "human" — the proxy's own relation, unchanged; a human
      principal is not a model lineage at all;
    * any OTHER declared kind — ``UNKNOWN``. An unrecognised kind cannot
      establish "this principal is not a model", which is the only reason
      ignoring it would be safe. Kinds are matched case- and
      whitespace-insensitively, since ``principal_kind`` (unlike ``actor_kind``)
      passes no boundary validation and "Agent" means "agent".

    A delegation carrying no ``principal_kind`` key at all (or an explicit
    ``None``) is left alone: that is
    the bare ``{"principal_id": ...}`` shape regista uses for separation of
    duties, and it predates any lineage claim, so blocking it would be an
    unrelated behaviour change rather than a fail-closed fix.

    ``review_event`` is anything event-shaped: a stored event or a validator
    ctx (both expose ``actor_metadata`` and ``on_behalf_of``).
    """
    relation = lineage_relation(author_lineages, _event_lineage(review_event))
    delegation = getattr(review_event, "on_behalf_of", None)
    if not isinstance(delegation, dict):
        return relation
    raw_kind = delegation.get("principal_kind")
    if raw_kind is None:
        return relation
    principal_kind = normalized_kind(raw_kind)
    if principal_kind == "human":
        return relation
    if principal_kind != "agent":
        # Declared but unusable (blank, non-string, or simply a kind this gate
        # does not know): it cannot vouch that the principal is not a model.
        return _weakest(relation, LineageRelation.UNKNOWN)
    principal_lineage = declared_lineage(delegation.get("principal_lineage"))
    if principal_lineage is None:
        return _weakest(relation, LineageRelation.UNKNOWN)
    return _weakest(relation, lineage_relation(author_lineages, principal_lineage))


def effective_lineage_relation(
    relation: LineageRelation, agent_author_undeclared: bool
) -> LineageRelation:
    """Fold the undeclared-agent-author flag into the reviewer verdict (WI-256).

    ``derive_authors`` reports whether some (non-exempt) agent author declared
    no lineage. Callers used to discard that flag and classify on the declared
    lineages alone, so a mixed history — one declared lineage-A event plus an
    undeclared agent event — read as ``DISTINCT`` against a lineage-B reviewer.
    Distinctness from the lineages we happen to know is not distinctness from
    the authors: if any agent author is undeclared, the honest verdict is
    ``UNKNOWN``. ``SAME`` is preserved because it is already the blocking
    verdict and it reports the collision more precisely.
    """
    if agent_author_undeclared and relation is LineageRelation.DISTINCT:
        return LineageRelation.UNKNOWN
    return relation


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


def _author_lineage_state(events: Sequence[Any]) -> tuple[set[str], bool]:
    """Author lineages plus the undeclared-agent-author flag (WI-256).

    Delegates to the gate's own ``derive_authors`` so the assurance view and
    the validators cannot drift: same non-author transitions, same WI-248
    service-identity exemption, same delegated-principal traversal, and — the
    part this module previously had no way to see — the same
    ``agent_author_undeclared`` verdict.
    """
    _ids, _kinds, author_lineages, agent_author_undeclared = derive_authors(events)
    return author_lineages, agent_author_undeclared


def compute_assurance_level(events: Sequence[Any]) -> AssuranceLevel:
    author_lineages, agent_author_undeclared = _author_lineage_state(events)

    last_pass_idx = -1
    for i, e in enumerate(events):
        if getattr(e, "transition", None) == "adversarial_pass":
            last_pass_idx = i

    if last_pass_idx < 0:
        return AssuranceLevel.NONE

    last_pass = events[last_pass_idx]
    # WI-239: an undeclared reviewer lineage is UNKNOWN, not independent. The
    # assurance level must not claim INDEPENDENTLY_REVIEWED unless distinctness
    # is actually established, so UNKNOWN escalates exactly as SAME does.
    # WI-258 folds a delegated agent reviewer principal into the verdict;
    # WI-256 folds in an undeclared agent author.
    relation = effective_lineage_relation(
        review_lineage_relation(author_lineages, last_pass), agent_author_undeclared
    )
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

    author_lineages, agent_author_undeclared = _author_lineage_state(events)

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
            "agent_author_undeclared": agent_author_undeclared,
        }

    last_pass = events[last_pass_idx]
    reviewer_lineage = _event_lineage(last_pass)
    # WI-239: UNKNOWN must not be read as proven independence. WI-258: a
    # delegated agent reviewer principal's lineage counts too. WI-256: an
    # undeclared agent author defeats any claim of distinctness — the reported
    # lineage_relation is the EFFECTIVE one the gate decided on, so an auditor
    # never sees "distinct" next to a history that could not establish it.
    relation = effective_lineage_relation(
        review_lineage_relation(author_lineages, last_pass), agent_author_undeclared
    )
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
            "agent_author_undeclared": agent_author_undeclared,
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
        "agent_author_undeclared": agent_author_undeclared,
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
