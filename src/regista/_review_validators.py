from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

_REVIEW_VERDICTS = frozenset({"accept", "request_changes", "adversarial_pass", "reject"})
_NON_AUTHOR_TRANSITIONS = _REVIEW_VERDICTS | {"comment"}


def _event_lineage(event: Any) -> str | None:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict):
        lineage = meta.get("model_lineage")
        if lineage:
            return str(lineage)
    return None


def derive_authors(prior_events: Iterable[Any]) -> tuple[set[str], set[str], set[str], bool]:
    author_ids: set[str] = set()
    author_kinds: set[str] = set()
    author_lineages: set[str] = set()
    agent_author_undeclared = False
    for event in prior_events:
        if getattr(event, "transition", None) in _NON_AUTHOR_TRANSITIONS:
            continue
        author_ids.add(event.actor_id)
        author_kinds.add(event.actor_kind)
        lineage = _event_lineage(event)
        if lineage:
            author_lineages.add(lineage)
        elif event.actor_kind == "agent":
            agent_author_undeclared = True
        delegation = getattr(event, "on_behalf_of", None)
        if isinstance(delegation, dict):
            principal_id = delegation.get("principal_id")
            principal_kind = delegation.get("principal_kind")
            if principal_id:
                author_ids.add(principal_id)
            if principal_kind:
                author_kinds.add(principal_kind)
            principal_lineage = delegation.get("principal_lineage")
            if principal_lineage:
                author_lineages.add(str(principal_lineage))
    return author_ids, author_kinds, author_lineages, agent_author_undeclared


class ReviewRejected(ValueError):  # noqa: N818
    def __init__(self, reason: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


def _check_separation_of_duties(ctx: Any, author_ids: set[str], gate: str) -> None:
    if ctx.actor_id in author_ids:
        raise ReviewRejected(
            f"{gate}: the reviewer must differ from every actor who "
            "worked this item (self-review is not allowed)",
            detail={"actor_id": ctx.actor_id, "authors": sorted(author_ids)},
        )
    delegation = getattr(ctx, "on_behalf_of", None)
    if isinstance(delegation, dict):
        principal_id = delegation.get("principal_id")
        if principal_id and principal_id in author_ids:
            raise ReviewRejected(
                f"{gate}: a reviewer acting on behalf of an author is a "
                "self-review (delegated self-review is not allowed)",
                detail={
                    "actor_id": ctx.actor_id,
                    "principal_id": principal_id,
                    "authors": sorted(author_ids),
                },
            )


def _require_review_note(ctx: Any, gate: str) -> None:
    note = (getattr(ctx, "payload", None) or {}).get("review_note")
    if not note or not str(note).strip():
        raise ReviewRejected(
            f"{gate}: a non-empty review note is required for every review verdict",
            detail={"transition": getattr(ctx, "transition_name", None)},
        )


def _adversarial_pass_identities(prior_events: Iterable[Any]) -> set[str]:
    identities: set[str] = set()
    for event in prior_events:
        if getattr(event, "transition", None) != "adversarial_pass":
            continue
        aid = getattr(event, "actor_id", None)
        if aid:
            identities.add(aid)
        delegation = getattr(event, "on_behalf_of", None)
        if isinstance(delegation, dict):
            pid = delegation.get("principal_id")
            if pid:
                identities.add(pid)
    return identities


def adversarial_review(ctx: Any) -> None:
    author_ids, author_kinds, author_lineages, agent_author_undeclared = derive_authors(
        ctx.prior_events
    )

    _check_separation_of_duties(ctx, author_ids, "adversarial_review")
    _require_review_note(ctx, "adversarial_review")

    reviewer_lineage = (getattr(ctx, "actor_metadata", None) or {}).get("model_lineage")
    reviewer_is_agent = ctx.actor_kind == "agent"
    agent_author = "agent" in author_kinds
    reviewer_collides = bool(reviewer_lineage) and reviewer_lineage in author_lineages
    reviewer_undeclared = reviewer_is_agent and not reviewer_lineage

    if reviewer_is_agent and agent_author and (
        reviewer_collides or reviewer_undeclared or agent_author_undeclared
    ):
        payload = getattr(ctx, "payload", None) or {}
        if payload.get("same_lineage_acknowledged") is not True:
            raise ReviewRejected(
                "adversarial_review: the reviewer's model lineage is not "
                "confirmed distinct from an author (shared lineage, undeclared "
                "reviewer lineage, or an undeclared agent author); same-lineage "
                "review requires an explicit same_lineage_acknowledged "
                "acknowledgment",
                detail={
                    "actor_id": ctx.actor_id,
                    "reviewer_lineage": reviewer_lineage,
                    "author_lineages": sorted(author_lineages),
                    "agent_author_undeclared": agent_author_undeclared,
                },
            )


def _last_adversarial_pass_lineage(prior_events: Iterable[Any]) -> str | None:
    last_pass = None
    for event in prior_events:
        if getattr(event, "transition", None) == "adversarial_pass":
            last_pass = event
    if last_pass is None:
        return None
    return _event_lineage(last_pass)


def human_gate(
    ctx: Any,
    *,
    require_human: bool = False,
    require_human_on_same_lineage: bool = False,
) -> None:
    if require_human:
        if ctx.actor_kind != "human":
            raise ReviewRejected(
                "human_gate: final acceptance requires a human actor",
                detail={"actor_id": ctx.actor_id, "actor_kind": ctx.actor_kind},
            )
        author_ids, _author_kinds, _author_lineages, _undeclared = derive_authors(
            ctx.prior_events
        )
        _check_separation_of_duties(ctx, author_ids, "human_gate")

    if require_human_on_same_lineage:
        from ._assurance import LineageRelation, lineage_relation

        # A pass may be absent (nothing reviewed yet) or present with an
        # undeclared lineage. Both leave _last_adversarial_pass_lineage at
        # None, but only the latter is an escalation trigger: with no pass at
        # all there is no same-lineage review to catch. Distinguish via the
        # pass's mere existence.
        pass_exists = _adversarial_pass_identities(ctx.prior_events) != set()
        reviewer_lineage = _last_adversarial_pass_lineage(ctx.prior_events)
        _author_ids, _author_kinds, author_lineages, _undeclared = derive_authors(
            ctx.prior_events
        )
        # WI-239: an undeclared reviewer lineage is UNKNOWN, not independent.
        # For the human-gate escalation it must behave exactly like SAME —
        # unknown independence is never a reason to skip the human.
        relation = lineage_relation(author_lineages, reviewer_lineage)
        needs_human = pass_exists and (
            relation in (LineageRelation.SAME, LineageRelation.UNKNOWN)
        )
        if needs_human and ctx.actor_kind != "human":
            raise ReviewRejected(
                "human_gate: same-lineage (or undeclared-lineage) review "
                "requires a human acceptor under the strict gate profile",
                detail={
                    "actor_id": ctx.actor_id,
                    "actor_kind": ctx.actor_kind,
                    "reviewer_lineage": reviewer_lineage,
                    "author_lineages": sorted(author_lineages),
                    "lineage_relation": relation.value,
                },
            )

    _require_review_note(ctx, "human_gate")

    if getattr(ctx, "transition_name", None) == "accept":
        pass_ids = _adversarial_pass_identities(ctx.prior_events)
        delegation = getattr(ctx, "on_behalf_of", None)
        acceptor_principal = (
            delegation.get("principal_id") if isinstance(delegation, dict) else None
        )
        if ctx.actor_id in pass_ids or (acceptor_principal and acceptor_principal in pass_ids):
            raise ReviewRejected(
                "human_gate: the final accepter must differ from every actor who "
                "performed an adversarial pass on this item (two-stage independence "
                "across review cycles and delegation)",
                detail={
                    "actor_id": ctx.actor_id,
                    "adversarial_pass_identities": sorted(pass_ids),
                },
            )


def _human_gate_builtin(ctx: Any) -> None:
    params = getattr(ctx, "validator_params", None) or {}
    raw = params.get("require_human", False)
    if not isinstance(raw, bool):
        raise ReviewRejected(
            f"human_gate: validator_params.require_human must be a boolean, "
            f"got {type(raw).__name__}",
            detail={"require_human": raw},
        )
    raw_same = params.get("require_human_on_same_lineage", False)
    if not isinstance(raw_same, bool):
        raise ReviewRejected(
            f"human_gate: validator_params.require_human_on_same_lineage "
            f"must be a boolean, got {type(raw_same).__name__}",
            detail={"require_human_on_same_lineage": raw_same},
        )
    human_gate(
        ctx,
        require_human=raw,
        require_human_on_same_lineage=raw_same,
    )


BUILTIN_REVIEW_VALIDATORS: dict[str, Callable[..., Any]] = {
    "adversarial_review": adversarial_review,
    "human_gate": _human_gate_builtin,
}
