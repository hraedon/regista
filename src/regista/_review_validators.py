from __future__ import annotations

from collections.abc import Callable, Iterable

_REVIEW_VERDICTS = frozenset({"accept", "request_changes", "adversarial_pass", "reject"})
_NON_AUTHOR_TRANSITIONS = _REVIEW_VERDICTS | {"comment"}


def _event_lineage(event) -> str | None:
    meta = getattr(event, "actor_metadata", None)
    if isinstance(meta, dict):
        lineage = meta.get("model_lineage")
        if lineage:
            return str(lineage)
    return None


def derive_authors(prior_events: Iterable) -> tuple[set[str], set[str], set[str], bool]:
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
    def __init__(self, reason: str, detail: dict | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


def _check_separation_of_duties(ctx, author_ids: set[str], gate: str) -> None:
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


def _require_review_note(ctx, gate: str) -> None:
    note = (getattr(ctx, "payload", None) or {}).get("review_note")
    if not note or not str(note).strip():
        raise ReviewRejected(
            f"{gate}: a non-empty review note is required for every review verdict",
            detail={"transition": getattr(ctx, "transition_name", None)},
        )


def _adversarial_pass_identities(prior_events) -> set[str]:
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


def adversarial_review(ctx) -> None:
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


def human_gate(ctx, *, require_human: bool = False) -> None:
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


def _human_gate_builtin(ctx) -> None:
    params = getattr(ctx, "validator_params", None) or {}
    raw = params.get("require_human", False)
    if not isinstance(raw, bool):
        raise ReviewRejected(
            f"human_gate: validator_params.require_human must be a boolean, "
            f"got {type(raw).__name__}",
            detail={"require_human": raw},
        )
    human_gate(ctx, require_human=raw)


BUILTIN_REVIEW_VALIDATORS: dict[str, Callable] = {
    "adversarial_review": adversarial_review,
    "human_gate": _human_gate_builtin,
}
