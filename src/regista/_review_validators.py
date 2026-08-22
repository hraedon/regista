from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from ._lineage import (
    declared_model_lineage,
    event_has_v6_envelope,
    event_model_lineage,
    reject_obsolete_reviewer_claims,
    require_canonical_reviewer_lineage,
    require_v6_reviewer_model_lineage,
    reviewer_model_lineage,
)

_REVIEW_VERDICTS = frozenset({"accept", "request_changes", "adversarial_pass", "reject"})
_NON_AUTHOR_TRANSITIONS = _REVIEW_VERDICTS | {"comment"}

# WI-248: actor ids that authenticate as actor_kind="agent" but are genuine
# non-model service identities (plumbing, not a model behind them). Their
# authored events carry no model_lineage by design, so they must be excluded
# from the agent-author lineage check that drives the agent_author_undeclared
# gate — otherwise every item they touch forces --same-lineage-acknowledged
# on every reviewer. The id still lands in author_ids so separation-of-duties
# (a service may not review its own filing) is preserved.
#
# Keep this set minimal and deliberate: every entry must be a genuine non-model
# service identity. Adding a real model agent here would silently weaken the
# cross-lineage review invariant, so extend with care and document the reason.
# Note: actor_kind="system" events are recorded too, but with kind "system"
# rather than "agent"; since the gate keys off "agent" in author_kinds, a
# system author never satisfies it and is effectively excluded — so system
# identities need not be listed here.
_NON_MODEL_SERVICE_ACTORS: frozenset[str] = frozenset({"agent-notes"})


def declared_lineage(value: Any) -> str | None:
    """The declared lineage in ``value``, or None if it declares nothing.

    WI-258 follow-up: ``if value:`` only catches ``None`` and ``""``. A
    whitespace string (``"   "``) or a non-string (``42``) is truthy, so it used
    to be str()-ified into a lineage that compares DISTINCT against every real
    author lineage — a declared-and-independent verdict conjured out of a value
    that names no model. Neither ``actor_metadata.model_lineage`` nor
    ``on_behalf_of.principal_lineage`` is validated at the API boundary
    (``validate_delegation_chain`` checks only ``principal_id``), so these
    values arrive unfiltered. Strip before trusting, as ``resolve_model_lineage``
    and ``_require_review_note`` already do: what is empty after stripping
    declares nothing and must fail closed to UNKNOWN / undeclared.

    A non-string declares nothing either. The old ``str(value)`` coercion cut
    both ways — ``42`` became the lineage ``"42"`` (independent of every real
    lineage) while ``0`` stayed falsy and read as absent — so the type is now
    part of the contract: a declared lineage is a non-blank string, full stop.
    """
    return declared_model_lineage(value)


def normalized_kind(kind: Any) -> str | None:
    """An actor/principal kind folded to its canonical spelling.

    WI-258 follow-up: ``actor_kind`` is validated against a fixed set at the
    boundary, but ``on_behalf_of.principal_kind`` is not validated anywhere.
    An exact ``== "agent"`` test therefore read ``"Agent"`` or ``"agent "`` as
    definitively-not-a-model and skipped every agent-principal rule. Case and
    surrounding whitespace are spelling, not meaning. A non-string kind names
    no kind at all and reads as absent.
    """
    if not isinstance(kind, str):
        return None
    return kind.strip().lower() or None


# WI-262: how a delegation's declared principal_kind reads to the gate.
#
# ABSENT   — no principal_kind key (or an explicit null). The bare
#            {"principal_id": ...} separation-of-duties shape: it claims nothing
#            about the principal, predates any lineage claim, and is left alone.
# HUMAN    — the one kind that can vouch "this principal is not a model".
# AGENT    — a model principal; its lineage participates in every comparison.
# OPAQUE   — declared, but not something this gate can reason about: a kind it
#            does not recognise, or a blank/non-string value. It CANNOT vouch
#            that the principal is not a model, so it fails closed exactly like
#            an undeclared agent. Ingress validation now rejects these
#            (validate_delegation_chain), but events written before it existed
#            still carry them and must fail closed rather than crash.
KIND_ABSENT = "absent"
KIND_HUMAN = "human"
KIND_AGENT = "agent"
KIND_OPAQUE = "opaque"


def classify_principal_kind(delegation: Any) -> str:
    """Classify a delegation's principal_kind into one of the KIND_* verdicts.

    WI-262: the author side used to ask ``principal_kind == "agent"`` and treat
    everything else as a non-model, so ``principal_kind="ai-agent"`` with no
    lineage sailed past the undeclared-agent gate and an end-to-end probe
    reached ``independently_reviewed`` with no acknowledgment. Only "human" is
    a negative answer; everything else declared is at best unknown.
    """
    if not isinstance(delegation, dict):
        return KIND_ABSENT
    raw = delegation.get("principal_kind")
    if raw is None:
        return KIND_ABSENT
    kind = normalized_kind(raw)
    if kind == KIND_HUMAN:
        return KIND_HUMAN
    if kind == KIND_AGENT:
        return KIND_AGENT
    return KIND_OPAQUE


def _event_lineage(event: Any) -> str | None:
    return event_model_lineage(event)


def _is_post_epoch(ctx: Any) -> bool:
    """Whether this verdict is being written inside the project's clean v6 epoch.

    WI-307: the epoch is "``project_identity`` present" (``_events._v6_epoch_open``),
    which a validator cannot read directly — it holds no connection, only ``ctx``.
    The per-event proxy is the one the lineage layer already uses: a v6 envelope
    carries ``version == 6`` (``_lineage.raw_event_model_lineage`` /
    ``event_has_v6_envelope``). Because the genesis gate refuses to open an epoch
    over legacy history, a work item worked inside the epoch has an all-v6 prior
    history, so any v6 prior event proves the epoch is open. A wholly pre-epoch
    item (persisted legacy rows, no v6 envelope) reads as legacy and keeps the
    tolerant present-only reviewer-lineage check.
    """
    return any(event_has_v6_envelope(e) for e in getattr(ctx, "prior_events", ()))


def _is_v6_review_context(ctx: Any) -> bool:
    return _is_post_epoch(ctx) or getattr(ctx, "producer", None) is not None


def _add_delegated_principal(
    event: Any,
    author_ids: set[str],
    author_kinds: set[str],
    author_lineages: set[str],
) -> bool:
    """Record an event's ``on_behalf_of`` principal; True if it is undeclared.

    The two author branches (exempt service identity and ordinary actor) apply
    identical delegation rules, so they share one implementation — WI-257 was
    exactly the drift between two copies of it.

    The kind is recorded in its canonical spelling so the ``"agent" in
    author_kinds`` test the gate performs cannot be dodged by capitalisation.

    WI-262: the author side is now symmetric with the review side — any kind
    that is not "human" (an unrecognised one, a blank, a non-string) trips the
    flag when the principal declares no lineage. The earlier rationale for
    exempting them (that an unrecognised kind was indistinguishable from a
    "system" principal) was simply wrong: no ``principal_kind`` of "system"
    exists anywhere in the estate — the ``actor_kind="system"`` note above is a
    different field — so the exemption bought nothing and cost a fail-open on
    unvalidated, attacker-controlled metadata.
    """
    delegation = getattr(event, "on_behalf_of", None)
    if not isinstance(delegation, dict):
        return False
    principal_id = delegation.get("principal_id")
    if principal_id:
        author_ids.add(principal_id)
    kind_class = classify_principal_kind(delegation)
    principal_kind = normalized_kind(delegation.get("principal_kind"))
    if principal_kind:
        author_kinds.add(principal_kind)
    principal_lineage = declared_lineage(delegation.get("principal_lineage"))
    if principal_lineage:
        author_lineages.add(principal_lineage)
        return False
    return kind_class in (KIND_AGENT, KIND_OPAQUE)


def derive_authors(prior_events: Iterable[Any]) -> tuple[set[str], set[str], set[str], bool]:
    author_ids: set[str] = set()
    author_kinds: set[str] = set()
    author_lineages: set[str] = set()
    agent_author_undeclared = False
    for event in prior_events:
        if getattr(event, "transition", None) in _NON_AUTHOR_TRANSITIONS:
            continue
        author_ids.add(event.actor_id)
        lineage = _event_lineage(event)
        # WI-248: a genuine non-model service identity is not an agent author.
        # Record its id (separation-of-duties still applies) but, when it carries
        # no model_lineage, do not count its kind and do not trip the
        # undeclared-agent gate.
        #
        # The exemption is gated on the ABSENCE of a declared lineage: if an
        # event claims a service id but DOES carry a model_lineage, it falls
        # through to the declared-author path below so the lineage is surfaced.
        # This closes the forgery where a model agent claims the service id to
        # hide a real lineage from the cross-lineage gate. (A no-lineage
        # forgery is the same free-form-actor_id false-identity regista already
        # permits for any actor id — documented, not newly introduced here.)
        is_service_id = event.actor_id in _NON_MODEL_SERVICE_ACTORS
        if is_service_id and not lineage:
            # F2 / WI-257: a delegated agent principal that declares no lineage
            # is an undeclared agent author — flag it rather than laundering it
            # into "declared" via the service exemption.
            if _add_delegated_principal(
                event, author_ids, author_kinds, author_lineages
            ):
                agent_author_undeclared = True
            continue
        author_kinds.add(event.actor_kind)
        if lineage:
            author_lineages.add(lineage)
        elif event.actor_kind == "agent":
            agent_author_undeclared = True
        # WI-257: the same rule as the service branch above, and for the same
        # reason. WI-248 only hardened the exempt-service path, so an ORDINARY
        # declared proxy still laundered an undeclared delegated agent
        # principal into "declared": the proxy's own lineage landed in
        # author_lineages, the principal contributed the "agent" kind but no
        # lineage, and nothing recorded that a mind behind the delegation never
        # declared itself. A delegated agent principal without a declared
        # lineage is an undeclared agent author no matter who proxied for it
        # (agent, human, or service).
        if _add_delegated_principal(event, author_ids, author_kinds, author_lineages):
            agent_author_undeclared = True
    return author_ids, author_kinds, author_lineages, agent_author_undeclared


class ReviewRejected(ValueError):  # noqa: N818
    def __init__(self, reason: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


def _authorization_participants(ctx: Any) -> set[str]:
    """Principals the *candidate* event's own delegation chain names.

    This is the WI-008 authorization chain that authorized the transition being
    validated, as verified by the writer before the validator runs. It is a set of
    acting identities exactly as ``actor_id`` and ``on_behalf_of.principal_id`` are,
    which is why every independence gate has to compare against it and not only
    against them.
    """

    evidence = getattr(ctx, "authorization_evidence", None)
    if evidence is None or getattr(evidence, "status", None) != "verified":
        return set()
    return set(getattr(evidence, "participating_principals", frozenset()))


def _check_separation_of_duties(ctx: Any, author_ids: set[str], gate: str) -> None:
    author_ids.update(
        getattr(ctx, "prior_authorization_principals", frozenset())
    )
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
    participants = _authorization_participants(ctx)
    if participants:
        conflicts = participants & author_ids
        if conflicts:
            raise ReviewRejected(
                f"{gate}: an action-delegation participant is an author",
                detail={
                    "actor_id": ctx.actor_id,
                    "authorization_principals": sorted(participants),
                    "authors": sorted(author_ids),
                    "conflicts": sorted(conflicts),
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
    from ._assurance import LineageRelation, review_lineage_relation

    if _is_v6_review_context(ctx):
        reject_obsolete_reviewer_claims(getattr(ctx, "payload", None))
    else:
        require_canonical_reviewer_lineage(getattr(ctx, "payload", None))

    params = getattr(ctx, "validator_params", None) or {}
    finding_only = params.get("finding_only", False)
    if not isinstance(finding_only, bool):
        raise ReviewRejected(
            "adversarial_review: validator_params.finding_only must be a boolean, "
            f"got {type(finding_only).__name__}",
            detail={"finding_only": finding_only},
        )
    negative_finding_transition = (
        getattr(ctx, "current_state", None) == "in_review"
        and getattr(ctx, "new_state", None) == "in_progress"
        and getattr(ctx, "transition_name", None) == "request_changes"
    )
    if finding_only and not negative_finding_transition:
        raise ReviewRejected(
            "adversarial_review: validator_params.finding_only is valid only "
            "for request_changes from in_review to in_progress",
            detail={
                "transition": getattr(ctx, "transition_name", None),
                "current_state": getattr(ctx, "current_state", None),
                "new_state": getattr(ctx, "new_state", None),
            },
        )
    # WI-284: persisted canonical v1/v2 definitions predate finding_only.
    canonical_legacy_request_changes = (
        getattr(ctx, "workflow_name", None) == "canonical"
        and getattr(ctx, "workflow_version", None) in (1, 2)
        and negative_finding_transition
    )
    if finding_only or canonical_legacy_request_changes:
        _require_review_note(ctx, "adversarial_review")
        return

    author_ids, author_kinds, author_lineages, agent_author_undeclared = derive_authors(
        ctx.prior_events
    )

    _check_separation_of_duties(ctx, author_ids, "adversarial_review")
    _require_review_note(ctx, "adversarial_review")

    reviewer_lineage = (
        require_v6_reviewer_model_lineage(ctx)
        if _is_v6_review_context(ctx)
        else reviewer_model_lineage(ctx)
    )
    # WI-262: "is there an agent mind behind this review?" is not answered by
    # the proxy's actor_kind alone. A HUMAN proxy recording a pass on behalf of
    # an agent principal is an agent review with a human typing it, and the
    # acknowledgment policy has to follow the mind, not the keyboard.
    reviewer_kind_class = classify_principal_kind(getattr(ctx, "on_behalf_of", None))
    reviewer_is_agent = ctx.actor_kind == "agent" or reviewer_kind_class in (
        KIND_AGENT,
        KIND_OPAQUE,
    )
    # Likewise on the author side: an undeclared agent author IS an agent
    # author, even when the kind that produced the flag was an opaque one that
    # never put the literal string "agent" into author_kinds.
    agent_author = "agent" in author_kinds or agent_author_undeclared
    # WI-258: the reviewer's lineage is no longer read from the proxy actor
    # alone. When this review is recorded on behalf of an agent principal, that
    # principal's lineage must clear the distinctness bar too (and an
    # undeclared one is UNKNOWN, never independence) — otherwise a proxy
    # declaring a distinct lineage launders a same-lineage review.
    reviewer_relation = review_lineage_relation(author_lineages, ctx)
    distinct = reviewer_relation is LineageRelation.DISTINCT

    if reviewer_is_agent and agent_author and (
        not distinct or agent_author_undeclared
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
                    "lineage_relation": reviewer_relation.value,
                },
            )


def _last_adversarial_pass(prior_events: Iterable[Any]) -> Any | None:
    """The deciding adversarial pass event, or None if there is none.

    WI-258: callers need the whole event, not just its ``actor_metadata``
    lineage — the reviewer's effective lineage also depends on the event's
    ``on_behalf_of`` principal.
    """
    last_pass = None
    for event in prior_events:
        if getattr(event, "transition", None) == "adversarial_pass":
            last_pass = event
    return last_pass


def human_gate(
    ctx: Any,
    *,
    require_human: bool = False,
    require_human_on_same_lineage: bool = False,
) -> None:
    if _is_v6_review_context(ctx):
        reject_obsolete_reviewer_claims(getattr(ctx, "payload", None))
    else:
        require_canonical_reviewer_lineage(getattr(ctx, "payload", None))

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
        from ._assurance import (
            LineageRelation,
            effective_lineage_relation,
            review_lineage_relation,
        )

        # A pass may be absent (nothing reviewed yet) or present with an
        # undeclared lineage. Both yield a None reviewer lineage, but only the
        # latter is an escalation trigger: with no pass at all there is no
        # same-lineage review to catch. Distinguish via the pass's existence.
        last_pass = _last_adversarial_pass(ctx.prior_events)
        reviewer_lineage = reviewer_model_lineage(last_pass) if last_pass is not None else None
        (
            _author_ids,
            _author_kinds,
            author_lineages,
            agent_author_undeclared,
        ) = derive_authors(ctx.prior_events)
        # WI-239: an undeclared reviewer lineage is UNKNOWN, not independent.
        # For the human-gate escalation it must behave exactly like SAME —
        # unknown independence is never a reason to skip the human.
        # WI-258: the deciding pass's delegated agent principal counts toward
        # that verdict, not just the proxy that recorded it.
        # WI-256: and an undeclared agent author defeats distinctness outright.
        # This gate previously discarded the undeclared flag entirely, so a
        # mixed history (one declared lineage-A event plus an undeclared agent
        # event) read as DISTINCT and let a non-human accept through.
        relation = (
            LineageRelation.UNKNOWN
            if last_pass is None
            else effective_lineage_relation(
                review_lineage_relation(author_lineages, last_pass),
                agent_author_undeclared,
            )
        )
        needs_human = last_pass is not None and (
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
                    "agent_author_undeclared": agent_author_undeclared,
                },
            )

    _require_review_note(ctx, "human_gate")

    if getattr(ctx, "transition_name", None) == "accept":
        pass_ids = _adversarial_pass_identities(ctx.prior_events)
        pass_ids.update(
            getattr(
                ctx,
                "prior_adversarial_pass_authorization_principals",
                frozenset(),
            )
        )
        delegation = getattr(ctx, "on_behalf_of", None)
        acceptor_principal = (
            delegation.get("principal_id") if isinstance(delegation, dict) else None
        )
        # WI-008 round two: the accepting event's OWN authorization chain is an
        # acceptor identity too, and it was the one this gate never compared. Since
        # `on_behalf_of` cannot be written inside a v6 epoch at all
        # (``_event_store.py``'s refusal), a WI-008 credential is the only surviving
        # delegation vehicle — so comparing `actor_id` and `on_behalf_of` alone let one
        # principal issue the credential for the adversarial pass AND the credential
        # for the acceptance and still reach `done`, which is precisely the
        # two-stage independence this gate exists to enforce.
        acceptor_ids = {ctx.actor_id} | _authorization_participants(ctx)
        if acceptor_principal:
            acceptor_ids.add(acceptor_principal)
        conflicts = acceptor_ids & pass_ids
        if conflicts:
            raise ReviewRejected(
                "human_gate: the final accepter must differ from every actor who "
                "performed an adversarial pass on this item (two-stage independence "
                "across review cycles and delegation)",
                detail={
                    "actor_id": ctx.actor_id,
                    "adversarial_pass_identities": sorted(pass_ids),
                    "conflicting_identities": sorted(conflicts),
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
