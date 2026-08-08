from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from regista._assurance import (
    AssuranceLevel,
    GateProfile,
    LineageRelation,
    compute_assurance_level,
    compute_assurance_level_from_dicts,
    gate_permits_done,
    gate_rationale,
    lineage_relation,
    same_lineage,
)
from regista._errors import ErrorCode, RegistaError
from regista._review_validators import ReviewRejected, human_gate
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

REVIEW_NOTE = {"review_note": "looks good"}
ACK_NOTE = {"review_note": "same lineage ack", "same_lineage_acknowledged": True}
HUMAN_GATE_REQUIRED = "review requires a human acceptor under the strict gate profile"


def _evt(
    transition: str | None,
    actor_id: str,
    *,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    on_behalf_of: dict | None = None,
    payload: dict | None = None,
    scheme_id: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        transition=transition,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        on_behalf_of=on_behalf_of,
        payload=payload,
        scheme_id=scheme_id,
    )


def _author_events(lineage: str = "glm") -> list:
    return [
        _evt("created", "a1", actor_metadata={"model_lineage": lineage}),
        _evt("start", "a1", actor_metadata={"model_lineage": lineage}),
        _evt("submit_for_review", "a1", actor_metadata={"model_lineage": lineage}),
    ]


def _pass_events(reviewer: str, lineage: str) -> list:
    return [
        _evt(
            "adversarial_pass", reviewer,
            actor_metadata={"model_lineage": lineage},
            payload=REVIEW_NOTE,
        ),
    ]


def _accept_events(accepter: str, kind: str = "agent", lineage: str | None = None) -> list:
    meta = {"model_lineage": lineage} if lineage else None
    return [
        _evt(
            "accept", accepter,
            actor_kind=kind, actor_metadata=meta, payload=REVIEW_NOTE,
        ),
    ]


def _accept_ctx(
    prior_events: list,
    *,
    actor_id: str = "acceptor",
    actor_kind: str = "agent",
) -> SimpleNamespace:
    """A minimal ``accept`` validator ctx for the strict human gate."""
    return SimpleNamespace(
        prior_events=tuple(prior_events),
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=None,
        payload=REVIEW_NOTE,
        transition_name="accept",
        on_behalf_of=None,
        validator_params={},
    )


def _close_from_open() -> list:
    return [
        _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
        _evt("close_from_open", "a1", actor_metadata={"model_lineage": "glm"}),
    ]


class TestSameLineage:
    def test_matching_lineage(self):
        assert same_lineage({"glm"}, "glm") is True

    def test_non_matching_lineage(self):
        assert same_lineage({"glm"}, "kimi") is False

    def test_none_reviewer(self):
        assert same_lineage({"glm"}, None) is False

    def test_empty_reviewer(self):
        assert same_lineage({"glm"}, "") is False

    def test_empty_authors(self):
        assert same_lineage(set(), "glm") is False

    def test_multiple_authors_one_matches(self):
        assert same_lineage({"glm", "kimi"}, "glm") is True

    def test_multiple_authors_none_match(self):
        assert same_lineage({"glm", "kimi"}, "claude") is False


class TestLineageRelation:
    """WI-239: three-state distinctness — UNKNOWN must never be read as
    proven independence."""

    def test_same(self):
        assert lineage_relation({"glm"}, "glm") == LineageRelation.SAME

    def test_distinct(self):
        assert lineage_relation({"glm"}, "kimi") == LineageRelation.DISTINCT

    def test_undeclared_reviewer_is_unknown(self):
        assert lineage_relation({"glm"}, None) == LineageRelation.UNKNOWN
        assert lineage_relation({"glm"}, "") == LineageRelation.UNKNOWN

    def test_no_authors_is_unknown(self):
        assert lineage_relation(set(), "glm") == LineageRelation.UNKNOWN

    def test_no_authors_and_no_reviewer_is_unknown(self):
        assert lineage_relation(set(), None) == LineageRelation.UNKNOWN

    def test_same_lineage_boolean_only_true_for_same(self):
        assert same_lineage({"glm"}, "glm") is True
        assert same_lineage({"glm"}, "kimi") is False
        # UNKNOWN is still False in the boolean, but callers that escalate
        # must use lineage_relation and treat UNKNOWN like SAME.
        assert same_lineage({"glm"}, None) is False


class TestUndeclaredLineageEscalation:
    """WI-239: the composed exploit path — a reviewer with undeclared lineage
    passes adversarial_review via same_lineage_acknowledged, and the human
    gate must still escalate rather than read unknown independence as proven."""

    def test_undeclared_reviewer_never_reaches_independent_level(self):
        events = _author_events("glm") + _pass_events("r1", None)
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_gate_rationale_undeclared_reviewer_is_not_cross_lineage(self):
        events = _author_events("glm") + _pass_events("r1", None) + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reason"] != "cross_lineage_review"
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value


class TestUndeclaredAgentAuthorEscalation:
    """WI-256: ``derive_authors`` reports whether some (non-exempt) agent author
    declared no lineage, and every consumer used to DISCARD that flag and
    classify on the declared lineages alone. A mixed history — one declared
    lineage-A event plus one undeclared agent event — therefore read as
    DISTINCT against a lineage-B reviewer: the strict human gate let a non-human
    accept through and the assurance view claimed INDEPENDENTLY_REVIEWED.
    Distinctness from the lineages we happen to know is not distinctness from
    the authors, so an undeclared agent author now yields UNKNOWN."""

    def _mixed_authors(self) -> list:
        return [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            # One event with no actor_metadata at all — the accidental shape,
            # not just the adversarial one.
            _evt("start", "a2", actor_metadata=None),
            _evt("submit_for_review", "a1", actor_metadata={"model_lineage": "glm"}),
        ]

    def test_mixed_authors_never_reach_independent_level(self):
        events = self._mixed_authors() + _pass_events("r1", "kimi")
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_mixed_authors_agent_accept_is_not_independent(self):
        events = (
            self._mixed_authors() + _pass_events("r1", "kimi")
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_mixed_authors_human_accept_is_human_accepted(self):
        events = (
            self._mixed_authors() + _pass_events("r1", "kimi")
            + _accept_events("h1", "human")
        )
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED

    def test_gate_rationale_reports_unknown_and_surfaces_the_flag(self):
        events = (
            self._mixed_authors() + _pass_events("r1", "kimi")
            + _accept_events("acceptor", "agent")
        )
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reason"] != "cross_lineage_review"
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value
        assert r["agent_author_undeclared"] is True
        # The reviewer's own declared lineage is still reported honestly.
        assert r["reviewer_lineage"] == "kimi"
        assert gate_permits_done(r) is False

    def test_gate_rationale_relaxed_still_permits_done(self):
        # The relaxed profile is unchanged: it permits an acknowledged
        # same-lineage (or unknown) review to reach done.
        events = (
            self._mixed_authors() + _pass_events("r1", "kimi")
            + _accept_events("acceptor", "agent")
        )
        r = gate_rationale(events, GateProfile.RELAXED)
        assert r["reason"] == "same_lineage_acknowledged"
        assert gate_permits_done(r) is True

    def test_gate_rationale_without_pass_still_surfaces_the_flag(self):
        r = gate_rationale(self._mixed_authors(), GateProfile.STRICT)
        assert r["reason"] == "not_done"
        assert r["agent_author_undeclared"] is True

    def test_strict_human_gate_rejects_agent_accept(self):
        prior = self._mixed_authors() + _pass_events("r1", "kimi")
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_strict_human_gate_allows_human_accept(self):
        prior = self._mixed_authors() + _pass_events("r1", "kimi")
        ctx = _accept_ctx(prior, actor_id="h1", actor_kind="human")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_fully_declared_authors_still_independent(self):
        # The negative direction: when every agent author declared a lineage,
        # a cross-lineage review is still independent and still permits done.
        events = (
            _author_events("glm") + _pass_events("r1", "kimi")
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reason"] == "cross_lineage_review"
        assert r["agent_author_undeclared"] is False
        assert gate_permits_done(r) is True
        human_gate(
            _accept_ctx(_author_events("glm") + _pass_events("r1", "kimi")),
            require_human_on_same_lineage=True,
        )

    def test_service_identity_filing_stays_exempt(self):
        # WI-248 must not be re-broken: the agent-notes service identity files
        # without a model_lineage by design and is not an agent author, so the
        # item can still reach INDEPENDENTLY_REVIEWED on a cross-lineage pass.
        events = [
            _evt("created", "agent-notes", actor_kind="agent", actor_metadata=None),
            *_author_events("glm"),
            *_pass_events("r1", "kimi"),
            *_accept_events("acceptor", "agent"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["agent_author_undeclared"] is False
        assert r["reason"] == "cross_lineage_review"

    def test_undeclared_human_author_does_not_escalate(self):
        # A human author carries no model lineage and never did — only an
        # undeclared AGENT author defeats distinctness.
        events = [
            _evt("created", "h1", actor_kind="human", actor_metadata=None),
            *_author_events("glm"),
            *_pass_events("r1", "kimi"),
            *_accept_events("acceptor", "agent"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED


class TestReviewerDelegationLineageAssurance:
    """WI-258: the deciding adversarial pass's ``on_behalf_of`` principal was
    read nowhere lineage-wise, so a proxy declaring lineage B acting for a
    principal declaring lineage A scored A-authored work as independently
    reviewed. The delegated agent principal's lineage now participates."""

    def _pass(self, proxy_lineage: str | None, **delegation) -> list:
        meta = {"model_lineage": proxy_lineage} if proxy_lineage else None
        return [
            _evt(
                "adversarial_pass", "review-proxy",
                actor_metadata=meta,
                on_behalf_of=delegation or None,
                payload=REVIEW_NOTE,
            ),
        ]

    def test_delegated_same_lineage_is_not_independent(self):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="real-reviewer", principal_kind="agent",
                principal_lineage="glm",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.SAME.value
        assert r["reason"] != "cross_lineage_review"
        assert gate_permits_done(r) is False

    def test_delegated_undeclared_principal_is_unknown(self):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="real-reviewer", principal_kind="agent",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    def test_delegated_cross_lineage_still_independent(self):
        # Both identities behind the review are distinct from the authors.
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="real-reviewer", principal_kind="agent",
                principal_lineage="claude",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reason"] == "cross_lineage_review"
        assert gate_permits_done(r) is True

    def test_delegated_human_principal_unaffected(self):
        events = (
            _author_events("glm")
            + self._pass("kimi", principal_id="human:boss", principal_kind="human")
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_strict_human_gate_rejects_agent_accept_after_delegated_same_lineage(self):
        prior = _author_events("glm") + self._pass(
            "kimi", principal_id="real-reviewer", principal_kind="agent",
            principal_lineage="glm",
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_strict_human_gate_rejects_agent_accept_after_undeclared_principal(self):
        prior = _author_events("glm") + self._pass(
            "kimi", principal_id="real-reviewer", principal_kind="agent",
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_strict_human_gate_allows_agent_accept_after_delegated_cross_lineage(self):
        prior = _author_events("glm") + self._pass(
            "kimi", principal_id="real-reviewer", principal_kind="agent",
            principal_lineage="claude",
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_strict_human_gate_allows_human_accept(self):
        prior = _author_events("glm") + self._pass(
            "kimi", principal_id="real-reviewer", principal_kind="agent",
            principal_lineage="glm",
        )
        ctx = _accept_ctx(prior, actor_id="h1", actor_kind="human")
        human_gate(ctx, require_human_on_same_lineage=True)


class TestWhoMakesALineageClaim:
    """WI-262: which identities behind a review make a lineage claim, decided
    the same way ``derive_authors`` decides it for authors — a declared lineage
    always claims, an undeclared AGENT claims UNKNOWN, and a human claims
    nothing because a human has no model lineage to declare."""

    def _human_proxy_pass(self, **delegation) -> list:
        return [
            _evt(
                "adversarial_pass", "human-proxy", actor_kind="human",
                actor_metadata=None,
                on_behalf_of=delegation or None,
                payload=REVIEW_NOTE,
            ),
        ]

    def test_human_proxy_for_declared_distinct_principal_is_independent(self):
        # The one place this change reads LESS strictly than before: a human
        # recording a pass for a declared cross-lineage agent principal used to
        # score UNKNOWN, because the human's absent model_lineage was treated
        # as an undeclared model. It is not — the principal is the mind, it
        # declared itself, and it is distinct.
        events = (
            _author_events("glm")
            + self._human_proxy_pass(
                principal_id="real-reviewer", principal_kind="agent",
                principal_lineage="claude",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.DISTINCT.value

    def test_human_proxy_for_same_lineage_principal_is_not_independent(self):
        events = (
            _author_events("glm")
            + self._human_proxy_pass(
                principal_id="real-reviewer", principal_kind="agent",
                principal_lineage="glm",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.SAME.value

    def test_human_proxy_for_undeclared_principal_is_unknown(self):
        events = (
            _author_events("glm")
            + self._human_proxy_pass(
                principal_id="real-reviewer", principal_kind="agent",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_undelegated_human_reviewer_is_still_unknown(self):
        # Regression guard on the claims model: nobody claims, so the verdict
        # stays UNKNOWN exactly as it always has for a bare human review.
        events = (
            _author_events("glm") + self._human_proxy_pass()
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    def test_undeclared_agent_proxy_still_claims_unknown(self):
        # An AGENT proxy that declares nothing is an undeclared model, and its
        # claim survives even when the principal declared a distinct lineage.
        events = [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "agent-proxy", actor_kind="agent",
                actor_metadata=None,
                on_behalf_of={
                    "principal_id": "real-reviewer",
                    "principal_kind": "agent",
                    "principal_lineage": "claude",
                },
                payload=REVIEW_NOTE,
            ),
            *_accept_events("acceptor", "agent"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    def test_human_proxy_for_opaque_principal_is_unknown(self):
        events = (
            _author_events("glm")
            + self._human_proxy_pass(
                principal_id="real-reviewer", principal_kind="ai-agent",
                principal_lineage="claude",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    def test_strict_human_gate_follows_the_claims(self):
        prior = _author_events("glm") + self._human_proxy_pass(
            principal_id="real-reviewer", principal_kind="agent",
            principal_lineage="glm",
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)


class TestDegenerateLineageValues:
    """PR #31 review B1/B2: neither ``model_lineage`` nor the ``on_behalf_of``
    fields are validated at the API boundary, so the assurance view must not
    mistake a blank, non-string or mis-spelled value for a declared one."""

    def _pass(self, proxy_lineage, **delegation) -> list:
        return [
            _evt(
                "adversarial_pass", "review-proxy",
                actor_metadata={"model_lineage": proxy_lineage},
                on_behalf_of=delegation or None,
                payload=REVIEW_NOTE,
            ),
        ]

    @pytest.mark.parametrize("blank", ["   ", "", "\t"])
    def test_blank_principal_lineage_is_not_independent(self, blank):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="p", principal_kind="agent",
                principal_lineage=blank,
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value
        assert gate_permits_done(r) is False

    @pytest.mark.parametrize("value", [42, 0, ["glm"]])
    def test_non_string_principal_lineage_is_not_independent(self, value):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="p", principal_kind="agent",
                principal_lineage=value,
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    @pytest.mark.parametrize("kind", ["Agent", " AGENT "])
    def test_non_canonical_kind_still_compares_the_principal(self, kind):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="p", principal_kind=kind,
                principal_lineage="glm",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.SAME.value

    @pytest.mark.parametrize("kind", ["ai-agent", "  ", 42])
    def test_unrecognised_kind_is_unknown(self, kind):
        events = (
            _author_events("glm")
            + self._pass(
                "kimi", principal_id="p", principal_kind=kind,
                principal_lineage="claude",
            )
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    @pytest.mark.parametrize("blank", ["   ", ""])
    def test_blank_reviewer_lineage_is_unknown(self, blank):
        events = (
            _author_events("glm") + self._pass(blank)
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reviewer_lineage"] is None
        assert r["lineage_relation"] == LineageRelation.UNKNOWN.value

    def test_blank_author_lineage_is_an_undeclared_agent_author(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("start", "a2", actor_metadata={"model_lineage": "   "}),
            *_pass_events("r1", "kimi"),
            *_accept_events("acceptor", "agent"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["agent_author_undeclared"] is True
        assert r["author_lineages"] == ["glm"]

    def test_strict_human_gate_rejects_agent_accept_on_blank_principal(self):
        prior = _author_events("glm") + self._pass(
            "kimi", principal_id="p", principal_kind="agent",
            principal_lineage="   ",
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)


class TestHistoryShapeAndOrdering:
    """The whole event history decides, and only the LAST adversarial pass is
    the deciding one — worth pinning since every read site recomputes rather
    than caching."""

    def test_author_added_after_the_pass_still_counts(self):
        # Work recorded after the review is still authorship: an undeclared
        # agent author appended post-pass must pull the item back off
        # INDEPENDENTLY_REVIEWED rather than being ignored.
        events = (
            _author_events("glm") + _pass_events("r1", "kimi")
            + [_evt("start", "late-agent", actor_metadata=None)]
            + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["agent_author_undeclared"] is True
        assert gate_permits_done(r) is False

    def test_declared_author_added_after_the_pass_can_collide(self):
        events = (
            _author_events("glm") + _pass_events("r1", "kimi")
            + [_evt("start", "late-agent", actor_metadata={"model_lineage": "kimi"})]
            + _accept_events("acceptor", "agent")
        )
        # The reviewer's lineage now appears among the authors.
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["lineage_relation"] == LineageRelation.SAME.value

    def test_last_pass_decides_same_after_distinct(self):
        events = (
            _author_events("glm") + _pass_events("r1", "kimi")
            + _pass_events("r2", "glm") + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reviewer_lineage"] == "glm"

    def test_last_pass_decides_distinct_after_same(self):
        events = (
            _author_events("glm") + _pass_events("r1", "glm")
            + _pass_events("r2", "kimi") + _accept_events("acceptor", "agent")
        )
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reviewer_lineage"] == "kimi"
        assert gate_permits_done(r) is True

    def test_last_pass_decides_for_the_strict_human_gate(self):
        prior = _author_events("glm") + _pass_events("r1", "kimi") + _pass_events(
            "r2", "glm"
        )
        ctx = _accept_ctx(prior, actor_id="acceptor", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_delegated_accept_does_not_add_author_lineage(self):
        # `accept` is a review verdict, so neither the accepter nor its
        # principal is an author — a delegated accept cannot introduce a
        # lineage that would collide with the reviewer.
        events = (
            _author_events("glm") + _pass_events("r1", "kimi")
            + [
                _evt(
                    "accept", "accept-proxy",
                    actor_metadata={"model_lineage": "claude"},
                    on_behalf_of={
                        "principal_id": "boss-agent",
                        "principal_kind": "agent",
                        "principal_lineage": "kimi",
                    },
                    payload=REVIEW_NOTE,
                ),
            ]
        )
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["author_lineages"] == ["glm"]
        assert r["agent_author_undeclared"] is False
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_delegated_accept_by_human_is_still_human_accepted(self):
        events = (
            _author_events("glm") + _pass_events("r1", "glm")
            + [
                _evt(
                    "accept", "h1", actor_kind="human",
                    on_behalf_of={
                        "principal_id": "boss-agent",
                        "principal_kind": "agent",
                        "principal_lineage": "claude",
                    },
                    payload=REVIEW_NOTE,
                ),
            ]
        )
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED


class TestAssuranceLevel:
    def test_same_lineage_agent_accept(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("a1", "agent")
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_cross_lineage_agent_accept(self):
        events = _author_events("glm") + _pass_events("r1", "kimi") + _accept_events("a1", "agent")
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_same_lineage_human_accept(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("h1", "human")
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED

    def test_cross_lineage_human_accept(self):
        events = _author_events("glm") + _pass_events("r1", "kimi") + _accept_events("h1", "human")
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENT_AND_ACCEPTED

    def test_close_from_open(self):
        assert compute_assurance_level(_close_from_open()) == AssuranceLevel.NONE

    def test_no_accept_same_lineage(self):
        events = _author_events("glm") + _pass_events("r1", "glm")
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_no_accept_cross_lineage(self):
        events = _author_events("glm") + _pass_events("r1", "kimi")
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_no_adversarial_pass_in_progress(self):
        events = _author_events("glm")
        assert compute_assurance_level(events) == AssuranceLevel.NONE

    def test_empty_events(self):
        assert compute_assurance_level([]) == AssuranceLevel.NONE

    def test_undeclared_reviewer_lineage_escalates_like_same(self):
        # WI-239: an undeclared reviewer lineage is UNKNOWN, not independent —
        # it must not claim INDEPENDENTLY_REVIEWED.
        events = _author_events("glm") + _pass_events("r1", None) + _accept_events("a1", "agent")
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_undeclared_author_lineage_escalates_like_same(self):
        # WI-239: no author lineages means distinctness cannot be established.
        events = [
            _evt("created", "a1", actor_metadata=None),
            _evt("start", "a1", actor_metadata=None),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "glm"},
                payload=REVIEW_NOTE,
            ),
            _evt("accept", "a1", actor_kind="agent", payload=REVIEW_NOTE),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED

    def test_principal_lineage_from_on_behalf_of(self):
        events = [
            _evt(
                "created", "a1",
                actor_metadata={"model_lineage": "glm"},
                on_behalf_of={
                    "principal_id": "human:boss",
                    "principal_kind": "human",
                    "principal_lineage": "glm",
                },
            ),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "glm"},
                payload=REVIEW_NOTE,
            ),
            _evt("accept", "h1", actor_kind="human", payload=REVIEW_NOTE),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED

    def test_multiple_adversarial_passes_uses_last(self):
        events = [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            ),
            _evt(
                "request_changes", "r1",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            ),
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r2",
                actor_metadata={"model_lineage": "glm"},
                payload=ACK_NOTE,
            ),
            *_accept_events("h1", "human"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED

    def test_reopen_cycle_ignores_stale_accept(self):
        events = [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE,
            ),
            *_accept_events("h1", "human"),
            _evt("reopen", "a1", actor_metadata={"model_lineage": "glm"}),
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r2",
                actor_metadata={"model_lineage": "kimi"}, payload=REVIEW_NOTE,
            ),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_reopen_cycle_with_new_accept(self):
        events = [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE,
            ),
            *_accept_events("h1", "human"),
            _evt("reopen", "a1", actor_metadata={"model_lineage": "glm"}),
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r2",
                actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE,
            ),
            *_accept_events("h1", "human"),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.HUMAN_ACCEPTED

    def test_reopen_cycle_same_lineage_no_accept(self):
        events = [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE,
            ),
            *_accept_events("h1", "human"),
            _evt("reopen", "a1", actor_metadata={"model_lineage": "glm"}),
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r2",
                actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE,
            ),
        ]
        assert compute_assurance_level(events) == AssuranceLevel.SELF_REVIEWED


class TestComputeAssuranceLevelFromDicts:
    def _dict_events(self, scenario: str) -> list[dict]:
        base = [
            {"transition": "created", "actor_id": "a1", "actor_kind": "agent",
             "actor_metadata": {"model_lineage": "glm"}, "on_behalf_of": None, "payload": None},
            {"transition": "start", "actor_id": "a1", "actor_kind": "agent",
             "actor_metadata": {"model_lineage": "glm"}, "on_behalf_of": None, "payload": None},
            {"transition": "submit_for_review", "actor_id": "a1", "actor_kind": "agent",
             "actor_metadata": {"model_lineage": "glm"}, "on_behalf_of": None, "payload": None},
        ]
        if scenario == "close_from_open":
            base.append({
                "transition": "close_from_open",
                "actor_id": "a1",
                "actor_kind": "agent",
                "actor_metadata": {"model_lineage": "glm"},
                "on_behalf_of": None,
                "payload": None,
            })
            return base
        pass_lineage = "kimi" if scenario.startswith("cross") else "glm"
        base.append({"transition": "adversarial_pass", "actor_id": "r1", "actor_kind": "agent",
                     "actor_metadata": {"model_lineage": pass_lineage}, "on_behalf_of": None,
                     "payload": REVIEW_NOTE})
        if scenario.endswith("_no_accept"):
            return base
        accept_kind = "human" if "human" in scenario else "agent"
        base.append({"transition": "accept", "actor_id": "h1", "actor_kind": accept_kind,
                     "actor_metadata": None, "on_behalf_of": None, "payload": REVIEW_NOTE})
        return base

    def test_cross_lineage_agent_accept(self):
        level = compute_assurance_level_from_dicts(self._dict_events("cross_agent"))
        assert level == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_cross_lineage_human_accept(self):
        level = compute_assurance_level_from_dicts(self._dict_events("cross_human"))
        assert level == AssuranceLevel.INDEPENDENT_AND_ACCEPTED

    def test_same_lineage_human_accept(self):
        level = compute_assurance_level_from_dicts(self._dict_events("same_human"))
        assert level == AssuranceLevel.HUMAN_ACCEPTED

    def test_same_lineage_agent_accept(self):
        level = compute_assurance_level_from_dicts(self._dict_events("same_agent"))
        assert level == AssuranceLevel.SELF_REVIEWED

    def test_close_from_open(self):
        level = compute_assurance_level_from_dicts(self._dict_events("close_from_open"))
        assert level == AssuranceLevel.NONE

    def test_no_accept_cross_lineage(self):
        level = compute_assurance_level_from_dicts(self._dict_events("cross_no_accept"))
        assert level == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_no_accept_same_lineage(self):
        level = compute_assurance_level_from_dicts(self._dict_events("same_no_accept"))
        assert level == AssuranceLevel.SELF_REVIEWED


class TestGateRationale:
    def test_cross_lineage_review(self):
        events = _author_events("glm") + _pass_events("r1", "kimi") + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert r["reason"] == "cross_lineage_review"
        assert r["profile"] == "relaxed"
        assert r["reviewer_lineage"] == "kimi"
        assert r["author_lineages"] == ["glm"]
        assert r["assurance_level"] == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_human_accept_for_same_lineage(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("h1", "human")
        r = gate_rationale(events, GateProfile.STRICT)
        assert r["reason"] == "human_accept_for_same_lineage"
        assert r["profile"] == "strict"
        assert r["reviewer_lineage"] == "glm"

    def test_same_lineage_acknowledged(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert r["reason"] == "same_lineage_acknowledged"

    def test_close_from_open(self):
        r = gate_rationale(_close_from_open(), GateProfile.RELAXED)
        assert r["reason"] == "close_from_open"
        assert r["assurance_level"] == AssuranceLevel.NONE
        assert r["reviewer_lineage"] is None

    def test_not_done_no_pass(self):
        events = _author_events("glm")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert r["reason"] == "not_done"
        assert r["assurance_level"] == AssuranceLevel.NONE

    def test_not_done_with_pass(self):
        events = _author_events("glm") + _pass_events("r1", "kimi")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert r["reason"] == "not_done"
        assert r["assurance_level"] == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_gate_permits_done_relaxed_same_lineage_agent(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert gate_permits_done(r) is True

    def test_gate_permits_done_strict_same_lineage_agent(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.STRICT)
        assert gate_permits_done(r) is False

    def test_gate_permits_done_strict_same_lineage_human(self):
        events = _author_events("glm") + _pass_events("r1", "glm") + _accept_events("h1", "human")
        r = gate_rationale(events, GateProfile.STRICT)
        assert gate_permits_done(r) is True

    def test_gate_permits_done_strict_cross_lineage_agent(self):
        events = _author_events("glm") + _pass_events("r1", "kimi") + _accept_events("a1", "agent")
        r = gate_rationale(events, GateProfile.STRICT)
        assert gate_permits_done(r) is True

    def test_gate_permits_done_close_from_open(self):
        r = gate_rationale(_close_from_open(), GateProfile.STRICT)
        assert gate_permits_done(r) is True

    def test_gate_permits_done_not_done(self):
        events = _author_events("glm") + _pass_events("r1", "kimi")
        r = gate_rationale(events, GateProfile.RELAXED)
        assert gate_permits_done(r) is False

    def test_invalid_profile_string_raises_regista_error(self):
        events = _author_events("glm")
        with pytest.raises(RegistaError) as exc:
            gate_rationale(events, "unknown_profile")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "unknown_profile" in exc.value.message


class TestLineageVerification:
    """WI-215: gate_rationale surfaces whether the deciding review event's
    lineage is cryptographically bound (per-actor asymmetric signature) or
    merely asserted (HMAC/v4). The signal is informational and never changes a
    gate decision."""

    def _events_with_pass_scheme(self, scheme_id):
        return [
            *_author_events("glm"),
            _evt(
                "adversarial_pass", "r1",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
                scheme_id=scheme_id,
            ),
            *_accept_events("a1", "agent"),
        ]

    def test_asserted_for_hmac_deciding_pass(self):
        r = gate_rationale(self._events_with_pass_scheme("hmac-sha256"), GateProfile.RELAXED)
        assert r["lineage_verification"] == "asserted"

    def test_asserted_when_deciding_pass_has_no_scheme(self):
        r = gate_rationale(self._events_with_pass_scheme(None), GateProfile.RELAXED)
        assert r["lineage_verification"] == "asserted"

    def test_verified_for_ed25519_deciding_pass(self):
        r = gate_rationale(self._events_with_pass_scheme("ed25519"), GateProfile.RELAXED)
        assert r["lineage_verification"] == "verified"

    def test_unknown_scheme_is_asserted(self):
        r = gate_rationale(self._events_with_pass_scheme("mystery-scheme"), GateProfile.RELAXED)
        assert r["lineage_verification"] == "asserted"

    def test_none_without_adversarial_pass(self):
        r = gate_rationale(_author_events("glm"), GateProfile.RELAXED)
        assert r["lineage_verification"] is None

    def test_signal_does_not_change_gate_decision(self):
        hmac_r = gate_rationale(self._events_with_pass_scheme("hmac-sha256"), GateProfile.STRICT)
        ed_r = gate_rationale(self._events_with_pass_scheme("ed25519"), GateProfile.STRICT)
        # Same cross-lineage review; only the lineage_verification differs.
        assert hmac_r["reason"] == ed_r["reason"] == "cross_lineage_review"
        assert gate_permits_done(hmac_r) == gate_permits_done(ed_r) is True
        assert hmac_r["lineage_verification"] == "asserted"
        assert ed_r["lineage_verification"] == "verified"


class TestStrictGateProfile:
    def _ctx(
        self,
        prior_events: list,
        actor_id: str = "h1",
        actor_kind: str = "agent",
        transition_name: str = "accept",
        validator_params: dict | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            prior_events=tuple(prior_events),
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=None,
            payload=REVIEW_NOTE,
            transition_name=transition_name,
            on_behalf_of=None,
            validator_params=validator_params or {},
        )

    def test_same_lineage_agent_accept_rejected_under_strict(self):
        prior = _author_events("glm") + _pass_events("r1", "glm")
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_same_lineage_human_accept_passes_under_strict(self):
        prior = _author_events("glm") + _pass_events("r1", "glm")
        ctx = self._ctx(prior, actor_id="h1", actor_kind="human")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_cross_lineage_agent_accept_passes_under_strict(self):
        prior = _author_events("glm") + _pass_events("r1", "kimi")
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_cross_lineage_human_accept_passes_under_strict(self):
        prior = _author_events("glm") + _pass_events("r1", "kimi")
        ctx = self._ctx(prior, actor_id="h1", actor_kind="human")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_relaxed_allows_same_lineage_agent_accept(self):
        prior = _author_events("glm") + _pass_events("r1", "glm")
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        human_gate(ctx, require_human_on_same_lineage=False)

    def test_no_adversarial_pass_passes(self):
        prior = _author_events("glm")
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_undeclared_reviewer_lineage_agent_accept_rejected_under_strict(self):
        """WI-239: an undeclared reviewer lineage is UNKNOWN, and for the
        human-gate escalation it must behave exactly like SAME — a non-human
        accepter cannot skip the human on unknown independence."""
        prior = _author_events("glm") + _pass_events("r1", None)
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_undeclared_reviewer_lineage_human_accept_passes_under_strict(self):
        prior = _author_events("glm") + _pass_events("r1", None)
        ctx = self._ctx(prior, actor_id="h1", actor_kind="human")
        human_gate(ctx, require_human_on_same_lineage=True)

    def test_undeclared_author_lineage_agent_accept_rejected_under_strict(self):
        """No author lineages means distinctness cannot be established."""
        prior = [
            _evt("created", "a1", actor_metadata=None),
            _evt("start", "a1", actor_metadata=None),
            _evt("adversarial_pass", "r1", actor_metadata=None, payload=REVIEW_NOTE),
        ]
        ctx = self._ctx(prior, actor_id="a1", actor_kind="agent")
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            human_gate(ctx, require_human_on_same_lineage=True)

    def test_builtin_reads_param(self):
        from regista._review_validators import _human_gate_builtin

        prior = _author_events("glm") + _pass_events("r1", "glm")
        ctx = self._ctx(
            prior, actor_id="a1", actor_kind="agent",
            validator_params={"require_human": False, "require_human_on_same_lineage": True},
        )
        with pytest.raises(ReviewRejected, match=HUMAN_GATE_REQUIRED):
            _human_gate_builtin(ctx)

    def test_builtin_rejects_non_bool_param(self):
        from regista._review_validators import _human_gate_builtin

        prior = _author_events("glm") + _pass_events("r1", "glm")
        ctx = self._ctx(
            prior, actor_id="h1", actor_kind="human",
            validator_params={"require_human": False, "require_human_on_same_lineage": "yes"},
        )
        with pytest.raises(ReviewRejected, match="must be a boolean"):
            _human_gate_builtin(ctx)


CANONICAL_WORKFLOW = """\
name: canonical_test
version: 1
regista_version: "0.4.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: in_human_review
  - name: done
    terminal: true

transitions:
  - name: start
    from: open
    to: in_progress
    allowed_roles: [human, agent, system]
  - name: submit_for_review
    from: in_progress
    to: in_review
    allowed_roles: [human, agent, system]
  - name: adversarial_pass
    from: in_review
    to: in_human_review
    allowed_roles: [human, agent, system]
    validator: adversarial_review
  - name: accept
    from: in_human_review
    to: done
    allowed_roles: [human, agent, system]
    validator: human_gate
    validator_params:
      require_human: false
  - name: reject
    from: in_human_review
    to: in_progress
    allowed_roles: [human, agent, system]
    validator: human_gate
    validator_params:
      require_human: false
  - name: close_from_open
    from: open
    to: done
    allowed_roles: [human, agent, system]

roles:
  - name: human
  - name: agent
  - name: system

work_item_types:
  - name: issue
    custom_fields:
      - name: title
        type: string
        required: true
"""

STRICT_WORKFLOW = """\
name: canonical_strict
version: 1
regista_version: "0.4.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: in_human_review
  - name: done
    terminal: true

transitions:
  - name: start
    from: open
    to: in_progress
    allowed_roles: [human, agent, system]
  - name: submit_for_review
    from: in_progress
    to: in_review
    allowed_roles: [human, agent, system]
  - name: adversarial_pass
    from: in_review
    to: in_human_review
    allowed_roles: [human, agent, system]
    validator: adversarial_review
  - name: accept
    from: in_human_review
    to: done
    allowed_roles: [human, agent, system]
    validator: human_gate
    validator_params:
      require_human: false
      require_human_on_same_lineage: true
  - name: reject
    from: in_human_review
    to: in_progress
    allowed_roles: [human, agent, system]
    validator: human_gate
    validator_params:
      require_human: false
      require_human_on_same_lineage: true
  - name: close_from_open
    from: open
    to: done
    allowed_roles: [human, agent, system]

roles:
  - name: human
  - name: agent
  - name: system

work_item_types:
  - name: issue
    custom_fields:
      - name: title
        type: string
        required: true
"""


class TestComputeAssuranceAPI:
    def _meta(self, lineage: str, role: str = "agent") -> dict:
        return {"model_lineage": lineage, "role": role}

    def _setup_to_review(
        self,
        sub: InMemoryRegista,
        *,
        creator_lineage: str = "glm",
        workflow: str = "canonical_test",
    ) -> uuid.UUID:
        wi, _ = sub.create_work_item(
            workflow_name=workflow,
            work_item_type="issue",
            actor_id="a1",
            actor_kind="agent",
            actor_metadata=self._meta(creator_lineage),
            custom_fields={"title": "test"},
        )
        sub.transition(
            wi.work_item_id, "start", "a1",
            actor_kind="agent",
            actor_metadata=self._meta(creator_lineage),
        )
        sub.transition(
            wi.work_item_id, "submit_for_review", "a1",
            actor_kind="agent",
            actor_metadata=self._meta(creator_lineage),
        )
        return wi.work_item_id

    def _setup_to_human_review(
        self,
        sub: InMemoryRegista,
        *,
        creator_lineage: str = "glm",
        reviewer_lineage: str = "kimi",
        workflow: str = "canonical_test",
    ) -> uuid.UUID:
        wi_id = self._setup_to_review(
            sub, creator_lineage=creator_lineage, workflow=workflow,
        )
        pass_payload = (
            {"review_note": "same lineage ack", "same_lineage_acknowledged": True}
            if creator_lineage == reviewer_lineage
            else REVIEW_NOTE
        )
        sub.transition(
            wi_id, "adversarial_pass", "r1",
            actor_kind="agent",
            actor_metadata=self._meta(reviewer_lineage),
            payload=pass_payload,
        )
        return wi_id

    def test_assurance_at_creation(self):
        sub = InMemoryRegista(project="test_assurance_create", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi, _ = sub.create_work_item(
            workflow_name="canonical_test",
            work_item_type="issue",
            actor_id="a1",
            actor_kind="agent",
            actor_metadata=self._meta("glm"),
            custom_fields={"title": "test"},
        )
        assert sub.compute_assurance(wi.work_item_id) == AssuranceLevel.NONE

    def test_assurance_in_review(self):
        sub = InMemoryRegista(project="test_assurance_review", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_review(sub)
        assert sub.compute_assurance(wi_id) == AssuranceLevel.NONE

    def test_assurance_after_cross_lineage_pass(self):
        sub = InMemoryRegista(project="test_assurance_cross_pass", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="kimi")
        assert sub.compute_assurance(wi_id) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_assurance_after_same_lineage_pass(self):
        sub = InMemoryRegista(project="test_assurance_same_pass", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="glm")
        assert sub.compute_assurance(wi_id) == AssuranceLevel.SELF_REVIEWED

    def test_assurance_after_cross_lineage_agent_accept(self):
        sub = InMemoryRegista(project="test_assurance_cross_agent", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="kimi")
        sub.transition(
            wi_id, "accept", "a2",
            actor_kind="agent",
            actor_metadata=self._meta("kimi"),
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_assurance_after_cross_lineage_human_accept(self):
        sub = InMemoryRegista(project="test_assurance_cross_human", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="kimi")
        sub.transition(
            wi_id, "accept", "h1",
            actor_kind="human",
            actor_metadata={"role": "human"},
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.INDEPENDENT_AND_ACCEPTED

    def test_assurance_after_same_lineage_human_accept(self):
        sub = InMemoryRegista(project="test_assurance_same_human", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="glm")
        sub.transition(
            wi_id, "accept", "h1",
            actor_kind="human",
            actor_metadata={"role": "human"},
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.HUMAN_ACCEPTED

    def test_assurance_after_same_lineage_agent_accept(self):
        sub = InMemoryRegista(project="test_assurance_same_agent", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="glm")
        sub.transition(
            wi_id, "accept", "a2",
            actor_kind="agent",
            actor_metadata=self._meta("glm"),
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.SELF_REVIEWED

    def test_assurance_close_from_open(self):
        sub = InMemoryRegista(project="test_assurance_close", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi, _ = sub.create_work_item(
            workflow_name="canonical_test",
            work_item_type="issue",
            actor_id="a1",
            actor_kind="agent",
            actor_metadata=self._meta("glm"),
            custom_fields={"title": "test"},
        )
        sub.transition(
            wi.work_item_id, "close_from_open", "a1",
            actor_kind="agent",
            actor_metadata=self._meta("glm"),
        )
        assert sub.compute_assurance(wi.work_item_id) == AssuranceLevel.NONE

    def test_gate_rationale_via_api(self):
        sub = InMemoryRegista(project="test_assurance_rationale", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="kimi")
        r = sub.gate_rationale(wi_id, profile="relaxed")
        assert r["reason"] == "not_done"
        assert r["reviewer_lineage"] == "kimi"
        assert r["author_lineages"] == ["glm"]

    def test_gate_rationale_strict_profile(self):
        sub = InMemoryRegista(project="test_assurance_strict_rat", hmac_key_path=KEY_PATH)
        sub.register_workflow(CANONICAL_WORKFLOW)
        wi_id = self._setup_to_human_review(sub, reviewer_lineage="glm")
        sub.transition(
            wi_id, "accept", "a2",
            actor_kind="agent",
            actor_metadata=self._meta("glm"),
            payload=REVIEW_NOTE,
        )
        r = sub.gate_rationale(wi_id, profile="strict")
        assert r["reason"] == "same_lineage_acknowledged"
        assert gate_permits_done(r) is False

    def test_strict_workflow_rejects_same_lineage_agent_accept(self):
        sub = InMemoryRegista(project="test_assurance_strict_wf", hmac_key_path=KEY_PATH)
        sub.register_workflow(STRICT_WORKFLOW)
        wi_id = self._setup_to_human_review(
            sub, reviewer_lineage="glm", workflow="canonical_strict",
        )
        with pytest.raises(Exception, match=HUMAN_GATE_REQUIRED):
            sub.transition(
                wi_id, "accept", "a2",
                actor_kind="agent",
                actor_metadata=self._meta("glm"),
                payload=REVIEW_NOTE,
            )

    def test_strict_workflow_allows_cross_lineage_agent_accept(self):
        sub = InMemoryRegista(project="test_assurance_strict_cross", hmac_key_path=KEY_PATH)
        sub.register_workflow(STRICT_WORKFLOW)
        wi_id = self._setup_to_human_review(
            sub, reviewer_lineage="kimi", workflow="canonical_strict",
        )
        sub.transition(
            wi_id, "accept", "a2",
            actor_kind="agent",
            actor_metadata=self._meta("kimi"),
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_strict_workflow_allows_same_lineage_human_accept(self):
        sub = InMemoryRegista(project="test_assurance_strict_human", hmac_key_path=KEY_PATH)
        sub.register_workflow(STRICT_WORKFLOW)
        wi_id = self._setup_to_human_review(
            sub, reviewer_lineage="glm", workflow="canonical_strict",
        )
        sub.transition(
            wi_id, "accept", "h1",
            actor_kind="human",
            actor_metadata={"role": "human"},
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.HUMAN_ACCEPTED

    def test_strict_workflow_rejects_undeclared_reviewer_agent_accept(self):
        """WI-239 composed exploit: an undeclared-lineage reviewer passes
        adversarial_review via same_lineage_acknowledged, then a non-human
        accept must STILL be rejected under the strict profile — unknown
        independence is never a reason to skip the human gate."""
        sub = InMemoryRegista(project="test_assurance_undeclared_strict", hmac_key_path=KEY_PATH)
        sub.register_workflow(STRICT_WORKFLOW)
        wi_id = self._setup_to_review(sub, workflow="canonical_strict")
        # Reviewer declares NO lineage but acknowledges same-lineage.
        sub.transition(
            wi_id, "adversarial_pass", "r1",
            actor_kind="agent",
            actor_metadata={"role": "agent"},
            payload=ACK_NOTE,
        )
        with pytest.raises(Exception, match=HUMAN_GATE_REQUIRED):
            sub.transition(
                wi_id, "accept", "a2",
                actor_kind="agent",
                actor_metadata={"role": "agent"},
                payload=REVIEW_NOTE,
            )

    def test_strict_workflow_allows_undeclared_reviewer_human_accept(self):
        sub = InMemoryRegista(project="test_assurance_undeclared_human", hmac_key_path=KEY_PATH)
        sub.register_workflow(STRICT_WORKFLOW)
        wi_id = self._setup_to_review(sub, workflow="canonical_strict")
        sub.transition(
            wi_id, "adversarial_pass", "r1",
            actor_kind="agent",
            actor_metadata={"role": "agent"},
            payload=ACK_NOTE,
        )
        sub.transition(
            wi_id, "accept", "h1",
            actor_kind="human",
            actor_metadata={"role": "human"},
            payload=REVIEW_NOTE,
        )
        assert sub.compute_assurance(wi_id) == AssuranceLevel.HUMAN_ACCEPTED


class TestCanonicalWorkflowStrictVariant:
    def test_strict_adds_require_human_on_same_lineage(self):
        from regista import canonical_workflow_yaml

        relaxed = canonical_workflow_yaml()
        strict = canonical_workflow_yaml(strict=True)

        assert "require_human_on_same_lineage" not in relaxed
        assert "require_human_on_same_lineage: true" in strict
        assert strict.count("require_human_on_same_lineage: true") == 2

    def test_strict_preserves_other_content(self):
        from regista import canonical_workflow_yaml

        relaxed = canonical_workflow_yaml()
        strict = canonical_workflow_yaml(strict=True)

        for line in relaxed.splitlines():
            if "require_human_on_same_lineage" not in line:
                assert line in strict or line.strip() == ""

    def test_relaxed_is_unchanged(self):
        from regista import canonical_workflow_yaml
        from regista._workflow import _CANONICAL_WORKFLOW_PATH

        raw = _CANONICAL_WORKFLOW_PATH.read_text(encoding="utf-8")
        assert canonical_workflow_yaml() == raw
        assert canonical_workflow_yaml(strict=False) == raw

    def test_strict_yaml_validates(self):
        from regista import canonical_workflow_yaml, validate_yaml

        result = validate_yaml(canonical_workflow_yaml(strict=True))
        assert result.valid, [e.message for e in result.errors]
