from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._review_validators import (
    BUILTIN_REVIEW_VALIDATORS,
    ReviewRejected,
    adversarial_review,
    derive_authors,
    human_gate,
)
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

REVIEW_NOTE = {"review_note": "looks good"}
ACK_NOTE = {"review_note": "same lineage ack", "same_lineage_acknowledged": True}


def _evt(
    transition: str | None,
    actor_id: str,
    *,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    on_behalf_of: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        transition=transition,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        on_behalf_of=on_behalf_of,
    )


def _ctx(
    prior_events: list,
    actor_id: str,
    *,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    payload: dict | None = None,
    transition_name: str = "adversarial_pass",
    on_behalf_of: dict | None = None,
    validator_params: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        prior_events=tuple(prior_events),
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        payload=payload,
        transition_name=transition_name,
        on_behalf_of=on_behalf_of,
        validator_params=validator_params,
    )


RELAXED_WORKFLOW = """\
name: review_relaxed
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
  - name: submit_for_review
    from: in_progress
    to: in_review
  - name: adversarial_pass
    from: in_review
    to: in_human_review
    validator: adversarial_review
  - name: request_changes
    from: in_review
    to: in_progress
    validator: adversarial_review
  - name: accept
    from: in_human_review
    to: done
    validator: human_gate
  - name: reject
    from: in_human_review
    to: in_progress
    validator: human_gate

roles: []

work_item_types:
  - name: issue
    custom_fields: []
"""

STRICT_WORKFLOW = """\
name: review_strict
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
  - name: submit_for_review
    from: in_progress
    to: in_review
  - name: adversarial_pass
    from: in_review
    to: in_human_review
    validator: adversarial_review
  - name: request_changes
    from: in_review
    to: in_progress
    validator: adversarial_review
  - name: accept
    from: in_human_review
    to: done
    validator: human_gate
    validator_params:
      require_human: true
  - name: reject
    from: in_human_review
    to: in_progress
    validator: human_gate

roles: []

work_item_types:
  - name: issue
    custom_fields: []
"""


def _relaxed_sub() -> InMemoryRegista:
    sub = InMemoryRegista(project="test_plan023_relaxed", hmac_key_path=KEY_PATH)
    sub.register_workflow(RELAXED_WORKFLOW)
    return sub


def _strict_sub() -> InMemoryRegista:
    sub = InMemoryRegista(project="test_plan023_strict", hmac_key_path=KEY_PATH)
    sub.register_workflow(STRICT_WORKFLOW)
    return sub


def _setup_to_review(
    sub: InMemoryRegista,
    *,
    creator: str = "glm-agent",
    creator_lineage: str = "glm",
    workflow: str = "review_relaxed",
) -> uuid.UUID:
    wi, _ = sub.create_work_item(
        workflow_name=workflow,
        work_item_type="issue",
        actor_id=creator,
        actor_kind="agent",
        actor_metadata={"model_lineage": creator_lineage},
    )
    sub.transition(
        wi.work_item_id, "start", creator,
        actor_kind="agent",
        actor_metadata={"model_lineage": creator_lineage},
    )
    sub.transition(
        wi.work_item_id, "submit_for_review", creator,
        actor_kind="agent",
        actor_metadata={"model_lineage": creator_lineage},
    )
    return wi.work_item_id


def _setup_to_human_review(
    sub: InMemoryRegista,
    *,
    creator: str = "glm-agent",
    creator_lineage: str = "glm",
    reviewer: str = "kimi-agent",
    reviewer_lineage: str = "kimi",
    workflow: str = "review_relaxed",
) -> uuid.UUID:
    wi_id = _setup_to_review(
        sub,
        creator=creator,
        creator_lineage=creator_lineage,
        workflow=workflow,
    )
    sub.transition(
        wi_id, "adversarial_pass", reviewer,
        actor_kind="agent",
        actor_metadata={"model_lineage": reviewer_lineage},
        payload=REVIEW_NOTE,
    )
    return wi_id


class TestDeriveAuthors:
    def test_excludes_review_verdicts(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
            _evt("accept", "h1", actor_kind="human"),
            _evt("request_changes", "r2", actor_metadata={"model_lineage": "kimi"}),
            _evt("reject", "h2", actor_kind="human"),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert ids == {"a1"}
        assert kinds == {"agent"}
        assert lineages == {"glm"}
        assert undeclared is False

    def test_excludes_comments(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("comment", "c1", actor_kind="human"),
        ]
        ids, _, _, _ = derive_authors(events)
        assert ids == {"a1"}

    def test_agent_kinds_and_lineages(self):
        events = [
            _evt("created", "a1", actor_kind="agent", actor_metadata={"model_lineage": "glm"}),
            _evt("start", "a2", actor_kind="agent", actor_metadata={"model_lineage": "kimi"}),
            _evt("submit", "h1", actor_kind="human"),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert ids == {"a1", "a2", "h1"}
        assert kinds == {"agent", "human"}
        assert lineages == {"glm", "kimi"}
        assert undeclared is False

    def test_undeclared_agent_lineage(self):
        events = [
            _evt("created", "a1", actor_kind="agent", actor_metadata=None),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert ids == {"a1"}
        assert kinds == {"agent"}
        assert lineages == set()
        assert undeclared is True

    def test_on_behalf_of_principal_inclusion(self):
        events = [
            _evt("created", "a1", actor_kind="agent", actor_metadata={"model_lineage": "glm"},
                 on_behalf_of={"principal_id": "human:boss", "principal_kind": "human"}),
        ]
        ids, kinds, _lineages, _ = derive_authors(events)
        assert "a1" in ids
        assert "human:boss" in ids
        assert "human" in kinds

    def test_principal_lineage_defensive_read(self):
        events = [
            _evt("created", "a1", actor_kind="agent", actor_metadata={"model_lineage": "glm"},
                 on_behalf_of={
                     "principal_id": "human:boss",
                     "principal_kind": "human",
                     "principal_lineage": "claude-opus",
                 }),
        ]
        _, _, lineages, _ = derive_authors(events)
        assert "claude-opus" in lineages


class TestAdversarialReview:
    def test_same_lineage_no_ack_rejected(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "glm"}, payload=REVIEW_NOTE)
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_same_lineage_with_ack_passes(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "glm"}, payload=ACK_NOTE)
        adversarial_review(ctx)

    def test_undeclared_reviewer_lineage_fail_closed(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata=None, payload=REVIEW_NOTE)
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_undeclared_reviewer_lineage_ack_passes(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata=None, payload=ACK_NOTE)
        adversarial_review(ctx)

    def test_undeclared_author_lineage_fail_closed(self):
        events = [_evt("created", "a1", actor_kind="agent", actor_metadata=None)]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "glm"}, payload=REVIEW_NOTE)
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_cross_lineage_agent_passes(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "kimi"}, payload=REVIEW_NOTE)
        adversarial_review(ctx)

    def test_human_reviewer_of_agent_work_passes(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "h1", actor_kind="human", actor_metadata=None, payload=REVIEW_NOTE)
        adversarial_review(ctx)

    def test_review_note_required(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "kimi"}, payload={})
        with pytest.raises(ReviewRejected, match="review note is required"):
            adversarial_review(ctx)

    def test_review_note_missing_entirely(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "kimi"}, payload=None)
        with pytest.raises(ReviewRejected, match="review note is required"):
            adversarial_review(ctx)

    def test_ack_must_be_exact_true(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        for bad_val in ["yes", 1, "true", {"flag": True}]:
            payload = {"review_note": "ack", "same_lineage_acknowledged": bad_val}
            ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "glm"}, payload=payload)
            with pytest.raises(ReviewRejected, match="not confirmed distinct"):
                adversarial_review(ctx)

    def test_agent_reviewer_of_all_human_authors_no_ack(self):
        events = [_evt("created", "h1", actor_kind="human")]
        ctx = _ctx(events, "r1", actor_metadata={"model_lineage": "glm"}, payload=REVIEW_NOTE)
        adversarial_review(ctx)

    def test_actor_metadata_none_passes_for_human(self):
        events = [_evt("created", "h1", actor_kind="human")]
        ctx = _ctx(events, "h2", actor_kind="human", actor_metadata=None, payload=REVIEW_NOTE)
        adversarial_review(ctx)

    def test_direct_self_review_rejected(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(events, "a1", actor_metadata={"model_lineage": "glm"}, payload=REVIEW_NOTE)
        with pytest.raises(ReviewRejected, match="self-review is not allowed"):
            adversarial_review(ctx)

    def test_delegation_self_review_rejected(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            events, "a2",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            on_behalf_of={"principal_id": "a1"},
        )
        with pytest.raises(ReviewRejected, match="delegated self-review"):
            adversarial_review(ctx)

    def test_whitespace_review_note_rejected(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            events, "r1",
            actor_metadata={"model_lineage": "kimi"},
            payload={"review_note": "   "},
        )
        with pytest.raises(ReviewRejected, match="review note is required"):
            adversarial_review(ctx)


class TestReviewerDelegationLineage:
    """WI-258: reviewer lineage used to be read from the proxy actor's
    metadata alone, so a proxy declaring lineage B acting on behalf of a
    principal declaring lineage A reviewed A-authored work as "cross-lineage".
    The delegated agent principal is the mind doing the review, so its lineage
    must clear the distinctness bar too; an undeclared one is UNKNOWN and fails
    closed (WI-239). A human principal keeps the previous behaviour."""

    def _authors(self, lineage: str = "glm") -> list:
        return [
            _evt("created", "a1", actor_metadata={"model_lineage": lineage}),
            _evt("submit_for_review", "a1", actor_metadata={"model_lineage": lineage}),
        ]

    def test_delegated_principal_same_lineage_blocked_without_ack(self):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "glm",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_delegated_principal_same_lineage_with_ack_passes(self):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "glm",
            },
            payload=ACK_NOTE,
        )
        adversarial_review(ctx)

    def test_delegated_principal_cross_lineage_passes_without_ack(self):
        # Both proxy and principal are distinct from the authors: a genuinely
        # independent delegated review still needs no acknowledgment.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_undeclared_delegated_principal_blocked(self):
        # An agent principal that declares no lineage is UNKNOWN, never
        # independence — the proxy's declared lineage does not stand in for it.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_same_lineage_proxy_blocked_despite_distinct_principal(self):
        # The verdict is the weakest of the two: a collision on either side is
        # a same-lineage review.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "glm"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_undeclared_proxy_with_distinct_principal_blocked(self):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata=None,
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_human_principal_unaffected(self):
        # A human principal is not a model lineage: the proxy's own distinct
        # lineage is the whole verdict, exactly as before WI-258.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={"principal_id": "human:boss", "principal_kind": "human"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_delegation_without_principal_kind_unaffected(self):
        # The bare {principal_id} delegation shape used by the separation-of-
        # duties tests declares no principal kind; it must not start failing.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={"principal_id": "some-operator"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_rejection_detail_reports_the_effective_relation(self):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "glm",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected) as exc_info:
            adversarial_review(ctx)
        # The proxy's own lineage still reads distinct; the recorded relation
        # is the effective one, so the detail cannot be read as "independent".
        assert exc_info.value.detail["reviewer_lineage"] == "kimi"
        assert exc_info.value.detail["lineage_relation"] == "same"

    @pytest.mark.parametrize("blank", ["   ", "", "\t\n"])
    def test_blank_principal_lineage_blocked(self, blank):
        # PR #31 review B1: a blank principal_lineage is truthy, so it used to
        # be compared as a lineage distinct from every real one — a declared
        # and independent verdict conjured from a value naming no model.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": blank,
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    @pytest.mark.parametrize("value", [42, 0, True, ["glm"]])
    def test_non_string_principal_lineage_blocked(self, value):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": value,
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    @pytest.mark.parametrize("kind", ["Agent", "AGENT", " agent "])
    def test_non_canonical_agent_kind_still_compared(self, kind):
        # PR #31 review B2: a mis-spelled kind used to skip the principal
        # entirely, so a colliding principal_lineage passed as DISTINCT.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": kind,
                "principal_lineage": "glm",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_non_canonical_agent_kind_does_not_over_block(self):
        # Normalisation must not turn a genuinely independent delegated review
        # into a blocked one.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "Agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    @pytest.mark.parametrize("kind", ["ai-agent", "model", "  ", 42])
    def test_unrecognised_principal_kind_is_unknown(self, kind):
        # An unrecognised kind cannot establish "this principal is not a
        # model", which is the only reason ignoring it would be safe — so on
        # the review side it fails closed to UNKNOWN.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": kind,
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_non_canonical_human_kind_unaffected(self):
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "kimi"},
            on_behalf_of={"principal_id": "human:boss", "principal_kind": "Human"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    @pytest.mark.parametrize("blank", ["   ", ""])
    def test_blank_proxy_lineage_blocked(self, blank):
        # The same laxness on the reviewer's own metadata: a blank
        # model_lineage is an undeclared reviewer, not a distinct one.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": blank},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_collision_reported_as_same_even_when_principal_undeclared(self):
        # The proxy already collides with the authors; an undeclared principal
        # on top of that must not blur the more precise SAME verdict.
        ctx = _ctx(
            self._authors(), "review-proxy",
            actor_metadata={"model_lineage": "glm"},
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected) as exc_info:
            adversarial_review(ctx)
        assert exc_info.value.detail["lineage_relation"] == "same"

    def test_human_proxy_for_same_lineage_agent_principal_blocked(self):
        # WI-262 (Sol R2, non-blocking): enforcement used to check only the
        # proxy's actor_kind, so a HUMAN typing a pass on behalf of a
        # same-lineage AGENT principal skipped the acknowledgment. The
        # acknowledgment policy follows the mind behind the review, not the
        # keyboard in front of it.
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            actor_metadata=None,
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "glm",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_human_proxy_for_same_lineage_agent_principal_passes_with_ack(self):
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "glm",
            },
            payload=ACK_NOTE,
        )
        adversarial_review(ctx)

    def test_human_proxy_for_undeclared_agent_principal_blocked(self):
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_human_proxy_for_opaque_principal_blocked(self):
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "ai-agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_human_proxy_for_distinct_agent_principal_passes(self):
        # Following the mind must not over-block: a genuinely cross-lineage
        # delegated review still needs no acknowledgment.
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={
                "principal_id": "real-reviewer",
                "principal_kind": "agent",
                "principal_lineage": "claude-opus",
            },
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_human_proxy_for_human_principal_unaffected(self):
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={"principal_id": "human:boss", "principal_kind": "human"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_human_proxy_with_bare_delegation_unaffected(self):
        # No principal_kind claimed at all: the separation-of-duties shape,
        # which asserts nothing about a mind behind the review.
        ctx = _ctx(
            self._authors(), "human-proxy", actor_kind="human",
            on_behalf_of={"principal_id": "some-operator"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_undelegated_human_reviewer_unaffected(self):
        ctx = _ctx(
            self._authors(), "h1", actor_kind="human", payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

    def test_end_to_end_delegated_same_lineage_review_blocked(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "adversarial_pass", "review-proxy",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "kimi"},
                    payload=REVIEW_NOTE,
                    on_behalf_of={
                        "principal_id": "glm-sibling",
                        "principal_kind": "agent",
                        "principal_lineage": "glm",
                    },
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "not confirmed distinct" in cause.reason
            assert sub.get_work_item(wi_id).current_state == "in_review"
        finally:
            sub.close()


class TestHumanGateStrict:
    def test_rejects_agent_actor(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            events, "r1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="requires a human actor"):
            human_gate(ctx, require_human=True)

    def test_human_not_author_passes(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"},
                 on_behalf_of=None),
        ]
        ctx = _ctx(
            events, "h1",
            actor_kind="human",
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        human_gate(ctx, require_human=True)

    def test_human_author_rejected(self):
        events = [_evt("created", "h1", actor_kind="human")]
        ctx = _ctx(
            events, "h1",
            actor_kind="human",
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="self-review is not allowed"):
            human_gate(ctx, require_human=True)

    def test_review_note_required(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "h1",
            actor_kind="human",
            payload={},
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="review note is required"):
            human_gate(ctx, require_human=True)

    def test_rejects_accepter_equal_to_adversarial_passer(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "r1",
            actor_kind="human",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="two-stage independence"):
            human_gate(ctx, require_human=True)

    def test_delegated_self_review_rejected(self):
        events = [_evt("created", "h1", actor_kind="human")]
        ctx = _ctx(
            events, "h2",
            actor_kind="human",
            payload=REVIEW_NOTE,
            transition_name="accept",
            on_behalf_of={"principal_id": "h1"},
        )
        with pytest.raises(ReviewRejected, match="delegated self-review"):
            human_gate(ctx, require_human=True)

    def test_reject_transition_no_two_stage_check(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "r1",
            actor_kind="human",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="reject",
        )
        human_gate(ctx, require_human=True)

    def test_reject_in_strict_mode_rejects_agent(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "r2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="reject",
        )
        with pytest.raises(ReviewRejected, match="requires a human actor"):
            human_gate(ctx, require_human=True)


class TestHumanGateRelaxed:
    def test_agent_accept_passes_after_cross_lineage_pass(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        human_gate(ctx, require_human=False)

    def test_author_self_close_passes_after_cross_lineage_pass(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "glm"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        human_gate(ctx, require_human=False)

    def test_review_note_required(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "glm"},
            payload={},
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="review note is required"):
            human_gate(ctx, require_human=False)

    def test_two_stage_independence_adversarial_passer_cannot_accept(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "r1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="two-stage independence"):
            human_gate(ctx, require_human=False)

    def test_delegation_aware_two_stage_independence(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
            on_behalf_of={"principal_id": "r1"},
        )
        with pytest.raises(ReviewRejected, match="two-stage independence"):
            human_gate(ctx, require_human=False)


class TestHumanGateDirectParameter:
    def test_require_human_true_rejects_agent(self):
        events = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            events, "r1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        with pytest.raises(ReviewRejected, match="requires a human actor"):
            human_gate(ctx, require_human=True)

    def test_require_human_false_allows_agent(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        human_gate(ctx, require_human=False)

    def test_default_require_human_allows_agent(self):
        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        human_gate(ctx)


class TestHumanGateBuiltinTypeValidation:
    def test_non_boolean_require_human_fails_closed(self):
        from regista._review_validators import _human_gate_builtin

        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        ctx.validator_params = {"require_human": "true"}
        with pytest.raises(ReviewRejected, match="must be a boolean"):
            _human_gate_builtin(ctx)

    def test_integer_require_human_fails_closed(self):
        from regista._review_validators import _human_gate_builtin

        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        ctx.validator_params = {"require_human": 1}
        with pytest.raises(ReviewRejected, match="must be a boolean"):
            _human_gate_builtin(ctx)

    def test_no_validator_params_defaults_to_relaxed(self):
        from regista._review_validators import _human_gate_builtin

        events = [
            _evt("created", "a1", actor_metadata={"model_lineage": "glm"}),
            _evt("adversarial_pass", "r1", actor_metadata={"model_lineage": "kimi"}),
        ]
        ctx = _ctx(
            events, "a2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
            payload=REVIEW_NOTE,
            transition_name="accept",
        )
        ctx.validator_params = None
        _human_gate_builtin(ctx)


def _assert_review_rejected(exc: RegistaError) -> ReviewRejected:
    assert exc.code == ErrorCode.VALIDATOR_FAILED
    cause = exc.__cause__
    assert isinstance(cause, ReviewRejected)
    return cause


class TestRelaxedFlowIntegration:
    def test_agent_self_close_after_cross_lineage_review(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            sub.transition(
                wi_id, "accept", "glm-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "glm"},
                payload=REVIEW_NOTE,
            )
            wi = sub.get_work_item(wi_id)
            assert wi is not None
            assert wi.current_state == "done"
        finally:
            sub.close()

    def test_human_accept_after_agent_review(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            sub.transition(
                wi_id, "accept", "human-1",
                actor_kind="human",
                payload=REVIEW_NOTE,
            )
            wi = sub.get_work_item(wi_id)
            assert wi is not None
            assert wi.current_state == "done"
        finally:
            sub.close()

    def test_same_lineage_adversarial_review_without_ack_rejected(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "adversarial_pass", "glm-agent-2",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "glm"},
                    payload=REVIEW_NOTE,
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "not confirmed distinct" in cause.reason
        finally:
            sub.close()

    def test_self_review_at_adversarial_review_rejected(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "adversarial_pass", "glm-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "glm"},
                    payload=REVIEW_NOTE,
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "self-review" in cause.reason
        finally:
            sub.close()

    def test_adversarial_passer_cannot_accept(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "accept", "kimi-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "kimi"},
                    payload=REVIEW_NOTE,
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "two-stage independence" in cause.reason
        finally:
            sub.close()


class TestStrictFlowIntegration:
    def test_agent_accept_rejected_not_human(self):
        sub = _strict_sub()
        try:
            wi_id = _setup_to_review(sub, workflow="review_strict")
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "accept", "kimi-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "kimi"},
                    payload=REVIEW_NOTE,
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "requires a human actor" in cause.reason
        finally:
            sub.close()

    def test_human_accept_after_agent_review(self):
        sub = _strict_sub()
        try:
            wi_id = _setup_to_review(sub, workflow="review_strict")
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            sub.transition(
                wi_id, "accept", "human-1",
                actor_kind="human",
                payload=REVIEW_NOTE,
            )
            wi = sub.get_work_item(wi_id)
            assert wi is not None
            assert wi.current_state == "done"
        finally:
            sub.close()


class TestDelegationIntegration:
    def test_agent_on_behalf_of_author_cannot_adversarial_pass(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "adversarial_pass", "other-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "kimi"},
                    payload=REVIEW_NOTE,
                    on_behalf_of={"principal_id": "glm-agent"},
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "delegated self-review" in cause.reason
        finally:
            sub.close()

    def test_agent_on_behalf_of_adversarial_passer_cannot_accept(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "accept", "other-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "claude-opus"},
                    payload=REVIEW_NOTE,
                    on_behalf_of={"principal_id": "kimi-agent"},
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "two-stage independence" in cause.reason
        finally:
            sub.close()


class TestBuiltinAutoRegistration:
    def test_validators_available_without_explicit_registration(self):
        sub = InMemoryRegista(project="test_plan023_builtin", hmac_key_path=KEY_PATH)
        try:
            sub.register_workflow(RELAXED_WORKFLOW)
            assert "adversarial_review" in sub._validators
            assert "human_gate" in sub._validators
            assert sub._validators["adversarial_review"] is adversarial_review
            assert sub._validators["human_gate"] is not human_gate
        finally:
            sub.close()

    def test_builtin_review_validators_dict_contents(self):
        assert "adversarial_review" in BUILTIN_REVIEW_VALIDATORS
        assert "human_gate" in BUILTIN_REVIEW_VALIDATORS
        assert BUILTIN_REVIEW_VALIDATORS["adversarial_review"] is adversarial_review


class TestValidatorParamsInYaml:
    def test_strict_workflow_has_require_human_true_on_accept(self):
        sub = _strict_sub()
        try:
            wf = sub.get_workflow("review_strict", 1)
            accept_trans = next(
                t for t in wf.transitions if t.name == "accept"
            )
            assert accept_trans.validator == "human_gate"
            assert accept_trans.validator_params == {"require_human": True}
        finally:
            sub.close()

    def test_relaxed_workflow_has_no_validator_params_on_accept(self):
        sub = _relaxed_sub()
        try:
            wf = sub.get_workflow("review_relaxed", 1)
            accept_trans = next(
                t for t in wf.transitions if t.name == "accept"
            )
            assert accept_trans.validator == "human_gate"
            assert accept_trans.validator_params is None
        finally:
            sub.close()


class TestFullReviewCycle:
    def test_multi_cycle_independence(self):
        sub = _relaxed_sub()
        try:
            wi_id = _setup_to_review(sub)
            sub.transition(
                wi_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "kimi"},
                payload=REVIEW_NOTE,
            )
            sub.transition(
                wi_id, "reject", "glm-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "glm"},
                payload={"review_note": "needs rework"},
            )
            sub.transition(
                wi_id, "submit_for_review", "glm-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "glm"},
            )
            sub.transition(
                wi_id, "adversarial_pass", "claude-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "claude-opus"},
                payload=REVIEW_NOTE,
            )
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi_id, "accept", "kimi-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "kimi"},
                    payload=REVIEW_NOTE,
                )
            cause = _assert_review_rejected(exc_info.value)
            assert "two-stage independence" in cause.reason

            sub.transition(
                wi_id, "accept", "human-1",
                actor_kind="human",
                payload=REVIEW_NOTE,
            )
            wi = sub.get_work_item(wi_id)
            assert wi is not None
            assert wi.current_state == "done"
        finally:
            sub.close()
