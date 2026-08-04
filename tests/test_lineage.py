from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from regista._lint import resolve_model_lineage, stamp_model_lineage
from regista._review_validators import (
    ReviewRejected,
    adversarial_review,
    derive_authors,
)
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

# Minimal workflow: open -> in_progress -> in_review -> done, with the
# adversarial_review validator gated on the adversarial_pass transition.
_REVIEW_WORKFLOW = """\
name: wi248_review
version: 1
regista_version: "0.4.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
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
    to: done
    validator: adversarial_review

roles: []

work_item_types:
  - name: issue
    custom_fields: []
"""


def _new_store(project: str) -> InMemoryRegista:
    sub = InMemoryRegista(project=project, hmac_key_path=KEY_PATH)
    sub.register_workflow(_REVIEW_WORKFLOW)
    return sub


class TestResolveModelLineage:
    def test_resolves_canonical_var(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "gpt-sol"}) == "gpt-sol"

    def test_canonical_takes_precedence(self):
        env = {
            "REGISTA_MODEL_LINEAGE": "gpt-sol",
            "AGENT_MODEL_LINEAGE": "other",
            "MODEL_LINEAGE": "fallback",
        }
        assert resolve_model_lineage(env) == "gpt-sol"

    def test_falls_back_through_vars(self):
        assert resolve_model_lineage({"MODEL_LINEAGE": "glm"}) == "glm"
        assert resolve_model_lineage({"AGENT_MODEL_LINEAGE": "kimi"}) == "kimi"

    def test_strips_whitespace(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "  gpt-sol  "}) == "gpt-sol"

    def test_none_when_unset(self):
        assert resolve_model_lineage({}) is None

    def test_none_when_blank(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "   "}) is None


class TestStampModelLineage:
    def test_stamps_agent_with_resolved_lineage(self):
        result = stamp_model_lineage(
            {"role": "agent"}, "agent", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"}
        )
        assert result == {"role": "agent", "model_lineage": "gpt-sol"}

    def test_stamps_none_metadata_for_agent(self):
        result = stamp_model_lineage(None, "agent", environ={"REGISTA_MODEL_LINEAGE": "glm"})
        assert result == {"model_lineage": "glm"}

    def test_never_overwrites_declared_lineage(self):
        result = stamp_model_lineage(
            {"model_lineage": "declared"},
            "agent",
            environ={"REGISTA_MODEL_LINEAGE": "resolved"},
        )
        assert result == {"model_lineage": "declared"}

    def test_passthrough_when_no_lineage_resolvable(self):
        original = {"role": "agent"}
        result = stamp_model_lineage(original, "agent", environ={})
        assert result == {"role": "agent"}

    def test_non_agent_is_untouched(self):
        result = stamp_model_lineage(
            {"role": "reviewer"}, "human", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"}
        )
        assert result == {"role": "reviewer"}

    def test_does_not_mutate_input(self):
        original = {"role": "agent"}
        stamp_model_lineage(original, "agent", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"})
        assert original == {"role": "agent"}


# ---------------------------------------------------------------------------
# WI-248: derive_authors / adversarial_review precision fix.
#
# Two event classes were falsely tripping the agent_author_undeclared gate:
#   (1) the `created` event authored by the agent-notes tracker CLI service
#       identity (actor "agent-notes", kind "agent", no model behind it);
#   (2) `claim_acquired` events, whose caller did not propagate the claimant
#       declared lineage.
#
# Fix: exempt genuine non-model service identities (a documented allowlist)
# from the agent-author lineage check, and prove claim_acquired can carry the
# claimant lineage end-to-end.
# ---------------------------------------------------------------------------

REVIEW_NOTE = {"review_note": "looks good"}


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
) -> SimpleNamespace:
    return SimpleNamespace(
        prior_events=tuple(prior_events),
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        payload=payload,
        transition_name=transition_name,
    )


class TestDeriveAuthorsServiceIdentityExemption:
    """A non-model service identity must not be flagged as an undeclared agent
    author, and must not contribute an "agent" kind to the author set."""

    def test_service_identity_created_event_not_flagged(self):
        events = [_evt("created", "agent-notes", actor_kind="agent")]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert ids == {"agent-notes"}
        # Not counted as an agent author at all.
        assert "agent" not in kinds
        assert lineages == set()
        assert undeclared is False

    def test_service_identity_with_metadata_not_flagged(self):
        # Even if a service identity carries metadata but no model_lineage,
        # it is still exempt (it has no model behind it).
        events = [
            _evt("created", "agent-notes", actor_kind="agent",
                 actor_metadata={"role": "tracker"}),
        ]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" not in kinds
        assert lineages == set()
        assert undeclared is False

    def test_claim_acquired_carries_claimant_lineage(self):
        events = [
            _evt("created", "agent-notes", actor_kind="agent"),
            _evt("claim_acquired", "gpt-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": "lineage-A"}),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert "gpt-agent" in ids
        assert "agent" in kinds
        assert lineages == {"lineage-A"}
        assert undeclared is False

    def test_genuine_undeclared_model_agent_still_flagged(self):
        # A real model agent that fails to declare lineage must STILL trip the
        # gate — the exemption is precision, not a loosening.
        events = [_evt("created", "gpt-agent", actor_kind="agent",
                       actor_metadata=None)]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert lineages == set()
        assert undeclared is True

    def test_unknown_agent_kind_agent_still_flagged(self):
        # An unrecognized actor id with kind=agent and no lineage is NOT a
        # known service identity, so it must still be flagged.
        events = [_evt("created", "some-random-agent", actor_kind="agent")]
        _, _, _, undeclared = derive_authors(events)
        assert undeclared is True


class TestAdversarialReviewAfterServiceIdentityAndClaim:
    """End-to-end gate behaviour for an item filed by the service identity and
    claimed with a declared lineage (the WI-248 acceptance scenario)."""

    def _prior(self) -> list:
        return [
            _evt("created", "agent-notes", actor_kind="agent"),
            _evt("claim_acquired", "gpt-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": "lineage-A"}),
        ]

    def test_cross_lineage_reviewer_passes_without_ack(self):
        # The core acceptance test: a genuinely cross-lineage reviewer must be
        # able to record a review WITHOUT --same-lineage-acknowledged.
        ctx = _ctx(
            self._prior(), "kimi-agent",
            actor_metadata={"model_lineage": "lineage-B"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)  # must not raise

    def test_same_lineage_reviewer_still_blocked(self):
        # A true same-lineage reviewer must STILL be blocked without the ack —
        # the fix must not loosen the invariant.
        ctx = _ctx(
            self._prior(), "gpt-agent-2",
            actor_metadata={"model_lineage": "lineage-A"},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_undeclared_reviewer_still_blocked(self):
        # An undeclared reviewer lineage is UNKNOWN, not independent; it must
        # STILL be blocked without the ack.
        ctx = _ctx(
            self._prior(), "x-agent",
            actor_metadata=None,
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)


class TestClaimLineagePropagationIntegration:
    """Prove the regista API propagates claimant lineage onto the claim_acquired
    event end-to-end (WI-248 fix leg #2). The API already accepts actor_metadata
    through acquire_claim; this locks the contract so a lineage-bearing claim is
    visible to derive_authors and the cross-lineage gate."""

    def test_acquire_claim_propagates_lineage_to_event(self):
        sub = _new_store("wi248_claim_prop")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent-notes",
                actor_kind="agent",
            )
            # The claimant declares its lineage via actor_metadata.
            sub.acquire_claim(
                wi.work_item_id, "gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id, limit=100)
            claim_events = [e for e in events if e.transition == "claim_acquired"]
            assert len(claim_events) == 1
            assert claim_events[0].actor_metadata == {"model_lineage": "lineage-A"}

            _ids, kinds, lineages, undeclared = derive_authors(events)
            assert "lineage-A" in lineages
            assert "agent" in kinds
            assert undeclared is False
        finally:
            sub.close()

    def test_claim_without_lineage_still_flags_undeclared(self):
        # A model agent that claims WITHOUT declaring lineage is a genuine
        # undeclared agent author and must still be flagged.
        sub = _new_store("wi248_claim_no_lineage")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent-notes",
                actor_kind="agent",
            )
            sub.acquire_claim(
                wi.work_item_id, "gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
            )
            events = sub.read_events(work_item_id=wi.work_item_id, limit=100)
            _, _, _, undeclared = derive_authors(events)
            assert undeclared is True
        finally:
            sub.close()

    def test_cross_lineage_review_passes_after_claim_with_lineage(self):
        # Full acceptance scenario through the real validator: file by the
        # service identity, claim with lineage, then a cross-lineage adversarial
        # pass WITHOUT the acknowledgment flag must succeed.
        sub = _new_store("wi248_claim_full")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent-notes",
                actor_kind="agent",
            )
            sub.acquire_claim(
                wi.work_item_id, "gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            sub.transition(
                wi.work_item_id, "start", "gpt-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            sub.transition(
                wi.work_item_id, "submit_for_review", "gpt-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            # Cross-lineage reviewer, no ack flag -> must pass.
            sub.transition(
                wi.work_item_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-B"},
                payload=REVIEW_NOTE,
            )
            assert sub.get_work_item(wi.work_item_id).current_state == "done"
        finally:
            sub.close()
