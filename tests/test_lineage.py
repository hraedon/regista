from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from regista._errors import RegistaError
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


def _new_store(project: str, tmp_path: Path) -> InMemoryRegista:
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    principals = ("agent:agent-notes", "agent:gpt-agent", "agent:kimi-agent")
    keyset = make_v6_keyset(tmp_path, principals=principals)
    sub = InMemoryRegista(project=project, hmac_key_path=keyset.path)
    open_v6_epoch(sub, keyset, principals=principals)
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
        assert resolve_model_lineage({"AGENT_MODEL_LINEAGE": "deepseek"}) == "deepseek"

    def test_rejects_whitespace_variant(self):
        with pytest.raises(RegistaError):
            resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "  gpt-sol  "})

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
            {"model_lineage": "kimi"},
            "agent",
            environ={"REGISTA_MODEL_LINEAGE": "glm"},
        )
        assert result == {"model_lineage": "kimi"}

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
                 actor_metadata={"model_lineage": "glm"}),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert "gpt-agent" in ids
        assert "agent" in kinds
        assert lineages == {"glm"}
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

    def test_spoofed_service_id_with_lineage_is_not_hidden(self):
        # F1 (CRITICAL): the exemption must NOT let a forger hide a real
        # model lineage behind the service id. If an event claims
        # actor_id="agent-notes" but CARRIES a model_lineage, the lineage must
        # be surfaced (fall through to the declared-author path), not silently
        # dropped. Otherwise a model agent could forge the service id to make
        # itself invisible to the cross-lineage gate.
        events = [
            _evt("created", "agent-notes", actor_kind="agent",
                 actor_metadata={"model_lineage": "kimi"}),
        ]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert "kimi" in lineages
        assert undeclared is False

    def test_spoofed_service_id_without_lineage_still_exempt(self):
        # The residual no-lineage case (forged service id, no lineage) is the
        # same free-form-actor_id false-identity regista already permits for
        # ANY actor id — the exemption correctly treats it as a non-author.
        events = [_evt("created", "agent-notes", actor_kind="agent")]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" not in kinds
        assert lineages == set()
        assert undeclared is False


class TestServiceIdentityDelegationUndeclared:
    """F2 (HIGH): on_behalf_of delegation on an exempt service-identity event
    must not launder an undeclared delegated agent principal into "declared"."""

    def test_undelegated_service_event_not_flagged(self):
        # Baseline: a plain service event with no delegation is exempt.
        events = [_evt("created", "agent-notes", actor_kind="agent")]
        _, _, _, undeclared = derive_authors(events)
        assert undeclared is False

    def test_delegated_undeclared_agent_principal_is_flagged(self):
        # A service event acting on behalf of an agent principal that declares
        # no lineage must trip the undeclared-agent gate — otherwise the
        # delegation would launder an undeclared author into "declared".
        events = [
            _evt("created", "agent-notes", actor_kind="agent",
                 on_behalf_of={
                     "principal_id": "delegated-agent",
                     "principal_kind": "agent",
                 }),
        ]
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert "delegated-agent" in ids
        assert "agent" in kinds
        assert lineages == set()
        assert undeclared is True

    def test_delegated_declared_agent_principal_not_flagged(self):
        # A delegated agent principal that DOES declare a lineage is genuinely
        # declared and must NOT trip the gate.
        events = [
            _evt("created", "agent-notes", actor_kind="agent",
                 on_behalf_of={
                     "principal_id": "delegated-agent",
                     "principal_kind": "agent",
                     "principal_lineage": "deepseek",
                 }),
        ]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert "deepseek" in lineages
        assert undeclared is False

    def test_delegated_human_principal_not_flagged(self):
        # A delegated human principal is not an agent author at all.
        events = [
            _evt("created", "agent-notes", actor_kind="agent",
                 on_behalf_of={
                     "principal_id": "human:boss",
                     "principal_kind": "human",
                 }),
        ]
        _, kinds, _, undeclared = derive_authors(events)
        assert "human" in kinds
        assert undeclared is False


class TestOrdinaryDelegationUndeclared:
    """WI-257: the WI-248 undeclared-principal rule was applied ONLY inside the
    exempt-service branch, so an ordinary declared proxy laundered an undeclared
    delegated agent principal into "declared" — adversarial_review passed with
    no acknowledgment and left no audit breadcrumb at all. The rule now applies
    on every branch: a delegated agent principal with no declared lineage is an
    undeclared agent author whoever proxied for it."""

    def _delegated(self, **delegation) -> list:
        # An ordinary (non-exempt) agent actor that DOES declare its own
        # lineage, recording work on behalf of some principal.
        return [
            _evt("created", "proxy-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": "glm"},
                 on_behalf_of=delegation),
        ]

    def test_ordinary_proxy_undeclared_agent_principal_is_flagged(self):
        events = self._delegated(
            principal_id="hidden-agent", principal_kind="agent",
        )
        ids, kinds, lineages, undeclared = derive_authors(events)
        assert "hidden-agent" in ids
        assert "agent" in kinds
        # The proxy's own lineage is still recorded — the point is that it no
        # longer stands in for the principal's missing one.
        assert lineages == {"glm"}
        assert undeclared is True

    def test_ordinary_proxy_declared_agent_principal_not_flagged(self):
        # A delegated agent principal that DOES declare a lineage is genuinely
        # declared: both lineages are surfaced and the gate is not tripped.
        events = self._delegated(
            principal_id="delegated-agent", principal_kind="agent",
            principal_lineage="deepseek",
        )
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert lineages == {"glm", "deepseek"}
        assert undeclared is False

    def test_ordinary_proxy_human_principal_not_flagged(self):
        # A delegated human principal is not an agent author at all.
        events = self._delegated(
            principal_id="human:boss", principal_kind="human",
        )
        _, kinds, _, undeclared = derive_authors(events)
        assert "human" in kinds
        assert undeclared is False

    def test_human_proxy_undeclared_agent_principal_is_flagged(self):
        # The proxy's own kind is irrelevant: what matters is that an agent
        # principal never declared itself. A human front for an undeclared
        # model must not launder it either.
        events = [
            _evt("created", "human-proxy", actor_kind="human",
                 on_behalf_of={
                     "principal_id": "hidden-agent",
                     "principal_kind": "agent",
                 }),
        ]
        _, kinds, _, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert undeclared is True

    def test_ordinary_and_service_branches_agree(self):
        # WI-248 parity: the exempt service identity and an ordinary actor must
        # reach the same verdict on the same delegation shape.
        delegation = {"principal_id": "hidden-agent", "principal_kind": "agent"}
        _, _, _, service = derive_authors(
            [_evt("created", "agent-notes", actor_kind="agent",
                  on_behalf_of=delegation)]
        )
        _, _, _, ordinary = derive_authors(
            [_evt("created", "proxy-agent", actor_kind="agent",
                  actor_metadata={"model_lineage": "glm"},
                  on_behalf_of=delegation)]
        )
        assert service is ordinary is True

    def test_cross_lineage_reviewer_blocked_without_ack(self):
        # The composed attack: the reviewer IS cross-lineage against every
        # declared lineage, but a mind behind the delegation never declared
        # itself, so distinctness is not established.
        ctx = _ctx(
            self._delegated(principal_id="hidden-agent", principal_kind="agent"),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_cross_lineage_reviewer_passes_with_ack(self):
        # The escape hatch is unchanged: an explicit acknowledgment records the
        # breadcrumb the laundering path used to skip entirely.
        ctx = _ctx(
            self._delegated(principal_id="hidden-agent", principal_kind="agent"),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload={"review_note": "ack", "same_lineage_acknowledged": True},
        )
        adversarial_review(ctx)

    def test_declared_principal_review_passes_without_ack(self):
        # Legitimate composition: every identity in the history declared a
        # lineage and the reviewer differs from all of them — no ack needed.
        ctx = _ctx(
            self._delegated(
                principal_id="delegated-agent", principal_kind="agent",
                principal_lineage="deepseek",
            ),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)

class TestDegenerateDelegationValues:
    """WI-257 follow-up (PR #31 review B1/B2): ``if principal_lineage:`` and
    ``principal_kind == "agent"`` are only as strong as the values reaching
    them, and ``validate_delegation_chain`` checks neither field. A blank or
    non-string lineage used to be str()-ified into a lineage distinct from
    every real one, and a mis-spelled kind used to read as
    definitively-not-a-model — both re-opening exactly the hole WI-257
    closed."""

    def _delegated(self, **delegation) -> list:
        return [
            _evt("created", "proxy-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": "glm"},
                 on_behalf_of=delegation),
        ]

    @pytest.mark.parametrize("blank", ["   ", "", "\t\n"])
    def test_blank_principal_lineage_is_undeclared(self, blank):
        events = self._delegated(
            principal_id="hidden-agent", principal_kind="agent",
            principal_lineage=blank,
        )
        _, _, lineages, undeclared = derive_authors(events)
        # The blank value must not enter the author set as a "lineage" — that
        # is what made it compare distinct from every real one.
        assert lineages == {"glm"}
        assert undeclared is True

    @pytest.mark.parametrize("value", [42, 0, True, ["glm"], {"lineage": "glm"}])
    def test_non_string_principal_lineage_is_undeclared(self, value):
        events = self._delegated(
            principal_id="hidden-agent", principal_kind="agent",
            principal_lineage=value,
        )
        _, _, lineages, undeclared = derive_authors(events)
        assert lineages == {"glm"}
        assert undeclared is True

    @pytest.mark.parametrize("kind", ["Agent", "AGENT", " agent ", "\tAgent\n"])
    def test_non_canonical_agent_kind_still_flags(self, kind):
        events = self._delegated(principal_id="hidden-agent", principal_kind=kind)
        _, kinds, _, undeclared = derive_authors(events)
        # Recorded canonically, so the gate's `"agent" in author_kinds` test
        # cannot be dodged by capitalisation either.
        assert "agent" in kinds
        assert undeclared is True

    @pytest.mark.parametrize("kind", ["Human", "HUMAN", " human "])
    def test_non_canonical_human_kind_still_exempt(self, kind):
        events = self._delegated(principal_id="human:boss", principal_kind=kind)
        _, kinds, _, undeclared = derive_authors(events)
        assert "human" in kinds
        assert undeclared is False

    @pytest.mark.parametrize("kind", ["ai-agent", "service", "break_glass", "robot"])
    def test_unrecognised_kind_is_flagged(self, kind):
        # WI-262: the author side is symmetric with the review side. An earlier
        # revision exempted unrecognised kinds on the theory that they were
        # indistinguishable from a "system" principal — that theory was wrong:
        # no principal_kind of "system" exists anywhere in the estate (the
        # actor_kind="system" note in _review_validators is a different field),
        # so the exemption bought nothing and let principal_kind="ai-agent"
        # with no lineage past the gate entirely. Only "human" can vouch that a
        # principal is not a model.
        events = self._delegated(principal_id="p", principal_kind=kind)
        _, kinds, _, undeclared = derive_authors(events)
        assert kind in kinds
        assert undeclared is True

    @pytest.mark.parametrize("kind", ["ai-agent", "service", 42, "  "])
    def test_unrecognised_kind_with_declared_lineage_not_flagged(self, kind):
        # The flag is about an UNDECLARED principal. A lineage-bearing
        # principal is declared whatever its kind, and the lineage itself is
        # what the comparison then uses.
        events = self._delegated(
            principal_id="p", principal_kind=kind, principal_lineage="deepseek",
        )
        _, _, lineages, undeclared = derive_authors(events)
        assert lineages == {"glm", "deepseek"}
        assert undeclared is False

    def test_unrecognised_kind_blocks_review_without_ack(self):
        # Sol R2 finding 2, end to end at the validator: a lineage-B reviewer
        # of work delegated to an "ai-agent" principal used to pass with no
        # acknowledgment at all.
        ctx = _ctx(
            self._delegated(principal_id="hidden", principal_kind="ai-agent"),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_unrecognised_kind_review_passes_with_ack(self):
        ctx = _ctx(
            self._delegated(principal_id="hidden", principal_kind="ai-agent"),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload={"review_note": "ack", "same_lineage_acknowledged": True},
        )
        adversarial_review(ctx)

    @pytest.mark.parametrize("blank", ["   ", "", "\t"])
    def test_blank_actor_model_lineage_is_undeclared(self, blank):
        # The same laxness on the proxy's own metadata: a blank model_lineage
        # declares nothing, so the agent author is undeclared.
        events = [
            _evt("created", "gpt-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": blank}),
        ]
        _, kinds, lineages, undeclared = derive_authors(events)
        assert "agent" in kinds
        assert lineages == set()
        assert undeclared is True

    def test_blank_principal_lineage_blocks_review_without_ack(self):
        ctx = _ctx(
            self._delegated(
                principal_id="hidden-agent", principal_kind="agent",
                principal_lineage="   ",
            ),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_non_canonical_kind_blocks_review_without_ack(self):
        ctx = _ctx(
            self._delegated(principal_id="hidden-agent", principal_kind="Agent"),
            "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        with pytest.raises(ReviewRejected, match="not confirmed distinct"):
            adversarial_review(ctx)

    def test_service_branch_applies_the_same_rules(self):
        # WI-248's exempt branch and the ordinary branch share one
        # implementation now; prove the degenerate values behave identically.
        for actor_id, meta in (
            ("agent-notes", None),
            ("proxy-agent", {"model_lineage": "glm"}),
        ):
            events = [
                _evt("created", actor_id, actor_kind="agent", actor_metadata=meta,
                     on_behalf_of={
                         "principal_id": "hidden-agent",
                         "principal_kind": " Agent ",
                         "principal_lineage": "  ",
                     }),
            ]
            _, kinds, _, undeclared = derive_authors(events)
            assert "agent" in kinds
            assert undeclared is True


class TestAdversarialReviewAfterServiceIdentityAndClaim:
    """End-to-end gate behaviour for an item filed by the service identity and
    claimed with a declared lineage (the WI-248 acceptance scenario)."""

    def _prior(self) -> list:
        return [
            _evt("created", "agent-notes", actor_kind="agent"),
            _evt("claim_acquired", "gpt-agent", actor_kind="agent",
                 actor_metadata={"model_lineage": "glm"}),
        ]

    def test_cross_lineage_reviewer_passes_without_ack(self):
        # The core acceptance test: a genuinely cross-lineage reviewer must be
        # able to record a review WITHOUT --same-lineage-acknowledged.
        ctx = _ctx(
            self._prior(), "kimi-agent",
            actor_metadata={"model_lineage": "kimi"},
            payload=REVIEW_NOTE,
        )
        adversarial_review(ctx)  # must not raise

    def test_same_lineage_reviewer_still_blocked(self):
        # A true same-lineage reviewer must STILL be blocked without the ack —
        # the fix must not loosen the invariant.
        ctx = _ctx(
            self._prior(), "gpt-agent-2",
            actor_metadata={"model_lineage": "glm"},
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

    def test_acquire_claim_propagates_lineage_to_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        sub = _new_store("wi248_claim_prop", tmp_path)
        try:
            monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-model")
            monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "glm")
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent:agent-notes",
                actor_kind="agent",
            )
            sub.acquire_claim(
                wi.work_item_id, "agent:gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
            )
            events = sub.read_events(work_item_id=wi.work_item_id, limit=100)
            claim_events = [e for e in events if e.transition == "claim_acquired"]
            assert len(claim_events) == 1
            envelope = json.loads(bytes(claim_events[0].canonical_envelope))
            assert envelope["producer"]["model_lineage"] == "glm"

            _ids, kinds, lineages, undeclared = derive_authors(events)
            assert "glm" in lineages
            assert "agent" in kinds
            assert undeclared is False
        finally:
            sub.close()

    def test_claim_without_lineage_still_flags_undeclared(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # A model agent that claims WITHOUT declaring lineage is a genuine
        # undeclared agent author and must still be flagged.
        sub = _new_store("wi248_claim_no_lineage", tmp_path)
        try:
            monkeypatch.delenv("REGISTA_PRODUCER_MODEL", raising=False)
            monkeypatch.delenv("REGISTA_PRODUCER_MODEL_LINEAGE", raising=False)
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent:agent-notes",
                actor_kind="agent",
            )
            sub.acquire_claim(
                wi.work_item_id, "agent:gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
            )
            events = sub.read_events(work_item_id=wi.work_item_id, limit=100)
            _, _, _, undeclared = derive_authors(events)
            assert undeclared is True
        finally:
            sub.close()

    def test_cross_lineage_review_passes_after_claim_with_lineage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # Full acceptance scenario through the real validator: file by the
        # service identity, claim with lineage, then a cross-lineage adversarial
        # pass WITHOUT the acknowledgment flag must succeed.
        sub = _new_store("wi248_claim_full", tmp_path)
        try:
            monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-model")
            monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "glm")
            wi, _ = sub.create_work_item(
                workflow_name="wi248_review",
                work_item_type="issue",
                actor_id="agent:agent-notes",
                actor_kind="agent",
            )
            sub.acquire_claim(
                wi.work_item_id, "agent:gpt-agent",
                ttl_seconds=300,
                actor_kind="agent",
            )
            sub.transition(
                wi.work_item_id, "start", "agent:gpt-agent",
                actor_kind="agent",
            )
            sub.transition(
                wi.work_item_id, "submit_for_review", "agent:gpt-agent",
                actor_kind="agent",
            )
            # Cross-lineage reviewer, no ack flag -> must pass.
            monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "kimi")
            sub.transition(
                wi.work_item_id, "adversarial_pass", "agent:kimi-agent",
                actor_kind="agent",
                payload={
                    **REVIEW_NOTE,
                    "reviewer_claims": {"model_lineage": "kimi"},
                },
            )
            assert sub.get_work_item(wi.work_item_id).current_state == "done"
        finally:
            sub.close()
