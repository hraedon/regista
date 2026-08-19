"""WI-305 A: the reviewer's model lineage is a canonical assertion in the SIGNED
review-verdict payload (``payload.reviewer_claims.model_lineage``).

Under the v6 envelope the reviewer's ``actor.metadata`` may not carry
``model_lineage`` at all (producer fields are refused there, ``V6-ENVELOPE.md``
§1.8), and the process-level ``producer`` block is one value per process — so
per-actor cross-lineage distinctness has no vehicle in those two places. The
settled home (WI-305 A) is the review-verdict payload's ``reviewer_claims``
block, which is signed by construction.

These tests pin that vehicle: reading + closed-registry validation, and the
gate consuming it (an ``adversarial_pass`` whose reviewer lineage is carried
ONLY in the payload — ``actor_metadata`` absent — is classified on that claim).
Persistent producer/author lineage stays process-level (WI-055); this file only
proves the reviewer role-specific assertion can cross the gate.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from regista._lineage import reviewer_model_lineage, verdict_reviewer_lineage
from regista._review_validators import ReviewRejected, adversarial_review

REVIEW_NOTE = {"review_note": "looks good"}


def _evt(
    transition: str,
    actor_id: str,
    *,
    actor_metadata: dict | None = None,
) -> SimpleNamespace:
    # The author events are legacy-shaped in this unit test (lineage in
    # actor_metadata). What is under test is the REVIEWER's lineage vehicle; the
    # author side is unchanged in either envelope.
    return SimpleNamespace(
        transition=transition,
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata=actor_metadata,
        on_behalf_of=None,
        payload=None,
    )


def _ctx(
    prior_events: list,
    actor_id: str,
    *,
    payload: dict | None,
    actor_metadata: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        prior_events=tuple(prior_events),
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata=actor_metadata,
        payload=payload,
        transition_name="adversarial_pass",
        on_behalf_of=None,
        validator_params=None,
        workflow_name="review_relaxed",
        workflow_version=1,
        current_state="in_review",
        new_state="in_human_review",
    )


def _pass_ctx(author_lineage: str = "glm", reviewer_claims: dict | None = None) -> SimpleNamespace:
    author = [_evt("created", "a1", actor_metadata={"model_lineage": author_lineage})]
    return _ctx(
        author,
        "r1",
        # The reviewer's actor_metadata is ABSENT — the v6 shape, where producer
        # fields are refused there — so the only lineage claim is the payload's.
        actor_metadata=None,
        payload={"review_note": "looks good", "reviewer_claims": reviewer_claims},
    )


class TestVerdictReviewerLineage:
    def test_payload_claim_is_validated_against_the_closed_registry(self) -> None:
        assert verdict_reviewer_lineage(
            {"reviewer_claims": {"model_lineage": "kimi"}}
        ) == "kimi"
        # An unknown lineage declares nothing — it must never become an invented
        # DISTINCT lineage.
        assert (
            verdict_reviewer_lineage(
                {"reviewer_claims": {"model_lineage": "not-a-family"}}
            )
            is None
        )
        assert verdict_reviewer_lineage({"reviewer_claims": {}}) is None

    def test_non_verdict_payload_contributes_nothing(self) -> None:
        assert verdict_reviewer_lineage({"review_note": "x"}) is None
        assert verdict_reviewer_lineage(None) is None
        assert verdict_reviewer_lineage("not-a-dict") is None

    def test_payload_claim_takes_precedence_over_legacy_lineage(self) -> None:
        from types import SimpleNamespace

        evt = SimpleNamespace(
            payload={"reviewer_claims": {"model_lineage": "kimi"}},
            actor_metadata={"model_lineage": "glm"},
        )
        # The payload assertion wins; the legacy actor_metadata value is only the
        # fallback for events written before the verdict carried the claim.
        assert reviewer_model_lineage(evt) == "kimi"


class TestGateConsumesPayloadLineage:
    def test_distinct_payload_lineage_passes_with_no_actor_metadata(self) -> None:
        ctx = _pass_ctx(author_lineage="glm", reviewer_claims={"model_lineage": "kimi"})
        adversarial_review(ctx)  # distinct -> no raise

    def test_same_payload_lineage_is_rejected_without_ack(self) -> None:
        ctx = _pass_ctx(author_lineage="glm", reviewer_claims={"model_lineage": "glm"})
        with pytest.raises(ReviewRejected, match="same-lineage"):
            adversarial_review(ctx)

    def test_invalid_payload_lineage_is_rejected_at_ingress(self) -> None:
        from regista._errors import ErrorCode, RegistaError

        ctx = _pass_ctx(
            author_lineage="glm",
            reviewer_claims={"model_lineage": "not-a-family"},
        )
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_absent_payload_lineage_is_rejected_at_ingress(self) -> None:
        from regista._errors import ErrorCode, RegistaError

        ctx = _pass_ctx(author_lineage="glm", reviewer_claims={})
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_malformed_reviewer_claims_is_rejected_at_ingress(self) -> None:
        from regista._errors import ErrorCode, RegistaError

        ctx = _pass_ctx(author_lineage="glm", reviewer_claims="not-an-object")
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_payload_claim_can_carry_the_acknowledgment(self) -> None:
        author = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            author,
            "r1",
            actor_metadata=None,
            payload={
                "review_note": "same lineage ack",
                "same_lineage_acknowledged": True,
                "reviewer_claims": {"model_lineage": "glm"},
            },
        )
        adversarial_review(ctx)  # ack present -> admitted


def _v6_evt(
    transition: str,
    actor_id: str,
    *,
    actor_kind: str = "agent",
) -> SimpleNamespace:
    """A v6-enveloped author event: its ``canonical_envelope`` carries version 6.

    That marker is the post-epoch signal ``_review_validators._is_post_epoch``
    reads (a work item worked inside the clean epoch has an all-v6 prior history).
    The envelope is minimal on purpose — this exercises epoch DETECTION, not
    lineage extraction (the Postgres-backed ``test_wi305_v6_review_gate`` proves
    the end-to-end lineage path over a genuine epoch).
    """
    return SimpleNamespace(
        transition=transition,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=None,
        on_behalf_of=None,
        payload=None,
        canonical_envelope=json.dumps({"version": 6}).encode("utf-8"),
    )


class TestPostEpochRequiresReviewerClaims:
    """WI-307: inside the v6 epoch the reviewer_claims block is mandatory."""

    def test_post_epoch_pass_omitting_reviewer_claims_fails_closed(self) -> None:
        from regista._errors import ErrorCode, RegistaError

        # Prior events carry v6 envelopes -> post-epoch. Payload omits the
        # reviewer_claims key entirely, which the present-only check would have
        # tolerated (fall back to producer lineage). It must now fail closed.
        ctx = _ctx(
            [_v6_evt("created", "a1")],
            "r1",
            actor_metadata=None,
            payload={"review_note": "looks good"},
        )
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_post_epoch_omission_is_not_launderable_by_acknowledgment(self) -> None:
        # The sharp regression: on the parent, a post-epoch pass could OMIT
        # reviewer_claims and still pass by asserting same_lineage_acknowledged,
        # laundering a verdict whose reviewer lineage was never signed in the
        # role-specific payload. WI-307 fails it closed at ingress, before the
        # acknowledgment path is ever consulted.
        from regista._errors import ErrorCode, RegistaError

        ctx = _ctx(
            [_v6_evt("created", "a1")],
            "r1",
            actor_metadata=None,
            payload={"review_note": "looks good", "same_lineage_acknowledged": True},
        )
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_post_epoch_pass_with_null_reviewer_claims_fails_closed(self) -> None:
        from regista._errors import ErrorCode, RegistaError

        ctx = _ctx(
            [_v6_evt("created", "a1")],
            "r1",
            actor_metadata=None,
            payload={"review_note": "looks good", "reviewer_claims": None},
        )
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_post_epoch_pass_with_canonical_reviewer_claims_passes(self) -> None:
        # Post-epoch (v6 prior event) pass carrying a canonical reviewer_claims
        # block is admitted. A human author means no agent-author ack gate, so
        # this isolates the WI-307 requirement: reviewer_claims present + canonical.
        ctx = _ctx(
            [_v6_evt("created", "a1", actor_kind="human")],
            "r1",
            actor_metadata=None,
            payload={"review_note": "looks good", "reviewer_claims": {"model_lineage": "kimi"}},
        )
        adversarial_review(ctx)  # no raise

    def test_post_epoch_present_but_noncanonical_still_fails_wi305(self) -> None:
        # The WI-305 A present-but-non-canonical rejection must still hold post-epoch.
        from regista._errors import ErrorCode, RegistaError

        ctx = _ctx(
            [_v6_evt("created", "a1")],
            "r1",
            actor_metadata=None,
            payload={
                "review_note": "looks good",
                "reviewer_claims": {"model_lineage": "not-a-family"},
            },
        )
        with pytest.raises(RegistaError) as exc:
            adversarial_review(ctx)
        assert exc.value.code is ErrorCode.INVALID_MODEL_LINEAGE

    def test_pre_epoch_legacy_pass_without_reviewer_claims_still_passes(self) -> None:
        # Legacy-shaped prior events (no canonical_envelope) -> pre-epoch. The
        # reviewer's lineage rides the legacy vehicle (actor_metadata) and is
        # distinct from the author, so the pass is admitted WITHOUT a
        # reviewer_claims block: the compatibility carve-out is preserved.
        author = [_evt("created", "a1", actor_metadata={"model_lineage": "glm"})]
        ctx = _ctx(
            author,
            "r1",
            actor_metadata={"model_lineage": "kimi"},
            payload={"review_note": "looks good"},
        )
        adversarial_review(ctx)  # no raise — legacy fallback still works
