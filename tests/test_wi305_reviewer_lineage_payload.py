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
