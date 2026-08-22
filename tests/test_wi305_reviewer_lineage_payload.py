"""Reviewer lineage compatibility and the v6 producer-only boundary."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._lineage import (
    require_canonical_reviewer_lineage,
    reviewer_model_lineage,
)
from regista._review_validators import ReviewRejected, adversarial_review


def _legacy_event(
    transition: str,
    *,
    actor_id: str = "a1",
    lineage: str | None = "glm",
) -> SimpleNamespace:
    metadata = {"model_lineage": lineage} if lineage is not None else None
    return SimpleNamespace(
        transition=transition,
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata=metadata,
        on_behalf_of=None,
        payload=None,
    )


def _context(
    prior_events: list,
    *,
    payload: dict | None,
    producer: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        prior_events=tuple(prior_events),
        actor_id="r1",
        actor_kind="agent",
        actor_metadata=None,
        producer=producer,
        payload=payload,
        transition_name="adversarial_pass",
        on_behalf_of=None,
        validator_params=None,
        workflow_name="review_relaxed",
        workflow_version=1,
        current_state="in_review",
        new_state="in_human_review",
    )


class TestLegacyReviewerLineageCompatibility:
    def test_legacy_payload_claim_remains_readable_for_replay(self) -> None:
        event = _legacy_event("adversarial_pass", lineage="glm")
        event.payload = {"reviewer_claims": {"model_lineage": "kimi"}}
        assert reviewer_model_lineage(event) == "kimi"

    def test_legacy_claim_validation_remains_available(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            require_canonical_reviewer_lineage(
                {"reviewer_claims": {"model_lineage": "not-a-family"}}
            )
        assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE


class TestV6ProducerOnlyReviewerLineage:
    def test_v6_producer_wins_over_payload_claim(self) -> None:
        ctx = _context(
            [_legacy_event("created", lineage="glm")],
            producer={
                "harness": "claude-code",
                "harness_version": "test-harness/1",
                "model": "claude-fable-5",
                "model_lineage": "fable",
            },
            payload={
                "review_note": "obsolete claim",
                "reviewer_claims": {"model_lineage": "kimi"},
            },
        )
        assert reviewer_model_lineage(ctx) == "fable"
        with pytest.raises(RegistaError) as exc_info:
            adversarial_review(ctx)
        assert exc_info.value.code is ErrorCode.INVALID_ARGUMENT

    def test_v6_same_lineage_uses_signed_producer(self) -> None:
        ctx = _context(
            [_legacy_event("created", lineage="glm")],
            producer={
                "harness": "claude-code",
                "harness_version": "test-harness/1",
                "model": "glm-5.3",
                "model_lineage": "glm",
            },
            payload={"review_note": "same lineage"},
        )
        with pytest.raises(ReviewRejected, match="same-lineage"):
            adversarial_review(ctx)

    def test_v6_missing_signed_producer_fails_closed(self) -> None:
        prior = SimpleNamespace(
            **_legacy_event("created", lineage=None).__dict__,
            canonical_envelope=json.dumps({"version": 6}).encode("utf-8"),
        )
        ctx = _context([prior], payload={"review_note": "missing producer"})
        with pytest.raises(RegistaError) as exc_info:
            adversarial_review(ctx)
        assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE
