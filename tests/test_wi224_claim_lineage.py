"""WI-224: claim_acquired events carried no model_lineage, so the
cross-lineage adversarial gate could never pass on a claimed work item.

The defect: the claim ops (``acquire_claim``, ``heartbeat_claim``,
``release_claim``) hard-coded ``actor_metadata=None`` on the events they
emit, while every authoring op accepts and records ``actor_metadata``.
``derive_authors()`` treats claim bookkeeping events as author events
(claiming a work item counts as working it, for separation of duties),
so an agent's un-attributed ``claim_acquired`` set
``agent_author_undeclared = True`` permanently and ``adversarial_review``
rejected every reviewer — even one with a genuinely distinct declared
lineage — unless it recorded a (false) ``same_lineage_acknowledged``.

The fix: the claim ops accept ``actor_metadata`` exactly like the
authoring ops and record it on the emitted ``claim_acquired`` /
``claim_stolen`` / ``claim_heartbeat`` / ``claim_released`` events, where
the gate's ``derive_authors()`` already reads ``model_lineage``.

Backward compatibility: ``actor_metadata`` stays optional. Claims made
without it record ``None`` exactly as before (missing != invalid), replay
and verification of old event chains are unaffected, and the gate keeps
requiring an acknowledgment for histories whose authors never declared a
lineage.

These tests run on the in-memory backend; the Postgres path
(``regista._claims``) is line-for-line the same plumbing and is exercised
by the DB-dependent suite in CI.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._review_validators import derive_authors
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

REVIEW_NOTE = {"review_note": "adversarial review: checked the diff"}

REVIEW_WORKFLOW = """\
name: wi224_review
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

OPUS = {"model_lineage": "claude-opus"}
SONNET = {"model_lineage": "claude-sonnet"}


def _sub() -> InMemoryRegista:
    sub = InMemoryRegista(project="test_wi224", hmac_key_path=KEY_PATH)
    sub.register_workflow(REVIEW_WORKFLOW)
    return sub


def _create(sub: InMemoryRegista, actor_id: str = "qual-agent") -> uuid.UUID:
    wi, _ = sub.create_work_item(
        workflow_name="wi224_review",
        work_item_type="issue",
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata=dict(OPUS),
    )
    return wi.work_item_id


def _events_by_transition(sub: InMemoryRegista, wi_id: uuid.UUID) -> dict:
    events = sub.read_events(work_item_id=wi_id, limit=1000)
    by_transition: dict = {}
    for evt in events:
        by_transition.setdefault(evt.transition, []).append(evt)
    return by_transition


class TestClaimEventsRecordActorMetadata:
    def test_claim_acquired_records_actor_metadata(self):
        sub = _sub()
        wi_id = _create(sub)

        sub.acquire_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))

        events = _events_by_transition(sub, wi_id)
        assert len(events["claim_acquired"]) == 1
        assert events["claim_acquired"][0].actor_metadata == OPUS

    def test_claim_heartbeat_and_release_record_actor_metadata(self):
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))

        sub.heartbeat_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))
        sub.release_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))

        events = _events_by_transition(sub, wi_id)
        assert events["claim_heartbeat"][0].actor_metadata == OPUS
        assert events["claim_released"][0].actor_metadata == OPUS

    def test_claim_without_metadata_records_none(self):
        """Backward compatibility: the parameter is optional and omitting it
        produces exactly the pre-fix event shape."""
        sub = _sub()
        wi_id = _create(sub)

        sub.acquire_claim(wi_id, "qual-agent")
        sub.heartbeat_claim(wi_id, "qual-agent")
        sub.release_claim(wi_id, "qual-agent")

        events = _events_by_transition(sub, wi_id)
        assert events["claim_acquired"][0].actor_metadata is None
        assert events["claim_heartbeat"][0].actor_metadata is None
        assert events["claim_released"][0].actor_metadata is None

    def test_replay_verifies_claims_with_and_without_metadata(self):
        """Neither the new field nor its absence may break chain replay."""
        sub = _sub()
        with_meta = _create(sub)
        sub.acquire_claim(with_meta, "qual-agent", actor_metadata=dict(OPUS))
        sub.release_claim(with_meta, "qual-agent", actor_metadata=dict(OPUS))

        without_meta = _create(sub)
        sub.acquire_claim(without_meta, "qual-agent")

        report = sub.replay()
        assert report.halted == 0, report
        assert report.replayed_drift == 0, report
        assert report.replayed_ok == 2, report


class TestDeriveAuthorsReadsClaimLineage:
    def test_claim_acquired_with_lineage_declares_the_author(self):
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))

        events = sub.read_events(work_item_id=wi_id, limit=1000)
        author_ids, author_kinds, lineages, undeclared = derive_authors(events)

        assert author_ids == {"qual-agent"}
        assert author_kinds == {"agent"}
        assert lineages == {"claude-opus"}
        assert undeclared is False

    def test_claim_acquired_without_lineage_still_flags_undeclared(self):
        """Unchanged pre-fix semantics for legacy events: an un-attributed
        agent claim still reads as an undeclared agent author."""
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent")

        events = sub.read_events(work_item_id=wi_id, limit=1000)
        _ids, _kinds, _lineages, undeclared = derive_authors(events)
        assert undeclared is True


class TestCrossLineageGateOnClaimedItem:
    """The WI-224 proof, inverted: the exact claim/work/review flow that
    could never pass now passes when the claim declares its lineage."""

    def _work_to_review(self, sub: InMemoryRegista, wi_id: uuid.UUID) -> None:
        sub.transition(
            wi_id, "start", "qual-agent",
            actor_kind="agent", actor_metadata=dict(OPUS),
        )
        sub.transition(
            wi_id, "submit_for_review", "qual-agent",
            actor_kind="agent", actor_metadata=dict(OPUS),
        )

    def test_claimed_item_passes_cross_lineage_review(self):
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))
        self._work_to_review(sub, wi_id)

        evt = sub.transition(
            wi_id, "adversarial_pass", "reviewer-agent",
            actor_kind="agent",
            actor_metadata=dict(SONNET),
            payload=dict(REVIEW_NOTE),
        )
        assert evt.transition == "adversarial_pass"

    def test_heartbeat_with_lineage_does_not_poison_the_gate(self):
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))
        sub.heartbeat_claim(wi_id, "qual-agent", actor_metadata=dict(OPUS))
        self._work_to_review(sub, wi_id)

        sub.transition(
            wi_id, "adversarial_pass", "reviewer-agent",
            actor_kind="agent",
            actor_metadata=dict(SONNET),
            payload=dict(REVIEW_NOTE),
        )

    def test_unattributed_claim_still_requires_acknowledgment(self):
        """Legacy behavior preserved: a claim recorded without lineage keeps
        the gate closed until the reviewer acknowledges explicitly."""
        sub = _sub()
        wi_id = _create(sub)
        sub.acquire_claim(wi_id, "qual-agent")
        self._work_to_review(sub, wi_id)

        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi_id, "adversarial_pass", "reviewer-agent",
                actor_kind="agent",
                actor_metadata=dict(SONNET),
                payload=dict(REVIEW_NOTE),
            )
        assert exc_info.value.code == ErrorCode.VALIDATOR_FAILED

        sub.transition(
            wi_id, "adversarial_pass", "reviewer-agent",
            actor_kind="agent",
            actor_metadata=dict(SONNET),
            payload={**REVIEW_NOTE, "same_lineage_acknowledged": True},
        )
