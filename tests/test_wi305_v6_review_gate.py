"""The v6 review gate uses the signed producer as the only lineage authority."""

from __future__ import annotations

import json
import uuid

import pytest
from _helpers import DSN

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema
from tests._v6_fixtures import (
    Producer,
    make_v6_keyset,
    open_v6_epoch,
    set_v6_producer_env,
)

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

REVIEW_PRINCIPALS = ("agent:author", "agent:reviewer", "human:operator")

REVIEW_WORKFLOW = """\
name: canonical_v6
version: 1
regista_version: "0.5.0"

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
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
"""


@pytest.fixture
def epoch(tmp_path_factory):
    keyset = make_v6_keyset(
        tmp_path_factory.mktemp("gate_keys"), principals=REVIEW_PRINCIPALS
    )
    project = f"wi305_gate_{uuid.uuid4().hex[:8]}"
    from regista import Regista

    sub = Regista.create_project(DSN, project, keyset.path)
    try:
        open_v6_epoch(sub, keyset, principals=REVIEW_PRINCIPALS)
        sub.register_workflow(REVIEW_WORKFLOW)
        yield sub
    finally:
        sub.close()
        drop_project_schema(DSN, project)


_PRODUCER_MODELS = {
    "fable": "claude-fable-5",
    "glm": "glm-5.3",
    "kimi": "kimi-k2.5",
}


def _set_producer(lineage: str | None, *, model: str | None = None) -> None:
    set_v6_producer_env(
        Producer(
            harness="claude-code",
            harness_version="test-harness/1",
            model=model if model is not None else _PRODUCER_MODELS.get(lineage),
            model_lineage=lineage,
        ),
        overwrite=True,
    )


def _work_to_review(sub, *, author_lineage: str = "fable") -> uuid.UUID:
    _set_producer(author_lineage)
    wi, _ = sub.create_work_item(
        workflow_name="canonical_v6",
        work_item_type="issue",
        actor_id="agent:author",
        actor_kind="agent",
        custom_fields={"title": "wi305 gate"},
    )
    sub.transition(wi.work_item_id, "start", "agent:author", actor_kind="agent")
    sub.transition(
        wi.work_item_id, "submit_for_review", "agent:author", actor_kind="agent"
    )
    return wi.work_item_id


def _pass(
    sub,
    wi_id,
    *,
    lineage: str,
    ack: bool = False,
    payload_claim: str | None = None,
) -> None:
    _set_producer(lineage)
    payload = {"review_note": "adversarial review: checked the diff"}
    if ack:
        payload["same_lineage_acknowledged"] = True
    if payload_claim is not None:
        payload["reviewer_claims"] = {"model_lineage": payload_claim}
    sub.transition(
        wi_id,
        "adversarial_pass",
        "agent:reviewer",
        actor_kind="agent",
        payload=payload,
    )


class TestCrossLineageGateOverV6:
    def test_distinct_payload_lineage_passes(self, epoch) -> None:
        wi_id = _work_to_review(epoch)
        _pass(epoch, wi_id, lineage="glm")
        refreshed = epoch.get_work_item(wi_id)
        assert refreshed is not None
        assert refreshed.current_state == "done"

    def test_same_lineage_reviewer_is_blocked_until_ack(self, epoch) -> None:
        wi_id = _work_to_review(epoch)
        with pytest.raises(RegistaError) as exc_info:
            _pass(epoch, wi_id, lineage="fable")
        assert exc_info.value.code == ErrorCode.VALIDATOR_FAILED

        wi_id2 = _work_to_review(epoch)
        _pass(epoch, wi_id2, lineage="fable", ack=True)

    def test_assurance_reflects_the_cross_lineage_verdict(self, epoch) -> None:
        from regista._assurance import AssuranceLevel, compute_assurance_level

        wi_id = _work_to_review(epoch)
        _pass(epoch, wi_id, lineage="glm")
        events = epoch.read_events(work_item_id=wi_id, limit=1000)
        level = compute_assurance_level(events)
        assert level is AssuranceLevel.INDEPENDENTLY_REVIEWED


class TestV6ProducerOnlyReviewerLineage:
    def test_positive_review_uses_signed_producer_only(self, epoch) -> None:
        wi_id = _work_to_review(epoch, author_lineage="fable")
        _pass(epoch, wi_id, lineage="glm")
        refreshed = epoch.get_work_item(wi_id)
        assert refreshed is not None
        assert refreshed.current_state == "done"
        event = epoch.read_events(work_item_id=wi_id, transition="adversarial_pass")[0]
        assert event.payload == {"review_note": "adversarial review: checked the diff"}
        assert json.loads(event.canonical_envelope)["producer"]["model_lineage"] == "glm"

    def test_payload_lineage_cannot_override_same_signed_producer(self, epoch) -> None:
        wi_id = _work_to_review(epoch, author_lineage="glm")
        with pytest.raises(RegistaError) as exc_info:
            _pass(epoch, wi_id, lineage="glm", payload_claim="kimi")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        refreshed = epoch.get_work_item(wi_id)
        assert refreshed is not None
        assert refreshed.current_state == "in_review"

    def test_v6_review_without_model_producer_fails_closed(self, epoch) -> None:
        wi_id = _work_to_review(epoch, author_lineage="fable")
        _set_producer(None, model=None)
        with pytest.raises(RegistaError) as exc_info:
            epoch.transition(
                wi_id,
                "adversarial_pass",
                "agent:reviewer",
                actor_kind="agent",
                payload={"review_note": "no model producer"},
            )
        assert exc_info.value.code == ErrorCode.INVALID_MODEL_LINEAGE


class TestV6PrincipalBindingVerifiedExecutesAcceptanceChain:
    def test_an_empty_v6_epoch_does_not_claim_binding_from_project_identity(
        self, epoch
    ) -> None:
        report = epoch.replay()
        assert report.halted == 0, report.to_dict()
        assert report.principal_binding_verified is False

    @pytest.mark.parametrize("flag", [False, True])
    def test_a_clean_v6_epoch_reports_acceptance_binding_executed(
        self, epoch, flag
    ) -> None:
        wi_id = _work_to_review(epoch)
        _pass(epoch, wi_id, lineage="glm")
        report = epoch.replay(verify_principal_binding=flag)
        assert report.halted == 0, report.to_dict()
        assert report.principal_binding_failures == 0
        assert report.principal_binding_verified is True

    def test_a_halted_v6_replay_does_not_claim_an_earlier_binding_check(
        self, epoch
    ) -> None:
        wi_id = _work_to_review(epoch)
        _pass(epoch, wi_id, lineage="glm")
        with epoch._mgr.transaction() as conn:
            conn.execute(
                "UPDATE events SET canonical_envelope = NULL WHERE work_item_id = %s",
                [wi_id],
            )

        report = epoch.replay()
        assert report.halted == 1, report.to_dict()
        assert report.principal_binding_verified is False
