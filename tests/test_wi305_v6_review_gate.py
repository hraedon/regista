"""WI-305 A v6 counterparts: the cross-lineage review gate over a genuine v6 epoch.

The retired pre-epoch review nodes recorded author and reviewer lineage in
``actor_metadata.model_lineage``, which the v6 envelope refuses at ingress
(producer fields must not appear in actor.metadata, ``V6-ENVELOPE.md`` §1.8).
This file pins the same surviving invariants over the v6 vehicles:

* author lineage rides the process-level ``producer`` block (one value per
  process, resolved from the environment);
* reviewer lineage is a canonical assertion in the signed verdict payload's
  ``reviewer_claims.model_lineage`` (``REVIEW-VERDICTS.md`` §2.2).

The gate therefore decides cross-lineage distinctness by comparing the author
producer lineages against the reviewer's payload claim. A claimed, worked item
whose reviewer declares a distinct lineage passes; a same-lineage reviewer is
blocked until acknowledged; assurance over the chain reflects the verdict.
"""

from __future__ import annotations

import uuid

import pytest
from _helpers import DSN

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema
from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

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


def _work_to_review(sub) -> uuid.UUID:
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


def _pass(sub, wi_id, *, lineage, ack=False) -> None:
    claims = {"model_lineage": lineage}
    payload = {"review_note": "adversarial review: checked the diff"}
    if ack:
        payload["same_lineage_acknowledged"] = True
    payload["reviewer_claims"] = claims
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


class TestIngressRejectsNoncanonicalReviewerLineage:
    def test_unknown_lineage_in_verdict_payload_is_rejected(self, epoch) -> None:
        from regista._lineage import require_canonical_reviewer_lineage

        with pytest.raises(RegistaError) as exc_info:
            require_canonical_reviewer_lineage(
                {"reviewer_claims": {"model_lineage": "not-a-family"}}
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
