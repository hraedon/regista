"""Assurance over a real v6 epoch uses signed producer lineage only."""

from __future__ import annotations

import uuid

import pytest
from _helpers import DSN

from regista import Regista
from regista._assurance import (
    AssuranceLevel,
    compute_assurance_level_from_dicts,
    gate_permits_done,
)
from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema
from tests._v6_fixtures import (
    Producer,
    make_v6_keyset,
    open_v6_epoch,
    set_v6_producer_env,
)

AUTHOR = "agent:author"
REVIEWER = "agent:reviewer"
AGENT_ACCEPTOR = "agent:acceptor"
HUMAN_ACCEPTOR = "human:operator"
AUTHOR_LINEAGE = "fable"
DISTINCT_LINEAGE = "glm"

ASSURANCE_PRINCIPALS = (AUTHOR, REVIEWER, AGENT_ACCEPTOR, HUMAN_ACCEPTOR)

PRODUCER_MODELS = {
    AUTHOR_LINEAGE: "claude-fable-5",
    DISTINCT_LINEAGE: "glm-5.3",
}


def _set_producer(lineage: str | None, *, model: str | None = None) -> None:
    set_v6_producer_env(
        Producer(
            harness="claude-code",
            harness_version="test-harness/1",
            model=(model if model is not None else PRODUCER_MODELS[lineage]),
            model_lineage=lineage,
        ),
        overwrite=True,
    )

ASSURANCE_WORKFLOW = """\
name: v6_assurance
version: 1
regista_version: "0.5.0"

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
  - name: accept
    from: in_human_review
    to: done
    validator: human_gate
    validator_params:
      require_human: false
  - name: close_from_open
    from: open
    to: done

roles: []

work_item_types:
  - name: issue
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
"""

STRICT_ASSURANCE_WORKFLOW = ASSURANCE_WORKFLOW.replace(
    'name: v6_assurance\n', 'name: v6_assurance_strict\n'
).replace(
    '      require_human: false\n',
    '      require_human: false\n      require_human_on_same_lineage: true\n',
)


@pytest.fixture
def epoch(tmp_path_factory):
    keyset = make_v6_keyset(
        tmp_path_factory.mktemp("wi305_assurance"),
        principals=ASSURANCE_PRINCIPALS,
    )
    project = f"wi305_assurance_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    try:
        open_v6_epoch(sub, keyset, principals=ASSURANCE_PRINCIPALS)
        sub.register_workflow(ASSURANCE_WORKFLOW)
        sub.register_workflow(STRICT_ASSURANCE_WORKFLOW)
        yield sub
    finally:
        sub.close()
        drop_project_schema(DSN, project)


def _setup_to_review(sub: Regista, *, workflow: str = "v6_assurance") -> uuid.UUID:
    _set_producer(AUTHOR_LINEAGE)
    work_item, _ = sub.create_work_item(
        workflow_name=workflow,
        work_item_type="issue",
        actor_id=AUTHOR,
        actor_kind="agent",
        custom_fields={"title": "v6 assurance"},
    )
    sub.transition(work_item.work_item_id, "start", AUTHOR, actor_kind="agent")
    sub.transition(
        work_item.work_item_id,
        "submit_for_review",
        AUTHOR,
        actor_kind="agent",
    )
    return work_item.work_item_id


def _pass(
    sub: Regista,
    work_item_id: uuid.UUID,
    *,
    lineage: str,
    acknowledged: bool = False,
) -> None:
    _set_producer(lineage)
    payload: dict[str, object] = {
        "review_note": "v6 adversarial review: checked the diff",
    }
    if acknowledged:
        payload["same_lineage_acknowledged"] = True
    sub.transition(
        work_item_id,
        "adversarial_pass",
        REVIEWER,
        actor_kind="agent",
        payload=payload,
    )


def _accept(
    sub: Regista,
    work_item_id: uuid.UUID,
    *,
    human: bool,
) -> None:
    actor_id = HUMAN_ACCEPTOR if human else AGENT_ACCEPTOR
    actor_kind = "human" if human else "agent"
    sub.transition(
        work_item_id,
        "accept",
        actor_id,
        actor_kind=actor_kind,
        payload={"review_note": "v6 acceptance"},
    )


class TestV6ComputeAssuranceAPI:
    """The sixteen retired API nodes, with signed v6 review evidence."""

    def test_assurance_at_creation(self, epoch: Regista) -> None:
        work_item, _ = epoch.create_work_item(
            workflow_name="v6_assurance",
            work_item_type="issue",
            actor_id=AUTHOR,
            actor_kind="agent",
            custom_fields={"title": "v6 assurance"},
        )
        assert epoch.compute_assurance(work_item.work_item_id) is AssuranceLevel.NONE

    def test_assurance_in_review(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.NONE

    def test_assurance_after_cross_lineage_pass(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_dict_assurance_reads_the_signed_producer_envelope(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        events = epoch.read_events(work_item_id=work_item_id, limit=1000)
        assert compute_assurance_level_from_dicts(
            [event.to_dict() for event in events]
        ) is AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_assurance_after_same_lineage_pass(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.SELF_REVIEWED

    def test_assurance_after_cross_lineage_agent_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        _accept(epoch, work_item_id, human=False)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_assurance_after_cross_lineage_human_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        _accept(epoch, work_item_id, human=True)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.INDEPENDENT_AND_ACCEPTED

    def test_assurance_after_same_lineage_human_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        _accept(epoch, work_item_id, human=True)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.HUMAN_ACCEPTED

    def test_assurance_after_same_lineage_agent_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        _accept(epoch, work_item_id, human=False)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.SELF_REVIEWED

    def test_assurance_close_from_open(self, epoch: Regista) -> None:
        work_item, _ = epoch.create_work_item(
            workflow_name="v6_assurance",
            work_item_type="issue",
            actor_id=AUTHOR,
            actor_kind="agent",
            custom_fields={"title": "v6 assurance"},
        )
        epoch.transition(
            work_item.work_item_id,
            "close_from_open",
            AUTHOR,
            actor_kind="agent",
        )
        assert epoch.compute_assurance(work_item.work_item_id) is AssuranceLevel.NONE

    def test_gate_rationale_via_api(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        rationale = epoch.gate_rationale(work_item_id, profile="relaxed")
        assert rationale["reason"] == "not_done"
        assert rationale["reviewer_lineage"] == DISTINCT_LINEAGE
        assert rationale["author_lineages"] == [AUTHOR_LINEAGE]

    def test_gate_rationale_strict_profile(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch)
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        _accept(epoch, work_item_id, human=False)
        rationale = epoch.gate_rationale(work_item_id, profile="strict")
        assert rationale["reason"] == "same_lineage_acknowledged"
        assert gate_permits_done(rationale) is False

    def test_strict_workflow_rejects_same_lineage_agent_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        with pytest.raises(RegistaError, match="human acceptor"):
            _accept(epoch, work_item_id, human=False)

    def test_strict_workflow_allows_cross_lineage_agent_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _pass(epoch, work_item_id, lineage=DISTINCT_LINEAGE)
        _accept(epoch, work_item_id, human=False)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.INDEPENDENTLY_REVIEWED

    def test_strict_workflow_allows_same_lineage_human_accept(self, epoch: Regista) -> None:
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        _accept(epoch, work_item_id, human=True)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.HUMAN_ACCEPTED

    def test_strict_workflow_rejects_undeclared_reviewer_agent_accept(
        self, epoch: Regista
    ) -> None:
        # v6 does not permit an undeclared reviewer claim: the canonical signed
        # counterpart is an explicit same-lineage claim, which still requires a
        # human acceptor under the strict profile.
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        with pytest.raises(RegistaError, match="human acceptor"):
            _accept(epoch, work_item_id, human=False)

    def test_strict_workflow_allows_undeclared_reviewer_human_accept(
        self, epoch: Regista
    ) -> None:
        # As above, the v6 vehicle makes the conservative claim explicit in the
        # signed payload; a human can acknowledge that same-lineage review.
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _pass(epoch, work_item_id, lineage=AUTHOR_LINEAGE, acknowledged=True)
        _accept(epoch, work_item_id, human=True)
        assert epoch.compute_assurance(work_item_id) is AssuranceLevel.HUMAN_ACCEPTED


class TestV6ReviewerProducerIngress:
    def test_payload_reviewer_lineage_is_rejected_as_obsolete(
        self, epoch: Regista
    ) -> None:
        work_item_id = _setup_to_review(epoch, workflow="v6_assurance_strict")
        _set_producer(DISTINCT_LINEAGE)
        with pytest.raises(RegistaError) as exc_info:
            epoch.transition(
                work_item_id,
                "adversarial_pass",
                REVIEWER,
                actor_kind="agent",
                payload={
                    "review_note": "obsolete payload claim",
                    "reviewer_claims": {"model_lineage": "kimi"},
                },
            )
        assert exc_info.value.code is ErrorCode.INVALID_ARGUMENT
