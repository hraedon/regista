"""WI-1 (dossier Plan 010) — the canonical workflow shipped from regista.

regista ships ONE canonical lifecycle workflow that both faces (dossier,
agent-notes) register verbatim, so a single work-item is governed by one shared
workflow. These tests assert it parses, is exported, registers idempotently, and
supports the north star: one item carrying agent work + a human accept to `done`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import regista
from regista import canonical_workflow_yaml, parse_and_validate
from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")
REVIEW_NOTE = {"review_note": "looks good"}
V6_PRINCIPALS = ("agent:author", "agent:glm-agent", "agent:kimi-agent", "human:paul")


def _v6_sub(tmp_path: Path, project: str) -> InMemoryRegista:
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    keyset = make_v6_keyset(tmp_path, principals=V6_PRINCIPALS)
    sub = InMemoryRegista(project=project, hmac_key_path=keyset.path)
    open_v6_epoch(sub, keyset, principals=V6_PRINCIPALS)
    return sub


def test_canonical_yaml_parses_and_validates():
    wf = parse_and_validate(canonical_workflow_yaml())
    assert wf.name == "canonical"
    assert wf.version == 3
    assert set(wf.states) == {
        "open", "in_progress", "blocked", "deferred",
        "in_review", "in_human_review", "done",
    }
    assert set(wf.roles) == {"human", "agent", "system"}
    assert {t.name for t in wf.work_item_types} == {"breadcrumb", "bug", "task"}


def test_request_changes_records_findings_without_claiming_independence():
    wf = parse_and_validate(canonical_workflow_yaml())
    transition = next(t for t in wf.transitions if t.name == "request_changes")

    assert transition.validator == "adversarial_review"
    assert transition.validator_params == {"finding_only": True}


def test_canonical_exported_at_top_level():
    assert regista.canonical_workflow_yaml() == canonical_workflow_yaml()


def test_canonical_registers_idempotently():
    # Both faces registering the same bytes against one project must be a no-op
    # the second time.
    sub = InMemoryRegista(project="test_canonical_idem", hmac_key_path=KEY_PATH)
    sub.register_workflow(canonical_workflow_yaml())
    sub.register_workflow(canonical_workflow_yaml())


def _canonical_item_in_review(sub: InMemoryRegista):
    wi, _ = sub.create_work_item(
        workflow_name="canonical",
        work_item_type="breadcrumb",
        actor_id="agent:author",
        actor_kind="agent",
        actor_metadata={"role": "agent"},
        custom_fields={"title": "finding path"},
    )
    identity = {
        "actor_kind": "agent",
        "actor_metadata": {"role": "agent"},
    }
    sub.transition(wi.work_item_id, "start", "agent:author", **identity)
    sub.transition(wi.work_item_id, "submit_for_review", "agent:author", **identity)
    return wi.work_item_id, identity


def test_canonical_request_changes_runs_note_requirement_end_to_end(tmp_path: Path):
    sub = _v6_sub(tmp_path, "test_canonical_findings")
    sub.register_workflow(canonical_workflow_yaml())
    wi_id, identity = _canonical_item_in_review(sub)

    sub.transition(
        wi_id,
        "request_changes",
        "agent:author",
        payload={"review_note": "The failure path is not transactional."},
        **identity,
    )
    assert sub.get_work_item(wi_id).current_state == "in_progress"


def test_canonical_request_changes_without_note_fails_closed(tmp_path: Path):
    sub = _v6_sub(tmp_path, "test_canonical_finding_note")
    sub.register_workflow(canonical_workflow_yaml())
    wi_id, identity = _canonical_item_in_review(sub)

    with pytest.raises(RegistaError, match="non-empty review note"):
        sub.transition(
            wi_id,
            "request_changes",
            "agent:author",
            payload={},
            **identity,
        )


@pytest.mark.parametrize("workflow_version", [1, 2])
def test_persisted_canonical_request_changes_uses_finding_semantics(
    workflow_version: int, tmp_path: Path,
):
    legacy = canonical_workflow_yaml().replace(
        "version: 3", f"version: {workflow_version}", 1
    ).replace(
        "    validator_params:\n      finding_only: true\n", "", 1
    )
    sub = _v6_sub(tmp_path, f"test_canonical_v{workflow_version}_finding")
    sub.register_workflow(legacy)
    wi_id, identity = _canonical_item_in_review(sub)

    sub.transition(
        wi_id,
        "request_changes",
        "agent:author",
        payload={"review_note": "The failure path is not transactional."},
        **identity,
    )
    assert sub.get_work_item(wi_id).current_state == "in_progress"


def test_missing_builtin_validator_fails_closed_in_memory(tmp_path: Path):
    sub = _v6_sub(tmp_path, "test_canonical_missing_validator")
    sub.register_workflow(canonical_workflow_yaml())
    sub._validators.pop("adversarial_review")
    wi_id, identity = _canonical_item_in_review(sub)

    with pytest.raises(RegistaError) as exc_info:
        sub.transition(
            wi_id,
            "request_changes",
            "agent:author",
            payload=REVIEW_NOTE,
            **identity,
        )
    assert exc_info.value.code == ErrorCode.VALIDATOR_NOT_REGISTERED
    assert sub.get_work_item(wi_id).current_state == "in_review"


def test_canonical_supports_mixed_agent_human_chain_to_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The north star at the regista level: one item, agent work + human accept."""
    sub = _v6_sub(tmp_path, "test_canonical_chain")
    sub.register_workflow(canonical_workflow_yaml())
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-model")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "glm")

    # Agent (glm lineage) creates and works a breadcrumb item.
    wi, _ = sub.create_work_item(
        workflow_name="canonical",
        work_item_type="breadcrumb",
        actor_id="agent:glm-agent",
        actor_kind="agent",
        actor_metadata={"role": "agent"},
        custom_fields={"title": "converge the workflow"},
    )
    aid = wi.work_item_id
    glm = {"actor_kind": "agent", "actor_metadata": {"role": "agent"}}
    sub.transition(aid, "start", "agent:glm-agent", **glm)
    sub.transition(aid, "submit_for_review", "agent:glm-agent", **glm)

    # A cross-lineage agent reviewer (kimi) passes the adversarial gate.
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "kimi-k2.5")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "kimi")
    sub.transition(
        aid, "adversarial_pass", "agent:kimi-agent",
        actor_kind="agent", actor_metadata={"role": "agent"},
        payload=REVIEW_NOTE,
    )

    # A human accepts (relaxed gate; the accepter is distinct from every author).
    monkeypatch.delenv("REGISTA_PRODUCER_MODEL", raising=False)
    monkeypatch.delenv("REGISTA_PRODUCER_MODEL_LINEAGE", raising=False)
    sub.transition(
        aid, "accept", "human:paul",
        actor_kind="human", actor_metadata={"role": "human"}, payload=REVIEW_NOTE,
    )

    final = sub.get_work_item(aid)
    assert final is not None
    assert final.current_state == "done"

    # The chain is genuinely mixed: agent author(s) + a human accepter.
    kinds = {e.actor_kind for e in sub.read_events(work_item_id=aid)}
    assert {"agent", "human"} <= kinds
