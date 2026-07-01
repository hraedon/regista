"""WI-1 (dossier Plan 010) — the canonical workflow shipped from regista.

regista ships ONE canonical lifecycle workflow that both faces (dossier,
agent-notes) register verbatim, so a single work-item is governed by one shared
workflow. These tests assert it parses, is exported, registers idempotently, and
supports the north star: one item carrying agent work + a human accept to `done`.
"""

from __future__ import annotations

from pathlib import Path

import regista
from regista import canonical_workflow_yaml, parse_and_validate
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")
REVIEW_NOTE = {"review_note": "looks good"}


def test_canonical_yaml_parses_and_validates():
    wf = parse_and_validate(canonical_workflow_yaml())
    assert wf.name == "canonical"
    assert wf.version == 2
    assert set(wf.states) == {
        "open", "in_progress", "blocked", "deferred",
        "in_review", "in_human_review", "done",
    }
    assert set(wf.roles) == {"human", "agent", "system"}
    assert {t.name for t in wf.work_item_types} == {"breadcrumb", "bug", "task"}


def test_canonical_exported_at_top_level():
    assert regista.canonical_workflow_yaml() == canonical_workflow_yaml()


def test_canonical_registers_idempotently():
    # Both faces registering the same bytes against one project must be a no-op
    # the second time.
    sub = InMemoryRegista(project="test_canonical_idem", hmac_key_path=KEY_PATH)
    sub.register_workflow(canonical_workflow_yaml())
    sub.register_workflow(canonical_workflow_yaml())


def test_canonical_supports_mixed_agent_human_chain_to_done():
    """The north star at the regista level: one item, agent work + human accept."""
    sub = InMemoryRegista(project="test_canonical_chain", hmac_key_path=KEY_PATH)
    sub.register_workflow(canonical_workflow_yaml())

    # Agent (glm lineage) creates and works a breadcrumb item.
    wi, _ = sub.create_work_item(
        workflow_name="canonical",
        work_item_type="breadcrumb",
        actor_id="glm-agent",
        actor_kind="agent",
        actor_metadata={"model_lineage": "glm", "role": "agent"},
        custom_fields={"title": "converge the workflow"},
    )
    aid = wi.work_item_id
    glm = {"actor_kind": "agent", "actor_metadata": {"model_lineage": "glm", "role": "agent"}}
    sub.transition(aid, "start", "glm-agent", **glm)
    sub.transition(aid, "submit_for_review", "glm-agent", **glm)

    # A cross-lineage agent reviewer (kimi) passes the adversarial gate.
    sub.transition(
        aid, "adversarial_pass", "kimi-agent",
        actor_kind="agent", actor_metadata={"model_lineage": "kimi", "role": "agent"},
        payload=REVIEW_NOTE,
    )

    # A human accepts (relaxed gate; the accepter is distinct from every author).
    sub.transition(
        aid, "accept", "paul",
        actor_kind="human", actor_metadata={"role": "human"}, payload=REVIEW_NOTE,
    )

    final = sub.get_work_item(aid)
    assert final is not None
    assert final.current_state == "done"

    # The chain is genuinely mixed: agent author(s) + a human accepter.
    kinds = {e.actor_kind for e in sub.read_events(work_item_id=aid)}
    assert {"agent", "human"} <= kinds
