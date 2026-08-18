from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _helpers import DSN

from regista._errors import RegistaError
from regista.testing import drop_project_schema
from tests._v6_fixtures import ACTOR_PRINCIPALS, make_v6_keyset, open_v6_epoch

TESTS_DIR = Path(__file__).parent
PHASE1_PATH = str(TESTS_DIR / "fixtures" / "sf2_phase1.yaml")
FULL_PIPELINE_PATH = str(TESTS_DIR / "fixtures" / "sf2_full_pipeline.yaml")


#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
#: One id per role the SF2 workflows gate on, plus the two extra architects the
#: escalation case needs as *distinct* claimants, plus the unauthorised actor.
ARCHITECT = "agent:architect"
ARCHITECT_B = "agent:architect-b"
ARCHITECT_C = "agent:architect-c"
GATE = "agent:gate"
IMPLEMENTER = "agent:implementer"
TEST_AUTHOR = "agent:test-author"
INTRUDER = "agent:intruder"

#: Passed to BOTH `make_v6_keyset` and `open_v6_epoch`, identical: a key on file is
#: not a project-local acceptance, so an id present in only one of the two lists is
#: refused with KEY_BINDING_UNRESOLVED (`_v6_fixtures.open_v6_epoch`, §5.11).
SF2_PRINCIPALS = (
    *ACTOR_PRINCIPALS,
    ARCHITECT,
    ARCHITECT_B,
    ARCHITECT_C,
    GATE,
    IMPLEMENTER,
    TEST_AUTHOR,
    INTRUDER,
)


@pytest.fixture(scope="function")
def regista(tmp_path):
    from regista import Regista

    project = f"test_sf2_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path, principals=SF2_PRINCIPALS)
    sub = Regista.create_project(DSN, project, keyset.path)
    # The epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset, principals=SF2_PRINCIPALS)
    sub.register_workflow_file(PHASE1_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


#: The ``unmigrated_regista`` fixture is gone. It existed for exactly one node —
#: ``test_attempt_threshold_drives_escalation`` — because ``_claims.py``'s
#: auto-escalation appended its ``escalated`` event as the bare literal
#: ``"system"``, which no keyset can bind (``ACTOR_SIGNER_MISMATCH``). Its own
#: docstring named the condition for its removal: "migrate it in the same change
#: that gives escalation a v6 principal." ``_events.resolve_system_actor_id`` is
#: that change, so the node runs on the ordinary migrated ``regista`` fixture and
#: the last-resort pattern is retired instead of inherited.


class TestSF2WorkflowRoundtripV1:
    def test_phase1_interface_spec_lifecycle(self, regista):
        regista.register_actor_role(ARCHITECT, "interface_architect")
        regista.register_actor_role(GATE, "mechanical_gate")

        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id=ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01", "AC-02"],
                "artifact_path": "/tmp/spec.md",
            },
        )
        assert wi.current_state == "new"
        assert wi.workflow_version == 1

        regista.transition(
            wi.work_item_id, "claim", ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
        )
        after_claim = regista.get_work_item(wi.work_item_id)
        assert after_claim.current_state == "in_progress"

        regista.transition(
            wi.work_item_id, "submit", ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={"artifact_hash": "sha256:abc"},
        )
        after_submit = regista.get_work_item(wi.work_item_id)
        assert after_submit.current_state == "gating"
        assert after_submit.custom_fields.get("artifact_hash") == "sha256:abc"

        regista.transition(
            wi.work_item_id, "gate_pass", GATE,
            actor_kind="agent",
            actor_metadata={"role": "mechanical_gate"},
        )
        after_gate = regista.get_work_item(wi.work_item_id)
        assert after_gate.current_state == "locked"

    def test_phase1_create_missing_required_field_rejected(self, regista):
        regista.register_actor_role(ARCHITECT, "interface_architect")
        with pytest.raises(RegistaError, match="CUSTOM_FIELD_VIOLATION"):
            regista.create_work_item(
                workflow_name="software_factory",
                work_item_type="interface_spec",
                actor_id=ARCHITECT,
                actor_kind="agent",
                actor_metadata={"role": "interface_architect"},
                custom_fields={
                    "artifact_path": "/tmp/spec.md",
                },
            )

    def test_role_gating_rejects_unauthorized(self, regista):
        regista.register_actor_role(ARCHITECT, "interface_architect")
        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id=ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )
        with pytest.raises(RegistaError, match="ROLE_NOT_PERMITTED"):
            regista.transition(
                wi.work_item_id, "claim", INTRUDER,
                actor_kind="agent",
                actor_metadata={"role": "mechanical_gate"},
            )

    def test_attempt_threshold_drives_escalation(self, regista):
        a, b, c = ARCHITECT, ARCHITECT_B, ARCHITECT_C
        regista.register_actor_role(a, "interface_architect")
        regista.register_actor_role(b, "interface_architect")
        regista.register_actor_role(c, "interface_architect")

        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id=a,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )

        regista.acquire_claim(wi.work_item_id, a, ttl_seconds=1)
        import time
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, b, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, c, ttl_seconds=1)

        final = regista.get_work_item(wi.work_item_id)
        assert final.needs_review is True


class TestSF2WorkflowRoundtripV2:
    def test_both_yamls_register_without_error(self, regista):
        v2 = regista.register_workflow_file(FULL_PIPELINE_PATH)
        assert v2.name == "software_factory"
        assert v2.version == 2

    def test_version_pinning_across_v1_v2(self, regista):
        regista.register_actor_role(ARCHITECT, "interface_architect")
        regista.register_actor_role(IMPLEMENTER, "implementer")
        regista.register_actor_role(TEST_AUTHOR, "test_author")

        wi1, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id=ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )
        assert wi1.workflow_version == 1

        regista.register_workflow_file(FULL_PIPELINE_PATH)

        ts, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="test_suite",
            actor_id=TEST_AUTHOR,
            actor_kind="agent",
            actor_metadata={"role": "test_author"},
            custom_fields={
                "interface_ref": str(wi1.work_item_id),
                "ac_coverage": ["AC-01"],
            },
        )

        wi2, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="implementation",
            actor_id=IMPLEMENTER,
            actor_kind="agent",
            actor_metadata={"role": "implementer"},
            custom_fields={
                "interface_ref": str(wi1.work_item_id),
                "test_suite_ref": str(ts.work_item_id),
            },
        )
        assert wi2.workflow_version == 2

        regista.transition(
            wi2.work_item_id, "claim", IMPLEMENTER,
            actor_kind="agent",
            actor_metadata={"role": "implementer"},
        )
        after_claim = regista.get_work_item(wi2.work_item_id)
        assert after_claim.current_state == "in_progress"

        with pytest.raises(RegistaError, match="ROLE_NOT_PERMITTED"):
            regista.transition(
                wi1.work_item_id, "claim", IMPLEMENTER,
                actor_kind="agent",
                actor_metadata={"role": "implementer"},
            )

    def test_full_pipeline_link_types(self, regista):
        regista.register_workflow_file(FULL_PIPELINE_PATH)
        regista.register_actor_role(ARCHITECT, "interface_architect")
        regista.register_actor_role(IMPLEMENTER, "implementer")
        regista.register_actor_role(TEST_AUTHOR, "test_author")

        wi1, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id=ARCHITECT,
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )
        ts, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="test_suite",
            actor_id=TEST_AUTHOR,
            actor_kind="agent",
            actor_metadata={"role": "test_author"},
            custom_fields={
                "interface_ref": str(wi1.work_item_id),
                "ac_coverage": ["AC-01"],
            },
        )
        wi2, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="implementation",
            actor_id=IMPLEMENTER,
            actor_kind="agent",
            actor_metadata={"role": "implementer"},
            custom_fields={
                "interface_ref": str(wi1.work_item_id),
                "test_suite_ref": str(ts.work_item_id),
            },
        )

        link = regista.create_link(
            from_work_item_id=wi2.work_item_id,
            to_work_item_id=wi1.work_item_id,
            link_type="implements",
            actor_id=IMPLEMENTER,
            actor_kind="agent",
        )
        assert link.link_type == "implements"

        items = regista.query_work_items(
            workflow_name="software_factory",
            has_link_type="implements",
        )
        assert len(items.items) == 1
