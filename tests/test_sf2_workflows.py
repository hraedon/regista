from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
PHASE1_PATH = str(TESTS_DIR / "fixtures" / "sf2_phase1.yaml")
FULL_PIPELINE_PATH = str(TESTS_DIR / "fixtures" / "sf2_full_pipeline.yaml")


@pytest.fixture(scope="function")
def regista():
    from regista import Regista

    project = f"test_sf2_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(PHASE1_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestSF2WorkflowRoundtripV1:
    def test_phase1_interface_spec_lifecycle(self, regista):
        regista.register_actor_role("arch-1", "interface_architect")
        regista.register_actor_role("gate-1", "mechanical_gate")

        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id="arch-1",
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
            wi.work_item_id, "claim", "arch-1",
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
        )
        after_claim = regista.get_work_item(wi.work_item_id)
        assert after_claim.current_state == "in_progress"

        regista.transition(
            wi.work_item_id, "submit", "arch-1",
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={"artifact_hash": "sha256:abc"},
        )
        after_submit = regista.get_work_item(wi.work_item_id)
        assert after_submit.current_state == "gating"
        assert after_submit.custom_fields.get("artifact_hash") == "sha256:abc"

        regista.transition(
            wi.work_item_id, "gate_pass", "gate-1",
            actor_kind="agent",
            actor_metadata={"role": "mechanical_gate"},
        )
        after_gate = regista.get_work_item(wi.work_item_id)
        assert after_gate.current_state == "locked"

    def test_phase1_create_missing_required_field_rejected(self, regista):
        regista.register_actor_role("arch-2", "interface_architect")
        with pytest.raises(RegistaError, match="CUSTOM_FIELD_VIOLATION"):
            regista.create_work_item(
                workflow_name="software_factory",
                work_item_type="interface_spec",
                actor_id="arch-2",
                actor_kind="agent",
                actor_metadata={"role": "interface_architect"},
                custom_fields={
                    "artifact_path": "/tmp/spec.md",
                },
            )

    def test_role_gating_rejects_unauthorized(self, regista):
        regista.register_actor_role("arch-3", "interface_architect")
        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id="arch-3",
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )
        with pytest.raises(RegistaError, match="ROLE_NOT_PERMITTED"):
            regista.transition(
                wi.work_item_id, "claim", "intruder-1",
                actor_kind="agent",
                actor_metadata={"role": "mechanical_gate"},
            )

    def test_attempt_threshold_drives_escalation(self, regista):
        regista.register_actor_role("arch-4a", "interface_architect")
        regista.register_actor_role("arch-4b", "interface_architect")
        regista.register_actor_role("arch-4c", "interface_architect")

        wi, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id="arch-4a",
            actor_kind="agent",
            actor_metadata={"role": "interface_architect"},
            custom_fields={
                "spec_section": "3.1",
                "ac_ids": ["AC-01"],
            },
        )

        regista.acquire_claim(wi.work_item_id, "arch-4a", ttl_seconds=1)
        import time
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, "arch-4b", ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, "arch-4c", ttl_seconds=1)

        final = regista.get_work_item(wi.work_item_id)
        assert final.needs_review is True


class TestSF2WorkflowRoundtripV2:
    def test_both_yamls_register_without_error(self, regista):
        v2 = regista.register_workflow_file(FULL_PIPELINE_PATH)
        assert v2.name == "software_factory"
        assert v2.version == 2

    def test_version_pinning_across_v1_v2(self, regista):
        regista.register_actor_role("arch-5", "interface_architect")
        regista.register_actor_role("imp-5", "implementer")
        regista.register_actor_role("ta-5", "test_author")

        wi1, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id="arch-5",
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
            actor_id="ta-5",
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
            actor_id="imp-5",
            actor_kind="agent",
            actor_metadata={"role": "implementer"},
            custom_fields={
                "interface_ref": str(wi1.work_item_id),
                "test_suite_ref": str(ts.work_item_id),
            },
        )
        assert wi2.workflow_version == 2

        regista.transition(
            wi2.work_item_id, "claim", "imp-5",
            actor_kind="agent",
            actor_metadata={"role": "implementer"},
        )
        after_claim = regista.get_work_item(wi2.work_item_id)
        assert after_claim.current_state == "in_progress"

        with pytest.raises(RegistaError, match="ROLE_NOT_PERMITTED"):
            regista.transition(
                wi1.work_item_id, "claim", "imp-5",
                actor_kind="agent",
                actor_metadata={"role": "implementer"},
            )

    def test_full_pipeline_link_types(self, regista):
        regista.register_workflow_file(FULL_PIPELINE_PATH)
        regista.register_actor_role("arch-6", "interface_architect")
        regista.register_actor_role("imp-6", "implementer")
        regista.register_actor_role("ta-6", "test_author")

        wi1, _ = regista.create_work_item(
            workflow_name="software_factory",
            work_item_type="interface_spec",
            actor_id="arch-6",
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
            actor_id="ta-6",
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
            actor_id="imp-6",
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
            actor_id="imp-6",
            actor_kind="agent",
        )
        assert link.link_type == "implements"

        items = regista.query_work_items(
            workflow_name="software_factory",
            has_link_type="implements",
        )
        assert len(items.items) == 1
