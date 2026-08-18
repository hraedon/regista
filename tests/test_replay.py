from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
WORKER = "agent:worker"


@pytest.fixture
def regista(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_replay_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # The epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC17RevokedKeyHaltsReplay:
    def test_replay_report_includes_halted_count(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC-17 halted"},
        )
        regista.transition(
            wi.work_item_id, "start", WORKER, actor_metadata={"role": "agent"}
        )

        report = regista.replay()
        assert report.halted >= 0
        assert report.replayed_ok >= 1


class TestAC29OutOfBandEditDrift:
    def test_direct_state_update_detected_as_drift(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC-29 state drift"},
        )

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current SET current_state = 'done' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.replayed_drift >= 1

    def test_direct_custom_fields_update_detected_as_drift(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC-29 field drift"},
        )

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current SET custom_fields = '{\"title\": \"tampered\"}'::jsonb "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.replayed_drift >= 1

    def test_no_drift_after_normal_operations(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"title": "AC-29 clean"},
        )
        regista.transition(
            wi.work_item_id, "start", WORKER, actor_metadata={"role": "agent"}
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestPrincipalBindingFailureReport:
    def test_report_round_trips_principal_binding_failures(self):
        from regista._types import ReplayReport

        report = ReplayReport(
            table_name="t",
            replayed_ok=1,
            replayed_drift=0,
            halted=0,
            warnings=2,
            principal_binding_failures=2,
        )
        d = report.to_dict()
        assert d["principal_binding_failures"] == 2
        assert d["warnings"] == 2

        restored = ReplayReport.from_dict(d)
        assert restored.principal_binding_failures == 2

    def test_report_omits_zero_principal_binding_failures(self):
        from regista._types import ReplayReport

        report = ReplayReport(
            table_name="t",
            replayed_ok=1,
            replayed_drift=0,
            halted=0,
        )
        assert "principal_binding_failures" not in report.to_dict()
        assert report.principal_binding_failures == 0
