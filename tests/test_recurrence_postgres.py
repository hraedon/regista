from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from substrate._errors import ErrorCode, SubstrateError
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_rec_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestPostgresRegisterRecurrenceRule:
    def test_register_computes_next_fire(self, substrate):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
        )
        assert rule["next_fire_at"] == start + timedelta(minutes=5)
        assert rule["status"] == "active"

    def test_register_with_end_at(self, substrate):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        end = start + timedelta(minutes=3)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            end_at=end,
        )
        # compute_next_fire returns None when next slot exceeds end_at;
        # register_recurrence_rule falls back to start_at
        assert rule["next_fire_at"] == start

    def test_register_validates_schedule(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.register_recurrence_rule(
                workflow_name="test_workflow",
                workflow_version=1,
                work_item_type="feature",
                template={"custom_fields": {"title": "recurring"}},
                schedule_kind="interval",
                schedule_expr="bad",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID

    def test_register_validates_template(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.register_recurrence_rule(
                workflow_name="test_workflow",
                workflow_version=1,
                work_item_type="feature",
                template="nope",
                schedule_kind="interval",
                schedule_expr="PT5M",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_TEMPLATE_INVALID

    def test_register_with_rrule(self, substrate):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="rrule",
            schedule_expr="FREQ=HOURLY",
            timezone="UTC",
            start_at=start,
        )
        assert rule["next_fire_at"] == start


class TestPostgresListRecurrenceRules:
    def test_list_all(self, substrate):
        substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="bug",
            template={"custom_fields": {"severity": "minor"}},
            schedule_kind="interval",
            schedule_expr="PT10M",
        )
        rules = substrate.list_recurrence_rules()
        assert len(rules) == 2

    def test_list_by_status(self, substrate):
        substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        active = substrate.list_recurrence_rules(status="active")
        assert len(active) == 1
        assert active[0]["status"] == "active"


class TestPostgresDueRecurrences:
    def test_due_recurrences_filters_active(self, substrate):
        past = datetime.now(UTC) - timedelta(minutes=5)
        future = datetime.now(UTC) + timedelta(minutes=5)

        rule_past = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="bug",
            template={"custom_fields": {"severity": "minor"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )

        due = substrate.due_recurrences()
        assert len(due) == 1
        assert due[0]["rule_id"] == rule_past["rule_id"]

    def test_due_recurrences_respects_now(self, substrate):
        future = datetime.now(UTC) + timedelta(hours=1)
        substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )
        due = substrate.due_recurrences()
        assert len(due) == 0


class TestPostgresFireRecurrence:
    def test_fire_creates_work_item(self, substrate):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        rule_id = rule["rule_id"]

        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is not None
        assert wi["work_item_type"] == "feature"
        assert wi["workflow_name"] == "test_workflow"
        assert wi["custom_fields"]["title"] == "recurring"

    def test_fire_updates_next_fire_at(self, substrate):
        past = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        rule_id = rule["rule_id"]
        old_next = rule["next_fire_at"]

        returned_rule, _wi = substrate.fire_recurrence(rule_id)
        assert returned_rule["next_fire_at"] >= old_next

    def test_fire_populates_not_before_offset(self, substrate):
        past = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={
                "custom_fields": {"title": "delayed"},
                "not_before_offset_seconds": 300,
            },
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        rule_id = rule["rule_id"]
        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is not None

    def test_fire_idempotent_early_return(self, substrate):
        future = datetime.now(UTC) + timedelta(hours=1)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )
        rule_id = rule["rule_id"]
        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is None

    def test_fire_exhausted_count(self, substrate):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
            count=1,
        )
        rule_id = rule["rule_id"]

        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is not None

        updated = substrate.list_recurrence_rules(status="exhausted")
        assert len(updated) == 1
        assert updated[0]["count_remaining"] == 0

        with pytest.raises(SubstrateError) as exc_info:
            substrate.fire_recurrence(rule_id)
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_EXHAUSTED


class TestPostgresCatchupPolicies:
    def test_fire_once_skips_past_slots(self, substrate):
        now = datetime.now(UTC)
        start = now - timedelta(minutes=20)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="fire_once",
        )
        rule_id = rule["rule_id"]
        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is not None
        updated = substrate.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > now

    def test_skip_advances_to_future(self, substrate):
        now = datetime.now(UTC)
        start = now - timedelta(hours=1)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="skip",
        )
        rule_id = rule["rule_id"]
        _, wi = substrate.fire_recurrence(rule_id)
        assert wi is None
        updated = substrate.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > now

    def test_fire_all_fires_one_per_call(self, substrate):
        now = datetime.now(UTC)
        start = now - timedelta(minutes=15)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="fire_all",
        )
        rule_id = rule["rule_id"]
        old_next = rule["next_fire_at"]
        _, wi1 = substrate.fire_recurrence(rule_id)
        assert wi1 is not None

        updated = substrate.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > old_next

        _, wi2 = substrate.fire_recurrence(rule_id)
        assert wi2 is not None


class TestPostgresCancelRecurrenceRule:
    def test_cancel_sets_status(self, substrate):
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        substrate.cancel_recurrence_rule(rule["rule_id"])
        updated = substrate.list_recurrence_rules(status="cancelled")
        assert len(updated) == 1

    def test_cancel_not_found_raises(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.cancel_recurrence_rule(uuid.uuid4())
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_NOT_FOUND


class TestPostgresUpdateRecurrenceRule:
    def test_update_schedule_expr(self, substrate):
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = substrate.update_recurrence_rule(
            rule["rule_id"], schedule_expr="PT10M",
        )
        assert updated["schedule_expr"] == "PT10M"

    def test_update_template(self, substrate):
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "old"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = substrate.update_recurrence_rule(
            rule["rule_id"], template={"custom_fields": {"title": "new"}},
        )
        assert updated["template"]["custom_fields"]["title"] == "new"

    def test_update_status(self, substrate):
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = substrate.update_recurrence_rule(
            rule["rule_id"], status="paused",
        )
        assert updated["status"] == "paused"

    def test_update_not_found_raises(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.update_recurrence_rule(
                uuid.uuid4(), schedule_expr="PT10M",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_NOT_FOUND


class TestPostgresRecurrenceCustomFields:
    def test_created_work_item_has_custom_fields(self, substrate):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = substrate.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "from template", "priority": "high"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        _, wi = substrate.fire_recurrence(rule["rule_id"])
        assert wi is not None
        assert wi["custom_fields"]["title"] == "from template"
        assert wi["custom_fields"]["priority"] == "high"
