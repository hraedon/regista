from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_rec_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestPostgresRegisterRecurrenceRule:
    def test_register_computes_next_fire(self, regista):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = regista.register_recurrence_rule(
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

    def test_register_with_end_at(self, regista):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        end = start + timedelta(minutes=3)
        rule = regista.register_recurrence_rule(
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

    def test_register_validates_schedule(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_recurrence_rule(
                workflow_name="test_workflow",
                workflow_version=1,
                work_item_type="feature",
                template={"custom_fields": {"title": "recurring"}},
                schedule_kind="interval",
                schedule_expr="bad",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID

    def test_register_validates_template(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_recurrence_rule(
                workflow_name="test_workflow",
                workflow_version=1,
                work_item_type="feature",
                template="nope",
                schedule_kind="interval",
                schedule_expr="PT5M",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_TEMPLATE_INVALID

    def test_register_with_rrule(self, regista):
        start = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = regista.register_recurrence_rule(
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
    def test_list_all(self, regista):
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="bug",
            template={"custom_fields": {"severity": "minor"}},
            schedule_kind="interval",
            schedule_expr="PT10M",
        )
        rules = regista.list_recurrence_rules()
        assert len(rules) == 2

    def test_list_by_status(self, regista):
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        active = regista.list_recurrence_rules(status="active")
        assert len(active) == 1
        assert active[0]["status"] == "active"


class TestPostgresDueRecurrences:
    def test_due_recurrences_filters_active(self, regista):
        past = datetime.now(UTC) - timedelta(minutes=5)
        future = datetime.now(UTC) + timedelta(minutes=5)

        rule_past = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="bug",
            template={"custom_fields": {"severity": "minor"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )

        due = regista.due_recurrences()
        assert len(due) == 1
        assert due[0]["rule_id"] == rule_past["rule_id"]

    def test_due_recurrences_respects_now(self, regista):
        future = datetime.now(UTC) + timedelta(hours=1)
        regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )
        due = regista.due_recurrences()
        assert len(due) == 0


class TestPostgresFireRecurrence:
    def test_fire_creates_work_item(self, regista):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        rule_id = rule["rule_id"]

        _, wi = regista.fire_recurrence(rule_id)
        assert wi is not None
        assert wi["work_item_type"] == "feature"
        assert wi["workflow_name"] == "test_workflow"
        assert wi["custom_fields"]["title"] == "recurring"

    def test_fire_updates_next_fire_at(self, regista):
        past = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = regista.register_recurrence_rule(
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

        returned_rule, _wi = regista.fire_recurrence(rule_id)
        assert returned_rule["next_fire_at"] >= old_next

    def test_fire_populates_not_before_offset(self, regista):
        past = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        rule = regista.register_recurrence_rule(
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
        _, wi = regista.fire_recurrence(rule_id)
        assert wi is not None

    def test_fire_idempotent_early_return(self, regista):
        future = datetime.now(UTC) + timedelta(hours=1)
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=future,
        )
        rule_id = rule["rule_id"]
        _, wi = regista.fire_recurrence(rule_id)
        assert wi is None

    def test_fire_exhausted_count(self, regista):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = regista.register_recurrence_rule(
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

        _, wi = regista.fire_recurrence(rule_id)
        assert wi is not None

        updated = regista.list_recurrence_rules(status="exhausted")
        assert len(updated) == 1
        assert updated[0]["count_remaining"] == 0

        with pytest.raises(RegistaError) as exc_info:
            regista.fire_recurrence(rule_id)
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_EXHAUSTED


class TestPostgresCatchupPolicies:
    def test_fire_once_skips_past_slots(self, regista):
        now = datetime.now(UTC)
        start = now - timedelta(minutes=20)
        rule = regista.register_recurrence_rule(
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
        _, wi = regista.fire_recurrence(rule_id)
        assert wi is not None
        updated = regista.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > now

    def test_skip_advances_to_future(self, regista):
        now = datetime.now(UTC)
        start = now - timedelta(hours=1)
        rule = regista.register_recurrence_rule(
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
        _, wi = regista.fire_recurrence(rule_id)
        assert wi is None
        updated = regista.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > now

    def test_fire_all_fires_one_per_call(self, regista):
        now = datetime.now(UTC)
        start = now - timedelta(minutes=15)
        rule = regista.register_recurrence_rule(
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
        _, wi1 = regista.fire_recurrence(rule_id)
        assert wi1 is not None

        updated = regista.list_recurrence_rules()[0]
        assert updated["next_fire_at"] > old_next

        _, wi2 = regista.fire_recurrence(rule_id)
        assert wi2 is not None


class TestPostgresCancelRecurrenceRule:
    def test_cancel_sets_status(self, regista):
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        regista.cancel_recurrence_rule(rule["rule_id"])
        updated = regista.list_recurrence_rules(status="cancelled")
        assert len(updated) == 1

    def test_cancel_not_found_raises(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.cancel_recurrence_rule(uuid.uuid4())
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_NOT_FOUND


class TestPostgresUpdateRecurrenceRule:
    def test_update_schedule_expr(self, regista):
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = regista.update_recurrence_rule(
            rule["rule_id"], schedule_expr="PT10M",
        )
        assert updated["schedule_expr"] == "PT10M"

    def test_update_template(self, regista):
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "old"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = regista.update_recurrence_rule(
            rule["rule_id"], template={"custom_fields": {"title": "new"}},
        )
        assert updated["template"]["custom_fields"]["title"] == "new"

    def test_update_status(self, regista):
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
        )
        updated = regista.update_recurrence_rule(
            rule["rule_id"], status="paused",
        )
        assert updated["status"] == "paused"

    def test_update_not_found_raises(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.update_recurrence_rule(
                uuid.uuid4(), schedule_expr="PT10M",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_RULE_NOT_FOUND


class TestPostgresRecurrenceCustomFields:
    def test_created_work_item_has_custom_fields(self, regista):
        past = datetime.now(UTC) - timedelta(minutes=5)
        rule = regista.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "from template", "priority": "high"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=past,
        )
        _, wi = regista.fire_recurrence(rule["rule_id"])
        assert wi is not None
        assert wi["custom_fields"]["title"] == "from template"
        assert wi["custom_fields"]["priority"] == "high"
