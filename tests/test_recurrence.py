from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._recurrence import (
    _parse_iso8601_duration,
    compute_next_fire,
    validate_schedule,
    validate_template,
)
from regista._types import RecurrenceRule


class TestComputeNextFire:
    def test_interval_minutes(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        next_fire = compute_next_fire(
            "interval", "PT5M", "UTC", start, None, None,
        )
        assert next_fire == start + timedelta(minutes=5)

    def test_interval_hours(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        next_fire = compute_next_fire(
            "interval", "PT1H", "UTC", start, None, None,
        )
        assert next_fire == start + timedelta(hours=1)

    def test_interval_days(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        next_fire = compute_next_fire(
            "interval", "P1D", "UTC", start, None, None,
        )
        assert next_fire == start + timedelta(days=1)

    def test_interval_respects_end_at(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        end = start + timedelta(minutes=3)
        next_fire = compute_next_fire(
            "interval", "PT5M", "UTC", start, None, end,
        )
        assert next_fire is None

    def test_interval_with_last_fired(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        last = start + timedelta(minutes=5)
        next_fire = compute_next_fire(
            "interval", "PT5M", "UTC", start, last, None,
        )
        assert next_fire == start + timedelta(minutes=10)

    def test_rrule_daily_first_occurrence_is_start(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        next_fire = compute_next_fire(
            "rrule", "FREQ=DAILY", "UTC", start, None, None,
        )
        assert next_fire == start

    def test_rrule_next_after_first(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        last = start
        next_fire = compute_next_fire(
            "rrule", "FREQ=DAILY", "UTC", start, last, None,
        )
        assert next_fire == start + timedelta(days=1)

    def test_rrule_with_end_at_before_start(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        end = start - timedelta(hours=1)
        next_fire = compute_next_fire(
            "rrule", "FREQ=DAILY", "UTC", start, None, end,
        )
        assert next_fire is None

    def test_unknown_schedule_kind(self):
        with pytest.raises(RegistaError) as exc_info:
            compute_next_fire("bogus", "", "UTC", datetime.now(UTC), None, None)
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID


class TestValidateSchedule:
    def test_valid_interval(self):
        validate_schedule("interval", "PT10M")

    def test_valid_rrule(self):
        validate_schedule("rrule", "FREQ=HOURLY")

    def test_invalid_rrule(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_schedule("rrule", "not a rrule")
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID

    def test_invalid_interval(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_schedule("interval", "xyz")
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID


class TestValidateTemplate:
    def test_valid(self):
        validate_template({"custom_fields": {}})

    def test_not_dict(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_template("nope")
        assert exc_info.value.code == ErrorCode.RECURRENCE_TEMPLATE_INVALID


class TestRecurrenceRuleDataclass:
    def test_roundtrip(self):
        rule = RecurrenceRule(
            rule_id=uuid.uuid4(),
            workflow_name="test",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {}},
            schedule_kind="interval",
            schedule_expr="PT1H",
            timezone="UTC",
            start_at=datetime.now(UTC),
            end_at=None,
            count_remaining=5,
            status="active",
            catchup_policy="fire_once",
            last_fired_at=None,
            next_fire_at=datetime.now(UTC),
            created_by="system",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        d = rule.to_dict()
        restored = RecurrenceRule.from_dict(d)
        assert restored.rule_id == rule.rule_id
        assert restored.workflow_name == rule.workflow_name
        assert restored.status == rule.status


class TestParseIso8601Duration:
    def test_fractional_seconds(self):
        td = _parse_iso8601_duration("PT0.5S")
        assert td == timedelta(seconds=0.5)

    def test_fractional_seconds_1_5(self):
        td = _parse_iso8601_duration("PT1.5S")
        assert td == timedelta(seconds=1.5)

    def test_fractional_seconds_with_hours(self):
        td = _parse_iso8601_duration("PT1H30.5S")
        assert td == timedelta(hours=1, seconds=30.5)

    def test_zero_duration_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            _parse_iso8601_duration("P0D")
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID

    def test_invalid_format(self):
        with pytest.raises(RegistaError) as exc_info:
            _parse_iso8601_duration("notaduration")
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID

    def test_integer_seconds(self):
        td = _parse_iso8601_duration("PT30S")
        assert td == timedelta(seconds=30)

    def test_days_and_hours(self):
        td = _parse_iso8601_duration("P1DT2H")
        assert td == timedelta(days=1, hours=2)


class TestCatchupPolicyFireOnce:
    def test_fire_once_skips_past_slots(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        now = start + timedelta(minutes=25)
        from regista._recurrence import _find_next_future_slot
        result = _find_next_future_slot(
            "interval", "PT5M", "UTC", start, start, now, None,
        )
        assert result == start + timedelta(minutes=30)

    def test_fire_once_next_already_future(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        now = start
        from regista._recurrence import _find_next_future_slot
        result = _find_next_future_slot(
            "interval", "PT5M", "UTC", start, start, now, None,
        )
        assert result == start + timedelta(minutes=5)

    def test_fire_once_past_end(self):
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        now = start + timedelta(hours=1)
        from regista._recurrence import _find_next_future_slot
        result = _find_next_future_slot(
            "interval", "PT5M", "UTC", start, start, now, start + timedelta(minutes=10),
        )
        assert result is None


class TestCatchupPolicySkip:
    def test_skip_policy_returns_none_work_item(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        rule = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="skip",
        )
        rule["next_fire_at"] = start
        rule_id = rule["rule_id"]

        _, wi = s.fire_recurrence(rule_id)
        assert wi is None

    def test_skip_advances_to_future(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        now = datetime.now(UTC)
        start = now - timedelta(hours=1)
        rule = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="skip",
        )
        rule["next_fire_at"] = start
        rule_id = rule["rule_id"]

        s.fire_recurrence(rule_id)
        updated = s._recurrence_rules[rule_id]
        assert updated["next_fire_at"] > now


class TestCatchupPolicyFireAll:
    def test_fire_all_fires_one_per_call(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        now = datetime.now(UTC)
        start = now - timedelta(minutes=15)
        rule = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="fire_all",
        )
        rule["next_fire_at"] = start
        rule_id = rule["rule_id"]

        _, wi1 = s.fire_recurrence(rule_id)
        assert wi1 is not None
        assert rule["next_fire_at"] == start + timedelta(minutes=5)

        _, wi2 = s.fire_recurrence(rule_id)
        assert wi2 is not None
        assert rule["next_fire_at"] == start + timedelta(minutes=10)

    def test_fire_all_does_not_skip_past_slots(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        now = datetime.now(UTC)
        start = now - timedelta(minutes=15)
        rule = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"title": "recurring"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
            catchup_policy="fire_all",
        )
        rule["next_fire_at"] = start
        rule_id = rule["rule_id"]

        _, wi = s.fire_recurrence(rule_id)
        assert wi is not None
        assert rule["next_fire_at"] == start + timedelta(minutes=5)


class TestInMemoryMultipleRules:
    def test_multiple_rules_same_workflow(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        r1 = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"env": "prod"}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
        )
        r2 = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {"env": "staging"}},
            schedule_kind="interval",
            schedule_expr="PT10M",
            start_at=start,
        )
        assert r1["rule_id"] != r2["rule_id"]
        rules = s.list_recurrence_rules()
        assert len(rules) == 2


class TestInMemoryNextFireAt:
    def test_register_computes_next_fire(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        rule = s.register_recurrence_rule(
            workflow_name="test_workflow",
            workflow_version=1,
            work_item_type="feature",
            template={"custom_fields": {}},
            schedule_kind="interval",
            schedule_expr="PT5M",
            start_at=start,
        )
        assert rule["next_fire_at"] == start + timedelta(minutes=5)

    def test_register_validates_schedule(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test")
        s.register_workflow_file(str(Path(__file__).parent / "test_workflow.yaml"))

        with pytest.raises(RegistaError) as exc_info:
            s.register_recurrence_rule(
                workflow_name="test_workflow",
                workflow_version=1,
                work_item_type="feature",
                template={"custom_fields": {}},
                schedule_kind="interval",
                schedule_expr="bad",
            )
        assert exc_info.value.code == ErrorCode.RECURRENCE_SCHEDULE_INVALID
