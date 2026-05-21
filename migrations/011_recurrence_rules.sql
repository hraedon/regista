CREATE TABLE recurrence_rules (
  rule_id         uuid PRIMARY KEY,
  workflow_name   text NOT NULL,
  workflow_version int NOT NULL,
  work_item_type  text NOT NULL,
  template        jsonb NOT NULL,
  schedule_kind   text NOT NULL CHECK (schedule_kind IN ('rrule','interval')),
  schedule_expr   text NOT NULL,
  timezone        text NOT NULL DEFAULT 'UTC',
  start_at        timestamptz NOT NULL,
  end_at          timestamptz NULL,
  count_remaining int NULL,
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','paused','exhausted','cancelled')),
  catchup_policy  text NOT NULL DEFAULT 'fire_once'
                  CHECK (catchup_policy IN ('fire_once','fire_all','skip')),
  last_fired_at   timestamptz NULL,
  next_fire_at    timestamptz NOT NULL,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_recurrence_due ON recurrence_rules (next_fire_at)
  WHERE status = 'active';
