"""Minimal telemetry-via-hooks example for regista.

This example demonstrates:
1. Creating a reporting table in a non-regista schema.
2. Registering a hook handler on transition events.
3. Rebuilding the reporting table from scratch by replaying events.

Usage:
    # Requires a running Postgres with regista migrations applied.
    # Edit DSN and KEY_PATH before running.
    python examples/telemetry_via_hooks.py
"""
from __future__ import annotations

import uuid
from datetime import datetime

import psycopg
from psycopg.sql import SQL, Identifier

from regista import Regista

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = "tests/test_keys.json"
REPORTING_SCHEMA = "regista_analytics"
PROJECT = "telemetry_example"


def ensure_reporting_schema(dsn: str) -> None:
    schema = Identifier(REPORTING_SCHEMA)
    with psycopg.connect(dsn) as conn:
        conn.execute(SQL("CREATE SCHEMA IF NOT EXISTS {}").format(schema))
        conn.execute(
            SQL(
                "CREATE TABLE IF NOT EXISTS {}.transitions_by_role ("
                "id SERIAL PRIMARY KEY, "
                "work_item_id UUID NOT NULL, "
                "transition TEXT NOT NULL, "
                "role TEXT, "
                "model TEXT, "
                "actor_id TEXT NOT NULL, "
                "occurred_at TIMESTAMPTZ NOT NULL"
                ")"
            ).format(schema)
        )
        conn.execute(
            SQL(
                "CREATE INDEX IF NOT EXISTS idx_transitions_role_time "
                "ON {}.transitions_by_role (role, occurred_at)"
            ).format(schema)
        )
        conn.commit()


def record_transition(
    event_id: uuid.UUID,
    work_item_id: uuid.UUID,
    transition: str,
    actor_id: str,
    actor_metadata: dict | None,
    timestamp: datetime,
    **kwargs: object,
) -> None:
    role = (actor_metadata or {}).get("role")
    model = (actor_metadata or {}).get("model")

    schema = Identifier(REPORTING_SCHEMA)
    with psycopg.connect(DSN) as conn:
        conn.execute(
            SQL(
                "INSERT INTO {}.transitions_by_role "
                "(work_item_id, transition, role, model, actor_id, occurred_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)"
            ).format(schema),
            [work_item_id, transition, role, model, actor_id, timestamp],
        )
        conn.commit()


def rebuild_analytics(sub: Regista) -> None:
    schema = Identifier(REPORTING_SCHEMA)
    with psycopg.connect(DSN) as conn:
        conn.execute(SQL("TRUNCATE {}.transitions_by_role").format(schema))
        conn.commit()

    page = sub.read_events(limit=1000)
    for event in page:
        if event.transition in ("created", "start", "submit_review", "approve", "reject"):
            record_transition(
                event_id=event.event_id,
                work_item_id=event.work_item_id,
                transition=event.transition,
                actor_id=event.actor_id,
                actor_metadata=event.actor_metadata,
                timestamp=event.timestamp,
            )


def main() -> None:
    ensure_reporting_schema(DSN)

    sub = Regista.create_project(DSN, PROJECT, KEY_PATH)
    sub.register_workflow(open("tests/test_workflow.yaml").read())

    sub.register_hook_handler("start", record_transition)
    sub.register_hook_handler("submit_review", record_transition)
    sub.register_hook_handler("approve", record_transition)
    sub.register_hook_handler("reject", record_transition)

    sub.start_hook_consumer()

    # ... your application runs here ...
    # sub.create_work_item(...)
    # sub.transition(...)

    # If the reporting table needs a full rebuild:
    # rebuild_analytics(sub)

    sub.stop_hook_consumer()
    sub.close()


if __name__ == "__main__":
    main()
