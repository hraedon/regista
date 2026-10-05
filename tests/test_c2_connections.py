"""Connection admission and the trusted administrator's live-DDL boundary."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Kernel, UnsupportedSchemaError, Workflow


def recycle(handle: Kernel) -> None:
    """Close existing physical connections; subsequent checkout must be new."""
    connections = [handle._pool.getconn() for _ in range(handle._pool.get_stats()["pool_size"])]
    for conn in connections:
        conn.close()
    for conn in connections:
        handle._pool.putconn(conn)


@pytest.mark.parametrize("damage", ["extra", "index"])
@pytest.mark.parametrize("new_connection", ["growth", "replacement"])
def test_new_physical_connection_refuses_drift_before_write(
    dsn: str, schema: str, workflow: Workflow, damage: str, new_connection: str,
) -> None:
    handle = Kernel.connect(dsn, schema=schema, pool_max_size=1)
    try:
        handle.initialize()
        handle.register_workflow(workflow)
        # Hold the admitted connection so growth cannot reuse it. Replacement
        # instead closes it, exercising psycopg_pool's lost-connection recovery.
        admitted = handle._pool.getconn()
        original_pid = admitted.info.backend_pid
        if new_connection == "growth":
            handle._pool.resize(1, 2)
        if new_connection == "replacement":
            admitted.close()
            handle._pool.putconn(admitted)
        try:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
                admin.execute("CREATE TABLE foreign_table(v int)" if damage == "extra"
                              else "DROP INDEX idx_wic_state")
            seen: list[int] = []
            original = handle._validate_baseline

            def observe(conn: Any) -> None:
                seen.append(conn.info.backend_pid)
                original(conn)

            with patch.object(handle, "_validate_baseline", observe):
                with pytest.raises(UnsupportedSchemaError, match="baseline"):
                    handle.create_work_item(workflow="review", type="task", actor_id="w")
            assert seen and all(pid != original_pid for pid in seen)
            with psycopg.connect(dsn) as admin:
                assert admin.execute(SQL("SELECT count(*) FROM {}.events").format(
                    Identifier(schema))).fetchone() == (0,)
                assert admin.execute(SQL("SELECT count(*) FROM {}.work_items_current").format(
                    Identifier(schema))).fetchone() == (0,)
        finally:
            if new_connection == "growth":
                handle._pool.putconn(admitted)
    finally:
        handle.close()


def test_live_connection_drift_is_documented_until_recycle(
    dsn: str, schema: str, workflow: Workflow,
) -> None:
    handle = Kernel.connect(dsn, schema=schema, pool_max_size=1)
    try:
        handle.initialize()
        handle.register_workflow(workflow)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(SQL("CREATE TABLE {}.foreign_table(v int)").format(Identifier(schema)))
        # A trusted administrator's DDL on a live admitted connection is outside
        # the contract. The next write succeeds, without a catalog fingerprint.
        with patch.object(handle, "_validate_baseline", side_effect=AssertionError("hot path")):
            item = handle.create_work_item(workflow="review", type="task", actor_id="w")
            assert handle.get(item.id).state == "new"
        recycle(handle)
        with pytest.raises(UnsupportedSchemaError, match="baseline"):
            handle.create_work_item(workflow="review", type="task", actor_id="w")
        with psycopg.connect(dsn) as admin:
            assert admin.execute(SQL("SELECT count(*) FROM {}.events").format(
                Identifier(schema))).fetchone() == (1,)
    finally:
        handle.close()


def test_connection_opened_empty_is_validated_after_initialization(
    dsn: str, schema: str, workflow: Workflow,
) -> None:
    handle = Kernel.connect(dsn, schema=schema, pool_max_size=1)
    idle = handle._pool.getconn()  # Opened before there was any supported baseline.
    try:
        handle._pool.resize(1, 2)
        handle.initialize()  # A second connection initializes and validates.
        handle.register_workflow(workflow)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(SQL("DROP INDEX {}.idx_wic_state").format(Identifier(schema)))
        # Hold the admitted connection before returning the earlier empty one.
        validated = handle._pool.getconn()
        handle._pool.putconn(idle)
        try:
            with pytest.raises(UnsupportedSchemaError, match="baseline"):
                handle.create_work_item(workflow="review", type="task", actor_id="w")
        finally:
            handle._pool.putconn(validated)
    finally:
        handle.close()


def test_fresh_initialization_validates_before_commit(
    dsn: str, schema: str,
) -> None:
    handle = Kernel.connect(dsn, schema=schema, pool_max_size=1)
    try:
        with patch.object(
            handle, "_validate_baseline", side_effect=UnsupportedSchemaError("probe"),
        ):
            with pytest.raises(UnsupportedSchemaError, match="probe"):
                handle.initialize()
        with psycopg.connect(dsn) as admin:
            assert admin.execute("SELECT count(*) FROM pg_catalog.pg_class c "
                                 "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                                 "WHERE n.nspname=%s", (schema,)).fetchone() == (0,)
    finally:
        handle.close()


def test_initialize_revalidates_live_connection(dsn: str, schema: str) -> None:
    handle = Kernel.connect(dsn, schema=schema, pool_max_size=1)
    try:
        handle.initialize()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(SQL("DROP INDEX {}.idx_wic_state").format(Identifier(schema)))
        with pytest.raises(UnsupportedSchemaError, match="baseline"):
            handle.initialize()
    finally:
        handle.close()
