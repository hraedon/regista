"""Fresh-baseline admission against representative pre-cutover marker rows."""

from __future__ import annotations

from collections.abc import Callable

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Kernel, UnsupportedSchemaError, Workflow


@pytest.mark.parametrize(
    "era,marker,version",
    [
        ("0.5", "_regista_migrations", 44),
        ("pre-rename", "_substrate_migrations", 27),
        ("0.6", "_regista_migrations", 50),
        ("0.7", "_regista_migrations", 50),
    ],
)
@pytest.mark.parametrize("spoof_current_marker", [False, True])
def test_old_schema_refuses_without_mutation(
    dsn: str,
    schema: str,
    workflow: Workflow,
    era: str,
    marker: str,
    version: int,
    spoof_current_marker: bool,
) -> None:
    # Marker shape from the retired migration runner; checksum from migration 012.
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        conn.execute(
            SQL(
                "CREATE TABLE {} (version integer PRIMARY KEY, "
                "applied_at timestamptz NOT NULL DEFAULT now(), checksum bytea)"
            ).format(Identifier(marker))
        )
        conn.execute(
            SQL("INSERT INTO {} (version, checksum) VALUES (%s, %s)").format(Identifier(marker)),
            (version, b"old-release-checksum"),
        )
        # Shared 001 marker: events required key_id/signature. Keep a real row.
        conn.execute(
            "CREATE TABLE events (event_id integer PRIMARY KEY, "
            "key_id text NOT NULL, signature bytea NOT NULL)"
        )
        conn.execute("INSERT INTO events VALUES (1, 'old-key', %s)", (b"old-signature",))
        if era in ("0.6", "0.7"):
            conn.execute(
                "CREATE TABLE project_identity (id boolean PRIMARY KEY, "
                "trust_domain_id text NOT NULL)"
            )
            conn.execute("INSERT INTO project_identity VALUES (true, 'old-domain')")
        if spoof_current_marker:
            conn.execute("CREATE TABLE kernel_meta (kernel_schema_version integer)")
            conn.execute("INSERT INTO kernel_meta VALUES (1)")

    def snapshot() -> tuple[object, object]:
        with psycopg.connect(dsn) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
            tables = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=%s ORDER BY table_name",
                (schema,),
            ).fetchall()
            contents = [
                (
                    name,
                    conn.execute(
                        SQL("SELECT * FROM {} ORDER BY 1").format(Identifier(name))
                    ).fetchall(),
                )
                for (name,) in tables
            ]
            objects = conn.execute(
                "SELECT c.relname, c.relkind, a.attname, a.atttypid, a.attnotnull "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 "
                "WHERE n.nspname=%s ORDER BY c.relname,a.attnum",
                (schema,),
            ).fetchall()
            return contents, objects

    before = snapshot()
    for existing in (False, True):
        with pytest.raises(UnsupportedSchemaError):
            Kernel.connect(dsn, schema=schema, require_existing=existing)
        assert snapshot() == before
    # An empty destination is not a validated baseline; late legacy objects refuse.
    # Connect to an empty schema first, then place a representative old marker.
    # This case is separately covered below; here admission itself must refuse.


def test_legacy_tables_added_after_open_refuse_writes(
    dsn: str,
    schema: str,
    workflow: Workflow,
) -> None:
    handle = Kernel.connect(dsn, schema=schema)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(
                SQL("CREATE TABLE {}._regista_migrations (version integer)").format(
                    Identifier(schema)
                )
            )
            conn.execute(
                SQL("INSERT INTO {}._regista_migrations VALUES (50)").format(Identifier(schema))
            )
        actions: list[Callable[[], object]] = [
            handle.initialize,
            lambda: handle.register_workflow(workflow),
        ]
        for action in actions:
            with pytest.raises(UnsupportedSchemaError):
                action()
        with psycopg.connect(dsn) as conn:
            assert conn.execute(
                SQL("SELECT * FROM {}._regista_migrations").format(Identifier(schema))
            ).fetchall() == [(50,)]
            assert conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (schema,)
            ).fetchall() == [
                ("_regista_migrations",),
            ]
    finally:
        handle.close()


def test_minimal_public_example(dsn: str, schema: str) -> None:
    """The README's complete public path runs with package-owned resources."""
    handle = Kernel.connect(dsn, schema=schema)
    try:
        handle.initialize()
        handle.register_workflow(Workflow(
            name="tasks", types=("task",), states=("new", "done"), initial="new",
            transitions={"finish": (("new",), "done")}, terminal=("done",),
        ))
        item = handle.create_work_item(workflow="tasks", type="task", actor_id="worker")
        lease = handle.claim(item.id, actor_id="worker", ttl_seconds=300)
        handle.transition(item.id, transition="finish", actor_id="worker", attempt=lease.attempt)
        handle.release(item.id, actor_id="worker", attempt=lease.attempt)
        assert [it.id for it in handle.list_items(states=["done"])] == [item.id]
        assert handle.replay(item.id)[2] == []
    finally:
        handle.close()


@pytest.mark.parametrize('object_kind', ['sequence', 'function'])
def test_non_table_schema_is_not_empty(dsn: str, schema: str, object_kind: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        if object_kind == 'sequence':
            conn.execute(SQL('CREATE SEQUENCE {}.only_object').format(Identifier(schema)))
        else:
            conn.execute(SQL('CREATE FUNCTION {}.only_object() RETURNS integer '
                             'LANGUAGE sql AS $$ SELECT 1 $$').format(Identifier(schema)))
    for existing in (False, True):
        with pytest.raises(UnsupportedSchemaError):
            Kernel.connect(dsn, schema=schema, require_existing=existing)
    with psycopg.connect(dsn) as conn:
        assert conn.execute('SELECT count(*) FROM pg_class c JOIN pg_namespace n '
                            'ON n.oid=c.relnamespace WHERE n.nspname=%s AND '
                            "c.relname='kernel_meta'", (schema,)).fetchone() == (0,)


@pytest.mark.parametrize('namespace_usage', [False, True])
def test_legacy_schema_hidden_from_unprivileged_role(
    dsn: str, schema: str, namespace_usage: bool,
) -> None:
    role = schema + '_reader'
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL('CREATE ROLE {}').format(Identifier(role)))
        try:
            conn.execute(SQL('CREATE TABLE {}._regista_migrations (version integer)').format(
                Identifier(schema)))
            if namespace_usage:
                conn.execute(SQL('GRANT USAGE ON SCHEMA {} TO {}').format(
                    Identifier(schema), Identifier(role)))
            conn.execute(SQL('SET ROLE {}').format(Identifier(role)))
            assert conn.execute('SELECT table_name FROM information_schema.tables '
                                'WHERE table_schema=%s', (schema,)).fetchall() == []
            conn.execute('RESET ROLE')
            restricted_dsn = psycopg.conninfo.make_conninfo(dsn, options=f'-c role={role}')
            for existing in (False, True):
                with pytest.raises(UnsupportedSchemaError):
                    Kernel.connect(restricted_dsn, schema=schema, require_existing=existing)
            assert conn.execute(SQL('SELECT * FROM {}._regista_migrations').format(
                Identifier(schema))).fetchall() == []
            conn.execute('RESET ROLE')
        finally:
            conn.execute('RESET ROLE')
            conn.execute(SQL('DROP OWNED BY {}').format(Identifier(role)))
            conn.execute(SQL('DROP ROLE {}').format(Identifier(role)))


def test_legacy_objects_added_to_initialized_schema_refuse_before_write(
    kernel: Kernel, dsn: str, schema: str, workflow: Workflow,
) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL('CREATE TABLE {}._regista_migrations (version integer)').format(
            Identifier(schema)))
        before = conn.execute(SQL('SELECT count(*) FROM {}.events').format(
            Identifier(schema))).fetchone()
    from test_c2_connections import recycle

    recycle(kernel)
    with pytest.raises(UnsupportedSchemaError):
        kernel.register_workflow(workflow)
    with psycopg.connect(dsn) as conn:
        assert conn.execute(SQL('SELECT count(*) FROM {}.events').format(
            Identifier(schema))).fetchone() == before
        assert conn.execute(SQL('SELECT count(*) FROM {}.workflow_registry').format(
            Identifier(schema))).fetchone() == (0,)
