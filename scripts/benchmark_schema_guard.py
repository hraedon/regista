"""Measure schema admission cost using only REGISTA_TEST_DSN disposable PostgreSQL."""

import ast
import inspect
import json
import os
import statistics
import textwrap
import time
import uuid

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

import regista.kernel as module
from regista import Kernel, Workflow


def main() -> None:
    dsn = os.environ["REGISTA_TEST_DSN"]
    schema = "b2_bench_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(SQL("CREATE SCHEMA {}").format(Identifier(schema)))
    handle = Kernel.connect(dsn, schema=schema)
    handle.initialize()
    handle.register_workflow(
        Workflow(name="bench", types=("task",), states=("new",), initial="new", transitions={})
    )
    legacy = "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()"
    marker = "SELECT kernel_schema_version FROM kernel_meta"
    # Extract the actual folded query, without a separately maintained copy.

    node = ast.parse(textwrap.dedent(inspect.getsource(Kernel._require_writable_schema)))
    folded = next(
        n.args[0].value
        for n in ast.walk(node)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "execute"
    )
    results = {}
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        queries = {
            "original_information_schema_plus_version": [legacy, marker],
            "folded_catalog_and_version": [folded],
            "version_only": [marker],
        }
        samples = {k: [] for k in queries}
        for round in range(7):
            for label, sqls in queries.items():
                for i in range(50):
                    for sql in sqls:
                        conn.execute(sql).fetchall()
                begin = time.perf_counter()
                for i in range(1000):
                    for sql in sqls:
                        conn.execute(sql).fetchall()
                samples[label].append((time.perf_counter() - begin) * 1000000 / 1000)
        results["query_us_median"] = {
            k: round_value
            for k, values in samples.items()
            for round_value in [statistics.median(values)]
        }
        results["query_us_samples"] = samples
    original = Kernel._require_writable_schema

    def old(conn):
        names = {r["table_name"] for r in conn.execute(legacy).fetchall()}
        if names & {
            "_regista_migrations",
            "_substrate_migrations",
            "project_identity",
            "principal_keys",
        } or (names and "kernel_meta" not in names):
            raise module.UnsupportedSchemaError("legacy")
        row = conn.execute(marker).fetchone()
        if not row or row["kernel_schema_version"] != module.KERNEL_SCHEMA_VERSION:
            raise module.UnsupportedSchemaError("version")

    try:
        samples = {"original_write": [], "folded_write": []}
        for repeat in range(7):
            for label, fn in [("original_write", old), ("folded_write", original)]:
                Kernel._require_writable_schema = staticmethod(fn)
                begin = time.perf_counter()
                for i in range(200):
                    handle.create_work_item(workflow="bench", type="task", actor_id="bench")
                samples[label].append((time.perf_counter() - begin) * 1000 / 200)
        results["write_ms_median"] = {k: statistics.median(v) for k, v in samples.items()}
        results["write_ms_samples"] = samples
    finally:
        Kernel._require_writable_schema = staticmethod(original)
        handle.close()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(schema)))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
