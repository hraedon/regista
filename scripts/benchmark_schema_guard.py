"""Measure complete baseline admission; use only REGISTA_TEST_DSN disposable PostgreSQL."""
from __future__ import annotations

import json
import os
import statistics
import time
import uuid
from unittest.mock import patch

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from regista import Kernel, Workflow
from regista.kernel import _catalog_fingerprint, _catalog_manifest


def main() -> None:
    dsn = os.environ["REGISTA_TEST_DSN"]
    schema = "c1_bench_" + uuid.uuid4().hex
    handle = Kernel.connect(dsn, schema=schema)
    try:
        handle.initialize()
        handle.register_workflow(Workflow(name="bench", types=("task",), states=("new",),
                                          initial="new", transitions={}))
        queries: dict[str, list[float]] = {
            "fingerprint": [], "full_manifest": [], "marker_only": [],
        }
        with psycopg.connect(dsn, row_factory=dict_row) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
            functions = {
                "fingerprint": lambda: _catalog_fingerprint(conn, schema),
                "full_manifest": lambda: _catalog_manifest(conn, schema),
                "marker_only": lambda: conn.execute(
                    "SELECT kernel_schema_version FROM kernel_meta").fetchone(),
            }
            for turn in range(7):
                for label in (list(functions) if turn % 2 == 0 else list(reversed(functions))):
                    fn = functions[label]
                    for _ in range(10):
                        fn()
                    begin = time.perf_counter()
                    for _ in range(100):
                        fn()
                    queries[label].append((time.perf_counter() - begin) * 1000 / 100)
        writes: dict[str, list[float]] = {"complete_admission": [], "without_manifest_control": []}
        original = Kernel._validate_baseline
        for turn in range(7):
            labels = list(writes) if turn % 2 == 0 else list(reversed(writes))
            for label in labels:
                fn = original if label == "complete_admission" else lambda self, conn: None
                with patch.object(Kernel, "_validate_baseline", fn):
                    begin = time.perf_counter()
                    for _ in range(50):
                        handle.create_work_item(workflow="bench", type="task", actor_id="bench")
                    writes[label].append((time.perf_counter() - begin) * 1000 / 50)
        print(json.dumps({"query_ms_samples": queries, "write_ms_samples": writes,
                          "query_ms_median": {k: statistics.median(v) for k,v in queries.items()},
                          "write_ms_median": {k: statistics.median(v) for k,v in writes.items()},
                          "method": "7 alternating batches; 100 queries or 50 writes; no DB cache"},
                         indent=2))
    finally:
        handle.close()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(schema)))


if __name__ == "__main__":
    main()
