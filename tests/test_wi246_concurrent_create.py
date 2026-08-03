from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from _helpers import DSN, KEY_PATH

from regista import Regista
from regista.testing import drop_project_schema


class TestConcurrentCreateProject:
    """WI-246: concurrent create_project calls must not deadlock.

    Migration 037 and register_project both issue
    ``CREATE TABLE IF NOT EXISTS public.projects``. The migration path holds
    the migration advisory lock; register_project runs outside it. Before the
    fix, two sessions racing on the catalog table DDL took conflicting locks
    and deadlocked — a production hazard (two processes onboarding at once),
    not just a test-parallelism one.

    The stress uses real Postgres threads (one connection pool each), which is
    the scenario that deadlocks: each create_project acquires the advisory
    lock on its own connection while doing catalog DDL on a pool connection.
    """

    def test_concurrent_create_project_no_deadlock(self):
        errors: list[Exception] = []

        def create(i: int) -> str:
            project = f"wi246_c_{i}_{uuid.uuid4().hex[:6]}"
            sub = Regista.create_project(DSN, project, KEY_PATH)
            sub.close()
            drop_project_schema(DSN, project)
            return project

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(create, i) for i in range(16)]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as exc:  # pragma: no cover - failure path
                    errors.append(exc)

        assert errors == [], f"Concurrent create_project deadlocked/errored: {errors[:3]}"

    def test_concurrent_provision_plus_create_project_no_deadlock(self):
        """Migrations + catalog bootstrap from two entry points at once.

        create_project and provision both end with register_project (catalog
        DDL) after running migrations (advisory-locked). Racing them is the
        exact lock-ordering the fix serializes.
        """
        from regista._provision import provision

        errors: list[Exception] = []
        lock = __import__("threading").Lock()

        def create() -> None:
            try:
                project = f"wi246_p_{uuid.uuid4().hex[:6]}"
                sub = Regista.create_project(DSN, project, KEY_PATH)
                sub.close()
                drop_project_schema(DSN, project)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        def provision_one() -> None:
            try:
                project = f"wi246_v_{uuid.uuid4().hex[:6]}"
                provision(DSN, [project])
                import psycopg

                drop_project_schema(DSN, project)
                with psycopg.connect(DSN, autocommit=True) as conn:
                    conn.execute(f'DROP ROLE IF EXISTS "regista_{project}"')
            except Exception as exc:
                with lock:
                    errors.append(exc)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(create) for _ in range(4)]
            futures += [pool.submit(provision_one) for _ in range(4)]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as exc:  # pragma: no cover - failure path
                    with lock:
                        errors.append(exc)

        assert errors == [], f"Concurrent provision+create deadlocked/errored: {errors[:3]}"


class TestCatalogBootstrapConcurrency:
    def test_ensure_catalog_table_concurrent(self):
        """Two sessions calling ensure_catalog_table on a missing table."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        import psycopg

        from regista._projects import ensure_catalog_table

        errors: list[Exception] = []

        def ensure() -> None:
            try:
                with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
                    ensure_catalog_table(conn)
                    conn.commit()
            except Exception as exc:
                errors.append(exc)

        # Drop the catalog table first so the CREATE path is exercised.
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS public.projects")

        try:
            with ThreadPoolExecutor(max_workers=6) as pool:
                futures = [pool.submit(ensure) for _ in range(12)]
                for f in as_completed(futures):
                    f.result()
        finally:
            # Restore the catalog table so sibling tests (and any concurrent
            # suite run) find it in place. ensure_catalog_table recreates the
            # empty table — the suite's leak guard tracks schemas, not this
            # table, so an empty catalog is a valid resting state.
            with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
                ensure_catalog_table(conn)
                conn.commit()

        assert errors == [], f"ensure_catalog_table deadlocked: {errors[:3]}"
