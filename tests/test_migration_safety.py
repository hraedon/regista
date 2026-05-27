"""BC-191: Tests for advisory lock serialisation and checksum drift detection."""
from __future__ import annotations

import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._migrations import MIGRATION_LOCK_ID, run_migrations
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _make_mgr(project: str) -> ConnectionManager:
    mgr = ConnectionManager(DSN, project)
    mgr.open()
    return mgr


def _create_schema(project: str) -> None:
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SQL("CREATE SCHEMA IF NOT EXISTS {}").format(Identifier(project)))


def _drop_schema(project: str) -> None:
    drop_project_schema(DSN, project)


class TestAdvisoryLockConcurrentBoot:
    """Two threads calling run_migrations against an empty DB must both
    succeed; exactly one applies each migration, the other waits on the
    advisory lock and returns after finding all versions already applied."""

    def test_concurrent_run_migrations_both_succeed(self):
        project = f"test_bc191_lock_{uuid.uuid4().hex[:8]}"
        _create_schema(project)

        errors: list[Exception] = []
        results: list[list[int]] = []

        def boot():
            mgr = _make_mgr(project)
            try:
                applied = run_migrations(mgr)
                results.append(applied)
            except Exception as exc:
                errors.append(exc)
            finally:
                mgr.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(boot), pool.submit(boot)]
            for f in as_completed(futures):
                f.result()  # re-raise thread-internal exceptions

        assert not errors, f"Concurrent boot raised errors: {errors}"
        assert len(results) == 2, "Both threads must complete"

        # One thread applied migrations, the other found nothing pending.
        combined = results[0] + results[1]
        # Every migration applied by the first thread must appear exactly once.
        assert len(combined) == len(set(combined)), (
            "Some migration was applied more than once: "
            f"thread0={results[0]}, thread1={results[1]}"
        )

        _drop_schema(project)

    def test_migration_lock_id_is_documented_value(self):
        """MIGRATION_LOCK_ID must equal the SHA-256-derived constant documented
        in BC-191 (4952183743003111440) so operators can verify non-collision."""
        assert MIGRATION_LOCK_ID == 4952183743003111440


class TestChecksumDriftDetection:
    """Editing an applied migration file then re-running run_migrations must
    raise MIGRATION_DRIFT with both checksums in the detail dict."""

    def test_drift_raises_migration_drift(self, tmp_path):
        import regista._migrations as mig_mod

        project = f"test_bc191_drift_{uuid.uuid4().hex[:8]}"
        _create_schema(project)

        # Point the migrations dir at a temporary copy so we can safely mutate.
        real_migrations = Path(mig_mod._migrations_dir())
        fake_migrations = tmp_path / "migrations"
        shutil.copytree(real_migrations, fake_migrations)

        original_migrations_dir = mig_mod._migrations_dir

        def patched_dir():
            return fake_migrations

        mig_mod._migrations_dir = patched_dir

        mgr = _make_mgr(project)
        try:
            # First run — apply all migrations from the fake dir.
            run_migrations(mgr)

            # Mutate an already-applied migration file.
            target = sorted(fake_migrations.glob("001_*.sql"))[0]
            original_bytes = target.read_bytes()
            target.write_bytes(original_bytes + b"\n-- tampered")

            with pytest.raises(RegistaError) as exc_info:
                run_migrations(mgr)

            err = exc_info.value
            assert err.code == ErrorCode.MIGRATION_DRIFT, (
                f"Expected MIGRATION_DRIFT, got {err.code}: {err.message}"
            )
            assert err.detail is not None
            assert "stored_checksum" in err.detail
            assert "current_checksum" in err.detail
            assert err.detail["stored_checksum"] != err.detail["current_checksum"]
            assert "001" in err.detail["path"]
        finally:
            mig_mod._migrations_dir = original_migrations_dir
            mgr.close()
            _drop_schema(project)

    def test_null_checksum_legacy_row_is_backfilled_not_rejected(self, tmp_path):
        """Rows inserted without a checksum (legacy / pre-BC-191) must be
        backfilled silently, not treated as drift."""
        import regista._migrations as mig_mod

        project = f"test_bc191_null_{uuid.uuid4().hex[:8]}"
        _create_schema(project)

        real_migrations = Path(mig_mod._migrations_dir())
        fake_migrations = tmp_path / "migrations"
        shutil.copytree(real_migrations, fake_migrations)

        original_migrations_dir = mig_mod._migrations_dir

        def patched_dir():
            return fake_migrations

        mig_mod._migrations_dir = patched_dir

        mgr = _make_mgr(project)
        try:
            run_migrations(mgr)

            # Simulate a legacy row by clearing the checksum for version 1.
            with psycopg.connect(DSN, autocommit=True) as conn:
                conn.execute(
                    SQL(
                        "UPDATE {}._regista_migrations "
                        "SET checksum = NULL WHERE version = 1"
                    ).format(Identifier(project))
                )

            # Re-run — should backfill, not raise.
            result = run_migrations(mgr)
            assert result == [], "No new migrations should be applied"

            # Verify the checksum was written.
            with psycopg.connect(DSN) as conn:
                row = conn.execute(
                    SQL("SELECT checksum FROM {}._regista_migrations WHERE version = 1").format(
                        Identifier(project)
                    )
                ).fetchone()
            assert row is not None and row[0] is not None, "Checksum must be backfilled"
        finally:
            mig_mod._migrations_dir = original_migrations_dir
            mgr.close()
            _drop_schema(project)
