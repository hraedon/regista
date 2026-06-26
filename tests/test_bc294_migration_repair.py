from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Regista
from regista._connection import ConnectionManager
from regista._migrations import discover_migrations, repair_checksums, run_migrations
from regista.testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = "tests/test_keys.json"


def _migrations_dir() -> Path:
    return Path(__file__).parent.parent / "migrations"


def _file_checksum(path: Path) -> bytes:
    return hashlib.sha256(path.read_bytes()).digest()


@pytest.fixture
def fresh_project():
    project = f"test_bc294_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    yield project
    sub.close()
    drop_project_schema(DSN, project)


def test_repair_checksums_updates_drifted(fresh_project):
    project = fresh_project
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        migrations = discover_migrations()
        target_version, target_path = migrations[0]
        current = _file_checksum(target_path)
        wrong = bytes(b ^ 0xFF for b in current)
        with mgr.transaction() as conn:
            conn.execute(
                "UPDATE _regista_migrations SET checksum = %s WHERE version = %s",
                [wrong, target_version],
            )

        repaired = repair_checksums(mgr)

        assert target_version in repaired
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT checksum FROM _regista_migrations WHERE version = %s",
                [target_version],
            ).fetchone()
            assert bytes(row["checksum"]) == current
    finally:
        mgr.close()


def test_repair_checksums_no_drift(fresh_project):
    project = fresh_project
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        repaired = repair_checksums(mgr)
        assert repaired == []
    finally:
        mgr.close()


def test_autocommit_migration_mode(fresh_project, tmp_path):
    import regista._migrations as mig_mod

    project = fresh_project
    real_migrations = Path(mig_mod._migrations_dir())
    fake_migrations = tmp_path / "migrations"
    shutil.copytree(real_migrations, fake_migrations)

    original_migrations_dir = mig_mod._migrations_dir
    mig_mod._migrations_dir = lambda: fake_migrations

    version = 999
    path = fake_migrations / f"{version:03d}_test_concurrent.sql"
    try:
        path.write_text(
            "-- regista: autocommit\n"
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_test_concurrent ON events (timestamp);\n"
        )
        mgr = ConnectionManager(DSN, project)
        try:
            mgr.open()
            applied = run_migrations(mgr)
            assert version in applied
        finally:
            mgr.close()

        with psycopg.connect(DSN) as conn:
            row = conn.execute(
                "SELECT 1 FROM pg_indexes WHERE schemaname = %s AND indexname = %s",
                [project, "idx_test_concurrent"],
            ).fetchone()
            assert row is not None
    finally:
        mig_mod._migrations_dir = original_migrations_dir
        with psycopg.connect(DSN) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            conn.execute("DROP INDEX IF EXISTS idx_test_concurrent")
            conn.commit()


def test_cli_schema_repair_checksums(fresh_project, capsys):
    from regista._cli import main

    project = fresh_project
    main(["--dsn", DSN, "--project", project, "schema", "repair-checksums"])
    captured = capsys.readouterr()
    assert "No checksum drift detected" in captured.out
