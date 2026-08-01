from __future__ import annotations

import hashlib
import importlib.resources
from pathlib import Path
from typing import Any

import structlog

from ._connection import ConnectionManager

log = structlog.get_logger()

# Advisory lock ID for the migration runner.
# Derived as the first 8 bytes of SHA-256("regista_migrations") interpreted
# as a signed int64 (big-endian), giving 2479241334166598476.  This value is
# documented here so operators can verify non-collision with other advisory
# locks in their stack.  The probability of accidental collision with an
# application-chosen lock id is ~1/2^63.
_RAW = hashlib.sha256(b"regista_migrations").digest()
MIGRATION_LOCK_ID: int = int.from_bytes(_RAW[:8], "big")
# Interpret as signed int64 (Postgres pg_advisory_lock takes bigint)
if MIGRATION_LOCK_ID >= 2**63:
    MIGRATION_LOCK_ID -= 2**64


def _file_checksum(path: Path) -> bytes:
    """Return SHA-256 digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).digest()


def _migrations_dir() -> Path:
    pkg = importlib.resources.files("regista")
    candidate = Path(str(pkg)).joinpath("migrations")
    if candidate.is_dir():
        return candidate
    fallback = Path(str(pkg)).parent.parent / "migrations"
    if fallback.is_dir():
        return fallback
    raise FileNotFoundError("Cannot locate migrations/ directory")


def discover_migrations() -> list[tuple[int, Path]]:
    migrations_dir = _migrations_dir()
    result = []
    for p in sorted(migrations_dir.glob("*.sql")):
        stem = p.stem
        try:
            version = int(stem.split("_", 1)[0])
        except (ValueError, IndexError):
            continue
        result.append((version, p))
    result.sort(key=lambda x: x[0])
    return result


def applied_versions(mgr: ConnectionManager) -> set[int]:
    with mgr.transaction() as conn:
        conn.execute(
            "DO $$ BEGIN "
            "IF EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_name = '_substrate_migrations') THEN "
            "ALTER TABLE _substrate_migrations RENAME TO _regista_migrations; "
            "END IF; END $$"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _regista_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        rows = conn.execute(
            "SELECT version FROM _regista_migrations ORDER BY version"
        ).fetchall()
        return {row["version"] for row in rows}


def run_migrations(mgr: ConnectionManager) -> list[int]:
    # Acquire a session-level advisory lock so that concurrent callers
    # (e.g. two pods booting simultaneously) serialise here.  The lock is
    # released on every exit path via the try/finally block.
    with mgr.connect() as lock_conn:
        lock_conn.execute("SELECT pg_advisory_lock(%s)", [MIGRATION_LOCK_ID])
        lock_conn.commit()
        try:
            return _run_migrations_locked(mgr, lock_conn)
        finally:
            lock_conn.rollback()
            lock_conn.autocommit = False
            lock_conn.execute("SELECT pg_advisory_unlock(%s)", [MIGRATION_LOCK_ID])


def _run_migrations_locked(mgr: ConnectionManager, lock_conn: Any) -> list[int]:
    from ._errors import ErrorCode, RegistaError

    all_migrations = discover_migrations()

    # Ensure table exists and has the checksum column (idempotent bootstrap).
    with mgr.transaction() as conn:
        # Handle rename from pre-0.4.0: if old tracking table exists, rename it.
        conn.execute(
            "DO $$ BEGIN "
            "IF EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_name = '_substrate_migrations') THEN "
            "ALTER TABLE _substrate_migrations RENAME TO _regista_migrations; "
            "END IF; END $$"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _regista_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        # Add checksum column if migration 012 has not yet run (bootstrap safety).
        conn.execute(
            "ALTER TABLE _regista_migrations ADD COLUMN IF NOT EXISTS checksum BYTEA"
        )

    # Fetch all applied rows including stored checksums.
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT version, checksum FROM _regista_migrations ORDER BY version"
        ).fetchall()

    applied: dict[int, bytes | None] = {
        row["version"]: bytes(row["checksum"]) if row["checksum"] is not None else None
        for row in rows
    }

    # Drift detection: for already-applied migrations verify or backfill checksum.
    for version, path in all_migrations:
        if version not in applied:
            continue
        stored = applied[version]
        current = _file_checksum(path)
        if stored is None:
            # Legacy row (pre-BC-191): backfill checksum, do not raise.
            with mgr.transaction() as conn:
                conn.execute(
                    "UPDATE _regista_migrations SET checksum = %s WHERE version = %s",
                    [current, version],
                )
            log.info(
                "migrations.checksum_backfilled",
                project=mgr.project,
                version=version,
                path=path.name,
            )
        elif stored != current:
            raise RegistaError(
                ErrorCode.MIGRATION_DRIFT,
                f"Migration {version} ({path.name}) has been modified after application. "
                f"stored={stored.hex()} current={current.hex()}",
                detail={
                    "version": version,
                    "path": str(path),
                    "stored_checksum": stored.hex(),
                    "current_checksum": current.hex(),
                },
            )

    pending = [(v, p) for v, p in all_migrations if v not in applied]

    if not pending:
        log.info("migrations.up_to_date", project=mgr.project)
        return []

    applied_now = []
    for version, path in pending:
        sql = path.read_text()
        checksum = _file_checksum(path)
        use_autocommit = _has_autocommit_directive(sql)

        if use_autocommit:
            lock_conn.autocommit = True
            lock_conn.execute(sql)
            lock_conn.autocommit = False
            with lock_conn.transaction():
                lock_conn.execute(
                    "INSERT INTO _regista_migrations (version, checksum) VALUES (%s, %s)",
                    [version, checksum],
                )
        else:
            with mgr.transaction() as conn:
                conn.execute(sql)
                conn.execute(
                    "INSERT INTO _regista_migrations (version, checksum) VALUES (%s, %s)",
                    [version, checksum],
                )

        applied_now.append(version)
        log.info(
            "migrations.applied",
            project=mgr.project,
            version=version,
            path=path.name,
            autocommit=use_autocommit,
        )

    return applied_now


def repair_checksums(mgr: ConnectionManager) -> list[int]:
    with mgr.connect() as lock_conn:
        lock_conn.execute("SELECT pg_advisory_lock(%s)", [MIGRATION_LOCK_ID])
        lock_conn.commit()
        try:
            return _repair_checksums_locked(mgr)
        finally:
            lock_conn.rollback()
            lock_conn.execute("SELECT pg_advisory_unlock(%s)", [MIGRATION_LOCK_ID])


def _repair_checksums_locked(mgr: ConnectionManager) -> list[int]:
    all_migrations = discover_migrations()

    with mgr.transaction() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _regista_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        conn.execute(
            "ALTER TABLE _regista_migrations ADD COLUMN IF NOT EXISTS checksum BYTEA"
        )

    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT version, checksum FROM _regista_migrations ORDER BY version"
        ).fetchall()

    stored_by_version: dict[int, bytes | None] = {
        row["version"]: bytes(row["checksum"]) if row["checksum"] is not None else None
        for row in rows
    }

    repaired: list[int] = []
    for version, path in all_migrations:
        stored = stored_by_version.get(version)
        if stored is None:
            continue

        current = _file_checksum(path)
        if stored == current:
            continue

        with mgr.transaction() as conn:
            conn.execute(
                "UPDATE _regista_migrations SET checksum = %s WHERE version = %s",
                [current, version],
            )
        repaired.append(version)
        log.warning(
            "migrations.checksum_repaired",
            project=mgr.project,
            version=version,
            path=path.name,
            old_checksum=stored.hex(),
            new_checksum=current.hex(),
        )

    return repaired


_AC_FLAG = "-- regista: autocommit"


def _has_autocommit_directive(sql: str) -> bool:
    for line in sql.splitlines()[:5]:
        if line.strip() == _AC_FLAG:
            return True
    return False


def check_migrations_current(mgr: ConnectionManager) -> None:
    all_migrations = discover_migrations()
    if not all_migrations:
        return
    available = {v for v, _ in all_migrations}
    applied = applied_versions(mgr)
    missing = available - applied
    if missing:
        from ._errors import ErrorCode, RegistaError

        raise RegistaError(
            ErrorCode.MIGRATION_REQUIRED,
            f"Migrations pending: schema {mgr.schema!r} has applied "
            f"{sorted(applied)}, missing {sorted(missing)}. "
            "Run regista migrations before starting.",
        )
