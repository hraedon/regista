from __future__ import annotations

import hashlib
import importlib.resources
from pathlib import Path
from typing import Any

import structlog

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError

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


def applied_versions(mgr: ConnectionManager, *, read_only: bool = False) -> set[int]:
    """Return the applied migration versions for ``mgr``'s schema.

    Refuses (read-only, before any write) a pre-0.8.0 schema or an untracked
    schema. 0.8.0 is a fresh single-baseline contract: there is no rename or
    in-place upgrade path from ``_substrate_migrations`` or the 1..50 chain.
    The only write this function may perform is creating the tracking table in
    an otherwise-empty schema.
    """
    with mgr.transaction() as conn:
        probe = conn.execute(
            "SELECT "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = '_regista_migrations') "
            "AS has_regista, "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = '_substrate_migrations') "
            "AS has_substrate, "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = 'events') "
            "AS has_events",
            [mgr.schema, mgr.schema, mgr.schema],
        ).fetchone()
        assert probe is not None
        has_regista = bool(probe["has_regista"])
        has_substrate = bool(probe["has_substrate"])
        has_events = bool(probe["has_events"])

        if has_substrate and not has_regista:
            raise RegistaError(
                ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
                f"schema {mgr.schema!r} has a pre-0.8.0 `_substrate_migrations` "
                "table. In-place upgrade is unsupported; use a fresh schema or "
                "restore a dump with a matching package version.",
                detail={"reason": "pre_rename_schema"},
            )
        if not has_regista:
            if has_events:
                raise RegistaError(
                    ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
                    f"schema {mgr.schema!r} contains regista tables but no "
                    "migration-tracking table; refusing to read or write it. "
                    "In-place upgrade from pre-0.8.0 schemas is unsupported.",
                    detail={"reason": "untracked_schema"},
                )
            if read_only:
                raise RegistaError(
                    ErrorCode.MIGRATION_REQUIRED,
                    f"Read-only connect: schema {mgr.schema!r} has no "
                    "_regista_migrations table; migrations were never applied "
                    "and a read-only connection cannot create it.",
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
    max_supported = max((v for v, _ in all_migrations), default=0)

    # Refuse old or foreign schemas BEFORE any DDL. 0.8.0 is an explicitly
    # breaking reset with a single baseline; there is no in-place upgrade path
    # from the 0.5/0.6/0.7 migration chains. Detect them read-only and stop.
    with mgr.transaction() as conn:
        row = conn.execute(
            "SELECT "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "  WHERE table_schema = current_schema() AND table_name = '_regista_migrations') "
            "AS has_regista, "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "  WHERE table_schema = current_schema() AND table_name = '_substrate_migrations') "
            "AS has_substrate, "
            "EXISTS(SELECT 1 FROM information_schema.tables "
            "  WHERE table_schema = current_schema() AND table_name = 'events') "
            "AS has_events"
        ).fetchone()
        assert row is not None
        has_regista = bool(row["has_regista"])
        has_substrate = bool(row["has_substrate"])
        has_events = bool(row["has_events"])
        applied_max = 0
        if has_regista:
            r1 = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM _regista_migrations"
            ).fetchone()
            applied_max = int(r1["v"]) if r1 is not None else 0
        elif has_substrate:
            r2 = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM _substrate_migrations"
            ).fetchone()
            applied_max = int(r2["v"]) if r2 is not None else 0

    if has_substrate and not has_regista:
        raise RegistaError(
            ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            "the target schema has a pre-0.8.0 `_substrate_migrations` table. "
            "In-place upgrade is unsupported; use a fresh schema or restore a "
            "dump with a matching package version.",
            detail={"reason": "pre_rename_schema"},
        )
    if has_events and not (has_regista or has_substrate):
        raise RegistaError(
            ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            "the target schema contains regista tables but no migration-tracking "
            "table; refusing to write. In-place upgrade from pre-0.8.0 schemas is "
            "unsupported — use a fresh schema or restore a dump.",
            detail={"reason": "untracked_schema"},
        )
    if applied_max > max_supported:
        raise RegistaError(
            ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            f"the target schema is at migration version {applied_max}, but this "
            f"library only supports up to {max_supported}. Refusing to write; "
            "in-place upgrade/downgrade is unsupported.",
            detail={"applied_max": applied_max, "supported_max": max_supported},
        )

    # Empty destination: create the tracking table. No rename/upgrade path —
    # any pre-0.8.0 schema was refused above before this write.
    with mgr.transaction() as conn:
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


def check_migrations_current(mgr: ConnectionManager, *, read_only: bool = False) -> None:
    all_migrations = discover_migrations()
    if not all_migrations:
        return
    available = {v for v, _ in all_migrations}
    max_supported = max(available)
    applied = applied_versions(mgr, read_only=read_only)
    excess = {v for v in applied if v > max_supported}
    if excess:
        raise RegistaError(
            ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            f"schema {mgr.schema!r} is at migration version {max(applied)}, but "
            f"this library supports up to {max_supported}. In-place "
            "upgrade/downgrade is unsupported; use a fresh schema or restore a "
            "dump with a matching package version.",
            detail={"applied_max": max(applied), "supported_max": max_supported},
        )
    missing = available - applied
    if missing:
        raise RegistaError(
            ErrorCode.MIGRATION_REQUIRED,
            f"Migrations pending: schema {mgr.schema!r} has applied "
            f"{sorted(applied)}, missing {sorted(missing)}. "
            "Run regista migrations before starting.",
        )
