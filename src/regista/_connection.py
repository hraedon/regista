from __future__ import annotations

import re
import weakref
from collections.abc import Generator
from contextlib import contextmanager
from types import TracebackType

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier
from psycopg_pool import ConnectionPool

from ._errors import ErrorCode, RegistaError

_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_RESERVED_SCHEMAS = frozenset(
    {"public", "information_schema", "pg_catalog", "pg_toast"}
)


def validate_project_name(name: str) -> str:
    if not _SCHEMA_RE.match(name):
        raise ValueError(
            f"Invalid project name {name!r}: must be 1-63 chars, lowercase "
            "alphanumeric/underscore, start with letter or underscore"
        )
    if name in _RESERVED_SCHEMAS or name.startswith("pg_"):
        raise ValueError(
            f"Invalid project name {name!r}: reserved schema name"
        )
    return name


def _configure_session(conn: psycopg.Connection) -> None:
    conn.execute("SET synchronous_commit = on")
    conn.commit()


def _close_pool_quietly(pool: ConnectionPool) -> None:
    """Close *pool* from the interpreter-exit path, swallowing every error.

    Registered via `weakref.finalize`, whose atexit hook routes a raising
    callback to ``sys.excepthook`` — printing the very traceback this guard
    exists to remove. Nothing downstream of process exit can act on a failure
    to close, so failures are dropped rather than reported.

    Deliberately no logging: structlog may already be torn down at exit, and a
    log call here would reintroduce stderr noise on a clean run.
    """
    try:
        pool.close()
    except BaseException:
        pass


class ConnectionManager:
    def __init__(
        self,
        dsn: str,
        project: str,
        pool_min: int = 1,
        pool_max: int = 10,
        pool_max_lifetime: float | None = None,
        require_ssl: bool = False,
    ) -> None:
        self._dsn = dsn
        self._schema = validate_project_name(project)
        self._project = project
        self._require_ssl = require_ssl
        kwargs: dict = {"row_factory": dict_row}
        pool_kwargs: dict = {
            "min_size": pool_min,
            "max_size": pool_max,
            "open": False,
            "configure": _configure_session,
            "kwargs": kwargs,
        }
        if pool_max_lifetime is not None:
            pool_kwargs["max_lifetime"] = pool_max_lifetime
        self._pool = ConnectionPool(dsn, **pool_kwargs)
        # WI-218: close the pool BEFORE the interpreter's finalization window.
        # psycopg_pool's ConnectionPool.__del__ joins its live daemon workers,
        # and on Python 3.14+ Thread.join() raises PythonFinalizationError once
        # finalization has begun — surfacing an "Exception ignored while calling
        # deallocator" traceback after the process has already done its work.
        #
        # weakref.finalize is the right tool here (rather than the bare
        # atexit.register that sufficed for agent-notes WI-046, where the pool
        # was a module global): it holds only a WEAK reference to self, so
        # registering one per ConnectionManager never keeps an instance alive,
        # and its atexit hook runs before finalization. close() detaches it, so
        # an explicitly closed manager has no exit-path work left to do.
        self._finalizer = weakref.finalize(self, _close_pool_quietly, self._pool)

    @property
    def dsn(self) -> str:
        return self._dsn

    @property
    def project(self) -> str:
        return self._project

    @property
    def schema(self) -> str:
        return self._schema

    def _verify_ssl(self, conn: psycopg.Connection) -> None:
        if not self._require_ssl:
            return
        row = conn.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        ).fetchone()
        using_ssl = bool(row is not None and row["ssl"] is True)
        if not using_ssl:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "SSL is required for this connection but not active. "
                "Set sslmode=require or sslmode=verify-full in the DSN.",
            )

    def open(self) -> None:
        self._pool.open()

    def close(self) -> None:
        """Close the connection pool. Idempotent.

        Detaches the exit-path finalizer first so the pool is never closed
        twice, then closes directly — an explicit close propagates errors to
        the caller, unlike the deliberately silent exit path.
        """
        self._finalizer.detach()
        self._pool.close()

    def __enter__(self) -> ConnectionManager:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    @contextmanager
    def connect(self) -> Generator[psycopg.Connection, None, None]:
        """Yield a raw connection with search_path set to the project schema.

        Uses session-scoped SET (not SET LOCAL) because there is no enclosing
        transaction block at this level. Each pool checkout overrides the
        setting, so the next caller always gets a clean path. Callers are
        responsible for committing or rolling back as needed.
        """
        with self._pool.connection() as conn:
            self._verify_ssl(conn)
            conn.execute(
                SQL("SET search_path TO {}").format(Identifier(self._schema))
            )
            conn.commit()
            yield conn

    @contextmanager
    def transaction(self) -> Generator[psycopg.Connection, None, None]:
        with self._pool.connection() as conn:
            self._verify_ssl(conn)
            with conn.transaction():
                conn.execute(
                    SQL("SET LOCAL search_path TO {}").format(
                        Identifier(self._schema)
                    )
                )
                yield conn

    @contextmanager
    def transaction_repeatable_read(self) -> Generator[psycopg.Connection, None, None]:
        with self._pool.connection() as conn:
            self._verify_ssl(conn)
            conn.rollback()
            prev_iso = conn.isolation_level
            conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            try:
                with conn.transaction():
                    conn.execute(
                        SQL("SET LOCAL search_path TO {}").format(
                            Identifier(self._schema)
                        )
                    )
                    yield conn
            finally:
                conn.isolation_level = prev_iso

    def schema_exists(self) -> bool:
        with self._pool.connection() as conn:
            self._verify_ssl(conn)
            row = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                [self._schema],
            ).fetchone()
            return row is not None

    def create_schema(self) -> None:
        with self._pool.connection() as conn:
            self._verify_ssl(conn)
            conn.execute(
                SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                    Identifier(self._schema)
                )
            )

    def ensure_schema(self) -> None:
        if not self.schema_exists():
            raise RegistaError(
                ErrorCode.DB_NOT_FOUND,
                f"Project schema {self._schema!r} does not exist. "
                "Use Regista.create_project() to initialize it.",
            )
