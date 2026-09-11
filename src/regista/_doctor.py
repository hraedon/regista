from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

from ._connection import ConnectionManager, DictConn, validate_project_name
from ._errors import ErrorCode, RegistaError
from ._migrations import check_migrations_current
from ._projects import list_catalog_projects
from ._version_info import SCHEMA_VERSION, versions

_check_status_values = frozenset({"ok", "warn", "fail", "skip"})


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str

    def __post_init__(self) -> None:
        if self.status not in _check_status_values:
            raise ValueError(f"Invalid status {self.status!r}")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DoctorReport:
    component: str
    version: str
    reachable: bool
    schema_version: int | None
    projects: list[dict[str, Any]]
    checks: list[DoctorCheck]

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "version": self.version,
            "reachable": self.reachable,
            "schema_version": self.schema_version,
            "projects": list(self.projects),
            "checks": [c.to_dict() for c in self.checks],
        }


def _sanitize_error(e: Exception) -> str:
    # Only the exception type: a psycopg connection error message can embed
    # host/user detail, and the doctor contract is a health surface, not a
    # credential-adjacent one.
    return type(e).__name__


def _mask_dsn(dsn: str | None) -> str:
    if not dsn:
        return "(not set)"
    parsed = urlparse(dsn)
    if parsed.password:
        netloc = f"{parsed.username}:***@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        return parsed._replace(netloc=netloc).geturl()
    return dsn


def _connect_kwargs(require_ssl: bool) -> dict[str, Any]:
    return {"sslmode": "require"} if require_ssl else {}


def _check_db_reachable(dsn: str, require_ssl: bool) -> tuple[bool, str]:
    try:
        import psycopg

        with psycopg.connect(
            dsn, connect_timeout=5, **_connect_kwargs(require_ssl)
        ) as conn:
            result = conn.execute("SELECT 1").fetchone()
            if result is None:
                return False, "SELECT 1 returned no rows"
            return True, f"connected to {_mask_dsn(dsn)}"
    except Exception as e:
        return False, _sanitize_error(e)


def _list_projects(dsn: str, require_ssl: bool) -> list[dict[str, Any]]:
    try:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(
            dsn,
            connect_timeout=5,
            row_factory=dict_row,
            **_connect_kwargs(require_ssl),
        ) as conn:
            entries = list_catalog_projects(cast(DictConn, conn))
            return [{"name": e.schema_name} for e in entries]
    except Exception:
        return []


def _check_schema_version(dsn: str, project: str, require_ssl: bool) -> DoctorCheck:
    name = f"schema:{project}"
    try:
        validate_project_name(project)
    except ValueError as e:
        return DoctorCheck(name=name, status="fail", detail=f"Invalid project name: {e}")

    mgr = ConnectionManager(dsn, project, require_ssl=require_ssl)
    try:
        mgr.open()
        if not mgr.schema_exists():
            return DoctorCheck(
                name=name,
                status="fail",
                detail=f"Project schema {project!r} is not present",
            )
        try:
            check_migrations_current(mgr, read_only=True)
        except RegistaError as e:
            if e.code is ErrorCode.MIGRATION_REQUIRED:
                return DoctorCheck(
                    name=name,
                    status="warn",
                    detail=(
                        f"Schema {project!r} is present but not current: "
                        f"{e.message} (library declares schema {SCHEMA_VERSION})"
                    ),
                )
            return DoctorCheck(
                name=name,
                status="fail",
                detail=f"{e.code}: {e.message}",
            )
        return DoctorCheck(
            name=name,
            status="ok",
            detail=f"Schema version {SCHEMA_VERSION} (current)",
        )
    except Exception as e:
        return DoctorCheck(name=name, status="fail", detail=_sanitize_error(e))
    finally:
        try:
            mgr.close()
        except Exception:  # pragma: no cover - close is best-effort
            pass


def run_doctor(
    dsn: str | None = None,
    *,
    project: str | None = None,
    require_ssl: bool = False,
    key_path: str | None = None,
    secret_backend: str | None = None,
    max_projects: int = 25,
) -> DoctorReport:
    """Run the regista health checks.

    A small, database-only contract: is Postgres reachable, does a project's
    schema carry the current migration baseline, and what does the project
    catalog hold. Unreachable infrastructure is reported as a clean ``fail``
    check, never a raised traceback.

    Args:
        dsn: Postgres connection string. ``None`` skips the DB checks.
        project: Target a single project schema instead of the catalog.
        require_ssl: Connect with ``sslmode=require``.
        key_path: Accepted for CLI compatibility; retired with the key/trust
            subsystem and unused by the kernel.
        secret_backend: Accepted for CLI compatibility; unused.
        max_projects: Upper bound on how many catalog projects are checked
            when ``project`` is not given; the ``projects`` check names the cap.
    """
    ver = versions()
    checks: list[DoctorCheck] = []
    reachable = False
    projects_list: list[dict[str, Any]] = []

    if dsn is None:
        checks.append(DoctorCheck(
            name="dsn",
            status="skip",
            detail="No DSN provided",
        ))
    else:
        reachable, detail = _check_db_reachable(dsn, require_ssl)
        checks.append(DoctorCheck(
            name="db:reachable",
            status="ok" if reachable else "fail",
            detail=detail,
        ))

        if reachable:
            projects_list = _list_projects(dsn, require_ssl)

            if project:
                checks.append(_check_schema_version(dsn, project, require_ssl))
            elif not projects_list:
                checks.append(DoctorCheck(
                    name="projects",
                    status="warn",
                    detail="No projects registered in public.projects catalog",
                ))
            else:
                names = [p["name"] for p in projects_list]
                if max_projects > 0 and len(names) > max_projects:
                    checked_projects = names[:max_projects]
                    checks.append(DoctorCheck(
                        name="projects",
                        status="warn",
                        detail=(
                            f"{len(names)} projects registered; checked the "
                            f"first {max_projects} — pass --project to target one"
                        ),
                    ))
                else:
                    checked_projects = names
                for name in checked_projects:
                    checks.append(_check_schema_version(dsn, name, require_ssl))

    checks.append(DoctorCheck(
        name="version:schema",
        status="ok",
        detail=f"Library declares schema {SCHEMA_VERSION}",
    ))

    return DoctorReport(
        component="regista",
        version=ver.library_version,
        reachable=reachable,
        schema_version=SCHEMA_VERSION if reachable else None,
        projects=projects_list,
        checks=checks,
    )
