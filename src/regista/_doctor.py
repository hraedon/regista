from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
    return f"{type(e).__name__}"


def _check_db_reachable(dsn: str, require_ssl: bool) -> tuple[bool, str]:
    try:
        import psycopg

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, connect_timeout=5, **connect_kwargs) as conn:
            result = conn.execute("SELECT 1").fetchone()
            if result is None:
                return False, "SELECT 1 returned no rows"
            return True, "connected"
    except Exception as e:
        return False, _sanitize_error(e)


def _list_projects(dsn: str, require_ssl: bool) -> list[dict[str, Any]]:
    try:
        import psycopg

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, connect_timeout=5, **connect_kwargs) as conn:
            rows = conn.execute(
                "SELECT schema_name FROM public.projects ORDER BY schema_name"
            ).fetchall()
            return [{"name": r[0]} for r in rows]
    except Exception:
        return []


def _check_schema_version(dsn: str, project: str, require_ssl: bool) -> DoctorCheck:
    from ._connection import validate_project_name

    try:
        validate_project_name(project)
    except ValueError as e:
        return DoctorCheck(
            name=f"schema:{project}",
            status="fail",
            detail=f"Invalid project name: {e}",
        )

    try:
        import psycopg
        from psycopg.sql import SQL, Identifier

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, connect_timeout=5, **connect_kwargs) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            rows = conn.execute(
                "SELECT version FROM _regista_migrations ORDER BY version DESC LIMIT 1"
            ).fetchall()
            if not rows:
                return DoctorCheck(
                    name=f"schema:{project}",
                    status="fail",
                    detail="No migrations applied",
                )
            applied = rows[0][0]
            if applied < SCHEMA_VERSION:
                return DoctorCheck(
                    name=f"schema:{project}",
                    status="warn",
                    detail=(
                        f"Schema version {applied}, expected "
                        f"{SCHEMA_VERSION} (migrations pending)"
                    ),
                )
            return DoctorCheck(
                name=f"schema:{project}",
                status="ok",
                detail=f"Schema version {applied}",
            )
    except Exception as e:
        return DoctorCheck(
            name=f"schema:{project}",
            status="fail",
            detail=_sanitize_error(e),
        )


def run_doctor(
    dsn: str | None = None,
    *,
    project: str | None = None,
    require_ssl: bool = False,
) -> DoctorReport:
    ver = versions()
    checks: list[DoctorCheck] = []

    if dsn is None:
        checks.append(DoctorCheck(
            name="dsn",
            status="skip",
            detail="No DSN provided",
        ))
        return DoctorReport(
            component="regista",
            version=ver.library_version,
            reachable=False,
            schema_version=None,
            projects=[],
            checks=checks,
        )

    reachable, detail = _check_db_reachable(dsn, require_ssl)
    checks.append(DoctorCheck(
        name="db:reachable",
        status="ok" if reachable else "fail",
        detail=detail,
    ))

    projects_list: list[dict[str, Any]] = []
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
            for p in projects_list:
                checks.append(_check_schema_version(dsn, p["name"], require_ssl))

    checks.append(DoctorCheck(
        name="version:schema",
        status="ok",
        detail=f"Library declares schema {SCHEMA_VERSION}, envelope {ver.envelope_version}",
    ))

    checks.append(DoctorCheck(
        name="version:signing_schemes",
        status="ok",
        detail=f"Available: {', '.join(ver.available_signing_schemes)}",
    ))

    return DoctorReport(
        component="regista",
        version=ver.library_version,
        reachable=reachable,
        schema_version=SCHEMA_VERSION if reachable else None,
        projects=projects_list,
        checks=checks,
    )
