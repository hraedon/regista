from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
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
        has_fail = any(c.status == "fail" for c in self.checks)
        has_warn = any(c.status == "warn" for c in self.checks)
        ok = self.reachable and not has_fail
        return {
            "component": self.component,
            "version": self.version,
            "ok": ok,
            "degraded": ok and has_warn,
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


def _resolve_key_file_path(key_path: str) -> str | None:
    from ._errors import RegistaError
    from ._secrets import _detect_prefix, resolve_str

    prefix, stripped = _detect_prefix(key_path)
    if prefix == "file":
        return stripped
    if prefix == "literal":
        return key_path
    try:
        return resolve_str(key_path)
    except RegistaError:
        return None


def _check_custody_consistency(
    key_path: str | None,
    secret_backend: str | None,
) -> DoctorCheck:
    if not key_path:
        return DoctorCheck(
            name="custody:consistency",
            status="skip",
            detail="No key_path configured",
        )
    backend = (secret_backend or "file").lower()
    fs_path = _resolve_key_file_path(key_path)
    if fs_path is None:
        return DoctorCheck(
            name="custody:consistency",
            status="skip",
            detail=f"Cannot resolve key_path {key_path!r} to a filesystem path",
        )
    path = Path(fs_path)
    if not path.is_file():
        return DoctorCheck(
            name="custody:consistency",
            status="skip",
            detail=f"Key file not found: {fs_path}",
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return DoctorCheck(
            name="custody:consistency",
            status="skip",
            detail="Key file unreadable or invalid JSON",
        )
    if not isinstance(data, dict):
        return DoctorCheck(
            name="custody:consistency",
            status="skip",
            detail="Key file is not a JSON object",
        )
    keys: list[dict[str, Any]] = data.get("keys", [])
    principal_entries = [
        k for k in keys
        if isinstance(k, dict) and k.get("principal_id") and k.get("secret_ref")
    ]
    if not principal_entries:
        return DoctorCheck(
            name="custody:consistency",
            status="ok",
            detail="No principal keys with secret_ref to check",
        )
    mismatches: list[str] = []
    for entry in principal_entries:
        ref = entry["secret_ref"]
        scheme = ref.split(":", 1)[0] if ":" in ref else "file"
        if backend == "operator":
            mismatches.append(
                f"{entry['principal_id']}: {scheme} (operator backend is read-only)"
            )
        elif scheme != backend:
            mismatches.append(
                f"{entry['principal_id']}: {scheme} (expected {backend})"
            )
    if mismatches:
        return DoctorCheck(
            name="custody:consistency",
            status="warn",
            detail="; ".join(mismatches),
        )
    return DoctorCheck(
        name="custody:consistency",
        status="ok",
        detail=f"{len(principal_entries)} principal key(s) match backend {backend}",
    )


def run_doctor(
    dsn: str | None = None,
    *,
    project: str | None = None,
    require_ssl: bool = False,
    key_path: str | None = None,
    secret_backend: str | None = None,
) -> DoctorReport:
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

    checks.append(_check_custody_consistency(key_path, secret_backend))

    return DoctorReport(
        component="regista",
        version=ver.library_version,
        reachable=reachable,
        schema_version=SCHEMA_VERSION if reachable else None,
        projects=projects_list,
        checks=checks,
    )
