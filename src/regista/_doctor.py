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
    # WI-223: be explicit that this compares secret_ref custody prefixes only.
    # The previous wording ("N principal key(s) match backend file") was read as
    # a statement that the principal keys were consistent with the project's
    # registry — a claim this check has never made. That claim now lives in
    # custody:registration.
    return DoctorCheck(
        name="custody:consistency",
        status="ok",
        detail=(
            f"{len(principal_entries)} principal key(s) have secret_ref custody "
            f"matching the {backend!r} backend (custody prefix only; "
            f"registry binding is custody:registration)"
        ),
    )


def _load_key_file_principals(key_path: str | None) -> dict[str, list[dict[str, Any]]]:
    """Map principal_id -> its key-file entries, in file order. Empty on any error."""
    if not key_path:
        return {}
    fs_path = _resolve_key_file_path(key_path)
    if fs_path is None:
        return {}
    path = Path(fs_path)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    keys = data.get("keys", [])
    if not isinstance(keys, list):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for k in keys:
        if not isinstance(k, dict):
            continue
        pid = k.get("principal_id")
        if not pid:
            continue
        out.setdefault(str(pid), []).append(k)
    return out


def _check_principal_registration(
    dsn: str | None,
    projects: list[str],
    key_path: str | None,
    require_ssl: bool,
) -> DoctorCheck:
    """Does the key the signer would pick have an active row in each project?

    WI-223. ``keys.json`` is shared across projects; ``principal_keys`` is
    per-project. When ``provision-principal`` ran for the same principal in two
    projects, the second run appended a second keypair to the shared file and
    demoted the first, so the signer began signing the *first* project's events
    with a key that project never registered. Nothing in ``regista doctor``
    looked at that: ``custody:consistency`` only compares ``secret_ref``
    prefixes. This check closes it — for every principal a project has
    registered keys for, the key the signer would select from the key file must
    be active in that project's ``principal_keys``.

    Principals with no key-file entry are not flagged: a project legitimately
    holds registry rows for principals that sign from another host's key file.
    """
    from ._keys import select_signing_key_id

    if not key_path:
        return DoctorCheck(
            name="custody:registration",
            status="skip",
            detail="No key_path configured",
        )
    if dsn is None or not projects:
        return DoctorCheck(
            name="custody:registration",
            status="skip",
            detail="No reachable project to check the key file against",
        )
    file_principals = _load_key_file_principals(key_path)
    if not file_principals:
        return DoctorCheck(
            name="custody:registration",
            status="skip",
            detail="Key file has no per-principal keys to check",
        )

    from ._connection import validate_project_name

    failures: list[str] = []
    checked = 0
    try:
        import psycopg
        from psycopg.sql import SQL, Identifier

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, connect_timeout=5, **connect_kwargs) as conn:
            for project in projects:
                try:
                    validate_project_name(project)
                except ValueError:
                    continue
                conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
                try:
                    rows = conn.execute(
                        "SELECT principal_id, key_id FROM principal_keys "
                        "WHERE status = 'active'"
                    ).fetchall()
                except Exception:
                    conn.rollback()
                    continue
                active_by_principal: dict[str, set[str]] = {}
                for pid, kid in rows:
                    active_by_principal.setdefault(pid, set()).add(kid)
                for pid, active_ids in active_by_principal.items():
                    entries = file_principals.get(pid)
                    if not entries:
                        continue
                    selected = select_signing_key_id(
                        [
                            (
                                str(e.get("key_id")),
                                str(e.get("scheme", "hmac-sha256")),
                                str(e.get("status", "active")),
                            )
                            for e in entries
                        ]
                    )
                    checked += 1
                    if selected is None:
                        failures.append(
                            f"{project}/{pid}: key file has no active key; "
                            f"project registers {sorted(active_ids)}"
                        )
                    elif selected not in active_ids:
                        failures.append(
                            f"{project}/{pid}: signer would use {selected!r}, "
                            f"which is not active in this project "
                            f"(registered: {sorted(active_ids)})"
                        )
    except Exception as e:
        return DoctorCheck(
            name="custody:registration",
            status="skip",
            detail=f"Could not read principal_keys: {_sanitize_error(e)}",
        )

    if failures:
        return DoctorCheck(
            name="custody:registration",
            status="fail",
            detail=(
                "signing key not registered in the project it signs for — "
                "chains written by these principals are not attributable and "
                "`regista bundle verify` will reject them: "
                + "; ".join(sorted(failures))
            ),
        )
    if checked == 0:
        return DoctorCheck(
            name="custody:registration",
            status="skip",
            detail="No principal is both registered in a project and present in the key file",
        )
    return DoctorCheck(
        name="custody:registration",
        status="ok",
        detail=(
            f"{checked} principal/project binding(s): the key the signer would "
            f"select is active in that project's principal_keys"
        ),
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

    if reachable:
        if project:
            registration_projects = [project]
        else:
            registration_projects = [p["name"] for p in projects_list]
        checks.append(
            _check_principal_registration(
                dsn, registration_projects, key_path, require_ssl,
            )
        )
    else:
        checks.append(DoctorCheck(
            name="custody:registration",
            status="skip",
            detail="Database not reachable",
        ))

    return DoctorReport(
        component="regista",
        version=ver.library_version,
        reachable=reachable,
        schema_version=SCHEMA_VERSION if reachable else None,
        projects=projects_list,
        checks=checks,
    )
