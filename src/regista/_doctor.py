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


def _check_role_attributes(dsn: str, require_ssl: bool) -> DoctorCheck:
    # Reports the connecting (session) role's rolcreaterole so the suite
    # bootstrap can verify the documented CREATEROLE prerequisite before it
    # provisions per-project service roles (WI-230).
    try:
        import psycopg

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(dsn, connect_timeout=5, **connect_kwargs) as conn:
            row = conn.execute(
                "SELECT rolname, rolsuper, rolcreaterole "
                "FROM pg_roles WHERE rolname = session_user"
            ).fetchone()
    except Exception as e:
        return DoctorCheck(
            name="role:createrole",
            status="warn",
            detail=f"Could not read session role attributes: {_sanitize_error(e)}",
        )

    if row is None:
        return DoctorCheck(
            name="role:createrole",
            status="warn",
            detail="Session role not found in pg_roles",
        )

    rolname, rolsuper, rolcreaterole = row[0], row[1], row[2]
    if rolsuper or rolcreaterole:
        reason = "superuser" if rolsuper else "rolcreaterole=true"
        return DoctorCheck(
            name="role:createrole",
            status="ok",
            detail=f"session role {rolname!r}: {reason} (can create roles)",
        )
    return DoctorCheck(
        name="role:createrole",
        status="warn",
        detail=(
            f"session role {rolname!r}: rolcreaterole=false; "
            "'regista provision' creates per-project service roles and "
            "requires CREATEROLE or superuser"
        ),
    )


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


_ANCHORING_STALE_AFTER_SECONDS = 3600


def _check_anchoring_stale_receipts(
    dsn: str,
    project: str,
    require_ssl: bool,
    stale_after_seconds: int,
) -> DoctorCheck:
    # WI-206: latest_confirmed_seq treats pending/retryable receipts as the
    # anchoring watermark, so a receipt stuck in either state (a crash that
    # left receipt_bytes NULL, or retry_failed_anchors never being scheduled)
    # silently stops new events from ever being anchored. Surface receipts that
    # have been stuck longer than the threshold so bootstrap/operators see it.
    from ._connection import validate_project_name

    name = f"anchoring:{project}"
    try:
        validate_project_name(project)
    except ValueError as e:
        return DoctorCheck(
            name=name,
            status="fail",
            detail=f"Invalid project name: {e}",
        )

    try:
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.sql import SQL, Identifier

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(
            dsn, connect_timeout=5, row_factory=dict_row, **connect_kwargs
        ) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            present = conn.execute(
                "SELECT to_regclass('anchor_receipts') IS NOT NULL AS present"
            ).fetchone()["present"]
            if not present:
                return DoctorCheck(
                    name=name,
                    status="skip",
                    detail="anchor_receipts table absent (anchoring migration not applied)",
                )
            row = conn.execute(
                "SELECT count(*) AS n, min(submitted_at) AS oldest "
                "FROM anchor_receipts "
                "WHERE status IN ('pending', 'retryable') "
                "AND submitted_at < now() - make_interval(secs => %s)",
                [stale_after_seconds],
            ).fetchone()
            stale_count = row["n"]
            oldest = row["oldest"]
            watermark = conn.execute(
                "SELECT COALESCE(MAX(target_global_seq), 0) AS max_seq "
                "FROM anchor_receipts "
                "WHERE status IN ('pending', 'committed', 'confirmed', 'retryable')"
            ).fetchone()["max_seq"]
    except Exception as e:
        return DoctorCheck(
            name=name,
            status="fail",
            detail=_sanitize_error(e),
        )

    if stale_count == 0:
        return DoctorCheck(
            name=name,
            status="ok",
            detail=(
                f"no receipts stuck pending/retryable beyond {stale_after_seconds}s"
            ),
        )
    age_detail = f", oldest submitted_at={oldest.isoformat()}" if oldest is not None else ""
    return DoctorCheck(
        name=name,
        status="warn",
        detail=(
            f"{stale_count} receipt(s) stuck pending/retryable beyond "
            f"{stale_after_seconds}s{age_detail}; the anchoring watermark is held at "
            f"global_seq={watermark} — retry or re-submit anchoring to unblock it"
        ),
    )


def _check_witness_key_enrollment(
    dsn: str,
    project: str,
    require_ssl: bool,
) -> DoctorCheck:
    from ._connection import validate_project_name
    from ._witness import witness_principal_id

    name = f"witness:key_enrollment:{project}"
    try:
        validate_project_name(project)
    except ValueError as e:
        return DoctorCheck(
            name=name,
            status="fail",
            detail=f"Invalid project name: {e}",
        )

    try:
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.sql import SQL, Identifier

        connect_kwargs: dict[str, Any] = {}
        if require_ssl:
            connect_kwargs["sslmode"] = "require"
        with psycopg.connect(
            dsn, connect_timeout=5, row_factory=dict_row, **connect_kwargs
        ) as conn:
            conn.execute(
                SQL("SET search_path TO {}").format(Identifier(project))
            )
            present = conn.execute(
                "SELECT to_regclass('witness_registrations') IS NOT NULL AS present"
            ).fetchone()["present"]
            if not present:
                return DoctorCheck(
                    name=name,
                    status="skip",
                    detail="witness_registrations table absent",
                )
            pk_present = conn.execute(
                "SELECT to_regclass('principal_keys') IS NOT NULL AS present"
            ).fetchone()["present"]
            if not pk_present:
                return DoctorCheck(
                    name=name,
                    status="skip",
                    detail="principal_keys table absent",
                )
            witnesses = conn.execute(
                "SELECT witness_id, public_key FROM witness_registrations "
                "WHERE key_scheme = 'ed25519' AND public_key IS NOT NULL"
            ).fetchall()
            if not witnesses:
                return DoctorCheck(
                    name=name,
                    status="ok",
                    detail="no Ed25519 witnesses to enroll",
                )
            gaps: list[str] = []
            for w in witnesses:
                row = conn.execute(
                    "SELECT public_key FROM principal_keys "
                    "WHERE principal_id = %s AND status = 'active'",
                    [witness_principal_id(w["witness_id"])],
                ).fetchone()
                if row is None or bytes(row["public_key"]) != bytes(w["public_key"]):
                    gaps.append(str(w["witness_id"]))
    except Exception as e:
        return DoctorCheck(
            name=name,
            status="fail",
            detail=_sanitize_error(e),
        )

    if gaps:
        return DoctorCheck(
            name=name,
            status="warn",
            detail=(
                f"{len(gaps)} Ed25519 witness key(s) not enrolled (or pinned "
                f"key differs) in the anchored principal-keys registry: "
                f"{', '.join(gaps[:8])}"
            ),
        )
    return DoctorCheck(
        name=name,
        status="ok",
        detail=f"{len(witnesses)} Ed25519 witness key(s) enrolled",
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


def _check_vault_auth(secret_backend: str | None) -> DoctorCheck:
    """Report which Vault auth method this host is on (WI-228).

    The Linux qualification could not run AppRole-only and had to inject a token
    per invocation from a wrapper script. Nothing in any health surface said so,
    which is what made a compensating control look like a working posture. This
    row states the method, so a host sitting on the dev method is visible rather
    than merely undocumented.

    Graded, not merely reported: AppRole is ``ok``, a static token is ``warn``
    (dev posture — docs/secrets-vault.md §6 wants no VAULT_TOKEN in a production
    environment), and AppRole material that is present but unusable is ``fail``,
    because that host resolves nothing.
    """
    from ._secrets import vault_auth_status

    status = vault_auth_status()
    if not status.get("provider_available"):
        if (secret_backend or "").lower() == "vault":
            return DoctorCheck(
                name="custody:vault_auth",
                status="fail",
                detail=(
                    "secret_backend is 'vault' but the vault provider is not "
                    "registered in this process — 'hvac' is not importable here. "
                    "Each component resolves vault: refs in its own environment; "
                    "install the vault extra for this one."
                ),
            )
        return DoctorCheck(
            name="custody:vault_auth",
            status="skip",
            detail="vault provider not registered in this process ('hvac' absent)",
        )
    if not status.get("vault_addr_set") and (secret_backend or "").lower() != "vault":
        return DoctorCheck(
            name="custody:vault_auth",
            status="skip",
            detail="No Vault configured (VAULT_ADDR unset)",
        )
    method = status.get("configured_method")
    if method is None:
        return DoctorCheck(
            name="custody:vault_auth",
            status="fail",
            detail=str(status.get("configured_error") or "vault: no usable credentials"),
        )
    if method == "approle":
        return DoctorCheck(
            name="custody:vault_auth",
            status="ok",
            detail=(
                f"vault auth: AppRole at auth/{status.get('approle_mount')} — "
                f"role_id from {status.get('role_id_source')}, secret_id from "
                f"{status.get('secret_id_source')}. No VAULT_TOKEN required."
            ),
        )
    return DoctorCheck(
        name="custody:vault_auth",
        status="warn",
        detail=(
            f"vault auth: static token ({status.get('token_source')}) — the "
            f"dev-only method. A production host operates AppRole-only with no "
            f"VAULT_TOKEN in its environment: set VAULT_ROLE_ID and "
            f"VAULT_SECRET_ID_FILE (agent-suite docs/secrets-vault.md §6)."
        ),
    )


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
    anchoring_stale_after_seconds: int | None = None,
) -> DoctorReport:
    ver = versions()
    checks: list[DoctorCheck] = []
    reachable = False
    projects_list: list[dict[str, Any]] = []
    stale_after = (
        anchoring_stale_after_seconds
        if anchoring_stale_after_seconds is not None
        else _ANCHORING_STALE_AFTER_SECONDS
    )

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
            checks.append(_check_role_attributes(dsn, require_ssl))

            if project:
                checks.append(_check_schema_version(dsn, project, require_ssl))
                checks.append(
                    _check_anchoring_stale_receipts(dsn, project, require_ssl, stale_after)
                )
                checks.append(
                    _check_witness_key_enrollment(dsn, project, require_ssl)
                )
            elif not projects_list:
                checks.append(DoctorCheck(
                    name="projects",
                    status="warn",
                    detail="No projects registered in public.projects catalog",
                ))
            else:
                for p in projects_list:
                    checks.append(_check_schema_version(dsn, p["name"], require_ssl))
                    checks.append(
                        _check_anchoring_stale_receipts(
                            dsn, p["name"], require_ssl, stale_after
                        )
                    )
                    checks.append(
                        _check_witness_key_enrollment(dsn, p["name"], require_ssl)
                    )

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

    checks.append(_check_vault_auth(secret_backend))

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
