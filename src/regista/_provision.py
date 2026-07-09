from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
from psycopg.sql import SQL, Identifier

from ._connection import validate_project_name
from ._errors import ErrorCode, RegistaError

log = structlog.get_logger()


@dataclass(frozen=True)
class ProvisionResult:
    project: str
    schema_created: bool
    migrations_applied: list[int]
    service_role_created: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "schema_created": self.schema_created,
            "migrations_applied": self.migrations_applied,
            "service_role_created": self.service_role_created,
            "error": self.error,
        }


@dataclass(frozen=True)
class PrincipalProvisionResult:
    principal_id: str
    project: str
    key_id: str
    fingerprint: str
    scheme: str
    private_key_stored: bool
    public_key_registered: bool
    already_existed: bool = False
    secret_backend: str = "file"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "project": self.project,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "private_key_stored": self.private_key_stored,
            "public_key_registered": self.public_key_registered,
            "already_existed": self.already_existed,
            "secret_backend": self.secret_backend,
            "error": self.error,
        }


def _role_name(project: str) -> str:
    return f"regista_{project}"


def _schema_exists(conn: Any, schema: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
        [schema],
    ).fetchone()
    return row is not None


def _role_exists(conn: Any, role: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM pg_roles WHERE rolname = %s",
        [role],
    ).fetchone()
    return row is not None


def _create_service_role(conn: Any, project: str) -> bool:
    role = _role_name(project)
    if _role_exists(conn, role):
        return False
    conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(role)))
    return True


def _grant_schema_privileges(conn: Any, project: str) -> None:
    role = _role_name(project)
    schema_id = Identifier(project)
    conn.execute(
        SQL(
            "GRANT USAGE ON SCHEMA {} TO {}"
        ).format(schema_id, Identifier(role))
    )
    conn.execute(
        SQL(
            "GRANT CREATE ON SCHEMA {} TO {}"
        ).format(schema_id, Identifier(role))
    )
    conn.execute(
        SQL(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}"
        ).format(schema_id, Identifier(role))
    )
    conn.execute(
        SQL(
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}"
        ).format(schema_id, Identifier(role))
    )
    conn.execute(
        SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {} "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
        ).format(schema_id, Identifier(role))
    )
    conn.execute(
        SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {} "
            "GRANT USAGE, SELECT ON SEQUENCES TO {}"
        ).format(schema_id, Identifier(role))
    )


def _revoke_cross_schema(conn: Any, project: str) -> None:
    role = _role_name(project)
    rows = conn.execute(
        """
        SELECT schema_name FROM information_schema.schemata
        WHERE schema_name <> %s
        AND schema_name NOT IN ('public', 'information_schema', 'pg_catalog', 'pg_toast')
        """,
        [project],
    ).fetchall()
    for r in rows:
        other_schema = r["schema_name"]
        conn.execute(
            SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(
                Identifier(other_schema), Identifier(role)
            )
        )


def provision(
    dsn: str,
    projects: list[str],
    *,
    dry_run: bool = False,
    require_ssl: bool = False,
) -> list[ProvisionResult]:
    results: list[ProvisionResult] = []
    for project in projects:
        validate_project_name(project)
        if dry_run:
            results.append(ProvisionResult(
                project=project,
                schema_created=True,
                migrations_applied=[],
                service_role_created=True,
            ))
            continue
        try:
            result = _provision_one(dsn, project, require_ssl=require_ssl)
            results.append(result)
        except Exception as e:
            results.append(ProvisionResult(
                project=project,
                schema_created=False,
                migrations_applied=[],
                service_role_created=False,
                error=str(e),
            ))
    return results


def _provision_one(
    dsn: str,
    project: str,
    *,
    require_ssl: bool = False,
) -> ProvisionResult:
    from ._connection import ConnectionManager
    from ._migrations import run_migrations

    mgr = ConnectionManager(dsn, project, require_ssl=require_ssl)
    schema_created = False
    migrations_applied: list[int] = []
    service_role_created = False
    try:
        mgr.open()
        if not mgr.schema_exists():
            mgr.create_schema()
            schema_created = True

        migrations_applied = run_migrations(mgr)

        with mgr._pool.connection() as conn:
            service_role_created = _create_service_role(conn, project)
            _grant_schema_privileges(conn, project)
            _revoke_cross_schema(conn, project)
            conn.commit()

        from ._projects import register_project

        with mgr.connect() as conn:
            register_project(
                conn,
                schema_name=project,
                created_by="provision",
            )
            conn.commit()

    finally:
        mgr.close()

    log.info(
        "provision.completed",
        project=project,
        schema_created=schema_created,
        migrations=len(migrations_applied),
        service_role_created=service_role_created,
    )
    return ProvisionResult(
        project=project,
        schema_created=schema_created,
        migrations_applied=migrations_applied,
        service_role_created=service_role_created,
    )


def _validate_principal_id(principal_id: str) -> str:
    import re
    if not re.match(r"^[a-zA-Z0-9._-]+$", principal_id):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Invalid principal_id {principal_id!r}: must be alphanumeric, "
            "dot, hyphen, or underscore only",
        )
    if len(principal_id) > 256:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id must be at most 256 characters",
        )
    return principal_id


def provision_principal(
    dsn: str,
    project: str,
    principal_id: str,
    *,
    hmac_key_path: str | None = None,
    private_key_dir: str | None = None,
    secret_backend: str | None = None,
    dry_run: bool = False,
    require_ssl: bool = False,
) -> PrincipalProvisionResult:
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    _validate_principal_id(principal_id)
    if not hmac_key_path:
        from ._config import resolve as resolve_config
        cfg = resolve_config()
        hmac_key_path = cfg.key_path
    if not hmac_key_path:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "hmac_key_path is required (set via --key-path or REGISTA_KEY_PATH)",
        )

    from ._custody import resolve_backend
    resolved_backend = resolve_backend(secret_backend)

    if dry_run:
        return PrincipalProvisionResult(
            principal_id=principal_id,
            project=project,
            key_id="(dry-run)",
            fingerprint="(dry-run)",
            scheme="ed25519",
            private_key_stored=False,
            public_key_registered=False,
            secret_backend=resolved_backend,
        )

    from ._connection import ConnectionManager
    from ._custody import store_private_key
    from ._principal_keys import get_active_key, register_principal_key

    mgr = ConnectionManager(dsn, project, require_ssl=require_ssl)
    try:
        mgr.open()
        mgr.ensure_schema()

        try:
            existing = get_active_key(mgr, principal_id)
            return PrincipalProvisionResult(
                principal_id=principal_id,
                project=project,
                key_id=existing.key_id,
                fingerprint=existing.fingerprint,
                scheme=existing.scheme,
                private_key_stored=False,
                public_key_registered=False,
                already_existed=True,
                secret_backend=resolved_backend,
            )
        except RegistaError:
            pass

        key_dir = _resolve_key_dir(
            private_key_dir, hmac_key_path, resolved_backend,
        )

        custody = store_private_key(
            backend=resolved_backend,
            principal_id=principal_id,
            project=project,
            private_key_dir=key_dir,
        )

        try:
            entry = register_principal_key(
                mgr,
                principal_id,
                custody.public_key,
                "ed25519",
                registered_by="provision-principal",
            )
        except Exception:
            log.error(
                "provision.principal_orphaned_secret",
                principal_id=principal_id,
                project=project,
                secret_ref=custody.secret_ref,
                backend=custody.backend,
            )
            raise

        _update_key_file(
            hmac_key_path,
            principal_id,
            entry.key_id,
            custody.public_key,
            custody.secret_ref,
            encoding=custody.encoding,
        )

        log.info(
            "provision.principal_completed",
            principal_id=principal_id,
            project=project,
            key_id=entry.key_id,
            fingerprint=entry.fingerprint,
            secret_backend=custody.backend,
        )
        return PrincipalProvisionResult(
            principal_id=principal_id,
            project=project,
            key_id=entry.key_id,
            fingerprint=entry.fingerprint,
            scheme=entry.scheme,
            private_key_stored=True,
            public_key_registered=True,
            secret_backend=custody.backend,
        )
    finally:
        mgr.close()


def _resolve_key_dir(
    private_key_dir: str | None,
    hmac_key_path: str,
    backend: str,
) -> str | None:
    if private_key_dir:
        return private_key_dir
    if backend != "file":
        return None
    from ._secrets import _detect_prefix

    prefix, stripped = _detect_prefix(hmac_key_path)
    if prefix == "file":
        base = stripped
    else:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"private_key_dir is required for the 'file' backend when "
            f"hmac_key_path is a non-file secret reference "
            f"(prefix {prefix!r}); cannot derive a directory from "
            f"{hmac_key_path!r}.",
        )
    return str(Path(base).parent / "principals")


def _update_key_file(
    key_file_path: str,
    principal_id: str,
    key_id: str,
    public_key: bytes,
    secret_ref: str,
    *,
    encoding: str | None = None,
) -> None:
    import base64
    import os as _os

    path = Path(key_file_path)
    from ._secrets import _ensure_secure_dir

    _ensure_secure_dir(path.parent)

    lock_fd = _os.open(str(path), _os.O_RDWR | _os.O_CREAT, 0o600)
    try:
        _flock(lock_fd)
        if not path.is_file() or path.stat().st_size == 0:
            data: dict[str, Any] = {"keys": []}
        else:
            try:
                data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                data = {"keys": []}

        if not isinstance(data, dict) or "keys" not in data:
            data = {"keys": []}

        keys: list[dict[str, Any]] = data.get("keys", [])
        existing = [
            k for k in keys
            if k.get("principal_id") == principal_id and k.get("key_id") == key_id
        ]
        if existing:
            return

        for k in keys:
            if k.get("principal_id") == principal_id and k.get("status") == "active":
                k["status"] = "deprecated"

        entry: dict[str, Any] = {
            "key_id": key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": secret_ref,
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "role": "actor",
            "status": "active",
        }
        if encoding is not None:
            entry["encoding"] = encoding
        keys.append(entry)
        data["keys"] = keys

        tmp_path = path.with_suffix(path.suffix + ".tmp")
        from ._secrets import _open_exclusive

        fd, tmp_path = _open_exclusive(tmp_path)
        try:
            payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
            remaining = memoryview(payload)
            while remaining:
                n = _os.write(fd, remaining)
                remaining = remaining[n:]
        finally:
            _os.close(fd)
        _os.replace(str(tmp_path), str(path))
    finally:
        _os.close(lock_fd)


def _flock(fd: int) -> None:
    try:
        import fcntl
    except ImportError:
        return
    fcntl.flock(fd, fcntl.LOCK_EX)
