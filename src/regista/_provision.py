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
    private_key_stored: bool
    public_key_registered: bool
    already_existed: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "project": self.project,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "private_key_stored": self.private_key_stored,
            "public_key_registered": self.public_key_registered,
            "already_existed": self.already_existed,
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


def _generate_ed25519_keypair() -> tuple[bytes, bytes]:
    try:
        import nacl.signing
    except ImportError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "Ed25519 key generation requires PyNaCl: pip install regista[ed25519]",
        ) from e
    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    return private_key, public_key


def provision_principal(
    dsn: str,
    project: str,
    principal_id: str,
    *,
    hmac_key_path: str | None = None,
    private_key_dir: str | None = None,
    dry_run: bool = False,
    require_ssl: bool = False,
) -> PrincipalProvisionResult:
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    if not hmac_key_path:
        from ._config import resolve as resolve_config
        cfg = resolve_config()
        hmac_key_path = cfg.key_path
    if not hmac_key_path:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "hmac_key_path is required (set via --key-path or REGISTA_KEY_PATH)",
        )

    if dry_run:
        return PrincipalProvisionResult(
            principal_id=principal_id,
            project=project,
            key_id="(dry-run)",
            fingerprint="(dry-run)",
            private_key_stored=False,
            public_key_registered=False,
        )

    from ._connection import ConnectionManager
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
                private_key_stored=False,
                public_key_registered=False,
                already_existed=True,
            )
        except RegistaError:
            pass

        private_key, public_key = _generate_ed25519_keypair()

        key_dir = (
            Path(private_key_dir) if private_key_dir
            else Path(hmac_key_path).parent / "principals"
        )
        key_dir.mkdir(parents=True, exist_ok=True)
        priv_key_path = key_dir / f"{principal_id}_ed25519.key"
        priv_key_path.write_bytes(private_key)
        try:
            priv_key_path.chmod(0o600)
        except OSError:
            pass

        entry = register_principal_key(
            mgr,
            principal_id,
            public_key,
            "ed25519",
            registered_by="provision-principal",
        )

        _update_key_file(hmac_key_path, principal_id, entry.key_id, public_key, str(priv_key_path))

        log.info(
            "provision.principal_completed",
            principal_id=principal_id,
            project=project,
            key_id=entry.key_id,
            fingerprint=entry.fingerprint,
        )
        return PrincipalProvisionResult(
            principal_id=principal_id,
            project=project,
            key_id=entry.key_id,
            fingerprint=entry.fingerprint,
            private_key_stored=True,
            public_key_registered=True,
        )
    finally:
        mgr.close()


def _update_key_file(
    key_file_path: str,
    principal_id: str,
    key_id: str,
    public_key: bytes,
    private_key_path: str,
) -> None:
    import base64

    path = Path(key_file_path)
    if not path.is_file():
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

    keys.append({
        "key_id": key_id,
        "scheme": "ed25519",
        "principal_id": principal_id,
        "secret_ref": f"file:{private_key_path}",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "role": "actor",
        "status": "active",
    })
    data["keys"] = keys
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
