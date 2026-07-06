from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError


@dataclass(frozen=True)
class PrincipalKeyEntry:
    principal_id: str
    key_id: str
    scheme: str
    public_key: bytes
    fingerprint: str
    status: str
    valid_from: datetime
    valid_to: datetime | None
    registered_by: str
    registered_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "scheme": self.scheme,
            "public_key": self.public_key.hex(),
            "fingerprint": self.fingerprint,
            "status": self.status,
            "valid_from": self.valid_from.isoformat(),
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
        }


def _compute_fingerprint(public_key: bytes, scheme: str) -> str:
    return f"{scheme}:sha256:{hashlib.sha256(public_key).hexdigest()}"


def _generate_key_id() -> str:
    return f"pk_{uuid.uuid4().hex[:16]}"


def principal_entity_id(principal_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_OID, f"principal:{principal_id}")


def register_principal_key(
    mgr: ConnectionManager,
    principal_id: str,
    public_key: bytes,
    scheme: str,
    *,
    key_id: str | None = None,
    registered_by: str = "system",
) -> PrincipalKeyEntry:
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    if not public_key:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "public_key is required",
        )

    if key_id is None:
        key_id = _generate_key_id()

    fingerprint = _compute_fingerprint(public_key, scheme)

    with mgr.transaction() as conn:
        conn.execute(
            "SELECT key_id FROM principal_keys "
            "WHERE principal_id = %s FOR UPDATE",
            [principal_id],
        )

        existing = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchall()

        if existing:
            row = existing[0]
            if row["status"] == "active":
                return _row_to_entry(row)
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEY_ALREADY_EXISTS,
                f"Key {key_id} already exists for principal "
                f"{principal_id} with status {row['status']}",
            )

        existing_active = conn.execute(
            "SELECT key_id FROM principal_keys "
            "WHERE principal_id = %s AND status = 'active'",
            [principal_id],
        ).fetchall()

        for r in existing_active:
            conn.execute(
                "UPDATE principal_keys SET status = 'superseded' "
                "WHERE principal_id = %s AND key_id = %s",
                [principal_id, r["key_id"]],
            )

        conn.execute(
            """
            INSERT INTO principal_keys
                (principal_id, key_id, scheme, public_key, fingerprint,
                 status, registered_by)
            VALUES (%s, %s, %s, %s, %s, 'active', %s)
            """,
            [principal_id, key_id, scheme, public_key, fingerprint, registered_by],
        )

        row = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchone()

    return _row_to_entry(row)


def _fetch_entry(
    mgr: ConnectionManager,
    principal_id: str,
    key_id: str,
) -> PrincipalKeyEntry:
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchall()
    if not rows:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEY_NOT_FOUND,
            f"Principal key not found: {principal_id}/{key_id}",
        )
    return _row_to_entry(rows[0])


def _row_to_entry(row: dict[str, Any]) -> PrincipalKeyEntry:
    return PrincipalKeyEntry(
        principal_id=row["principal_id"],
        key_id=row["key_id"],
        scheme=row["scheme"],
        public_key=bytes(row["public_key"]),
        fingerprint=row["fingerprint"],
        status=row["status"],
        valid_from=row["valid_from"],
        valid_to=row["valid_to"],
        registered_by=row["registered_by"],
        registered_at=row["registered_at"],
        revoked_at=row["revoked_at"],
        revoked_reason=row["revoked_reason"],
    )


def list_principal_keys(
    mgr: ConnectionManager,
    principal_id: str | None = None,
    *,
    status: str | None = None,
) -> list[PrincipalKeyEntry]:
    query = "SELECT * FROM principal_keys WHERE 1=1"
    params: list[Any] = []
    if principal_id is not None:
        query += " AND principal_id = %s"
        params.append(principal_id)
    if status is not None:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY registered_at DESC"
    with mgr.transaction() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_entry(r) for r in rows]


def list_principal_keys_for_conn(
    conn: psycopg.Connection,
    principal_id: str | None = None,
    *,
    status: str | None = None,
) -> list[PrincipalKeyEntry]:
    query = "SELECT * FROM principal_keys WHERE 1=1"
    params: list[Any] = []
    if principal_id is not None:
        query += " AND principal_id = %s"
        params.append(principal_id)
    if status is not None:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY registered_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [_row_to_entry(r) for r in rows]


def get_active_key(
    mgr: ConnectionManager,
    principal_id: str,
) -> PrincipalKeyEntry:
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND status = 'active' "
            "ORDER BY registered_at DESC LIMIT 1",
            [principal_id],
        ).fetchall()
    if not rows:
        raise RegistaError(
            ErrorCode.UNREGISTERED_SIGNER,
            f"No active key for principal {principal_id!r}",
        )
    return _row_to_entry(rows[0])


def rotate_principal_key(
    mgr: ConnectionManager,
    principal_id: str,
    new_public_key: bytes,
    scheme: str,
    *,
    registered_by: str = "system",
) -> PrincipalKeyEntry:
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    if not new_public_key:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "new_public_key is required",
        )

    new_key_id = _generate_key_id()
    fingerprint = _compute_fingerprint(new_public_key, scheme)

    with mgr.transaction() as conn:
        conn.execute(
            "SELECT key_id FROM principal_keys "
            "WHERE principal_id = %s FOR UPDATE",
            [principal_id],
        )

        now = datetime.now(UTC)
        conn.execute(
            "UPDATE principal_keys SET status = 'superseded', "
            "valid_to = %s WHERE principal_id = %s AND status = 'active'",
            [now, principal_id],
        )

        conn.execute(
            """
            INSERT INTO principal_keys
                (principal_id, key_id, scheme, public_key, fingerprint,
                 status, registered_by)
            VALUES (%s, %s, %s, %s, %s, 'active', %s)
            """,
            [principal_id, new_key_id, scheme, new_public_key,
             fingerprint, registered_by],
        )

        row = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, new_key_id],
        ).fetchone()

    return _row_to_entry(row)


def revoke_principal_key(
    mgr: ConnectionManager,
    principal_id: str,
    key_id: str,
    *,
    reason: str = "unspecified",
) -> PrincipalKeyEntry:
    with mgr.transaction() as conn:
        existing = conn.execute(
            "SELECT * FROM principal_keys WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchall()

        if not existing:
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEY_NOT_FOUND,
                f"Principal key not found: {principal_id}/{key_id}",
            )

        row = existing[0]
        if row["status"] == "revoked":
            return _row_to_entry(row)

        now = datetime.now(UTC)
        conn.execute(
            "UPDATE principal_keys SET status = 'revoked', "
            "revoked_at = %s, revoked_reason = %s "
            "WHERE principal_id = %s AND key_id = %s",
            [now, reason, principal_id, key_id],
        )

        row = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchone()

    return _row_to_entry(row)


def verify_principal_binding(
    mgr: ConnectionManager,
    principal_id: str,
    actor_id: str,
) -> PrincipalKeyEntry:
    if principal_id != actor_id:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"Actor-signer mismatch: event actor_id={actor_id!r} "
            f"does not match signing principal_id={principal_id!r}",
        )
    return get_active_key(mgr, principal_id)
