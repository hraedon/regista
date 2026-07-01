from __future__ import annotations

import psycopg
from psycopg.sql import SQL

from ._contract import check_actor_role_authorized as _check_roles
from ._contract import validate_actor_id, validate_role
from ._errors import ErrorCode, RegistaError


def register_actor_role(
    conn: psycopg.Connection,
    actor_id: str,
    role: str,
) -> None:
    validate_actor_id(actor_id)
    validate_role(role)
    conn.execute(
        SQL(
            "INSERT INTO actor_roles (actor_id, role) VALUES (%s, %s) "
            "ON CONFLICT (actor_id, role) DO NOTHING"
        ),
        [actor_id, role],
    )


def unregister_actor_role(
    conn: psycopg.Connection,
    actor_id: str,
    role: str,
) -> None:
    result = conn.execute(
        SQL(
            "DELETE FROM actor_roles WHERE actor_id = %s AND role = %s"
        ),
        [actor_id, role],
    )
    if result.rowcount == 0:
        raise RegistaError(
            ErrorCode.ACTOR_ROLE_NOT_REGISTERED,
            f"Actor {actor_id!r} does not have role {role!r}",
        )


def list_actor_roles(
    conn: psycopg.Connection,
    actor_id: str | None = None,
) -> list[dict]:
    if actor_id is not None:
        rows = conn.execute(
            SQL(
                "SELECT actor_id, role, created_at FROM actor_roles "
                "WHERE actor_id = %s ORDER BY role"
            ),
            [actor_id],
        ).fetchall()
    else:
        rows = conn.execute(
            SQL(
                "SELECT actor_id, role, created_at FROM actor_roles "
                "ORDER BY actor_id, role"
            ),
        ).fetchall()
    return [dict(r) for r in rows]


def check_actor_role_authorized(
    conn: psycopg.Connection,
    actor_id: str,
    claimed_role: str,
    *,
    strict: bool = False,
    actor_metadata: dict | None = None,
) -> None:
    rows = conn.execute(
        SQL(
            "SELECT role FROM actor_roles WHERE actor_id = %s"
        ),
        [actor_id],
    ).fetchall()
    registered = {r["role"] for r in rows}
    _check_roles(registered, actor_id, claimed_role, strict=strict, actor_metadata=actor_metadata)
