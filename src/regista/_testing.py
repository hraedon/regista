from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import psycopg

from ._connection import DictConn
from ._encryption import available_encryption_schemes as available_encryption_schemes
from ._encryption import decrypt_fields as decrypt_fields
from ._encryption import encrypt_fields as encrypt_fields
from ._encryption import get_encryption_scheme as get_encryption_scheme
from ._encryption import is_encrypted_field as is_encrypted_field
from ._encryption import is_encrypted_payload as is_encrypted_payload
from ._encryption import verify_encrypted_integrity as verify_encrypted_integrity
from ._hooks import poll_and_process_hooks as poll_and_process_hooks
from ._keys import KeySet as KeySet
from ._observability import Metrics as Metrics
from ._replay import replay as replay_fn
from ._signing import sign_event as sign_event
from ._signing import verify_event as verify_event
from ._signing_scheme import available_schemes as available_schemes
from ._signing_scheme import get_scheme as get_scheme

__all__ = [
    "KeySet",
    "Metrics",
    "available_encryption_schemes",
    "available_schemes",
    "decrypt_fields",
    "drop_project_schema",
    "encrypt_fields",
    "get_encryption_scheme",
    "get_scheme",
    "is_encrypted_field",
    "is_encrypted_payload",
    "poll_and_process_hooks",
    "raw_transaction",
    "replay_fn",
    "seed_legacy_principal_key",
    "seed_legacy_principal_key_revocation",
    "seed_legacy_principal_key_rotation",
    "sign_event",
    "verify_encrypted_integrity",
    "verify_event",
]


@contextmanager
def raw_transaction(regista: Any) -> Generator[DictConn, None, None]:
    with regista._mgr.transaction() as conn:
        yield conn


def seed_legacy_principal_key(
    mgr: Any,
    principal_id: str,
    public_key: bytes,
    scheme: str = "ed25519",
    *,
    key_id: str | None = None,
    registered_by: str = "legacy",
    status: str = "active",
) -> Any:
    """Seed a pre-cutover ``principal_keys`` row for **legacy-epoch tests**.

    ``TRUST-DOMAIN.md`` §5.9 made ``principal_keys`` a projection of signed
    trust-log events, and the public mutators are gone (§5.9 rule 2). The legacy
    (v4/v5) epoch has no signed lifecycle events to project from — overlay change 3
    — so tests that exercise legacy verification still need registry rows, and this
    is the only sanctioned way to make one.

    Rows created here are ``legacy_unsourced``: ``source_event_hash`` is NULL, the
    rebuild leaves them untouched, and no v6 verification consults them (§5.9 rule
    1). This is deliberately in the **testing** module — it is not a production
    write path, and it cannot manufacture a v6-sourced row.
    """
    from ._principal_keys import _insert_legacy_unsourced_key

    with mgr.transaction() as conn:
        return _insert_legacy_unsourced_key(
            conn,
            principal_id,
            public_key,
            scheme,
            key_id=key_id,
            registered_by=registered_by,
            status=status,
        )


def seed_legacy_principal_key_rotation(
    mgr: Any,
    principal_id: str,
    new_public_key: bytes,
    scheme: str = "ed25519",
    *,
    key_id: str | None = None,
    registered_by: str = "legacy",
) -> Any:
    """Legacy-epoch equivalent of a rotation: supersede the active row, add a new one.

    Same posture as :func:`seed_legacy_principal_key` — both rows stay
    ``legacy_unsourced``. Supersession sets ``valid_to`` so the legacy row shape
    matches what the pre-0.6.0 rotation produced.
    """
    from datetime import UTC, datetime

    from ._principal_keys import _insert_legacy_unsourced_key

    now = datetime.now(UTC)
    with mgr.transaction() as conn:
        conn.execute(
            "UPDATE principal_keys SET status = 'superseded', valid_to = %s "
            "WHERE principal_id = %s AND status = 'active'",
            [now, principal_id],
        )
        return _insert_legacy_unsourced_key(
            conn,
            principal_id,
            new_public_key,
            scheme,
            key_id=key_id,
            registered_by=registered_by,
        )


def seed_legacy_principal_key_revocation(
    mgr: Any,
    principal_id: str,
    key_id: str,
    *,
    reason: str = "unspecified",
) -> Any:
    """Legacy-epoch equivalent of a revocation: flip an existing legacy row.

    Refuses to touch a v6-sourced row: those are projections of signed events and
    must only change via :func:`regista._principal_keys._apply_revocation_projection`.
    """
    from datetime import UTC, datetime

    from ._errors import ErrorCode, RegistaError
    from ._principal_keys import _row_to_entry

    now = datetime.now(UTC)
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM principal_keys WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchall()
        if not rows:
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEY_NOT_FOUND,
                f"Principal key not found: {principal_id}/{key_id}",
            )
        if rows[0].get("source_event_hash") is not None:
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
                f"{principal_id}/{key_id} is a v6-sourced projection row; revoke it "
                "through a signed principal_key_revoked event, not a test seeder.",
                {"reason": "row_is_v6_sourced"},
            )
        conn.execute(
            "UPDATE principal_keys SET status = 'revoked', revoked_at = %s, "
            "revoked_reason = %s WHERE principal_id = %s AND key_id = %s",
            [now, reason, principal_id, key_id],
        )
        row = conn.execute(
            "SELECT * FROM principal_keys WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchone()
        assert row is not None
        return _row_to_entry(dict(row))


def drop_project_schema(dsn: str, project: str) -> None:
    """Drop the Postgres schema for a project. Public API via ``regista.testing``.

    Also removes the project's row from the ``public.projects`` catalog so the
    schema drop is a full unregister, not just a ``DROP SCHEMA``. Leaving the
    catalog row behind let the test suite accumulate one stale entry per test
    project — tens of thousands in a shared instance — which ``run_doctor``
    then iterated serially (WI-243/WI-244).

    Args:
        dsn: Postgres connection string.
        project: Project (schema) name to drop.
    """
    from psycopg.sql import SQL, Identifier

    from ._connection import validate_project_name

    validate_project_name(project)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(project)))
        try:
            conn.execute(
                SQL("DELETE FROM {} WHERE schema_name = %s").format(
                    Identifier("public", "projects")
                ),
                [project],
            )
        except psycopg.errors.UndefinedTable:
            pass
