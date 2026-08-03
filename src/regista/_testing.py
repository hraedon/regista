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
    "sign_event",
    "verify_encrypted_integrity",
    "verify_event",
]


@contextmanager
def raw_transaction(regista: Any) -> Generator[DictConn, None, None]:
    with regista._mgr.transaction() as conn:
        yield conn


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
