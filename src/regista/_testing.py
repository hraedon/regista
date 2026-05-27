from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

import psycopg

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
    "available_schemes",
    "drop_project_schema",
    "get_scheme",
    "poll_and_process_hooks",
    "raw_transaction",
    "replay_fn",
    "sign_event",
    "verify_event",
]


@contextmanager
def raw_transaction(regista) -> Generator[psycopg.Connection, None, None]:
    with regista._mgr.transaction() as conn:
        yield conn


def drop_project_schema(dsn: str, project: str) -> None:
    """Drop the Postgres schema for a project. Public API via ``regista.testing``.

    Args:
        dsn: Postgres connection string.
        project: Project (schema) name to drop.
    """
    from psycopg.sql import SQL, Identifier

    from ._connection import validate_project_name

    validate_project_name(project)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(project)))
