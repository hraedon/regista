"""WI-315: the v6 epoch-boundary DB trigger (migration 049).

Defense-in-depth: once a project has opened its v6 epoch (``project_identity``
populated), a direct ``events`` insert that bypasses the library -- the exact shape
a stale 0.5.5 client repointed at a 0.6.0 v6 schema produces -- must be refused at
the database level. The trigger requires every post-genesis ``events`` insert to
carry a v6 ``canonical_envelope`` (``type=regista.event``, ``version=6``).

The discriminator is deliberately "is a v6 envelope", NOT merely "canonical_envelope
IS NOT NULL": a 0.5.5 client DOES populate ``canonical_envelope`` (with a v5 envelope
that has no top-level type/version), so a NULL-only guard would let its corrupt row
through. Both the NULL path (v1-v4) and the v5 path are exercised here.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from _helpers import DSN
from psycopg.sql import SQL
from test_genesis import _envelope, _key_file

from regista import Regista
from regista.testing import drop_project_schema

_SQLSTATE = "RG315"

# A minimal, valid-except-for-the-trigger events row. entity_id (031 trigger),
# entity_kind/hash_alg/scheme_id (column defaults), global_seq (sequence default)
# and timestamp (now()) are all supplied by the table, so this is the smallest
# column set that a raw INSERT can carry and still satisfy every NOT NULL.
_RAW_INSERT = SQL(
    "INSERT INTO events (event_id, work_item_id, event_seq, actor_id, actor_kind, "
    "key_id, payload_canonical_hash, signature, canonical_envelope) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

# A v6 canonical envelope only needs its top-level discriminators to satisfy the
# trigger; the trigger is a boundary guard, not a full envelope validator (that is
# the library's job on the write path).
_V6_ENVELOPE = b'{"type":"regista.event","version":6}'
# What a 0.5.5 / legacy (v5) writer's sign_event produces: a flat envelope with no
# top-level type/version. It is NON-NULL, which is exactly why a NULL-only guard is
# insufficient.
_V5_ENVELOPE = b'{"event_id":"x","actor_id":"agent:stale","transition":null,"payload":null}'


def _raw_insert(conn, *, canonical_envelope: bytes | None) -> None:
    conn.execute(
        _RAW_INSERT,
        [
            uuid.uuid4(),
            uuid.uuid4(),
            1,
            "agent:stale-0-5-5",
            "agent",
            "pk-stale",
            b"\x00" * 32,
            b"\x00" * 64,
            canonical_envelope,
        ],
    )


def _open_epoch_project(tmp_path) -> tuple[Regista, str]:
    """A project with its v6 epoch opened (genesis written)."""
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_wi315_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(DSN, project, str(key_path))
    regista.write_genesis(_envelope(public_key), gate_passed=True)
    return regista, project


def test_trigger_rejects_null_envelope_after_genesis(tmp_path) -> None:
    """The core corruption path: a raw insert with canonical_envelope=NULL is
    refused once the epoch is open."""
    regista, project = _open_epoch_project(tmp_path)
    try:
        with regista._mgr.connect() as conn:
            with pytest.raises(psycopg.Error) as excinfo:
                with conn.transaction():
                    _raw_insert(conn, canonical_envelope=None)
            assert excinfo.value.sqlstate == _SQLSTATE
            assert "epoch boundary violation" in str(excinfo.value)
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)


def test_trigger_rejects_v5_envelope_after_genesis(tmp_path) -> None:
    """The stale-0.5.5 path: a NON-NULL but non-v6 (v5) envelope is refused. This is
    the case a NULL-only discriminator would silently admit."""
    regista, project = _open_epoch_project(tmp_path)
    try:
        with regista._mgr.connect() as conn:
            with pytest.raises(psycopg.Error) as excinfo:
                with conn.transaction():
                    _raw_insert(conn, canonical_envelope=_V5_ENVELOPE)
            assert excinfo.value.sqlstate == _SQLSTATE
            assert "non-v6 events insert" in str(excinfo.value)
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)


def test_trigger_allows_v6_envelope_after_genesis(tmp_path) -> None:
    """A well-formed v6 envelope insert still succeeds once the epoch is open."""
    regista, project = _open_epoch_project(tmp_path)
    try:
        with regista._mgr.connect() as conn:
            with conn.transaction():
                _raw_insert(conn, canonical_envelope=_V6_ENVELOPE)
            row = conn.execute(
                SQL(
                    "SELECT count(*) AS c FROM events "
                    "WHERE canonical_envelope = %s"
                ),
                [_V6_ENVELOPE],
            ).fetchone()
            assert row is not None and row["c"] == 1
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)


def test_trigger_is_what_blocks_the_bad_insert(tmp_path) -> None:
    """Before/after: with the trigger dropped the NULL insert lands (the corruption
    path is genuinely open at the DB level); with the trigger present the identical
    insert is refused. Proves the trigger -- not some other constraint -- is the
    thing that closes the hole."""

    class _RollbackError(Exception):
        pass

    regista, project = _open_epoch_project(tmp_path)
    try:
        with regista._mgr.connect() as conn:
            # BEFORE (trigger absent): the corrupt insert succeeds. Rolled back so the
            # dropped trigger and the corrupt row never persist.
            try:
                with conn.transaction():
                    conn.execute(
                        SQL(
                            "DROP TRIGGER events_enforce_v6_epoch_boundary ON events"
                        )
                    )
                    _raw_insert(conn, canonical_envelope=None)
                    landed = conn.execute(
                        SQL(
                            "SELECT count(*) AS c FROM events "
                            "WHERE canonical_envelope IS NULL"
                        )
                    ).fetchone()
                    assert landed is not None and landed["c"] == 1
                    raise _RollbackError()
            except _RollbackError:
                pass

            # AFTER (trigger restored by the rollback): the identical insert is refused.
            with pytest.raises(psycopg.Error) as excinfo:
                with conn.transaction():
                    _raw_insert(conn, canonical_envelope=None)
            assert excinfo.value.sqlstate == _SQLSTATE

            # And nothing corrupt remains.
            remaining = conn.execute(
                SQL(
                    "SELECT count(*) AS c FROM events WHERE canonical_envelope IS NULL"
                )
            ).fetchone()
            assert remaining is not None and remaining["c"] == 0
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)


def test_trigger_dormant_before_genesis(tmp_path) -> None:
    """Pre-genesis (no project_identity) the trigger must not fire: a direct legacy
    insert lands untouched, so the pre-genesis refusal form the library owns
    (GENESIS_REQUIRED) and legacy-epoch fixtures are unchanged."""
    key_path = tmp_path / "keys.json"
    _key_file(key_path)
    project = "test_wi315_pre_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(DSN, project, str(key_path))
    try:
        # No genesis written -> project_identity empty -> trigger short-circuits.
        with regista._mgr.connect() as conn:
            with conn.transaction():
                _raw_insert(conn, canonical_envelope=None)
                row = conn.execute(
                    SQL(
                        "SELECT count(*) AS c FROM events "
                        "WHERE canonical_envelope IS NULL"
                    )
                ).fetchone()
                assert row is not None and row["c"] == 1
                # Prove it really is dormant, not merely tolerant of NULL: a v5
                # envelope also lands pre-genesis.
                _raw_insert(conn, canonical_envelope=_V5_ENVELOPE)
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)


def test_genesis_write_path_not_blocked(tmp_path) -> None:
    """The genesis-writing path itself is never gated: genesis inserts its events row
    while project_identity is still empty, then populates project_identity. The row
    exists afterwards with a v6 canonical_envelope, and the epoch is open."""
    regista, project = _open_epoch_project(tmp_path)
    try:
        with regista._mgr.connect() as conn:
            identity = conn.execute(
                SQL("SELECT count(*) AS c FROM project_identity WHERE id = TRUE")
            ).fetchone()
            assert identity is not None and identity["c"] == 1
            genesis = conn.execute(
                SQL(
                    "SELECT canonical_envelope FROM events "
                    "WHERE transition = 'project_initialized'"
                )
            ).fetchone()
            assert genesis is not None
            assert genesis["canonical_envelope"] is not None
            conn.rollback()
    finally:
        regista.close()
        drop_project_schema(DSN, project)
