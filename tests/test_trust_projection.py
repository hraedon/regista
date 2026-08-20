"""``principal_keys`` as a rebuildable projection (P2.2, TRUST-DOMAIN.md §5.9).

§9 criteria covered here:

* **12** — ``regista trust rebuild-projection`` reproduces ``principal_keys``
  byte-for-byte from signed events, for a store built entirely post-cutover
  (``TestCriterion12RebuildReproducesTheProjection``).
* **13** — an ``UPDATE principal_keys SET status='active'`` on a revoked key
  changes no verification outcome for any v6 event, and the doctor projection check
  fails (``TestCriterion13HandEditChangesNoVerificationOutcome``).
* **17** — importing the old public mutator names fails
  (``TestCriterion17BypassNamesAreGone``).

Criterion 18's payload/authority half is in ``tests/test_trust_log.py``; its
"reported everywhere it surfaces, including in a bundle verdict" half needs the
bundle verdict renderer (sibling C / P3.3) and the v6 verifier, and is **not**
claimed here.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from _helpers import DSN, KEY_PATH
from _trust_fixtures import mint_solo
from _trust_log_fixtures import (
    TrustLogKey,
    make_authorized_by,
    make_enrollment_payload,
    make_possession_challenge,
    make_registrar_delegation_payload,
    make_revocation_payload,
    make_rotation_payload,
    persist_consumed_possession_challenge,
    principal_entity_uuid,
)

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._trust_log import (
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
)
from regista._trust_log_writer import (
    _row_event_hash,
    append_trust_log_event,
    chain_order,
    read_trust_log_rows,
    write_trust_genesis,
)
from regista._trust_projection import (
    check_projection_consistent,
    projection_summary,
    rebuild_projection,
    rebuild_projection_from_trust_log,
    verify_project_acceptance,
)
from regista.testing import drop_project_schema, seed_legacy_principal_key

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR_PRINCIPAL = "service:registrar-1"
# This module drives the *production* writer, whose possession-challenge admission
# compares each challenge's ``expires_at`` against ``max(datetime.now(UTC), occurred_at)``
# at append (``_trust_log_writer.py`` :961 and :1761-1767). The prior fix (a756677)
# anchored the event times to a module-import ``_NOW`` — but in a *full-suite* run pytest
# imports this module at COLLECTION (t=0) and executes its tests ~10 min later, so a
# window of ``import_time + 5 min`` was already expired at execution: a suite-position
# time bomb (``possession_challenge_expired_at_admission``). The fix, mirroring
# ``tests/_trust_log_fixtures.py::_ts()``, is to read ``now()`` per call at test
# *execution* — never at import — via ``_now()``/``_event_ts()`` below, so issue and
# admission are milliseconds apart by construction regardless of suite position. The
# ``_now()`` indirection also lets a unit test prove the window tracks call time. Event
# builders default to ``_event_ts()`` (≈ now); a rotation ordered after its enrollment
# uses ``_event_ts(timedelta(days=1))`` (≈ now + 1 day), preserving the deliberate gap.


def _now() -> datetime:
    """Real wall-clock now, indirected so tests can prove call-time anchoring."""
    return datetime.now(UTC)


def _event_ts(offset: timedelta = timedelta(0)) -> str:
    """A fixture event timestamp anchored to call-time ``now()`` plus ``offset``."""
    return (_now() + offset).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

_COLUMNS = (
    "principal_id, key_id, scheme, public_key, fingerprint, status, valid_from, "
    "valid_to, registered_by, registered_at, revoked_at, revoked_reason, "
    "trust_domain_id, source_event_hash, acceptance_event_hash, projection_version"
)


@pytest.fixture
def trust_store(tmp_path):
    """A production-writer trust log with pinned genesis and durable evidence."""
    os.environ.setdefault("REGISTA_PRODUCER_HARNESS", "pytest")
    os.environ.setdefault("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL", "test-fixture")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")

    project = f"p22_tl_{uuid.uuid4().hex[:8]}"
    genesis = mint_solo()
    genesis_path = tmp_path / "trust-genesis.json"
    genesis_path.write_text(json.dumps(genesis.document), encoding="utf-8")
    os.environ["REGISTA_TRUST_GENESIS_PATH"] = str(genesis_path)
    os.environ.pop("REGISTRA_TRUST_GENESIS_PATH", None)
    root_signer = genesis.signer_ids[0]
    root_key = TrustLogKey(
        key_id="pk_root_a",
        seed=genesis.seeds[root_signer],
        public_key=genesis.public_keys[root_signer],
        fingerprint=genesis.fingerprints[root_signer],
    )
    registrar_key = TrustLogKey.mint("pk_registrar")
    key_path = tmp_path / "trust_keys.json"
    key_path.write_text(
        json.dumps(
            {
                "keys": [
                    _key_entry(ROOT_PRINCIPAL, root_key),
                    _key_entry(REGISTRAR_PRINCIPAL, registrar_key),
                ]
            }
        ),
        encoding="utf-8",
    )
    handle = Regista.create_project(DSN, project, hmac_key_path=str(key_path))
    write_trust_genesis(
        handle._mgr,
        keys=handle._keys,
        genesis_document=genesis.document,
        root_principal_id=ROOT_PRINCIPAL,
    )
    delegation_payload = make_registrar_delegation_payload(
        trust_domain_id=genesis.trust_domain_id,
        registrar_principal_id=REGISTRAR_PRINCIPAL,
        key=registrar_key,
        max_operations=100,
        root_keys=[root_key],
        # Anchor the delegation window to call-time now, not fixed 2026/2027 dates: the
        # registrar-liveness check (_trust_log_writer.py:1977) compares real now() against
        # [not_before, not_after] at append AND replay requires each event's occurred_at
        # inside it. A fixed not_after fired after 2027-01-01. now-1d..now+365d always
        # brackets now and every event time this module emits (including the +1d rotation).
        not_before=_event_ts(timedelta(days=-1)),
        not_after=_event_ts(timedelta(days=365)),
    )
    append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=genesis.document,
        transition="registrar_delegated",
        payload=delegation_payload,
        entity_kind="trust_domain",
        entity_id=uuid.UUID(genesis.trust_domain_id),
        principal_id=ROOT_PRINCIPAL,
        authority="root",
    )
    with handle._mgr.transaction() as conn:
        rows = chain_order(read_trust_log_rows(conn))
    delegation_hash = next(
        _row_event_hash(row)
        for row in rows
        if row["transition"] == "registrar_delegated"
    )
    store = SimpleNamespace(
        dsn=DSN,
        project=project,
        handle=handle,
        genesis_document=genesis.document,
        trust_domain_id=genesis.trust_domain_id,
        project_instance_id=str(genesis.document["trust_log"]["project_instance_id"]),
        registrar_key=registrar_key,
        delegation_event_hash=delegation_hash,
        events=[],
    )
    yield store
    handle.close()
    drop_project_schema(DSN, project)


def _key_entry(principal_id: str, key: TrustLogKey) -> dict[str, str]:
    return {
        "key_id": key.key_id,
        "scheme": "ed25519",
        "alg": "Ed25519",
        "secret": base64.b64encode(key.seed).decode("ascii"),
        "encoding": "base64",
        "public_key": base64.b64encode(key.public_key).decode("ascii"),
        "principal_id": principal_id,
        "role": "actor",
        "status": "active",
    }


@pytest.fixture
def principal_keys_project(regista_instance):
    """A migrated project for applier-level unit checks."""
    return regista_instance


def _mgr(store):
    from regista._connection import ConnectionManager

    mgr = ConnectionManager(store.dsn, store.project)
    mgr.open()
    return mgr


def _writer_mgr(store):
    return store.handle._mgr


def _event_time(occurred_at: str | None) -> datetime:
    return datetime.fromisoformat((occurred_at or _event_ts()).replace("Z", "+00:00"))


def _event_record(store, event_id: str, payload: dict) -> SimpleNamespace:
    with _writer_mgr(store).transaction() as conn:
        row = conn.execute(
            "SELECT event_id, transition, entity_kind, entity_id, event_seq, payload, "
            "canonical_envelope, signature, timestamp FROM events WHERE event_id = %s",
            [uuid.UUID(event_id)],
        ).fetchone()
    assert row is not None
    record = SimpleNamespace(
        event_id=str(row["event_id"]),
        transition=str(row["transition"]),
        entity_kind=str(row["entity_kind"]),
        entity_id=str(row["entity_id"]),
        entity_seq=int(row["event_seq"]),
        payload=payload,
        event_hash=_row_event_hash(row),
        canonical_envelope=bytes(row["canonical_envelope"]),
        signature=bytes(row["signature"]),
        occurred_at=row["timestamp"].isoformat(),
    )
    store.events.append(record)
    return record


def _challenge(store, principal_id: str, key: TrustLogKey, occurred_at: str | None):
    # Anchor the window to call-time ``now()``, not to any module constant: admission
    # admits only while ``expires_at`` is still ahead of ``max(now, occurred_at)`` at
    # append (_trust_log_writer.py:961, :1761-1767). ``max(_now(), event_at)`` brackets
    # BOTH real now-at-execution AND a deliberately future-dated event's occurred_at, so
    # ``expires_at`` clears admission by construction — issue and admission are
    # milliseconds apart regardless of how far collection preceded execution.
    event_at = _event_time(occurred_at)
    admission_anchor = max(_now(), event_at)
    issued_at = (admission_anchor - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expires_at = (admission_anchor + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return make_possession_challenge(
        trust_domain_id=store.trust_domain_id,
        principal_id=principal_id,
        fingerprint=key.fingerprint,
        project=store.project,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _authorized(store):
    return make_authorized_by(
        authority="registrar",
        principal_id=REGISTRAR_PRINCIPAL,
        key_id=store.registrar_key.key_id,
        delegation_event_hash=store.delegation_event_hash,
    )


def _snapshot(store) -> list[tuple]:
    """Every column of every row, ordered — the byte-for-byte comparison surface.

    Takes anything naming a schema: a ``TrustLogStore`` (``.dsn`` + ``.project``) or a
    ``Regista`` handle, which carries ``.project`` but no ``.dsn`` — the ceremony
    round-trip reads the *ordinary* project's projection, so both shapes are needed.
    """
    dsn = getattr(store, "dsn", None) or DSN
    return _snapshot_of(dsn, store.project)


def _snapshot_of(dsn: str, project: str) -> list[tuple]:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'SET search_path TO "{project}"')
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM principal_keys "
            "ORDER BY principal_id, key_id"
        ).fetchall()
    return [tuple(bytes(v) if isinstance(v, memoryview) else v for v in r) for r in rows]


def _enrol(store, principal_id, key, *, writer, occurred_at=None, **kwargs):
    occurred_at = occurred_at or _event_ts()
    challenge = _challenge(store, principal_id, key, occurred_at)
    payload = make_enrollment_payload(
        trust_domain_id=store.trust_domain_id,
        principal_id=principal_id,
        key=key,
        authorized_by=_authorized(store),
        challenge=challenge,
        **kwargs,
    )
    with _writer_mgr(store).transaction() as conn:
        persist_consumed_possession_challenge(
            conn, challenge, payload["possession_proof"]["signature"]
        )
    event_id = append_trust_log_event(
        _writer_mgr(store),
        keys=store.handle._keys,
        genesis_document=store.genesis_document,
        transition=PRINCIPAL_KEY_ENROLLED,
        payload=payload,
        entity_kind="principal",
        entity_id=principal_entity_uuid(principal_id),
        principal_id=REGISTRAR_PRINCIPAL,
        authority="registrar",
        occurred_at=_event_time(occurred_at),
    )
    return _event_record(store, event_id, payload)


def _rotate(
    store,
    principal_id: str,
    old_key: TrustLogKey,
    new_key: TrustLogKey,
    *,
    occurred_at: str | None = None,
    **kwargs,
):
    occurred_at = occurred_at or _event_ts()
    challenge = _challenge(store, principal_id, new_key, occurred_at)
    payload = make_rotation_payload(
        trust_domain_id=store.trust_domain_id,
        principal_id=principal_id,
        key=new_key,
        supersedes_key_id=old_key.key_id,
        superseded_key=old_key,
        authorized_by=_authorized(store),
        challenge=challenge,
        **kwargs,
    )
    with _writer_mgr(store).transaction() as conn:
        persist_consumed_possession_challenge(
            conn, challenge, payload["possession_proof"]["signature"]
        )
    event_id = append_trust_log_event(
        _writer_mgr(store),
        keys=store.handle._keys,
        genesis_document=store.genesis_document,
        transition=PRINCIPAL_KEY_ROTATED,
        payload=payload,
        entity_kind="principal",
        entity_id=principal_entity_uuid(principal_id),
        principal_id=REGISTRAR_PRINCIPAL,
        authority="registrar",
        occurred_at=_event_time(occurred_at),
    )
    return _event_record(store, event_id, payload)


def _revoke(store, principal_id: str, key_id: str, *, reason: str = "compromised"):
    if reason not in {
        "compromised",
        "superseded",
        "decommissioned",
        "policy",
        "unspecified",
    }:
        reason = "unspecified"
    payload = make_revocation_payload(
        trust_domain_id=store.trust_domain_id,
        principal_id=principal_id,
        key_id=key_id,
        reason=reason,
        authorized_by=_authorized(store),
    )
    event_id = append_trust_log_event(
        _writer_mgr(store),
        keys=store.handle._keys,
        genesis_document=store.genesis_document,
        transition=PRINCIPAL_KEY_REVOKED,
        payload=payload,
        entity_kind="principal",
        entity_id=principal_entity_uuid(principal_id),
        principal_id=REGISTRAR_PRINCIPAL,
        authority="registrar",
    )
    return _event_record(store, event_id, payload)


class TestCriterion12RebuildReproducesTheProjection:
    """§9.12: rebuild reproduces ``principal_keys`` from signed events alone."""

    def test_rebuild_reproduces_a_post_cutover_store_byte_for_byte(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        alice = TrustLogKey.mint("pk_alice_1")
        bob = TrustLogKey.mint("pk_bob_1")
        alice2 = TrustLogKey.mint("pk_alice_2")

        _enrol(trust_store, "agent:alice", alice, writer=writer)
        _enrol(trust_store, "agent:bob", bob, writer=writer)
        # One call-time value for both fields so the rotation is ordered a day after its
        # enrollment (relative to now, not a module-import constant): occurred_at feeds
        # the event's registered_at, not_before feeds valid_from, and the byte-for-byte
        # rebuild derives each from these same events.
        later = _event_ts(timedelta(days=1))
        _rotate(
            trust_store,
            "agent:alice",
            alice,
            alice2,
            occurred_at=later,
            not_before=later,
        )
        _revoke(
            trust_store,
            "agent:bob",
            bob.key_id,
        )

        mgr = _mgr(trust_store)
        try:
            first = rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert first.applied is True
            assert first.events_replayed == 4
            assert first.events_by_transition == {
                PRINCIPAL_KEY_ENROLLED: 2,
                PRINCIPAL_KEY_ROTATED: 1,
                PRINCIPAL_KEY_REVOKED: 1,
            }
            after_first = _snapshot(trust_store)
            assert len(after_first) == 3  # alice x2 (one superseded), bob x1

            # THE criterion: rebuilding again reproduces the identical table.
            second = rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert second.consistent is True, second.differences
            assert _snapshot(trust_store) == after_first

            # ...and a dry run agrees, having written nothing.
            check = check_projection_consistent(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert check.consistent is True
            assert check.applied is False
            assert _snapshot(trust_store) == after_first
        finally:
            mgr.close()

    def test_the_rebuilt_rows_carry_the_event_hashes_they_came_from(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        key = TrustLogKey.mint("pk_carol_1")
        event = _enrol(trust_store, "agent:carol", key, writer=writer)

        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            from regista._principal_keys import get_active_key

            entry = get_active_key(mgr, "agent:carol")
            assert entry.source_event_hash == event.event_hash
            assert entry.trust_domain_id == trust_store.trust_domain_id
            assert entry.key_id == key.key_id
            assert entry.public_key == key.public_key
            assert entry.provenance == "v6_sourced"
        finally:
            mgr.close()

    def test_rotation_supersedes_the_named_key_and_closes_its_window(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        old = TrustLogKey.mint("pk_dave_1")
        new = TrustLogKey.mint("pk_dave_2")
        _enrol(trust_store, "agent:dave", old, writer=writer)
        _rotate(
            trust_store,
            "agent:dave",
            old,
            new,
            # A rotation dated a few days out, anchored to call-time now (was fixed
            # 2026-08-25, which would fire once real time passed it): stays inside the
            # registrar delegation window and orders after the enrollment.
            not_before=_event_ts(timedelta(days=5)),
        )
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            from regista._principal_keys import list_principal_keys

            rows = {k.key_id: k for k in list_principal_keys(mgr, "agent:dave")}
            assert rows[old.key_id].status == "superseded"
            # §5.6: valid_to derived from the event, not from a code path that
            # remembered the UPDATE.
            assert rows[old.key_id].valid_to is not None
            assert rows[new.key_id].status == "active"
        finally:
            mgr.close()

    def test_a_rebuild_of_an_empty_store_is_a_clean_no_op(self, trust_store):
        mgr = _mgr(trust_store)
        try:
            report = rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert report.events_replayed == 0
            assert report.rows_rebuilt == 0
            assert report.consistent is True
        finally:
            mgr.close()


class TestLegacyUnsourcedRowsAreLeftAlone:
    """§5.9 AMENDED: "a rebuild that empties them is a defect, and one that
    invents them is worse"."""

    def test_a_rebuild_neither_deletes_nor_invents_legacy_rows(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        key = TrustLogKey.mint("pk_v6_1")
        _enrol(trust_store, "agent:v6", key, writer=writer)

        mgr = _mgr(trust_store)
        try:
            legacy = seed_legacy_principal_key(
                mgr, "legacy-actor", b"\x09" * 32, "ed25519", key_id="legacy-key",
            )
            assert legacy.source_event_hash is None

            before = projection_summary(mgr)
            assert before == {"legacy_unsourced": 1, "v6_sourced": 0}

            report = rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert report.legacy_unsourced_preserved == 1

            after = projection_summary(mgr)
            assert after == {"legacy_unsourced": 1, "v6_sourced": 1}

            from regista._principal_keys import list_principal_keys

            rows = {k.key_id: k for k in list_principal_keys(mgr, "legacy-actor")}
            # Byte-identical: untouched, not rewritten with a fabricated source.
            assert rows["legacy-key"].public_key == b"\x09" * 32
            assert rows["legacy-key"].source_event_hash is None
            assert rows["legacy-key"].provenance == "legacy_unsourced"
        finally:
            mgr.close()

    def test_legacy_rows_do_not_register_as_divergence(self, trust_store):
        """A legacy row is not "missing from the rebuild" — it is out of scope."""
        mgr = _mgr(trust_store)
        try:
            seed_legacy_principal_key(mgr, "legacy-only", b"\x0a" * 32, "ed25519")
            report = check_projection_consistent(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert report.consistent is True
            assert report.differences == ()
            assert report.legacy_unsourced_preserved == 1
        finally:
            mgr.close()


class TestCriterion13HandEditChangesNoVerificationOutcome:
    """§9.13 — the hand-edited-row case, in two provable halves.

    1. The doctor's ``trust:projection_consistent`` check **fails**. Provable now.
    2. The edit changes **no verification outcome for any v6 event**. The direct
       form of that assertion needs the v6 verifier (P1.7-adjacent, §5.10's
       traversal), which does not exist yet. What is provable now is the contract it
       rests on: the projection is never consulted for a v6 event, because key
       material is carried by the signed enrolment event itself (§5.5) and resolved
       through ``signing.key_binding_event_hash`` (§5.10), never through this table
       (§5.11's last row). Both halves are asserted below; the second is asserted as
       the *is-never-consulted* contract, and is completed by P1.7.
    """

    def _revoked_store(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        key = TrustLogKey.mint("pk_evan_1")
        enrol = _enrol(trust_store, "agent:evan", key, writer=writer)
        revoke = _revoke(trust_store, "agent:evan", key.key_id)
        return key, enrol, revoke

    def _reactivate(self, store, principal_id):
        with psycopg.connect(store.dsn, autocommit=True) as conn:
            conn.execute(f'SET search_path TO "{store.project}"')
            conn.execute(
                "UPDATE principal_keys SET status = 'active', revoked_at = NULL, "
                "revoked_reason = NULL WHERE principal_id = %s",
                [principal_id],
            )

    def test_the_doctor_projection_check_fails_after_the_hand_edit(self, trust_store):
        from regista._doctor import _check_projection_consistent

        self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            ok = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
            assert ok.status == "ok", ok.detail
        finally:
            mgr.close()

        # The exact edit criterion 13 names.
        self._reactivate(trust_store, "agent:evan")

        check = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
        # A FAILURE, not a warning, in production posture (§5.9 rule 3).
        assert check.status == "fail", check.detail
        assert "diverge" in check.detail
        assert "status" in check.detail

    def test_the_divergence_names_the_row_and_the_changed_fields(self, trust_store):
        self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            self._reactivate(trust_store, "agent:evan")
            report = check_projection_consistent(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert report.consistent is False
            assert len(report.differences) == 1
            diff = report.differences[0]
            assert diff.principal_id == "agent:evan"
            assert diff.kind == "field_mismatch"
            assert "status" in diff.fields
            assert "revoked_at" in diff.fields
        finally:
            mgr.close()

    def test_the_rebuild_restores_the_revocation(self, trust_store):
        """Hand-fixing is pointless: the events win, every time."""
        self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            self._reactivate(trust_store, "agent:evan")
            from regista._principal_keys import list_principal_keys

            assert [k.status for k in list_principal_keys(mgr, "agent:evan")] == [
                "active"
            ]
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            rows = list_principal_keys(mgr, "agent:evan")
            assert [k.status for k in rows] == ["revoked"]
            assert rows[0].revoked_reason == "compromised"
        finally:
            mgr.close()

    def test_the_key_material_a_verifier_needs_comes_from_the_event_not_the_row(
        self, trust_store,
    ):
        """The is-never-consulted contract, asserted structurally (§5.5, §5.11).

        The signed enrolment event carries the public key bytes, so a verifier can
        obtain the key without reading ``principal_keys`` at all. That is why a
        hand-edit to this table cannot move a v6 verification outcome — there is no
        code path from the row to the decision.
        """
        key, enrol, _revoke = self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            self._reactivate(trust_store, "agent:evan")

            # Re-read the key out of the stored signed event, ignoring the table.
            from regista._trust_log import parse_principal_key_enrolled

            with psycopg.connect(trust_store.dsn, autocommit=True) as conn:
                conn.execute(f'SET search_path TO "{trust_store.project}"')
                row = conn.execute(
                    "SELECT payload FROM events WHERE event_id = %s",
                    [uuid.UUID(enrol.event_id)],
                ).fetchone()
            parsed = parse_principal_key_enrolled(row[0])
            assert parsed.key.public_key == key.public_key
            assert parsed.key.fingerprint == key.fingerprint

            # The revocation is likewise a fact about the event log, and the log
            # still says revoked regardless of what the table was edited to say.
            revocations = [
                e for e in trust_store.events if e.transition == PRINCIPAL_KEY_REVOKED
            ]
            assert len(revocations) == 1
            assert revocations[0].payload["key_id"] == key.key_id
        finally:
            mgr.close()

    @pytest.mark.parametrize(
        "sql",
        [
            "UPDATE principal_keys SET fingerprint = 'ed25519:sha256:{}'".format(
                "0" * 64
            ),
            "UPDATE principal_keys SET public_key = '\\x00'::bytea",
            "DELETE FROM principal_keys WHERE source_event_hash IS NOT NULL",
        ],
    )
    def test_any_hand_edit_to_a_v6_row_is_caught(self, trust_store, sql):
        self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
        finally:
            mgr.close()
        with psycopg.connect(trust_store.dsn, autocommit=True) as conn:
            conn.execute(f'SET search_path TO "{trust_store.project}"')
            conn.execute(sql)

        from regista._doctor import _check_projection_consistent

        check = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
        assert check.status == "fail", check.detail


class TestCriterion17BypassNamesAreGone:
    """§9.17: importing the old public mutators fails.

    "Documentation is not a control" (D-6). The three bypass paths were closed by
    *removing the names*, so the failure is at import, not at review.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "register_principal_key",
            "rotate_principal_key",
            "revoke_principal_key",
            "register_principal_key_conn",
            "rotate_principal_key_conn",
            "revoke_principal_key_conn",
        ],
    )
    def test_the_old_mutator_name_cannot_be_imported(self, name):
        module = importlib.import_module("regista._principal_keys")
        with pytest.raises(AttributeError):
            getattr(module, name)

    @pytest.mark.parametrize(
        "name",
        [
            "register_principal_key",
            "rotate_principal_key",
            "revoke_principal_key",
            "register_principal_key_conn",
            "rotate_principal_key_conn",
            "revoke_principal_key_conn",
        ],
    )
    def test_a_from_import_of_the_old_name_raises_importerror(self, name):
        with pytest.raises(ImportError):
            exec(f"from regista._principal_keys import {name}")

    def test_the_replacement_appliers_exist_and_are_private(self):
        module = importlib.import_module("regista._principal_keys")
        for name in (
            "_apply_enrollment_projection",
            "_apply_rotation_projection",
            "_apply_revocation_projection",
        ):
            applier = getattr(module, name)
            assert callable(applier)
            assert name.startswith("_"), "the appliers must not be package surface"

    def test_every_applier_requires_a_source_event_hash(self):
        """The signature is the control: source_event_hash is keyword-only and
        has no default, so a caller cannot omit it by accident."""
        import inspect

        module = importlib.import_module("regista._principal_keys")
        for name in (
            "_apply_enrollment_projection",
            "_apply_rotation_projection",
            "_apply_revocation_projection",
        ):
            sig = inspect.signature(getattr(module, name))
            param = sig.parameters["source_event_hash"]
            assert param.kind is inspect.Parameter.KEYWORD_ONLY
            assert param.default is inspect.Parameter.empty

    def test_the_ops_facade_refuses_instead_of_writing(self, trust_store):
        from regista import Regista

        sub = Regista(DSN, trust_store.project, KEY_PATH)
        try:
            for call in (
                lambda: sub.principals.register("agent:x", b"\x01" * 32),
                lambda: sub.principals.rotate("agent:x", b"\x02" * 32),
                lambda: sub.principals.revoke("agent:x", "pk_x"),
            ):
                with pytest.raises(RegistaError) as exc_info:
                    call()
                assert exc_info.value.code is (
                    ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
                )
        finally:
            sub.close()


class TestRebuildRefusesAnUnmigratedStore:
    def test_a_store_without_the_projection_columns_is_named_not_guessed(
        self, trust_store,
    ):
        with psycopg.connect(trust_store.dsn, autocommit=True) as conn:
            conn.execute(f'SET search_path TO "{trust_store.project}"')
            conn.execute("ALTER TABLE principal_keys DROP COLUMN source_event_hash")
        mgr = _mgr(trust_store)
        try:
            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection(
                    mgr, project=trust_store.project,
                    genesis_document=trust_store.genesis_document,
                )
            assert exc_info.value.code is ErrorCode.MIGRATION_REQUIRED
            assert exc_info.value.detail["reason"] == "projection_columns_absent"
        finally:
            mgr.close()

    def test_the_doctor_skips_rather_than_failing_an_unmigrated_store(
        self, trust_store,
    ):
        from regista._doctor import _check_projection_consistent

        with psycopg.connect(trust_store.dsn, autocommit=True) as conn:
            conn.execute(f'SET search_path TO "{trust_store.project}"')
            conn.execute("ALTER TABLE principal_keys DROP COLUMN source_event_hash")
        check = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
        # "Cannot check" is not "diverged" — an un-upgraded store must not look
        # corrupt.
        assert check.status == "skip"


class TestRebuildAndTheSanctionedWriterIntersect:
    """The rebuild must be able to see and reproduce the sanctioned writer's events.

    Regression for the P2.2 review's blocking finding B1. Every refusal message P2.2
    added points callers at ``PrincipalLifecycle`` — the one correct event-driven
    implementation (§5.1). Before the fix its ``commit()`` emitted Plan-026
    transitions (``principal_enrolled``/``_rotated``/``_revoked``) with a payload
    carrying no public key, while the rebuild replays only the §5.3 catalogue names
    and parses strictly against §5.5. A row written by the ceremony was therefore
    stamped as v6-sourced yet invisible to the rebuild, which meant: diff reports
    ``only_live`` -> doctor reports ``fail`` -> the remediation text says "run
    rebuild-projection" -> the applied rebuild's DELETE removes the row the ceremony
    just wrote.

    **Scope note, stated plainly.** The end-to-end commit->rebuild path cannot be
    exercised today: ``commit()`` appends through the legacy writer, which P1.2
    refuses on both sides of genesis (``GENESIS_REQUIRED`` before, ``V6_EPOCH_OPEN``
    after). That is why all 27 ``commit()`` tests in
    ``test_principal_lifecycle_durable.py`` are epoch-blocked on P1.7, and it is why
    the destruction was latent rather than live. What is provable now — and what
    these tests pin — is the *contract* between the two halves: the ceremony emits
    exactly the transitions the rebuild replays, and a payload the rebuild's own
    parsers accept. When P1.7 supplies the append path, the loop closes on agreeing
    shapes instead of diverging ones.
    """

    def _prepared_operation(self, sub, op_type="enrollment"):
        """Drive the ceremony as far as it goes without appending."""
        import nacl.signing

        from regista.principal_lifecycle import (
            CustodyMode,
            EnrollmentRequest,
            PossessionProof,
            PrincipalKind,
            PrincipalLifecycle,
            ProofFormat,
        )

        private_key = nacl.signing.SigningKey.generate()
        public_key = bytes(private_key.verify_key)
        lifecycle = PrincipalLifecycle(sub.project, mgr=sub._mgr, keys=sub._keys)
        request = EnrollmentRequest(
            principal_id="agent:ceremony",
            principal_kind=PrincipalKind.AGENT,
            actor_id="human:requester",
            public_key=public_key,
            scheme="ed25519",
            custody_mode=CustodyMode.FILE,
            reason="intersection regression",
            requested_authority="root",
            policy_version="v1",
        )
        operation = lifecycle.prepare_enrollment(request, idempotency_key="idem-x")
        challenge = lifecycle.issue_possession_challenge(operation.operation_id)
        proof = PossessionProof(
            format=ProofFormat.SIGNATURE_V1,
            challenge_id=challenge.challenge_id,
            operation_id=challenge.operation_id,
            operation_digest=operation.digest.value,
            signature=private_key.sign(challenge.signing_bytes()).signature,
        )
        operation = lifecycle.submit_possession(operation.operation_id, proof)
        return lifecycle, operation, public_key

    def test_the_ceremony_emits_the_transitions_the_rebuild_replays(self):
        """The exact mismatch that made the ceremony's events invisible."""
        from regista._trust_log import PROJECTION_DRIVING_TRANSITIONS
        from regista.principal_lifecycle import (
            LifecycleOperationType,
            PrincipalLifecycle,
        )

        lifecycle = PrincipalLifecycle("any-project")
        emitted = {
            lifecycle._transition_for(op_type)
            for op_type in LifecycleOperationType
        }
        assert emitted == set(PROJECTION_DRIVING_TRANSITIONS), (
            "the sanctioned ceremony must emit exactly the transitions the rebuild "
            f"replays; emits {sorted(emitted)}, rebuild replays "
            f"{sorted(PROJECTION_DRIVING_TRANSITIONS)}"
        )

    def test_the_ceremony_payload_parses_under_the_rebuild_s_own_parsers(
        self, trust_store, tmp_path,
    ):
        """A payload the rebuild would reject is an event that cannot be replayed.

        Built against a project that has a trust domain, because §5.5 requires one;
        a pre-genesis project has none, and there ``commit()`` refuses at the append
        with GENESIS_REQUIRED before the shape matters.
        """
        from regista import Regista
        from regista._trust_log import parse_principal_key_enrolled

        sub = Regista(DSN, trust_store.project, KEY_PATH)
        try:
            with sub._mgr.transaction() as conn:
                conn.execute(
                    "INSERT INTO project_identity (id, project_instance_id, "
                    "trust_domain_id, genesis_event_id, genesis_event_hash, "
                    "principal_id, key_id, scheme_id, key_fingerprint) "
                    "VALUES (TRUE, %s, %s, %s, %s, %s, %s, %s, %s)",
                    [
                        trust_store.project_instance_id,
                        trust_store.trust_domain_id,
                        str(uuid.uuid4()),
                        b"\x00" * 32,
                        "agent:genesis",
                        "pk-genesis",
                        "ed25519",
                        "ed25519:sha256:" + "0" * 64,
                    ],
                )
            lifecycle, operation, public_key = self._prepared_operation(sub)
            payload = lifecycle._trust_log_payload(operation, key_id="pk_ceremony_1")

            # The rebuild's own parser is the acceptance test.
            parsed = parse_principal_key_enrolled(payload)
            assert parsed.key.public_key == public_key, (
                "the event must carry the key bytes, or the projection is not "
                "rebuildable from it (Defect A / WI-273)"
            )
            assert parsed.key.key_id == "pk_ceremony_1", (
                "the event must name the key id the applier will write, or the row "
                "cannot be reproduced from the event"
            )
            assert parsed.trust_domain_id == trust_store.trust_domain_id
            assert parsed.possession_proof.domain == "regista.principal-possession.v2"
        finally:
            sub.close()

    def test_a_row_written_as_the_rebuild_derives_it_is_reproduced_not_deleted(
        self, trust_store,
    ):
        """Applier-level: a §5.5-sourced row survives an applied rebuild.

        Honest scope (P2.2 review B1-prime): this hand-crafts the applier call with the
        values the rebuild derives, so it proves "a row written the way the rebuild
        derives it reproduces" — NOT "a row written by PrincipalLifecycle
        reproduces". The latter is
        ``test_the_ceremony_path_round_trips_byte_for_byte`` below, which drives
        commit() itself and is the acceptance evidence.
        """
        from regista._principal_keys import (
            _apply_enrollment_projection,
            list_principal_keys,
        )

        writer = TrustLogKey.mint("pk-trust-log")
        key = TrustLogKey.mint("pk_ceremony_1")
        event = _enrol(trust_store, "agent:ceremony", key, writer=writer)

        mgr = _mgr(trust_store)
        try:
            # Exactly what PrincipalLifecycle._commit_key does after appending.
            with mgr.transaction() as conn:
                _apply_enrollment_projection(
                    conn,
                    "agent:ceremony",
                    key.public_key,
                    "ed25519",
                    source_event_hash=event.event_hash,
                    # Match what the rebuild derives (_trust_projection.py:838,840):
                    # valid_from is the payload's not_before, registered_at is the
                    # event's occurred_at. Taking both from the event keeps the row
                    # consistent with the now-anchored fixture clock rather than a
                    # fixed date that only happened to equal the old midnight base.
                    valid_from=datetime.fromisoformat(
                        event.payload["not_before"].replace("Z", "+00:00")
                    ),
                    registered_at=datetime.fromisoformat(event.occurred_at),
                    key_id=key.key_id,
                    # registered_by MUST be the event's authorized_by.principal_id:
                    # that is what the rebuild derives it from, and PrincipalLifecycle
                    # sets both from operation.actor_id for exactly this reason. A
                    # mismatch here is a permanent field_mismatch divergence.
                    registered_by=event.payload["authorized_by"]["principal_id"],
                    trust_domain_id=trust_store.trust_domain_id,
                )
            assert len(list_principal_keys(mgr, "agent:ceremony")) == 1

            report = check_projection_consistent(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            assert report.consistent is True, report.differences

            rebuild_projection(
                mgr, project=trust_store.project, genesis_document=trust_store.genesis_document
            )
            after = list_principal_keys(mgr, "agent:ceremony")
            assert len(after) == 1, (
                "an applied rebuild deleted a row whose source event is in the store"
            )
            assert after[0].key_id == key.key_id
            assert after[0].public_key == key.public_key
        finally:
            mgr.close()


class TestEventHashConstructionMatchesTheWritePath:
    """Regression for blocking finding B2.

    ``_trust_projection._event_hash_text`` (rebuild) and
    ``principal_lifecycle._lifecycle_event_hash`` (write path) must compute the same
    hash for the same event. The rebuild used the v6 construction unconditionally
    while the write path branched on ``scheme_id``, so an HMAC-schemed lifecycle
    event got a v6-labelled hash from the rebuild and a legacy one from the writer —
    a permanent, wrongly-labelled divergence in the "invents rows" direction.
    """

    def _row(self, scheme_id):
        return {
            "canonical_envelope": b"envelope-bytes",
            "signature": b"signature-bytes",
            "scheme_id": scheme_id,
        }

    def test_ed25519_uses_the_v6_construction(self):
        from regista._signing import compute_v6_event_hash
        from regista._trust_projection import _event_hash_text

        expected = "sha256:" + compute_v6_event_hash(
            b"envelope-bytes", b"signature-bytes"
        ).hex()
        assert _event_hash_text(self._row("ed25519")) == expected

    @pytest.mark.parametrize("scheme_id", ["hmac-sha256", None])
    def test_a_non_ed25519_event_is_hashed_as_legacy_not_re_labelled_v6(
        self, scheme_id,
    ):
        import hashlib

        from regista._signing import compute_v6_event_hash
        from regista._trust_projection import _event_hash_text

        legacy = "sha256:" + hashlib.sha256(
            b"envelope-bytes" + b"signature-bytes"
        ).hexdigest()
        v6 = "sha256:" + compute_v6_event_hash(
            b"envelope-bytes", b"signature-bytes"
        ).hex()
        assert legacy != v6
        assert _event_hash_text(self._row(scheme_id)) == legacy

    def test_the_rebuild_and_the_write_path_agree_for_both_schemes(self):
        """The property that actually matters: the two constructions never diverge."""
        from types import SimpleNamespace

        from regista._trust_projection import _event_hash_text
        from regista.principal_lifecycle import _lifecycle_event_hash

        for scheme_id in ("ed25519", "hmac-sha256"):
            event = SimpleNamespace(
                canonical_envelope=b"envelope-bytes",
                signature=b"signature-bytes",
                scheme_id=scheme_id,
            )
            assert _lifecycle_event_hash(event) == _event_hash_text(
                self._row(scheme_id)
            ), f"write path and rebuild disagree for scheme_id={scheme_id!r}"


class TestSourceEventHashShapeIsValidated:
    """B2's second half: the applier must reject a placeholder provenance hash."""

    @pytest.mark.parametrize(
        "bad",
        ["not-a-hash", "sha256:tooshort", "sha1:" + "a" * 64, "SHA256:" + "a" * 64,
         "sha256:" + "A" * 64],
    )
    def test_a_malformed_source_event_hash_is_refused(self, principal_keys_project, bad):
        from regista._principal_keys import _apply_enrollment_projection

        with pytest.raises(RegistaError) as exc_info:
            with principal_keys_project._mgr.transaction() as conn:
                _apply_enrollment_projection(
                    conn,
                    "agent:shape",
                    b"\x01" * 32,
                    "ed25519",
                    source_event_hash=bad,
                    valid_from=datetime(2026, 8, 20, tzinfo=UTC),
                    registered_at=datetime(2026, 8, 20, tzinfo=UTC),
                )
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["reason"] == "source_event_hash_malformed"


class TestCeremonyPathRoundTrip:
    """The acceptance evidence for B1/B1-prime: join and rebuild a ceremony.

    Regression for the P2.2 review's B1-prime finding. The round-trip test in the class
    above hand-crafts the applier call, so it could not catch the ceremony and rebuild
    reading per-row values from different sources:

    * ``trust_domain_id`` was never passed (row NULL vs the payload's real UUID),
    * ``valid_from`` came from a second, later clock read than the payload's
      ``not_before``,
    * a revocation carried a reason mapped into the closed §5.7 set.

    Each was a permanent ``field_mismatch``. This test drives the ceremony's actual
    code path and asserts every compared column reproduces byte-for-byte.

    **Two chains are explicit.** The trust-log writer records the lifecycle fact in
    its own schema; the ordinary project records ``principal_key_accepted``. The
    coordinator verifies both chains and joins them by exact event hashes before
    materializing the projection. This prevents a project-local acceptance or a raw
    hash from becoming trust-domain evidence.
    """

    def _project_with_identity(
        self, trust_store, tmp_path, *, accepted_principals=None
    ):
        """A SECOND, ORDINARY project with a real v6 epoch — not the trust log.

        This used to build a ``Regista`` on ``trust_store.project`` and INSERT a fake
        ``project_identity`` row there. That was the P1.7 Finding-4 defect: the trust
        log is a **separate project chain** (``TRUST-DOMAIN.md`` §5.2 — "one
        estate-wide project, with its own ``project_instance_id``"), so a fixture
        that puts a project identity on the trust log's schema models a state
        production cannot produce, and it is what made the genesis admission rule
        (``events`` must be empty) look self-contradictory. It is not.

        The two chains agree on ``trust_domain_id`` and on nothing else — that is the
        whole point of §6.6's cross-chain ordering window — so the domain is passed
        through to the genesis envelope and the project chain is opened for real.

        Returns ``(handle, keyset)``; the caller closes the handle and drops the
        schema (WI-243's leak guard fails the session otherwise).
        """
        from _v6_fixtures import ACTOR_PRINCIPALS, make_v6_keyset, open_v6_epoch

        from regista import Regista

        project = f"p22_ceremony_{uuid.uuid4().hex[:8]}"
        # The ceremony's own actors are not in ACTOR_PRINCIPALS: the project accepts
        # the requester, while the enrolled subject is accepted after the trust-log
        # lifecycle event exists and can be named by its exact hash.
        principals = (*ACTOR_PRINCIPALS, "human:requester", "agent:ceremony")
        keyset = make_v6_keyset(tmp_path, principals=principals, filename="ceremony_keys.json")
        handle = Regista.create_project(DSN, project, keyset.path)
        open_v6_epoch(
            handle,
            keyset,
            principals=accepted_principals
            or (*ACTOR_PRINCIPALS, "human:requester"),
            trust_domain_id=trust_store.trust_domain_id,
        )
        return handle, keyset

    def _rebuild_ceremony_projection(
        self, trust_store, sub, evidence, *, dry_run=False
    ):
        return rebuild_projection_from_trust_log(
            sub._mgr,
            trust_store.handle._mgr,
            project=sub.project,
            genesis_document=trust_store.genesis_document,
            dry_run=dry_run,
            acceptance_by_principal={"agent:ceremony": evidence},
        )

    def test_two_chain_acceptance_evidence_is_distinct_and_verified(
        self, trust_store, tmp_path
    ):
        """The coordinator joins two independently signed chains by exact hashes."""
        from _v6_fixtures import ACTOR_PRINCIPALS, accept_key, project_identity_of

        from regista._trust_log_writer import verify_trust_log_chain
        from regista._trust_projection import (
            rebuild_projection_from_trust_log,
            verify_project_acceptance,
        )

        sub, keyset = self._project_with_identity(
            trust_store,
            tmp_path,
            accepted_principals=(*ACTOR_PRINCIPALS, "human:requester"),
        )
        try:
            project_key = keyset.key_for("agent:ceremony")
            trust_key = TrustLogKey(
                key_id=project_key.key_id,
                seed=project_key.seed,
                public_key=project_key.public_key,
                fingerprint=project_key.fingerprint,
            )
            trust_event = _enrol(
                trust_store,
                "agent:ceremony",
                trust_key,
                writer=TrustLogKey.mint("unused-fixture-writer"),
            )

            project_genesis = SimpleNamespace(
                to_dict=lambda: {
                    "event_hash": project_identity_of(sub).genesis_event_hash_text
                }
            )
            acceptance = accept_key(
                sub,
                keyset,
                project_genesis,
                "agent:ceremony",
                trust_event_hash=trust_event.event_hash,
            )
            with sub._mgr.transaction() as conn:
                evidence = verify_project_acceptance(
                    conn,
                    event_hash=acceptance.event_hash_text,
                    public_key=keyset.bootstrap.public_key,
                )

            with trust_store.handle._mgr.transaction() as conn:
                verified = verify_trust_log_chain(conn, trust_store.genesis_document)
            assert any(
                item.event_hash == trust_event.event_hash
                for item in verified.verified
            )
            assert evidence.event_hash == acceptance.event_hash_text
            assert evidence.event_hash != trust_event.event_hash

            report = rebuild_projection_from_trust_log(
                sub._mgr,
                trust_store.handle._mgr,
                project=sub.project,
                genesis_document=trust_store.genesis_document,
                acceptance_by_principal={"agent:ceremony": evidence},
            )
            assert report.events_replayed == 1
            from regista._principal_keys import get_active_key

            projected = get_active_key(sub._mgr, "agent:ceremony")
            assert projected.source_event_hash == trust_event.event_hash
            assert projected.acceptance_event_hash == acceptance.event_hash_text
            assert projected.source_event_hash != projected.acceptance_event_hash
        finally:
            project = sub.project
            sub.close()
            drop_project_schema(DSN, project)

    def test_raw_acceptance_hash_is_refused_at_the_cross_schema_seam(
        self, trust_store, tmp_path
    ):
        sub, keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            self._run_ceremony(trust_store, sub, keyset)
            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection_from_trust_log(
                    sub._mgr,
                    trust_store.handle._mgr,
                    project=sub.project,
                    genesis_document=trust_store.genesis_document,
                    acceptance_by_principal={
                        "agent:ceremony": "sha256:" + "0" * 64
                    },
                )
            assert exc_info.value.detail["reason"] == "acceptance_evidence_unstructured"
        finally:
            project = sub.project
            sub.close()
            drop_project_schema(DSN, project)

    def test_acceptance_must_be_on_the_current_head_to_genesis_path(
        self, trust_store, tmp_path
    ):
        from _v6_fixtures import ACTOR_PRINCIPALS, accept_key, project_identity_of

        sub, keyset = self._project_with_identity(
            trust_store,
            tmp_path,
            accepted_principals=(*ACTOR_PRINCIPALS, "human:requester"),
        )
        try:
            project_key = keyset.key_for("agent:ceremony")
            trust_key = TrustLogKey(
                key_id=project_key.key_id,
                seed=project_key.seed,
                public_key=project_key.public_key,
                fingerprint=project_key.fingerprint,
            )
            trust_event = _enrol(
                trust_store,
                "agent:ceremony",
                trust_key,
                writer=TrustLogKey.mint("unused-fixture-writer"),
            )
            project_genesis = SimpleNamespace(
                to_dict=lambda: {
                    "event_hash": project_identity_of(sub).genesis_event_hash_text
                }
            )
            acceptance = accept_key(
                sub,
                keyset,
                project_genesis,
                "agent:ceremony",
                trust_event_hash=trust_event.event_hash,
            )
            with sub._mgr.transaction() as conn:
                conn.execute(
                    "UPDATE event_chain_head SET head_hash = %s WHERE id = TRUE",
                    [bytes.fromhex(project_genesis.to_dict()["event_hash"][7:])],
                )
                with pytest.raises(RegistaError) as exc_info:
                    verify_project_acceptance(
                        conn,
                        event_hash=acceptance.event_hash_text,
                        public_key=keyset.bootstrap.public_key,
                    )
            assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
            assert exc_info.value.detail["reason"] == "acceptance_not_on_project_head_chain"
        finally:
            project = sub.project
            sub.close()
            drop_project_schema(DSN, project)

    def _run_ceremony(self, trust_store, sub, keyset):
        """Complete enrollment through the two-chain ceremony boundary.

        The trust log supplies the lifecycle fact and the ordinary project supplies
        the signed local acceptance. The coordinator must join them by their exact
        hashes before it may materialize ``principal_keys``.
        """
        from _v6_fixtures import accept_key, project_identity_of

        project_key = keyset.key_for("agent:ceremony")
        trust_key = TrustLogKey(
            key_id=project_key.key_id,
            seed=project_key.seed,
            public_key=project_key.public_key,
            fingerprint=project_key.fingerprint,
        )
        trust_event = _enrol(
            trust_store,
            "agent:ceremony",
            trust_key,
            writer=TrustLogKey.mint("unused-fixture-writer"),
        )
        project_genesis = SimpleNamespace(
            to_dict=lambda: {
                "event_hash": project_identity_of(sub).genesis_event_hash_text
            }
        )
        acceptance = accept_key(
            sub,
            keyset,
            project_genesis,
            "agent:ceremony",
            trust_event_hash=trust_event.event_hash,
        )
        with sub._mgr.transaction() as conn:
            evidence = verify_project_acceptance(
                conn,
                event_hash=acceptance.event_hash_text,
                public_key=keyset.bootstrap.public_key,
            )
        report = self._rebuild_ceremony_projection(
            trust_store, sub, evidence
        )
        assert report.applied is True
        assert report.events_replayed == 1
        receipt = SimpleNamespace(key_id=project_key.key_id)
        return receipt, project_key.public_key, trust_event, evidence

    def test_the_ceremony_path_round_trips_byte_for_byte(
        self, trust_store, tmp_path,
    ):
        sub, _keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            receipt, public_key, _trust_event, evidence = self._run_ceremony(
                trust_store, sub, _keyset
            )

            before = _snapshot(sub)
            assert len(before) == 1, "the ceremony must have written exactly one row"

            # No divergence: the ceremony's row is what the rebuild derives.
            report = self._rebuild_ceremony_projection(
                trust_store, sub, evidence, dry_run=True
            )
            assert report.consistent is True, (
                "the ceremony's own row diverges from a rebuild of its own event: "
                f"{[(d.kind, d.fields) for d in report.differences]}"
            )
            assert report.events_replayed == 1

            # ...and an applied rebuild reproduces every compared column exactly.
            self._rebuild_ceremony_projection(trust_store, sub, evidence)
            after = _snapshot(sub)
            assert after == before, "an applied rebuild rewrote the ceremony's row"
            assert receipt.key_id
            assert before[0][3] == public_key  # public_key column
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)

    def test_rebuild_without_acceptance_evidence_cannot_erase_existing_hash(
        self, trust_store, tmp_path
    ):
        sub, keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            _receipt, _public_key, _trust_event, evidence = self._run_ceremony(
                trust_store, sub, keyset
            )
            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection_from_trust_log(
                    sub._mgr,
                    trust_store.handle._mgr,
                    project=sub.project,
                    genesis_document=trust_store.genesis_document,
                )
            assert exc_info.value.detail["reason"] == "acceptance_evidence_required"

            from regista._principal_keys import get_active_key

            projected = get_active_key(sub._mgr, "agent:ceremony")
            assert projected.acceptance_event_hash == evidence.event_hash
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)

    def test_archived_project_acceptance_remains_rebuildable(
        self, trust_store, tmp_path
    ):
        sub, keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            _receipt, _public_key, _trust_event, evidence = self._run_ceremony(
                trust_store, sub, keyset
            )
            with sub._mgr.transaction() as conn:
                conn.execute(
                    "INSERT INTO events_archive SELECT * FROM events "
                    "WHERE transition = 'principal_key_accepted'"
                )
                conn.execute(
                    "DELETE FROM events WHERE transition = 'principal_key_accepted'"
                )

            report = self._rebuild_ceremony_projection(trust_store, sub, evidence)
            assert report.consistent is True
            from regista._principal_keys import get_active_key

            projected = get_active_key(sub._mgr, "agent:ceremony")
            assert projected.acceptance_event_hash == evidence.event_hash
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)

    def test_the_ceremony_row_records_the_trust_domain(self, trust_store, tmp_path):
        """The column that was silently NULL while the payload carried the UUID."""
        from regista._principal_keys import get_active_key

        sub, _keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            self._run_ceremony(trust_store, sub, _keyset)
            entry = get_active_key(sub._mgr, "agent:ceremony")
            assert entry.trust_domain_id == trust_store.trust_domain_id
            assert entry.source_event_hash is not None
            assert entry.provenance == "v6_sourced"
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)

    def test_the_ceremony_row_and_its_event_agree_on_valid_from(
        self, trust_store, tmp_path,
    ):
        """One clock read, not two: the row's valid_from IS the payload's not_before."""
        from regista._principal_keys import get_active_key

        sub, _keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            _receipt, _public_key, trust_event, _evidence = self._run_ceremony(
                trust_store, sub, _keyset
            )
            entry = get_active_key(sub._mgr, "agent:ceremony")
            with trust_store.handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT payload FROM events WHERE event_id = %s",
                    [uuid.UUID(trust_event.event_id)],
                ).fetchone()
            assert row is not None, "the ceremony appended no trust-log enrollment"
            payload = row["payload"]
            from regista._trust_log import parse_principal_key_enrolled

            parsed = parse_principal_key_enrolled(payload)
            assert entry.valid_from == parsed.not_before
            assert entry.key_id == parsed.key.key_id
            assert entry.registered_by == parsed.authorized_by.principal_id
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)

    def test_a_revocation_with_an_out_of_set_reason_round_trips(
        self, trust_store, tmp_path,
    ):
        """B1-prime item 3: the write path used the RAW reason, the payload a mapped one.

        §5.7 closes the reason set, so ``_trust_log_payload`` maps anything outside
        it to ``"unspecified"``. The write path used ``operation.reason`` verbatim, so
        any out-of-set reason diverged on ``revoked_reason`` forever. Both sides now
        take the mapped value from the payload.
        """
        sub, _keyset = self._project_with_identity(trust_store, tmp_path)
        try:
            receipt, _public_key, _trust_event, evidence = self._run_ceremony(
                trust_store, sub, _keyset
            )
            _revoke(
                trust_store,
                "agent:ceremony",
                receipt.key_id,
                reason="operator-said-so",
            )
            self._rebuild_ceremony_projection(trust_store, sub, evidence)

            from regista._principal_keys import list_principal_keys

            rows = list_principal_keys(sub._mgr, "agent:ceremony")
            assert [r.status for r in rows] == ["revoked"]
            # Mapped, on BOTH sides — not the raw "operator-said-so".
            assert rows[0].revoked_reason == "unspecified"

            before = _snapshot(sub)
            report = self._rebuild_ceremony_projection(
                trust_store, sub, evidence, dry_run=True
            )
            assert report.consistent is True, (
                f"{[(d.kind, d.fields) for d in report.differences]}"
            )
            self._rebuild_ceremony_projection(trust_store, sub, evidence)
            assert _snapshot(sub) == before
        finally:
            _sub_project = sub.project
            sub.close()
            drop_project_schema(DSN, _sub_project)


class TestPossessionChallengeIsSuitePositionIndependent:
    """Completes a756677: the possession-challenge clock tracks call-time ``now()``.

    The remaining bug the release fixed was subtle: this module used to derive the
    challenge window from a module-import constant (``_NOW``). pytest imports the module
    at COLLECTION but executes its tests minutes later in a full-suite run, so a window
    of ``import_time + 5 min`` was already expired when the writer admitted at execution
    (``_trust_log_writer.py`` :961, :1761-1767) → ``possession_challenge_expired_at_admission``.
    An isolated run of just this module never exposes it, because collection and
    execution are seconds apart. This test proves the fix without needing the database:
    it drives ``_challenge`` through the ``_now()`` indirection and shows the window
    follows the clock at the moment the helper *runs*, so a 10-minute collection→execution
    gap can no longer expire it.
    """

    @staticmethod
    def _expiry(challenge) -> datetime:
        return datetime.fromisoformat(challenge.expires_at.replace("Z", "+00:00"))

    def test_a_ten_minute_gap_no_longer_expires_the_challenge(self, monkeypatch):
        mod = sys.modules[__name__]
        store = SimpleNamespace(trust_domain_id=str(uuid.uuid4()), project="p_gap_demo")
        key = SimpleNamespace(fingerprint="sha256:" + "a" * 64)

        # Model COLLECTION: build a challenge with the clock pinned to t0. (Under the old
        # code, ``_NOW`` was frozen here at import — this is exactly that instant.)
        t0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC)
        monkeypatch.setattr(mod, "_now", lambda: t0)
        at_collection = _challenge(store, "agent:x", key, None)
        collect_expiry = self._expiry(at_collection)
        assert collect_expiry == t0 + timedelta(minutes=5)

        # Model EXECUTION ~10 min later. A full-suite gap DOES exceed the 5-min window,
        # so a window frozen at collection would already be expired at admission — the
        # bug was real:
        t_exec = t0 + timedelta(minutes=10)
        assert t_exec >= collect_expiry

        # The fix: ``_challenge`` reads ``_now()`` when it RUNS. During a real suite it
        # runs at execution, so advancing the clock and rebuilding yields a window that
        # brackets execution-now — admission at t_exec succeeds:
        monkeypatch.setattr(mod, "_now", lambda: t_exec)
        at_execution = _challenge(store, "agent:x", key, None)
        exec_expiry = self._expiry(at_execution)
        assert exec_expiry == t_exec + timedelta(minutes=5)
        assert exec_expiry > t_exec  # not expired at admission
        # The window moved forward by exactly the gap — proof it tracks call-time now(),
        # not a module-import anchor:
        assert exec_expiry - collect_expiry == timedelta(minutes=10)

    def test_a_future_dated_event_window_brackets_its_occurred_at(self, monkeypatch):
        """The rotation ordered a day out (Criterion 12) must still admit.

        For a future ``occurred_at`` the writer's admission anchor is
        ``max(now, occurred_at) = occurred_at``; the challenge window must bracket THAT,
        not merely real now.
        """
        mod = sys.modules[__name__]
        store = SimpleNamespace(trust_domain_id=str(uuid.uuid4()), project="p_future")
        key = SimpleNamespace(fingerprint="sha256:" + "b" * 64)

        now = datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC)
        monkeypatch.setattr(mod, "_now", lambda: now)
        occurred_at = _event_ts(timedelta(days=1))  # ≈ now + 1 day
        challenge = _challenge(store, "agent:x", key, occurred_at)
        expiry = self._expiry(challenge)
        occurred = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        admission_at = max(now, occurred)  # what the writer compares against
        assert expiry > admission_at
        assert expiry == occurred + timedelta(minutes=5)
