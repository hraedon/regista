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

import importlib
import uuid

import psycopg
import pytest
from _helpers import DSN, KEY_PATH
from _trust_fixtures import mint_solo
from _trust_log_fixtures import (
    TrustLogKey,
    make_enrollment_payload,
    make_revocation_payload,
    make_rotation_payload,
    make_trust_log_project,
    open_trust_log,
    principal_entity_uuid,
    store_trust_log_event,
)

from regista._errors import ErrorCode, RegistaError
from regista._trust_log import (
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
)
from regista._trust_projection import (
    check_projection_consistent,
    projection_summary,
    rebuild_projection,
)
from regista.testing import drop_project_schema, seed_legacy_principal_key

_COLUMNS = (
    "principal_id, key_id, scheme, public_key, fingerprint, status, valid_from, "
    "valid_to, registered_by, registered_at, revoked_at, revoked_reason, "
    "trust_domain_id, source_event_hash, acceptance_event_hash, projection_version"
)


@pytest.fixture
def trust_store(tmp_path):
    """A trust-log project whose chain is opened by `trust_domain_established`.

    The log is a real v6 chain: Bootstrap A first (the only event permitted a null
    key binding and a null previous_project_event_hash), everything else anchored to
    it. Starting mid-chain would let the fixtures produce envelopes the v6 rules
    reject, which is how a rebuild test ends up proving nothing.
    """
    project = f"p22_tl_{uuid.uuid4().hex[:8]}"
    genesis = mint_solo()
    store = make_trust_log_project(
        DSN,
        project,
        tmp_path / "trust_keys.json",
        trust_domain_id=genesis.trust_domain_id,
    )
    root_signer = genesis.signer_ids[0]
    root_key = TrustLogKey(
        key_id="pk_root_a",
        seed=genesis.seeds[root_signer],
        public_key=genesis.public_keys[root_signer],
        fingerprint=genesis.fingerprints[root_signer],
    )
    open_trust_log(store, genesis.document, root_key)
    yield store
    drop_project_schema(DSN, project)


def _mgr(store):
    from regista._connection import ConnectionManager

    mgr = ConnectionManager(store.dsn, store.project)
    mgr.open()
    return mgr


def _snapshot(store) -> list[tuple]:
    """Every column of every row, ordered — the byte-for-byte comparison surface."""
    with psycopg.connect(store.dsn, autocommit=True) as conn:
        conn.execute(f'SET search_path TO "{store.project}"')
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM principal_keys "
            "ORDER BY principal_id, key_id"
        ).fetchall()
    return [tuple(bytes(v) if isinstance(v, memoryview) else v for v in r) for r in rows]


def _enrol(store, principal_id, key, *, writer, occurred_at=None, **kwargs):
    payload = make_enrollment_payload(
        trust_domain_id=store.trust_domain_id,
        principal_id=principal_id,
        key=key,
        **kwargs,
    )
    return store_trust_log_event(
        store,
        transition=PRINCIPAL_KEY_ENROLLED,
        payload=payload,
        signing_key=writer,
        entity_id=principal_entity_uuid(principal_id),
        occurred_at=occurred_at,
    )


class TestCriterion12RebuildReproducesTheProjection:
    """§9.12: rebuild reproduces ``principal_keys`` from signed events alone."""

    def test_rebuild_reproduces_a_post_cutover_store_byte_for_byte(self, trust_store):
        writer = TrustLogKey.mint("pk-trust-log")
        alice = TrustLogKey.mint("pk_alice_1")
        bob = TrustLogKey.mint("pk_bob_1")
        alice2 = TrustLogKey.mint("pk_alice_2")

        _enrol(trust_store, "agent:alice", alice, writer=writer)
        _enrol(trust_store, "agent:bob", bob, writer=writer)
        store_trust_log_event(
            trust_store,
            transition=PRINCIPAL_KEY_ROTATED,
            payload=make_rotation_payload(
                trust_domain_id=trust_store.trust_domain_id,
                principal_id="agent:alice",
                key=alice2,
                supersedes_key_id=alice.key_id,
                superseded_key=alice,
                not_before="2026-08-21T00:00:00.000000Z",
            ),
            signing_key=writer,
            entity_id=principal_entity_uuid("agent:alice"),
            occurred_at="2026-08-21T00:00:00.000000Z",
        )
        store_trust_log_event(
            trust_store,
            transition=PRINCIPAL_KEY_REVOKED,
            payload=make_revocation_payload(
                trust_domain_id=trust_store.trust_domain_id,
                principal_id="agent:bob",
                key_id=bob.key_id,
                reason="compromised",
            ),
            signing_key=writer,
            entity_id=principal_entity_uuid("agent:bob"),
            occurred_at="2026-08-22T00:00:00.000000Z",
        )

        mgr = _mgr(trust_store)
        try:
            first = rebuild_projection(mgr, project=trust_store.project)
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
            second = rebuild_projection(mgr, project=trust_store.project)
            assert second.consistent is True, second.differences
            assert _snapshot(trust_store) == after_first

            # ...and a dry run agrees, having written nothing.
            check = check_projection_consistent(mgr, project=trust_store.project)
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
            rebuild_projection(mgr, project=trust_store.project)
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
        store_trust_log_event(
            trust_store,
            transition=PRINCIPAL_KEY_ROTATED,
            payload=make_rotation_payload(
                trust_domain_id=trust_store.trust_domain_id,
                principal_id="agent:dave",
                key=new,
                supersedes_key_id=old.key_id,
                superseded_key=old,
                not_before="2026-08-25T00:00:00.000000Z",
            ),
            signing_key=writer,
            entity_id=principal_entity_uuid("agent:dave"),
        )
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(mgr, project=trust_store.project)
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
            report = rebuild_projection(mgr, project=trust_store.project)
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

            report = rebuild_projection(mgr, project=trust_store.project)
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
            report = check_projection_consistent(mgr, project=trust_store.project)
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
        revoke = store_trust_log_event(
            trust_store,
            transition=PRINCIPAL_KEY_REVOKED,
            payload=make_revocation_payload(
                trust_domain_id=trust_store.trust_domain_id,
                principal_id="agent:evan",
                key_id=key.key_id,
                reason="compromised",
            ),
            signing_key=writer,
            entity_id=principal_entity_uuid("agent:evan"),
        )
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
            rebuild_projection(mgr, project=trust_store.project)
            ok = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
            assert ok.status == "ok", ok.detail
        finally:
            mgr.close()

        # The exact edit criterion 13 names.
        self._reactivate(trust_store, "agent:evan")

        check = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
        # A FAILURE, not a warning, in production posture (§5.9 rule 3).
        assert check.status == "fail"
        assert "diverge" in check.detail
        assert "status" in check.detail

    def test_the_divergence_names_the_row_and_the_changed_fields(self, trust_store):
        self._revoked_store(trust_store)
        mgr = _mgr(trust_store)
        try:
            rebuild_projection(mgr, project=trust_store.project)
            self._reactivate(trust_store, "agent:evan")
            report = check_projection_consistent(mgr, project=trust_store.project)
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
            rebuild_projection(mgr, project=trust_store.project)
            self._reactivate(trust_store, "agent:evan")
            from regista._principal_keys import list_principal_keys

            assert [k.status for k in list_principal_keys(mgr, "agent:evan")] == [
                "active"
            ]
            rebuild_projection(mgr, project=trust_store.project)
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
            rebuild_projection(mgr, project=trust_store.project)
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
            rebuild_projection(mgr, project=trust_store.project)
        finally:
            mgr.close()
        with psycopg.connect(trust_store.dsn, autocommit=True) as conn:
            conn.execute(f'SET search_path TO "{trust_store.project}"')
            conn.execute(sql)

        from regista._doctor import _check_projection_consistent

        check = _check_projection_consistent(DSN, trust_store.project, require_ssl=False)
        assert check.status == "fail"


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
                rebuild_projection(mgr, project=trust_store.project)
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


class TestEnrolmentWithoutPublicKeyIsRejectedAtRebuild:
    """§9.16 again, from the storage side: a bad event cannot become a good row."""

    def test_an_enrolment_event_lacking_public_key_fails_the_rebuild(
        self, trust_store,
    ):
        writer = TrustLogKey.mint("pk-trust-log")
        key = TrustLogKey.mint("pk_bad")
        payload = make_enrollment_payload(
            trust_domain_id=trust_store.trust_domain_id,
            principal_id="agent:bad",
            key=key,
            omit_public_key=True,
        )
        store_trust_log_event(
            trust_store,
            transition=PRINCIPAL_KEY_ENROLLED,
            payload=payload,
            signing_key=writer,
            entity_id=principal_entity_uuid("agent:bad"),
        )
        mgr = _mgr(trust_store)
        try:
            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection(mgr, project=trust_store.project)
            assert exc_info.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
            assert "public_key" in exc_info.value.detail["missing"]
        finally:
            mgr.close()
