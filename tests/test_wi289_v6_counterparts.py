"""v6 counterparts for WI-289 clusters 1, 2, 3 and 5 (the P1.7 coverage debt).

``tests/retired_tests_ledger.json`` retired 56 tests whose harnesses were
v5/HMAC-specific but whose **invariants survive the epoch reset**. Cluster 4
(bundle v3) is owed to P3.3 and cluster 6 (in-memory parity) was discharged by
WI-287 in ``tests/test_wi287_inmem_parity.py::TestWI289Cluster6``. The remaining
39 entries are P1.7's, and this module is where they are discharged.

Three things distinguish these from the originals, and they are the whole content
of the carry-forward strings:

1. **The formula changed; the invariant did not.** The originals asserted
   ``sha256(envelope || signature)`` and the v5 row shape. These assert the
   domain-tagged ``compute_v6_event_hash`` and the v6 envelope's own ``chain``
   block. Where it is cheap, the v5 value is additionally asserted **absent** —
   asserting only the v6 value would still pass if the writer had kept the v5
   formula on another code path.
2. **The verdict is asserted, not merely the reconciliation.** Cluster 6 had to
   live with ``row_reconciled`` / ``mismatched_field_names`` because
   ``_verification._verify_v6_row`` was clamped to
   ``INVALID``/``ENVELOPE_SCHEMA_INCOMPLETE`` for *every* v6 row, so an
   ``applicability == INVALID`` assertion would have passed on a clean event and
   proved nothing. P1.7 phase 2 (NOTES-P17 §0b) removed the clamp, so every
   tamper test here pairs a clean ``FULLY_AUTHENTICATED`` with a tampered
   ``INVALID``. The pairing *is* the evidence; the ``INVALID`` half alone is not.
3. **The link is inside the signed envelope now.** In v5 a chain link was a row
   column the row alone carried, so rewriting it was only a structural chain
   break. In v6 ``chain.previous_entity_event_hash`` /
   ``chain.previous_project_event_hash`` are signed members duplicated into the
   row, so the same rewrite is *both* a reconciliation failure and a chain break —
   and the tests assert both halves rather than picking one.

Everything here runs against a **real Postgres epoch** written by the real
writer, verified through the real store-backed referent resolver. The synthetic
corpus in ``tests/test_p17_v6_verifier_boundary.py`` proves the decision
procedure; the retired originals were end-to-end store tests, so their
counterparts have to be too.

``TestLedgerMapping::test_every_entry_this_file_discharges_names_a_test_that_exists``
machine-checks the ledger pointers, mirroring cluster 6: a mapping that names a
test which stops existing after a rename is the normal way a coverage-owed ledger
rots.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import threading
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from regista._signing import compute_v6_event_hash
from regista._v6_referents import store_referents
from regista._v6_writer import append_v6_event
from regista._verification import (
    Applicability,
    EventRow,
    FailureReason,
    KeySetResolver,
    parse_v6_envelope_strict,
    verify_event_strict,
)
from tests._v6_fixtures import (
    ACTOR_PRINCIPALS,
    BOOTSTRAP_PRINCIPAL,
    V6TestKeyset,
    acceptance_payload,
    make_v6_keyset,
    open_v6_epoch,
    v6_producer,
)

# Aliased on import: a module-level class named ``Test*`` makes pytest emit a
# collection warning for every file that imports it.
from tests._v6_fixtures import TestKey as V6TestKey

DSN = os.environ.get("REGISTA_TEST_DSN", "")

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

WORKER = "agent:worker"
REVIEWER = "human:reviewer"
WORKFLOW_PATH = "tests/test_workflow.yaml"
WORKFLOW_NAME = "test_workflow"
WORKFLOW_VERSION = 1

#: ``test_workflow.yaml`` gates each transition on ``allowed_roles``, and
#: ``_contract.check_role_gating`` reads the role from ``actor.metadata`` — not from
#: the ``actor_roles`` table. It is worth naming because it is the one place these
#: counterparts put anything in ``actor.metadata``: the v6 key acceptance authorises
#: the *signer*, the workflow's role gate authorises the *transition*, and the two
#: are separate mechanisms that a passing test should not blur.
AGENT_ROLE = {"role": "agent"}
REVIEWER_ROLE = {"role": "reviewer"}

#: A payload whose keys ``jsonb`` and JCS order **differently**: ``jsonb`` sorts by
#: (length, bytes) and JCS by UTF-16 code unit, so ``b`` precedes ``aa`` in the
#: stored column while ``aa`` precedes ``b`` in the signed bytes. The payload
#: key-reorder counterparts assert that divergence before asserting the
#: reconciliation, because without it the canonical comparison is never reached and
#: the test would pass on a byte-for-byte comparator.
REORDERING_PAYLOAD = {"aa": 1, "b": {"nested": True}, "cccc": [1, 2, 3], "z": None}

#: ``actor.kind`` for each principal-id prefix. ``service:`` maps to ``system``
#: because a ``service`` principal acting on its own behalf is what the envelope
#: grammar calls a system actor; the other two are the same word twice.
_ACTOR_KINDS = {"human": "human", "agent": "agent", "service": "system"}

#: Every column ``EventRow.from_mapping`` reads. Kept as one string so a test
#: cannot accidentally verify a row with a column missing — a NULL that the
#: reconciler then compares against a signed value is a false mismatch.
EVENT_COLUMNS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, event_seq, "
    "actor_id, actor_kind, actor_metadata, key_id, workflow_name, "
    "workflow_version, timestamp, transition, payload, payload_canonical_hash, "
    "signature, canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "global_seq, prev_global_event_hash"
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _Epoch:
    """A real v6 epoch on Postgres, plus the four operations these tests need.

    ``append`` / ``row`` / ``verify`` / ``sql`` deliberately mirror cluster 6's
    ``_append`` / ``_row`` / ``_verify`` / ``_rewrite_row`` so the two files read
    the same way; the difference is that ``verify`` here presents
    ``store_referents(conn)``, which is what makes the ``applicability`` verdict
    meaningful rather than clamped.
    """

    def __init__(self, instance: Any, keyset: V6TestKeyset, genesis: Any) -> None:
        self.instance = instance
        self.keyset = keyset
        self.genesis = genesis

    # -- writing ----------------------------------------------------------

    def append(self, *, keys: Any = None, **kwargs: Any) -> Any:
        kwargs.setdefault("entity_kind", "work_item")
        kwargs.setdefault("entity_id", uuid.uuid4())
        kwargs.setdefault("transition", "created")
        kwargs.setdefault("actor_id", WORKER)
        kwargs.setdefault("actor_kind", "agent")
        kwargs.setdefault("producer", v6_producer())
        with self.instance._mgr.transaction() as conn:
            return append_v6_event(conn, keys or self.instance._keys, **kwargs)

    def append_with_workflow(self, **kwargs: Any) -> Any:
        kwargs.setdefault("workflow_name", WORKFLOW_NAME)
        kwargs.setdefault("workflow_version", WORKFLOW_VERSION)
        kwargs.setdefault("payload", {"note": "workflow bearing"})
        return self.append(**kwargs)

    # -- reading ----------------------------------------------------------

    def row(self, event_id: Any) -> Any:
        with self.instance._mgr.transaction() as conn:
            row = conn.execute(
                f"SELECT {EVENT_COLUMNS} FROM events WHERE event_id = %s", [event_id]
            ).fetchone()
        assert row is not None, f"no events row for {event_id}"
        return row

    def envelope(self, event_id: Any) -> dict[str, Any]:
        return parse_v6_envelope_strict(bytes(self.row(event_id)["canonical_envelope"]))

    def verify(self, event_id: Any) -> Any:
        with self.instance._mgr.transaction() as conn:
            row = conn.execute(
                f"SELECT {EVENT_COLUMNS} FROM events WHERE event_id = %s", [event_id]
            ).fetchone()
            assert row is not None, f"no events row for {event_id}"
            return verify_event_strict(
                EventRow.from_mapping(row),
                keys=KeySetResolver(self.instance._keys),
                referents=store_referents(conn, label="wi289 counterpart"),
            )

    def fetchall(self, statement: str, params: Any = ()) -> list[Any]:
        with self.instance._mgr.transaction() as conn:
            return conn.execute(statement, list(params)).fetchall()

    def fetchone(self, statement: str, params: Any = ()) -> Any:
        with self.instance._mgr.transaction() as conn:
            return conn.execute(statement, list(params)).fetchone()

    # -- tampering --------------------------------------------------------

    def sql(self, statement: str, params: Any = ()) -> None:
        """The attacker's ``UPDATE``. A direct write, never through the API."""

        with self.instance._mgr.transaction() as conn:
            conn.execute(statement, list(params))

    def rewrite(self, event_id: Any, column: str, value: Any) -> None:
        self.sql(
            f"UPDATE events SET {column} = %s WHERE event_id = %s", [value, event_id]
        )


def _open_epoch(dsn: str, keyset: V6TestKeyset, label: str) -> Any:
    from regista import Regista

    project = f"wi289_{label}_{uuid.uuid4().hex[:8]}"
    instance = Regista.create_project(dsn, project, keyset.path)
    genesis = open_v6_epoch(instance, keyset, principals=ACTOR_PRINCIPALS)
    return project, instance, genesis


def _jsonb_key_order(epoch: _Epoch, event_id: Any) -> list[str]:
    """The order Postgres renders the stored ``payload`` column's keys in.

    ``payload::text`` is the only way to observe it: ``psycopg`` hands back a
    ``dict`` whose order came from the text, but going through ``json.loads`` here
    keeps the parse explicit about what is being measured.
    """

    text = epoch.fetchone(
        "SELECT payload::text AS t FROM events WHERE event_id = %s", [event_id]
    )["t"]
    return list(json.loads(text))


@pytest.fixture
def keyset(tmp_path: Path) -> V6TestKeyset:
    return make_v6_keyset(tmp_path)


@pytest.fixture
def epoch(keyset: V6TestKeyset):
    """A fresh epoch per test, with ``test_workflow`` registered.

    Function-scoped on purpose: every tamper test writes directly to ``events``,
    and a shared epoch would let one test's rewrite decide another's verdict.

    ``close()`` + ``drop_project_schema`` are the fixture contract, not
    politeness — WI-243's leak guard fails the session on a surviving schema.
    """

    from regista._testing import drop_project_schema

    project, instance, genesis = _open_epoch(DSN, keyset, "e")
    try:
        instance.register_workflow_file(WORKFLOW_PATH)
        yield _Epoch(instance, keyset, genesis)
    finally:
        instance.close()
        drop_project_schema(DSN, project)


# ---------------------------------------------------------------------------
# Cluster 1 — row reconciliation (V6-ENVELOPE.md §9.1/§9.2)
# ---------------------------------------------------------------------------

#: The signed members duplicated into the ``events`` row, with the value an
#: attacker rewrites them to and the mismatch field name the verifier must name.
#: ``_reconcile_v6``'s field map is the authority; this is the subset the retired
#: ``test_row_column_rewrite_fails_verification`` parametrization covered, plus
#: ``scheme_id`` (cluster 3's "``scheme_id`` equality with the trusted key").
ROW_REWRITES: tuple[tuple[str, Any, str], ...] = (
    ("actor_id", "agent:attacker", "actor_id"),
    ("actor_kind", "human", "actor_kind"),
    ("actor_metadata", json.dumps({"role": "admin"}), "actor_metadata"),
    ("hash_alg", "sha-512", "hash_alg"),
    ("key_id", "other-key", "key_id"),
    ("payload", json.dumps({"rewritten": True}), "payload"),
    ("transition", "approve", "transition"),
    ("workflow_name", "other_wf", "workflow_name"),
    ("workflow_version", 9, "workflow_version"),
)


class TestCluster1RowReconciliation:
    """Nine signed columns, the timestamp, the JCS-bytes comparisons, the entity
    alias, envelope deletion and the unknown-envelope-shape halt."""

    @pytest.mark.parametrize(
        ("column", "value", "field"), ROW_REWRITES, ids=[r[0] for r in ROW_REWRITES]
    )
    def test_a_rewritten_signed_row_column_is_invalid_and_named(
        self, epoch, column: str, value: Any, field: str
    ) -> None:
        """Discharges the nine
        ``tests/test_wi267_row_authentication.py::TestEndToEndPostgres::test_row_column_rewrite_fails_verification``
        parametrizations (``actor_id``, ``actor_kind``, ``actor_metadata``,
        ``hash_alg``, ``key_id``, ``payload``, ``transition``, ``workflow_name``,
        ``workflow_version``).

        Two assertions carry the v6-specific content:

        * ``signature_valid is True`` — the signature is over the *stored
          envelope bytes*, which the attacker did not touch. A row rewrite is
          caught by **reconciliation**, never by the signature going bad, and a
          test that accepted "something failed" would not notice if the two
          swapped places.
        * ``KEY_UNRESOLVABLE`` never appears: the trusted key is resolved from the
          **envelope's** ``signing.key_id``, so rewriting the row column to a
          key id that does not exist in the keyset is a named *mismatch*. A
          verifier that resolved from the row would report an unresolvable key —
          a materially weaker finding, because "I could not check this" reads
          very differently from "this row is lying".
        """

        appended = epoch.append_with_workflow()

        clean = epoch.verify(appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()
        assert clean.row_reconciled is True
        assert clean.mismatched_field_names == ()

        epoch.rewrite(appended.event_id, column, value)

        result = epoch.verify(appended.event_id)
        assert result.signature_valid is True, result.summary()
        assert result.row_reconciled is False
        assert result.mismatched_field_names == (field,)
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_UNRESOLVABLE not in result.reasons
        assert FailureReason.SCHEME_UNRESOLVABLE not in result.reasons
        if column == "key_id":
            # The reason set names the disagreement specifically, beside the
            # generic row mismatch — measured, not assumed.
            assert FailureReason.KEY_ID_MISMATCH in result.reasons
            assert "other-key" in (result.detail or ""), result.detail

    def test_a_timestamp_rewrite_of_one_second_is_invalid(self, epoch) -> None:
        """Discharges ``TestEndToEndPostgres::test_timestamp_rewrite_fails_verification``.

        Ledger invariant: "a +1s timestamp rewrite fails verification" — carried
        forward as ``occurred_at`` ↔ ``timestamp`` **instant** equality (§9.2).
        """

        appended = epoch.append()
        clean = epoch.verify(appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        original = epoch.row(appended.event_id)["timestamp"]
        epoch.rewrite(appended.event_id, "timestamp", original + timedelta(seconds=1))

        result = epoch.verify(appended.event_id)
        assert result.signature_valid is True
        assert result.mismatched_field_names == ("timestamp",)
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons
        assert result.applicability is Applicability.INVALID

    def test_re_rendering_the_timestamp_in_another_timezone_is_not_tamper(
        self, epoch
    ) -> None:
        """Discharges ``test_timestamp_rendering_in_another_timezone_is_not_tamper``
        (``TestEndToEndPostgres``).

        Ledger invariant: "timezone re-rendering of the same instant is not
        tamper". The comparison is instant-based, not text-based (§2.3/§9.2), so
        the *same instant* rendered at another offset must stay
        ``FULLY_AUTHENTICATED`` — and the offset must really have changed, or the
        test proves nothing.
        """

        appended = epoch.append()
        before = epoch.row(appended.event_id)["timestamp"]

        # A `timestamptz` column stores an instant; the session TimeZone decides
        # only how it is rendered. Reading the same row under a different zone is
        # exactly the "another timezone" the retired test meant.
        with epoch.instance._mgr.transaction() as conn:
            conn.execute("SET LOCAL TimeZone = 'Asia/Kolkata'")
            row = conn.execute(
                f"SELECT {EVENT_COLUMNS} FROM events WHERE event_id = %s",
                [appended.event_id],
            ).fetchone()
            assert row is not None
            rendered = row["timestamp"]
            result = verify_event_strict(
                EventRow.from_mapping(row),
                keys=KeySetResolver(epoch.instance._keys),
                referents=store_referents(conn, label="wi289 tz"),
            )

        assert rendered.utcoffset() != before.utcoffset(), (
            "the session zone did not change the rendering, so this test would "
            f"pass vacuously ({rendered!r} vs {before!r})"
        )
        assert rendered == before, "the instant must be identical"
        assert result.mismatched_field_names == ()
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()

    def test_a_payload_key_reorder_in_the_row_is_not_tamper(self, epoch) -> None:
        """Discharges ``TestEndToEndPostgres::test_payload_key_reorder_is_not_tamper``.

        Ledger invariant: "jsonb key reorder of payload is not tamper". v6
        reconciles the payload as **canonical JCS bytes** (§9.2), so a jsonb
        column whose keys came back in another order is the same payload. The
        reorder is asserted to have actually happened at the SQL level, or the
        test would be satisfied by a no-op ``UPDATE``.
        """

        payload = REORDERING_PAYLOAD
        appended = epoch.append(payload=payload)

        # The reorder does not have to be *inflicted*: `jsonb` orders keys by
        # (length, bytes) and JCS orders them by code unit, so the stored column
        # and the signed bytes disagree about order for this payload already. That
        # divergence is asserted rather than assumed — if the two agreed, this test
        # would pass without the canonical comparison doing any work at all.
        stored_order = _jsonb_key_order(epoch, appended.event_id)
        signed_order = list(payload)
        assert stored_order != signed_order, (
            "jsonb and JCS agreed on key order, so nothing here exercises the "
            f"canonical comparison ({stored_order})"
        )
        assert sorted(stored_order) == sorted(signed_order)

        # And then inflict one anyway, through `json` (which preserves textual
        # order) and back, which is exactly the operator UPDATE the retired test
        # modelled.
        reordered = json.dumps({k: payload[k] for k in reversed(list(payload))})
        epoch.sql(
            "UPDATE events SET payload = %s::json::jsonb WHERE event_id = %s",
            [reordered, appended.event_id],
        )
        assert _jsonb_key_order(epoch, appended.event_id) == stored_order, (
            "jsonb re-normalised the inflicted order, which is why the divergence "
            "above is the load-bearing half of this test"
        )

        result = epoch.verify(appended.event_id)
        assert result.mismatched_field_names == ()
        assert result.row_reconciled is True
        assert "payload" in result.authenticated_fields
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()

    def test_replay_survives_a_payload_key_reorder(self, epoch) -> None:
        """Discharges ``test_replay_survives_jsonb_payload_key_reorder``
        (``tests/test_signing.py::TestAC26JsonbDriftSurvival``).

        Same invariant as above, asserted where the retired test asserted it —
        through ``replay()``, which is the consumer that would have reported the
        reorder as drift.

        The event goes through ``create_work_item`` because replay is the consumer
        under test and a raw-writer event has no ``work_items_current`` row to
        replay. The divergence between the stored jsonb order and the signed JCS
        order is asserted on that real funnel-built payload, so the canonical
        comparison is genuinely exercised rather than assumed.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "reorder", "metadata": {"aa": 1, "b": 2}},
        )
        assert wi is not None
        target = epoch.fetchone(
            "SELECT event_id FROM events WHERE work_item_id = %s ORDER BY event_seq",
            [wi.work_item_id],
        )["event_id"]
        stored_order = _jsonb_key_order(epoch, target)
        signed_order = list(epoch.envelope(target)["payload"])
        assert stored_order != signed_order, (
            "jsonb and JCS agreed on key order for this payload, so the reorder "
            f"below exercises nothing ({stored_order})"
        )

        epoch.sql(
            "UPDATE events SET payload = payload::text::json::jsonb "
            "WHERE work_item_id = %s",
            [wi.work_item_id],
        )

        report = epoch.instance.replay()
        assert report.replayed_ok >= 1
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0
        assert report.halted == 0, [e.detail for e in report.entries]

    def test_a_global_seq_rewrite_is_never_a_mismatch(self, epoch) -> None:
        """Discharges ``test_global_seq_rewrite_is_not_reported_as_a_mismatch``
        (``TestEndToEndPostgres``).

        Ledger invariant: "global_seq rewrite is never a verification mismatch".
        ``global_seq`` is an operational allocation, never signed and never
        compared (§4.1/§9.2), so it may not appear in ``mismatched_field_names``
        **and** may not appear in ``authenticated_fields`` either — the second
        half is what stops a future change from "fixing" this by signing it.
        """

        appended = epoch.append()
        clean = epoch.verify(appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()
        assert "global_seq" not in clean.authenticated_fields

        epoch.rewrite(appended.event_id, "global_seq", 999_999)

        result = epoch.verify(appended.event_id)
        assert result.mismatched_field_names == ()
        assert result.row_reconciled is True
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert "global_seq" not in result.authenticated_fields

    def test_a_broken_work_item_entity_alias_is_invalid(self, epoch) -> None:
        """Discharges ``test_a_broken_work_item_entity_alias_fails_verification``
        (``TestEndToEndPostgres``).

        Ledger invariant: "repointing the unsigned ``work_item_id`` column away
        from ``entity_id`` fails verification". v6 keeps ``work_item_id``
        constrained ``== entity.id`` and **unsigned** (§7.3/§9.2) — an unsigned
        column that must still agree, which is why the finding is a named
        pseudo-field rather than a field mismatch.
        """

        appended = epoch.append()
        clean = epoch.verify(appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        epoch.rewrite(appended.event_id, "work_item_id", uuid.uuid4())

        result = epoch.verify(appended.event_id)
        assert result.signature_valid is True
        assert result.row_reconciled is False
        assert "work_item_id!=entity_id" in result.mismatched_field_names
        assert result.applicability is Applicability.INVALID

    def test_deleting_the_canonical_envelope_is_unverifiable_and_names_the_absence(
        self, epoch
    ) -> None:
        """Discharges ``test_deleting_an_envelope_halts_because_the_row_contradicts_itself``
        (``TestEndToEndPostgres``).

        Ledger invariant: "nulling ``canonical_envelope`` on a signed row halts
        (the row contradicts its own signature/hash)". The stored bytes are the
        artifact (``V6-ENVELOPE.md`` §9.2), so with them gone there is nothing left
        to verify.

        **The verdict is ``UNVERIFIABLE``, not ``INVALID``, and that is measured
        rather than assumed.** The v5 original reached a *halt* through
        ``AbsentEnvelopeProbe``: a legacy row's retained ``signature`` and
        ``payload_canonical_hash`` could be re-derived from the row and shown to
        contradict it, which made the verdict stricter. There is no v6
        reconstruction — offline rebuilding is an explicit operator action, never a
        verify-path fallback — so the probe does not run and the honest answer is
        "nothing could be checked". The *halt* half of the invariant survives
        intact and is asserted next door in
        ``test_deleting_the_canonical_envelope_halts_replay``; what must not be
        claimed is a contradiction the verifier did not find.
        """

        appended = epoch.append()
        clean = epoch.verify(appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        epoch.rewrite(appended.event_id, "canonical_envelope", None)

        result = epoch.verify(appended.event_id)
        assert result.envelope_present is False
        assert result.signature_valid is False
        assert result.row_reconciled is False
        assert result.reasons == (FailureReason.ENVELOPE_ABSENT,)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        # Named, never absent-and-assumed-fine: a consumer that reads only
        # `signature_valid` must still be told why.
        assert "canonical_envelope" in (result.detail or "")

    def test_deleting_the_canonical_envelope_halts_replay(self, epoch) -> None:
        """Discharges ``test_replay_succeeds_with_missing_envelope_postgres``
        (``tests/test_hash_chain.py::TestBC311ReplayChainFields``).

        The retired test's *name* said "succeeds"; its recorded invariant is the
        corrected one — nulling ``canonical_envelope`` on a signed v6 row **halts**
        replay. A missing artifact that replay walked past would be the exact
        "nothing was checked, so everything checks out" failure the epoch reset
        exists to remove.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "envelope deletion"},
        )
        assert wi is not None
        assert epoch.instance.replay().halted == 0

        epoch.sql(
            "UPDATE events SET canonical_envelope = NULL WHERE work_item_id = %s",
            [wi.work_item_id],
        )

        report = epoch.instance.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        assert report.replayed_ok == 0
        # `_replay` finds the CONTRADICTION the verifier could not: it probes
        # whether any envelope this row could have carried reproduces the retained
        # signature, and none does. `verify_event_strict` reports UNVERIFIABLE
        # (nothing to check); replay reports the contradiction. Both are asserted
        # so the split between them stays visible.
        detail = next(e.detail for e in report.entries if e.category == "halted") or ""
        assert "no canonical_envelope" in detail, detail
        assert "contradicts its o" in detail, detail

    def test_an_unknown_stored_envelope_shape_halts_replay_and_is_invalid(
        self, epoch
    ) -> None:
        """Discharges ``TestEndToEndPostgres::test_replay_halts_on_an_unknown_envelope_schema``.

        Ledger invariant: "an unrecognizable stored envelope shape halts replay".
        Strict parsing (§8) has no "closest known version" fallback, so an object
        that is not a recognised envelope is ``ENVELOPE_UNKNOWN_SCHEMA`` — never
        classified as the version it most resembles.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "unknown schema"},
        )
        assert wi is not None
        target = epoch.fetchone(
            "SELECT event_id FROM events WHERE work_item_id = %s "
            "ORDER BY event_seq DESC LIMIT 1",
            [wi.work_item_id],
        )["event_id"]

        clean = epoch.verify(target)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        epoch.rewrite(
            target,
            "canonical_envelope",
            json.dumps({"attacker": "authored", "version": 6}).encode("utf-8"),
        )

        result = epoch.verify(target)
        assert FailureReason.ENVELOPE_UNKNOWN_SCHEMA in result.reasons
        assert result.applicability is Applicability.INVALID

        report = epoch.instance.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        detail = next(e.detail for e in report.entries if e.category == "halted") or ""
        assert "envelope_unknown_schema" in detail, detail
        # Not silently reclassified as the version it most resembles: the halt says
        # `envelope=unknown_schema`, not `envelope=v6`.
        assert "envelope=unknown_schema" in detail, detail

    def test_replay_halts_on_a_rewritten_payload(self, epoch) -> None:
        """Discharges ``TestEndToEndPostgres::test_replay_halts_on_a_rewritten_payload``."""

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "payload rewrite"},
        )
        assert wi is not None
        assert epoch.instance.replay().halted == 0

        epoch.sql(
            "UPDATE events SET payload = %s::jsonb WHERE work_item_id = %s",
            [json.dumps({"rewritten": True}), wi.work_item_id],
        )

        report = epoch.instance.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        detail = next(e.detail for e in report.entries if e.category == "halted") or ""
        assert "Signature verification failed" in detail, detail
        assert "mismatched=payload" in detail, detail

    def test_replay_halts_on_a_rewritten_transition(self, epoch) -> None:
        """Discharges ``TestEndToEndPostgres::test_replay_halts_on_a_rewritten_transition``.

        The row/envelope disagreement half is
        ``test_a_rewritten_signed_row_column_is_invalid_and_named[transition]``;
        this is the consumer-level half the retired test asserted.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "transition rewrite"},
        )
        assert wi is not None
        assert epoch.instance.replay().halted == 0

        epoch.sql(
            "UPDATE events SET transition = 'approve' WHERE work_item_id = %s",
            [wi.work_item_id],
        )

        report = epoch.instance.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        detail = next(e.detail for e in report.entries if e.category == "halted") or ""
        assert "Signature verification failed" in detail, detail
        assert "mismatched=transition" in detail, detail
        # The rewritten transition is a *signed-field* disagreement, not a
        # projection disagreement: replay halts before it could apply the state
        # machine, so this is never reported as drift.
        assert report.replayed_drift == 0

    def test_the_stored_bytes_are_the_artifact_and_every_signed_field_reconciles(
        self, epoch
    ) -> None:
        """Discharges ``test_signature_verification_uses_stored_envelope``
        (``tests/test_signing.py::TestAC26JsonbDriftSurvival``).

        Ledger invariant: "signature verification verifies the exact stored
        envelope bytes, with every signed field reconciled against the row"
        (§5.4 JCS fixed point + §9.1 full row agreement). Both halves in one
        place, because the carry-forward names them together:

        * the stored bytes re-canonicalize to **themselves** — they are the
          artifact, not a rendering of one;
        * the verdict is ``FULLY_AUTHENTICATED`` with every reconciled field in
          ``authenticated_fields`` and none in ``mismatched_field_names``.
        """

        from regista._signing import canonicalize_v6_envelope

        appended = epoch.append_with_workflow(payload={"z": 1, "a": {"nested": True}})
        row = epoch.row(appended.event_id)
        stored = bytes(row["canonical_envelope"])

        assert stored == appended.canonical_envelope
        assert canonicalize_v6_envelope(parse_v6_envelope_strict(stored)) == stored

        result = epoch.verify(appended.event_id)
        assert result.signature_valid is True
        assert result.row_reconciled is True
        assert result.mismatched_field_names == ()
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        # Every member `_reconcile_v6` compares must be reported as
        # authenticated. Naming them keeps the claim "every signed field", not
        # "the ones the comparator happened to reach".
        for field in (
            "event_id",
            "entity_kind",
            "entity_id",
            "entity_seq",
            "actor_id",
            "actor_kind",
            "actor_metadata",
            "scheme_id",
            "key_id",
            "timestamp",
            "transition",
            "payload",
            "hash_alg",
            "prev_event_hash",
            "prev_global_event_hash",
            "workflow_name",
            "workflow_version",
        ):
            assert field in result.authenticated_fields, field

    def test_a_workflow_transition_event_verifies_against_its_stored_envelope(
        self, epoch
    ) -> None:
        """Discharges ``test_transition_event_signature_verifies_with_stored_envelope``
        (``TestAC26JsonbDriftSurvival``).

        Same invariant, for a **workflow-transition** event written through the
        public API rather than the raw writer, and with the row's ``entity_kind``
        and ``hash_alg`` explicitly among the authenticated fields as the ledger
        entry names.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "transition"},
        )
        assert wi is not None
        epoch.instance.transition(
            wi.work_item_id, "start", WORKER, actor_kind="agent", actor_metadata=AGENT_ROLE
        )

        target = epoch.fetchone(
            "SELECT event_id, transition FROM events WHERE work_item_id = %s "
            "ORDER BY event_seq DESC LIMIT 1",
            [wi.work_item_id],
        )
        assert target["transition"] == "start"

        result = epoch.verify(target["event_id"])
        assert result.signature_valid is True
        assert result.row_reconciled is True
        assert result.mismatched_field_names == ()
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert "entity_kind" in result.authenticated_fields
        assert "hash_alg" in result.authenticated_fields
        envelope = epoch.envelope(target["event_id"])
        assert envelope["workflow"]["name"] == WORKFLOW_NAME
        assert envelope["workflow"]["version"] == WORKFLOW_VERSION
        # The registration this transition binds to is named in the signed bytes,
        # which is what makes the workflow claim checkable rather than asserted.
        assert envelope["workflow"]["definition_hash"].startswith("sha256:")
        assert envelope["workflow"]["registration_event_hash"].startswith("sha256:")
        assert envelope["transition"] == "start"


# ---------------------------------------------------------------------------
# Cluster 2 — entity- and project-chain integrity (§5.3/§4.1)
# ---------------------------------------------------------------------------


class TestCluster2ChainIntegrity:
    """Signed prev links, tamper/orphan/genesis corruption, and the serialization
    of concurrent appends onto one unbroken chain."""

    def test_the_postgres_entity_link_uses_the_v6_formula_not_the_v5_one(
        self, epoch
    ) -> None:
        """Discharges ``test_second_event_includes_prev_hash``
        (``tests/test_hash_chain.py::TestBC233HashChain``).

        The retired test asserted ``sha256(envelope || signature)``. Asserting
        only the v6 value would still pass if the writer had kept the v5 formula
        on another code path, so the v5 value is asserted **absent** — in the
        signed envelope member *and* in the row column that duplicates it. That
        pairing is the strongest form of this assertion and is what cluster 6's
        equivalent test established.
        """

        entity_id = uuid.uuid4()
        first = epoch.append(entity_id=entity_id, transition="created")
        second = epoch.append(entity_id=entity_id, transition="updated")

        v6 = compute_v6_event_hash(first.canonical_envelope, first.signature)
        v5 = hashlib.sha256(first.canonical_envelope + first.signature).digest()
        assert v6 != v5, "domain tagging must actually change the digest"

        envelope = epoch.envelope(second.event_id)
        assert envelope["chain"]["previous_entity_event_hash"] == "sha256:" + v6.hex()
        assert envelope["chain"]["previous_entity_event_hash"] != "sha256:" + v5.hex()

        row = epoch.row(second.event_id)
        assert bytes(row["prev_event_hash"]) == v6
        assert bytes(row["prev_event_hash"]) != v5

    def test_the_public_append_api_persists_the_v6_entity_chain_link(
        self, epoch
    ) -> None:
        """Discharges ``TestBC233HashChain::test_append_event_api_persists_prev_hash``.

        Ledger invariant: "the **public append API** persists the entity-chain
        link". The distinction from
        ``TestSemanticConformance::test_the_entity_chain_links_by_signed_v6_event_hash``
        is the funnel: that test calls ``append_v6_event`` directly, this one goes
        through ``create_work_item``/``transition``, which is the surface a caller
        actually has. A link the raw writer persists and the funnel drops would
        pass there and fail here.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "public api"},
        )
        assert wi is not None
        epoch.instance.transition(
            wi.work_item_id, "start", WORKER, actor_kind="agent", actor_metadata=AGENT_ROLE
        )

        rows = epoch.fetchall(
            "SELECT event_id, event_seq, canonical_envelope, signature, prev_event_hash "
            "FROM events WHERE work_item_id = %s ORDER BY event_seq",
            [wi.work_item_id],
        )
        assert len(rows) >= 2
        assert rows[0]["prev_event_hash"] is None
        for previous, current in itertools.pairwise(rows):
            expected = compute_v6_event_hash(
                bytes(previous["canonical_envelope"]), bytes(previous["signature"])
            )
            assert bytes(current["prev_event_hash"]) == expected
            envelope = epoch.envelope(current["event_id"])
            assert envelope["chain"]["previous_entity_event_hash"] == (
                "sha256:" + expected.hex()
            )

    def test_a_rewritten_entity_chain_link_is_both_invalid_and_a_chain_break(
        self, epoch
    ) -> None:
        """Discharges ``TestBC233HashChain::test_broken_chain_detected``.

        Ledger invariant: "a rewritten entity-chain row link is **both** a
        verification halt **and** a structural chain break". In v5 the link was
        only a row column, so this was one finding; in v6 it is a signed envelope
        member duplicated into the row, so the same rewrite must produce two
        independent findings — and a reader may be watching either
        (``_ReplayHaltError`` carries both for exactly this reason).
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "entity link"},
        )
        assert wi is not None
        epoch.instance.transition(
            wi.work_item_id, "start", WORKER, actor_kind="agent", actor_metadata=AGENT_ROLE
        )
        assert epoch.instance.replay().halted == 0

        target = epoch.fetchone(
            "SELECT event_id FROM events WHERE work_item_id = %s AND event_seq = 2",
            [wi.work_item_id],
        )["event_id"]
        epoch.rewrite(target, "prev_event_hash", b"\x11" * 32)

        result = epoch.verify(target)
        assert result.signature_valid is True
        assert result.mismatched_field_names == ("prev_event_hash",)
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons
        assert result.applicability is Applicability.INVALID

        # BOTH findings, asserted as both: the verification halt AND the structural
        # chain break, from the one rewrite. `_ReplayHaltError` carries the
        # chain-break count out through the halt precisely so the halt cannot erase
        # it, and a test that checked only `halted` would not notice if it did.
        report = epoch.instance.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        assert report.chain_breaks == 1, report.to_dict()
        detail = next(e.detail for e in report.entries if e.category == "halted") or ""
        assert "Signature verification failed" in detail, detail
        assert "mismatched=prev_event_hash" in detail, detail

    def test_a_rewritten_project_chain_link_is_reported_as_a_chain_break(
        self, epoch
    ) -> None:
        """Discharges ``test_bc300_replay_detects_global_chain_tamper``
        (``tests/test_global_event_chain.py``).

        Ledger invariant: "a rewritten project-chain row link is reported as a
        chain break by replay" — plus the v6 half the carry-forward adds: the
        link is signed, so the row rewrite also reconciles ``INVALID``.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "project link"},
        )
        assert wi is not None
        baseline = epoch.instance.replay()
        assert baseline.chain_breaks == 0
        assert baseline.halted == 0

        target = epoch.fetchone(
            "SELECT event_id FROM events WHERE work_item_id = %s "
            "ORDER BY event_seq DESC LIMIT 1",
            [wi.work_item_id],
        )["event_id"]
        epoch.rewrite(target, "prev_global_event_hash", b"\x22" * 32)

        result = epoch.verify(target)
        assert result.mismatched_field_names == ("prev_global_event_hash",)
        assert result.applicability is Applicability.INVALID

        # Two findings, and the second is not slack: the rewritten event is the
        # chain's tail, so it becomes unreachable (one orphan) AND `event_chain_head`
        # stops matching what the walk now reaches (one head mismatch). Named
        # exactly, so a change that dropped either would fail here.
        report = epoch.instance.replay()
        assert report.chain_breaks == 2, report.to_dict()
        assert report.halted == 1, [e.detail for e in report.entries]

    def test_the_project_chain_links_across_work_items_and_the_head_tracks_the_tail(
        self, epoch
    ) -> None:
        """Discharges ``test_global_chain_links_events_across_work_items``
        (``tests/test_global_event_chain.py``).

        Ledger invariant: "one project-wide chain links events across work items;
        head pointer tracks the tail". The retired test asserted the link with the
        v5 formula and read ``event_chain_head``; both halves are here, over the
        v6 formula, and the head is checked to name the **tail event** as well as
        its hash — a head hash that matched while ``head_event_id`` pointed
        elsewhere would be a silently forked sentinel.
        """

        first, second = uuid.uuid4(), uuid.uuid4()
        one = epoch.append(entity_id=first, transition="created")
        two = epoch.append(entity_id=second, transition="created")

        envelope = epoch.envelope(two.event_id)
        assert envelope["chain"]["previous_project_event_hash"] == one.event_hash_text
        # Different entities, so the entity link must be null on the second.
        assert envelope["chain"]["previous_entity_event_hash"] is None
        assert bytes(epoch.row(two.event_id)["prev_global_event_hash"]) == (
            compute_v6_event_hash(one.canonical_envelope, one.signature)
        )

        head = epoch.fetchone(
            "SELECT head_hash, head_event_id FROM event_chain_head WHERE id = TRUE"
        )
        assert bytes(head["head_hash"]) == compute_v6_event_hash(
            two.canonical_envelope, two.signature
        )
        assert head["head_event_id"] == two.event_id

    def test_the_project_chain_survives_global_seq_gaps(self, epoch) -> None:
        """Discharges ``test_global_chain_survives_global_seq_gaps``.

        Ledger invariant: "the chain links by hash, immune to ``global_seq``
        gaps". Order and completeness come from the hash links **only** (§4.1),
        so punching a gap into ``global_seq`` — and inverting its order relative
        to the chain — must leave replay clean.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "seq gaps"},
        )
        assert wi is not None
        epoch.instance.transition(
            wi.work_item_id, "start", WORKER, actor_kind="agent", actor_metadata=AGENT_ROLE
        )
        assert epoch.instance.replay().chain_breaks == 0

        # A gap AND an inversion: multiplying by -1 and offsetting reverses the
        # ordering of every event, so a walk that sorted by global_seq would see
        # the chain backwards rather than merely sparsely.
        epoch.sql("UPDATE events SET global_seq = 1000000 - global_seq * 7")
        seqs = [
            r["global_seq"]
            for r in epoch.fetchall("SELECT global_seq FROM events ORDER BY global_seq")
        ]
        assert len(seqs) == len(set(seqs))
        assert max(seqs) - min(seqs) > len(seqs), "the gap must be real"

        report = epoch.instance.replay()
        assert report.chain_breaks == 0, report.to_dict()
        assert report.halted == 0, [e.detail for e in report.entries]
        assert report.replayed_drift == 0

    def test_a_forged_project_chain_link_is_reported_as_an_orphan_chain_break(
        self, epoch
    ) -> None:
        """Discharges ``test_hash_walk_detects_orphan``
        (``tests/test_plan024_global_chain.py::TestPlan024VerifierHashWalk``).

        Ledger invariant: "a forged project-chain row link halts verification and
        is reported as an orphan chain break". Forging the link on a **middle**
        event detaches it and everything behind it from the genesis root, so the
        walk reaches fewer events than exist — which is the orphan finding, not a
        broken-link finding.
        """

        entity = uuid.uuid4()
        epoch.append(entity_id=entity, transition="created")
        middle = epoch.append(entity_id=entity, transition="updated")
        epoch.append(entity_id=entity, transition="updated")

        total = epoch.fetchone("SELECT count(*) AS c FROM events")["c"]
        epoch.rewrite(middle.event_id, "prev_global_event_hash", b"\x33" * 32)

        result = epoch.verify(middle.event_id)
        assert result.applicability is Applicability.INVALID
        assert "prev_global_event_hash" in result.mismatched_field_names

        # The exact orphan count, not ">= 1": the walk reaches genesis and
        # everything up to the forged event's predecessor, and reports every event
        # behind the forgery as unreachable. An off-by-one here would mean the walk
        # was following something other than the links.
        reachable = _reachable_from_genesis(epoch)
        assert reachable == total - 2, (
            f"the forgery must detach exactly the forged event and its successor "
            f"({reachable} reachable of {total})"
        )
        breaks, tail = _walk_project_chain(epoch)
        assert breaks == total - reachable == 2
        assert tail is not None

        # replay() reports one MORE finding than the bare walk, and the extra one
        # is not slack: the walk's tail is now the forged event's predecessor while
        # `event_chain_head` still names the real tail, which `_replay` counts as a
        # head mismatch. Naming the exact total keeps that third finding from being
        # silently traded away by a `>=`.
        report = epoch.instance.replay()
        assert report.chain_breaks == 3, report.to_dict()

    def test_corrupting_the_genesis_link_leaves_no_root_and_orphans_everything(
        self, epoch
    ) -> None:
        """Discharges ``TestPlan024VerifierHashWalk::test_hash_walk_no_genesis_reports_orphans``.

        Ledger invariant: "corrupting the genesis link leaves no root and every
        event is reported orphaned". v6 makes this sharper than v5 did: genesis is
        a **signed claim**, so a store with no reachable root fails verification
        loudly — the genesis row itself becomes ``INVALID`` on the very column
        that was supposed to prove it was the root.
        """

        epoch.append()
        total = epoch.fetchone("SELECT count(*) AS c FROM events")["c"]
        assert total >= 3

        # Genesis is the only event with a NULL project link. Giving it one leaves
        # the store with no root at all.
        genesis_id = epoch.genesis.event_id
        assert epoch.row(genesis_id)["prev_global_event_hash"] is None
        epoch.rewrite(genesis_id, "prev_global_event_hash", b"\x44" * 32)

        result = epoch.verify(genesis_id)
        assert result.applicability is Applicability.INVALID
        assert "prev_global_event_hash" in result.mismatched_field_names

        breaks, tail = _walk_project_chain(epoch)
        assert tail is None, "there must be no reachable chain tail"
        assert breaks == total, (
            "with no genesis every event is an orphan; "
            f"got {breaks} findings for {total} events"
        )
        # Exactly `total`, not more: with no root there is no tail, so the
        # head-mismatch check `_replay` runs after the walk cannot fire and every
        # finding is an orphan.
        report = epoch.instance.replay()
        assert report.chain_breaks == total, report.to_dict()

    def test_concurrent_appends_serialize_onto_one_unbroken_project_chain(
        self, epoch
    ) -> None:
        """Discharges ``test_concurrent_raw_appends_replay_clean``
        (``TestPlan024ConcurrentGlobalChain``).

        Ledger invariant: "concurrent raw appends produce an unbroken project
        chain". The retired test walked the chain with a local helper that
        hardcoded the v5 formula; the walk here uses
        ``_replay._verify_global_hash_chain``, the production walk, so the
        counterpart cannot pass against a formula the product does not use.

        The serialization itself is the ``event_chain_head`` ``FOR UPDATE``
        sentinel, which ``append_v6_event`` takes before it signs.
        """

        threads = 4
        per_thread = 3
        errors: list[BaseException] = []
        barrier = threading.Barrier(threads)

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=30)
                principal = ACTOR_PRINCIPALS[index % len(ACTOR_PRINCIPALS)]
                for _ in range(per_thread):
                    epoch.append(
                        entity_id=uuid.uuid4(),
                        transition="created",
                        actor_id=principal,
                        actor_kind=_ACTOR_KINDS[principal.split(":", 1)[0]],
                        payload={"thread": index},
                    )
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        for thread in pool:
            thread.start()
        for thread in pool:
            thread.join(timeout=120)

        assert errors == [], errors
        written = epoch.fetchone(
            "SELECT count(*) AS c FROM events WHERE transition = 'created'"
        )["c"]
        assert written == threads * per_thread

        breaks, tail = _walk_project_chain(epoch)
        assert breaks == 0, "concurrent appends must not fork the project chain"
        assert tail is not None
        head = epoch.fetchone(
            "SELECT head_event_id FROM event_chain_head WHERE id = TRUE"
        )
        assert tail["event_id"] == head["head_event_id"]
        assert epoch.instance.replay().chain_breaks == 0

    def test_global_seq_order_matches_chain_order_under_cache_one(self, epoch) -> None:
        """Discharges ``test_global_seq_matches_chain_order_with_cache1``
        (``TestPlan024VerifierHashWalk``).

        Ledger invariant, explicitly **operational** rather than evidentiary:
        with ``events_global_seq_seq`` at ``CACHE 1`` (migration 034),
        ``global_seq`` order agrees with chain-link order. Nothing depends on it —
        the walk is by hash — but an operator reading ``ORDER BY global_seq``
        should not be silently reading a different order, so the agreement is
        pinned, together with the sequence setting it rests on.
        """

        cache = epoch.fetchone(
            "SELECT cache_size FROM pg_sequences "
            "WHERE sequencename = 'events_global_seq_seq' "
            "AND schemaname = current_schema()"
        )
        assert cache is not None and cache["cache_size"] == 1, cache

        threads = 4
        errors: list[BaseException] = []
        barrier = threading.Barrier(threads)

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=30)
                for _ in range(2):
                    epoch.append(entity_id=uuid.uuid4(), payload={"thread": index})
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        for thread in pool:
            thread.start()
        for thread in pool:
            thread.join(timeout=120)
        assert errors == [], errors

        chain_order = _chain_order(epoch)
        seq_order = [
            r["event_id"]
            for r in epoch.fetchall("SELECT event_id FROM events ORDER BY global_seq")
        ]
        assert chain_order == seq_order


def _event_rows(epoch: _Epoch) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in epoch.fetchall(
            "SELECT event_id, global_seq, prev_global_event_hash, canonical_envelope, "
            "signature FROM events ORDER BY global_seq"
        )
    ]


def _walk_project_chain(epoch: _Epoch) -> tuple[int, dict[str, Any] | None]:
    """The production project-chain walk, over the store's real rows.

    Reusing ``_replay._verify_global_hash_chain`` rather than re-deriving it is
    the point of the counterpart: the retired original hardcoded the v5 hash
    formula in its own helper, and a helper is exactly where a formula stops
    being the product's.
    """

    from regista._replay import _verify_global_hash_chain

    return _verify_global_hash_chain(_event_rows(epoch))


def _reachable_from_genesis(epoch: _Epoch) -> int:
    from regista._replay import _event_head_hash

    rows = _event_rows(epoch)
    by_prev: dict[bytes, dict[str, Any]] = {}
    root: dict[str, Any] | None = None
    for row in rows:
        if row["prev_global_event_hash"] is None:
            root = row
        else:
            by_prev[bytes(row["prev_global_event_hash"])] = row
    count = 0
    current = root
    while current is not None:
        count += 1
        head = _event_head_hash(current)
        if head is None:
            break
        current = by_prev.get(head)
    return count


def _chain_order(epoch: _Epoch) -> list[Any]:
    """Event ids in project-chain order, following the signed links only."""

    from regista._replay import _event_head_hash

    rows = _event_rows(epoch)
    by_prev: dict[bytes, dict[str, Any]] = {}
    root: dict[str, Any] | None = None
    for row in rows:
        if row["prev_global_event_hash"] is None:
            assert root is None, "more than one genesis event"
            root = row
        else:
            by_prev[bytes(row["prev_global_event_hash"])] = row
    order: list[Any] = []
    current = root
    while current is not None:
        order.append(current["event_id"])
        head = _event_head_hash(current)
        current = by_prev.get(head) if head is not None else None
    assert len(order) == len(rows), "the walk did not reach every event"
    return order


# ---------------------------------------------------------------------------
# Cluster 5 — key lifecycle under the v6 trust log (P2.2)
# ---------------------------------------------------------------------------


def _rotatable_keyset(tmp_path: Path) -> tuple[V6TestKeyset, V6TestKey, V6TestKey]:
    """A keyset carrying **two** actor keys for ``agent:worker``.

    ``make_v6_keyset`` writes one key per principal, which is the right default
    (a shared key is what v6 refuses) but leaves no way to express a lifecycle.
    Here the *second* key is the one a status-blind ``select_signing_key_id``
    would pick — ``_latest_active_key_for`` takes the LAST asymmetric candidate —
    so a test that gets the first key back has genuinely exercised the status
    filter rather than benefited from ordering luck.
    """

    import base64

    from nacl.signing import SigningKey

    keyset = make_v6_keyset(tmp_path)
    active = keyset.key_for(WORKER)

    signing_key = SigningKey.generate()
    deprecated = V6TestKey(
        principal_id=WORKER,
        key_id="pk_deprecated_worker",
        seed=bytes(signing_key),
        public_key=bytes(signing_key.verify_key),
    )

    document = json.loads(Path(keyset.path).read_text(encoding="utf-8"))
    document["keys"].append(
        {
            "key_id": deprecated.key_id,
            "scheme": "ed25519",
            "alg": "Ed25519",
            "secret": base64.b64encode(deprecated.seed).decode("ascii"),
            "encoding": "base64",
            "public_key": deprecated.public_key_b64,
            "principal_id": WORKER,
            "role": "actor",
            "status": "deprecated",
        }
    )
    Path(keyset.path).write_text(json.dumps(document, indent=2), encoding="utf-8")
    return keyset, active, deprecated


class TestCluster5KeyLifecycle:
    """Active-key selection and rotation-clean replay, under the v6 key lifecycle.

    Both are asserted **project-locally**: the acceptance events these tests rely
    on are ``principal_key_accepted`` / ``principal_key_acceptance_revoked``
    events on the project chain, which ``append_v6_event`` writes today. The
    *trust-log* half of the lifecycle (enrolment and rotation writes) has no
    production append path — that is WI-301, and nothing here claims it.
    """

    @pytest.fixture
    def rotation_epoch(self, tmp_path: Path):
        from regista._testing import drop_project_schema

        keyset, active, deprecated = _rotatable_keyset(tmp_path)
        project, instance, genesis = _open_epoch(DSN, keyset, "rot")
        try:
            instance.register_workflow_file(WORKFLOW_PATH)
            yield _Epoch(instance, keyset, genesis), active, deprecated
        finally:
            instance.close()
            drop_project_schema(DSN, project)

    def test_the_writer_signs_with_the_active_key_not_a_deprecated_one(
        self, rotation_epoch
    ) -> None:
        """Discharges ``test_events_signed_with_active_key_scheme``
        (``tests/test_signing_ed25519.py::TestEd25519KeyRotation``).

        Ledger invariant: "new events are signed with the active key's scheme,
        not a deprecated key's". The HMAC half of the original dies with v5 (the
        v6 writer refuses any non-Ed25519 key outright), so what survives is the
        **selection**: with a deprecated key present for the same principal — and
        listed where a status-blind selector would pick it — the writer must sign
        with the active key, and the envelope's ``scheme_id`` must equal the
        trusted key's scheme.
        """

        epoch, active, deprecated = rotation_epoch
        appended = epoch.append(payload={"note": "active key"})

        envelope = epoch.envelope(appended.event_id)
        assert envelope["signing"]["key_id"] == active.key_id
        assert envelope["signing"]["key_id"] != deprecated.key_id
        assert envelope["signing"]["scheme_id"] == "ed25519"
        assert epoch.row(appended.event_id)["key_id"] == active.key_id

        # scheme_id equality with the TRUSTED key, not merely with a literal:
        # the resolved key's own scheme is what the read path must dispatch on.
        trusted = KeySetResolver(epoch.instance._keys).resolve(active.key_id)
        assert trusted is not None
        assert trusted.scheme_id == envelope["signing"]["scheme_id"]
        assert trusted.principal_id == WORKER

        result = epoch.verify(appended.event_id)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert "scheme_id" in result.authenticated_fields

    def test_replay_is_clean_across_a_key_rotation(self, rotation_epoch) -> None:
        """Discharges ``TestEd25519KeyRotation::test_replay_handles_mixed_schemes``.

        Ledger invariant: "replay stays clean across key rotation". The original's
        mixed-*scheme* premise (a deprecated HMAC key coexisting with an active
        Ed25519 one) dies with v5 — HMAC is read-only history in the clean epoch.
        What survives is rotation itself: events signed under the pre-rotation key
        and events signed under the post-rotation key are in one chain, and replay
        verifies **all** of them.

        The rotation is a real one: the keyset file flips which key is active, a
        fresh ``KeySet`` picks the new one up, and the project chain gets a
        standalone ``principal_key_accepted`` for it — without that acceptance
        ``resolve_key_binding_anchor`` refuses the append, which is the property
        that makes this a lifecycle test rather than a file-editing test.
        """

        from regista._keys import KeySet

        epoch, active, deprecated = rotation_epoch
        before = epoch.append(payload={"phase": "pre-rotation"})
        assert epoch.envelope(before.event_id)["signing"]["key_id"] == active.key_id

        # Rotate on disk: the old key becomes deprecated, the new one active.
        document = json.loads(Path(epoch.keyset.path).read_text(encoding="utf-8"))
        for entry in document["keys"]:
            if entry["key_id"] == active.key_id:
                entry["status"] = "deprecated"
            elif entry["key_id"] == deprecated.key_id:
                entry["status"] = "active"
        Path(epoch.keyset.path).write_text(
            json.dumps(document, indent=2), encoding="utf-8"
        )
        rotated_keys = KeySet(epoch.keyset.path, poll_interval=0.0)
        assert (
            rotated_keys.resolve_signing_key(WORKER).key_id == deprecated.key_id
        ), "the rotation did not take effect"

        # The new key needs its own project-local acceptance before it may sign.
        _accept_rotated_key(epoch, rotated_keys, deprecated)

        after = epoch.append(keys=rotated_keys, payload={"phase": "post-rotation"})
        assert epoch.envelope(after.event_id)["signing"]["key_id"] == deprecated.key_id

        # Both events verify, each against the key its own envelope names.
        for event_id in (before.event_id, after.event_id):
            result = epoch.verify(event_id)
            assert result.applicability is Applicability.FULLY_AUTHENTICATED, (
                result.summary()
            )

        report = epoch.instance.replay()
        assert report.chain_breaks == 0, report.to_dict()
        assert report.replayed_drift == 0
        assert report.unverifiable == 0
        verification_halts = [
            e
            for e in report.entries
            if e.category == "halted" and "verification" in (e.detail or "").lower()
        ]
        assert verification_halts == [], verification_halts


def _accept_rotated_key(epoch: _Epoch, keys: Any, key: V6TestKey) -> Any:
    """Append the standalone ``principal_key_accepted`` for a rotated-in key.

    ``_v6_fixtures.accept_key`` resolves the accepted key through
    ``V6TestKeyset.key_for``, which is one key per principal by construction, so
    a rotation needs the payload built against the *specific* new key. Everything
    else — signed by the bootstrap principal, anchored on genesis, never on
    itself — is unchanged.
    """

    from regista._v6_writer import PRINCIPAL_KEY_ACCEPTED, read_project_identity

    rotated_view = V6TestKeyset(
        path=epoch.keyset.path,
        keys={**epoch.keyset.keys, key.principal_id: key},
    )
    with epoch.instance._mgr.transaction() as conn:
        identity = read_project_identity(conn)
    assert identity is not None
    payload = acceptance_payload(
        rotated_view,
        principal_id=key.principal_id,
        accepted_by=BOOTSTRAP_PRINCIPAL,
        accepted_by_anchor=epoch.genesis.to_dict()["event_hash"],
        project_instance_id=str(identity.project_instance_id),
        trust_domain_id=str(identity.trust_domain_id),
    )
    with epoch.instance._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            keys,
            entity_kind="principal",
            entity_id=uuid.uuid5(
                uuid.NAMESPACE_OID, "regista.principal:rotated:" + key.key_id
            ),
            transition=PRINCIPAL_KEY_ACCEPTED,
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="system",
            producer=v6_producer(),
            payload=payload,
        )


# ---------------------------------------------------------------------------
# Retained subsystem — archive_events on the v6 writer
# ---------------------------------------------------------------------------


class TestArchiveEventsOnTheV6Writer:
    """The four retained ``archive_events`` behaviours, re-covered in a v6 epoch.

    Their carry-forward said "re-cover on the v6 writer (P1.7) **once work items
    can be created in the v6 epoch**". They can now, so these are the counterparts
    — and they are ordinary retention tests, not verification tests: the only v6
    content is that the events being archived are real v6 events written through
    the funnel, and that replay stays drift-free afterwards.
    """

    @staticmethod
    def _terminal_item(epoch: _Epoch) -> Any:
        """A work item driven to the workflow's terminal state (``done``)."""

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "archivable"},
        )
        assert wi is not None
        epoch.instance.transition(
            wi.work_item_id, "start", WORKER, actor_kind="agent", actor_metadata=AGENT_ROLE
        )
        epoch.instance.transition(
            wi.work_item_id,
            "submit_review",
            WORKER,
            actor_kind="agent",
            actor_metadata=AGENT_ROLE,
        )
        epoch.instance.transition(
            wi.work_item_id,
            "approve",
            REVIEWER,
            actor_kind="human",
            actor_metadata=REVIEWER_ROLE,
        )
        current = epoch.fetchone(
            "SELECT current_state FROM work_items_current WHERE work_item_id = %s",
            [wi.work_item_id],
        )
        assert current["current_state"] == "done", current
        return wi

    @staticmethod
    def _cutoff(epoch: _Epoch) -> Any:
        row = epoch.fetchone("SELECT max(timestamp) AS t FROM events")
        return row["t"] + timedelta(seconds=1)

    def test_archiving_a_terminal_item_moves_its_events_and_leaves_replay_clean(
        self, epoch
    ) -> None:
        """Discharges ``tests/test_webhooks_archive.py::TestArchiveEvents::test_archive_actual``.

        Ledger invariant: "archival moves a terminal item's events to
        ``events_archive`` and removes the projection row, leaving replay
        drift-free".
        """

        wi = self._terminal_item(epoch)
        before = epoch.fetchone(
            "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
            [wi.work_item_id],
        )["c"]
        assert before >= 4

        moved = epoch.instance.archive_events(before_timestamp=self._cutoff(epoch))
        assert moved == before

        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == 0
        )
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM events_archive WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == before
        )
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == 0
        )
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM work_items_archive WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == 1
        )

        report = epoch.instance.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0, [e.detail for e in report.entries]

        # MEASURED, and pinned rather than left silent: archiving the chain's TAIL
        # leaves `event_chain_head` naming an event the live table no longer has, so
        # `_replay` reports exactly one chain break — the head mismatch. That is the
        # "chain hole that is an artifact of the read, not of the data"
        # `docs/0.6.0/CUTOVER-CLASSIFICATION.md` §5.3 names, and it arrives as a bare
        # counter with no report entry explaining it. Asserting the exact number is
        # the strict reading: if archival ever starts producing MORE findings (a
        # mid-chain archive orphans every later event), this fails instead of being
        # absorbed by a `>=`.
        assert report.chain_breaks == 1, report.to_dict()
        assert [e.detail for e in report.entries if e.chain_breaks] == []

    def test_a_dry_run_counts_archivable_events_without_writing(self, epoch) -> None:
        """Discharges ``TestArchiveEvents::test_archive_dry_run_with_events``."""

        wi = self._terminal_item(epoch)
        live = epoch.fetchone(
            "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
            [wi.work_item_id],
        )["c"]

        counted = epoch.instance.archive_events(
            before_timestamp=self._cutoff(epoch), dry_run=True
        )
        assert counted == live
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == live
        )
        assert epoch.fetchone("SELECT count(*) AS c FROM events_archive")["c"] == 0
        assert epoch.fetchone("SELECT count(*) AS c FROM work_items_archive")["c"] == 0

    def test_re_running_the_archive_over_the_same_cutoff_archives_nothing_new(
        self, epoch
    ) -> None:
        """Discharges ``TestArchiveEvents::test_archive_idempotent``."""

        wi = self._terminal_item(epoch)
        cutoff = self._cutoff(epoch)
        first = epoch.instance.archive_events(before_timestamp=cutoff)
        assert first >= 4

        second = epoch.instance.archive_events(before_timestamp=cutoff)
        assert second == 0
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM events_archive WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == first
        )

    def test_a_dormant_non_terminal_item_is_never_archived(self, epoch) -> None:
        """Discharges ``TestArchiveEvents::test_archive_skips_non_terminal_dormant_item``.

        Ledger invariant, and the guardrail's whole point: dormancy alone is not
        archivability. An item parked in a non-terminal state stays in the live
        log however old its only event is.
        """

        wi, _event = epoch.instance.create_work_item(
            WORKFLOW_NAME,
            "feature",
            WORKER,
            actor_kind="agent",
            custom_fields={"title": "dormant"},
        )
        assert wi is not None
        current = epoch.fetchone(
            "SELECT current_state FROM work_items_current WHERE work_item_id = %s",
            [wi.work_item_id],
        )
        assert current["current_state"] == "new"

        live = epoch.fetchone(
            "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
            [wi.work_item_id],
        )["c"]
        assert live >= 1

        counted = epoch.instance.archive_events(before_timestamp=self._cutoff(epoch))
        assert counted == 0
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM events WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == live
        )
        assert (
            epoch.fetchone(
                "SELECT count(*) AS c FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            )["c"]
            == 1
        )


# ---------------------------------------------------------------------------
# The ledger mapping, machine-checked
# ---------------------------------------------------------------------------

LEDGER_PATH = Path(__file__).resolve().parents[1] / "tests" / "retired_tests_ledger.json"

#: The files a WI-289 cluster-1/2/3/5 pointer is allowed to name. A pointer into
#: any other module is a mapping nobody will maintain.
COUNTERPART_MODULES = {
    "tests/test_wi289_v6_counterparts.py",
    "tests/test_p17_v6_writer.py",
    "tests/test_p17_v6_verifier_boundary.py",
}


class TestLedgerMapping:
    """Cluster 6's self-check, for clusters 1/2/3/5.

    ``covered_by`` is a string in a JSON file: nothing stops it naming a test
    that was renamed away, and a coverage-owed ledger whose pointers do not
    resolve is worse than one with no pointers, because it reads as discharged.
    """

    def test_every_entry_this_file_discharges_names_a_test_that_exists(self) -> None:
        import importlib

        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        entries = [
            entry
            for entry in ledger["entries"]
            if entry.get("work_item") == "WI-289"
            and entry.get("covered_in", "").startswith("P1.7")
        ]
        assert entries, "no WI-289 entry is recorded as discharged by P1.7"

        for entry in entries:
            assert entry["disposition"] == "coverage_owed", entry["node_id"]
            pointer = entry["covered_by"]
            module_path, _, rest = pointer.partition("::")
            assert module_path in COUNTERPART_MODULES, pointer
            class_name, _, method = rest.partition("::")
            assert method, f"{pointer}: a class alone is not a counterpart"

            module_name = module_path.removesuffix(".py").replace("/", ".")
            module = importlib.import_module(module_name)
            owner = getattr(module, class_name, None)
            assert owner is not None, f"{pointer}: {class_name} does not exist"
            assert callable(getattr(owner, method, None)), pointer

    def test_no_cluster_4_or_cluster_6_entry_was_claimed_here(self) -> None:
        """The scope boundary, asserted rather than trusted.

        Cluster 4 (``tests/test_bundle.py``, bundle v3) is owed to P3.3 and
        cluster 6 to WI-287. Claiming one of those here would make the ledger say
        P1.7 discharged coverage it did not write.
        """

        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        claimed = [
            entry["node_id"]
            for entry in ledger["entries"]
            if entry.get("covered_in", "").startswith("P1.7")
        ]
        assert not [n for n in claimed if n.startswith("tests/test_bundle.py")]
        assert not [
            n
            for n in claimed
            if n
            in {
                "tests/test_global_event_chain.py::test_bc300_in_memory_replay_detects_global_chain_tamper",
                "tests/test_hash_chain.py::TestBC233HashChainInMemory::test_multi_event_chain",
                "tests/test_hash_chain.py::TestBC233HashChainInMemory::test_second_event_includes_prev_hash",
                "tests/test_hash_chain.py::TestBC311ReplayChainFields::test_replay_succeeds_with_missing_envelope_in_memory",
                "tests/test_wi267_row_authentication.py::TestInMemoryBackendParity::test_in_memory_envelope_deletion_halts_like_postgres",
                "tests/test_wi267_row_authentication.py::TestInMemoryBackendParity::test_in_memory_row_rewrite_halts_replay",
            }
        ]
