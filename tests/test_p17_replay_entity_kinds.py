"""Replay's contract for NON-work-item entity groups (P1.7 Phase 3, Finding 14).

A v6 epoch's chain necessarily carries ``project``, ``principal`` and ``workflow``
entity events beside its work items. Before this file, ``replay()`` folded every
such group into the generic ``warnings`` counter — so a *healthy* clean-epoch
replay reported seven warnings, and every migrated fixture asserting a clean
report would have had to either fail or weaken its assertion.

The corrected contract, and what each assertion here falsifies:

* an entity kind in the **CLOSED** seven-value registry (``V6-ENVELOPE.md`` §1.2)
  other than ``work_item`` is a spec-legal chain member: no halt, no warning,
  counted by name in ``ReplayReport.non_work_item_groups_verified``;
* an entity kind **outside** that registry halts, fail-closed, exactly as an
  orphaned work item does — the tolerance above is granted to five named values,
  not to "anything that is not a work item";
* their bytes stay inside the global hash-chain verification, which is the
  substance behind the word "verified" in the field's name.

Both backends, because the two may not disagree about whether a healthy v6 chain
has findings.

NOTES-P17 Finding 14 recorded this as "every non-work-item entity group is filed
as an orphan HALT". Measured on this branch, that was wrong: ``halted`` was 0 and
the groups surfaced as ``warnings`` (``_handle_orphan_group`` has had a
non-work-item early return since WI-266). The corrected semantics are the same
either way — a healthy chain must report neither — so the finding's *remedy*
stands even though its diagnosis did not.
"""

from __future__ import annotations

import os
import uuid

import pytest

from regista._genesis import _V6_ENTITY_KINDS as _GENESIS_KINDS
from regista._v6_writer import _V6_ENTITY_KINDS as _WRITER_KINDS
from regista._verification import V6_ENTITY_KINDS
from tests._v6_fixtures import (
    ACTOR_PRINCIPALS,
    make_v6_keyset,
    open_v6_epoch,
)

DSN = os.environ.get("REGISTA_TEST_DSN", "")
WORKFLOW_PATH = "tests/test_workflow.yaml"

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")


def test_the_closed_registry_is_one_registry() -> None:
    """Three modules used to hand-copy the seven values. A replay that halts on
    "not in the registry" is only as trustworthy as the registry being singular —
    two registries that drift make the halt a coin toss."""

    assert _GENESIS_KINDS is V6_ENTITY_KINDS
    assert _WRITER_KINDS is V6_ENTITY_KINDS
    assert V6_ENTITY_KINDS == {
        "work_item",
        "project",
        "principal",
        "trust_domain",
        "project_instance",
        "workflow",
        "spec",
    }


class TestPostgresEntityGroups:
    @pytest.fixture
    def epoch(self, tmp_path_factory):
        from regista import Regista
        from regista._testing import drop_project_schema

        project = "p17_ek_" + uuid.uuid4().hex[:8]
        keyset = make_v6_keyset(tmp_path_factory.mktemp("ek_keys"))
        instance = Regista.create_project(DSN, project, keyset.path)
        try:
            open_v6_epoch(instance, keyset, principals=ACTOR_PRINCIPALS)
            instance.register_workflow_file(WORKFLOW_PATH)
            instance.create_work_item(
                "test_workflow",
                "feature",
                "agent:worker",
                actor_kind="agent",
                custom_fields={"title": "entity kinds"},
            )
            yield instance
        finally:
            instance.close()
            drop_project_schema(DSN, project)

    @staticmethod
    def _non_work_item_group_count(instance) -> int:
        with instance._mgr.transaction() as conn:
            rows = conn.execute(
                "SELECT DISTINCT entity_kind, entity_id FROM events "
                "WHERE entity_kind <> 'work_item'"
            ).fetchall()
        return len(rows)

    def test_a_healthy_v6_epoch_replays_with_no_halt_and_a_named_count(
        self, epoch
    ) -> None:
        """The assertion Phase 3's fixture migration rests on: a correctly opened
        epoch, with the entity events the spec requires, is CLEAN."""

        expected = self._non_work_item_group_count(epoch)
        assert expected >= 3, "a v6 epoch carries project, principal and workflow groups"

        report = epoch.replay()

        assert report.halted == 0, [e.detail for e in report.entries]
        assert report.replayed_ok >= 1
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0
        # Not folded into `warnings`: a healthy chain must not warn. This is the
        # half that would silently regress if someone reverted the split.
        assert report.warnings == 0
        assert report.non_work_item_groups_verified == expected
        # And it is reported, not merely counted in memory.
        assert report.to_dict()["non_work_item_groups_verified"] == expected

    def test_a_principal_group_alone_is_not_a_finding(self, epoch) -> None:
        """The narrow claim, isolated from the project and workflow groups: the
        acceptance events `open_v6_epoch` writes are `principal` entities, and
        their presence is the ordinary case."""

        with epoch._mgr.transaction() as conn:
            principal_groups = conn.execute(
                "SELECT DISTINCT entity_id FROM events WHERE entity_kind = 'principal'"
            ).fetchall()
        assert len(principal_groups) == len(
            [p for p in ACTOR_PRINCIPALS if p != "service:regista-bootstrap"]
        ) or len(principal_groups) >= 1

        report = epoch.replay()
        halted_details = [e.detail for e in report.entries if e.category == "halted"]
        assert halted_details == []
        assert report.non_work_item_groups_verified >= len(principal_groups)

    def test_an_entity_kind_outside_the_closed_registry_still_halts(
        self, epoch
    ) -> None:
        """Fail-closed. `entity_kind` is a plain TEXT column with no CHECK
        constraint, so a foreign kind is a state the database can hold; the five
        legal non-work-item kinds get tolerance, "not a work item" does not."""

        clean = epoch.replay()
        assert clean.halted == 0

        with epoch._mgr.transaction() as conn:
            victim = conn.execute(
                "SELECT entity_id FROM events WHERE entity_kind = 'principal' LIMIT 1"
            ).fetchone()
            assert victim is not None
            conn.execute(
                "UPDATE events SET entity_kind = 'not_a_registered_kind' "
                "WHERE entity_id = %s",
                [victim["entity_id"]],
            )

        report = epoch.replay()
        assert report.halted == 1, [e.detail for e in report.entries]
        assert report.non_work_item_groups_verified == (
            clean.non_work_item_groups_verified - 1
        )
        detail = next(e.detail for e in report.entries if e.category == "halted")
        assert detail is not None
        assert "closed v6 registry" in detail
        assert "not_a_registered_kind" in detail

    def test_the_mixed_kind_branch_is_unreachable_on_postgres_by_construction(
        self
    ) -> None:
        """Stated as an absence so nobody reads its in-memory counterpart as
        Postgres coverage.

        The Postgres group loop keys on ``(entity_kind, entity_id)`` — that pair
        IS the group key — so a group handed to ``_handle_orphan_group`` carries
        exactly one entity kind and the mixed branch cannot be reached from this
        backend. It is kept rather than deleted because the in-memory backend
        groups by ``work_item_id`` alone, where the shape IS reachable and IS
        tested (``TestInMemoryEntityGroups::test_a_mixed_kind_orphan_group_halts``),
        and because one decision procedure written twice must be written the same
        way both times."""

        import inspect

        from regista import _replay

        source = inspect.getsource(_replay._replay_inner)
        assert 'key = (evt["entity_kind"], evt["entity_id"])' in source, (
            "the group key is what makes the mixed branch unreachable here; if "
            "grouping changed, this test's claim is stale and the branch needs "
            "Postgres coverage"
        )

    def test_a_rewritten_principal_event_is_a_chain_break_not_a_silent_pass(
        self, epoch
    ) -> None:
        """What "verified" in the field name actually covers. These groups are
        skipped for the PROJECTION rebuild only — their bytes are still in the
        global hash-chain verification, so rewriting one is a finding.

        The rewrite is to ``canonical_envelope``, which is what the chain link
        commits to. (A ``payload``-column-only rewrite is deliberately NOT a chain
        break — the column is a duplicate of the signed bytes and reconciliation,
        not the chain, is what catches it. Measured: it reports zero chain breaks,
        which is correct and is why this test does not use it.)"""

        with epoch._mgr.transaction() as conn:
            before = conn.execute(
                "SELECT event_id, canonical_envelope FROM events "
                "WHERE entity_kind = 'principal' LIMIT 1"
            ).fetchone()
            assert before is not None
            tampered = bytearray(bytes(before["canonical_envelope"]))
            # Flip one byte inside the JSON body, keeping the length so nothing
            # but the hash changes.
            tampered[-2] = tampered[-2] ^ 0x01
            conn.execute(
                "UPDATE events SET canonical_envelope = %s WHERE event_id = %s",
                [bytes(tampered), before["event_id"]],
            )

        report = epoch.replay()
        assert report.chain_breaks > 0, report.to_dict()


class TestInMemoryEntityGroups:
    """Backend parity. WI-287 made the in-memory backend able to open a real
    epoch, so this is the same claim over the same decision procedure."""

    @pytest.fixture
    def epoch(self, tmp_path_factory):
        from regista.testing import InMemoryRegista

        keyset = make_v6_keyset(tmp_path_factory.mktemp("ek_mem_keys"))
        instance = InMemoryRegista(project="p17_ek_mem", hmac_key_path=keyset.path)
        open_v6_epoch(instance, keyset, principals=ACTOR_PRINCIPALS)
        yield instance, keyset

    def test_a_healthy_in_memory_epoch_reports_the_named_count_not_warnings(
        self, epoch
    ) -> None:
        instance, _keyset = epoch
        store = instance._store
        expected = len(
            {
                (e.entity_kind, e.work_item_id)
                for evts in store.events.values()
                for e in evts
                if e.entity_kind != "work_item"
            }
        )
        assert expected >= 3

        report = instance.replay()

        assert report.halted == 0
        assert report.non_work_item_groups_verified == expected
        # `warnings` may be non-zero for an unrelated in-memory reason only when
        # principal binding was requested; it was not.
        assert report.warnings == 0

    def test_the_in_memory_global_chain_verifies_under_the_v6_hash_formula(
        self, epoch
    ) -> None:
        """Both in-memory chain walks hardcoded the v1-v5
        ``sha256(envelope || signature)`` formula, so no v6 event was reachable
        from genesis and a HEALTHY epoch reported one chain break per post-genesis
        event. The parity claim (WI-287) was measurably false for the chain, and
        the assertion nobody had written is this one.

        Asserted at the primitive as well as through the report, per NOTES-P17
        finding 15: a behavioural assertion alone is satisfied by a chain check
        that checks nothing."""

        from regista._in_memory_replay import _head_hash
        from regista._signing import compute_v6_event_hash

        instance, _keyset = epoch
        report = instance.replay()
        assert report.chain_breaks == 0, report.to_dict()

        v6_events = [
            e
            for evts in instance._store.events.values()
            for e in evts
            if e.canonical_envelope is not None and e.signature is not None
        ]
        assert v6_events, "the epoch must have signed v6 events to make this claim"
        for evt in v6_events:
            assert _head_hash(evt) == compute_v6_event_hash(
                bytes(evt.canonical_envelope), bytes(evt.signature)
            )

    def test_an_unknown_entity_kind_halts_in_memory_too(self, epoch) -> None:
        import dataclasses

        instance, _keyset = epoch
        store = instance._store
        clean = instance.replay()
        assert clean.halted == 0

        target = next(
            (key, evts)
            for key, evts in store.events.items()
            if any(e.entity_kind == "principal" for e in evts)
        )
        key, evts = target
        store.events[key] = [
            dataclasses.replace(e, entity_kind="not_a_registered_kind") for e in evts
        ]

        report = instance.replay()
        assert report.halted == 1
        assert report.non_work_item_groups_verified == (
            clean.non_work_item_groups_verified - 1
        )

    def test_a_mixed_kind_orphan_group_halts(self, epoch) -> None:
        """The branch the Postgres backend cannot reach. In memory the groups are
        keyed by ``work_item_id`` alone, so one id CAN carry two kinds — and when
        it does, the group is neither a work item to rebuild nor a foreign entity
        to pass over. Halt rather than pick one."""

        import dataclasses

        instance, _keyset = epoch
        store = instance._store

        key, evts = next(
            (key, evts)
            for key, evts in store.events.items()
            if any(e.entity_kind == "principal" for e in evts)
        )
        # A second event under the SAME in-memory group key, carrying a
        # work_item kind. The group is an orphan either way (no projection row
        # exists for a principal entity id), so this reaches the mixed branch.
        store.events[key] = [
            *evts,
            dataclasses.replace(evts[0], entity_kind="work_item", event_seq=2),
        ]

        report = instance.replay()
        assert report.halted == 1, report.to_dict()
