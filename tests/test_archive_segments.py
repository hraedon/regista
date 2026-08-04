from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from regista import Regista
from regista._testing import drop_project_schema, raw_transaction

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"


def _drive_to_terminal(sub, wi):
    agent = {"role": "agent"}
    reviewer = {"role": "reviewer"}
    sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata=agent)
    sub.transition(wi.work_item_id, "submit_review", "agent-1", actor_metadata=agent)
    sub.transition(wi.work_item_id, "approve", "reviewer-1", actor_metadata=reviewer)


@pytest.fixture(scope="module")
def project():
    name = f"seg_test_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture(scope="module")
def sub(project):
    s = Regista.create_project(DSN, project, KEY_PATH)
    with open(WORKFLOW_PATH) as f:
        s.register_workflow(f.read())
    yield s
    s.close()


def _count_segments(sub) -> int:
    with raw_transaction(sub) as conn:
        row = conn.execute("SELECT count(*) AS c FROM event_segments").fetchone()
    return row["c"]


def _count_seal_events(sub) -> int:
    with raw_transaction(sub) as conn:
        row = conn.execute(
            "SELECT count(*) AS c FROM events WHERE entity_kind = 'segment'"
        ).fetchone()
    return row["c"]


class TestSealSegment:
    def test_seal_creates_segment_and_signed_event(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "seal-test",
            custom_fields={"title": "seal-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before)

        assert result["event_count"] > 0
        assert result["segment_id"] is not None
        assert result["dry_run"] is False
        assert result["head_hash"] is not None
        assert result["first_global_seq"] is not None
        assert result["last_global_seq"] is not None
        assert result["seal_event_id"] is not None
        assert result["seal_signature"] is not None

        assert _count_segments(sub) >= 1
        assert _count_seal_events(sub) >= 1

    def test_verify_passes(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "verify-test",
            custom_fields={"title": "verify-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before)
        segment_id = uuid.UUID(result["segment_id"])

        verify_result = sub.archive.verify(segment_id)
        assert verify_result["verified"] is True
        assert verify_result["global_chain_ok"] is True
        assert verify_result["work_item_chain_ok"] is True
        assert verify_result["head_hash_matches"] is True
        assert verify_result["event_count"] == verify_result["expected_count"]

    def test_replay_with_sealed_segment_no_orphan_warnings(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "replay-test",
            custom_fields={"title": "replay-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        sub.archive.seal(before_timestamp=before)

        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_dry_run_writes_nothing(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "dryrun-test",
            custom_fields={"title": "dryrun-test"},
        )
        _drive_to_terminal(sub, wi)

        seg_before = _count_segments(sub)
        evt_before = _count_seal_events(sub)

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before, dry_run=True)

        assert result["dry_run"] is True
        assert result["event_count"] > 0
        assert _count_segments(sub) == seg_before
        assert _count_seal_events(sub) == evt_before

    def test_no_events_returns_count_zero(self, sub):
        result = sub.archive.seal(
            before_timestamp=datetime(2020, 1, 1, tzinfo=UTC),
        )
        assert result["event_count"] == 0
        assert result["segment_id"] is None

    def test_list_segments(self, sub):
        segments = sub.archive.list_segments()
        assert len(segments) >= 1
        for seg in segments:
            assert "segment_id" in seg
            assert "first_global_seq" in seg
            assert "last_global_seq" in seg
            assert "head_hash" in seg
            assert "event_count" in seg
            assert "archived" in seg

    def test_list_segments_filter_archived(self, sub):
        not_archived = sub.archive.list_segments(archived=False)
        assert all(s["archived"] is False for s in not_archived)

    def test_verify_nonexistent_segment_raises(self, sub):
        from regista._errors import ErrorCode, RegistaError

        fake_id = uuid.uuid4()
        with pytest.raises(RegistaError) as exc_info:
            sub.archive.verify(fake_id)
        assert exc_info.value.code == ErrorCode.SEGMENT_NOT_FOUND

    def test_verify_reports_seal_signature(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "sig-test",
            custom_fields={"title": "sig-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before)
        segment_id = uuid.UUID(result["segment_id"])

        verify_result = sub.archive.verify(segment_id)
        assert verify_result["seal_event_verified"] is True

    def test_non_genesis_segment_verifies(self, sub):
        # Seal the first batch of events (includes genesis).
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "first-batch",
            custom_fields={"title": "first-batch"},
        )
        _drive_to_terminal(sub, wi1)
        cutoff1 = datetime.now(UTC) + timedelta(seconds=1)
        sub.archive.seal(before_timestamp=cutoff1)

        # Create more events after the first seal and seal them too.
        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "second-batch",
            custom_fields={"title": "second-batch"},
        )
        _drive_to_terminal(sub, wi2)
        cutoff2 = datetime.now(UTC) + timedelta(days=365)
        result2 = sub.archive.seal(before_timestamp=cutoff2)
        segment_id = uuid.UUID(result2["segment_id"])

        verify_result = sub.archive.verify(segment_id)
        assert verify_result["verified"] is True
        assert verify_result["global_chain_ok"] is True
        assert verify_result["head_hash_matches"] is True

    def test_replay_bridges_multiple_segments(self, sub):
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "bridge-first",
            custom_fields={"title": "bridge-first"},
        )
        _drive_to_terminal(sub, wi1)
        sub.archive.seal(before_timestamp=datetime.now(UTC) + timedelta(seconds=1))

        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "bridge-second",
            custom_fields={"title": "bridge-second"},
        )
        _drive_to_terminal(sub, wi2)
        sub.archive.seal(before_timestamp=datetime.now(UTC) + timedelta(days=365))

        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_live_work_item_not_sealed(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "live-wi",
            custom_fields={"title": "live-wi"},
        )
        sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before)

        if result.get("work_item_ids"):
            assert str(wi.work_item_id) not in result["work_item_ids"]

    def test_seal_after_work_item_becomes_terminal(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "becomes-terminal",
            custom_fields={"title": "becomes-terminal"},
        )
        sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        before1 = datetime.now(UTC) + timedelta(days=365)
        result1 = sub.archive.seal(before_timestamp=before1)
        if result1.get("work_item_ids"):
            assert str(wi.work_item_id) not in result1["work_item_ids"]

        sub.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        before2 = datetime.now(UTC) + timedelta(days=365)
        result2 = sub.archive.seal(before_timestamp=before2)

        assert result2["event_count"] > 0
        assert str(wi.work_item_id) in result2["work_item_ids"]

    def test_multi_seal_interleaved_live_and_terminal(self, sub):
        wi_a, _ = sub.create_work_item(
            "test_workflow", "feature", "interleave-a",
            custom_fields={"title": "interleave-a"},
        )
        _drive_to_terminal(sub, wi_a)

        wi_b, _ = sub.create_work_item(
            "test_workflow", "feature", "interleave-b",
            custom_fields={"title": "interleave-b"},
        )
        sub.transition(wi_b.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        cutoff1 = datetime.now(UTC) + timedelta(seconds=1)
        result1 = sub.archive.seal(before_timestamp=cutoff1)
        assert result1["event_count"] > 0
        assert str(wi_a.work_item_id) in result1["work_item_ids"]
        assert str(wi_b.work_item_id) not in result1["work_item_ids"]

        sub.transition(
            wi_b.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi_b.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        cutoff2 = datetime.now(UTC) + timedelta(days=365)
        result2 = sub.archive.seal(before_timestamp=cutoff2)
        assert result2["event_count"] > 0
        assert str(wi_b.work_item_id) in result2["work_item_ids"]

        segment_id = uuid.UUID(result2["segment_id"])
        verify_result = sub.archive.verify(segment_id)
        assert verify_result["verified"] is True
        assert verify_result["global_chain_ok"] is True
        assert verify_result["work_item_chain_ok"] is True
        assert verify_result["head_hash_matches"] is True

    def test_spanning_entity_no_bug(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "spanning-repro",
            custom_fields={"title": "spanning-repro"},
        )
        sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        cutoff1 = datetime.now(UTC) + timedelta(seconds=1)
        result1 = sub.archive.seal(before_timestamp=cutoff1)
        if result1.get("work_item_ids"):
            assert str(wi.work_item_id) not in result1["work_item_ids"]

        sub.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        cutoff2 = datetime.now(UTC) + timedelta(days=365)
        result2 = sub.archive.seal(before_timestamp=cutoff2)

        assert result2["event_count"] > 0
        assert str(wi.work_item_id) in result2["work_item_ids"]

        segment_id = uuid.UUID(result2["segment_id"])
        verify_result = sub.archive.verify(segment_id)
        assert verify_result["verified"] is True

    def test_list_segments_includes_work_item_ids(self, sub):
        segments = sub.archive.list_segments()
        assert len(segments) >= 1
        for seg in segments:
            assert "work_item_ids" in seg
            assert isinstance(seg["work_item_ids"], list)

    def test_dry_run_includes_work_item_ids(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "dryrun-wi",
            custom_fields={"title": "dryrun-wi"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        result = sub.archive.seal(before_timestamp=before, dry_run=True)

        assert result["dry_run"] is True
        assert "work_item_ids" in result
        assert str(wi.work_item_id) in result["work_item_ids"]

    def test_no_new_segment_when_all_sealed(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "quiesce-test",
            custom_fields={"title": "quiesce-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        result1 = sub.archive.seal(before_timestamp=before)
        assert result1["event_count"] > 0

        seg_before = _count_segments(sub)

        result2 = sub.archive.seal(before_timestamp=before)
        assert result2["event_count"] == 0
        assert result2["segment_id"] is None
        assert _count_segments(sub) == seg_before

    def test_verify_chain_two_segments_links_through_seal(self, sub):
        """WI-249: verify_archive_chain must link 2+ segments through the
        inter-segment seal event, not assume strict adjacency."""
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "chain-first-seg",
            custom_fields={"title": "chain-first-seg"},
        )
        _drive_to_terminal(sub, wi1)
        sub.archive.seal(
            before_timestamp=datetime.now(UTC) + timedelta(seconds=1)
        )

        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "chain-second-seg",
            custom_fields={"title": "chain-second-seg"},
        )
        _drive_to_terminal(sub, wi2)
        sub.archive.seal(
            before_timestamp=datetime.now(UTC) + timedelta(days=365)
        )

        result = sub.verify_archive_chain()
        # The project is shared across the class (module-scoped fixture), so
        # earlier tests' sealed segments accumulate; assert the property that
        # matters — the full multi-segment chain verifies through each
        # inter-segment seal event, with no chain breaks.
        assert result["segment_count"] >= 2
        assert result["verified"], result["chain_breaks"]
        assert len(result["chain_breaks"]) == 0

    def test_verify_chain_gap_events_archived(self, sub):
        """WI-249 review F1: verify_archive_chain must walk the inter-segment
        chain through gap events that were archived after sealing.

        A gap between two sealed segments can hold work-item events created
        between the two seals. Once that work-item reaches terminal and
        archive_events moves its events to events_archive, the DB-side gap
        query (reading only `events`) misses them and the chain walk falls
        short — a false `chain_link_mismatch` on an INTACT store. The gap
        query must read from BOTH `events` and `events_archive`."""
        agent = {"role": "agent"}
        reviewer = {"role": "reviewer"}

        # Segment A: a terminal work-item, sealed.
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "arch-gap-seg-a",
            custom_fields={"title": "arch-gap-seg-a"},
        )
        _drive_to_terminal(sub, wi1)
        sub.archive.seal(
            before_timestamp=datetime.now(UTC) + timedelta(seconds=1)
        )

        # A work-item that stays LIVE while segment B is sealed, so its
        # events land in the gap between the two segments.
        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "arch-gap-live",
            custom_fields={"title": "arch-gap-live"},
        )
        sub.transition(
            wi2.work_item_id, "start", "agent-1", actor_metadata=agent
        )

        # Segment B: another terminal work-item, sealed.
        wi3, _ = sub.create_work_item(
            "test_workflow", "feature", "arch-gap-seg-b",
            custom_fields={"title": "arch-gap-seg-b"},
        )
        _drive_to_terminal(sub, wi3)
        sub.archive.seal(
            before_timestamp=datetime.now(UTC) + timedelta(days=365)
        )

        # Now drive the gap work-item to terminal and archive it. Its events
        # move to events_archive; the inter-segment seal event stays in
        # events (entity_kind='segment').
        sub.transition(
            wi2.work_item_id, "submit_review", "agent-1", actor_metadata=agent
        )
        sub.transition(
            wi2.work_item_id, "approve", "reviewer-1", actor_metadata=reviewer
        )
        archived = sub.archive.archive_events(
            before_timestamp=datetime.now(UTC) + timedelta(days=365)
        )
        assert archived > 0, "expected the gap work-item's events to be archived"

        # Post-fix: the chain verifies through the archived gap events.
        # Pre-fix this fails with `chain_link_mismatch` (and the per-segment
        # verification failed too, since verify_segment also read only
        # `events`).
        result = sub.verify_archive_chain()
        assert result["segment_count"] >= 2
        assert result["verified"], result["chain_breaks"]
        assert len(result["chain_breaks"]) == 0, result["chain_breaks"]

        # Pin the implicit coupling: verify_archive_chain passes here because
        # archive_events ALSO archived the segments' own work-item events, so
        # each segment's events are split across `events` and `events_archive`.
        # Assert explicitly that a segment whose OWN events are archived still
        # verifies — the union-read behaviour is what makes this pass, and the
        # test must not rely on that coupling by accident.
        with raw_transaction(sub) as conn:
            seg_rows = conn.execute(
                "SELECT segment_id FROM event_segments ORDER BY first_global_seq"
            ).fetchall()
        assert len(seg_rows) >= 2, f"expected 2+ segments, got {len(seg_rows)}"
        for seg_row in seg_rows:
            seg_report = sub.archive.verify(seg_row["segment_id"])
            assert seg_report["verified"], (
                f"segment {seg_row['segment_id']} failed per-segment "
                f"verification after archival: "
                f"global_chain_ok={seg_report['global_chain_ok']} "
                f"head_hash_matches={seg_report['head_hash_matches']} "
                f"seal_event_verified={seg_report['seal_event_verified']} "
                f"event_count={seg_report['event_count']}/"
                f"{seg_report['expected_count']}"
            )
