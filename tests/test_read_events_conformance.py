from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(params=["real", "in_memory"])
def sub(request, tmp_path):
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    # One Ed25519 actor-role keyset per parametrisation; both backends open the
    # clean epoch before the workflow registration, which emits a signed
    # `workflow_registered` event that needs an epoch to land in.
    keyset = make_v6_keyset(tmp_path)
    if request.param == "real":
        from regista import Regista

        project = f"test_read_evt_{uuid.uuid4().hex[:8]}"
        s = Regista.create_project(DSN, project, keyset.path)
        open_v6_epoch(s, keyset)
        s.register_workflow_file(WORKFLOW_PATH)
        yield s
        s.close()
        drop_project_schema(DSN, project)
    else:
        s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(s, keyset)
        s.register_workflow_file(WORKFLOW_PATH)
        yield s
        s.close()


def _create_work_item_with_events(sub, n_extra=5):
    wi, _ = sub.create_work_item(
        workflow_name="test_workflow",
        work_item_type="feature",
        actor_id="agent:worker",
        custom_fields={"title": "ordering-test"},
    )
    for _ in range(n_extra):
        # An explicit transition, because a v6 event has no transitionless form
        # (RECONCILIATION.md Resolution 3) — this test's subject is read ordering,
        # not the shape of a bare append.
        sub.append_event(wi.work_item_id, "agent:worker", transition="note")
    return wi


class TestReadEventsOrderingConformance:
    def test_full_read_returns_all_asc_by_seq(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(work_item_id=wi.work_item_id, limit=100)
        assert len(evts) == 6
        seqs = [e.event_seq for e in evts]
        assert seqs == sorted(seqs)
        assert seqs == [1, 2, 3, 4, 5, 6]

    def test_limit_returns_newest_events(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(work_item_id=wi.work_item_id, limit=3)
        assert len(evts) == 3
        seqs = [e.event_seq for e in evts]
        assert seqs == [4, 5, 6]
        assert seqs == sorted(seqs)

    def test_limit_one_returns_newest_single(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(work_item_id=wi.work_item_id, limit=1)
        assert len(evts) == 1
        assert evts[0].event_seq == 6

    def test_before_seq_returns_correct_window(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(
            work_item_id=wi.work_item_id,
            limit=2,
            before_seq=4,
        )
        assert len(evts) == 2
        seqs = [e.event_seq for e in evts]
        assert seqs == [2, 3]
        assert seqs == sorted(seqs)

    def test_before_seq_with_large_limit(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(
            work_item_id=wi.work_item_id,
            limit=100,
            before_seq=4,
        )
        assert len(evts) == 3
        seqs = [e.event_seq for e in evts]
        assert seqs == [1, 2, 3]

    def test_before_seq_at_boundary(self, sub):
        wi = _create_work_item_with_events(sub, n_extra=5)
        evts = sub.read_events(
            work_item_id=wi.work_item_id,
            limit=100,
            before_seq=1,
        )
        assert len(evts) == 0

    def test_desc_ordering_without_work_item_id(self, sub):
        for i in range(3):
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent:worker",
                custom_fields={"title": f"item-{i}"},
            )
        evts = sub.read_events(limit=10)
        assert len(evts) >= 3
        timestamps = [e.timestamp for e in evts]
        for i in range(len(timestamps) - 1):
            assert timestamps[i] >= timestamps[i + 1], "Events must be DESC by timestamp"

    def test_desc_tiebreaker_event_seq(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "tiebreaker"},
        )
        sub.append_event(wi.work_item_id, "agent:worker", transition="note")
        sub.append_event(wi.work_item_id, "agent:worker", transition="note")
        evts = sub.read_events(limit=10)
        assert len(evts) >= 3
        for i in range(len(evts) - 1):
            curr = evts[i]
            nxt = evts[i + 1]
            assert curr.timestamp >= nxt.timestamp
            if curr.timestamp == nxt.timestamp:
                assert curr.event_seq >= nxt.event_seq, (
                    "event_seq must be DESC when timestamps are equal"
                )
