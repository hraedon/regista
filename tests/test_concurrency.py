from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from _v6_fixtures import ACTOR_PRINCIPALS, make_v6_keyset, open_v6_epoch

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

NUM_WORKERS = 20

#: One canonical principal per concurrent writer (``TRUST-DOMAIN.md`` §2.1). The v6
#: writer requires ``entry.principal_id == actor_id`` — there is no shared signing key —
#: so twenty concurrent appenders need twenty keys, and the list passed to
#: ``make_v6_keyset`` and to ``open_v6_epoch`` must be identical or the unaccepted ids
#: are refused with ``KEY_BINDING_UNRESOLVED``.
WORKERS = tuple(f"agent:worker-{i}" for i in range(NUM_WORKERS))
CREATOR = "agent:worker"
REVIEWER = "human:reviewer"
PRINCIPALS = (*ACTOR_PRINCIPALS, *WORKERS)


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista

    project = f"test_conc_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("conc_keys"), principals=PRINCIPALS)
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch before the registration: `register_workflow_file` emits
    # the signed `workflow_registered` event admission gate 1 requires, and there
    # is no epoch to append it to until `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset, principals=PRINCIPALS)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC28ConcurrentSeqGapFree:
    def test_concurrent_appends_are_gap_free(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=CREATOR,
            custom_fields={"title": "AC-28 concurrency"},
        )

        num_workers = NUM_WORKERS
        events_per_worker = 5
        total = num_workers * events_per_worker
        errors: list[Exception] = []
        results: list[int] = []

        def append_events(worker_id):
            local_seqs = []
            try:
                for i in range(events_per_worker):
                    evt = regista.append_event(
                        work_item_id=wi.work_item_id,
                        actor_id=WORKERS[worker_id],
                        transition=f"concurrent_{worker_id}_{i}",
                    )
                    local_seqs.append(evt.event_seq)
            except Exception as e:
                errors.append(e)
            return local_seqs

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(append_events, w) for w in range(num_workers)]
            for f in futures:
                results.extend(f.result())

        assert not errors, f"Errors during concurrent appends: {errors}"
        assert len(results) == total, f"Expected {total} events, got {len(results)}"

        results.sort()
        expected = list(range(2, total + 2))
        assert results == expected, f"Gap in event_seq: got {results}, expected {expected}"

    def test_concurrent_transitions_gap_free(self, regista):
        num_workers = 10
        work_items = []
        for i in range(num_workers):
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=CREATOR,
                actor_metadata={"role": "agent"},
                custom_fields={"title": f"AC-28 trans {i}"},
            )
            work_items.append(wi)

        errors: list[Exception] = []

        def do_transition(wi):
            try:
                regista.transition(
                    work_item_id=wi.work_item_id,
                    transition_name="start",
                    actor_id=CREATOR,
                    actor_metadata={"role": "agent"},
                )
                regista.transition(
                    work_item_id=wi.work_item_id,
                    transition_name="submit_review",
                    actor_id=CREATOR,
                    actor_metadata={"role": "agent"},
                )
                regista.transition(
                    work_item_id=wi.work_item_id,
                    transition_name="approve",
                    actor_id=REVIEWER,
                    actor_metadata={"role": "reviewer"},
                )
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(do_transition, wi) for wi in work_items]
            for f in futures:
                f.result()

        assert not errors, f"Errors during concurrent transitions: {errors}"

        for wi in work_items:
            refreshed = regista.get_work_item(wi.work_item_id)
            assert refreshed.current_state == "done"
            events = regista.read_events(work_item_id=wi.work_item_id)
            seqs = [e.event_seq for e in events]
            assert seqs == sorted(seqs)
