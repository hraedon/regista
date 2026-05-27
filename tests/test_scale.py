from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from regista._testing import Metrics, poll_and_process_hooks, raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

slow = pytest.mark.slow
pytestmark = slow


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: scale benchmarks, skipped by default")


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_scale_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestReplayBenchmark:
    @slow
    def test_replay_at_scale(self, regista):
        n_items = 100
        events_per_item = 10

        for i in range(n_items):
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"Bench item {i}"},
            )
            for j in range(events_per_item - 1):
                if j == 0:
                    regista.transition(
                        wi.work_item_id, "start", "agent-1",
                        actor_metadata={"role": "agent"},
                    )
                else:
                    regista.append_event(
                        wi.work_item_id, "agent-1",
                        transition=f"bench_note_{j}",
                        payload={"note": f"event {j}"},
                    )

        total_events = n_items * events_per_item
        start = time.time()
        report = regista.replay()
        elapsed = time.time() - start

        print(f"\n  [replay] {n_items} items x {events_per_item} events = {total_events} total")
        print(f"  [replay] wall-clock: {elapsed:.3f}s")
        print(f"  [replay] per-event: {elapsed / total_events * 1000:.3f}ms")
        print(f"  [replay] drift: {report.replayed_drift}, halted: {report.halted}")
        assert report.replayed_drift == 0
        assert report.halted == 0

    @slow
    def test_replay_long_history(self, regista):
        n_items = 100
        events_per_item = 100

        prev_wi_id = None
        for i in range(n_items):
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"Long history item {i}"},
            )
            regista.transition(
                wi.work_item_id, "start", "agent-1",
                actor_metadata={"role": "agent"},
            )
            regista.transition(
                wi.work_item_id, "submit_review", "agent-1",
                actor_metadata={"role": "agent"},
            )
            if i % 2 == 0:
                regista.transition(
                    wi.work_item_id, "approve", "reviewer-1",
                    actor_metadata={"role": "reviewer"},
                )
                used = 4
            else:
                regista.transition(
                    wi.work_item_id, "reject", "reviewer-1",
                    actor_metadata={"role": "reviewer"},
                )
                regista.transition(
                    wi.work_item_id, "submit_review", "agent-1",
                    actor_metadata={"role": "agent"},
                )
                regista.transition(
                    wi.work_item_id, "approve", "reviewer-1",
                    actor_metadata={"role": "reviewer"},
                )
                used = 6

            for j in range(events_per_item - used - 1):
                regista.append_event(
                    wi.work_item_id, "agent-1",
                    transition=f"note_{j}",
                    payload={"idx": j},
                )

            if i > 0:
                regista.create_link(
                    from_work_item_id=wi.work_item_id,
                    to_work_item_id=prev_wi_id,
                    link_type="blocks",
                    actor_id="agent-1",
                )
            prev_wi_id = wi.work_item_id

        total_events = n_items * events_per_item
        start = time.time()
        report = regista.replay()
        elapsed = time.time() - start

        print(
            f"\n  [replay-long] {n_items} items x {events_per_item} events"
            f" = {total_events} total"
        )
        print(f"  [replay-long] wall-clock: {elapsed:.3f}s")
        print(f"  [replay-long] per-event: {elapsed / total_events * 1000:.3f}ms")
        print(f"  [replay-long] drift: {report.replayed_drift}, halted: {report.halted}")
        assert report.replayed_drift == 0
        assert report.halted == 0

        from psycopg.sql import SQL, Identifier

        with raw_transaction(regista) as conn:
            sample = conn.execute(
                SQL("SELECT work_item_id FROM {} ORDER BY work_item_id LIMIT 5")
                .format(Identifier(report.table_name))
            ).fetchall()
            for row in sample:
                wi_id = row["work_item_id"]
                live = conn.execute(
                    SQL(
                        "SELECT current_state, custom_fields, needs_review, "
                        "not_before, last_event_seq "
                        "FROM work_items_current WHERE work_item_id = %s"
                    ),
                    [wi_id],
                ).fetchone()
                rep = conn.execute(
                    SQL(
                        "SELECT current_state, custom_fields, needs_review, "
                        "not_before, last_event_seq "
                        "FROM {} WHERE work_item_id = %s"
                    ).format(Identifier(report.table_name)),
                    [wi_id],
                ).fetchone()
                assert dict(live) == dict(rep)


class TestLinkQueryBenchmark:
    @slow
    def test_link_query_at_scale(self, regista):
        n_items = 50
        links_per_item = 5

        sources = []
        targets = []
        for i in range(n_items):
            src, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"Link src {i}"},
            )
            tgt, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="bug",
                actor_id="agent-1",
                custom_fields={"severity": "major"},
            )
            sources.append(src.work_item_id)
            targets.append(tgt.work_item_id)

        for i in range(n_items):
            for j in range(links_per_item):
                t_idx = (i + j + 1) % n_items
                regista.create_link(
                    from_work_item_id=sources[i],
                    to_work_item_id=targets[t_idx],
                    link_type="fixes",
                    actor_id="agent-1",
                )

        total_links = n_items * links_per_item

        start = time.time()
        for _ in range(10):
            page = regista.query_work_items(
                workflow_name="test_workflow",
                has_link_type="fixes",
                page_size=100,
            )
        elapsed = time.time() - start

        print(f"\n  [link query] {total_links} live links across {n_items * 2} work items")
        print(f"  [link query] 10 queries wall-clock: {elapsed:.3f}s")
        print(f"  [link query] per-query: {elapsed / 10 * 1000:.1f}ms")
        print(f"  [link query] results: {len(page.items)} items with fixes links")


class TestHookThroughputBenchmark:
    @slow
    def test_hook_drain_throughput(self, regista):
        import psycopg.types.json
        from psycopg.sql import SQL

        n_hooks = 500

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Hook bench"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        event_id = events[0].event_id

        with raw_transaction(regista) as conn:
            for i in range(n_hooks):
                conn.execute(
                    SQL(
                        "INSERT INTO hook_queue "
                        "(event_id, hook_name, hook_type, payload, max_retries) "
                        "VALUES (%s, %s, 'async', %s, 3)"
                    ),
                    [
                        event_id,
                        f"bench_hook_{i % 5}",
                        psycopg.types.json.Jsonb({"work_item_id": str(wi.work_item_id)}),
                    ],
                )

        def noop_handler(ctx):
            pass

        handlers = {f"bench_hook_{i % 5}": noop_handler for i in range(5)}

        drain_count = 0
        start = time.time()
        while True:
            with raw_transaction(regista) as conn:
                batch = poll_and_process_hooks(
                    conn, handlers, regista._keys,
                    Metrics(), regista.project,
                )
            drain_count += batch
            if batch == 0:
                break
        elapsed = time.time() - start

        print(f"\n  [hook drain] {n_hooks} hooks enqueued, {drain_count} processed")
        print(f"  [hook drain] wall-clock: {elapsed:.3f}s")
        print(f"  [hook drain] per-hook: {elapsed / max(drain_count, 1) * 1000:.3f}ms")
        print(f"  [hook drain] throughput: {drain_count / max(elapsed, 0.001):.0f} hooks/sec")
        assert drain_count == n_hooks
