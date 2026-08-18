from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from _helpers import DSN
from _v6_fixtures import make_v6_keyset, open_v6_epoch
from psycopg.rows import dict_row

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent

#: Canonical per ``TRUST-DOMAIN.md`` §2.1; the bare legacy spelling is refused at the
#: v6 ingress.
ACTOR = "agent:worker"

WORKFLOW_WITH_HOOKS = """\
name: hook_prim_test
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: finish
    from: new
    to: done
    hooks: [on_finish]

roles:
  - name: agent

work_item_types:
  - name: task
    custom_fields: []

link_types: []
attempt_threshold: 99
"""


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista

    project = f"test_hookprim_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("hookprim_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch before the registration: `register_workflow` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no epoch to
    # append it to until `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow(WORKFLOW_WITH_HOOKS)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


#: The ``unmigrated_regista`` fixture is gone, and with it the last-resort pattern
#: its docstring described. It existed because ``_hooks._move_to_dead_letter``
#: appended ``hook_dead_lettered`` with a hardcoded ``actor_id="system"`` — neither a
#: canonical §2.1 principal nor a key any epoch can bind, refused with
#: ``ACTOR_SIGNER_MISMATCH``. That production gap is closed by
#: ``_events.resolve_system_actor_id``, which attributes the dead-lettering to the
#: project's own bootstrap principal, so the node runs on the migrated handle.


def _raw_conn(schema: str):
    conn = psycopg.connect(DSN, row_factory=dict_row, autocommit=True)
    conn.execute(f'SET search_path TO "{schema}"')
    return conn


def _trigger_hook(regista, actor_id=ACTOR):
    wi, _ = regista.create_work_item(
        workflow_name="hook_prim_test",
        work_item_type="task",
        actor_id=actor_id,
        custom_fields={},
    )
    regista.transition(
        work_item_id=wi.work_item_id,
        transition_name="finish",
        actor_id=actor_id,
    )
    return wi


class TestHookClaimCompleteRoundTrip:
    def test_hook_claim_complete_round_trip(self, regista):
        _trigger_hook(regista)
        schema = regista._mgr.schema

        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60)
        assert len(claimed) == 1
        ctx = claimed[0]
        assert ctx.hook_name == "on_finish"

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status, lease_expires_at FROM hook_queue WHERE id = %s",
                [ctx.hook_queue_id],
            ).fetchone()
        assert row["status"] == "in_progress"
        assert row["lease_expires_at"] > datetime.now(UTC)

        regista.complete_hook(ctx.hook_queue_id)

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status FROM hook_queue WHERE id = %s",
                [ctx.hook_queue_id],
            ).fetchone()
        assert row["status"] == "completed"


class TestHookClaimSkipLocked:
    def test_hook_claim_skip_locked(self, regista):
        for _ in range(5):
            _trigger_hook(regista)

        import threading

        results: list[list] = [[], []]

        def claim(i):
            results[i] = regista.claim_hooks(max_batch=10, lease_seconds=120)

        t1 = threading.Thread(target=claim, args=(0,))
        t2 = threading.Thread(target=claim, args=(1,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        ids_0 = {c.hook_queue_id for c in results[0]}
        ids_1 = {c.hook_queue_id for c in results[1]}
        total = len(ids_0) + len(ids_1)
        overlap = ids_0 & ids_1

        assert overlap == set(), f"Overlap found: {overlap}"
        assert total >= 1


class TestHookFailRetriesThenDeadLetters:
    def test_hook_fail_retries_then_dead_letters(self, regista):
        wi = _trigger_hook(regista)
        schema = regista._mgr.schema

        claimed = regista.claim_hooks(max_batch=1, lease_seconds=30)
        assert len(claimed) >= 1
        ctx = claimed[0]
        hook_id = ctx.hook_queue_id

        with _raw_conn(schema) as conn:
            max_retries = conn.execute(
                "SELECT max_retries FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()["max_retries"]

        for attempt in range(max_retries - 1):
            regista.fail_hook(hook_id, f"error attempt {attempt}")

            with _raw_conn(schema) as conn:
                row = conn.execute(
                    "SELECT status, retry_count FROM hook_queue WHERE id = %s",
                    [hook_id],
                ).fetchone()
            assert row is not None
            assert row["status"] == "pending"
            assert row["retry_count"] == attempt + 1

            with _raw_conn(schema) as conn:
                conn.execute(
                    "UPDATE hook_queue SET next_retry_at = NULL WHERE id = %s",
                    [hook_id],
                )

            reclaimed = regista.claim_hooks(max_batch=100, lease_seconds=30)
            assert any(c.hook_queue_id == hook_id for c in reclaimed), (
                f"Could not reclaim hook on attempt {attempt + 1}"
            )

        regista.fail_hook(hook_id, "final error")

        with _raw_conn(schema) as conn:
            dead_row = conn.execute(
                "SELECT id FROM hook_dead_letter WHERE original_hook_queue_id = %s",
                [hook_id],
            ).fetchone()
        assert dead_row is not None, "Hook was not dead-lettered after exhausting retries"

        events = regista.read_events(work_item_id=wi.work_item_id)
        dead_letter_events = [e for e in events if e.transition == "hook_dead_lettered"]
        assert len(dead_letter_events) >= 1


class TestHookLeaseExpiryRequeues:
    def test_hook_lease_expiry_requeues(self, regista):
        _trigger_hook(regista)
        schema = regista._mgr.schema

        claimed = regista.claim_hooks(max_batch=1, lease_seconds=1)
        assert len(claimed) >= 1
        ctx = claimed[0]
        hook_id = ctx.hook_queue_id

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT retry_count FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        original_retry_count = row["retry_count"]

        with _raw_conn(schema) as conn:
            conn.execute(
                "UPDATE hook_queue SET lease_expires_at = now() - interval '1 second' "
                "WHERE id = %s",
                [hook_id],
            )

        requeued = regista.sweep_expired_hook_leases()
        assert requeued >= 1

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status, retry_count FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "pending"
        assert row["retry_count"] == original_retry_count, (
            "sweep_expired_hook_leases must not increment retry_count"
        )
