"""
Tests for BC-184 (hook_queue_depth metric) and BC-185 (maintenance metrics).

BC-184: regista_hook_queue_depth gauge with status labels.
BC-185: maintenance counters and maintenance_healthy property.
"""
from __future__ import annotations

import uuid
from pathlib import Path

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")

WORKFLOW_YAML = """\
name: bc184_185_test
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


# ---------------------------------------------------------------------------
# BC-184: hook_queue_depth gauge (Postgres backend)
# ---------------------------------------------------------------------------

class TestHookQueueDepthMetric:
    """BC-184: regista_hook_queue_depth gauge reflects hook_queue counts."""

    def test_refresh_hook_queue_metrics_initial(self):
        """gauge starts at 0 for all statuses before any hooks are enqueued."""
        from prometheus_client import CollectorRegistry

        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc184_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(
            DSN, project, KEY_PATH, prometheus_registry=registry, auto_partition=True
        )
        sub.register_workflow(WORKFLOW_YAML)
        try:
            sub.refresh_hook_queue_metrics()
            samples = {
                (s.name, s.labels.get("status")): s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert ("regista_hook_queue_depth", "pending") in samples
            assert samples[("regista_hook_queue_depth", "pending")] == 0.0
            assert samples[("regista_hook_queue_depth", "dead_letter")] == 0.0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_gauge_reflects_pending_hooks(self):
        """After enqueuing hooks, pending count rises; after processing, it drops."""
        from prometheus_client import CollectorRegistry

        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc184b_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(
            DSN, project, KEY_PATH, prometheus_registry=registry, auto_partition=True
        )
        sub.register_workflow(WORKFLOW_YAML)

        completed = []

        def on_finish(ctx):
            completed.append(ctx.hook_queue_id)

        sub.register_hook_handler("on_finish", on_finish)
        try:
            # Enqueue 3 hooks via transitions.
            for _ in range(3):
                wi, _ = sub.create_work_item(
                    workflow_name="bc184_185_test",
                    work_item_type="task",
                    actor_id="agent-1",
                )
                sub.transition(
                    wi.work_item_id, "finish", "agent-1",
                    actor_metadata={"role": "agent"},
                )

            # Before processing: 3 pending.
            sub.refresh_hook_queue_metrics()
            samples = {
                (s.name, s.labels.get("status")): s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert samples[("regista_hook_queue_depth", "pending")] == 3.0

            # Process all hooks.
            sub.poll_hooks()

            # After processing: 0 pending.
            sub.refresh_hook_queue_metrics()
            samples = {
                (s.name, s.labels.get("status")): s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert samples[("regista_hook_queue_depth", "pending")] == 0.0
        finally:
            sub.close()
            drop_project_schema(DSN, project)


# ---------------------------------------------------------------------------
# BC-184: InMemory backend - refresh_hook_queue_metrics emits log lines
# ---------------------------------------------------------------------------

class TestHookQueueDepthInMemory:
    """BC-184: InMemory backend refresh_hook_queue_metrics runs without error."""

    def test_refresh_does_not_raise(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test_bc184_mem")
        sub.refresh_hook_queue_metrics()  # should not raise

    def test_maintenance_healthy_returns_true(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test_bc184_mem2")
        assert sub.maintenance_healthy is True


# ---------------------------------------------------------------------------
# BC-185: maintenance_healthy property (Postgres backend)
# ---------------------------------------------------------------------------

class TestMaintenanceHealthy:
    """BC-185: maintenance_healthy returns True (pending Plan 009 thread)."""

    def test_maintenance_healthy_true_before_plan009(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc185_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH, auto_partition=True)
        try:
            assert sub.maintenance_healthy is True
        finally:
            sub.close()
            drop_project_schema(DSN, project)


# ---------------------------------------------------------------------------
# BC-185: maintenance counters (Postgres backend)
# ---------------------------------------------------------------------------

class TestMaintenanceCounters:
    """BC-185: maintenance counters increment correctly on sweep operations."""

    def test_maintenance_claims_swept_counter(self):
        """sweep_expired_claims increments regista_maintenance_claims_swept_total."""
        from datetime import UTC, datetime, timedelta

        import psycopg
        from prometheus_client import CollectorRegistry

        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc185c_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(
            DSN, project, KEY_PATH, prometheus_registry=registry, auto_partition=True
        )
        sub.register_workflow(WORKFLOW_YAML)
        try:
            # Create a work item and acquire a claim.
            wi, _ = sub.create_work_item(
                workflow_name="bc184_185_test",
                work_item_type="task",
                actor_id="agent-sweep",
            )
            sub.acquire_claim(wi.work_item_id, "agent-sweep", ttl_seconds=1)

            # Manually expire the claim by back-dating it.
            conn = psycopg.connect(DSN, autocommit=True)
            conn.execute(
                f'SET search_path TO "{project}"'
            )
            conn.execute(
                "UPDATE claims SET expires_at = %s WHERE actor_id = 'agent-sweep'",
                [datetime.now(UTC) - timedelta(seconds=60)],
            )
            conn.close()

            swept = sub.sweep_expired_claims()
            assert swept >= 1

            samples = {
                s.name: s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert "regista_maintenance_claims_swept_total" in samples
            assert samples["regista_maintenance_claims_swept_total"] >= 1.0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_maintenance_hook_leases_swept_counter(self):
        """sweep_expired_hook_leases increments regista_maintenance_hook_leases_swept_total."""
        from datetime import UTC, datetime, timedelta

        import psycopg
        from prometheus_client import CollectorRegistry

        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc185h_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(
            DSN, project, KEY_PATH, prometheus_registry=registry, auto_partition=True
        )
        sub.register_workflow(WORKFLOW_YAML)

        def on_finish(ctx):
            pass  # don't complete so hook stays in_progress

        sub.register_hook_handler("on_finish", on_finish)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="bc184_185_test",
                work_item_type="task",
                actor_id="agent-hls",
            )
            sub.transition(
                wi.work_item_id, "finish", "agent-hls",
                actor_metadata={"role": "agent"},
            )

            # Claim the hook with a short lease.
            hooks = sub.claim_hooks(max_batch=10, lease_seconds=1)
            assert len(hooks) >= 1

            # Expire the lease by back-dating.
            conn = psycopg.connect(DSN, autocommit=True)
            conn.execute(f'SET search_path TO "{project}"')
            conn.execute(
                "UPDATE hook_queue SET lease_expires_at = %s WHERE status = 'in_progress'",
                [datetime.now(UTC) - timedelta(seconds=60)],
            )
            conn.close()

            swept = sub.sweep_expired_hook_leases()
            assert swept >= 1

            samples = {
                s.name: s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert "regista_maintenance_hook_leases_swept_total" in samples
            assert samples["regista_maintenance_hook_leases_swept_total"] >= 1.0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_maintenance_partitions_created_counter_deprecated(self):
        """ensure_event_partitions is a no-op after migration 014."""
        from prometheus_client import CollectorRegistry

        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_bc185p_{uuid.uuid4().hex[:8]}"
        registry = CollectorRegistry()
        sub = Regista.create_project(
            DSN, project, KEY_PATH, prometheus_registry=registry, auto_partition=False
        )
        try:
            names = sub.ensure_event_partitions(months_ahead=2)
            assert names == []

            samples = {
                s.name: s.value
                for m in registry.collect()
                for s in m.samples
                if s.labels.get("project") == project
            }
            assert "regista_maintenance_partitions_created_total" not in samples
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_maintenance_recurrences_fired_counter_registered(self):
        """regista_maintenance_recurrences_fired_total counter is registered and can be incremented."""  # noqa: E501
        from prometheus_client import CollectorRegistry

        from regista._observability import Metrics

        registry = CollectorRegistry()
        metrics = Metrics(registry=registry)
        project = "test_project"

        # Counter should not yet appear.
        names_before = {s.name for m in registry.collect() for s in m.samples}
        assert "regista_maintenance_recurrences_fired_total" not in names_before

        # After inc(), it should appear.
        metrics.inc("maintenance_recurrences_fired", project)
        samples = {
            s.name: s.value
            for m in registry.collect()
            for s in m.samples
            if s.labels.get("project") == project
        }
        assert "regista_maintenance_recurrences_fired_total" in samples
        assert samples["regista_maintenance_recurrences_fired_total"] == 1.0
