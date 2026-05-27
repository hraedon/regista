from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg.types.json
import pytest

from regista._testing import raw_transaction
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_replay_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestReplayClaimLifecycle:
    def test_replay_derives_claim_acquired(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "claim replay"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_derives_claim_stolen(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "steal replay"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.release_claim(wi.work_item_id, "agent-1")
        regista.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_derives_claim_released(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "release replay"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.release_claim(wi.work_item_id, "agent-1")

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_derives_claim_expired(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "expired replay"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)
        import time
        time.sleep(2)
        regista.sweep_expired_claims()

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_heartbeat_drift_within_threshold(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "heartbeat replay"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=600)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayLinkLifecycle:
    def test_replay_derives_link_created_and_removed(self, regista):
        wi_a, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "link src"},
        )
        wi_b, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "link dst"},
        )
        regista.create_link(
            wi_a.work_item_id, wi_b.work_item_id, "blocks", "agent-1",
        )
        regista.remove_link(
            wi_a.work_item_id, wi_b.work_item_id, "blocks", "agent-1",
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayEscalationAndNotBefore:
    def test_replay_derives_escalated(self, regista):
        regista.register_actor_role("agent-1", "agent")
        regista.register_actor_role("reviewer-1", "reviewer")

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "escalation replay"},
        )
        # attempt_threshold=3; need 3 claim acquisitions to trigger escalation.
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.release_claim(wi.work_item_id, "agent-1")
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.release_claim(wi.work_item_id, "agent-1")
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.needs_review is True

    def test_replay_derives_not_before_set(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "not_before replay"},
        )
        future = datetime.now(UTC) + timedelta(days=1)
        regista.update_not_before(wi.work_item_id, future, "agent-1")

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayCustomFieldsUpdate:
    def test_replay_derives_custom_fields_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "cf replay"},
        )
        regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 1}},
        )
        regista.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 2}},
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayOrphanEvents:
    def test_orphan_with_created_event_warns(self, regista):
        wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "orphan created"},
        )
        with raw_transaction(regista) as conn:
            conn.execute(
                "DELETE FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.warnings >= 1

    def test_orphan_without_created_event_halts(self, regista):
        from psycopg.sql import SQL
        orphan_id = uuid.uuid4()
        with raw_transaction(regista) as conn:
            conn.execute(
                SQL(
                    "INSERT INTO events "
                    "(event_id, work_item_id, event_seq, actor_id, actor_kind, "
                    "actor_metadata, key_id, workflow_name, workflow_version, "
                    "timestamp, transition, payload, payload_canonical_hash, "
                    "signature, canonical_envelope) "
                    "VALUES (%s, %s, 1, 'x', 'agent', %s, 'test-key-001', "
                    "'test_workflow', 1, "
                    "now(), 'start', %s, %s, %s, %s)"
                ),
                [
                    str(uuid.uuid4()),
                    str(orphan_id),
                    psycopg.types.json.Jsonb({}),
                    psycopg.types.json.Jsonb({}),
                    b'\x00', b'\x00', b'\x00',
                ],
            )

        report = regista.replay()
        assert report.halted >= 1


class TestReplayContinueOnRevoked:
    def test_continue_on_revoked_skips_unknown_key(self, regista):
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "revoked replay"},
        )

        report = regista.replay(continue_on_revoked=True)
        assert report.replayed_ok >= 1

    def test_continue_on_revoked_warnings_counted(self, regista):
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "revoked warnings"},
        )
        report = regista.replay(continue_on_revoked=True)
        assert report.warnings is not None
        assert report.replayed_ok >= 1


class TestReplayKeyFailurePaths:
    def test_signature_mismatch_halts(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "sig halt"},
        )
        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET signature = E'\\\\xDEADBEEF'::bytea "
                "WHERE work_item_id = %s AND transition = 'created'",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.halted >= 1

    def test_missing_workflow_halts(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "missing wf"},
        )
        key_set = regista._keys

        from regista._signing import sign_event as _sign_event
        new_event_id = uuid.uuid4()
        payload = {"initial_state": "new", "custom_fields": {"title": "missing wf"}}
        now = datetime.now(UTC)
        sig, c_hash, env = _sign_event(
            event_id=new_event_id,
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            key_id="test-key-001",
            event_seq=2,
            workflow_name=wi.workflow_name,
            workflow_version=wi.workflow_version,
            timestamp=now,
            transition="start",
            payload=payload,
            key=key_set.active_key().secret,
        )

        with raw_transaction(regista) as conn:
            # Change work_item to v999 so replay reads v999 for subsequent events
            conn.execute(
                "UPDATE work_items_current SET workflow_version = 999 "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )
            # Insert an event at seq=2 claiming workflow v999 which no longer exists
            conn.execute(
                "INSERT INTO events "
                "(event_id, work_item_id, event_seq, actor_id, actor_kind, "
                "key_id, workflow_name, workflow_version, timestamp, "
                "transition, payload, payload_canonical_hash, signature, canonical_envelope) "
                "VALUES (%s, %s, 2, 'agent-1', 'agent', 'test-key-001', "
                "'test_workflow', 999, now(), "
                "'start', %s, %s, %s, %s)",
                [new_event_id, wi.work_item_id,
                 psycopg.types.json.Jsonb(payload), c_hash, sig, env],
            )
            # Also bump all existing events to v999 so the first events pass
            conn.execute(
                "UPDATE events SET workflow_version = 999 WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.halted >= 1

    def test_invalid_from_state_halts(self, regista):
        regista.register_actor_role("agent-1", "agent")
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "bad state"},
        )
        regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )

        key_set = regista._keys
        from regista._signing import sign_event as _sign_event
        new_event_id = uuid.uuid4()
        payload = None
        now = datetime.now(UTC)
        sig, c_hash, env = _sign_event(
            event_id=new_event_id,
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            key_id="test-key-001",
            event_seq=3,
            workflow_name=wi.workflow_name,
            workflow_version=wi.workflow_version,
            timestamp=now,
            transition="start",
            payload=payload,
            key=key_set.active_key().secret,
        )

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current SET current_state = 'done' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )
            conn.execute(
                "INSERT INTO events "
                "(event_id, work_item_id, event_seq, actor_id, actor_kind, "
                "key_id, workflow_name, workflow_version, timestamp, "
                "transition, payload, payload_canonical_hash, signature, canonical_envelope) "
                "VALUES (%s, %s, 3, 'agent-1', 'agent', 'test-key-001', 'test_workflow', 1, now(), "
                "'start', %s, %s, %s, %s)",
                [new_event_id, wi.work_item_id,
                 psycopg.types.json.Jsonb(payload or {}), c_hash, sig, env],
            )

        report = regista.replay()
        assert report.halted >= 1


class TestInMemoryReplayParity:
    def test_in_memory_no_drift_after_claim_transition_link(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem parity"},
        )
        s.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        s.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 1}},
        )
        s.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        s.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=600)
        s.release_claim(wi.work_item_id, "agent-1")

        wi2, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "link target"},
        )
        s.create_link(
            wi.work_item_id, wi2.work_item_id, "blocks", "agent-1",
        )

        report = s.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_in_memory_replay_orphan_warning(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "orphan"},
        )
        del s._work_items[wi.work_item_id]

        report = s.replay()
        assert report.warnings >= 1

    def test_in_memory_replay_count_matches(self):
        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)

        for i in range(3):
            s.create_work_item(
                "test_workflow", "feature", "agent-1",
                custom_fields={"title": f"item {i}"},
            )

        report = s.replay()
        assert report.replayed_ok == 3
        assert report.halted == 0
        assert report.replayed_drift == 0
