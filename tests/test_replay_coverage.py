from __future__ import annotations

import dataclasses
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

#: WI-315: the epoch-boundary trigger (migration 049) refuses a non-v6 events
#: insert once the epoch is open. Several tests below deliberately seed a corrupt
#: legacy row to prove that REPLAY still halts on it -- a defense-in-depth layer
#: beneath the trigger. Only that trigger is toggled (031's entity_id trigger stays
#: enabled), so the seeded row is byte-identical to what these tests injected before.
_DISABLE_EPOCH_TRIGGER = "ALTER TABLE events DISABLE TRIGGER events_enforce_v6_epoch_boundary"
_ENABLE_EPOCH_TRIGGER = "ALTER TABLE events ENABLE TRIGGER events_enforce_v6_epoch_boundary"


#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
WORKER = "agent:worker"
#: The second, distinct claimant every steal/contest case needs.
OTHER = "agent:reviewer"
REVIEWER = "human:reviewer"
#: The pre-epoch spellings, still used by the two unmigrated nodes below.
LEGACY_WORKER = "agent-1"
LEGACY_REVIEWER = "reviewer-1"


@pytest.fixture
def keyset(tmp_path):
    from tests._v6_fixtures import make_v6_keyset

    return make_v6_keyset(tmp_path)


@pytest.fixture
def regista(keyset):
    from regista import Regista
    from tests._v6_fixtures import open_v6_epoch

    project = f"test_replay_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    # The epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


#: The ``unmigrated_regista`` fixture is gone. It existed for exactly one node —
#: ``test_replay_derives_escalated`` — because ``_claims.py``'s auto-escalation
#: appended its ``escalated`` event as the bare literal ``"system"``, which no
#: keyset can bind (``ACTOR_SIGNER_MISMATCH``). Its own docstring named the
#: condition for its removal: "the node should be migrated in the same change that
#: gives escalation a v6 principal." ``_events.resolve_system_actor_id`` is that
#: change, so the node now runs on the ordinary migrated ``regista`` fixture and
#: the last-resort pattern is retired rather than inherited.


def _in_memory(keyset):
    """An ``InMemoryRegista`` on a clean v6 epoch, workflow registered."""

    from tests._v6_fixtures import open_v6_epoch

    s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
    open_v6_epoch(s, keyset)
    s.register_workflow_file(WORKFLOW_PATH)
    return s


class TestReplayClaimLifecycle:
    def test_replay_derives_claim_acquired(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "claim replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_derives_claim_stolen(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "steal replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=1)
        import time
        time.sleep(2)
        regista.acquire_claim(wi.work_item_id, OTHER, ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.claimed_by == OTHER
        assert live.attempt_number == 2

    def test_replay_derives_claim_released(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "release replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.release_claim(wi.work_item_id, WORKER)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_derives_claim_expired(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "expired replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=1)
        import time
        time.sleep(2)
        regista.sweep_expired_claims()

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_replay_heartbeat_drift_within_threshold(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "heartbeat replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.heartbeat_claim(wi.work_item_id, WORKER, ttl_seconds=600)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayLinkLifecycle:
    def test_replay_derives_link_created_and_removed(self, regista):
        wi_a, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "link src"},
        )
        wi_b, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "link dst"},
        )
        regista.create_link(
            wi_a.work_item_id, wi_b.work_item_id, "blocks", WORKER,
        )
        regista.remove_link(
            wi_a.work_item_id, wi_b.work_item_id, "blocks", WORKER,
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayEscalationAndNotBefore:
    def test_replay_derives_escalated(self, regista):
        regista.register_actor_role(WORKER, "agent")
        regista.register_actor_role(REVIEWER, "reviewer")

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "escalation replay"},
        )
        # attempt_threshold=3; need 3 claim acquisitions to trigger escalation.
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.release_claim(wi.work_item_id, WORKER)
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.release_claim(wi.work_item_id, WORKER)
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.needs_review is True

    def test_replay_derives_not_before_set(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "not_before replay"},
        )
        future = datetime.now(UTC) + timedelta(days=1)
        regista.update_not_before(wi.work_item_id, future, WORKER)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayCustomFieldsUpdate:
    def test_replay_derives_custom_fields_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "cf replay"},
        )
        regista.transition(
            wi.work_item_id, "start", WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 1}},
        )
        regista.transition(
            wi.work_item_id, "submit_review", WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 2}},
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestReplayOrphanEvents:
    def test_orphan_with_created_event_halts(self, regista):
        # WI-266: a projection row deleted out from under its created log is
        # the same structural finding scoped replay halts on — halted, not a
        # warning, so whole-store and scoped replay return the same verdict.
        wi, _evt = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "orphan created"},
        )
        with raw_transaction(regista) as conn:
            conn.execute(
                "DELETE FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.halted >= 1
        assert report.warnings == 0

    def test_orphan_without_created_event_halts(self, regista):
        from psycopg.sql import SQL
        orphan_id = uuid.uuid4()
        with raw_transaction(regista) as conn:
            # This deliberately fabricates a corrupt (orphan, non-v6) row to prove
            # replay HALTS on it -- a layer beneath the WI-315 epoch-boundary trigger,
            # which would otherwise refuse exactly this insert. Seed it under a
            # disabled trigger so the row (and replay's view of it) is unchanged.
            conn.execute(_DISABLE_EPOCH_TRIGGER)
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
            conn.execute(_ENABLE_EPOCH_TRIGGER)

        report = regista.replay()
        assert report.halted >= 1


class TestReplayContinueOnRevoked:
    def test_continue_on_revoked_skips_unknown_key(self, regista):
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "revoked replay"},
        )

        report = regista.replay(continue_on_revoked=True)
        assert report.replayed_ok >= 1

    def test_continue_on_revoked_warnings_counted(self, regista):
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "revoked warnings"},
        )
        report = regista.replay(continue_on_revoked=True)
        assert report.warnings is not None
        assert report.replayed_ok >= 1


class TestReplayKeyFailurePaths:
    def test_signature_mismatch_halts(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
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
            "test_workflow", "feature", WORKER,
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
            actor_id=WORKER,
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
            # Insert an event at seq=2 claiming workflow v999 which no longer exists.
            # This is a deliberately-corrupt legacy row seeded to prove replay halts;
            # the WI-315 trigger would refuse it, so seed under a disabled trigger.
            conn.execute(_DISABLE_EPOCH_TRIGGER)
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
            conn.execute(_ENABLE_EPOCH_TRIGGER)
            # Also bump all existing events to v999 so the first events pass
            conn.execute(
                "UPDATE events SET workflow_version = 999 WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.halted >= 1

    def test_invalid_from_state_halts(self, regista):
        regista.register_actor_role(WORKER, "agent")
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "bad state"},
        )
        regista.transition(
            wi.work_item_id, "start", WORKER,
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
            actor_id=WORKER,
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
            # Deliberately-corrupt legacy row (invalid from-state) seeded to prove
            # replay halts; the WI-315 trigger would refuse it, so seed it under a
            # disabled trigger.
            conn.execute(_DISABLE_EPOCH_TRIGGER)
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
            conn.execute(_ENABLE_EPOCH_TRIGGER)

        report = regista.replay()
        assert report.halted >= 1


class TestInMemoryReplayParity:
    def test_in_memory_no_drift_after_claim_transition_link(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "inmem parity"},
        )
        s.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        s.transition(
            wi.work_item_id, "start", WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"step": 1}},
        )
        s.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        s.heartbeat_claim(wi.work_item_id, WORKER, ttl_seconds=600)
        s.release_claim(wi.work_item_id, WORKER)

        wi2, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "link target"},
        )
        s.create_link(
            wi.work_item_id, wi2.work_item_id, "blocks", WORKER,
        )

        report = s.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_in_memory_replay_orphan_halts(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "orphan"},
        )
        del s._work_items[wi.work_item_id]

        report = s.replay()
        # WI-266: orphan-with-created is halted in the InMemory backend too,
        # matching Postgres.
        assert report.halted >= 1
        assert report.warnings == 0

    def test_in_memory_replay_count_matches(self, keyset):
        s = _in_memory(keyset)

        for i in range(3):
            s.create_work_item(
                "test_workflow", "feature", WORKER,
                custom_fields={"title": f"item {i}"},
            )

        report = s.replay()
        assert report.replayed_ok == 3
        assert report.halted == 0
        assert report.replayed_drift == 0


class TestBC090ClaimStateDriftDetection:
    def test_claimed_by_tampered_detected_as_drift(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "claim drift by"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current SET claimed_by = 'tampered-actor' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.replayed_drift >= 1

    def test_claim_expires_at_tampered_detected_as_drift(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "claim drift expires"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current "
                "SET claim_expires_at = now() + interval '1 day' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.replayed_drift >= 1

    def test_claim_state_cleared_after_workflow_transition(self, regista):
        regista.register_actor_role(WORKER, "agent")
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "claim cleared"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.transition(
            wi.work_item_id, "start", WORKER,
            actor_metadata={"role": "agent"},
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.claimed_by is None
        assert live.claim_expires_at is None

    def test_claim_state_correct_after_acquire_and_heartbeat(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "claim hb replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.heartbeat_claim(wi.work_item_id, WORKER, ttl_seconds=600)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.claimed_by == WORKER
        assert live.claim_expires_at is not None

    def test_claim_attempt_number_reconstructed(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "attempt replay"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.release_claim(wi.work_item_id, WORKER)
        regista.acquire_claim(wi.work_item_id, OTHER, ttl_seconds=300)

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        live = regista.get_work_item(wi.work_item_id)
        assert live.attempt_number == 2
        assert live.claimed_by == OTHER

    def test_claim_stolen_replay_drift_detection(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "steal drift detect"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=1)
        import time
        time.sleep(2)
        regista.acquire_claim(wi.work_item_id, OTHER, ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE work_items_current SET claimed_by = 'tampered' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        report = regista.replay()
        assert report.replayed_drift >= 1


class TestBC095InMemoryReplaySignatureVerification:
    def test_in_memory_signature_mismatch_halts(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "sig tamper"},
        )

        events = s._store.events[wi.work_item_id]
        tampered = dataclasses.replace(events[0], signature=b"\x00" * 32)
        events[0] = tampered
        s._store.event_id_index[tampered.event_id] = tampered

        report = s.replay()
        assert report.halted >= 1

    def test_in_memory_unknown_key_with_continue_on_revoked(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "unknown key skip"},
        )

        events = s._store.events[wi.work_item_id]
        tampered = dataclasses.replace(events[0], key_id="nonexistent-key")
        events[0] = tampered
        s._store.event_id_index[tampered.event_id] = tampered

        report = s.replay(continue_on_revoked=True)
        assert report.warnings >= 1
        assert report.halted == 0
        assert report.replayed_ok >= 1

    def test_in_memory_unknown_key_without_continue_on_revoked_halts(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "unknown key halt"},
        )

        events = s._store.events[wi.work_item_id]
        tampered = dataclasses.replace(events[0], key_id="nonexistent-key")
        events[0] = tampered
        s._store.event_id_index[tampered.event_id] = tampered

        report = s.replay()
        assert report.halted >= 1

    def test_in_memory_replay_verifies_and_detects_drift(self, keyset):
        s = _in_memory(keyset)

        wi, _ = s.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "drift detect"},
        )
        s.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        s._work_items[wi.work_item_id]["claimed_by"] = "tampered"

        report = s.replay()
        assert report.replayed_drift >= 1
