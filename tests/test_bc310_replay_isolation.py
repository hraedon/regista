from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
from psycopg.sql import SQL, Identifier

from regista import Regista
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


def _create_project(tmp_path):
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_bc310_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # `register_workflow_file` emits a signed `workflow_registered` event, so the
    # epoch has to be open first.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    return sub, project


def _setup_work_item(sub):
    sub.register_actor_role("agent:worker", "agent")
    sub.register_actor_role("human:reviewer", "reviewer")
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "agent:worker",
        custom_fields={"title": "isolation test"},
    )
    sub.transition(
        wi.work_item_id, "start", "agent:worker", actor_metadata={"role": "agent"}
    )
    return wi.work_item_id


class TestRepeatableReadTransactionManager:
    def test_transaction_repeatable_read_sets_isolation(self, tmp_path):
        sub, project = _create_project(tmp_path)
        try:
            with sub._mgr.transaction_repeatable_read() as conn:
                row = conn.execute("SHOW transaction_isolation").fetchone()
                assert row["transaction_isolation"] == "repeatable read"
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_transaction_repeatable_read_sets_search_path(self, tmp_path):
        sub, project = _create_project(tmp_path)
        try:
            with sub._mgr.transaction_repeatable_read() as conn:
                row = conn.execute("SHOW search_path").fetchone()
                assert project in row["search_path"]
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestReplayUsesRepeatableRead:
    def test_replay_succeeds_under_repeatable_read(self, tmp_path):
        sub, project = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            report = sub.replay()
            assert report.replayed_ok >= 1
            assert report.replayed_drift == 0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_scoped_replay_succeeds_under_repeatable_read(self, tmp_path):
        sub, project = _create_project(tmp_path)
        try:
            wi_id = _setup_work_item(sub)
            report = sub.replay(work_item_id=wi_id)
            assert report.replayed_ok >= 1
            assert report.replayed_drift == 0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_replay_does_not_see_concurrent_write(self, tmp_path):
        sub, project = _create_project(tmp_path)
        try:
            wi_id = _setup_work_item(sub)

            with sub._mgr.transaction_repeatable_read() as replay_conn:
                replay_conn.execute(
                    SQL("SELECT work_item_id FROM work_items_current WHERE work_item_id = %s"),
                    [wi_id],
                ).fetchall()

                all_events = replay_conn.execute(
                    SQL("SELECT transition FROM events WHERE work_item_id = %s ORDER BY event_seq"),
                    [wi_id],
                ).fetchall()

                event_count_before = len(all_events)

                with psycopg.connect(DSN) as writer_conn:
                    writer_conn.execute(
                        SQL("SET search_path TO {}").format(Identifier(project))
                    )
                    # `global_seq` is chain-wide, not per-work-item: a v6 epoch's
                    # chain already carries genesis, the key acceptances and the
                    # workflow registration, so `len(all_events) + 1` would collide
                    # with `events_global_seq_unique`. `event_seq` stays
                    # entity-scoped.
                    next_global_seq = writer_conn.execute(
                        "SELECT COALESCE(MAX(global_seq), 0) + 1 AS next FROM events"
                    ).fetchone()[0]
                    writer_conn.execute(
                        "INSERT INTO events (event_id, work_item_id, "
                        "entity_kind, entity_id, hash_alg, "
                        "event_seq, global_seq, actor_id, actor_kind, "
                        "actor_metadata, key_id, "
                        "workflow_name, workflow_version, timestamp, "
                        "transition, payload, "
                        "payload_canonical_hash, signature, canonical_envelope) "
                        "VALUES (%s, %s, 'work_item', %s, 'sha-256', "
                        "%s, %s, 'agent:worker', 'agent', NULL, 'test-key', "
                        "'test_workflow', 1, now(), 'escalated', NULL, "
                        "'\\x00', '\\x00', '\\x00')",
                        [
                            str(uuid.uuid4()),
                            str(wi_id),
                            str(wi_id),
                            len(all_events) + 1,
                            next_global_seq,
                        ],
                    )
                    writer_conn.execute(
                        "UPDATE work_items_current SET current_state = 'review', "
                        "last_event_seq = %s WHERE work_item_id = %s",
                        [len(all_events) + 1, str(wi_id)],
                    )
                    writer_conn.commit()

                all_events_after = replay_conn.execute(
                    SQL("SELECT transition FROM events WHERE work_item_id = %s ORDER BY event_seq"),
                    [wi_id],
                ).fetchall()

                assert len(all_events_after) == event_count_before

                live_row = replay_conn.execute(
                    SQL(
                        "SELECT current_state, last_event_seq "
                        "FROM work_items_current WHERE work_item_id = %s"
                    ),
                    [wi_id],
                ).fetchone()

                assert live_row["last_event_seq"] == event_count_before
        finally:
            sub.close()
            drop_project_schema(DSN, project)
