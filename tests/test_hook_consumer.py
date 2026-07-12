from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

WORKFLOW_WITH_HOOKS = """\
name: hook_test
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
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []

attempt_threshold: 99
"""


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_hookcons_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow(WORKFLOW_WITH_HOOKS)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestHookConsumerLifecycle:
    def test_start_and_stop_hook_consumer(self, regista):
        regista.start_hook_consumer()
        assert regista._hook_consumer.is_running
        regista.stop_hook_consumer()
        assert not regista._hook_consumer.is_running

    def test_start_idempotent(self, regista):
        regista.start_hook_consumer()
        regista.start_hook_consumer()
        assert regista._hook_consumer.is_running
        regista.stop_hook_consumer()

    def test_stop_idempotent(self, regista):
        regista.stop_hook_consumer()
        regista.stop_hook_consumer()
        assert not regista._hook_consumer.is_running


class TestBC227ProcessingFlagReset:
    """BC-227: _processing must be False after _run exits regardless of path."""

    def _make_consumer(self):
        from regista._hooks import HookConsumer
        from regista._keys import KeySet

        key_set = MagicMock(spec=KeySet)
        return HookConsumer(
            dsn="postgresql://localhost/fake",
            schema="public",
            project="test",
            handlers={},
            key_set=key_set,
            metrics=None,
            poll_interval=0.1,
        )

    def test_processing_false_after_connect_exhaustion(self):
        # BC-232: drive the real _run() rather than reimplementing the loop.
        # _max_reconnect_attempts=1 and _reconnect_backoff_base=0 keep the test
        # fast without changing the production exhaustion path.
        consumer = self._make_consumer()
        consumer._max_reconnect_attempts = 1
        consumer._reconnect_backoff_base = 0.0

        with patch.object(consumer, "_connect", side_effect=ConnectionError("refused")):
            t = threading.Thread(target=consumer._run, daemon=True)
            t.start()
            t.join(timeout=3)
            assert not t.is_alive(), "_run did not exit"

        assert not consumer._processing, "_processing should be False after connect exhaustion"

    def test_processing_false_after_stop_during_connect_loop(self):
        consumer = self._make_consumer()
        # Signal stop immediately so the connect loop exits with conn=None.
        consumer._stop.set()

        with patch.object(consumer, "_connect", side_effect=ConnectionError("refused")):
            t = threading.Thread(target=consumer._run, daemon=True)
            t.start()
            t.join(timeout=3)

        assert not consumer._processing, (
            "_processing should be False when stopped during connect loop"
        )


class TestWI203ConnectedFlag:
    """WI-203: is_running must return False when the connection is lost or
    exhausted, even if _processing is still True."""

    def _make_consumer(self):
        from regista._hooks import HookConsumer
        from regista._keys import KeySet

        key_set = MagicMock(spec=KeySet)
        return HookConsumer(
            dsn="postgresql://localhost/fake",
            schema="public",
            project="test",
            handlers={},
            key_set=key_set,
            metrics=None,
            poll_interval=0.1,
        )

    def test_is_running_false_after_connect_exhaustion(self):
        consumer = self._make_consumer()
        consumer._max_reconnect_attempts = 1
        consumer._reconnect_backoff_base = 0.0

        with patch.object(consumer, "_connect", side_effect=ConnectionError("refused")):
            t = threading.Thread(target=consumer._run, daemon=True)
            t.start()
            t.join(timeout=3)
            assert not t.is_alive(), "_run did not exit"

        assert not consumer._connected
        assert not consumer.is_running

    def test_is_running_false_during_connection_loss(self):
        consumer = self._make_consumer()
        consumer._max_reconnect_attempts = 2
        consumer._reconnect_backoff_base = 0.0

        import psycopg

        real_conn = MagicMock()
        real_conn.notifies.side_effect = psycopg.OperationalError("connection lost")
        real_conn.close = MagicMock()
        real_conn.transaction = MagicMock()

        call_count = [0]

        def fake_connect():
            call_count[0] += 1
            if call_count[0] == 1:
                consumer._connected = True
                return real_conn
            raise ConnectionError("reconnect refused")

        with patch.object(consumer, "_connect", side_effect=fake_connect):
            t = threading.Thread(target=consumer._run, daemon=True)
            t.start()
            t.join(timeout=5)
            assert not t.is_alive(), "_run did not exit"

        assert not consumer._connected
        assert not consumer.is_running

    def test_is_running_false_during_reconnect_attempt(self):
        consumer = self._make_consumer()
        consumer._max_reconnect_attempts = 3
        consumer._reconnect_backoff_base = 0.0

        import psycopg

        real_conn = MagicMock()
        real_conn.notifies.side_effect = psycopg.OperationalError("connection lost")
        real_conn.close = MagicMock()
        real_conn.transaction = MagicMock()

        connect_calls = [0]
        barrier = threading.Event()

        def fake_connect():
            connect_calls[0] += 1
            if connect_calls[0] == 1:
                consumer._connected = True
                return real_conn
            barrier.set()
            raise ConnectionError("reconnect in progress")

        with patch.object(consumer, "_connect", side_effect=fake_connect):
            t = threading.Thread(target=consumer._run, daemon=True)
            t.start()
            barrier.wait(timeout=5)

            assert not consumer._connected
            assert not consumer.is_running

            consumer._stop.set()
            t.join(timeout=5)


class TestHookConsumerDelivery:
    def test_consumer_polls_hooks_after_start(self, regista):
        received: list = []

        def handler(ctx):
            received.append(ctx)

        regista.register_hook_handler("on_finish", handler)
        regista.start_hook_consumer()
        time.sleep(0.3)

        wi, _ = regista.create_work_item(
            workflow_name="hook_test",
            work_item_type="task",
            actor_id="agent-1",
            custom_fields={"title": "consumer test"},
        )
        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="finish",
            actor_id="agent-1",
        )

        deadline = time.time() + 15
        while not received and time.time() < deadline:
            regista.poll_hooks()
            time.sleep(0.5)

        regista.stop_hook_consumer()

        assert len(received) >= 1
        ctx = received[0]
        assert ctx.hook_name == "on_finish"
        assert ctx.work_item_id == wi.work_item_id
        assert ctx.transition == "finish"
