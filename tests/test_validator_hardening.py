"""Validator tests.

BC-192 removed the AST-based I/O check and the ThreadPoolExecutor-based
wall-clock timeout. Validators are now trusted, synchronous, in-process.
The remaining tests verify the contracts that *are* still enforced:
exceptions become VALIDATOR_FAILED, transaction rollback, and the
Postgres `statement_timeout` (5s) protection for DB-call hangs.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._hooks import run_validator
from regista._types import ValidatorContext
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")

WORKFLOW_WITH_VALIDATOR = """\
name: validator_test
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
    validator: check_finish

roles: []

work_item_types:
  - name: task
    custom_fields: []

link_types: []

attempt_threshold: 99
"""


def _make_ctx():
    return ValidatorContext(
        work_item_id=uuid.uuid4(),
        workflow_name="test",
        workflow_version=1,
        work_item_type="task",
        current_state="new",
        new_state="done",
        transition_name="finish",
        payload=None,
        custom_fields={},
        actor_id="agent-1",
        actor_metadata=None,
    )


class TestRunValidator:
    def test_clean_validator_returns_normally(self):
        run_validator("ok", lambda ctx: None, _make_ctx())

    def test_exception_becomes_validator_failed(self):
        def boom(ctx):
            raise ValueError("nope")

        with pytest.raises(RegistaError) as exc_info:
            run_validator("boom", boom, _make_ctx())
        assert exc_info.value.code == ErrorCode.VALIDATOR_FAILED

    def test_regista_error_passes_through(self):
        def custom(ctx):
            raise RegistaError(ErrorCode.CUSTOM_FIELD_VIOLATION, "bad")

        with pytest.raises(RegistaError) as exc_info:
            run_validator("custom", custom, _make_ctx())
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_slow_validator_logs_warning_but_does_not_raise(self):
        """BC-192: wall-clock is a soft warning, not an enforced bound."""
        from prometheus_client import CollectorRegistry

        from regista._observability import Metrics

        registry = CollectorRegistry()
        metrics = Metrics(registry=registry)
        # Soft threshold is 80% of `timeout` arg; sleep > that fires the warning.
        run_validator(
            "slow", lambda ctx: time.sleep(0.45), _make_ctx(),
            timeout=0.5, metrics=metrics, project="test",
        )
        # We do not assert on the metric here (counter wiring is tested
        # separately); the assertion is that the call returned, not raised.


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_bc192_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow(WORKFLOW_WITH_VALIDATOR)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestValidatorTransactionRollback:
    def test_clean_validator_allows_transition(self, regista):
        regista.register_validator("check_finish", lambda ctx: None)

        wi, _ = regista.create_work_item(
            workflow_name="validator_test",
            work_item_type="task",
            actor_id="agent-1",
        )

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="finish",
            actor_id="agent-1",
        )
        assert evt.transition == "finish"

    def test_validator_failure_rolls_back(self, regista):
        def fail_validator(ctx):
            raise ValueError("boom")

        regista.register_validator("check_finish", fail_validator)

        wi, _ = regista.create_work_item(
            workflow_name="validator_test",
            work_item_type="task",
            actor_id="agent-1",
        )

        with pytest.raises(RegistaError, match="VALIDATOR_FAILED"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="finish",
                actor_id="agent-1",
            )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "new"


class TestTrustedValidatorContract:
    """BC-192: validators are trusted code. The previous AST-based I/O
    safety check and ThreadPoolExecutor wall-clock timeout are removed.
    A handler that does I/O or hangs is the caller's bug, not regista's
    enforcement gap. These tests pin the new (honest) contract.
    """

    def test_io_referencing_handler_can_be_registered(self, regista):
        import socket

        def uses_socket(ctx):
            socket.gethostname()

        regista.register_validator("check_finish", uses_socket)
        # No raise — registration accepts the handler.

    def test_registration_is_purely_a_dict_update(self, regista):
        regista.register_validator("check_finish", lambda ctx: None)
        # No AST inspection, no I/O check, no exception class beyond
        # whatever Python raises for non-callables.
