from __future__ import annotations

import os
import uuid

import pytest

from regista import Regista, RegistaError
from regista._errors import ErrorCode
from regista._integrity import REGISTA_VERSION
from regista._testing import raw_transaction

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _resolve_dsn() -> str:
    try:
        import conftest
    except ImportError:
        return os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN)
    return getattr(conftest, "DSN", os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN))


DSN = _resolve_dsn()

WORKFLOW_NAME = "kernel_replay_wf"
ACTOR = "agent:replayer"

WF_YAML = f"""
name: {WORKFLOW_NAME}
version: 1
regista_version: "{REGISTA_VERSION}"
states:
  - name: new
    initial: true
  - name: in_progress
  - name: done
    terminal: true
transitions:
  - name: start
    from: new
    to: in_progress
  - name: finish
    from: in_progress
    to: done
roles: []
work_item_types:
  - name: task
    custom_fields: []
"""


def _seed(sub: Regista) -> uuid.UUID:
    sub.register_workflow(WF_YAML)
    wi, _ = sub.create_work_item(
        workflow_name=WORKFLOW_NAME,
        work_item_type="task",
        actor_id=ACTOR,
    )
    sub.transition(wi.work_item_id, "start", ACTOR)
    return wi.work_item_id


def test_replay_reports_ok(sub: Regista) -> None:
    work_item_id = _seed(sub)
    report = sub.replay(work_item_id=work_item_id)

    assert report.replayed_ok >= 1
    assert report.replayed_drift == 0
    assert report.halted == 0
    assert any(entry.category == "ok" for entry in report.entries)


def test_scoped_replay_only_covers_the_named_item(sub: Regista) -> None:
    work_item_id = _seed(sub)
    report = sub.replay(work_item_id=work_item_id)

    assert len(report.entries) >= 1
    assert all(entry.work_item_id == work_item_id for entry in report.entries)


def test_injected_projection_drift_is_reported(sub: Regista) -> None:
    work_item_id = _seed(sub)

    with raw_transaction(sub) as conn:
        conn.execute(
            "UPDATE work_items_current SET current_state = 'bogus_state' "
            "WHERE work_item_id = %s",
            [work_item_id],
        )

    report = sub.replay(work_item_id=work_item_id)

    assert report.replayed_drift >= 1
    drift_entries = [e for e in report.entries if e.category == "drift"]
    assert drift_entries
    assert any(
        e.detail is not None and "current_state" in e.detail for e in drift_entries
    )


def test_scoped_replay_unknown_id_raises(sub: Regista) -> None:
    with pytest.raises(RegistaError) as exc_info:
        sub.replay(work_item_id=uuid.uuid4())
    assert exc_info.value.code is ErrorCode.WORK_ITEM_NOT_FOUND
