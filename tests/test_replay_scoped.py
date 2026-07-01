from __future__ import annotations

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@contextmanager
def backend(backend_name: str) -> Generator[Regista | InMemoryRegista, None, None]:
    if backend_name == "postgres":
        project = f"test_scoped_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            yield sub
        finally:
            sub.close()
            drop_project_schema(DSN, project)
    else:
        sub = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        yield sub


def _create_and_transition(sub: Regista | InMemoryRegista) -> uuid.UUID:
    sub.register_actor_role("agent-1", "agent")
    sub.register_actor_role("reviewer-1", "reviewer")
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "agent-1",
        custom_fields={"title": "scoped replay"},
    )
    sub.transition(
        wi.work_item_id, "start", "agent-1",
        actor_metadata={"role": "agent"},
    )
    sub.transition(
        wi.work_item_id, "submit_review", "agent-1",
        actor_metadata={"role": "agent"},
    )
    return wi.work_item_id


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_ok(backend_name):
    with backend(backend_name) as sub:
        wid = _create_and_transition(sub)
        report = sub.replay(work_item_id=wid)
        assert report.replayed_ok == 1
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == 0


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_detects_drift(backend_name):
    with backend(backend_name) as sub:
        wid = _create_and_transition(sub)
        if isinstance(sub, Regista):
            with raw_transaction(sub) as conn:
                conn.execute(
                    "UPDATE work_items_current SET current_state = 'tampered_state' "
                    "WHERE work_item_id = %s",
                    [wid],
                )
        else:
            sub._work_items[wid]["current_state"] = "tampered_state"
        report = sub.replay(work_item_id=wid)
        assert report.replayed_ok == 0
        assert report.replayed_drift == 1
        assert report.halted == 0


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_unknown_work_item_raises(backend_name):
    with backend(backend_name) as sub:
        unknown = uuid.uuid4()
        with pytest.raises(RegistaError) as exc_info:
            sub.replay(work_item_id=unknown)
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_skips_global_verification(backend_name):
    with backend(backend_name) as sub:
        wid = _create_and_transition(sub)
        sub.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "second"},
        )
        full_report = sub.replay()
        scoped_report = sub.replay(work_item_id=wid)
        assert full_report.warnings == 0
        assert scoped_report.warnings == 0
        assert scoped_report.replayed_ok == 1
        assert scoped_report.replayed_drift == 0


def test_full_replay_unchanged_when_work_item_id_none():
    with backend("postgres") as sub:
        _create_and_transition(sub)
        sub.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "full replay regression"},
        )
        report = sub.replay()
        assert report.replayed_ok == 2
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == 0


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_inmemory_full_replay_regression(backend_name):
    with backend(backend_name) as sub:
        _create_and_transition(sub)
        report = sub.replay()
        assert report.replayed_ok == 1
        assert report.replayed_drift == 0
        assert report.halted == 0


@pytest.mark.parametrize("backend_name", ["postgres", "inmemory"])
def test_scoped_replay_projection_row_missing_reports_corruption(backend_name):
    with backend(backend_name) as sub:
        wid = _create_and_transition(sub)
        if isinstance(sub, Regista):
            with raw_transaction(sub) as conn:
                conn.execute(
                    "DELETE FROM work_items_current WHERE work_item_id = %s",
                    [wid],
                )
        else:
            del sub._work_items[wid]
        report = sub.replay(work_item_id=wid)
        assert report.halted == 1
        assert report.replayed_ok == 0
        assert report.replayed_drift == 0
