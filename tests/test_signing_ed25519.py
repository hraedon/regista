from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista._testing import KeySet, get_scheme
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
ED_KEY_PATH = str(TESTS_DIR / "test_keys_ed25519.json")
COMBINED_KEY_PATH = str(TESTS_DIR / "test_keys_combined.json")


def _write_keys(tmp_path, keys_data):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps(keys_data))
    return str(p)


@pytest.fixture
def ed_regista():
    from regista import Regista

    project = f"test_ed_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, ED_KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture
def combined_regista():
    from regista import Regista

    project = f"test_comb_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, COMBINED_KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.mark.skipif(
    not pytest.importorskip("nacl.signing", reason="PyNaCl not installed"),
    reason="PyNaCl not installed",
)
class TestEd25519PostgresIntegration:
    def test_create_and_read_ed25519_event(self, ed_regista):
        wi, _ = ed_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ed25519 test"},
        )
        events = ed_regista.read_events(work_item_id=wi.work_item_id)
        assert len(events) >= 1
        created_evt = events[-1]
        assert created_evt.scheme_id == "ed25519"

    def test_transition_produces_ed25519_scheme_id(self, ed_regista):
        wi, _ = ed_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ed25519 transition"},
        )
        ed_regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        events = ed_regista.read_events(work_item_id=wi.work_item_id)
        assert any(e.scheme_id == "ed25519" for e in events)

    def test_replay_verifies_ed25519_signatures(self, ed_regista):
        ed_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ed25519 replay"},
        )
        report = ed_regista.replay()
        assert report.halted == 0, f"Replay failed: {report.entries}"

    def test_ed25519_key_scheme_resolution(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-001",
                    "secret": "lVv8seYO5jZLwduGJdVh3qG5tTA9PzOeFTAKUmWQPVg=",
                    "status": "active",
                    "scheme": "ed25519",
                }
            ]
        })
        ks = KeySet(kf)
        entry = ks.active_key()
        assert entry.scheme == "ed25519"
        scheme = get_scheme("ed25519")
        assert scheme.scheme_id == "ed25519"

    def test_in_memory_ed25519_lifecycle(self):
        sub = InMemoryRegista(project="test", hmac_key_path=ED_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ed25519 in-mem"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "ed25519"
        report = sub.replay()
        assert report.halted == 0


@pytest.mark.skipif(
    not pytest.importorskip("nacl.signing", reason="PyNaCl not installed"),
    reason="PyNaCl not installed",
)
class TestEd25519KeyRotation:
    def test_replay_handles_mixed_schemes(self, combined_regista):
        combined_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "rotation test"},
        )
        report = combined_regista.replay()
        assert report.halted == 0, f"Replay failed with mixed schemes: halted={report.halted}"

    def test_events_signed_with_active_key_scheme(self, combined_regista):
        wi, _ = combined_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "active scheme test"},
        )
        events = combined_regista.read_events(work_item_id=wi.work_item_id)
        assert events[-1].scheme_id == "ed25519"

    def test_key_set_reports_both_schemes(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "deprecated",
                    "scheme": "hmac-sha256",
                },
                {
                    "key_id": "ed-001",
                    "secret": "QgQvfKgA6y6h3uO72gP8k5V9QIdAy89BB2TH4nFkm88=",
                    "status": "active",
                    "scheme": "ed25519",
                    "public_key": "iMZMllXSQnbuFzdpJdRgyJKD2qbPi5W6QAH5HsDvd3Y=",
                },
            ]
        })
        ks = KeySet(kf)
        active = ks.active_key()
        assert active.scheme == "ed25519"
        assert active.key_id == "ed-001"
        deprecated = ks.get_key("hmac-001")
        assert deprecated.scheme == "hmac-sha256"
        assert deprecated.status == "deprecated"


class TestEd25519KeyLoadErrors:
    def test_ed25519_without_pynacl_raises(self, tmp_path, monkeypatch):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-001",
                    "secret": "lVv8seYO5jZLwduGJdVh3qG5tTA9PzOeFTAKUmWQPVg=",
                    "status": "active",
                    "scheme": "ed25519",
                }
            ]
        })
        monkeypatch.setitem(__import__("sys").modules, "nacl", None)
        monkeypatch.setitem(__import__("sys").modules, "nacl.signing", None)
        from regista._keys import KeySet as _KeySet

        with pytest.raises(RegistaError, match=r"ed25519.*PyNaCl"):
            _KeySet(kf)

    def test_unknown_scheme_raises(self, tmp_path):
        from regista._errors import ErrorCode, RegistaError

        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "k1",
                    "secret": "c2VjcmV0",
                    "status": "active",
                    "scheme": "rsa-4096",
                }
            ]
        })
        with pytest.raises(RegistaError) as exc_info:
            KeySet(kf)
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
