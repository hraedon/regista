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


def _write_keys(tmp_path, keys_data):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps(keys_data))
    return str(p)


ACTOR = "agent:worker"


@pytest.fixture
def ed_regista(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    # `make_v6_keyset` is itself an Ed25519 keyset — one actor-role key per
    # principal — so it replaces `test_keys_ed25519.json` without weakening what
    # this module is about. That file's single key has no `principal_id`, which the
    # v6 writer refuses (ACTOR_SIGNER_MISMATCH).
    project = f"test_ed_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(sub, keyset)
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
            actor_id=ACTOR,
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
            actor_id=ACTOR,
            custom_fields={"title": "ed25519 transition"},
        )
        ed_regista.transition(
            wi.work_item_id, "start", ACTOR,
            actor_metadata={"role": "agent"},
        )
        events = ed_regista.read_events(work_item_id=wi.work_item_id)
        assert any(e.scheme_id == "ed25519" for e in events)

    def test_replay_verifies_ed25519_signatures(self, ed_regista):
        ed_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
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

    def test_in_memory_ed25519_lifecycle(self, tmp_path):
        from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

        keyset = make_v6_keyset(tmp_path)
        sub = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(sub, keyset)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
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

        _KeySet(kf)
        from regista._signing_scheme import Ed25519Scheme

        scheme = Ed25519Scheme()
        with pytest.raises(RegistaError, match=r"ed25519.*PyNaCl"):
            scheme.sign(b"envelope", b"key-material")

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
