from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import (
    KeySet,
    raw_transaction,
    replay_fn,
    sign_event,
    verify_event,
)
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

SECRET = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl"


def _write_key_file(path: Path, keys: list[dict]) -> Path:
    path.write_text(json.dumps({"keys": keys}))
    return path


class TestUnknownKeyId:
    def test_get_key_rejects_unknown(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "known-1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc_info:
            ks.get_key("nonexistent-key")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_active_key_rejects_when_empty(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "revoked-1", "secret": SECRET, "status": "revoked"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc_info:
            ks.active_key()
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_verify_key_status_rejects_unknown(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "known-1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc_info:
            ks.verify_key_status("nonexistent-key")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_load_rejects_missing_file(self, tmp_path):
        with pytest.raises(RegistaError) as exc_info:
            KeySet(str(tmp_path / "nonexistent.json"))
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR

    def test_load_rejects_invalid_json(self, tmp_path):
        kf = tmp_path / "bad.json"
        kf.write_text("not json")
        with pytest.raises(RegistaError) as exc_info:
            KeySet(str(kf))
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR

    def test_load_rejects_missing_keys_field(self, tmp_path):
        kf = tmp_path / "nokeys.json"
        kf.write_text('{"not_keys": []}')
        with pytest.raises(RegistaError) as exc_info:
            KeySet(str(kf))
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR


class TestRevokedKeyId:
    def test_active_key_raises_unknown_when_only_revoked(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "rev-1", "secret": SECRET, "status": "revoked"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc_info:
            ks.active_key()
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_verify_key_status_rejects_revoked(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "active-1", "secret": SECRET, "status": "active"},
            {"key_id": "rev-1", "secret": SECRET, "status": "revoked"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(RegistaError) as exc_info:
            ks.verify_key_status("rev-1")
        assert exc_info.value.code == ErrorCode.REVOKED_KEY_ID

class TestDeprecatedKeyId:
    def test_verify_key_status_accepts_deprecated(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "active-1", "secret": SECRET, "status": "active"},
            {"key_id": "dep-1", "secret": SECRET, "status": "deprecated"},
        ])
        ks = KeySet(str(kf))
        entry = ks.verify_key_status("dep-1")
        assert entry.key_id == "dep-1"
        assert entry.status == "deprecated"

    def test_verify_key_status_accepts_active(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "active-1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.verify_key_status("active-1")
        assert entry.key_id == "active-1"
        assert entry.status == "active"

    def test_active_key_prefers_active_over_deprecated(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "dep-1", "secret": SECRET, "status": "deprecated"},
            {"key_id": "active-1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.active_key()
        assert entry.key_id == "active-1"

    def test_deprecated_key_used_for_signing(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "dep-1", "secret": SECRET, "status": "deprecated"},
            {"key_id": "active-1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.verify_key_status("dep-1")

        eid = uuid.uuid4()
        wid = uuid.uuid4()
        # WI-267: sign and verify must name the SAME instant. This test used to
        # call datetime.now(UTC) twice — the row it described carried a
        # different timestamp than the envelope signed, and verification did
        # not care, which is the defect in miniature.
        ts = datetime.now(UTC)
        sig, chash, envelope = sign_event(
            event_id=eid, work_item_id=wid, actor_id="test",
            key_id=entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=ts,
            transition="evt", payload=None, key=entry.secret,
        )
        assert verify_event(
            event_id=eid, work_item_id=wid, actor_id="test",
            key_id=entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=ts,
            transition="evt", payload=None, signature=sig,
            canonical_hash=chash, key=entry.secret,
            stored_envelope=envelope,
        )

    def test_replay_accepts_deprecated_key(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-16 deprecated replay"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        key_id = events[0].key_id

        dep_path = TESTS_DIR / f"_ac16_dep_{uuid.uuid4().hex[:8]}.json"
        try:
            _write_key_file(dep_path, [
                {"key_id": key_id, "secret": SECRET, "status": "deprecated"},
            ])
            dep_ks = KeySet(str(dep_path))

            with raw_transaction(regista) as conn:
                report = replay_fn(
                    conn, regista._mgr.schema, regista.project,
                    dep_ks, continue_on_revoked=True,
                )
            assert report.halted == 0
            assert report.replayed_ok >= 1
            assert report.replayed_drift == 0
        finally:
            dep_path.unlink(missing_ok=True)


class TestHotReload:
    def test_hot_reload_detects_new_key(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf), poll_interval=0.0)
        assert ks.get_key("k1").key_id == "k1"

        _write_key_file(kf, [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        import time
        time.sleep(0.01)

        assert ks.get_key("k2").key_id == "k2"

    def test_hot_reload_revokes_active_key(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf), poll_interval=0.0)

        _write_key_file(kf, [
            {"key_id": "k1", "secret": SECRET, "status": "revoked"},
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        import time
        time.sleep(0.01)

        with pytest.raises(RegistaError) as exc_info:
            ks.verify_key_status("k1")
        assert exc_info.value.code == ErrorCode.REVOKED_KEY_ID

        entry = ks.active_key()
        assert entry.key_id == "k2"


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_ac16_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestCreateWorkItemKeyId:
    """WI-227: create_work_item must accept key_id to pin the signing key on the
    event that opens a chain, mirroring append_event/transition."""

    @pytest.fixture
    def multi_key_sub(self, tmp_path):
        from regista import Regista

        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        project = f"test_wi227_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, str(kf))
        sub.register_workflow_file(WORKFLOW_PATH)
        yield sub
        sub.close()
        drop_project_schema(DSN, project)

    def test_create_pins_key_id(self, multi_key_sub):
        _wi, evt = multi_key_sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "pin-k2"},
            key_id="k2",
        )
        assert evt.key_id == "k2"

    def test_create_defaults_to_active_key(self, multi_key_sub):
        _wi, evt = multi_key_sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "default-key"},
        )
        assert evt.key_id == "k1"

    def test_create_rejects_unknown_key_id(self, multi_key_sub):
        with pytest.raises(RegistaError) as exc_info:
            multi_key_sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "bad-key"},
                key_id="nonexistent",
            )
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_facade_create_pins_key_id(self, multi_key_sub):
        _wi, evt = multi_key_sub.work_items.create(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "facade-pin"},
            key_id="k2",
        )
        assert evt.key_id == "k2"

    def test_in_memory_create_pins_key_id(self, tmp_path):
        from regista.testing import InMemoryRegista

        kf = _write_key_file(tmp_path / "im_keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        sub = InMemoryRegista(project="wi227_im", hmac_key_path=str(kf))
        sub.register_workflow_file(WORKFLOW_PATH)
        _wi, evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "im-pin"},
            key_id="k2",
        )
        assert evt.key_id == "k2"
