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


def _actor_key_entry(key) -> dict:
    """The keyset-file shape of a ``_v6_fixtures.TestKey``."""

    import base64

    return {
        "key_id": key.key_id,
        "scheme": "ed25519",
        "alg": "Ed25519",
        "secret": base64.b64encode(key.seed).decode("ascii"),
        "encoding": "base64",
        "public_key": key.public_key_b64,
        "principal_id": key.principal_id,
        "role": "actor",
        "status": "active",
    }


def _two_actor_keys(tmp_path):
    """A keyset in which ``agent:worker`` holds TWO Ed25519 actor keys.

    ``make_v6_keyset`` is one key per principal by construction — it derives the
    key id from the principal id — so the second key is built here and both are
    written into a single file. Ordering is load-bearing:
    ``_keys.select_signing_key_id`` picks the LAST active asymmetric entry for a
    principal, so the file below puts the *pinned* key first and the *default*
    key last. That is what makes "pinning overrides the default" a real
    assertion rather than a tautology.
    """

    from nacl.signing import SigningKey

    from tests._v6_fixtures import (
        BOOTSTRAP_PRINCIPAL,
        TestKey,
        V6TestKeyset,
        make_v6_keyset,
    )

    base = make_v6_keyset(tmp_path)
    signing_key = SigningKey.generate()
    pinned = TestKey(
        principal_id="agent:worker",
        key_id="pk_agent_worker_pinned",
        seed=bytes(signing_key),
        public_key=bytes(signing_key.verify_key),
    )

    default_key_id = base.key_for("agent:worker").key_id
    entries = json.loads(Path(base.path).read_text(encoding="utf-8"))["keys"]
    default_entry = [e for e in entries if e["key_id"] == default_key_id]
    rest = [e for e in entries if e["key_id"] != default_key_id]
    merged = tmp_path / "v6_keys_two_actor.json"
    merged.write_text(
        json.dumps({"keys": [*rest, _actor_key_entry(pinned), *default_entry]}, indent=2),
        encoding="utf-8",
    )

    pinned_keyset = V6TestKeyset(
        path=str(merged),
        keys={BOOTSTRAP_PRINCIPAL: base.bootstrap, "agent:worker": pinned},
    )
    return merged, base, pinned_keyset, default_key_id, pinned.key_id


def _open_two_key_epoch(instance, base, pinned_keyset):
    """Open the epoch and accept BOTH of ``agent:worker``'s keys.

    The key-binding anchor is per ``(principal_id, key_id)``, so a second key
    that is only present in the file is refused with ``KEY_BINDING_UNRESOLVED``.
    It needs its own standalone ``principal_key_accepted``.
    """

    from tests._v6_fixtures import accept_key, open_v6_epoch

    genesis = open_v6_epoch(instance, base)
    accept_key(instance, pinned_keyset, genesis, "agent:worker")
    return genesis


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

    def test_replay_accepts_deprecated_key(self, regista, v6_keyset, tmp_path):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "AC-16 deprecated replay"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        key_id = events[0].key_id
        assert key_id == v6_keyset.key_for("agent:worker").key_id

        # The whole keyset, with the writer's entry marked deprecated. A one-key
        # HMAC file (the v5 shape) would make genesis and the key acceptances
        # unverifiable too, which is a different subject: the claim here is that a
        # DEPRECATED key still replays clean.
        dep_entries = []
        for principal_id, key in v6_keyset.keys.items():
            entry = _actor_key_entry(key)
            if principal_id == "agent:worker":
                entry["status"] = "deprecated"
            dep_entries.append(entry)
        dep_ks = KeySet(str(_write_key_file(tmp_path / "deprecated_keys.json", dep_entries)))

        with raw_transaction(regista) as conn:
            report = replay_fn(
                conn, regista._mgr.schema, regista.project,
                dep_ks, continue_on_revoked=True,
            )
        assert report.halted == 0
        assert report.replayed_ok >= 1
        assert report.replayed_drift == 0


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
def v6_keyset(tmp_path):
    from tests._v6_fixtures import make_v6_keyset

    return make_v6_keyset(tmp_path)


@pytest.fixture
def regista(v6_keyset):
    from regista import Regista
    from tests._v6_fixtures import open_v6_epoch

    project = f"test_ac16_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, v6_keyset.path)
    # `register_workflow_file` emits a signed `workflow_registered` event, so the
    # epoch has to be open first.
    open_v6_epoch(sub, v6_keyset)
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

        merged, base, pinned_keyset, default_key_id, pinned_key_id = _two_actor_keys(
            tmp_path
        )
        project = f"test_wi227_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, str(merged))
        _open_two_key_epoch(sub, base, pinned_keyset)
        sub.register_workflow_file(WORKFLOW_PATH)
        yield sub, default_key_id, pinned_key_id
        sub.close()
        drop_project_schema(DSN, project)

    def test_create_pins_key_id(self, multi_key_sub):
        sub, default_key_id, pinned_key_id = multi_key_sub
        _wi, evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "pin-second-key"},
            key_id=pinned_key_id,
        )
        assert evt.key_id == pinned_key_id
        assert evt.key_id != default_key_id

    def test_create_defaults_to_active_key(self, multi_key_sub):
        sub, default_key_id, pinned_key_id = multi_key_sub
        _wi, evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "default-key"},
        )
        assert evt.key_id == default_key_id
        assert evt.key_id != pinned_key_id

    def test_create_rejects_unknown_key_id(self, multi_key_sub):
        sub, _default_key_id, _pinned_key_id = multi_key_sub
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent:worker",
                custom_fields={"title": "bad-key"},
                key_id="nonexistent",
            )
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_facade_create_pins_key_id(self, multi_key_sub):
        sub, default_key_id, pinned_key_id = multi_key_sub
        _wi, evt = sub.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "facade-pin"},
            key_id=pinned_key_id,
        )
        assert evt.key_id == pinned_key_id
        assert evt.key_id != default_key_id

    def test_in_memory_create_pins_key_id(self, tmp_path):
        from regista.testing import InMemoryRegista

        merged, base, pinned_keyset, default_key_id, pinned_key_id = _two_actor_keys(
            tmp_path
        )
        sub = InMemoryRegista(project="wi227_im", hmac_key_path=str(merged))
        _open_two_key_epoch(sub, base, pinned_keyset)
        sub.register_workflow_file(WORKFLOW_PATH)
        _wi, evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "im-pin"},
            key_id=pinned_key_id,
        )
        assert evt.key_id == pinned_key_id
        assert evt.key_id != default_key_id
