from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from _helpers import DSN, KEY_PATH

from regista import Regista
from regista._principal_keys import get_active_key, principal_entity_id
from regista._provision import provision_principal
from regista.testing import drop_project_schema

PYTHON = sys.executable


def _run_cli(*args, env=None):
    base_env = {
        "REGISTA_DSN": DSN,
        "REGISTA_HMAC_KEY_PATH": KEY_PATH,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if env:
        base_env.update(env)
    return subprocess.run(
        [PYTHON, "-m", "regista._cli", *args],
        capture_output=True,
        text=True,
        env=base_env,
        timeout=30,
    )


@pytest.fixture
def enroll_instance(tmp_path):
    key_path = tmp_path / "keys.json"
    shutil.copy(KEY_PATH, key_path)
    project = f"test_enroll_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, str(key_path))
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestEnrollPrincipal:
    def test_new_enrollment_issues_keypair_and_emits_event(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"enroll.test.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        result = sub.enroll_principal(
            principal_id,
            private_key_dir=private_key_dir,
        )

        assert result["principal_id"] == principal_id
        assert result["project"] == sub.project
        assert result["scheme"] == "ed25519"
        assert result["private_key_stored"] is True
        assert result["public_key_registered"] is True
        assert result["already_existed"] is False
        assert "private_key" not in result

        entry = get_active_key(sub._mgr, principal_id)
        assert entry.key_id == result["key_id"]
        assert entry.fingerprint == result["fingerprint"]
        assert entry.scheme == "ed25519"

        priv_path = Path(private_key_dir) / f"{principal_id}_ed25519.key"
        assert priv_path.is_file()
        assert priv_path.stat().st_mode & 0o777 == 0o600
        private_key = priv_path.read_bytes()
        assert len(private_key) == 32

        key_data = json.loads(Path(sub._hmac_key_path).read_text())
        matches = [
            k for k in key_data["keys"]
            if k.get("principal_id") == principal_id and k.get("key_id") == result["key_id"]
        ]
        assert len(matches) == 1
        assert matches[0]["scheme"] == "ed25519"
        assert matches[0]["status"] == "active"
        assert matches[0].get("secret_ref", "").startswith("file:")

        events = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events) == 1
        evt = events[0]
        assert evt.entity_kind == "principal"
        assert evt.transition == "principal_enrolled"
        assert evt.actor_id == "system"
        assert evt.actor_kind == "system"
        payload = evt.payload or {}
        assert payload["principal_id"] == principal_id
        assert payload["key_id"] == result["key_id"]
        assert payload["fingerprint"] == result["fingerprint"]
        assert payload["scheme"] == "ed25519"

    def test_idempotent_re_enroll_no_duplicate_event(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"enroll.idem.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        result1 = sub.enroll_principal(
            principal_id,
            private_key_dir=private_key_dir,
        )
        events1 = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events1) == 1

        result2 = sub.enroll_principal(
            principal_id,
            private_key_dir=private_key_dir,
        )
        events2 = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events2) == 1

        assert result2["already_existed"] is True
        assert result2["key_id"] == result1["key_id"]
        assert result2["fingerprint"] == result1["fingerprint"]
        assert result2["private_key_stored"] is False
        assert result2["public_key_registered"] is False
        assert events1[0].event_id == events2[0].event_id

    def test_self_heal_re_emits_event_after_gap(self, enroll_instance, tmp_path):
        from regista._testing import raw_transaction

        sub = enroll_instance
        principal_id = f"enroll.heal.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        result1 = sub.enroll_principal(principal_id, private_key_dir=private_key_dir)
        assert len(sub.read_principal_enrollment_events(principal_id=principal_id)) == 1

        eid = principal_entity_id(principal_id)
        with raw_transaction(sub) as conn:
            conn.execute(
                "DELETE FROM events WHERE entity_kind = 'principal' AND entity_id = %s",
                [eid],
            )
        assert len(sub.read_principal_enrollment_events(principal_id=principal_id)) == 0

        result2 = sub.enroll_principal(principal_id, private_key_dir=private_key_dir)
        events2 = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events2) == 1
        assert events2[0].payload["key_id"] == result1["key_id"]
        assert result2["already_existed"] is True

    def test_does_not_break_replay(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"enroll.replay.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        sub.enroll_principal(principal_id, private_key_dir=private_key_dir)

        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_enroll_principal_entity_id_stable(self, enroll_instance):
        sub = enroll_instance
        principal_id = f"enroll.entity.{uuid.uuid4().hex[:8]}"
        entity_id = principal_entity_id(principal_id)

        sub.enroll_principal(principal_id)

        events = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events) == 1
        assert events[0].effective_entity_id == entity_id


class TestEnrollPrincipalCLI:
    def test_cli_enroll_principal(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"enroll.cli.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        result = _run_cli(
            "--project", sub.project,
            "--hmac-key-path", sub._hmac_key_path,
            "--json",
            "principal", "enroll",
            "--principal", principal_id,
            "--private-key-dir", private_key_dir,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["principal_id"] == principal_id
        assert data["already_existed"] is False
        assert data["scheme"] == "ed25519"
        assert "private_key" not in data

        events = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events) == 1
        assert events[0].transition == "principal_enrolled"

    def test_cli_enroll_idempotent(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"enroll.cli.idem.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        _run_cli(
            "--project", sub.project,
            "--hmac-key-path", sub._hmac_key_path,
            "--json",
            "principal", "enroll",
            "--principal", principal_id,
            "--private-key-dir", private_key_dir,
        )
        result2 = _run_cli(
            "--project", sub.project,
            "--hmac-key-path", sub._hmac_key_path,
            "--json",
            "principal", "enroll",
            "--principal", principal_id,
            "--private-key-dir", private_key_dir,
        )
        assert result2.returncode == 0, result2.stderr
        data = json.loads(result2.stdout)
        assert data["already_existed"] is True

        events = sub.read_principal_enrollment_events(principal_id=principal_id)
        assert len(events) == 1


class TestProvisionPrincipalScheme:
    def test_provision_principal_returns_scheme(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"provision.scheme.{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        result = provision_principal(
            DSN,
            sub.project,
            principal_id,
            hmac_key_path=sub._hmac_key_path,
            private_key_dir=private_key_dir,
        )

        assert result.scheme == "ed25519"
