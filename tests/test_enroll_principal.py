from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid

import pytest
from _helpers import DSN, KEY_PATH

from regista import Regista
from regista._errors import ErrorCode, RegistaError
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


class TestEnrollPrincipalIsRefusedPendingSignedEnrolment:
    """`enroll_principal` delegates to `provision_principal`, which P2.2 refuses.

    Until P2.2, enrolment minted a keypair, wrote ``principal_keys`` directly, and
    then appended a ``principal_enrolled`` event **afterwards, in a separate
    transaction** (`_api_meta.py:430-446`) — so the row could exist with no event,
    and the event carried no public key bytes (§5.1 Defect A). §5.9 rule 2 closes
    the write; §5.5 replaces the event with one that carries the key material.

    These tests previously asserted the old behaviour and were epoch-blocked on
    P1.7. They are no longer blocked *by the v6-writer guard* — reverting that guard
    would not make them pass — so they left the manifest and now assert what 0.6.0
    actually does. Their former node ids are recorded in
    ``tests/retired_tests_ledger.json`` with ``coverage_owed``: the invariants come
    back as signed ``principal_key_enrolled`` events under P1.7.
    """

    def test_enrolment_is_refused_by_name(self, enroll_instance, tmp_path):
        sub = enroll_instance
        principal_id = f"agent:enroll-test-{uuid.uuid4().hex[:8]}"

        with pytest.raises(RegistaError) as exc_info:
            sub.enroll_principal(
                principal_id,
                private_key_dir=str(tmp_path / "principals"),
            )
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["blocked_on"]

    def test_the_refusal_writes_no_row_and_emits_no_event(
        self, enroll_instance, tmp_path,
    ):
        """The property that matters: no half-enrolled state.

        The old failure mode was a registry row with no event. The new one must be
        neither a row nor an event nor a private key.
        """
        sub = enroll_instance
        principal_id = f"agent:enroll-none-{uuid.uuid4().hex[:8]}"
        private_key_dir = tmp_path / "principals"

        with pytest.raises(RegistaError):
            sub.enroll_principal(principal_id, private_key_dir=str(private_key_dir))

        with pytest.raises(RegistaError):
            get_active_key(sub._mgr, principal_id)
        assert sub.read_principal_enrollment_events(principal_id=principal_id) == []
        assert not private_key_dir.exists() or not any(private_key_dir.iterdir())

    def test_the_principal_entity_id_derivation_is_unchanged(self, enroll_instance):
        """§5.2: keep the v1 derivation. Do not "fix" it.

        Changing it would orphan the ``principal_enrolled`` events already written.
        This is the one part of the old enrolment surface that must not move, so it
        is asserted directly rather than through an enrolment that now refuses.
        """
        principal_id = f"agent:enroll-entity-{uuid.uuid4().hex[:8]}"
        import uuid as _uuid

        assert principal_entity_id(principal_id) == _uuid.uuid5(
            _uuid.NAMESPACE_OID, f"principal:{principal_id}"
        )
        # Stable across calls, and distinct per principal.
        assert principal_entity_id(principal_id) == principal_entity_id(principal_id)
        assert principal_entity_id(principal_id) != principal_entity_id(
            principal_id + "x"
        )

    def test_replay_is_unaffected_by_a_refused_enrolment(
        self, enroll_instance, tmp_path,
    ):
        sub = enroll_instance
        principal_id = f"agent:enroll-replay-{uuid.uuid4().hex[:8]}"
        with pytest.raises(RegistaError):
            sub.enroll_principal(
                principal_id, private_key_dir=str(tmp_path / "principals"),
            )
        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestEnrollPrincipalCLIIsRefused:
    def test_cli_enroll_exits_nonzero_with_the_named_error(
        self, enroll_instance, tmp_path,
    ):
        sub = enroll_instance
        principal_id = f"agent:enroll-cli-{uuid.uuid4().hex[:8]}"

        result = _run_cli(
            "--project", sub.project,
            "--hmac-key-path", sub._hmac_key_path,
            "--json",
            "principal", "enroll",
            "--principal", principal_id,
            "--private-key-dir", str(tmp_path / "principals"),
        )
        assert result.returncode != 0
        assert "PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED" in (
            result.stdout + result.stderr
        )
        assert sub.read_principal_enrollment_events(principal_id=principal_id) == []


class TestProvisionPrincipalScheme:
    def test_provision_principal_is_refused_pending_signed_enrolment(
        self, enroll_instance, tmp_path,
    ):
        """P2.2 / §5.9 rule 2: provisioning wrote the projection with no event.

        Not epoch-blocked on P1.7 like its siblings in this file — this one asserts
        the *refusal*, which is present now. When P1.7 lands and enrolment becomes a
        signed `principal_key_enrolled` event, this test is what must change.
        """
        sub = enroll_instance
        principal_id = f"agent:provision-scheme-{uuid.uuid4().hex[:8]}"
        private_key_dir = str(tmp_path / "principals")

        with pytest.raises(RegistaError) as exc_info:
            provision_principal(
                DSN,
                sub.project,
                principal_id,
                hmac_key_path=sub._hmac_key_path,
                private_key_dir=private_key_dir,
            )
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["blocked_on"]

    def test_dry_run_still_reports_the_scheme_without_writing(
        self, enroll_instance, tmp_path,
    ):
        """The dry-run path never wrote anything, so it is unaffected by the refusal."""
        sub = enroll_instance
        result = provision_principal(
            DSN,
            sub.project,
            f"agent:provision-dry-{uuid.uuid4().hex[:8]}",
            hmac_key_path=sub._hmac_key_path,
            private_key_dir=str(tmp_path / "principals"),
            dry_run=True,
        )
        assert result.scheme == "ed25519"
        assert result.private_key_stored is False
        assert result.public_key_registered is False
