"""WI-223: cross-project principal-key collision must not read as green.

The defect: ``provision-principal`` for the same principal in two projects
mints two Ed25519 keypairs and appends both to the *same* ``keys.json``,
marking the earlier one ``deprecated``. The signer then selects a key by
principal_id with no project scoping, so every event written to project A is
signed with a key registered only in project B's ``principal_keys``.

Four surfaces reported green on such a chain; only ``bundle verify`` caught
it. These tests pin the two independent fixes:

1. ``provision_principal`` refuses to mint a second keypair for a principal
   that already has an active key in the shared key file, and
2. ``replay(verify_principal_binding=True)`` counts a failure when an event's
   ``key_id`` has no active row in *that project's* ``principal_keys`` — while
   still skipping actors with no registered keys at all (HMAC-only
   deployments).
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest
from _helpers import DSN, WORKFLOW_PATH

from regista import Regista
from regista._errors import ErrorCode, RegistaError


def _keypair() -> tuple[bytes, bytes]:
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def _write_priv(tmp_path: Path, name: str, sk: bytes) -> Path:
    path = tmp_path / f"{name}.key"
    path.write_bytes(sk)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _bootstrap_hmac_entry() -> dict:
    return {
        "key_id": "bootstrap-hmac",
        "secret": "dGVzdA==",
        "encoding": "base64",
        "status": "active",
    }


def _ed25519_entry(
    key_id: str,
    principal_id: str,
    priv_path: Path,
    public_key: bytes,
    status: str = "active",
) -> dict:
    return {
        "key_id": key_id,
        "scheme": "ed25519",
        "principal_id": principal_id,
        "secret_ref": f"file:{priv_path}",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "role": "actor",
        "status": status,
    }


@pytest.fixture
def cross_project_collision(tmp_path):
    """Reproduce the qual-linux state: project A's chain signed by B's key.

    ``keys.json`` holds two Ed25519 entries for one principal — A's key
    (``deprecated``, as ``_update_key_file`` leaves it) and B's key
    (``active``). Project A's ``principal_keys`` registers only A's key.
    The signer therefore picks B's key for every event written to A.
    """
    from regista.testing import drop_project_schema

    principal_id = f"wi223_agent_{uuid.uuid4().hex[:8]}"
    project_a = f"wi223_a_{uuid.uuid4().hex[:8]}"
    project_b = f"wi223_b_{uuid.uuid4().hex[:8]}"

    sk_a, vk_a = _keypair()
    sk_b, vk_b = _keypair()
    priv_a = _write_priv(tmp_path, f"{principal_id}_a", sk_a)
    priv_b = _write_priv(tmp_path, f"{principal_id}_b", sk_b)

    key_id_a = f"pk_a_{uuid.uuid4().hex[:8]}"
    key_id_b = f"pk_b_{uuid.uuid4().hex[:8]}"

    key_file = tmp_path / "keys.json"
    key_file.write_text(
        json.dumps(
            {
                "keys": [
                    _bootstrap_hmac_entry(),
                    # Project A's key, demoted by the second provisioning run.
                    _ed25519_entry(
                        key_id_a, principal_id, priv_a, vk_a, status="deprecated",
                    ),
                    # Project B's key — the one the signer will now pick.
                    _ed25519_entry(key_id_b, principal_id, priv_b, vk_b),
                ]
            }
        )
    )

    Regista.create_project(DSN, project_a, str(key_file))
    Regista.create_project(DSN, project_b, str(key_file))
    sub_a = Regista(DSN, project_a, str(key_file))
    sub_b = Regista(DSN, project_b, str(key_file))
    try:
        sub_a.register_workflow_file(WORKFLOW_PATH)
        from regista._principal_keys import register_principal_key

        register_principal_key(
            sub_a._mgr, principal_id, vk_a, "ed25519", key_id=key_id_a,
        )
        register_principal_key(
            sub_b._mgr, principal_id, vk_b, "ed25519", key_id=key_id_b,
        )
        yield sub_a, principal_id, key_id_a, key_id_b
    finally:
        sub_a.close()
        sub_b.close()
        drop_project_schema(DSN, project_a)
        drop_project_schema(DSN, project_b)


@pytest.fixture
def signed_but_unregistered(tmp_path):
    """The collapsed branch: the actor has *no* rows in this project at all.

    Reached by provisioning the principal in project B only and then pointing
    the CLI at project A with the same key file — the signer happily selects
    B's active Ed25519 key and signs into A, where nothing names that actor.
    Pre-fix, replay treated this exactly like an HMAC-only deployment and
    skipped it.
    """
    from regista.testing import drop_project_schema

    principal_id = f"wi223_orphan_{uuid.uuid4().hex[:8]}"
    project = f"wi223_o_{uuid.uuid4().hex[:8]}"

    sk, vk = _keypair()
    priv = _write_priv(tmp_path, f"{principal_id}_b", sk)
    key_id = f"pk_o_{uuid.uuid4().hex[:8]}"

    key_file = tmp_path / "keys.json"
    key_file.write_text(
        json.dumps(
            {
                "keys": [
                    _bootstrap_hmac_entry(),
                    _ed25519_entry(key_id, principal_id, priv, vk),
                ]
            }
        )
    )

    Regista.create_project(DSN, project, str(key_file))
    sub = Regista(DSN, project, str(key_file))
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        # Deliberately no register_principal_key for this project.
        yield sub, principal_id, key_id
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def hmac_only_project(tmp_path):
    """An HMAC-only deployment: no principal keys registered at all."""
    from regista.testing import drop_project_schema

    project = f"wi223_hmac_{uuid.uuid4().hex[:8]}"
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))

    Regista.create_project(DSN, project, str(key_file))
    sub = Regista(DSN, project, str(key_file))
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        yield sub
    finally:
        sub.close()
        drop_project_schema(DSN, project)


def _drive_chain(sub, actor_id: str) -> uuid.UUID:
    wi, _evt = sub.create_work_item(
        workflow_name="test_workflow",
        work_item_type="feature",
        actor_id=actor_id,
        custom_fields={"title": "wi223"},
    )
    sub.transition(
        work_item_id=wi.work_item_id,
        transition_name="start",
        actor_id=actor_id,
        actor_metadata={"role": "agent"},
    )
    return wi.work_item_id


class TestReplayCatchesCrossProjectKey:
    """The RED test: replay must not report zero failures on this chain."""

    def test_cross_project_key_is_a_binding_failure(self, cross_project_collision):
        sub, principal_id, key_id_a, key_id_b = cross_project_collision

        wi_id = _drive_chain(sub, principal_id)

        events = sub.read_events(work_item_id=wi_id)
        assert events, "expected a signed chain"
        # Precondition: the signer picked project B's key, not project A's.
        assert all(e.key_id == key_id_b for e in events), (
            f"expected all events signed with {key_id_b}, "
            f"got {[e.key_id for e in events]}"
        )

        report = sub.replay(verify_principal_binding=True)

        assert report.principal_binding_failures >= len(events), (
            "replay reported "
            f"principal_binding_failures={report.principal_binding_failures} "
            f"for a chain of {len(events)} events signed by {key_id_b!r}, a key "
            f"with no active row in this project's principal_keys "
            f"(only {key_id_a!r} is registered here)"
        )
        assert report.warnings >= len(events)

    def test_binding_failure_names_the_unregistered_key(self, cross_project_collision):
        sub, principal_id, _key_id_a, key_id_b = cross_project_collision

        wi_id = _drive_chain(sub, principal_id)
        events = sub.read_events(work_item_id=wi_id)

        result = sub.verify_event_principal_binding(events[0])
        assert result["verified"] is False
        assert result["error"] is not None
        assert key_id_b in result["error"]

    def test_strict_binding_makes_replay_exit_nonzero(self, cross_project_collision):
        """The CLI's --strict-principal-binding gate must trip on this chain."""
        sub, principal_id, _key_id_a, _key_id_b = cross_project_collision
        _drive_chain(sub, principal_id)

        report = sub.replay(verify_principal_binding=True)
        # This is the condition cmd_replay uses for its exit code.
        assert report.principal_binding_failures > 0


class TestCollapsedBranchIsSplit:
    """"no keys for this actor" and "asymmetric key nobody here registered"
    are different verdicts, not one skip."""

    def test_asymmetric_event_from_unregistered_actor_fails(
        self, signed_but_unregistered,
    ):
        sub, principal_id, key_id = signed_but_unregistered

        wi_id = _drive_chain(sub, principal_id)
        events = sub.read_events(work_item_id=wi_id)
        assert all(e.key_id == key_id for e in events)
        assert all(e.scheme_id == "ed25519" for e in events)

        report = sub.replay(verify_principal_binding=True)

        assert report.principal_binding_failures >= len(events), (
            "an Ed25519 chain whose actor has no row at all in this project's "
            "principal_keys is an unregistered signer, not a legacy HMAC "
            "deployment; it must not be skipped"
        )

    def test_error_says_unregistered_signer(self, signed_but_unregistered):
        sub, principal_id, _key_id = signed_but_unregistered
        wi_id = _drive_chain(sub, principal_id)
        events = sub.read_events(work_item_id=wi_id)

        result = sub.verify_event_principal_binding(events[0])
        assert result["verified"] is False
        assert "unregistered-signer" in result["error"]


class TestHmacOnlyDeploymentStaysGreen:
    """Backward compatibility: no registered keys for the actor means skip."""

    def test_hmac_only_chain_reports_no_binding_failures(self, hmac_only_project):
        sub = hmac_only_project
        _drive_chain(sub, "hmac-only-actor")

        report = sub.replay(verify_principal_binding=True)

        assert report.principal_binding_failures == 0, (
            "an HMAC-only deployment (no principal keys registered) must not "
            "report binding failures"
        )
        assert report.halted == 0
        assert report.replayed_drift == 0

    def test_unregistered_actor_alongside_registered_one_is_skipped(
        self, cross_project_collision,
    ):
        """Only the actor with registered keys is checked; others skip."""
        sub, _principal_id, _key_id_a, _key_id_b = cross_project_collision

        # A second actor with no principal keys at all, signing with the
        # bootstrap HMAC key.
        wi_id = _drive_chain(sub, "no-keys-actor")
        events = sub.read_events(work_item_id=wi_id)
        assert all(e.key_id == "bootstrap-hmac" for e in events)

        report = sub.replay(verify_principal_binding=True)
        assert report.principal_binding_failures == 0


class TestProvisionPrincipalRefusesCollision:
    """Fix 1: don't silently mint a colliding second keypair."""

    def test_second_project_provisioning_is_refused(self, tmp_path):
        from regista._provision import provision_principal
        from regista.testing import drop_project_schema

        principal_id = f"agent:wi223prov{uuid.uuid4().hex[:8]}"
        project_a = f"wi223_pa_{uuid.uuid4().hex[:8]}"
        project_b = f"wi223_pb_{uuid.uuid4().hex[:8]}"
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))

        Regista.create_project(DSN, project_a, str(key_file))
        Regista.create_project(DSN, project_b, str(key_file))
        try:
            first = provision_principal(
                DSN,
                project_a,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
            )
            assert first.public_key_registered is True

            with pytest.raises(RegistaError) as exc:
                provision_principal(
                    DSN,
                    project_b,
                    principal_id,
                    hmac_key_path=str(key_file),
                    private_key_dir=str(tmp_path / "principals"),
                    secret_backend="file",
                )
            assert exc.value.code == ErrorCode.PRINCIPAL_KEY_ALREADY_EXISTS
            assert first.key_id in str(exc.value)

            # The key file must be unchanged: one active Ed25519 entry.
            data = json.loads(key_file.read_text())
            ed = [
                k for k in data["keys"]
                if k.get("principal_id") == principal_id
            ]
            assert len(ed) == 1, f"key file gained a colliding entry: {ed}"
            assert ed[0]["status"] == "active"
            assert ed[0]["key_id"] == first.key_id
        finally:
            drop_project_schema(DSN, project_a)
            drop_project_schema(DSN, project_b)

    def test_reuse_existing_key_registers_the_same_public_key(self, tmp_path):
        """The supported way for one principal to act in two projects."""
        from regista._principal_keys import get_active_key
        from regista._provision import provision_principal
        from regista.testing import drop_project_schema

        principal_id = f"agent:wi223reuse{uuid.uuid4().hex[:8]}"
        project_a = f"wi223_ra_{uuid.uuid4().hex[:8]}"
        project_b = f"wi223_rb_{uuid.uuid4().hex[:8]}"
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))

        Regista.create_project(DSN, project_a, str(key_file))
        Regista.create_project(DSN, project_b, str(key_file))
        try:
            first = provision_principal(
                DSN,
                project_a,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
            )
            second = provision_principal(
                DSN,
                project_b,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
                reuse_existing_key=True,
            )
            assert second.key_id == first.key_id
            assert second.private_key_stored is False
            assert second.public_key_registered is True

            # Both projects now register the key the signer will actually use.
            sub_a = Regista(DSN, project_a, str(key_file))
            sub_b = Regista(DSN, project_b, str(key_file))
            try:
                assert get_active_key(sub_a._mgr, principal_id).key_id == first.key_id
                assert get_active_key(sub_b._mgr, principal_id).key_id == first.key_id
                assert (
                    get_active_key(sub_a._mgr, principal_id).fingerprint
                    == get_active_key(sub_b._mgr, principal_id).fingerprint
                )
            finally:
                sub_a.close()
                sub_b.close()

            # And the key file still has exactly one entry for the principal.
            data = json.loads(key_file.read_text())
            ed = [k for k in data["keys"] if k.get("principal_id") == principal_id]
            assert len(ed) == 1

            # A chain written to the second project verifies its binding.
            sub_b = Regista(DSN, project_b, str(key_file))
            try:
                sub_b.register_workflow_file(WORKFLOW_PATH)
                _drive_chain(sub_b, principal_id)
                report = sub_b.replay(verify_principal_binding=True)
                assert report.principal_binding_failures == 0
                assert report.principal_binding_verified is True
            finally:
                sub_b.close()
        finally:
            drop_project_schema(DSN, project_a)
            drop_project_schema(DSN, project_b)

    def test_reprovisioning_same_project_is_still_idempotent(self, tmp_path):
        from regista._provision import provision_principal
        from regista.testing import drop_project_schema

        principal_id = f"agent:wi223idem{uuid.uuid4().hex[:8]}"
        project = f"wi223_pi_{uuid.uuid4().hex[:8]}"
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))

        Regista.create_project(DSN, project, str(key_file))
        try:
            first = provision_principal(
                DSN,
                project,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
            )
            second = provision_principal(
                DSN,
                project,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
            )
            assert second.already_existed is True
            assert second.key_id == first.key_id
        finally:
            drop_project_schema(DSN, project)


class TestReportNeverClaimsAnUncheckedZero:
    """``principal_binding_failures=0`` must mean "checked, none found"."""

    def test_unverified_report_says_so(self, hmac_only_project):
        sub = hmac_only_project
        _drive_chain(sub, "hmac-only-actor")

        report = sub.replay()
        assert report.principal_binding_verified is False
        # No affirmative zero in the serialized form either.
        assert "principal_binding_failures" not in report.to_dict()
        assert report.to_dict()["principal_binding_verified"] is False

    def test_verified_report_publishes_the_zero(self, hmac_only_project):
        sub = hmac_only_project
        _drive_chain(sub, "hmac-only-actor")

        report = sub.replay(verify_principal_binding=True)
        assert report.principal_binding_verified is True
        assert report.to_dict()["principal_binding_failures"] == 0

    def test_in_memory_backend_never_claims_verification(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista()
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            _drive_chain(sub, "in-mem-actor")
            report = sub.replay(verify_principal_binding=True)
            # The InMemory backend has no principal_keys registry at all, so it
            # must not report a verified binding.
            assert report.principal_binding_verified is False
        finally:
            sub.close()

    def test_cli_replay_verifies_by_default(self, cross_project_collision, capsys):
        """`regista replay` with no binding flag at all must catch the collision."""
        sub, principal_id, _key_id_a, _key_id_b = cross_project_collision
        _drive_chain(sub, principal_id)
        dsn = sub._mgr.dsn
        project = sub._project
        key_path = sub._hmac_key_path
        sub.close()

        from regista._cli import main

        with pytest.raises(SystemExit) as exc:
            main([
                "--dsn", dsn,
                "--project", project,
                "--hmac-key-path", key_path,
                "replay",
                "--strict-principal-binding",
            ])
        out = capsys.readouterr().out
        assert "principal_binding=not-verified" not in out
        assert "principal_binding_failures=0" not in out
        assert exc.value.code == 1, (
            f"expected strict binding to fail the run; output: {out}"
        )

    def test_cli_opt_out_is_labelled_not_verified(self, hmac_only_project, capsys):
        sub = hmac_only_project
        _drive_chain(sub, "hmac-only-actor")
        dsn = sub._mgr.dsn
        project = sub._project
        key_path = sub._hmac_key_path
        sub.close()

        from regista._cli import main

        main([
            "--dsn", dsn,
            "--project", project,
            "--hmac-key-path", key_path,
            "replay",
            "--no-verify-principal-binding",
        ])
        out = capsys.readouterr().out
        assert "principal_binding=not-verified" in out
        assert "principal_binding_failures" not in out


class TestDoctorSeesTheCollision:
    """``regista doctor`` must not report green on a colliding key file."""

    def test_registration_check_fails_on_cross_project_key(
        self, cross_project_collision,
    ):
        from regista._doctor import run_doctor

        sub, _principal_id, key_id_a, key_id_b = cross_project_collision
        dsn = sub._mgr.dsn
        project = sub._project
        key_path = sub._hmac_key_path

        report = run_doctor(
            dsn, project=project, key_path=key_path, secret_backend="file",
        )
        checks = {c.name: c for c in report.checks}
        assert "custody:registration" in checks
        reg = checks["custody:registration"]
        assert reg.status == "fail", f"custody:registration said {reg.status}: {reg.detail}"
        assert key_id_b in reg.detail
        assert key_id_a in reg.detail
        # And the whole doctor report must be not-ok, so `agent-suite doctor`
        # (which folds each component's top-level `ok`) turns red too.
        assert report.to_dict()["ok"] is False

    def test_registration_check_passes_when_aligned(self, tmp_path):
        from regista._doctor import run_doctor
        from regista._provision import provision_principal
        from regista.testing import drop_project_schema

        principal_id = f"agent:wi223dr{uuid.uuid4().hex[:8]}"
        project = f"wi223_dr_{uuid.uuid4().hex[:8]}"
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))

        Regista.create_project(DSN, project, str(key_file))
        try:
            provision_principal(
                DSN,
                project,
                principal_id,
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
                secret_backend="file",
            )
            report = run_doctor(
                DSN,
                project=project,
                key_path=str(key_file),
                secret_backend="file",
            )
            checks = {c.name: c for c in report.checks}
            assert checks["custody:registration"].status == "ok", (
                checks["custody:registration"].detail
            )
            assert report.to_dict()["ok"] is True
        finally:
            drop_project_schema(DSN, project)

    def test_hmac_only_key_file_is_skipped_not_failed(self, hmac_only_project):
        from regista._doctor import run_doctor

        sub = hmac_only_project
        report = run_doctor(
            sub._mgr.dsn,
            project=sub._project,
            key_path=sub._hmac_key_path,
            secret_backend="file",
        )
        checks = {c.name: c for c in report.checks}
        assert checks["custody:registration"].status == "skip"
        assert report.to_dict()["ok"] is True


class TestSelectionRuleIsShared:
    """doctor and the signer must not drift on which key gets used."""

    def test_prefers_the_last_active_asymmetric_key(self):
        from regista._keys import select_signing_key_id

        assert select_signing_key_id([]) is None
        assert select_signing_key_id(
            [("k1", "hmac-sha256", "active")]
        ) == "k1"
        assert select_signing_key_id(
            [("k1", "ed25519", "deprecated"), ("k2", "ed25519", "active")]
        ) == "k2"
        assert select_signing_key_id(
            [("k1", "ed25519", "active"), ("k2", "ed25519", "active")]
        ) == "k2"
        assert select_signing_key_id(
            [("k1", "hmac-sha256", "active"), ("k2", "ed25519", "active")]
        ) == "k2"
        assert select_signing_key_id(
            [("k1", "ed25519", "revoked")]
        ) is None

    def test_matches_keyset_resolution(self, tmp_path):
        """The pure helper agrees with the live KeySet on the same file."""
        from regista._keys import KeySet, select_signing_key_id

        principal_id = "sel_principal"
        sk1, vk1 = _keypair()
        sk2, vk2 = _keypair()
        priv1 = _write_priv(tmp_path, "sel1", sk1)
        priv2 = _write_priv(tmp_path, "sel2", sk2)
        key_file = tmp_path / "keys.json"
        entries = [
            _bootstrap_hmac_entry(),
            _ed25519_entry("sel-k1", principal_id, priv1, vk1, status="deprecated"),
            _ed25519_entry("sel-k2", principal_id, priv2, vk2),
        ]
        key_file.write_text(json.dumps({"keys": entries}))

        ks = KeySet(str(key_file))
        live = ks.resolve_signing_key(principal_id)
        pure = select_signing_key_id(
            [
                (e["key_id"], e.get("scheme", "hmac-sha256"), e.get("status", "active"))
                for e in entries
                if e.get("principal_id") == principal_id
            ]
        )
        assert live.key_id == pure == "sel-k2"


class TestRefusalIsClassifiedAsRefusal:
    """agent-suite's onboard/bootstrap read this message, not just the code."""

    def test_message_lands_in_the_refused_branch(self, tmp_path):
        """agent-suite treats "already"/"exists" in stderr as *success*, and
        checks "refuse"/"clobber" first. The refusal must hit that branch or a
        hard stop is reported as a green onboarding step."""
        from regista._provision import _guard_shared_key_file

        principal_id = "guard_wording"
        sk, vk = _keypair()
        priv = _write_priv(tmp_path, "guard", sk)
        key_file = tmp_path / "keys.json"
        key_file.write_text(
            json.dumps({
                "keys": [
                    _bootstrap_hmac_entry(),
                    _ed25519_entry("pk_guard", principal_id, priv, vk),
                ]
            })
        )

        with pytest.raises(RegistaError) as exc:
            _guard_shared_key_file(str(key_file), principal_id, "some_project")

        msg = str(exc.value).lower()
        assert "refus" in msg or "clobber" in msg, (
            "agent-suite's onboard/bootstrap classify provisioning failures by "
            "scanning stderr; without refuse/clobber this refusal is read as "
            f"'already provisioned' and reported green. Message: {msg}"
        )
        assert exc.value.code == ErrorCode.PRINCIPAL_KEY_ALREADY_EXISTS

    def test_guard_is_silent_when_the_key_file_is_clean(self, tmp_path):
        from regista._provision import _guard_shared_key_file

        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [_bootstrap_hmac_entry()]}))
        # No principal entries at all — nothing to collide with.
        _guard_shared_key_file(str(key_file), "nobody", "some_project")

    def test_guard_ignores_a_revoked_entry(self, tmp_path):
        """A revoked key cannot sign, so it is not a collision."""
        from regista._provision import _guard_shared_key_file

        principal_id = "guard_revoked"
        sk, vk = _keypair()
        priv = _write_priv(tmp_path, "guard_rev", sk)
        key_file = tmp_path / "keys.json"
        key_file.write_text(
            json.dumps({
                "keys": [
                    _bootstrap_hmac_entry(),
                    _ed25519_entry(
                        "pk_revoked", principal_id, priv, vk, status="revoked",
                    ),
                ]
            })
        )
        _guard_shared_key_file(str(key_file), principal_id, "some_project")
