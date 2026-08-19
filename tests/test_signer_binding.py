from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest
from _helpers import DSN, WORKFLOW_PATH

from regista import Regista
from regista._errors import ErrorCode, RegistaError


def _generate_ed25519_keypair() -> tuple[bytes, bytes]:
    import nacl.signing
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def _make_ed25519_key_file(tmp_path: Path, principal_id: str) -> tuple[str, bytes, bytes, str]:
    sk, vk = _generate_ed25519_keypair()
    priv_path = tmp_path / f"{principal_id}_priv.key"
    priv_path.write_bytes(sk)
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": f"ed25519-{principal_id}",
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv_path}",
            "public_key": base64.b64encode(vk).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))
    return str(key_file), sk, vk, str(priv_path)


def _make_multi_ed25519_key_file(
    tmp_path: Path, principal_id: str,
) -> tuple[str, bytes, bytes, bytes, bytes]:
    sk1, vk1 = _generate_ed25519_keypair()
    sk2, vk2 = _generate_ed25519_keypair()
    priv1 = tmp_path / f"{principal_id}_priv1.key"
    priv2 = tmp_path / f"{principal_id}_priv2.key"
    priv1.write_bytes(sk1)
    priv2.write_bytes(sk2)
    try:
        priv1.chmod(0o600)
        priv2.chmod(0o600)
    except OSError:
        pass
    key_file = tmp_path / "keys.json"
    v2_key_id = f"ed25519-{principal_id}-v2"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": f"ed25519-{principal_id}",
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv1}",
            "public_key": base64.b64encode(vk1).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
        {
            "key_id": v2_key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv2}",
            "public_key": base64.b64encode(vk2).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))
    return str(key_file), sk1, vk1, sk2, vk2


@pytest.fixture
def principal_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    key_path, sk, vk, _priv_path = _make_ed25519_key_file(tmp_path, principal_id)

    Regista.create_project(DSN, project, key_path)
    sub = Regista(DSN, project, key_path)
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista.testing import seed_legacy_principal_key
        key_id = f"ed25519-{principal_id}"
        entry = seed_legacy_principal_key(
            sub._mgr, principal_id, vk, "ed25519", key_id=key_id,
        )
        yield sub, principal_id, entry.key_id, sk, vk
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def multi_key_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    key_path, sk1, vk1, sk2, vk2 = _make_multi_ed25519_key_file(tmp_path, principal_id)

    Regista.create_project(DSN, project, key_path)
    sub = Regista(DSN, project, key_path)
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista.testing import seed_legacy_principal_key
        key_id = f"ed25519-{principal_id}"
        entry = seed_legacy_principal_key(
            sub._mgr, principal_id, vk1, "ed25519", key_id=key_id,
        )
        yield sub, principal_id, entry.key_id, sk1, vk1, sk2, vk2
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def rotated_key_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    sk1, vk1 = _generate_ed25519_keypair()
    sk2, vk2 = _generate_ed25519_keypair()
    priv1 = tmp_path / f"{principal_id}_priv1.key"
    priv2 = tmp_path / f"{principal_id}_priv2.key"
    priv1.write_bytes(sk1)
    priv2.write_bytes(sk2)
    try:
        priv1.chmod(0o600)
        priv2.chmod(0o600)
    except OSError:
        pass
    old_key_id = f"ed25519-{principal_id}"
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": old_key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv1}",
            "public_key": base64.b64encode(vk1).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))

    Regista.create_project(DSN, project, str(key_file))
    sub = Regista(DSN, project, str(key_file))
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista.testing import seed_legacy_principal_key
        seed_legacy_principal_key(
            sub._mgr, principal_id, vk1, "ed25519", key_id=old_key_id,
        )
        import time
        # Stagger so the old event predates the rotation's valid_to.
        time.sleep(0.15)
        yield sub, principal_id, old_key_id, sk1, vk1, sk2, vk2
    finally:
        sub.close()
        drop_project_schema(DSN, project)

class TestPrincipalKeyOpsFacade:
    def test_verify_binding_via_facade(self, principal_setup):
        sub, principal_id, key_id, _sk, _vk = principal_setup
        result = sub.principals.verify_binding(principal_id, principal_id)
        assert result["principal_id"] == principal_id
        assert result["key_id"] == key_id

    def test_verify_binding_mismatch_raises(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup
        with pytest.raises(RegistaError) as exc_info:
            sub.principals.verify_binding(principal_id, "different-actor")
        assert exc_info.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH


class TestKeySetSecretRef:
    def test_resolve_signing_key_by_principal_id(self, tmp_path):
        sk, vk = _generate_ed25519_keypair()
        priv_path = tmp_path / "test_priv.key"
        priv_path.write_bytes(sk)
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "ed25519-principal",
                "scheme": "ed25519",
                "principal_id": "my-principal",
                "secret_ref": f"file:{priv_path}",
                "public_key": base64.b64encode(vk).decode("ascii"),
                "role": "actor",
                "status": "active",
            }
        ]}))
        from regista._keys import KeySet
        ks = KeySet(str(key_file))
        entry = ks.resolve_signing_key("my-principal")
        assert entry.scheme == "ed25519"
        assert entry.principal_id == "my-principal"
        assert entry.secret == sk
        assert entry.public_key == vk

    def test_secret_ref_env_provider(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_TEST_KEY", "env-secret-value")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "env-key",
                "scheme": "hmac-sha256",
                "secret_ref": "env:MY_TEST_KEY",
                "status": "active",
            }
        ]}))
        from regista._keys import KeySet
        ks = KeySet(str(key_file))
        entry = ks.get_key("env-key")
        assert entry.secret == b"env-secret-value"

class TestPathTraversal:
    def test_provision_principal_rejects_path_traversal(self, tmp_path):
        """A principal id may never become a path that escapes the custody directory.

        The refusal *code* changed with P2.3 (WI-294): the pre-0.6.0 validator answered
        ``INVALID_ARGUMENT`` for anything outside the ASCII
        alphanumeric-dot-hyphen-underscore class, and the canonical §2.1 grammar answers
        ``PRINCIPAL_ID_UNGRAMMATICAL`` for the same input (no ``kind:`` prefix, and ``/`` is
        not a bare-name character). The *security property* is unchanged and is asserted
        below; the second case is new coverage the inversion made necessary.
        """
        from regista._provision import provision_principal
        project = f"prov_{uuid.uuid4().hex[:8]}"
        from regista.testing import drop_project_schema
        try:
            from regista._provision import provision as _prov
            _prov(DSN, [project])
            with pytest.raises(RegistaError) as exc_info:
                provision_principal(
                    DSN, project, "../../../etc/cron.d/evil",
                    hmac_key_path=str(tmp_path / "keys.json"),
                )
            assert exc_info.value.code == ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL
            assert exc_info.value.detail["reason"] == "not_kind_colon_subject"
        finally:
            drop_project_schema(DSN, project)
            import psycopg
            with psycopg.connect(DSN, autocommit=True) as conn:
                conn.execute(f'DROP ROLE IF EXISTS "regista_{project}"')

    def test_a_canonical_principal_id_can_never_escape_the_custody_directory(self, tmp_path):
        """The vector the enrolment inversion newly reaches.

        ``TRUST-DOMAIN.md`` §2.1's subject class includes ``/`` (``service:idp:tenant-a/svc-7``
        is a stated legal example), so ``agent:a/../../../etc/cron.d/evil`` is a *grammatically
        canonical* principal id. Before the inversion the validator rejected the colon, so no
        id containing ``/`` could reach ``_custody.build_ref`` and its
        ``key_dir / f"{principal_id}_ed25519.key"`` was safe by accident. It is now safe on
        purpose: a path-bearing id falls back to the §2.2 derived ``rp-<32 hex>`` name.
        """
        from regista._custody import build_ref

        key_dir = tmp_path / "principals"
        for principal_id in (
            "agent:a/../../../etc/cron.d/evil",
            "service:idp:tenant-a/svc-7",
            "agent:x/../../y",
        ):
            ref = build_ref("file", principal_id, private_key_dir=str(key_dir))
            written = Path(ref.removeprefix("file:")).resolve()
            assert written.parent == key_dir.resolve(), (
                f"{principal_id!r} escaped the custody directory: {written}"
            )
            assert written.name.startswith("rp-"), written.name

        # A legacy bare name keeps its historical filename, so no existing secret_ref is
        # invalidated by the guard.
        legacy = build_ref("file", "mvmcc03-agent", private_key_dir=str(key_dir))
        assert legacy == f"file:{key_dir / 'mvmcc03-agent_ed25519.key'}"

        # The derived name is reversible through the §2.2 lookup verb, so the KV/disk tree
        # stays auditable by hand.
        from regista._principals import resolve_backend_name

        ref = build_ref("file", "service:idp:tenant-a/svc-7", private_key_dir=str(key_dir))
        derived = Path(ref.removeprefix("file:")).name.removesuffix("_ed25519.key")
        assert resolve_backend_name(derived, ["service:idp:tenant-a/svc-7"]) == (
            "service:idp:tenant-a/svc-7"
        )

    def test_a_maximum_length_canonical_id_enrolls_instead_of_raising_oserror(self, tmp_path):
        """``service:`` + a 247-character subject is the *longest legal* §2.1 principal id.

        Its direct filename is 267 bytes, over ``NAME_MAX`` (255), and
        ``_secrets.FileProvider.store`` opens ``<name>.tmp`` — 271 bytes. Before the length
        condition in ``_custody._contained_key_path``, that surfaced as a bare
        ``OSError: [Errno 36] File name too long`` propagating **untyped** out of
        ``store_private_key`` and therefore out of ``provision_principal`` /
        ``enroll_principal``: an always-strict boundary answering a legal input with an
        unhandled OS exception. It now routes to the §2.2 derived name and simply works.
        """
        from regista._custody import store_private_key
        from regista._principals import backend_name, resolve_backend_name

        principal_id = "service:" + "a" * 247
        assert len(principal_id) == 255  # §2.1's maximum
        assert len(f"{principal_id}_ed25519.key".encode()) == 267  # over NAME_MAX

        key_dir = tmp_path / "principals"
        result = store_private_key(
            backend="file", principal_id=principal_id, private_key_dir=str(key_dir)
        )
        written = Path(result.secret_ref.removeprefix("file:"))
        assert written.is_file()
        assert written.parent == key_dir
        assert written.name == f"{backend_name(principal_id)}_ed25519.key"
        assert len(written.name.encode()) < 255

        # And it is reversible, so the operator can still tell whose key this is.
        derived = written.name.removesuffix("_ed25519.key")
        assert resolve_backend_name(derived, [principal_id]) == principal_id

    def test_the_length_cutover_matches_what_was_ever_writable(self, tmp_path):
        """The length condition orphans no existing secret.

        Its budget is exactly the one ``FileProvider`` has always been bound by —
        ``NAME_MAX`` minus the ``.tmp`` reserve — so an id that now routes to the derived
        name is precisely an id whose direct write would previously have failed with
        ``ENAMETOOLONG``. There is no id that used to get a writable direct filename and
        now gets a different one.
        """
        import os

        from regista._custody import (
            _FILENAME_SUFFIX_RESERVE,
            _MAX_FILENAME_BYTES,
            build_ref,
        )

        key_dir = tmp_path / "principals"
        key_dir.mkdir()
        assert _MAX_FILENAME_BYTES == 255
        assert _FILENAME_SUFFIX_RESERVE == len(".tmp")
        assert os.pathconf(str(key_dir), "PC_NAME_MAX") == _MAX_FILENAME_BYTES

        budget = _MAX_FILENAME_BYTES - _FILENAME_SUFFIX_RESERVE
        suffix = len("_ed25519.key")
        longest_direct = "a" * (budget - suffix)  # a legacy bare name, path-safe
        assert len(f"{longest_direct}_ed25519.key".encode()) == budget

        # At the budget: still the historical direct name, and genuinely creatable.
        ref = build_ref("file", longest_direct, private_key_dir=str(key_dir))
        assert Path(ref.removeprefix("file:")).name == f"{longest_direct}_ed25519.key"
        probe = key_dir / f"{longest_direct}_ed25519.key.tmp"
        probe.write_bytes(b"x")  # proves the kernel accepts the tmp name too
        probe.unlink()

        # One byte over: routes to the derived name, and the direct name it declined would
        # in fact have been unwritable.
        one_over = longest_direct + "a"
        ref = build_ref("file", one_over, private_key_dir=str(key_dir))
        assert Path(ref.removeprefix("file:")).name.startswith("rp-")
        with pytest.raises(OSError, match="File name too long"):
            (key_dir / f"{one_over}_ed25519.key.tmp").write_bytes(b"x")


class TestReplayPrincipalBinding:
    """End-to-end tests: replay(verify_principal_binding=True) closes the
    non-repudiation loop — a forged actor with a valid key-set key is caught.
    """









    def test_register_superseded_key_closes_validity_window(self, multi_key_setup):
        """WI-265: superseding a key via `register` must close the old key's
        validity window exactly like `rotate` does.

        `register` is the operator-facing path (the CLI funnels rotations
        through it), and before the fix it left the rotated-out key valid
        forever: an attacker holding the retired private key could still sign
        events that passed the validity-window check. An event signed with the
        old key BEFORE the supersede must still verify; one signed AFTER must
        be rejected with `key-not-valid-at-time`.
        """
        import time
        from datetime import timedelta
        from types import SimpleNamespace

        from regista._principal_keys import list_principal_keys
        from regista._signing import sign_event as _sign_event
        from regista._signing_scheme import get_scheme
        from regista.testing import seed_legacy_principal_key

        sub, principal_id, old_key_id, sk1, _vk1, _sk2, vk2 = multi_key_setup

        time.sleep(0.05)
        seed_legacy_principal_key(
            sub._mgr, principal_id, vk2, "ed25519",
            key_id=f"ed25519-{principal_id}-v2",
        )

        old_entry = next(
            k for k in list_principal_keys(sub._mgr, principal_id)
            if k.key_id == old_key_id
        )
        assert old_entry.status == "superseded"
        assert old_entry.valid_to is not None
        assert old_entry.valid_from < old_entry.valid_to

        scheme = get_scheme("ed25519")

        def _forge(timestamp):
            event_id = uuid.uuid4()
            work_item_id = uuid.uuid4()
            signature, canonical_hash, envelope = _sign_event(
                event_id=event_id,
                work_item_id=work_item_id,
                actor_id=principal_id,
                key_id=old_key_id,
                event_seq=1,
                workflow_name="test_workflow",
                workflow_version=1,
                timestamp=timestamp,
                transition="created",
                payload={},
                key=sk1,
                scheme=scheme,
            )
            return SimpleNamespace(
                event_id=event_id,
                work_item_id=work_item_id,
                # WI-267: this stand-in must carry `entity_id` and `global_seq`
                # like the real row does. Verification reconciles the row
                # against the signed envelope, and `entity_id` is what v4/v5
                # sign — a stand-in that omits it is not describing a row the
                # store could hold. (It used to be masked by an
                # `effective_entity_id` fallback that treated a missing/NULL
                # `entity_id` as `work_item_id`; that fallback was itself a
                # masking bug and was removed.)
                entity_id=work_item_id,
                global_seq=None,
                event_seq=1,
                actor_id=principal_id,
                actor_kind="agent",
                actor_metadata=None,
                key_id=old_key_id,
                workflow_name="test_workflow",
                workflow_version=1,
                timestamp=timestamp,
                transition="created",
                payload={},
                payload_canonical_hash=canonical_hash,
                signature=signature,
                canonical_envelope=envelope,
                on_behalf_of=None,
                scheme_id="ed25519",
                prev_event_hash=None,
                prev_global_event_hash=None,
                entity_kind="work_item",
                hash_alg="sha-256",
            )

        # An event signed inside the old key's validity window (before the
        # supersede) must still verify: rotation is not retroactive.
        before_ts = old_entry.valid_from + (
            old_entry.valid_to - old_entry.valid_from
        ) / 2
        result_before = sub.verify_event_principal_binding(_forge(before_ts))
        assert result_before["verified"] is True
        assert result_before["key_id"] == old_key_id

        # An event signed after the supersede with the retired key must be
        # rejected: the validity window is closed.
        after_ts = old_entry.valid_to + timedelta(seconds=1)
        result_after = sub.verify_event_principal_binding(_forge(after_ts))
        assert result_after["verified"] is False
        assert result_after["error"] is not None
        assert "key-not-valid-at-time" in (result_after["error"] or "")



    def test_verify_principal_binding_no_crash_on_malformed_event(
        self, principal_setup,
    ):
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        class MalformedEvent:
            actor_id = principal_id
            scheme_id = "ed25519"
            key_id = _key_id
            timestamp = None
            signature = None
            payload_canonical_hash = None
            canonical_envelope = None
            on_behalf_of = None
            prev_event_hash = None
            prev_global_event_hash = None
            entity_kind = "work_item"
            hash_alg = "sha-256"
            event_id = uuid.uuid4()
            work_item_id = uuid.uuid4()
            event_seq = 1
            workflow_name = "test"
            workflow_version = 1
            transition: str = "created"
            payload: dict = {}  # noqa: RUF012

        result = sub.verify_event_principal_binding(MalformedEvent())
        assert result["verified"] is False
        assert result["error"] is not None


class TestVerifyPrincipalBindingCoreEdgeCases:
    def _make_entry(
        self,
        key_id="k1",
        scheme="ed25519",
        status="active",
        valid_from=None,
        valid_to=None,
        public_key=b"\x00" * 32,
    ):
        from datetime import UTC, datetime

        from regista._principal_keys import PrincipalKeyEntry
        now = datetime.now(UTC)
        return PrincipalKeyEntry(
            principal_id="alice",
            key_id=key_id,
            scheme=scheme,
            public_key=public_key,
            fingerprint=f"{scheme}:sha256:abc",
            status=status,
            valid_from=valid_from or now,
            valid_to=valid_to,
            registered_by="system",
            registered_at=now,
            revoked_at=None,
            revoked_reason=None,
        )

    def test_missing_timestamp_fail_closed(self):
        from datetime import UTC, datetime

        from regista._signing import _verify_principal_binding_core

        entry = self._make_entry(valid_from=datetime.now(UTC))
        result = _verify_principal_binding_core(
            [entry],
            actor_id="alice",
            scheme_id="ed25519",
            verify_fn=lambda pk: True,
            event_key_id="k1",
            event_timestamp=None,
        )
        assert not result.verified
        assert "key-not-valid-at-time" in (result.error or "")

    def test_pre_filtered_temporal_diagnostic(self):
        from datetime import UTC, datetime, timedelta

        from regista._signing import _verify_principal_binding_core

        now = datetime.now(UTC)
        old_valid_to = now - timedelta(days=1)
        e1 = self._make_entry(key_id="k1", valid_to=old_valid_to)
        e2 = self._make_entry(key_id="k2", valid_to=old_valid_to)

        result = _verify_principal_binding_core(
            [e1, e2],
            actor_id="alice",
            scheme_id="ed25519",
            verify_fn=lambda pk: True,
            event_key_id=None,
            event_timestamp=now,
        )
        assert not result.verified
        assert "key-not-valid-at-time" in (result.error or "")

    def test_pre_filtered_scheme_diagnostic(self):
        from datetime import UTC, datetime

        from regista._signing import _verify_principal_binding_core

        now = datetime.now(UTC)
        e1 = self._make_entry(key_id="k1", scheme="hmac-sha256")
        e2 = self._make_entry(key_id="k2", scheme="hmac-sha256")

        result = _verify_principal_binding_core(
            [e1, e2],
            actor_id="alice",
            scheme_id="ed25519",
            verify_fn=lambda pk: True,
            event_key_id=None,
            event_timestamp=now,
        )
        assert not result.verified
        assert "scheme-mismatch" in (result.error or "")

    def test_revoked_key_specific_error(self):
        from datetime import UTC, datetime

        from regista._signing import _verify_principal_binding_core

        revoked_entry = self._make_entry(key_id="k1", status="revoked")
        result = _verify_principal_binding_core(
            [revoked_entry],
            actor_id="alice",
            scheme_id="ed25519",
            verify_fn=lambda pk: True,
            event_key_id="k1",
            event_timestamp=datetime.now(UTC),
        )
        assert not result.verified
        assert "key-revoked" in (result.error or "")

