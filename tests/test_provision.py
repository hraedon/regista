from __future__ import annotations

import base64
import json
import uuid

import pytest
from _helpers import DSN

from regista._errors import ErrorCode, RegistaError
from regista._provision import (
    provision,
    provision_principal,
)


def _drop_schema(project: str) -> None:
    from regista.testing import drop_project_schema
    drop_project_schema(DSN, project)


def _drop_role(role: str) -> None:
    import psycopg
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(f'DROP ROLE IF EXISTS "{role}"')


class TestProvision:
    def test_provision_creates_schema_and_role(self):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        try:
            results = provision(DSN, [project])
            assert len(results) == 1
            r = results[0]
            assert r.project == project
            assert r.error is None
            assert r.schema_created is True
            assert r.service_role_created is True
            assert len(r.migrations_applied) > 0
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_idempotent(self):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        try:
            provision(DSN, [project])
            results = provision(DSN, [project])
            r = results[0]
            assert r.schema_created is False
            assert r.service_role_created is False
            assert r.migrations_applied == []
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_multiple_projects(self):
        p1 = f"prov_{uuid.uuid4().hex[:8]}"
        p2 = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(p1)
        _drop_schema(p2)
        _drop_role(f"regista_{p1}")
        _drop_role(f"regista_{p2}")
        try:
            results = provision(DSN, [p1, p2])
            assert len(results) == 2
            assert all(r.error is None for r in results)
            assert all(r.schema_created for r in results)
        finally:
            _drop_schema(p1)
            _drop_schema(p2)
            _drop_role(f"regista_{p1}")
            _drop_role(f"regista_{p2}")

    def test_provision_dry_run(self):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        try:
            results = provision(DSN, [project], dry_run=True)
            r = results[0]
            assert r.schema_created is True
            assert r.service_role_created is True
            assert r.migrations_applied == []
            import psycopg
            with psycopg.connect(DSN) as conn:
                row = conn.execute(
                    "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                    [project],
                ).fetchone()
                assert row is None
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_cross_schema_denied(self):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        other = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_schema(other)
        _drop_role(f"regista_{project}")
        _drop_role(f"regista_{other}")
        try:
            provision(DSN, [project, other])
            import psycopg
            with psycopg.connect(DSN) as conn:
                row = conn.execute(
                    """
                    SELECT has_schema_privilege(
                        (SELECT oid FROM pg_roles WHERE rolname = %s),
                        (SELECT oid FROM pg_namespace WHERE nspname = %s),
                        'USAGE'
                    )
                    """,
                    [f"regista_{project}", other],
                ).fetchone()
                assert row[0] is False
        finally:
            _drop_schema(project)
            _drop_schema(other)
            _drop_role(f"regista_{project}")
            _drop_role(f"regista_{other}")


class TestProvisionPrincipal:
    def test_provision_principal_is_refused_post_cutover(self, tmp_path):
        """P2.2 / §5.9: provisioning wrote principal_keys with no signed event.

        That was a fourth bypass path, unnamed in §5.1's list of three. Key
        provisioning is Gate 2 and needs Gate 1's trust log plus P1.7's v6 append
        path; enrolment must be a signed `principal_key_enrolled` event (§5.5).
        """
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64", "status": "active"}
        ]}))
        try:
            provision(DSN, [project])
            with pytest.raises(RegistaError) as exc_info:
                provision_principal(
                    DSN, project, "agent:alice",
                    hmac_key_path=str(key_file),
                    private_key_dir=str(tmp_path / "principals"),
                )
            assert exc_info.value.code is (
                ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
            )
            assert exc_info.value.detail["stage"] == "mint_new_key"
            assert exc_info.value.detail["blocked_on"]

            # It refuses BEFORE minting: no orphaned private key is left behind.
            priv_key_path = tmp_path / "principals" / "agent:alice_ed25519.key"
            assert not priv_key_path.exists()
            # ...and the key file was not amended with an entry nothing can enrol.
            key_data = json.loads(key_file.read_text())
            assert [
                k for k in key_data["keys"] if k.get("principal_id") == "agent:alice"
            ] == []
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_principal_reuse_path_is_refused_too(self, tmp_path):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64",
             "status": "active"},
            {"key_id": "pk_reuse", "scheme": "ed25519", "status": "active",
             "principal_id": "agent:carol",
             "public_key": base64.b64encode(b"\x01" * 32).decode()},
        ]}))
        try:
            provision(DSN, [project])
            with pytest.raises(RegistaError) as exc_info:
                provision_principal(
                    DSN, project, "agent:carol",
                    hmac_key_path=str(key_file),
                    private_key_dir=str(tmp_path / "principals"),
                    reuse_existing_key=True,
                )
            assert exc_info.value.code is (
                ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
            )
            assert exc_info.value.detail["stage"] == "reuse_existing_key"
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_already_existing_key_is_still_reported_without_a_write(self, tmp_path):
        """The read path survives: an existing active key short-circuits before the
        refusal, because reporting an existing enrolment writes nothing."""
        from regista.testing import seed_legacy_principal_key

        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64", "status": "active"}
        ]}))
        try:
            provision(DSN, [project])
            from regista._connection import ConnectionManager

            mgr = ConnectionManager(DSN, project)
            mgr.open()
            try:
                entry = seed_legacy_principal_key(mgr, "agent:bob", b"\x02" * 32, "ed25519")
            finally:
                mgr.close()

            result = provision_principal(
                DSN, project, "agent:bob",
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
            )
            assert result.already_existed is True
            assert result.key_id == entry.key_id
            assert result.private_key_stored is False
            assert result.public_key_registered is False
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_principal_dry_run(self, tmp_path):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": []}))
        try:
            provision(DSN, [project])
            result = provision_principal(
                DSN, project, "agent:carol",
                hmac_key_path=str(key_file),
                dry_run=True,
            )
            assert result.key_id == "(dry-run)"
            assert result.private_key_stored is False
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")


class TestSecretRefInKeySet:
    def test_key_set_loads_secret_ref(self, tmp_path):
        secret_file = tmp_path / "private.key"
        secret_file.write_bytes(b"test-secret-bytes")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "ref-key-001",
                "scheme": "hmac-sha256",
                "secret_ref": f"file:{secret_file}",
                "status": "active",
            }
        ]}))
        from regista._keys import KeySet
        ks = KeySet(str(key_file))
        entry = ks.get_key("ref-key-001")
        assert entry.secret == b"test-secret-bytes"
