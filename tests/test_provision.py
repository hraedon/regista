from __future__ import annotations

import json
import uuid

from regista._provision import (
    provision,
    provision_principal,
)
from tests.conftest import DSN


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
    def test_provision_principal_issues_keypair(self, tmp_path):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64", "status": "active"}
        ]}))
        try:
            provision(DSN, [project])
            result = provision_principal(
                DSN, project, "alice",
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
            )
            assert result.error is None
            assert result.already_existed is False
            assert result.private_key_stored is True
            assert result.public_key_registered is True
            assert result.key_id.startswith("pk_")
            assert result.fingerprint.startswith("ed25519:sha256:")

            priv_key_path = tmp_path / "principals" / "alice_ed25519.key"
            assert priv_key_path.exists()

            key_data = json.loads(key_file.read_text())
            ed25519_entries = [
                k for k in key_data["keys"]
                if k.get("scheme") == "ed25519" and k.get("principal_id") == "alice"
            ]
            assert len(ed25519_entries) == 1
            assert ed25519_entries[0]["status"] == "active"
            assert "secret_ref" in ed25519_entries[0]
            assert "public_key" in ed25519_entries[0]
        finally:
            _drop_schema(project)
            _drop_role(f"regista_{project}")

    def test_provision_principal_idempotent(self, tmp_path):
        project = f"prov_{uuid.uuid4().hex[:8]}"
        _drop_schema(project)
        _drop_role(f"regista_{project}")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64", "status": "active"}
        ]}))
        try:
            provision(DSN, [project])
            result1 = provision_principal(
                DSN, project, "bob",
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
            )
            result2 = provision_principal(
                DSN, project, "bob",
                hmac_key_path=str(key_file),
                private_key_dir=str(tmp_path / "principals"),
            )
            assert result2.already_existed is True
            assert result2.key_id == result1.key_id
            assert result2.fingerprint == result1.fingerprint
            assert result2.private_key_stored is False
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
                DSN, project, "carol",
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
