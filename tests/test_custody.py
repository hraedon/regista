from __future__ import annotations

import base64
import json
import sys
import uuid

import pytest
from _helpers import DSN

from regista._custody import (
    build_ref,
    operator_ref_template,
    resolve_backend,
    store_private_key,
)
from regista._errors import ErrorCode, RegistaError
from regista._provision import provision, provision_principal
from regista._secrets import (
    register_provider,
    unregister_provider,
)
from regista._secrets import (
    resolve as resolve_secret,
)
from regista._secrets import (
    store as store_secret,
)
from regista.testing import drop_project_schema


def _drop(project: str) -> None:
    drop_project_schema(DSN, project)


class _FakeVaultProvider:
    name = "vault"

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def resolve(self, ref: str) -> bytes:
        if ref not in self._store:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: key not found at {ref}",
            )
        return self._store[ref].encode("ascii")

    def store(self, ref: str, data: bytes) -> str:
        self._store[ref] = base64.b64encode(data).decode("ascii")
        return f"vault:{ref}"

    def reset(self) -> None:
        self._store.clear()


@pytest.fixture
def fake_vault():
    from regista._secrets import _PROVIDERS

    provider = _FakeVaultProvider()
    prev = _PROVIDERS.get("vault")
    register_provider(provider)
    yield provider
    if prev is not None:
        register_provider(prev)
    else:
        unregister_provider("vault")


@pytest.fixture
def project_with_keys(tmp_path):
    project = f"custody_{uuid.uuid4().hex[:8]}"
    _drop(project)
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [
        {"key_id": "bootstrap", "secret": "dGVzdA==", "encoding": "base64", "status": "active"}
    ]}))
    try:
        provision(DSN, [project])
        yield project, key_file
    finally:
        _drop(project)


class TestStoreProtocol:
    def test_file_store_writes_0600_and_returns_ref(self, tmp_path):
        target = tmp_path / "out" / "key.bin"
        ref = store_secret(f"file:{target}", b"raw-bytes")
        assert ref == f"file:{target}"
        assert target.read_bytes() == b"raw-bytes"
        assert target.stat().st_mode & 0o777 == 0o600

    def test_file_store_is_atomic_no_tmp_leftover(self, tmp_path):
        target = tmp_path / "key.bin"
        store_secret(f"file:{target}", b"data")
        assert not (tmp_path / "key.bin.tmp").exists()

    def test_env_store_raises_unsupported(self):
        with pytest.raises(RegistaError) as exc:
            store_secret("env:MY_VAR", b"data")
        assert exc.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    def test_literal_store_raises_unsupported(self):
        with pytest.raises(RegistaError) as exc:
            store_secret("literal:foo", b"data")
        assert exc.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    def test_store_empty_ref_raises(self):
        with pytest.raises(RegistaError) as exc:
            store_secret("", b"data")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_file_round_trip(self, tmp_path):
        target = tmp_path / "k.bin"
        ref = store_secret(f"file:{target}", b"payload")
        assert resolve_secret(ref) == b"payload"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI only")
class TestWindowsStore:
    def test_store_returns_windows_ref_and_round_trips(self):
        ref = store_secret("windows:some-label", b"secret-data")
        assert ref.startswith("windows:")
        assert resolve_secret(ref) == b"secret-data"


class TestCustodyHelper:
    def test_file_backend_stores_key_and_returns_public_key(self, tmp_path):
        result = store_private_key(
            backend="file",
            principal_id="alice",
            private_key_dir=str(tmp_path / "principals"),
        )
        assert result.backend == "file"
        assert result.encoding is None
        assert result.secret_ref.startswith("file:")
        assert len(result.public_key) == 32
        key_path = tmp_path / "principals" / "alice_ed25519.key"
        assert key_path.exists()
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert resolve_secret(result.secret_ref) == key_path.read_bytes()

    def test_fake_vault_backend_writes_no_local_key_file(self, tmp_path, fake_vault):
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()
        result = store_private_key(
            backend="vault",
            principal_id="bob",
            project="myproj",
            private_key_dir=str(principals_dir),
        )
        assert result.backend == "vault"
        assert result.encoding == "base64"
        assert result.secret_ref.startswith("vault:")
        assert not any(principals_dir.iterdir()), "no .key file should be written to disk"
        resolved = resolve_secret(result.secret_ref)
        decoded = base64.b64decode(resolved)
        assert len(decoded) == 32

    def test_operator_backend_raises_external_without_keypair(self, tmp_path):
        with pytest.raises(RegistaError) as exc:
            store_private_key(
                backend="operator",
                principal_id="carol",
                project="myproj",
                private_key_dir=str(tmp_path / "principals"),
            )
        assert exc.value.code == ErrorCode.SECRET_WRITE_EXTERNAL
        assert "operator" in str(exc.value)
        assert exc.value.detail is not None
        assert "ref_template" in exc.value.detail
        assert not (tmp_path / "principals").exists() or not any(
            (tmp_path / "principals").iterdir()
        )

    def test_unknown_backend_raises_invalid_argument(self, tmp_path):
        with pytest.raises(RegistaError) as exc:
            store_private_key(
                backend="nonsense",
                principal_id="dave",
                private_key_dir=str(tmp_path),
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_build_ref_file(self, tmp_path):
        ref = build_ref("file", "eve", private_key_dir=str(tmp_path))
        assert ref == f"file:{tmp_path / 'eve_ed25519.key'}"

    def test_build_ref_vault(self):
        ref = build_ref("vault", "eve", project="proj")
        assert ref == "vault:secret/regista/proj/principals/eve/private_key"

    def test_build_ref_azure_sanitizes(self):
        ref = build_ref("azure", "eve.example.com", project="my_proj")
        assert ref == "azure:regista-my-proj-eve-example-com"

    def test_build_ref_azure_truncation_includes_hash(self):
        import hashlib

        long_id = "a" * 200
        ref = build_ref("azure", long_id, project="p")
        name = ref.removeprefix("azure:")
        assert len(name) <= 127
        raw = f"regista-p-{long_id}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        assert name.endswith(digest)

    def test_resolve_backend_defaults_to_file(self, monkeypatch):
        monkeypatch.delenv("REGISTA_SECRET_BACKEND", raising=False)
        assert resolve_backend(None) == "file"

    def test_resolve_backend_from_config(self, monkeypatch):
        monkeypatch.setenv("REGISTA_SECRET_BACKEND", "vault")
        assert resolve_backend(None) == "vault"

    def test_resolve_backend_explicit_overrides_config(self, monkeypatch):
        monkeypatch.setenv("REGISTA_SECRET_BACKEND", "vault")
        assert resolve_backend("windows") == "windows"

    def test_operator_ref_template(self):
        tmpl = operator_ref_template("alice", project="myproj")
        assert tmpl == "vault:secret/regista/myproj/principals/alice/private_key"

    def test_resolve_key_dir_file_ref_strips_prefix(self):
        from regista._provision import _resolve_key_dir

        d = _resolve_key_dir(None, "file:/opt/keys/keys.json", "file")
        assert d.endswith("opt/keys/principals")

    def test_resolve_key_dir_plain_path(self):
        from regista._provision import _resolve_key_dir

        d = _resolve_key_dir(None, "/opt/keys/keys.json", "file")
        assert d.endswith("opt/keys/principals")

    def test_resolve_key_dir_literal_ref_raises(self):
        from regista._provision import _resolve_key_dir

        with pytest.raises(RegistaError) as exc:
            _resolve_key_dir(None, 'literal:{"keys":[]}', "file")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_resolve_key_dir_env_ref_raises(self):
        from regista._provision import _resolve_key_dir

        with pytest.raises(RegistaError) as exc:
            _resolve_key_dir(None, "env:KEY_FILE_PATH", "file")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_resolve_key_dir_non_file_backend_returns_none(self):
        from regista._provision import _resolve_key_dir

        assert _resolve_key_dir(None, "env:X", "vault") is None

    def test_resolve_key_dir_explicit_overrides(self):
        from regista._provision import _resolve_key_dir

        assert _resolve_key_dir("/explicit", "env:X", "file") == "/explicit"

    def test_env_backend_raises_write_unsupported(self, tmp_path):
        with pytest.raises(RegistaError) as exc:
            store_private_key(
                backend="env",
                principal_id="eve",
                private_key_dir=str(tmp_path),
            )
        assert exc.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    def test_literal_backend_raises_write_unsupported(self, tmp_path):
        with pytest.raises(RegistaError) as exc:
            store_private_key(
                backend="literal",
                principal_id="eve",
                private_key_dir=str(tmp_path),
            )
        assert exc.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    def test_env_literal_error_raised_before_keypair_generation(self, tmp_path):
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()
        with pytest.raises(RegistaError):
            store_private_key(backend="env", principal_id="eve")
        assert not any(principals_dir.iterdir())

    def test_custom_writable_provider_via_register(self, tmp_path):
        class _MemProvider:
            name = "memstore"

            def __init__(self) -> None:
                self._data: dict[str, bytes] = {}

            def resolve(self, ref: str) -> bytes:
                return self._data[ref]

            def store(self, ref: str, data: bytes) -> str:
                self._data[ref] = data
                return f"memstore:{ref}"

        prov = _MemProvider()
        register_provider(prov)
        try:
            result = store_private_key(
                backend="memstore",
                principal_id="eve",
                private_key_dir=str(tmp_path),
            )
        finally:
            unregister_provider("memstore")
        assert result.backend == "memstore"
        assert result.encoding is None
        assert result.secret_ref.startswith("memstore:")
        assert resolve_secret(result.secret_ref) == resolve_secret(result.secret_ref)


class TestProvisionPrincipalBackendAware:
    def test_file_backend_provision_round_trip(self, project_with_keys, tmp_path):
        project, key_file = project_with_keys
        principals_dir = tmp_path / "principals"
        result = provision_principal(
            DSN, project, "agent:alice",
            hmac_key_path=str(key_file),
            private_key_dir=str(principals_dir),
            secret_backend="file",
        )
        assert result.secret_backend == "file"
        assert result.private_key_stored is True
        assert "private_key" not in result.to_dict()

        key_data = json.loads(key_file.read_text())
        entry = next(
            k for k in key_data["keys"]
            if k.get("principal_id") == "agent:alice"
        )
        assert entry["secret_ref"].startswith("file:")
        assert "encoding" not in entry

        priv_path = principals_dir / "agent:alice_ed25519.key"
        priv_bytes = priv_path.read_bytes()
        pub_b64 = entry["public_key"]
        pub_bytes = base64.b64decode(pub_b64)
        _assert_keypair_verifies(priv_bytes, pub_bytes)

    def test_vault_backend_provision_writes_no_plaintext_key(
        self, project_with_keys, tmp_path, fake_vault,
    ):
        project, key_file = project_with_keys
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()

        result = provision_principal(
            DSN, project, "agent:bob",
            hmac_key_path=str(key_file),
            private_key_dir=str(principals_dir),
            secret_backend="vault",
        )
        assert result.secret_backend == "vault"
        assert result.private_key_stored is True
        assert "private_key" not in result.to_dict()

        assert not any(principals_dir.iterdir()), (
            "the gap-catching test: a non-file backend must not write a "
            "plaintext .key file to local disk"
        )

        key_data = json.loads(key_file.read_text())
        entry = next(
            k for k in key_data["keys"]
            if k.get("principal_id") == "agent:bob"
        )
        assert entry["secret_ref"].startswith("vault:")
        assert entry.get("encoding") == "base64"

        resolved = resolve_secret(entry["secret_ref"])
        priv_bytes = base64.b64decode(resolved)
        pub_bytes = base64.b64decode(entry["public_key"])
        _assert_keypair_verifies(priv_bytes, pub_bytes)

    def test_operator_backend_provision_raises_loud(
        self, project_with_keys, tmp_path,
    ):
        project, key_file = project_with_keys
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()

        with pytest.raises(RegistaError) as exc:
            provision_principal(
                DSN, project, "agent:carol",
                hmac_key_path=str(key_file),
                private_key_dir=str(principals_dir),
                secret_backend="operator",
            )
        assert exc.value.code == ErrorCode.SECRET_WRITE_EXTERNAL
        assert not any(principals_dir.iterdir()), (
            "operator backend must not write any key file"
        )

    def test_dry_run_reports_backend(self, project_with_keys, tmp_path):
        project, key_file = project_with_keys
        result = provision_principal(
            DSN, project, "agent:dave",
            hmac_key_path=str(key_file),
            secret_backend="vault",
            dry_run=True,
        )
        assert result.secret_backend == "vault"
        assert result.private_key_stored is False


def _assert_keypair_verifies(private_key: bytes, public_key: bytes) -> None:
    import nacl.encoding
    import nacl.signing

    sk = nacl.signing.SigningKey(private_key)
    vk = sk.verify_key
    assert bytes(vk) == public_key
    msg = b"test-message"
    signed = sk.sign(msg)
    vk.verify(signed.message, signature=signed.signature)
