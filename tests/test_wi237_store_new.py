"""WI-237 — create-only/CAS custody writes for migrations (``store_new``).

``store()`` is an unconditional upsert: a migration write to a path that
unexpectedly already exists silently clobbers it, and dedicated per-secret
paths only prevent *sibling* clobbering, not same-path surprises. The
migration-grade contract under test:

1. **Create-only**: vault uses KV-v2 ``cas=0`` so a pre-existing path is
   refused by Vault itself, not just by our pre-read; ``file:`` opens the
   destination with ``O_EXCL``.
2. **Read-back verification**: after a create the value is read back and its
   fingerprint (sha256 of the stored bytes) compared; a mismatch raises.
3. **Idempotent re-run**: a pre-existing destination REFUSES
   (``SECRET_ALREADY_EXISTS``) unless what is already there is byte-identical
   to what we were about to write — then ``ALREADY_PRESENT`` is returned, a
   distinct outcome rather than a silent success.

Vault is a client double throughout (the WI-228 idiom) — no live Vault. The
double's ``create_or_update_secret`` enforces ``cas`` the way KV-v2 does, so
"cas=0 was actually sent" is proved by behaviour, not by argument capture
alone.
"""

from __future__ import annotations

import base64
import stat

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._secrets import FileProvider, StoreNewOutcome, VaultProvider, store_new

_regista_db_dependent = False

_ADDR = "https://vault.example:8200"
_REF = "kv/agent-suite/hosts/h/regista/hmac_key"


class FakeVaultError(Exception):
    pass


class FakeForbiddenError(FakeVaultError):
    pass


class FakeInvalidPathError(FakeVaultError):
    pass


class FakeInvalidRequestError(FakeVaultError):
    """What hvac raises when KV-v2 rejects a check-and-set write."""


class _FakeKvV2:
    def __init__(self, server):
        self._server = server

    def read_secret_version(self, path, mount_point, raise_on_deleted_version=None):
        data = self._server.store.get((mount_point, path))
        if data is None:
            raise FakeInvalidPathError("no such path")
        return {"data": {"data": dict(data)}}

    def create_or_update_secret(self, path, mount_point, secret, cas=None):
        self._server.writes.append(
            {"mount": mount_point, "path": path, "secret": dict(secret), "cas": cas}
        )
        exists = (mount_point, path) in self._server.store
        # KV-v2 semantics: cas=0 means "only create"; a pre-existing path is
        # a 400 InvalidRequest, which is what makes the race closable
        # server-side rather than by our pre-read.
        if cas == 0 and exists:
            raise FakeInvalidRequestError("check-and-set parameter did not match")
        stored = dict(secret)
        if self._server.corrupt_writes:
            stored = {k: "corrupted-by-backend" for k in stored}
        self._server.store[(mount_point, path)] = stored
        return {"data": {"version": 1}}


class FakeVaultServer:
    def __init__(self):
        self.store = {}
        self.writes = []
        self.corrupt_writes = False


class FakeClient:
    def __init__(self, url, server):
        self.url = url
        self.token = None
        self.secrets = type(
            "_S", (), {"kv": type("_Kv", (), {"v2": _FakeKvV2(server)})()}
        )()
        self.auth = type(
            "_A",
            (),
            {"token": type("_T", (), {"lookup_self": staticmethod(lambda: {})})()},
        )()

    def is_authenticated(self):
        return True


class _FakeExceptions:
    Forbidden = FakeForbiddenError
    InvalidPath = FakeInvalidPathError
    InvalidRequest = FakeInvalidRequestError


@pytest.fixture
def server():
    return FakeVaultServer()


@pytest.fixture
def provider(monkeypatch, server):
    prov = VaultProvider(
        client_factory=lambda url: FakeClient(url, server),
        environ={"VAULT_ADDR": _ADDR, "VAULT_TOKEN": "dev-token"},
    )
    fake_hvac = type("H", (), {"exceptions": _FakeExceptions})
    monkeypatch.setattr(prov, "_hvac", lambda: fake_hvac)
    return prov


def _encoded(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Vault: create / refuse / idempotent re-run / read-back
# ---------------------------------------------------------------------------


class TestVaultStoreNew:
    def test_creates_when_absent(self, provider, server):
        assert provider.store_new(_REF, b"payload") is StoreNewOutcome.CREATED
        stored = server.store[("kv", "agent-suite/hosts/h/regista")]
        # Round-trips through the same base64 encoding store() uses.
        assert stored == {"hmac_key": _encoded(b"payload")}
        assert provider.resolve(_REF) == _encoded(b"payload").encode()

    def test_the_create_is_cas_0(self, provider, server):
        """cas=0 is the whole point: Vault, not our pre-read, refuses dupes."""
        provider.store_new(_REF, b"payload")
        assert [w["cas"] for w in server.writes] == [0]

    def test_refuses_a_pre_existing_path_with_different_material(
        self, provider, server
    ):
        server.store[("kv", "agent-suite/hosts/h/regista")] = {
            "hmac_key": _encoded(b"the-old-key")
        }
        with pytest.raises(RegistaError) as exc:
            provider.store_new(_REF, b"the-new-key")
        assert exc.value.code == ErrorCode.SECRET_ALREADY_EXISTS
        assert "refusing to overwrite" in exc.value.message
        # And nothing was written.
        assert server.writes == []
        assert server.store[("kv", "agent-suite/hosts/h/regista")] == {
            "hmac_key": _encoded(b"the-old-key")
        }

    def test_idempotent_rerun_reports_already_present(self, provider, server):
        """A re-run with identical material is safe — and says what happened
        rather than pretending it wrote something."""
        assert provider.store_new(_REF, b"payload") is StoreNewOutcome.CREATED
        assert provider.store_new(_REF, b"payload") is StoreNewOutcome.ALREADY_PRESENT
        # Only the original create ever reached the backend.
        assert len(server.writes) == 1

    def test_store_then_store_new_of_the_same_material_matches(self, provider):
        """Fingerprints compare like-for-like with store()'s encoding: a value
        custodied by plain store() is recognized as already present."""
        provider.store(_REF, b"payload")
        assert provider.store_new(_REF, b"payload") is StoreNewOutcome.ALREADY_PRESENT

    def test_a_path_with_only_other_fields_still_refuses(self, provider, server):
        """store() replaces the whole path map, so writing 'just our field'
        into an occupied path would clobber the siblings — refuse instead."""
        server.store[("kv", "agent-suite/hosts/h/regista")] = {"other": "keep-me"}
        with pytest.raises(RegistaError) as exc:
            provider.store_new(_REF, b"payload")
        assert exc.value.code == ErrorCode.SECRET_ALREADY_EXISTS
        assert server.store[("kv", "agent-suite/hosts/h/regista")] == {
            "other": "keep-me"
        }

    def test_read_back_mismatch_raises(self, provider, server):
        """What lands must be what was written; a backend that mangles the
        value must not be reported as a successful custody."""
        server.corrupt_writes = True
        with pytest.raises(RegistaError) as exc:
            provider.store_new(_REF, b"payload")
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED
        assert "read-back" in exc.value.message

    def _race(self, monkeypatch, server, landed_value):
        """Make the concurrent writer win: absent at pre-read, present at write."""
        original = _FakeKvV2.create_or_update_secret

        def racing(fake_self, path, mount_point, secret, cas=None):
            server.store[(mount_point, path)] = {"hmac_key": landed_value}
            return original(fake_self, path, mount_point, secret, cas=cas)

        monkeypatch.setattr(_FakeKvV2, "create_or_update_secret", racing)

    def test_lost_cas_race_with_matching_material_is_already_present(
        self, provider, server, monkeypatch
    ):
        """The concurrent writer stored the same material, so the honest
        answer is ALREADY_PRESENT — not an opaque CAS failure."""
        self._race(monkeypatch, server, _encoded(b"payload"))
        assert provider.store_new(_REF, b"payload") is StoreNewOutcome.ALREADY_PRESENT

    def test_lost_cas_race_with_different_material_refuses(
        self, provider, server, monkeypatch
    ):
        self._race(monkeypatch, server, _encoded(b"other"))
        with pytest.raises(RegistaError) as exc:
            provider.store_new(_REF, b"payload")
        assert exc.value.code == ErrorCode.SECRET_ALREADY_EXISTS

    def test_short_ref_is_rejected_before_any_network_call(self, provider, server):
        with pytest.raises(RegistaError) as exc:
            provider.store_new("kv/too/short", b"x")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert server.writes == []


# ---------------------------------------------------------------------------
# file: O_EXCL semantics
# ---------------------------------------------------------------------------


class TestFileStoreNew:
    def test_creates_when_absent(self, tmp_path):
        path = tmp_path / "keys" / "material.key"
        provider = FileProvider()
        assert provider.store_new(str(path), b"payload") is StoreNewOutcome.CREATED
        assert path.read_bytes() == b"payload"

    def test_created_file_is_0600(self, tmp_path):
        path = tmp_path / "material.key"
        FileProvider().store_new(str(path), b"payload")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_refuses_a_pre_existing_file_with_different_content(self, tmp_path):
        path = tmp_path / "material.key"
        path.write_bytes(b"the-old-key")
        with pytest.raises(RegistaError) as exc:
            FileProvider().store_new(str(path), b"the-new-key")
        assert exc.value.code == ErrorCode.SECRET_ALREADY_EXISTS
        assert path.read_bytes() == b"the-old-key"

    def test_idempotent_rerun_reports_already_present(self, tmp_path):
        path = tmp_path / "material.key"
        provider = FileProvider()
        assert provider.store_new(str(path), b"payload") is StoreNewOutcome.CREATED
        assert (
            provider.store_new(str(path), b"payload")
            is StoreNewOutcome.ALREADY_PRESENT
        )

    def test_no_fallback_name_is_ever_created(self, tmp_path):
        """_open_exclusive's collision behaviour is to write a *different*
        file — liveness for a tmp file, a silent miss for a destination.
        store_new must never do that."""
        path = tmp_path / "material.key"
        path.write_bytes(b"existing")
        with pytest.raises(RegistaError):
            FileProvider().store_new(str(path), b"payload")
        assert [p.name for p in tmp_path.iterdir()] == ["material.key"]

    def test_read_back_mismatch_raises(self, tmp_path, monkeypatch):
        from pathlib import Path

        path = tmp_path / "material.key"
        monkeypatch.setattr(Path, "read_bytes", lambda self: b"corrupted")
        with pytest.raises(RegistaError) as exc:
            FileProvider().store_new(str(path), b"payload")
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED
        assert "read-back" in exc.value.message


# ---------------------------------------------------------------------------
# Module-level dispatch, and providers without create-only semantics
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_dispatches_to_the_file_provider(self, tmp_path):
        path = tmp_path / "material.key"
        assert store_new(f"file:{path}", b"payload") is StoreNewOutcome.CREATED
        assert path.read_bytes() == b"payload"

    @pytest.mark.parametrize("ref", ["env:SOME_VAR", "literal:some-value"])
    def test_providers_without_create_only_semantics_refuse(self, ref):
        with pytest.raises(RegistaError) as exc:
            store_new(ref, b"payload")
        assert exc.value.code == ErrorCode.SECRET_WRITE_UNSUPPORTED

    def test_empty_ref_is_invalid(self):
        with pytest.raises(RegistaError) as exc:
            store_new("", b"payload")
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_public_facade_exports_it(self):
        import regista.secrets as public

        assert callable(public.store_new)
        assert public.StoreNewOutcome is StoreNewOutcome
        assert "store_new" in public.__all__
        assert "StoreNewOutcome" in public.__all__
