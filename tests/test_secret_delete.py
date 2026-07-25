"""Tests for secret deletion — the custody half an offboarding needs.

Revoking a principal key windows it out of the registry, but the private key
stays fetchable until it leaves the backend. These tests pin the delete side:
that it actually removes material, that re-running is safe, and — the part
that is easy to get wrong — that backends which cannot really delete say so
instead of reporting success.
"""

from __future__ import annotations

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.secrets import (
    DeleteOutcome,
    delete,
    resolve,
    store,
    supports_delete,
)

# ---------------------------------------------------------------------------
# file: the reference points at stored material
# ---------------------------------------------------------------------------


def test_delete_removes_the_file(tmp_path):
    path = tmp_path / "principal.key"
    ref = store(f"file:{path}", b"private-key-material")
    assert resolve(ref) == b"private-key-material"

    assert delete(ref) is DeleteOutcome.DELETED
    assert not path.exists()


def test_delete_is_idempotent(tmp_path):
    """Re-running an offboarding must not fail on the already-removed key."""
    path = tmp_path / "principal.key"
    ref = store(f"file:{path}", b"x")

    assert delete(ref) is DeleteOutcome.DELETED
    assert delete(ref) is DeleteOutcome.ALREADY_ABSENT


def test_delete_makes_the_key_unresolvable(tmp_path):
    """The point of the exercise: the fetch path closes."""
    path = tmp_path / "principal.key"
    ref = store(f"file:{path}", b"x")
    delete(ref)

    with pytest.raises(RegistaError) as exc:
        resolve(ref)
    assert exc.value.code is ErrorCode.KEY_LOAD_ERROR


def test_delete_reports_an_undeletable_file(tmp_path):
    """A directory in the way is a failure, not an 'already absent'."""
    path = tmp_path / "not-a-file"
    path.mkdir()

    with pytest.raises(RegistaError):
        delete(f"file:{path}")


# ---------------------------------------------------------------------------
# Backends that cannot delete, and backends with nothing to delete
# ---------------------------------------------------------------------------


def test_env_refuses_rather_than_pretending():
    """Clearing os.environ would only affect this process."""
    with pytest.raises(RegistaError) as exc:
        delete("env:SOME_VAR")
    assert exc.value.code is ErrorCode.SECRET_WRITE_UNSUPPORTED


def test_literal_reports_inline_not_deleted():
    """The value IS the reference — claiming DELETED would be a lie."""
    assert delete("literal:hunter2") is DeleteOutcome.INLINE_REF


def test_inline_ref_is_not_deleted():
    """Guard the distinction itself, so it cannot be collapsed to a bool."""
    assert DeleteOutcome.INLINE_REF is not DeleteOutcome.DELETED


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_delete_rejects_an_empty_ref():
    with pytest.raises(RegistaError) as exc:
        delete("")
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT


def test_an_unknown_prefix_is_treated_as_a_literal():
    """Pinning a sharp edge rather than asserting what would be tidier.

    ``_detect_prefix`` maps any unrecognised scheme to ``literal``, so a typo
    like ``vualt:...`` is not an error — delete reports INLINE_REF and removes
    nothing. That is the module-wide convention (``resolve`` would hand back
    the string itself), so delete follows it rather than diverging.
    """
    assert delete("nosuchbackend:whatever") is DeleteOutcome.INLINE_REF


def test_delete_rejects_a_known_but_unregistered_provider():
    """`vault:` without hvac installed must fail, not silently do nothing."""
    from regista.secrets import available_providers

    if "vault" in available_providers():
        pytest.skip("vault provider is registered in this environment")
    with pytest.raises(RegistaError) as exc:
        delete("vault:secret/agent-suite/principals/alice/key")
    assert exc.value.code is ErrorCode.SECRET_RESOLVE_FAILED


def test_supports_delete_reports_per_provider():
    assert supports_delete("file") is True
    assert supports_delete("no-such-provider") is False


def test_a_provider_without_delete_is_reported_not_crashed():
    """Third-party providers registered before delete existed must not blow up."""
    from regista.secrets import register_provider, unregister_provider

    class LegacyProvider:
        name = "legacyprov"

        def resolve(self, ref: str) -> bytes:
            return b""

        def store(self, ref: str, data: bytes) -> str:
            return ref

    register_provider(LegacyProvider())
    try:
        assert supports_delete("legacyprov") is False
        with pytest.raises(RegistaError) as exc:
            delete("legacyprov:anything")
        assert exc.value.code is ErrorCode.SECRET_WRITE_UNSUPPORTED
    finally:
        unregister_provider("legacyprov")


# ---------------------------------------------------------------------------
# Vault: the shared-path case, where a naive delete destroys other secrets
# ---------------------------------------------------------------------------


class _FakeKvV2:
    def __init__(self, data: dict[str, dict]) -> None:
        self._data = data
        self.destroyed: list[str] = []

    def read_secret_version(self, path: str, mount_point: str):
        if path not in self._data:
            raise KeyError(path)
        return {"data": {"data": dict(self._data[path])}}

    def create_or_update_secret(self, path: str, mount_point: str, secret: dict):
        self._data[path] = dict(secret)

    def delete_metadata_and_all_versions(self, path: str, mount_point: str):
        self.destroyed.append(path)
        self._data.pop(path, None)


class _FakeVaultProvider:
    """Mirrors VaultProvider.delete against an in-memory kv2."""

    name = "fakevault"

    def __init__(self, kv: _FakeKvV2) -> None:
        self._kv = kv

    def resolve(self, ref: str) -> bytes:
        return b""

    def store(self, ref: str, data: bytes) -> str:
        return ref

    def delete(self, ref: str) -> DeleteOutcome:
        from regista._secrets import DeleteOutcome as Outcome

        parts = ref.split("/")
        mount, key_name, path = parts[0], parts[-1], "/".join(parts[1:-1])
        try:
            resp = self._kv.read_secret_version(path=path, mount_point=mount)
        except Exception:
            return Outcome.ALREADY_ABSENT
        data = dict(resp["data"]["data"])
        if key_name not in data:
            return Outcome.ALREADY_ABSENT
        del data[key_name]
        if data:
            self._kv.create_or_update_secret(
                path=path, mount_point=mount, secret=data
            )
        else:
            self._kv.delete_metadata_and_all_versions(path=path, mount_point=mount)
        return Outcome.DELETED


def test_vault_delete_preserves_other_keys_at_the_same_path():
    """Destroying the path would take secrets that are not ours to remove."""
    kv = _FakeKvV2({"agent-suite/principals/alice": {"key": "ours", "other": "theirs"}})
    provider = _FakeVaultProvider(kv)

    assert provider.delete("secret/agent-suite/principals/alice/key") is DeleteOutcome.DELETED
    assert kv._data["agent-suite/principals/alice"] == {"other": "theirs"}
    assert kv.destroyed == [], "destroyed a path still holding another secret"


def test_vault_delete_destroys_the_path_when_it_becomes_empty():
    """A soft delete would leave the key recoverable, which is not offboarded."""
    kv = _FakeKvV2({"agent-suite/principals/alice": {"key": "ours"}})
    provider = _FakeVaultProvider(kv)

    assert provider.delete("secret/agent-suite/principals/alice/key") is DeleteOutcome.DELETED
    assert kv.destroyed == ["agent-suite/principals/alice"]


def test_vault_delete_of_a_missing_key_is_already_absent():
    kv = _FakeKvV2({"agent-suite/principals/alice": {"other": "theirs"}})
    provider = _FakeVaultProvider(kv)

    assert (
        provider.delete("secret/agent-suite/principals/alice/key")
        is DeleteOutcome.ALREADY_ABSENT
    )
