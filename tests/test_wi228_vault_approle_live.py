"""End-to-end AppRole proof against a real Vault (WI-228). Opt-in.

Skipped unless ``REGISTA_TEST_VAULT_APPROLE_DIR`` names a directory holding
credential material, so the default suite stays hermetic and offline. The
hermetic state-machine coverage is in ``test_wi228_vault_approle.py``; this module
exists because "AppRole-only works" is a claim about a real Vault, and the
qualification's finding was precisely that a compensating control had been
mistaken for evidence.

To run it, create scoped material inside the sanctioned namespace
(``kv/agent-suite/qual/**``, ``auth/approle/role/qual-*``,
``sys/policies/acl/agent-suite-qual*``) and point the variables at it:

    kv/agent-suite/qual/wi228/probe        field `hmac_key`
    sys/policies/acl/agent-suite-qual-wi228  read on kv/{data,metadata}/agent-suite/qual/wi228/*
    auth/approle/role/qual-wi228           token_ttl=60s secret_id_num_uses=0

    export REGISTA_TEST_VAULT_APPROLE_DIR=/path/holding/role-id+secret-id
    export VAULT_ADDR=https://vault.example:8200
    # deliberately NO VAULT_TOKEN
    pytest tests/test_wi228_vault_approle_live.py -v

The directory must contain ``role-id`` and ``secret-id`` (one value per file,
mode 0600), and optionally ``wrapping-token`` for the response-wrapped case.
``expected-sha256`` lets the assertions check the resolved value without ever
printing it.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import time

import pytest

_regista_db_dependent = False

_DIR = os.environ.get("REGISTA_TEST_VAULT_APPROLE_DIR")

pytestmark = pytest.mark.skipif(
    not _DIR,
    reason="set REGISTA_TEST_VAULT_APPROLE_DIR to run the live AppRole proof",
)

REF = "kv/agent-suite/qual/wi228/probe/hmac_key"
DENIED_REF = "kv/agent-suite/qual/shared/db/regista_dsn_password"


def _material(name):
    path = pathlib.Path(_DIR) / name
    if not path.is_file():
        pytest.skip(f"{name} not present in REGISTA_TEST_VAULT_APPROLE_DIR")
    return str(path)


@pytest.fixture
def approle_env(monkeypatch):
    """The production posture: AppRole material, and no VAULT_TOKEN at all."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_ROLE_ID_FILE", _material("role-id"))
    monkeypatch.setenv("VAULT_SECRET_ID_FILE", _material("secret-id"))
    assert "VAULT_TOKEN" not in os.environ
    assert os.environ.get("VAULT_ADDR"), "VAULT_ADDR must be set"


@pytest.fixture
def provider(approle_env):
    from regista._secrets import VaultProvider

    return VaultProvider()


def _expected_sha256():
    path = pathlib.Path(_DIR) / "expected-sha256"
    if not path.is_file():
        return None
    return path.read_text().strip()


class TestLiveAppRole:
    def test_resolves_with_no_vault_token(self, provider):
        """The posture docs/secrets-vault.md §6 requires and §QL-F1 said was impossible.

        On origin/main this same environment produced
        `[KEY_LOAD_ERROR] vault: authentication failed`.
        """
        value = provider.resolve(REF)
        assert value, "resolved an empty secret"
        expected = _expected_sha256()
        if expected:
            assert hashlib.sha256(value).hexdigest() == expected

    def test_reports_approle_as_the_active_method(self, provider):
        provider.resolve(REF)
        status = provider.auth_status()
        assert status["active_method"] == "approle"
        assert status["configured_method"] == "approle"
        assert status["role_id_source"] == "file:VAULT_ROLE_ID_FILE"
        assert status["secret_id_source"] == "file:VAULT_SECRET_ID_FILE"
        assert status["lease_duration_seconds"] and status["lease_duration_seconds"] > 0
        assert status["reauthenticatable"] is True

    def test_status_carries_no_credential_values(self, provider):
        provider.resolve(REF)
        blob = repr(provider.auth_status())
        for name in ("role-id", "secret-id"):
            secret = pathlib.Path(_DIR, name).read_text().strip()
            assert secret not in blob

    def test_a_ref_outside_the_policy_is_a_clean_error(self, provider):
        """A scoped policy makes 403 the common case, not the exotic one."""
        from regista._errors import ErrorCode, RegistaError

        provider.resolve(REF)  # prove the credential itself is good first
        with pytest.raises(RegistaError) as exc:
            provider.resolve(DENIED_REF)
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED
        assert "permission denied" in exc.value.message
        # Correctly attributed to policy rather than to a dead token.
        assert exc.value.detail["token_valid"] is True
        assert exc.value.detail["auth_method"] == "approle"

    def test_a_policy_denial_does_not_trigger_a_relogin(self, provider):
        from regista._errors import RegistaError

        provider.resolve(REF)
        before = provider.auth_status()["logins"]
        with pytest.raises(RegistaError):
            provider.resolve(DENIED_REF)
        assert provider.auth_status()["logins"] == before

    def test_response_wrapped_secret_id_delivery(self, monkeypatch):
        """docs/secrets-vault.md §5: only a single-use wrapping token lands on disk.

        Needs a freshly issued `wrapping-token` file; a spent or expired one
        makes this skip rather than fail, since the token is one-shot by design.
        """
        from regista._errors import RegistaError
        from regista._secrets import VaultProvider

        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.setenv("VAULT_ROLE_ID_FILE", _material("role-id"))
        monkeypatch.setenv("VAULT_SECRET_ID_FILE", _material("wrapping-token"))
        monkeypatch.setenv("VAULT_SECRET_ID_RESPONSE_WRAPPED", "1")
        provider = VaultProvider()
        try:
            value = provider.resolve(REF)
        except RegistaError as e:
            if "single-use" in e.message:
                pytest.skip("wrapping token already spent — issue a fresh one")
            raise
        assert value
        assert provider.auth_status()["secret_id_source"] == (
            "file:VAULT_SECRET_ID_FILE (response-wrapped)"
        )

    @pytest.mark.skipif(
        os.environ.get("REGISTA_TEST_VAULT_LEASE_SECONDS") is None,
        reason=(
            "set REGISTA_TEST_VAULT_LEASE_SECONDS to the role's token_ttl to run "
            "the real lease-expiry proof (it sleeps past it)"
        ),
    )
    def test_survives_a_real_lease_expiry(self, provider):
        """The mechanism behind dossier's 503 and cairn integrity's exit 1.

        One provider held across the expiry boundary, exactly as a long-running
        service holds one. On origin/main the client was cached for the process
        lifetime, so the first read after the lease lapsed failed and never
        recovered.
        """
        lease = int(os.environ["REGISTA_TEST_VAULT_LEASE_SECONDS"])
        first = provider.resolve(REF)
        logins_before = provider.auth_status()["logins"]
        time.sleep(lease + 15)
        second = provider.resolve(REF)
        assert second == first
        assert provider.auth_status()["logins"] > logins_before, (
            "no re-authentication happened — the provider would have wedged"
        )
