"""VaultProvider AppRole login (WI-228).

`docs/secrets-vault.md` §6 requires a production host to operate with **no
`VAULT_TOKEN`** in its environment. Before this, `VaultProvider` authenticated
with `VAULT_TOKEN` and nothing else, so the Linux qualification could not reach
that posture: it wrote an undocumented wrapper script that minted a 1h token per
invocation, and correctly labelled it a compensating control rather than
evidence. Because the shim lived outside any generated systemd unit,
systemd-launched services never got a token at all — which is why `cairn
integrity` exited 1 and dossier's `/healthz` returned 503 on that host.

These tests cover the whole auth state machine without a Vault, by injecting a
client double. They assert the four properties WI-228 asks for:

  1. An AppRole-only resolve works with **no VAULT_TOKEN in the environment**.
  2. The resolver **reports which method it used**, so a host cannot silently sit
     on the weaker one.
  3. AppRole material that is configured but unusable **fails closed** with an
     actionable message, and never falls back to the dev token.
  4. A login yields a **lease**, and a long-running process re-authenticates
     rather than wedging when it expires.

The matching end-to-end proof against the real Vault lives in
`test_wi228_vault_approle_live.py`, which is skipped unless an operator opts in.
"""

from __future__ import annotations

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._secrets import DeleteOutcome, VaultProvider, _vault_auth_shape

_regista_db_dependent = False

_ADDR = "https://vault.example:8200"
_REF = "kv/agent-suite/qual/hosts/h/regista/hmac_key"
_SECRET = "aGVsbG8td29ybGQ="  # not a credential: fixture payload


class FakeVaultError(Exception):
    """Base for the doubles' exceptions, mirroring hvac's hierarchy."""


# Named with the Error suffix for the linter; each maps to the hvac exception
# whose name it echoes (hvac.exceptions.Forbidden / .InvalidPath).
class FakeForbiddenError(FakeVaultError):
    pass


class FakeInvalidPathError(FakeVaultError):
    pass


class _FakeKvV2:
    def __init__(self, client):
        self._client = client

    def read_secret_version(self, path, mount_point, raise_on_deleted_version=None):
        self._client.reads.append((mount_point, path, self._client.token))
        if self._client.read_raises is not None:
            raise self._client.read_raises
        if not self._client.token_valid():
            raise FakeForbiddenError("permission denied")
        data = self._client.store.get((mount_point, path))
        if data is None:
            raise FakeInvalidPathError("no such path")
        return {"data": {"data": dict(data)}}

    def create_or_update_secret(self, path, mount_point, secret):
        if not self._client.token_valid():
            raise FakeForbiddenError("permission denied")
        self._client.store[(mount_point, path)] = dict(secret)
        return {"data": {"version": 1}}

    def delete_metadata_and_all_versions(self, path, mount_point):
        if not self._client.token_valid():
            raise FakeForbiddenError("permission denied")
        self._client.store.pop((mount_point, path), None)
        return True


class _FakeSecrets:
    def __init__(self, client):
        self.kv = type("_Kv", (), {"v2": _FakeKvV2(client)})()


class _FakeApprole:
    def __init__(self, client):
        self._client = client

    def login(self, role_id, secret_id, mount_point="approle"):
        c = self._client
        c.logins.append({"role_id": role_id, "secret_id": secret_id, "mount": mount_point})
        if role_id != c.valid_role_id or secret_id not in c.valid_secret_ids:
            raise FakeVaultError("invalid role or secret id")
        token = f"s.token-{len(c.logins)}"
        c.token = token
        c.live_tokens.add(token)
        return {
            "auth": {
                "client_token": token,
                "lease_duration": c.lease_duration,
                "renewable": True,
            }
        }


class _FakeTokenAuth:
    def __init__(self, client):
        self._client = client

    def lookup_self(self):
        if not self._client.token_valid():
            raise FakeForbiddenError("permission denied")
        return {"data": {"ttl": self._client.static_token_ttl, "renewable": False}}


class _FakeAuth:
    def __init__(self, client):
        self.approle = _FakeApprole(client)
        self.token = _FakeTokenAuth(client)


class _FakeSys:
    def __init__(self, client):
        self._client = client

    def unwrap(self):
        c = self._client
        wrapped = c.wrapped.get(self._client.token)
        if wrapped is None:
            raise FakeVaultError("wrapping token is not valid or already used")
        # Response-wrapping tokens are single-use.
        del c.wrapped[self._client.token]
        return {"data": {"secret_id": wrapped}}


class FakeVaultServer:
    """Server-side state, shared by every client the provider builds.

    Deliberately *not* per-client: re-authentication constructs a new client, and
    a double that reset its state on each one would make an expired SecretID look
    valid again — hiding exactly the fail-closed behaviour under test.
    """

    def __init__(self):
        self.store = {("kv", "agent-suite/qual/hosts/h/regista"): {"hmac_key": _SECRET}}
        self.logins = []
        self.reads = []
        self.live_tokens = set()
        self.valid_role_id = "role-abc"
        self.valid_secret_ids = {"secret-xyz"}
        self.lease_duration = 3600
        self.static_token_ttl = 0
        self.read_raises = None
        self.wrapped = {}
        self.static_tokens = {"dev-token"}

    def expire_all_tokens(self):
        """Every issued lease runs out server-side (or Vault restarted)."""
        self.live_tokens.clear()


class FakeClient:
    """A Vault client double over shared :class:`FakeVaultServer` state."""

    def __init__(self, url, server):
        self.url = url
        self.token = None
        self._server = server
        self.secrets = _FakeSecrets(self)
        self.auth = _FakeAuth(self)
        self.sys = _FakeSys(self)

    # Server state reads through to the shared object, so a test that changes it
    # on the server is seen by every client — including ones built later.
    def __getattr__(self, name):
        return getattr(self._server, name)

    def token_valid(self):
        return self.token in self._server.live_tokens or self.token in self._server.static_tokens

    def is_authenticated(self):
        return self.token_valid()


class _FakeExceptions:
    Forbidden = FakeForbiddenError
    InvalidPath = FakeInvalidPathError
    VaultDown = type("VaultDown", (FakeVaultError,), {})
    Unauthorized = type("Unauthorized", (FakeVaultError,), {})
    InternalServerError = type("InternalServerError", (FakeVaultError,), {})


@pytest.fixture
def server():
    """The shared Vault-side state the provider talks to."""
    return FakeVaultServer()


@pytest.fixture
def clients(server):
    """Every client the provider builds, in order."""
    return []


@pytest.fixture
def make_provider(monkeypatch, server, clients):
    """Build a VaultProvider wired to the double, with an explicit environment.

    `environ` is passed explicitly rather than patched into os.environ so a test
    asserting "no VAULT_TOKEN present" is making a statement about the exact
    mapping the provider reads, not about what the operator's shell happens to
    hold.
    """

    class _FakeHvac:
        exceptions = _FakeExceptions

    def _factory(env, *, on_new=None):
        if on_new is not None:
            on_new(server)

        def client_factory(url):
            client = FakeClient(url, server)
            clients.append(client)
            return client

        provider = VaultProvider(client_factory=client_factory, environ=dict(env))
        monkeypatch.setattr(provider, "_hvac", lambda: _FakeHvac)
        return provider

    return _factory


def _approle_env(tmp_path, **overrides):
    """The production shape: RoleID inline, SecretID in a file, no VAULT_TOKEN."""
    secret_file = tmp_path / "secret-id"
    secret_file.write_text("secret-xyz\n")
    env = {
        "VAULT_ADDR": _ADDR,
        "VAULT_ROLE_ID": "role-abc",
        "VAULT_SECRET_ID_FILE": str(secret_file),
    }
    env.update(overrides)
    return env


# ---------------------------------------------------------------------------
# 1. AppRole-only, with no VAULT_TOKEN anywhere
# ---------------------------------------------------------------------------


class TestAppRoleOnlyResolve:
    def test_resolves_with_no_vault_token_in_the_environment(self, make_provider, tmp_path):
        """The property the qualification could not reach at all.

        Before AppRole existed, this exact environment produced
        `[KEY_LOAD_ERROR] vault: authentication failed`.
        """
        env = _approle_env(tmp_path)
        assert "VAULT_TOKEN" not in env
        provider = make_provider(env)
        assert provider.resolve(_REF) == _SECRET.encode()

    def test_it_actually_logged_in_via_approle(self, make_provider, tmp_path, server):
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        assert len(server.logins) == 1
        assert server.logins[0]["mount"] == "approle"
        assert len(server.live_tokens) == 1

    def test_secret_id_is_read_from_the_file(self, make_provider, tmp_path, server):
        """The SecretID arrives as a file — that is where delivery lands it."""
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        assert server.logins[0]["secret_id"] == "secret-xyz"

    def test_role_id_may_also_come_from_a_file(self, make_provider, tmp_path, server):
        role_file = tmp_path / "role-id"
        role_file.write_text("role-abc\n")
        env = _approle_env(tmp_path)
        del env["VAULT_ROLE_ID"]
        env["VAULT_ROLE_ID_FILE"] = str(role_file)
        provider = make_provider(env)
        provider.resolve(_REF)
        assert server.logins[0]["role_id"] == "role-abc"

    def test_custom_approle_mount_is_honoured(self, make_provider, tmp_path, server):
        env = _approle_env(tmp_path, VAULT_APPROLE_MOUNT_POINT="approle-suite")
        provider = make_provider(env)
        provider.resolve(_REF)
        assert server.logins[0]["mount"] == "approle-suite"

    def test_approle_wins_when_a_token_is_also_present(self, make_provider, tmp_path, server):
        """A leftover VAULT_TOKEN must not silently take precedence.

        The qualification host had both — the shim injected a token while the
        AppRole material was also on disk. The stronger method wins, and the
        report says so, so the host cannot be quietly on the weaker one.
        """
        env = _approle_env(tmp_path, VAULT_TOKEN="dev-token")
        provider = make_provider(env)
        provider.resolve(_REF)
        assert provider.auth_status()["active_method"] == "approle"
        assert len(server.logins) == 1

    def test_response_wrapped_secret_id_is_unwrapped_on_the_host(
        self, make_provider, tmp_path
    ):
        """docs/secrets-vault.md §5: only a wrapping token crosses onto the host."""
        secret_file = tmp_path / "wrap-token"
        secret_file.write_text("wrap-token-1\n")
        env = {
            "VAULT_ADDR": _ADDR,
            "VAULT_ROLE_ID": "role-abc",
            "VAULT_SECRET_ID_FILE": str(secret_file),
            "VAULT_SECRET_ID_RESPONSE_WRAPPED": "1",
        }

        def seed(srv):
            srv.wrapped["wrap-token-1"] = "secret-xyz"

        provider = make_provider(env, on_new=seed)
        assert provider.resolve(_REF) == _SECRET.encode()
        assert provider.auth_status()["secret_id_source"] == (
            "file:VAULT_SECRET_ID_FILE (response-wrapped)"
        )

    def test_unwrapped_secret_id_survives_for_relogin(self, make_provider, tmp_path):
        """A wrapping token is single-use, so the SecretID must be kept.

        Otherwise the first re-login after a lease expiry would have nothing
        left to authenticate with — the wedge this work item is about, moved one
        step later.
        """
        secret_file = tmp_path / "wrap-token"
        secret_file.write_text("wrap-token-1\n")
        env = {
            "VAULT_ADDR": _ADDR,
            "VAULT_ROLE_ID": "role-abc",
            "VAULT_SECRET_ID_FILE": str(secret_file),
            "VAULT_SECRET_ID_RESPONSE_WRAPPED": "1",
        }

        def seed(srv):
            srv.wrapped["wrap-token-1"] = "secret-xyz"
            srv.lease_duration = 1

        provider = make_provider(env, on_new=seed)
        assert provider.resolve(_REF) == _SECRET.encode()
        # The wrapping token is now spent; a second unwrap would fail. Force the
        # lease to look expired and confirm the re-login still succeeds.
        provider._deadline = 0.0
        assert provider.resolve(_REF) == _SECRET.encode()
        assert provider.auth_status()["logins"] == 2


# ---------------------------------------------------------------------------
# 2. Reporting which method was used
# ---------------------------------------------------------------------------


class TestAuthMethodReporting:
    def test_reports_approle_and_where_each_credential_came_from(
        self, make_provider, tmp_path
    ):
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        status = provider.auth_status()
        assert status["configured_method"] == "approle"
        assert status["active_method"] == "approle"
        assert status["role_id_source"] == "env:VAULT_ROLE_ID"
        assert status["secret_id_source"] == "file:VAULT_SECRET_ID_FILE"
        assert status["approle_mount"] == "approle"
        assert status["authenticated"] is True

    def test_reports_the_token_method_distinctly(self, make_provider):
        provider = make_provider({"VAULT_ADDR": _ADDR, "VAULT_TOKEN": "dev-token"})
        provider.resolve(_REF)
        status = provider.auth_status()
        assert status["configured_method"] == "token"
        assert status["active_method"] == "token"
        assert status["token_source"] == "env:VAULT_TOKEN"
        # The dev method cannot mint itself a new token, and says so.
        assert status["reauthenticatable"] is False

    def test_status_never_contains_credential_values(self, make_provider, tmp_path):
        """The whole point of a reportable status is that it is safe to print."""
        env = _approle_env(tmp_path, VAULT_TOKEN="dev-token")
        provider = make_provider(env)
        provider.resolve(_REF)
        blob = repr(provider.auth_status())
        for secret in ("role-abc", "secret-xyz", "dev-token"):
            assert secret not in blob
        # It names the *source*, which is what an operator needs.
        assert "VAULT_SECRET_ID_FILE" in blob

    def test_configured_method_is_known_before_any_network_call(
        self, make_provider, tmp_path, clients
    ):
        """Doctor must be able to report the posture without authenticating."""
        provider = make_provider(_approle_env(tmp_path))
        status = provider.auth_status()
        assert status["configured_method"] == "approle"
        assert status["active_method"] is None
        assert status["authenticated"] is False
        assert clients == []

    def test_probe_distinguishes_declared_from_working(self, make_provider, tmp_path):
        env = _approle_env(tmp_path)
        provider = make_provider(env)
        assert provider.auth_status(probe=True)["probe_ok"] is True

        bad = _approle_env(tmp_path, VAULT_ROLE_ID="wrong-role")
        provider2 = make_provider(bad)
        status = provider2.auth_status(probe=True)
        assert status["configured_method"] == "approle"
        assert status["probe_ok"] is False
        assert "AppRole login was refused" in status["probe_error"]

    def test_lease_is_reported(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        status = provider.auth_status()
        assert status["lease_duration_seconds"] == 3600
        assert 0 < status["expires_in_seconds"] <= 3600
        assert status["renewable"] is True
        assert status["reauthenticatable"] is True

    def test_module_level_status_reports_a_missing_provider_honestly(self, monkeypatch):
        """Each component resolves refs in its own env; say so when hvac is absent."""
        from regista import _secrets

        monkeypatch.delitem(_secrets._PROVIDERS, "vault", raising=False)
        status = _secrets.vault_auth_status()
        assert status["provider_available"] is False
        assert status["active_method"] is None
        assert "hvac" in status["configured_error"]

    def test_public_facade_exports_it(self):
        import regista.secrets as public

        assert callable(public.vault_auth_status)
        assert "vault_auth_status" in public.__all__


# ---------------------------------------------------------------------------
# 3. Fail closed when AppRole material is configured but unusable
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_role_id_without_secret_id_refuses(self, make_provider):
        provider = make_provider({"VAULT_ADDR": _ADDR, "VAULT_ROLE_ID": "role-abc"})
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "VAULT_SECRET_ID_FILE" in exc.value.message

    def test_secret_id_without_role_id_refuses(self, make_provider, tmp_path):
        secret_file = tmp_path / "secret-id"
        secret_file.write_text("secret-xyz\n")
        provider = make_provider(
            {"VAULT_ADDR": _ADDR, "VAULT_SECRET_ID_FILE": str(secret_file)}
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "VAULT_ROLE_ID" in exc.value.message

    def test_partial_approle_never_falls_back_to_the_dev_token(
        self, make_provider, clients
    ):
        """The property that keeps a posture from silently degrading.

        A host with half its AppRole material and a stray VAULT_TOKEN must fail,
        not quietly become a dev host that works.
        """
        provider = make_provider(
            {
                "VAULT_ADDR": _ADDR,
                "VAULT_ROLE_ID": "role-abc",
                "VAULT_TOKEN": "dev-token",
            }
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "downgrade" in exc.value.message
        assert clients == [], "it authenticated anyway"

    def test_missing_secret_id_file_names_the_path(self, make_provider, tmp_path):
        missing = tmp_path / "never-delivered"
        provider = make_provider(
            {
                "VAULT_ADDR": _ADDR,
                "VAULT_ROLE_ID": "role-abc",
                "VAULT_SECRET_ID_FILE": str(missing),
            }
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert str(missing) in exc.value.message
        assert "does not exist" in exc.value.message

    def test_empty_secret_id_file_is_a_failed_delivery(self, make_provider, tmp_path):
        empty = tmp_path / "secret-id"
        empty.write_text("   \n")
        provider = make_provider(
            {
                "VAULT_ADDR": _ADDR,
                "VAULT_ROLE_ID": "role-abc",
                "VAULT_SECRET_ID_FILE": str(empty),
            }
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "is empty" in exc.value.message

    def test_rejected_login_says_what_to_do(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path, VAULT_ROLE_ID="wrong-role"))
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "AppRole login was refused" in exc.value.message
        assert "re-deliver" in exc.value.message
        assert exc.value.detail is not None
        assert "remediation" in exc.value.detail

    def test_no_credentials_at_all_names_both_options(self, make_provider):
        provider = make_provider({"VAULT_ADDR": _ADDR})
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "VAULT_ROLE_ID" in exc.value.message
        assert "VAULT_TOKEN" in exc.value.message

    def test_response_wrapped_without_a_file_refuses(self, make_provider):
        provider = make_provider(
            {
                "VAULT_ADDR": _ADDR,
                "VAULT_ROLE_ID": "role-abc",
                "VAULT_SECRET_ID": "secret-xyz",
                "VAULT_SECRET_ID_RESPONSE_WRAPPED": "1",
            }
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "VAULT_SECRET_ID_FILE" in exc.value.message

    def test_spent_wrapping_token_is_actionable(self, make_provider, tmp_path):
        secret_file = tmp_path / "wrap-token"
        secret_file.write_text("already-used\n")
        provider = make_provider(
            {
                "VAULT_ADDR": _ADDR,
                "VAULT_ROLE_ID": "role-abc",
                "VAULT_SECRET_ID_FILE": str(secret_file),
                "VAULT_SECRET_ID_RESPONSE_WRAPPED": "1",
            }
        )
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "single-use" in exc.value.message

    def test_unreachable_vault_does_not_blame_the_credentials(
        self, monkeypatch, tmp_path, clients
    ):
        """A network failure must not send an operator to rotate a SecretID.

        Found while validating on the qual-linux container, which has no outbound
        network: a `ConnectTimeout` was reported as "the SecretID expired or ran
        out of uses — issue a new one", which is wasted and misleading work when
        nothing was ever able to ask Vault.
        """
        from regista._secrets import VaultProvider

        # The detection is by class *name* (hvac's HTTP stack is not a regista
        # dependency), so the double must carry requests' name exactly.
        class _ConnectTimeoutError(Exception):
            pass

        _ConnectTimeoutError.__name__ = "ConnectTimeout"

        class _Unreachable:
            def __init__(self, url):
                self.token = None
                self.auth = self
                self.approle = self

            def login(self, **kwargs):
                raise _ConnectTimeoutError("timed out")

        env = _approle_env(tmp_path)
        provider = VaultProvider(client_factory=_Unreachable, environ=env)
        fake_hvac = type("H", (), {"exceptions": _FakeExceptions})
        monkeypatch.setattr(provider, "_hvac", lambda: fake_hvac)
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "could not reach" in exc.value.message
        assert "do not need rotating" in exc.value.message
        assert exc.value.detail["credentials_rejected"] is False

    def test_a_real_refusal_still_points_at_the_secret_id(self, make_provider, tmp_path):
        """The other side of that split must keep its original remedy."""
        provider = make_provider(_approle_env(tmp_path, VAULT_ROLE_ID="wrong-role"))
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "refused" in exc.value.message
        assert exc.value.detail["credentials_rejected"] is True

    def test_no_vault_addr_still_reported_first(self, make_provider):
        provider = make_provider({"VAULT_ROLE_ID": "role-abc"})
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "VAULT_ADDR" in exc.value.message

    def test_failures_never_echo_credential_values(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path, VAULT_ROLE_ID="wrong-role"))
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        blob = exc.value.message + repr(exc.value.detail)
        assert "wrong-role" not in blob
        assert "secret-xyz" not in blob


# ---------------------------------------------------------------------------
# 4. Token lifecycle — a long-running process must not wedge
# ---------------------------------------------------------------------------


class TestTokenLifecycle:
    def test_reauthenticates_before_the_lease_expires(self, make_provider, tmp_path):
        """The bug behind dossier 503-ing an hour after start.

        The client was cached for the process lifetime while the token behind it
        had a one-hour lease.
        """
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        assert provider.auth_status()["logins"] == 1
        # Wind the deadline into the re-auth margin, as wall-clock time would.
        provider._deadline = 0.0
        provider.resolve(_REF)
        assert provider.auth_status()["logins"] == 2

    def test_recovers_when_the_token_dies_without_warning(
        self, make_provider, tmp_path, server
    ):
        """A revoked token, or a Vault restart, is a 403 with no advance notice."""
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        server.expire_all_tokens()
        assert provider.resolve(_REF) == _SECRET.encode()
        assert provider.auth_status()["logins"] == 2

    def test_a_policy_denial_is_not_retried_as_an_expiry(
        self, make_provider, tmp_path, server
    ):
        """The 403 disambiguation, in the direction that matters for correctness.

        Vault answers both "your policy forbids this" and "your token is dead"
        with 403. Telling them apart by asking whether the token still validates
        means a genuine denial is reported at once instead of driving a login
        loop — and it is reported as a *policy* problem, which is the actionable
        reading.
        """
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        logins_before = provider.auth_status()["logins"]
        # Token stays alive; the read itself is refused.
        server.read_raises = FakeForbiddenError("permission denied")
        with pytest.raises(RegistaError) as exc:
            provider.resolve("kv/agent-suite/qual/hosts/other-host/regista/hmac_key")
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED
        assert "permission denied" in exc.value.message
        assert "its policy, not" in exc.value.message
        assert provider.auth_status()["logins"] == logins_before, (
            "a policy denial triggered a re-login — that is a login loop"
        )

    def test_a_dead_static_token_is_reported_not_retried(self, make_provider, server):
        """There is nothing to log in with, so say so rather than looping."""
        provider = make_provider({"VAULT_ADDR": _ADDR, "VAULT_TOKEN": "dev-token"})
        provider.resolve(_REF)
        server.static_tokens.clear()
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED
        assert provider.auth_status()["logins"] == 1

    def test_reauth_failure_fails_closed_rather_than_looping(
        self, make_provider, tmp_path, server
    ):
        """When the SecretID itself has expired, the process must fail clearly."""
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        server.expire_all_tokens()
        server.valid_secret_ids.clear()
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "AppRole login was refused" in exc.value.message

    def test_a_lease_less_token_is_not_re_authenticated_pointlessly(self, make_provider):
        """A root/never-expiring token has no deadline, so nothing to pre-empt."""
        provider = make_provider({"VAULT_ADDR": _ADDR, "VAULT_TOKEN": "dev-token"})
        provider.resolve(_REF)
        assert provider.auth_status()["expires_in_seconds"] is None
        provider.resolve(_REF)
        assert provider.auth_status()["logins"] == 1

    def test_reauth_margin_scales_down_for_short_leases(self, make_provider, tmp_path):
        """A 10s lease must not be treated as expired the instant it is issued."""

        def short_lease(srv):
            srv.lease_duration = 10

        provider = make_provider(_approle_env(tmp_path), on_new=short_lease)
        provider.resolve(_REF)
        assert provider._margin() == 5.0
        # Still inside the usable window, so no second login.
        provider.resolve(_REF)
        assert provider.auth_status()["logins"] == 1


# ---------------------------------------------------------------------------
# Error mapping and the estate's ref-shape traps
# ---------------------------------------------------------------------------


class TestErrorMapping:
    def test_absent_path_is_a_clear_error_not_a_traceback(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path))
        with pytest.raises(RegistaError) as exc:
            provider.resolve("kv/agent-suite/qual/nowhere/field")
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "no secret at" in exc.value.message
        # And it restates the trap that bit this estate.
        assert "field LAST" in exc.value.message

    def test_a_403_carries_structured_remediation(self, make_provider, tmp_path, server):
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        server.read_raises = FakeForbiddenError("permission denied")
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        detail = exc.value.detail
        assert detail["auth_method"] == "approle"
        assert detail["token_valid"] is True
        assert any("kv/data/" in c for c in detail["required_capabilities"])

    def test_backend_message_text_never_reaches_the_error(self, make_provider, tmp_path, server):
        """Contract §3 redaction: only the exception type is reported."""
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        server.read_raises = FakeVaultError("secret was hunter2 at kv/homelab/x")
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "hunter2" not in exc.value.message
        assert "FakeVaultError" in exc.value.message

    @pytest.mark.parametrize(
        "ref",
        [
            "kv/too/short",
            "kv/agent-suite/regista#signing_key",
            "secret/agent-suite/regista#signing_key",
        ],
    )
    def test_three_segment_and_hash_field_refs_are_rejected(
        self, make_provider, tmp_path, ref
    ):
        """The shape the old runbooks printed can never resolve — reject it early.

        `vault:kv/a/b#field` parses to a *different, neighbouring* secret against
        a real mount, which a permissive policy will happily read. The
        four-segment minimum refuses it before any network call.
        """
        provider = make_provider(_approle_env(tmp_path))
        with pytest.raises(RegistaError) as exc:
            provider.resolve(ref)
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "mount/path/key" in exc.value.message

    def test_delete_of_an_absent_secret_is_idempotent(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path))
        assert (
            provider.delete("kv/agent-suite/qual/nowhere/field")
            is DeleteOutcome.ALREADY_ABSENT
        )

    def test_delete_does_not_report_a_403_as_already_absent(
        self, make_provider, tmp_path, server
    ):
        """The old code did `except Exception: return ALREADY_ABSENT`.

        That told an operator running an offboarding that the key was gone when
        the read had been refused and nothing was even looked at.
        """
        provider = make_provider(_approle_env(tmp_path))
        provider.resolve(_REF)
        server.read_raises = FakeForbiddenError("permission denied")
        with pytest.raises(RegistaError) as exc:
            provider.delete(_REF)
        assert exc.value.code == ErrorCode.SECRET_RESOLVE_FAILED

    def test_delete_removes_only_the_named_field(self, make_provider, tmp_path, server):
        def seed(srv):
            srv.store[("kv", "agent-suite/qual/hosts/h/regista")] = {
                "hmac_key": _SECRET,
                "other_key": "keep-me",
            }

        provider = make_provider(_approle_env(tmp_path), on_new=seed)
        assert provider.delete(_REF) is DeleteOutcome.DELETED
        remaining = server.store[("kv", "agent-suite/qual/hosts/h/regista")]
        assert remaining == {"other_key": "keep-me"}

    def test_store_round_trips(self, make_provider, tmp_path):
        provider = make_provider(_approle_env(tmp_path))
        ref = "kv/agent-suite/qual/wi228/probe/value"
        assert provider.store(ref, b"payload") == f"vault:{ref}"
        # store base64-encodes, so the round trip is through the same encoding.
        import base64

        assert base64.b64decode(provider.resolve(ref)) == b"payload"


# ---------------------------------------------------------------------------
# Shape classification, independent of any client
# ---------------------------------------------------------------------------


class TestNoAmbientCredential:
    """The client must never be born holding a credential nobody named.

    `hvac.Client(url=...)` defaults to `token=None`, which makes hvac call
    `get_token_from_env()` — and that picks up `$VAULT_TOKEN` **and**
    `~/.vault-token`. On a host that is supposed to be AppRole-only, the client
    would start out holding an ambient credential. Nothing reads before the
    explicit auth path assigns a token, so this is defence in depth rather than a
    live bug, but "no ambient token" should be structural and testable rather
    than a property of statement ordering. acb hit the same trap
    (agent-capability-broker PR #20).
    """

    def test_client_is_constructed_with_an_empty_token(self, monkeypatch):
        import hvac

        from regista._secrets import VaultProvider

        seen = {}

        class _Recording:
            def __init__(self, url, token=None, **kwargs):
                seen["token"] = token

        monkeypatch.setattr(hvac, "Client", _Recording)
        provider = VaultProvider(environ={"VAULT_ADDR": _ADDR})
        provider._new_client(_ADDR)
        assert seen["token"] == "", (
            "token=None lets hvac read $VAULT_TOKEN and ~/.vault-token"
        )

    def test_hvac_really_does_pick_up_ambient_credentials(self, monkeypatch, tmp_path):
        """Pin the upstream behaviour this guards against, so it is not folklore.

        If a future hvac stops doing this the guard becomes redundant rather than
        wrong, and this test says so out loud.
        """
        import hvac

        monkeypatch.setenv("VAULT_TOKEN", "ambient-from-env")
        assert hvac.Client(url=_ADDR).token == "ambient-from-env"
        assert hvac.Client(url=_ADDR, token="").token == ""
        monkeypatch.delenv("VAULT_TOKEN")
        home = tmp_path / "home"
        home.mkdir()
        (home / ".vault-token").write_text("ambient-from-dotfile\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        assert hvac.Client(url=_ADDR, token="").token == ""

    def test_a_dotfile_token_does_not_make_a_bare_host_resolve(self, tmp_path, monkeypatch):
        """No VAULT_* configured at all must stay fail-closed.

        Otherwise a stray ~/.vault-token would make an unconfigured host appear
        to work, which is the silent-posture problem in its purest form.
        """
        from regista._secrets import VaultProvider

        home = tmp_path / "home"
        home.mkdir()
        (home / ".vault-token").write_text("ambient-from-dotfile\n")
        monkeypatch.setattr("pathlib.Path.home", lambda: home)
        provider = VaultProvider(environ={"VAULT_ADDR": _ADDR})
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "no credentials configured" in exc.value.message


class TestAcbPlaneFileInterop:
    """One credential-file format across components.

    acb provisions AppRoles and writes a mode-0600 env-style "plane file" with
    `VAULT_ADDR`, `VAULT_ROLE_ID` and `VAULT_SECRET_ID`
    (agent-capability-broker PR #20). Those are the same variable names this
    resolver reads, so `VAULT_ENV_FILE` pointed at that file makes one file serve
    both instead of each component inventing its own.
    """

    def _plane_file(self, tmp_path, body):
        p = tmp_path / "vault.env"
        p.write_text(body)
        p.chmod(0o600)
        return p

    def test_resolves_from_an_acb_written_plane_file(self, make_provider, tmp_path):
        plane = self._plane_file(
            tmp_path,
            f"VAULT_ADDR={_ADDR}\nVAULT_ROLE_ID=role-abc\nVAULT_SECRET_ID=secret-xyz\n",
        )
        provider = make_provider({"VAULT_ENV_FILE": str(plane)})
        assert provider.resolve(_REF) == _SECRET.encode()
        status = provider.auth_status()
        assert status["active_method"] == "approle"
        # Provenance must say "plane", not "env" — attributing a plane-file value
        # to the process environment sends an operator to the wrong place.
        assert status["role_id_source"] == "plane:VAULT_ROLE_ID"
        assert status["secret_id_source"] == "plane:VAULT_SECRET_ID"

    def test_export_prefix_quotes_and_comments_are_tolerated(self, make_provider, tmp_path):
        plane = self._plane_file(
            tmp_path,
            "# provisioned by acb\n"
            f'export VAULT_ADDR="{_ADDR}"\n'
            "export VAULT_ROLE_ID='role-abc'   # the harness role\n"
            "VAULT_SECRET_ID=secret-xyz\n",
        )
        provider = make_provider({"VAULT_ENV_FILE": str(plane)})
        assert provider.resolve(_REF) == _SECRET.encode()

    def test_non_vault_keys_are_ignored(self, make_provider, tmp_path):
        """So the file may also be a shared suite.env without side effects."""
        plane = self._plane_file(
            tmp_path,
            f"REGISTA_DSN=postgresql://nope\nVAULT_ADDR={_ADDR}\n"
            "VAULT_ROLE_ID=role-abc\nVAULT_SECRET_ID=secret-xyz\n",
        )
        provider = make_provider({"VAULT_ENV_FILE": str(plane)})
        assert provider.resolve(_REF) == _SECRET.encode()

    def test_process_environment_wins_over_the_plane_file(self, make_provider, tmp_path):
        """Matches acb's own merge, so an explicit override still overrides."""
        plane = self._plane_file(
            tmp_path,
            f"VAULT_ADDR={_ADDR}\nVAULT_ROLE_ID=stale-role\nVAULT_SECRET_ID=secret-xyz\n",
        )
        provider = make_provider(
            {"VAULT_ENV_FILE": str(plane), "VAULT_ROLE_ID": "role-abc"}
        )
        assert provider.resolve(_REF) == _SECRET.encode()
        status = provider.auth_status()
        assert status["role_id_source"] == "env:VAULT_ROLE_ID"
        assert status["secret_id_source"] == "plane:VAULT_SECRET_ID"

    def test_a_named_but_missing_plane_file_fails_closed(self, make_provider, tmp_path):
        """An operator who named a plane file meant to use it."""
        provider = make_provider({"VAULT_ENV_FILE": str(tmp_path / "absent.env")})
        with pytest.raises(RegistaError) as exc:
            provider.resolve(_REF)
        assert "does not exist" in exc.value.message
        assert "VAULT_ENV_FILE" in exc.value.message

    def test_auth_status_reports_a_broken_plane_file_instead_of_raising(
        self, make_provider, tmp_path
    ):
        provider = make_provider({"VAULT_ENV_FILE": str(tmp_path / "absent.env")})
        status = provider.auth_status()
        assert status["configured_method"] is None
        assert "VAULT_ENV_FILE" in status["configured_error"]

    def test_response_wrapped_delivery_still_available_alongside(
        self, make_provider, tmp_path
    ):
        """The plane file cannot express a one-shot wrapping token.

        acb writes a plain SecretID; agent-suite's §5 delivery lands a single-use
        wrapping token in a file of its own. Both shapes must keep working, which
        is why `VAULT_SECRET_ID_FILE` is not replaced by the plane file.
        """
        wrap = tmp_path / "wrap-token"
        wrap.write_text("wrap-token-1\n")
        plane = self._plane_file(tmp_path, f"VAULT_ADDR={_ADDR}\nVAULT_ROLE_ID=role-abc\n")

        def seed(srv):
            srv.wrapped["wrap-token-1"] = "secret-xyz"

        provider = make_provider(
            {
                "VAULT_ENV_FILE": str(plane),
                "VAULT_SECRET_ID_FILE": str(wrap),
                "VAULT_SECRET_ID_RESPONSE_WRAPPED": "1",
            },
            on_new=seed,
        )
        assert provider.resolve(_REF) == _SECRET.encode()

    def test_acb_and_regista_agree_that_approle_beats_a_token(
        self, make_provider, tmp_path
    ):
        """Precedence must match acb's `_authenticate` order (AppRole before token).

        Divergence here would mean the same plane file authenticates as different
        identities depending on which component read it.
        """
        plane = self._plane_file(
            tmp_path,
            f"VAULT_ADDR={_ADDR}\nVAULT_ROLE_ID=role-abc\n"
            "VAULT_SECRET_ID=secret-xyz\nVAULT_TOKEN=dev-token\n",
        )
        provider = make_provider({"VAULT_ENV_FILE": str(plane)})
        provider.resolve(_REF)
        assert provider.auth_status()["active_method"] == "approle"


class TestAuthShape:
    def test_token_only(self):
        shape = _vault_auth_shape({"VAULT_TOKEN": "x"})
        assert shape.method == "token"
        assert shape.error is None

    def test_nothing_configured(self):
        shape = _vault_auth_shape({})
        assert shape.method is None
        assert shape.error is not None

    def test_file_is_preferred_over_the_inline_variable(self, tmp_path):
        """The file is the documented delivery channel and stays out of /proc."""
        f = tmp_path / "sid"
        f.write_text("from-file")
        shape = _vault_auth_shape(
            {
                "VAULT_ROLE_ID": "r",
                "VAULT_SECRET_ID": "from-env",
                "VAULT_SECRET_ID_FILE": str(f),
            }
        )
        assert shape.secret_id_source == "file:VAULT_SECRET_ID_FILE"

    def test_inline_secret_id_is_still_accepted(self):
        shape = _vault_auth_shape({"VAULT_ROLE_ID": "r", "VAULT_SECRET_ID": "s"})
        assert shape.method == "approle"
        assert shape.secret_id_source == "env:VAULT_SECRET_ID"

    def test_to_dict_carries_no_values(self, tmp_path):
        f = tmp_path / "sid"
        f.write_text("secret-xyz")
        shape = _vault_auth_shape(
            {"VAULT_ROLE_ID": "role-abc", "VAULT_SECRET_ID_FILE": str(f)}
        )
        blob = repr(shape.to_dict())
        assert "role-abc" not in blob
        assert "secret-xyz" not in blob

    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
    def test_response_wrapped_flag_parsing(self, tmp_path, raw):
        f = tmp_path / "sid"
        f.write_text("t")
        shape = _vault_auth_shape(
            {
                "VAULT_ROLE_ID": "r",
                "VAULT_SECRET_ID_FILE": str(f),
                "VAULT_SECRET_ID_RESPONSE_WRAPPED": raw,
            }
        )
        assert shape.response_wrapped is True

    @pytest.mark.parametrize("raw", ["0", "false", "no", "", "maybe"])
    def test_response_wrapped_flag_defaults_off(self, tmp_path, raw):
        f = tmp_path / "sid"
        f.write_text("t")
        shape = _vault_auth_shape(
            {
                "VAULT_ROLE_ID": "r",
                "VAULT_SECRET_ID_FILE": str(f),
                "VAULT_SECRET_ID_RESPONSE_WRAPPED": raw,
            }
        )
        assert shape.response_wrapped is False


# ---------------------------------------------------------------------------
# The doctor row, and the CLI surface
# ---------------------------------------------------------------------------


class TestDoctorAndCli:
    def _run_cli(self, argv):
        from regista._cli import main

        try:
            main(argv)
        except SystemExit as e:
            return e.code if e.code is not None else 0
        return 0

    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        for var in (
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "VAULT_ROLE_ID",
            "VAULT_ROLE_ID_FILE",
            "VAULT_SECRET_ID",
            "VAULT_SECRET_ID_FILE",
            "VAULT_SECRET_ID_RESPONSE_WRAPPED",
            "REGISTA_SECRET_BACKEND",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_doctor_grades_approle_ok(self, monkeypatch, tmp_path):
        from regista._doctor import _check_vault_auth

        f = tmp_path / "sid"
        f.write_text("s")
        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_ROLE_ID", "r")
        monkeypatch.setenv("VAULT_SECRET_ID_FILE", str(f))
        check = _check_vault_auth("vault")
        assert check.name == "custody:vault_auth"
        assert check.status == "ok"
        assert "AppRole" in check.detail

    def test_doctor_warns_on_the_dev_token(self, monkeypatch):
        from regista._doctor import _check_vault_auth

        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_TOKEN", "dev-token")
        check = _check_vault_auth("vault")
        assert check.status == "warn"
        assert "dev-only" in check.detail
        assert "VAULT_SECRET_ID_FILE" in check.detail

    def test_doctor_fails_on_unusable_approle_material(self, monkeypatch):
        from regista._doctor import _check_vault_auth

        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_ROLE_ID", "r")
        check = _check_vault_auth("vault")
        assert check.status == "fail"

    def test_doctor_skips_when_no_vault_is_configured(self, monkeypatch):
        from regista._doctor import _check_vault_auth

        check = _check_vault_auth(None)
        assert check.status == "skip"

    def test_doctor_row_is_in_the_report(self, monkeypatch):
        """Wire-up check: the row must actually reach run_doctor's output."""
        from regista._doctor import run_doctor

        report = run_doctor(None)
        assert "custody:vault_auth" in {c.name for c in report.checks}

    def test_cli_auth_status_json(self, monkeypatch, tmp_path, capsys):
        import json

        f = tmp_path / "sid"
        f.write_text("s")
        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_ROLE_ID", "r")
        monkeypatch.setenv("VAULT_SECRET_ID_FILE", str(f))
        assert self._run_cli(["--json", "secrets", "--auth-status"]) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["configured_method"] == "approle"
        assert status["secret_id_source"] == "file:VAULT_SECRET_ID_FILE"

    def test_cli_auth_status_text(self, monkeypatch, capsys):
        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_TOKEN", "dev-token")
        assert self._run_cli(["secrets", "--auth-status"]) == 0
        out = capsys.readouterr().out
        assert "configured auth method:   token" in out
        assert "dev-token" not in out

    def test_cli_auth_status_reports_without_probing(self, monkeypatch, capsys):
        """A pure report exits 0 even when the configuration is unusable."""
        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_ROLE_ID", "r")
        assert self._run_cli(["secrets", "--auth-status"]) == 0
        assert "problem:" in capsys.readouterr().out

    def test_cli_probe_failure_exits_nonzero(self, monkeypatch, capsys):
        """Contract §2: a probe that could not authenticate is a failure."""
        monkeypatch.setenv("VAULT_ADDR", _ADDR)
        monkeypatch.setenv("VAULT_ROLE_ID", "r")
        code = self._run_cli(["--json", "secrets", "--auth-status", "--probe"])
        out = capsys.readouterr()
        import json

        assert json.loads(out.out)["probe_ok"] is False
        assert "error:" in out.err
        assert code == 1
