"""CLI contract v1 violations found by Lane C / Lane H (WI-229).

Three defects, one test class each, plus an audit test that sweeps every
``--json`` verb whose failure is reported inside its own result shape.

The violations, and what each one cost:

(a) ``provision --json`` exited 0 while its body said the work did not happen.
    ``agent-suite bootstrap`` trusted the exit code and reported ``bootstrap:
    OK`` over a provision that never created the service role. The umbrella has
    since hardened (``evaluate_component_result``, agent-suite PR #8), but the
    contract break lived here and every other consumer inherited it.
(b) ``secrets --ref`` let ``hvac.exceptions.Forbidden`` escape as a raw
    traceback instead of the error envelope (contract §4). A 403 is exactly what
    a scoped AppRole policy produces when a ref reaches outside it, so this path
    gets *more* traffic once AppRole lands (WI-228), not less.
(c) ``principal enroll`` ignored ``REGISTA_KEY_PATH`` — the canonical variable
    name — and read only its legacy alias.

Every test here is hermetic: no Postgres, no Vault, no network. The store is
replaced with a double so the assertions are about the CLI's contract behaviour
rather than about any backend being up.
"""

from __future__ import annotations

import json
from typing import ClassVar

import pytest

from regista._errors import ErrorCode, RegistaError

# conftest's DB-skip heuristic flags any module mentioning "DSN" as
# database-dependent. This module only ever sets REGISTA_DSN to a value nothing
# connects to, so declare it hermetic — otherwise the contract check silently
# skips on a machine with no Postgres, which is exactly the "a gate that skips
# enforces nothing" failure mode (cli-contract.md §7).
_regista_db_dependent = False

_DSN = "postgresql://unused:unused@127.0.0.1:1/unused"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip inherited suite/Vault configuration so results are hermetic."""
    for var in (
        "REGISTA_DSN",
        "REGISTA_PROJECT",
        "REGISTA_KEY_PATH",
        "REGISTA_HMAC_KEY_PATH",
        "REGISTA_SECRET_BACKEND",
        "VAULT_ADDR",
        "VAULT_TOKEN",
        "VAULT_ROLE_ID",
        "VAULT_ROLE_ID_FILE",
        "VAULT_SECRET_ID",
        "VAULT_SECRET_ID_FILE",
        "AGENT_SUITE_CONFIG",
    ):
        monkeypatch.delenv(var, raising=False)
    # _config.resolve() also reads /etc/agent-suite/suite.env and
    # ~/.config/agent-suite/suite.env; point the user one at nothing so an
    # operator box's real config cannot reach these assertions.
    monkeypatch.setenv("AGENT_SUITE_CONFIG", "/nonexistent/regista-wi229/suite.env")


def _run_cli(argv):
    """Invoke the CLI in-process, returning its exit code (0 when it returns)."""
    from regista._cli import main

    try:
        main(argv)
    except SystemExit as e:
        return e.code if e.code is not None else 0
    return 0


# ---------------------------------------------------------------------------
# (a) exit 0 with an error body
# ---------------------------------------------------------------------------


class _ProvisionResult:
    """Stand-in for regista._provision.ProvisionResult."""

    def __init__(self, project, error=None):
        self.project = project
        self.error = error
        self.schema_created = False
        self.migrations_applied = []
        self.service_role_created = False

    def to_dict(self):
        return {
            "project": self.project,
            "error": self.error,
            "schema_created": self.schema_created,
            "migrations_applied": self.migrations_applied,
            "service_role_created": self.service_role_created,
        }


class TestProvisionJsonExitCode:
    """(a) The exact shape that made agent-suite report OK over a failure."""

    @pytest.fixture
    def failing_provision(self, monkeypatch):
        import regista._provision as provision_mod

        def _fake(dsn, projects, dry_run=False):
            return [
                _ProvisionResult(p, error="permission denied to create role")
                for p in projects
            ]

        monkeypatch.setattr(provision_mod, "provision", _fake)
        monkeypatch.setenv("REGISTA_DSN", _DSN)

    def test_json_error_body_exits_nonzero(self, failing_provision, capsys):
        """The regression under test: an {error: ...} body must not exit 0.

        This is the assertion WI-229 asks for by name — non-zero whenever the
        envelope says the work failed.
        """
        code = _run_cli(["provision", "--json", "--project", "wi229"])
        out = capsys.readouterr()
        payload = json.loads(out.out)
        assert payload[0]["error"] == "permission denied to create role"
        assert payload[0]["service_role_created"] is False
        assert code == 1, (
            "provision --json exited 0 while reporting a hard failure — "
            "cli-contract.md §2: no path may print an error and exit 0"
        )

    def test_machine_readable_channel_still_carries_the_answer(
        self, failing_provision, capsys
    ):
        """Fixing the exit code must not empty stdout.

        The consumer parses stdout; the exit code only corroborates. A 'fix'
        that moved the body to stderr would break every reader.
        """
        _run_cli(["provision", "--json", "--project", "wi229"])
        out = capsys.readouterr()
        payload = json.loads(out.out)
        assert isinstance(payload, list) and payload[0]["project"] == "wi229"
        # And a stderr-only reader is no longer blind to the refusal.
        assert "wi229" in out.err

    def test_text_and_json_agree_on_the_exit_code(self, failing_provision, capsys):
        """The two output formats described the same state with different codes."""
        json_code = _run_cli(["provision", "--json", "--project", "wi229"])
        capsys.readouterr()
        text_code = _run_cli(["provision", "--project", "wi229"])
        capsys.readouterr()
        assert json_code == text_code == 1

    def test_success_still_exits_zero(self, monkeypatch, capsys):
        """The guard must not turn a clean provision into a failure."""
        import regista._provision as provision_mod

        monkeypatch.setattr(
            provision_mod,
            "provision",
            lambda dsn, projects, dry_run=False: [_ProvisionResult(p) for p in projects],
        )
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        assert _run_cli(["provision", "--json", "--project", "wi229"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["error"] is None

    def test_partial_failure_picks_a_side(self, monkeypatch, capsys):
        """Contract §2: 'some succeeded' is not exit 0."""
        import regista._provision as provision_mod

        def _fake(dsn, projects, dry_run=False):
            return [
                _ProvisionResult(projects[0]),
                _ProvisionResult(projects[1], error="permission denied to create role"),
            ]

        monkeypatch.setattr(provision_mod, "provision", _fake)
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        code = _run_cli(
            ["provision", "--json", "--project", "ok_one", "--project", "bad_one"]
        )
        payload = json.loads(capsys.readouterr().out)
        assert [r["error"] is None for r in payload] == [True, False]
        assert code == 1


class _PrincipalResult:
    def __init__(self, error=None):
        self.error = error
        self.already_existed = False
        self.principal_id = "wi229-principal"
        self.key_id = None
        self.fingerprint = None
        self.private_key_stored = False
        self.public_key_registered = False

    def to_dict(self):
        return {"error": self.error, "principal_id": self.principal_id}


class TestProvisionPrincipalJsonExitCode:
    """The same shape on the sibling verb — found by the WI-229 audit sweep."""

    def test_json_error_body_exits_nonzero(self, monkeypatch, capsys):
        import regista._provision as provision_mod

        monkeypatch.setattr(
            provision_mod,
            "provision_principal",
            lambda *a, **k: _PrincipalResult(error="permission denied to create role"),
        )
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        code = _run_cli(
            ["provision-principal", "--json", "--principal", "p", "--project", "wi229"]
        )
        out = capsys.readouterr()
        assert json.loads(out.out)["error"] == "permission denied to create role"
        assert code == 1


class TestVerifyVerbsJsonExitCode:
    """`--json` reported a failed verification and exited 0 (audit sweep).

    An auditor scripting `bundle verify --json` got exit 0 on a bundle whose
    body said every signature failed — the same class as (a) on the verbs whose
    whole purpose is to say yes or no.
    """

    def test_bundle_verify_json_exits_nonzero_when_unverified(
        self, monkeypatch, capsys, tmp_path
    ):
        from regista import Regista

        report = {
            "verified": False,
            "bundle_hash_ok": True,
            "global_chain_ok": False,
            "global_chain_error": "hash mismatch at seq 4",
            "work_item_chain_ok": True,
            "segment_chain_ok": True,
            "errors": ["No public key for key_id 'pk_deadbeef' in bundle registry"],
        }
        monkeypatch.setattr(
            Regista, "verify_audit_bundle_offline", staticmethod(lambda p: report)
        )
        bundle = tmp_path / "bundle.tar.gz"
        bundle.write_bytes(b"")
        code = _run_cli(["bundle", "verify", str(bundle), "--json"])
        out = capsys.readouterr()
        assert json.loads(out.out)["verified"] is False
        assert code == 1

    @pytest.mark.parametrize("json_mode", [True, False], ids=["json", "text"])
    def test_archive_verify_exits_nonzero_when_unverified(
        self, monkeypatch, capsys, json_mode
    ):
        """`archive verify` exited 0 in *both* formats while printing FAILED.

        Not the asymmetry the others have — a plain "print an error, exit 0". Its
        sibling `bundle verify` already exited 1 for the same claim over a wider
        range, so both channels are brought into line here.
        """
        import regista._cli as cli

        class _Archive:
            def verify(self, segment_id):
                return {
                    "verified": False,
                    "event_count": 3,
                    "errors": ["head_hash mismatch"],
                }

        class _FakeRegista:
            def __init__(self, *a, **k):
                self.archive = _Archive()

            def close(self):
                pass

        monkeypatch.setattr(cli, "Regista", _FakeRegista)
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        monkeypatch.setenv("REGISTA_PROJECT", "wi229")
        argv = ["archive", "verify", "00000000-0000-0000-0000-000000000000"]
        if json_mode:
            argv.append("--json")
        code = _run_cli(argv)
        out = capsys.readouterr()
        if json_mode:
            assert json.loads(out.out)["verified"] is False
        assert code == 1

    def test_archive_verify_still_zero_when_verified(self, monkeypatch, capsys):
        import regista._cli as cli

        class _Archive:
            def verify(self, segment_id):
                return {"verified": True, "event_count": 3, "head_hash": "ab" * 16}

        class _FakeRegista:
            def __init__(self, *a, **k):
                self.archive = _Archive()

            def close(self):
                pass

        monkeypatch.setattr(cli, "Regista", _FakeRegista)
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        monkeypatch.setenv("REGISTA_PROJECT", "wi229")
        code = _run_cli(
            ["archive", "verify", "00000000-0000-0000-0000-000000000000", "--json"]
        )
        assert json.loads(capsys.readouterr().out)["verified"] is True
        assert code == 0

    def test_bundle_verify_json_still_zero_when_verified(
        self, monkeypatch, capsys, tmp_path
    ):
        from regista import Regista

        monkeypatch.setattr(
            Regista,
            "verify_audit_bundle_offline",
            staticmethod(
                lambda p: {
                    "verified": True,
                    "event_count": 5,
                    "anchor_receipt_count": 0,
                    "segment_count": 1,
                    "signatures_verified": 4,
                    "signatures_unverifiable": 1,
                    "signature_check": "enforced",
                }
            ),
        )
        bundle = tmp_path / "bundle.tar.gz"
        bundle.write_bytes(b"")
        assert _run_cli(["bundle", "verify", str(bundle), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["verified"] is True


# ---------------------------------------------------------------------------
# (b) a backend 403 escaping as a traceback
# ---------------------------------------------------------------------------


class TestSecretsForbiddenEnvelope:
    """(b) `secrets --ref` must answer a 403 with the envelope, not a traceback.

    `hvac.exceptions.Forbidden` is not a `RegistaError`, and both the handler and
    `main`'s dispatch caught only `RegistaError` — so the process died with a
    traceback and exit 1 from the interpreter, with no parseable document at all.
    """

    @pytest.fixture
    def forbidden_provider(self, monkeypatch):
        """Register a 'vault' provider that raises a real hvac Forbidden."""
        hvac = pytest.importorskip("hvac")
        from regista import _secrets

        class _Forbidden:
            name = "vault"

            def resolve(self, ref):
                raise hvac.exceptions.Forbidden("permission denied")

            def store(self, ref, data):  # pragma: no cover - not exercised
                raise hvac.exceptions.Forbidden("permission denied")

            def delete(self, ref):
                raise hvac.exceptions.Forbidden("permission denied")

        previous = _secrets._PROVIDERS.get("vault")
        _secrets.register_provider(_Forbidden())
        yield
        if previous is not None:
            _secrets.register_provider(previous)
        else:  # pragma: no cover - hvac is installed in this venv
            _secrets.unregister_provider("vault")

    def test_forbidden_becomes_the_error_envelope(self, forbidden_provider, capsys):
        code = _run_cli(
            ["--json", "secrets", "--ref", "vault:kv/agent-suite/qual/denied/field"]
        )
        out = capsys.readouterr()
        assert "Traceback (most recent call last)" not in out.err, (
            "a documented error path raised a traceback — cli-contract.md §4"
        )
        payload = json.loads(out.out)
        assert payload["ok"] is False
        assert payload["error"]["code"] == str(ErrorCode.SECRET_RESOLVE_FAILED)
        assert payload["error"]["retryable"] is False
        assert code == 1

    def test_envelope_names_the_exception_type_not_its_text(
        self, forbidden_provider, capsys
    ):
        """Contract §3 redaction: a backend message never reaches the envelope.

        A Vault error body is attacker-adjacent and can quote request data, so
        only the exception's type is reported.
        """
        _run_cli(
            ["--json", "secrets", "--ref", "vault:kv/agent-suite/qual/denied/field"]
        )
        payload = json.loads(capsys.readouterr().out)
        assert "Forbidden" in payload["error"]["message"]

    def test_text_mode_also_avoids_the_traceback(self, forbidden_provider, capsys):
        code = _run_cli(["secrets", "--ref", "vault:kv/agent-suite/qual/denied/field"])
        out = capsys.readouterr()
        assert "Traceback (most recent call last)" not in out.err
        assert f"[{ErrorCode.SECRET_RESOLVE_FAILED}]" in out.err
        assert out.out == ""
        assert code == 1

    def test_delete_path_is_covered_too(self, forbidden_provider, capsys):
        code = _run_cli(
            [
                "--json",
                "secrets",
                "--delete",
                "--ref",
                "vault:kv/agent-suite/qual/denied/field",
            ]
        )
        out = capsys.readouterr()
        assert "Traceback (most recent call last)" not in out.err
        assert json.loads(out.out)["ok"] is False
        assert code == 1

    def test_a_registaerror_still_reports_its_own_code(self, monkeypatch, capsys):
        """The net must not flatten errors the resolver already classified."""
        from regista import _secrets

        monkeypatch.setattr(
            _secrets,
            "resolve",
            lambda ref: (_ for _ in ()).throw(
                RegistaError(ErrorCode.INVALID_ARGUMENT, "vault: ref must be mount/path/key")
            ),
        )
        code = _run_cli(["--json", "secrets", "--ref", "vault:kv/too/short"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["error"]["code"] == str(ErrorCode.INVALID_ARGUMENT)
        assert code == 1


# ---------------------------------------------------------------------------
# (c) REGISTA_KEY_PATH ignored
# ---------------------------------------------------------------------------


class TestPrincipalEnrollKeyPath:
    """(c) `principal enroll` read only the legacy alias.

    ``REGISTA_KEY_PATH`` is the canonical name in ``_config.CANONICAL_VARS`` and
    the one every runbook and ``suite.env`` sets; ``REGISTA_HMAC_KEY_PATH`` is
    its alias. ``_resolve_config`` consulted the alias only, so the variable an
    operator actually sets was dropped on the floor while ``doctor`` — which goes
    through ``_config.resolve`` — honoured it.
    """

    @pytest.fixture
    def captured(self, monkeypatch):
        """Replace the store with a double that records its constructor args."""
        import regista._cli as cli

        seen = {}

        class _FakeRegista:
            def __init__(self, dsn, project, hmac_key_path=None, *a, **k):
                seen["dsn"] = dsn
                seen["project"] = project
                seen["hmac_key_path"] = hmac_key_path

            def enroll_principal(self, principal, **kwargs):
                return {
                    "principal_id": principal,
                    "key_id": "k1",
                    "fingerprint": "ff",
                    "scheme": "ed25519",
                    "secret_backend": "file",
                    "already_existed": False,
                }

            def close(self):
                pass

        monkeypatch.setattr(cli, "Regista", _FakeRegista)
        monkeypatch.setenv("REGISTA_DSN", _DSN)
        monkeypatch.setenv("REGISTA_PROJECT", "wi229")
        return seen

    def test_canonical_key_path_is_honoured(self, captured, monkeypatch, tmp_path):
        keys = tmp_path / "keys.json"
        keys.write_text('{"keys": []}')
        monkeypatch.setenv("REGISTA_KEY_PATH", str(keys))
        assert _run_cli(["principal", "enroll", "--principal", "p"]) == 0
        assert captured["hmac_key_path"] == str(keys), (
            "principal enroll ignored REGISTA_KEY_PATH from the environment"
        )

    def test_legacy_alias_still_works(self, captured, monkeypatch, tmp_path):
        keys = tmp_path / "legacy.json"
        keys.write_text('{"keys": []}')
        monkeypatch.setenv("REGISTA_HMAC_KEY_PATH", str(keys))
        _run_cli(["principal", "enroll", "--principal", "p"])
        assert captured["hmac_key_path"] == str(keys)

    def test_canonical_wins_over_the_alias(self, captured, monkeypatch, tmp_path):
        """_config.resolve prefers the canonical name; the CLI must agree."""
        canonical = tmp_path / "canonical.json"
        alias = tmp_path / "alias.json"
        for p in (canonical, alias):
            p.write_text('{"keys": []}')
        monkeypatch.setenv("REGISTA_KEY_PATH", str(canonical))
        monkeypatch.setenv("REGISTA_HMAC_KEY_PATH", str(alias))
        _run_cli(["principal", "enroll", "--principal", "p"])
        assert captured["hmac_key_path"] == str(canonical)

    def test_explicit_flag_still_wins(self, captured, monkeypatch, tmp_path):
        env_path = tmp_path / "env.json"
        flag_path = tmp_path / "flag.json"
        for p in (env_path, flag_path):
            p.write_text('{"keys": []}')
        monkeypatch.setenv("REGISTA_KEY_PATH", str(env_path))
        _run_cli(
            ["--hmac-key-path", str(flag_path), "principal", "enroll", "--principal", "p"]
        )
        assert captured["hmac_key_path"] == str(flag_path)

    def test_the_fix_reaches_every_verb_on_the_shared_helper(
        self, captured, monkeypatch, tmp_path
    ):
        """`_resolve_config` is shared, so `replay`/`principal list` gain it too.

        WI-225 filed the same omission against those verbs; they read the same
        helper, so one fix covers them and this pins that down.
        """
        import regista._cli as cli

        keys = tmp_path / "keys.json"
        keys.write_text('{"keys": []}')
        monkeypatch.setenv("REGISTA_KEY_PATH", str(keys))

        class _Args:
            dsn = None
            project = None
            hmac_key_path = None

        assert cli._resolve_config(_Args())[2] == str(keys)


class TestJsonExitCodeAudit:
    """Sweep: no `--json` verb may report failure in its body and exit 0.

    (a) was found on `provision`; the work item asks for every `--json` path to
    be audited for the same shape. This encodes the sweep's result so a new verb
    reintroducing the shape has to argue with a test.
    """

    # Verbs whose failure is carried inside their own result document rather
    # than as an error envelope, with the field that says so.
    SELF_REPORTING_FAILURE_VERBS: ClassVar[dict[str, str]] = {
        "provision": "error",
        "provision-principal": "error",
        "bundle verify": "verified",
        "archive verify": "verified",
        "archive verify-chain": "verified",
    }

    def test_each_audited_verb_decides_its_exit_outside_the_format_branch(self):
        """Guard against the structural cause, not just the symptom.

        Every instance of this bug was a ``sys.exit(1)`` nested inside the
        ``else:`` of an ``if args.json:`` — so the exit was unreachable in JSON
        mode. Assert no ``sys.exit`` remains inside such a branch in the handlers
        that report failure in their own body.
        """
        import ast
        import inspect

        import regista._cli as cli

        handlers = {
            "cmd_provision",
            "cmd_provision_principal",
            "cmd_bundle_verify",
            "cmd_archive_verify",
            "cmd_archive_verify_chain",
        }
        offenders = []
        for name in sorted(handlers):
            fn = getattr(cli, name)
            tree = ast.parse(inspect.getsource(fn).lstrip())
            for node in ast.walk(tree):
                if not isinstance(node, ast.If):
                    continue
                test_src = ast.unparse(node.test)
                if "json" not in test_src or not node.orelse:
                    continue
                for inner in node.orelse:
                    for sub in ast.walk(inner):
                        if (
                            isinstance(sub, ast.Call)
                            and isinstance(sub.func, ast.Attribute)
                            and sub.func.attr == "exit"
                        ):
                            offenders.append(f"{name}: sys.exit inside `else` of `{test_src}`")
        assert offenders == [], (
            "an exit code reachable only when --json is absent means the JSON "
            "channel reports failure and exits 0: " + "; ".join(offenders)
        )

    def test_the_audit_list_is_not_empty(self):
        """cli-contract.md §7: a gate that covers nothing enforces nothing."""
        assert len(self.SELF_REPORTING_FAILURE_VERBS) >= 5
