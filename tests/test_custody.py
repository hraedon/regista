from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
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

#: Azure Key Vault's secret-name rule, transcribed from the service contract rather than
#: from regista: ``^[0-9a-zA-Z-]+$``, 1-127 characters.
AZURE_SECRET_NAME_RE = re.compile(r"[0-9a-zA-Z-]{1,127}")

#: Every backend that regista can custody a generated key on. ``file`` is excluded from the
#: name-shape pins below on purpose: it keeps the ratified dual convention (WI-294), where a
#: path-safe legacy id stays verbatim so existing refs resolve.
WRITABLE_NAME_DERIVING_BACKENDS = ("azure", "windows", "vault")


def _bn(principal_id: str) -> str:
    from regista._principals import backend_name

    return backend_name(principal_id)


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
        from regista._principals import backend_name

        ref = build_ref("vault", "eve", project="proj")
        assert ref == (
            f"vault:secret/regista/proj/principals/{backend_name('eve')}/private_key"
        )

    def test_build_ref_azure_derives_the_principal_segment(self):
        """WI-297: the principal segment is §2.2's derived name, not a ``-`` substitution.

        The project segment stays readable — a Key Vault may be shared across projects, so
        dropping it would let two projects collide on one secret.
        """
        from regista._principals import backend_name

        ref = build_ref("azure", "eve.example.com", project="myproj")
        assert ref == f"azure:regista-myproj-{backend_name('eve.example.com')}"

    def test_build_ref_azure_derives_a_project_key_vault_cannot_spell(self):
        """``my_proj`` is a legal upstream project name but ``_`` is illegal in Key Vault."""
        from regista._custody import _project_segment
        from regista._principals import backend_name

        ref = build_ref("azure", "eve", project="my_proj")
        seg = _project_segment("my_proj")
        assert seg == "px-" + hashlib.sha256(
            b"regista.custody.project-name.v1\x00my_proj"
        ).hexdigest()[:32]
        assert ref == f"azure:regista-{seg}-{backend_name('eve')}"

    def test_build_ref_azure_needs_no_truncation_branch(self):
        """The derived form is bounded by construction, so the old lossy truncate-and-hash
        fallback is gone: a 200-character principal id and a 200-character project both
        land inside Key Vault's 127-character limit."""
        name = build_ref("azure", "a" * 200, project="p" * 200).removeprefix("azure:")
        assert len(name) <= 127
        assert AZURE_SECRET_NAME_RE.fullmatch(name)

    def test_build_ref_windows_is_colon_free(self):
        """§2.2 applies to every name regista produces. The value is superseded at store
        time (``WindowsProvider.store`` returns the DPAPI blob as the ref), but a
        ``:``-bearing credential name is a violation wherever it is minted."""
        from regista._principals import backend_name

        ref = build_ref("windows", "human:it-admin", project="proj")
        assert ref == f"windows:regista-proj-{backend_name('human:it-admin')}"

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
        from regista._principals import backend_name

        tmpl = operator_ref_template("alice", project="myproj")
        assert tmpl == (
            f"vault:secret/regista/myproj/principals/{backend_name('alice')}/private_key"
        )

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
    """Backend-aware custody, exercised directly against ``store_private_key``.

    Rewritten for P2.2: ``provision_principal`` refuses **before** minting
    (TRUST-DOMAIN.md §5.9 rule 2 — it wrote ``principal_keys`` with no signed
    event), so it can no longer be the vehicle for testing custody backends. The
    backend assertions are unchanged; they now call the unit they were always about.
    """

    def test_file_backend_round_trip(self, tmp_path):
        principals_dir = tmp_path / "principals"
        custody = store_private_key(
            backend="file",
            principal_id="agent:alice",
            project="p",
            private_key_dir=str(principals_dir),
        )
        assert custody.backend == "file"
        assert custody.secret_ref.startswith("file:")
        assert custody.encoding is None

        # Read the key back through the secret_ref the caller was handed, rather
        # than re-deriving _custody's filename rule in the test. That rule has two
        # branches (direct name vs the §2.2 derived backend-safe name, depending on
        # whether "<id>_ed25519.key" is a safe single path component), and a test
        # that hardcodes one of them pins a name the contract does not promise.
        assert custody.secret_ref.startswith("file:")
        priv_path = pathlib.Path(custody.secret_ref.removeprefix("file:"))
        assert priv_path.parent == principals_dir
        priv_bytes = priv_path.read_bytes()
        _assert_keypair_verifies(priv_bytes, custody.public_key)

    def test_vault_backend_writes_no_plaintext_key(self, tmp_path, fake_vault):
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()
        custody = store_private_key(
            backend="vault",
            principal_id="agent:bob",
            project="p",
            private_key_dir=str(principals_dir),
        )
        assert custody.backend == "vault"
        assert not any(principals_dir.iterdir()), (
            "the gap-catching test: a non-file backend must not write a "
            "plaintext .key file to local disk"
        )
        assert custody.secret_ref.startswith("vault:")
        assert custody.encoding == "base64"

        resolved = resolve_secret(custody.secret_ref)
        priv_bytes = base64.b64decode(resolved)
        _assert_keypair_verifies(priv_bytes, custody.public_key)

    def test_operator_backend_raises_loud(self, tmp_path):
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()
        with pytest.raises(RegistaError) as exc:
            store_private_key(
                backend="operator",
                principal_id="agent:carol",
                project="p",
                private_key_dir=str(principals_dir),
            )
        assert exc.value.code == ErrorCode.SECRET_WRITE_EXTERNAL
        assert not any(principals_dir.iterdir()), (
            "operator backend must not write any key file"
        )

    def test_provision_refuses_before_touching_custody(
        self, project_with_keys, tmp_path,
    ):
        """The refusal is upstream of key minting, so no orphaned secret is left."""
        project, key_file = project_with_keys
        principals_dir = tmp_path / "principals"
        principals_dir.mkdir()
        with pytest.raises(RegistaError) as exc:
            provision_principal(
                DSN, project, "agent:alice",
                hmac_key_path=str(key_file),
                private_key_dir=str(principals_dir),
                secret_backend="file",
            )
        assert exc.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert not any(principals_dir.iterdir()), (
            "a refused provisioning must not leave private key material behind"
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


# ---------------------------------------------------------------------------
# WI-297: §2.2 conformance of the names build_ref mints
# ---------------------------------------------------------------------------


class TestWI297BackendSafeNaming:
    """Fix-forward, not a migration: refs are resolved verbatim from the record they were
    written into, so these pins constrain what regista *mints* from now on. Nothing here
    asserts anything about an existing ref."""

    def test_distinct_principals_never_share_a_name_on_any_writable_backend(self):
        """The collision the old ``:``->``-`` substitution had, mirrored from
        ``test_p23_principal_grammar.py::test_backend_name_is_not_a_colon_to_hyphen_substitution``.
        Under substitution both of these spell ``human-it-admin``."""
        for backend in WRITABLE_NAME_DERIVING_BACKENDS:
            a = build_ref(backend, "human:it-admin", project="proj")
            b = build_ref(backend, "human-it:admin", project="proj")
            assert a != b, backend

    def test_distinct_principals_never_share_a_name_on_the_file_backend(self, tmp_path):
        """The file backend keeps the WI-294 dual convention, so it gets the same pin by a
        different route: both ids contain no path separator, so both take the verbatim
        branch, and the verbatim branch is the identity map."""
        a = build_ref("file", "human:it-admin", private_key_dir=str(tmp_path))
        b = build_ref("file", "human-it:admin", private_key_dir=str(tmp_path))
        assert a != b

    def test_a_long_principal_id_does_not_collide_by_truncation(self):
        """The deleted azure truncation branch cut the *head* of the name to fit 127 and
        appended 16 hex of the raw string; two ids sharing a long prefix relied entirely on
        that suffix. The derived name has no truncation at all."""
        long_a = "agent:" + "a" * 240
        long_b = "agent:" + "a" * 239 + "b"
        for backend in WRITABLE_NAME_DERIVING_BACKENDS:
            assert build_ref(backend, long_a, project="p") != build_ref(
                backend, long_b, project="p"
            ), backend

    def test_distinct_projects_never_share_a_name(self):
        """Why the project segment survived the rewrite (WI-297 review): a Key Vault may be
        shared across projects, so a principal-only name would collide across them. Includes
        the pair the old lossy substitution merged (``my_proj``/``my-proj``)."""
        projects = ["my_proj", "my-proj", "myproj", "p" * 200, "p" * 201, "prod/eu"]
        for backend in WRITABLE_NAME_DERIVING_BACKENDS:
            names = {build_ref(backend, "agent:a", project=p) for p in projects}
            assert len(names) == len(projects), backend

    def test_a_project_named_like_the_derived_form_cannot_alias_another_project(self):
        """The verbatim and derived branches must have disjoint ranges, or a project
        *named* ``px-<32 hex>`` could squat on the derived segment of another project."""
        from regista._custody import _project_segment

        squatter = _project_segment("prod/eu")
        assert squatter.startswith("px-")
        assert _project_segment(squatter) != squatter

    def test_case_differing_projects_do_not_fold_together_on_azure(self):
        """Key Vault secret names are **case-insensitive**, so plain inequality is not the
        test — the names must differ *after case folding*. ``MyProj`` therefore takes the
        derived branch instead of being spelled verbatim next to ``myproj``."""
        upper = build_ref("azure", "agent:a", project="MyProj").removeprefix("azure:")
        lower = build_ref("azure", "agent:a", project="myproj").removeprefix("azure:")
        assert upper != lower
        assert upper.casefold() != lower.casefold()
        assert lower == f"regista-myproj-{_bn('agent:a')}"
        assert "px-" in upper  # MyProj derived rather than kept verbatim

    def test_no_two_projects_fold_together_on_azure(self):
        """The case-folded generalisation of the disjointness pin, over the spellings that
        probe the branch boundary."""
        projects = [
            "myproj", "MyProj", "MYPROJ", "my_proj", "my-proj",
            "px-" + "a" * 32, "PX-" + "A" * 32, "p" * 63, "p" * 64,
        ]
        folded = {
            build_ref("azure", "agent:a", project=p).removeprefix("azure:").casefold()
            for p in projects
        }
        assert len(folded) == len(projects)

    def test_an_uppercase_derived_shape_project_cannot_case_fold_squat(self):
        """The specific escape the lowercase-only class closes: ``px-<UPPERCASE 32 hex>``
        passed the old ``[A-Za-z0-9-]`` class and the lowercase-only shape refusal, so it
        was emitted verbatim and case-folded straight onto a real derived segment."""
        from regista._custody import _project_segment

        victim = _project_segment("prod/eu")
        assert victim == victim.casefold()
        squatter = "px-" + victim.removeprefix("px-").upper()
        assert squatter.casefold() == victim  # it *would* fold, if emitted verbatim
        assert _project_segment(squatter).casefold() != victim

    def test_the_verbatim_class_is_stricter_than_key_vaults_own(self):
        """Not a redundant restatement of the service grammar: uppercase and 64-plus are
        legal at Key Vault and refused here, and that gap is the whole safety argument."""
        from regista._custody import _VERBATIM_PROJECT_RE

        assert _VERBATIM_PROJECT_RE.fullmatch("myproj")
        assert not _VERBATIM_PROJECT_RE.fullmatch("MyProj")
        assert not _VERBATIM_PROJECT_RE.fullmatch("p" * 64)
        assert AZURE_SECRET_NAME_RE.fullmatch("MyProj")
        assert AZURE_SECRET_NAME_RE.fullmatch("p" * 64)

    @pytest.mark.parametrize("backend", WRITABLE_NAME_DERIVING_BACKENDS)
    def test_the_principal_segment_is_colon_free(self, backend):
        """§2.2's premise: Azure Key Vault and the Windows credential store forbid ``:``."""
        from regista._principals import backend_name

        ref = build_ref(backend, "service:idp:tenant-a/svc-7", project="proj")
        value = ref.partition(":")[2]
        assert ":" not in value
        assert backend_name("service:idp:tenant-a/svc-7") in value

    def test_azure_names_match_the_key_vault_grammar_and_length(self):
        """Not just colon-free: Key Vault accepts only ``[0-9a-zA-Z-]``, max 127."""
        hostile = [
            "eve.example.com",
            "human:it-admin",
            "service:idp:tenant-a/svc-7",
            "agent:a/../../../etc/cron.d/evil",
            "agent:ünïcøde",
            "agent:" + "a" * 240,
        ]
        projects = ["proj", "my_proj", "prod/eu", "pr oj", "ünïcøde", "p" * 200]
        for principal_id in hostile:
            for project in projects:
                name = build_ref(
                    "azure", principal_id, project=project
                ).removeprefix("azure:")
                assert AZURE_SECRET_NAME_RE.fullmatch(name), (principal_id, project, name)

    def test_the_principal_segment_is_the_fixed_width_trailing_token(self):
        """Why ``regista-<project>-<backend_name>`` is unambiguous without an escape rule:
        ``backend_name`` is exactly 35 characters, so the name parses right-to-left however
        many hyphens the project segment contains."""
        from regista._principals import backend_name, is_backend_name

        name = build_ref(
            "azure", "human:it-admin", project="a-b-c-d"
        ).removeprefix("azure:")
        assert is_backend_name(name[-35:])
        assert name[-35:] == backend_name("human:it-admin")
        assert name == "regista-a-b-c-d-" + name[-35:]

    def test_vault_keeps_its_path_structure(self):
        """Only the principal segment changed; the tree stays browsable by project."""
        ref = build_ref("vault", "human:it-admin", project="proj")
        assert ref.startswith("vault:secret/regista/proj/principals/")
        assert ref.endswith("/private_key")

    def test_operator_ref_template_and_vault_agree(self):
        """The template an operator is told to populate must be the ref regista would have
        built, or operator-writes custody lands the key somewhere nothing reads."""
        assert operator_ref_template("human:it-admin", project="proj") == build_ref(
            "vault", "human:it-admin", project="proj"
        )


class TestWI297OperatorPrefixIsRefused:
    """``operator`` names a custody mode, not a provider. It is absent from
    ``_KNOWN_PROVIDER_NAMES``, so before WI-297 ``_detect_prefix`` fell through to
    ``literal`` and ``resolve()`` returned the *reference text* as secret bytes."""

    def test_resolve_refuses_an_operator_ref_instead_of_returning_bytes(self):
        ref = "operator:secret/regista/proj/principals/alice/private_key"
        with pytest.raises(RegistaError) as exc:
            resolve_secret(ref)
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT
        assert "custody mode" in str(exc.value)

    def test_the_refusal_is_not_a_literal_fallback(self):
        """The regression in one line: whatever happens, it is never the ref itself."""
        ref = "operator:whatever"
        try:
            out = resolve_secret(ref)
        except RegistaError:
            return
        assert out != ref.encode("utf-8")
        raise AssertionError(f"operator: ref resolved to {out!r} instead of raising")

    @pytest.mark.parametrize(
        "ref",
        [
            "operator:some/path",
            "OPERATOR:some/path",
            "Operator:some/path",
            " operator:some/path",
            "operator :some/path",
            "\toperator:some/path",
        ],
    )
    def test_the_refusal_is_not_defeated_by_case_or_whitespace(self, ref):
        """The fail-open this closes is not case-sensitive: every one of these took the
        same fall-through to the literal provider, so every one has to be refused."""
        with pytest.raises(RegistaError) as exc:
            resolve_secret(ref)
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT
        assert exc.value.detail["reason"] == "reserved_custody_prefix"

    def test_normalising_the_prefix_does_not_widen_anything_else(self):
        """The normalisation applies to the reserved-name test only. A prefix that is not
        reserved under any spelling must resolve exactly as it did before — otherwise this
        would quietly become a case-insensitive provider lookup."""
        assert resolve_secret("NOSUCHBACKEND:whatever") == b"NOSUCHBACKEND:whatever"
        assert resolve_secret("FILE:whatever") == b"FILE:whatever"
        assert resolve_secret(" literal:x") == b" literal:x"

    def test_store_refuses_an_operator_ref(self):
        with pytest.raises(RegistaError) as exc:
            store_secret("operator:some/path", b"secret-bytes")
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT

    def test_reference_provider_refuses_operator_in_both_modes(self):
        from regista._secrets import reference_provider

        for require_explicit in (False, True):
            with pytest.raises(RegistaError) as exc:
                reference_provider("operator:some/path", require_explicit=require_explicit)
            assert exc.value.code is ErrorCode.INVALID_ARGUMENT
            assert "custody mode" in str(exc.value)

    def test_operator_is_still_not_advertised_as_a_provider(self):
        from regista._secrets import available_providers, known_providers

        assert "operator" not in known_providers()
        assert "operator" not in available_providers()

    def test_an_ordinary_unknown_prefix_still_falls_back_to_literal(self):
        """The refusal is a narrow reserved-name rule, not a change to the module-wide
        literal convention that ``test_secret_delete.py`` pins."""
        assert resolve_secret("nosuchbackend:whatever") == b"nosuchbackend:whatever"

    def test_doctor_reports_the_refusal_instead_of_raising(self):
        """Doctor's contract is a report, never a traceback, so the new refusal has to
        degrade to a skipped check where doctor sniffs a key_path prefix."""
        from regista._doctor import run_doctor

        report = run_doctor(dsn=None, key_path="operator:secret/x/private_key")
        consistency = [c for c in report.checks if c.name == "custody:consistency"]
        assert consistency and consistency[0].status == "skip"
        assert "operator:secret/x/private_key" in consistency[0].detail

    def test_doctor_only_swallows_this_refusal_not_every_future_one(self, monkeypatch):
        """A bare ``except RegistaError`` there would silently downgrade the *next*
        fail-closed check added to ``_detect_prefix`` into a skipped health row."""
        import regista._secrets as secrets_mod
        from regista._doctor import _resolve_key_file_path

        def _boom(ref):
            raise RegistaError(ErrorCode.SECRET_RESOLVE_FAILED, "some future gate")

        monkeypatch.setattr(secrets_mod, "_detect_prefix", _boom)
        with pytest.raises(RegistaError) as exc:
            _resolve_key_file_path("file:/tmp/keys.json")
        assert exc.value.code is ErrorCode.SECRET_RESOLVE_FAILED


def _assert_keypair_verifies(private_key: bytes, public_key: bytes) -> None:
    import nacl.encoding
    import nacl.signing

    sk = nacl.signing.SigningKey(private_key)
    vk = sk.verify_key
    assert bytes(vk) == public_key
    msg = b"test-message"
    signed = sk.sign(msg)
    vk.verify(signed.message, signature=signed.signature)
