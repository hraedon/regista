"""WI-236 — signing-key encoding contract + operator fingerprint surface.

Two prerequisites for moving keys.json material behind secret refs safely:

1. **A closed encoding contract.** A KeySet entry declares its transport
   encoding; ``base64`` is the only transform and ``utf8`` the explicit
   spelling of the default. Before this, an unrecognized ``encoding`` value
   fell through silently to the textual bytes — deriving a *different*
   signing key than the entry declared, with every health surface green.

2. **An effective-fingerprint surface.** ``regista keys fingerprint`` prints
   each key_id, where its material came from, and the fingerprint of the
   EFFECTIVE key bytes — never the material. Its ``--json`` output is stable
   and parseable, which is the documented before/after equality primitive for
   custody changes.

The trap both guard: the estate's active HMAC key *looks* base64 but carries
no ``encoding``, so regista signs with its textual bytes. Any migration that
decodes it silently invalidates historical HMAC verification. The fingerprint
must therefore reflect the effective bytes — and nothing in WI-236 may change
how any existing entry's effective key is derived.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._keys import SUPPORTED_KEY_ENCODINGS, KeySet

# Hermetic: everything here runs against tmp_path key files.
_regista_db_dependent = False

# Not a credential: fixture payload. Its base64 alphabet makes it "look
# base64" while its textual bytes are a perfectly usable HMAC key.
_LOOKS_B64 = "znJ3YniJUD536jl8SX0CGIstOP/ZWUwr8vkuRMGYfnI="


def _write_keys(tmp_path, entries):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": entries}))
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip inherited suite config so results are hermetic (WI-229 idiom)."""
    for var in (
        "REGISTA_DSN",
        "REGISTA_PROJECT",
        "REGISTA_KEY_PATH",
        "REGISTA_HMAC_KEY_PATH",
        "REGISTA_SECRET_BACKEND",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_SUITE_CONFIG", "/nonexistent/regista-wi236/suite.env")


# ---------------------------------------------------------------------------
# 1. The encoding contract: closed set, loud rejection, no fall-through
# ---------------------------------------------------------------------------


class TestEncodingContract:
    def test_unknown_inline_encoding_fails_at_load(self, tmp_path):
        """The defect this item exists for: ``banana`` used to fall through.

        Before WI-236 an unrecognized encoding silently used the textual
        bytes — signing with a key the entry never declared.
        """
        path = _write_keys(
            tmp_path, [{"key_id": "k1", "secret": _LOOKS_B64, "encoding": "banana"}]
        )
        with pytest.raises(RegistaError) as exc:
            KeySet(path)
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "banana" in exc.value.message

    def test_rejection_names_the_supported_encodings(self, tmp_path):
        path = _write_keys(
            tmp_path, [{"key_id": "k1", "secret": "x", "encoding": "hex"}]
        )
        with pytest.raises(RegistaError) as exc:
            KeySet(path)
        for supported in SUPPORTED_KEY_ENCODINGS:
            assert repr(supported) in exc.value.message

    def test_unknown_encoding_on_a_secret_ref_entry_fails_at_load(self, tmp_path):
        secret_file = tmp_path / "key-material"
        secret_file.write_text(_LOOKS_B64)
        path = _write_keys(
            tmp_path,
            [
                {
                    "key_id": "k1",
                    "secret_ref": f"file:{secret_file}",
                    "encoding": "base85",
                }
            ],
        )
        with pytest.raises(RegistaError) as exc:
            KeySet(path)
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "base85" in exc.value.message

    def test_unknown_encoding_fails_even_under_an_env_override(self, tmp_path, monkeypatch):
        """A broken key file is broken on every host, not just the ones
        without the env override that would mask it."""
        monkeypatch.setenv("REGISTA_HMAC_KEY_K1", "override-material")
        path = _write_keys(
            tmp_path, [{"key_id": "k1", "secret": "x", "encoding": "banana"}]
        )
        with pytest.raises(RegistaError) as exc:
            KeySet(path)
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR

    def test_non_string_encoding_is_rejected_not_guessed(self, tmp_path):
        path = _write_keys(
            tmp_path, [{"key_id": "k1", "secret": "x", "encoding": 64}]
        )
        with pytest.raises(RegistaError) as exc:
            KeySet(path)
        assert exc.value.code == ErrorCode.KEY_LOAD_ERROR

    def test_base64_still_decodes_inline(self, tmp_path):
        raw = os.urandom(32)
        entry = {
            "key_id": "k1",
            "secret": base64.b64encode(raw).decode("ascii"),
            "encoding": "base64",
        }
        keyset = KeySet(_write_keys(tmp_path, [entry]))
        assert keyset.get_key("k1").secret == raw

    def test_base64_still_decodes_through_a_secret_ref(self, tmp_path):
        raw = os.urandom(32)
        secret_file = tmp_path / "key-material"
        secret_file.write_bytes(base64.b64encode(raw))
        entry = {
            "key_id": "k1",
            "secret_ref": f"file:{secret_file}",
            "encoding": "base64",
        }
        keyset = KeySet(_write_keys(tmp_path, [entry]))
        assert keyset.get_key("k1").secret == raw

    def test_explicit_utf8_is_the_spelled_out_default(self, tmp_path):
        explicit = KeySet(
            _write_keys(
                tmp_path, [{"key_id": "k1", "secret": "hello", "encoding": "utf8"}]
            )
        )
        assert explicit.get_key("k1").secret == b"hello"

    def test_absent_encoding_uses_textual_bytes_even_when_it_looks_base64(
        self, tmp_path
    ):
        """The effective-key trap, pinned.

        This is the estate's active-key shape: base64-looking material with no
        ``encoding``. The effective key IS the textual bytes; decoding it here
        would invalidate every historical HMAC signature.
        """
        keyset = KeySet(_write_keys(tmp_path, [{"key_id": "k1", "secret": _LOOKS_B64}]))
        entry = keyset.get_key("k1")
        assert entry.secret == _LOOKS_B64.encode("utf-8")
        assert entry.secret != base64.b64decode(_LOOKS_B64)


# ---------------------------------------------------------------------------
# 2. The operator surface: describe_keys()
# ---------------------------------------------------------------------------


class TestDescribeKeys:
    def _keyset(self, tmp_path):
        secret_file = tmp_path / "ref-material"
        raw = os.urandom(32)
        secret_file.write_bytes(base64.b64encode(raw))
        entries = [
            {"key_id": "inline-key", "secret": _LOOKS_B64},
            {
                "key_id": "ref-key",
                "secret_ref": f"file:{secret_file}",
                "encoding": "base64",
            },
        ]
        return KeySet(_write_keys(tmp_path, entries)), raw

    def test_reports_source_kind_per_key(self, tmp_path):
        keyset, _ = self._keyset(tmp_path)
        rows = {r["key_id"]: r for r in keyset.describe_keys()}
        assert rows["inline-key"]["source"] == "inline"
        assert rows["ref-key"]["source"] == "secret_ref:file"

    def test_env_override_is_attributed_to_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REGISTA_HMAC_KEY_INLINE_KEY", "env-material")
        keyset, _ = self._keyset(tmp_path)
        rows = {r["key_id"]: r for r in keyset.describe_keys()}
        assert rows["inline-key"]["source"] == "env"
        assert rows["inline-key"]["fingerprint"] == (
            f"hmac-sha256:sha256:{_sha256(b'env-material')}"
        )

    def test_fingerprint_is_over_the_effective_bytes(self, tmp_path):
        """One digest per shape of the trap: textual on one side of the
        migration, decoded on the other — and they must differ."""
        keyset, raw = self._keyset(tmp_path)
        rows = {r["key_id"]: r for r in keyset.describe_keys()}
        textual = _sha256(_LOOKS_B64.encode("utf-8"))
        decoded = _sha256(base64.b64decode(_LOOKS_B64))
        assert rows["inline-key"]["fingerprint"] == f"hmac-sha256:sha256:{textual}"
        assert rows["inline-key"]["fingerprint"] != f"hmac-sha256:sha256:{decoded}"
        assert rows["ref-key"]["fingerprint"] == f"hmac-sha256:sha256:{_sha256(raw)}"

    def test_reports_the_applied_encoding(self, tmp_path):
        keyset, _ = self._keyset(tmp_path)
        rows = {r["key_id"]: r for r in keyset.describe_keys()}
        assert rows["inline-key"]["encoding"] is None
        assert rows["ref-key"]["encoding"] == "base64"

    def test_never_contains_key_material(self, tmp_path):
        keyset, raw = self._keyset(tmp_path)
        blob = repr(keyset.describe_keys())
        assert _LOOKS_B64 not in blob
        assert base64.b64encode(raw).decode("ascii") not in blob

    def test_before_after_equality_across_a_custody_change(self, tmp_path):
        """The primitive itself: same effective bytes => same fingerprint.

        An inline textual key is re-custodied behind a file ref carrying the
        base64 encoding of the SAME textual bytes. The fingerprints must be
        equal — that equality is what proves the migration did not change the
        signing key.
        """
        before = KeySet(
            _write_keys(tmp_path, [{"key_id": "k1", "secret": _LOOKS_B64}])
        ).describe_keys()

        migrated = tmp_path / "migrated-material"
        effective = _LOOKS_B64.encode("utf-8")
        migrated.write_bytes(base64.b64encode(effective))
        after_dir = tmp_path / "after"
        after_dir.mkdir()
        after = KeySet(
            _write_keys(after_dir, [
                {
                    "key_id": "k1",
                    "secret_ref": f"file:{migrated}",
                    "encoding": "base64",
                },
            ])
        ).describe_keys()

        assert before[0]["fingerprint"] == after[0]["fingerprint"]

    def test_the_trap_migration_is_caught_by_inequality(self, tmp_path):
        """And the wrong migration — decoding the looks-base64 key — is
        exactly what the comparison catches."""
        before = KeySet(
            _write_keys(tmp_path, [{"key_id": "k1", "secret": _LOOKS_B64}])
        ).describe_keys()

        wrong = tmp_path / "wrongly-decoded"
        wrong.write_bytes(_LOOKS_B64.encode("utf-8"))  # ref now holds the b64 text
        after_dir = tmp_path / "after"
        after_dir.mkdir()
        after = KeySet(
            _write_keys(after_dir, [
                {
                    "key_id": "k1",
                    "secret_ref": f"file:{wrong}",
                    "encoding": "base64",  # ...and regista decodes it
                },
            ])
        ).describe_keys()

        assert before[0]["fingerprint"] != after[0]["fingerprint"]


# ---------------------------------------------------------------------------
# 3. The CLI verb: regista keys fingerprint
# ---------------------------------------------------------------------------


def _run_cli(argv):
    from regista._cli import main

    try:
        main(argv)
    except SystemExit as e:
        return e.code if e.code is not None else 0
    return 0


class TestKeysFingerprintCli:
    @pytest.fixture
    def key_file(self, tmp_path):
        return _write_keys(
            tmp_path,
            [
                {"key_id": "regista-prod-001", "secret": _LOOKS_B64},
                {
                    "key_id": "k-b64",
                    "secret": base64.b64encode(b"decoded-material").decode("ascii"),
                    "encoding": "base64",
                },
            ],
        )

    def test_json_output_is_stable_and_parseable(self, key_file, monkeypatch, capsys):
        """The scriptable before/after primitive: parse, index by key_id,
        compare ``fingerprint``."""
        monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint", "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["key_path"] == str(key_file)
        rows = {r["key_id"]: r for r in report["keys"]}
        assert set(rows) == {"regista-prod-001", "k-b64"}
        expected = {"key_id", "source", "scheme", "status", "principal_id",
                    "encoding", "fingerprint"}
        assert set(rows["regista-prod-001"]) == expected
        assert rows["regista-prod-001"]["fingerprint"] == (
            f"hmac-sha256:sha256:{_sha256(_LOOKS_B64.encode('utf-8'))}"
        )
        assert rows["k-b64"]["fingerprint"] == (
            f"hmac-sha256:sha256:{_sha256(b'decoded-material')}"
        )

    def test_honors_regista_key_path_like_doctor_does(
        self, key_file, monkeypatch, capsys
    ):
        """WI-225's fix, reused: the canonical variable name works..."""
        monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["keys"]

    def test_honors_the_legacy_alias_too(self, key_file, monkeypatch, capsys):
        """...and so does its legacy alias, through the same _config.resolve."""
        monkeypatch.setenv("REGISTA_HMAC_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["keys"]

    def test_explicit_flag_wins(self, key_file, monkeypatch, capsys):
        monkeypatch.setenv("REGISTA_KEY_PATH", "/nonexistent/other-keys.json")
        assert _run_cli(
            ["--hmac-key-path", str(key_file), "keys", "fingerprint", "--json"]
        ) == 0
        assert json.loads(capsys.readouterr().out)["key_path"] == str(key_file)

    def test_single_key_filter(self, key_file, monkeypatch, capsys):
        monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint", "k-b64", "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert [r["key_id"] for r in report["keys"]] == ["k-b64"]

    def test_unknown_key_id_is_an_enveloped_error(self, key_file, monkeypatch, capsys):
        monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint", "nope", "--json"]) == 1
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "UNKNOWN_KEY_ID"

    def test_no_key_path_configured_is_an_enveloped_error(self, capsys):
        assert _run_cli(["keys", "fingerprint", "--json"]) == 1
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["ok"] is False
        assert "REGISTA_KEY_PATH" in envelope["error"]["message"]

    def test_text_output_never_contains_key_material(
        self, key_file, monkeypatch, capsys
    ):
        monkeypatch.setenv("REGISTA_KEY_PATH", str(key_file))
        assert _run_cli(["keys", "fingerprint"]) == 0
        out = capsys.readouterr().out
        assert "regista-prod-001" in out
        assert "fingerprint:" in out
        assert _LOOKS_B64 not in out
        assert base64.b64encode(b"decoded-material").decode("ascii") not in out

    def test_docstring_documents_the_before_after_primitive(self):
        """WI-236 item 4: the equality check is documented, not folklore."""
        from regista._cli import cmd_keys_fingerprint

        doc = cmd_keys_fingerprint.__doc__ or ""
        assert "before" in doc and "after" in doc
        assert "fingerprint" in doc
