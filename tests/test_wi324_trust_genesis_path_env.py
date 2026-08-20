"""WI-324: the pinned-genesis environment variable was spelled ``REGISTRA_...``.

Every call site read ``REGISTRA_TRUST_GENESIS_PATH`` — a misspelling of the product
name — so an operator who exported the documented ``REGISTA_TRUST_GENESIS_PATH`` got a
SILENT miss and the no-genesis posture: `trust enroll` refused for "no genesis
document", and `doctor`'s projection check reported the projection unverifiable, both
while a perfectly good pin sat in the environment under the right name.

The fix is a shared resolver (``_trust_genesis_file.trust_genesis_path_from_env``) that
prefers the canonical spelling and honours the misspelling as a DEPRECATED fallback
with a stderr warning — never silently, because a silently-honoured typo is how the
typo survives.

No DSN needed: this is entirely about environment resolution.
"""

from __future__ import annotations

import json

import pytest

from regista._cli import _load_genesis_document
from regista._doctor import _operator_genesis_document
from regista._errors import ErrorCode, RegistaError
from regista._trust_genesis_file import (
    DEPRECATED_TRUST_GENESIS_PATH_ENV,
    TRUST_GENESIS_PATH_ENV,
    trust_genesis_path_from_env,
)

CANONICAL = TRUST_GENESIS_PATH_ENV
DEPRECATED = DEPRECATED_TRUST_GENESIS_PATH_ENV


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv(CANONICAL, raising=False)
    monkeypatch.delenv(DEPRECATED, raising=False)
    return monkeypatch


def _doc(tmp_path, name="genesis.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"type": "regista.trust-genesis", "marker": name}),
                    encoding="utf-8")
    return str(path)


def test_the_canonical_spelling_is_the_documented_one():
    """The name in docs, runbooks and suite.env — spelled with one R, not two."""
    assert CANONICAL == "REGISTA_TRUST_GENESIS_PATH"
    assert DEPRECATED == "REGISTRA_TRUST_GENESIS_PATH"


def test_canonical_spelling_is_honoured(clean_env, tmp_path):
    """The regression: before WI-324 this was a silent miss at every call site."""
    path = _doc(tmp_path)
    clean_env.setenv(CANONICAL, path)
    assert trust_genesis_path_from_env() == path
    assert _load_genesis_document(None) == {
        "type": "regista.trust-genesis", "marker": "genesis.json"
    }
    assert _operator_genesis_document() is not None


def test_deprecated_spelling_still_works_but_warns(clean_env, tmp_path, capsys):
    path = _doc(tmp_path, "legacy.json")
    clean_env.setenv(DEPRECATED, path)
    assert trust_genesis_path_from_env() == path
    warning = capsys.readouterr().err
    assert DEPRECATED in warning
    assert CANONICAL in warning
    assert "deprecated" in warning.lower()


def test_the_canonical_spelling_wins_when_both_are_set(clean_env, tmp_path, capsys):
    """A mixed environment is not ambiguous; it has one right answer and no warning."""
    canonical = _doc(tmp_path, "canonical.json")
    clean_env.setenv(CANONICAL, canonical)
    clean_env.setenv(DEPRECATED, _doc(tmp_path, "legacy.json"))
    assert trust_genesis_path_from_env() == canonical
    assert capsys.readouterr().err == ""


def test_neither_set_resolves_to_none(clean_env):
    assert trust_genesis_path_from_env() is None
    assert _load_genesis_document(None) is None
    assert _operator_genesis_document() is None


def test_an_explicit_blank_value_is_a_config_error_not_an_absence(clean_env):
    """A configured-but-empty pin must not downgrade to the no-genesis posture.

    ``load_trust_genesis_document`` already distinguished these; the env resolver has
    to preserve the distinction rather than mapping blank to ``None``.
    """
    clean_env.setenv(CANONICAL, "")
    assert trust_genesis_path_from_env() == ""
    with pytest.raises(RegistaError) as exc:
        _load_genesis_document(None)
    assert exc.value.code is ErrorCode.TRUST_GENESIS_SCHEMA_INVALID
    assert exc.value.detail["reason"] == "genesis_path_empty"


def test_an_explicit_flag_beats_both_spellings(clean_env, tmp_path):
    clean_env.setenv(CANONICAL, _doc(tmp_path, "env.json"))
    explicit = _doc(tmp_path, "flag.json")
    assert _load_genesis_document(explicit)["marker"] == "flag.json"


def test_the_misspelling_is_gone_from_every_call_site():
    """A structural check: the typo may only survive as the named deprecated constant.

    Without this, the next module to need the pin can reintroduce the misspelling and
    nothing turns red — which is exactly how it reached five call sites.
    """
    import pathlib

    import regista

    root = pathlib.Path(regista.__file__).parent
    offenders: list[str] = []
    for source in sorted(root.rglob("*.py")):
        text = source.read_text(encoding="utf-8")
        if DEPRECATED not in text:
            continue
        if source.name == "_trust_genesis_file.py":
            # The one legitimate home: the deprecated-constant definition and its
            # warning text.
            continue
        offenders.append(str(source.relative_to(root)))
    assert offenders == [], (
        "the misspelled env var reappeared outside _trust_genesis_file.py: "
        f"{offenders}. Resolve the pin through trust_genesis_path_from_env()."
    )
