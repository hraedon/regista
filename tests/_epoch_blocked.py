"""Epoch-blocked manifest machinery (SUITE-RECONCILIATION.md §2.1).

Holds the manifest loading, the strict-xfail mark application, and the
failure-form validation used by tests/conftest.py, plus the pure matcher the
meta-tests falsify. Kept out of conftest so it is importable under full
collection (the name ``conftest`` is ambiguous between the root and sidecar
conftests) and so an end-to-end falsifier can drive the same hooks from a
synthetic mini-project.

``REGISTA_EPOCH_MANIFEST`` overrides the manifest path — that exists ONLY so
the end-to-end falsifier in tests/test_epoch_blocked_meta.py can exercise
these hooks against a synthetic manifest; production sessions never set it.
"""

from __future__ import annotations

import json
import os
from typing import Any

_DEFAULT_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "epoch_blocked_manifest.json")

_cache: tuple[str, dict[str, dict[str, Any]]] | None = None

_XFAIL_REASON = (
    "epoch-blocked on the v6 ordinary-event writer (P1.7) — "
    "SUITE-RECONCILIATION.md §2.1; proven by the guard-reverted control run"
)


def manifest_path() -> str:
    return os.environ.get("REGISTA_EPOCH_MANIFEST", _DEFAULT_MANIFEST_PATH)


def load_epoch_manifest() -> dict[str, dict[str, Any]]:
    """Manifest entries keyed by exact node ID (cached per path)."""
    global _cache
    path = manifest_path()
    if _cache is None or _cache[0] != path:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        _cache = (path, {entry["node_id"]: entry for entry in manifest["entries"]})
    return _cache[1]


def epoch_failure_form_matches(entry: dict[str, Any], excinfo: Any) -> bool:
    """The failure must still be the refusal form recorded at reconciliation.

    A manifest node that starts failing DIFFERENTLY must report honest red,
    not XFAIL — strict xfail alone would conceal a changed failure mode
    (design-review round-3 B1). Pinning is structural (round-4 B1): the
    exception class must match for every entry, and direct entries compare
    the structured ``RegistaError.code`` — not text, which would accept an
    unrelated error whose *message* mentions the refusal code.
    """
    expected = entry.get("expected", {})
    value = excinfo.value
    if type(value).__name__ != expected.get("exception"):
        return False
    if entry.get("cause") == "direct":
        code = getattr(value, "code", None)
        code_name = getattr(code, "name", None) or (str(code) if code is not None else None)
        return code_name == expected.get("error_code")
    # Traceback-style rendering ("KeyError: 'work_item'"), matching how the
    # signatures were recorded from the base JUnit report; repr() fallback
    # covers signatures recorded from repr-shaped fragments.
    text = f"{type(value).__name__}: {value}"
    signature = expected.get("signature", "")
    return signature in text or signature in repr(value)


def apply_epoch_marks(items: list[Any], pytest_module: Any) -> None:
    """Mark exactly the manifest's nodes strict-xfail (+ epoch_blocked)."""
    epoch_blocked = load_epoch_manifest()
    if not epoch_blocked:
        return
    xfail_marker = pytest_module.mark.xfail(strict=True, reason=_XFAIL_REASON)
    for item in items:
        if item.nodeid in epoch_blocked:
            item.add_marker(xfail_marker)
            item.add_marker(pytest_module.mark.epoch_blocked)


def validate_xfail_report(item: Any, call: Any, rep: Any) -> None:
    """Post-report validation: refuse an XFAIL whose failure form changed."""
    entry = load_epoch_manifest().get(item.nodeid)
    if (
        entry is None
        or call.excinfo is None
        or getattr(rep, "wasxfail", None) is None
        or epoch_failure_form_matches(entry, call.excinfo)
    ):
        return
    rep.outcome = "failed"
    del rep.wasxfail
    rep.sections.append(
        (
            "epoch_blocked form validator",
            f"{item.nodeid} is epoch-blocked but no longer fails with the "
            f"recorded refusal form {entry.get('expected')!r}; it now raises "
            f"{call.excinfo.type.__name__}: {call.excinfo.value!r}. A changed "
            "failure mode must be triaged, not absorbed as XFAIL "
            "(SUITE-RECONCILIATION.md §2.1).",
        )
    )
