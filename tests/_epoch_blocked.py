"""Epoch-blocked manifest helpers (SUITE-RECONCILIATION.md §2.1).

Shared by tests/conftest.py (which applies the strict-xfail marks and the
failure-form validator) and tests/test_epoch_blocked_meta.py (which proves
the validator can reject). Kept out of conftest so it is importable under
full collection, where the name ``conftest`` is ambiguous between the root
and sidecar conftests.
"""

from __future__ import annotations

import json
import os
from typing import Any

_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "epoch_blocked_manifest.json")

_cache: dict[str, dict[str, Any]] | None = None


def load_epoch_manifest() -> dict[str, dict[str, Any]]:
    """Manifest entries keyed by exact node ID (cached)."""
    global _cache
    if _cache is None:
        with open(_MANIFEST_PATH, encoding="utf-8") as fh:
            manifest = json.load(fh)
        _cache = {entry["node_id"]: entry for entry in manifest["entries"]}
    return _cache


def epoch_failure_form_matches(entry: dict[str, Any], excinfo: Any) -> bool:
    """The failure must still be the refusal form recorded at reconciliation.

    A manifest node that starts failing DIFFERENTLY must report honest red,
    not XFAIL — strict xfail alone would conceal a changed failure mode
    (design-review round-3 blocking finding 1). Pure so the meta-tests can
    exercise the deny cases directly.
    """
    expected = entry.get("expected", {})
    value = excinfo.value
    # Traceback-style rendering: "KeyError: 'work_item'", matching how the
    # signatures were recorded from the base JUnit report. repr() would give
    # "KeyError('work_item')" and false-mismatch.
    text = f"{type(value).__name__}: {value}"
    if entry.get("cause") == "direct":
        return (
            type(value).__name__ == expected.get("exception")
            and expected.get("error_code", "") in text
        )
    signature = expected.get("signature", "")
    return signature in text or signature in repr(value)
