"""Epoch-blocked manifest meta-guards (SUITE-RECONCILIATION.md §2.1).

The manifest is the machine-readable epoch debt. These tests keep it honest:
its nodes must exist, its count can only shrink from the ratified bootstrap,
every entry must carry a failure-form pin, and the form validator must be
able to REJECT (a guard that cannot reject is a tautology).

The cross-branch ratchet (PR manifest count vs target branch) lives in
scripts/check-epoch-debt.py and CI; the local guards here are the
collection-existence and bootstrap-cap legs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from _epoch_blocked import epoch_failure_form_matches as _epoch_failure_form_matches

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "tests" / "epoch_blocked_manifest.json"

# One-time ratified bootstrap (SUITE-RECONCILIATION.md §2.1): the manifest was
# established at exactly this size. It may only shrink afterwards.
RATIFIED_BOOTSTRAP_COUNT = 874


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


@pytest.fixture(scope="module")
def collected_manifest_file_nodes(manifest: dict) -> set[str]:
    """Collect (without running) every test file the manifest references."""
    files = sorted({e["node_id"].split("::")[0] for e in manifest["entries"]})
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *files],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 5), f"collection failed:\n{proc.stdout}\n{proc.stderr}"
    return {line.strip() for line in proc.stdout.splitlines() if "::" in line}


def test_every_manifest_node_exists_in_collection(
    manifest: dict, collected_manifest_file_nodes: set[str]
) -> None:
    """A renamed or deleted blocked test must be loud, not silently absorbed."""
    missing = [
        e["node_id"]
        for e in manifest["entries"]
        if e["node_id"] not in collected_manifest_file_nodes
    ]
    assert not missing, (
        f"{len(missing)} manifest node(s) no longer exist in collection; "
        "either restore them or move them to tests/retired_tests_ledger.json "
        f"with a disposition (SUITE-RECONCILIATION.md §2.2): {missing[:10]}"
    )


def test_manifest_count_is_consistent_and_ratcheted(manifest: dict) -> None:
    entries = manifest["entries"]
    assert manifest["baseline_count"] == len(entries), (
        "baseline_count must equal the entry count — regenerate, don't hand-edit"
    )
    assert len(entries) <= RATIFIED_BOOTSTRAP_COUNT, (
        f"manifest grew past the ratified bootstrap ({RATIFIED_BOOTSTRAP_COUNT}): "
        "new epoch-blocked tests require a ratified amendment to "
        "SUITE-RECONCILIATION.md, not a manifest edit"
    )
    assert len(entries) == len({e["node_id"] for e in entries}), "duplicate node_id"


def test_every_entry_carries_a_failure_form_pin(manifest: dict) -> None:
    for e in manifest["entries"]:
        expected = e.get("expected", {})
        if e["cause"] == "direct":
            assert expected.get("exception") and expected.get("error_code"), e["node_id"]
        else:
            assert expected.get("signature"), e["node_id"]


def test_final_060_release_refuses_nonempty_manifest(manifest: dict) -> None:
    """SUITE-RECONCILIATION.md §2.1 release-gate binding.

    regista has no separate release workflow; the release path is a version
    bump on a branch whose CI runs this suite. So the gate lives here: a
    FINAL (non-pre-release) version >= 0.6.0 with epoch debt outstanding is
    a failing test, wherever that release is being cut. Pre-releases (rc/a/
    b/dev) may carry the debt — labeled, per §2.1.
    """
    import re
    import tomllib

    version = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["version"]
    is_final = re.fullmatch(r"\d+\.\d+\.\d+", version) is not None
    major, minor = (int(p) for p in version.split(".")[:2])
    if is_final and (major, minor) >= (0, 6) and manifest["entries"]:
        pytest.fail(
            f"version {version} is a final >=0.6.0 release but the epoch-blocked "
            f"manifest still carries {len(manifest['entries'])} node(s) — "
            "P1.7 must empty the manifest before a final ships "
            "(SUITE-RECONCILIATION.md §2.1)"
        )


class _FakeError(RuntimeError):
    pass


def _fake_excinfo(exc: BaseException) -> SimpleNamespace:
    return SimpleNamespace(value=exc, type=type(exc))


def test_form_validator_accepts_recorded_direct_form() -> None:
    class RegistaError(Exception):
        pass

    entry = {
        "cause": "direct",
        "expected": {"exception": "RegistaError", "error_code": "GENESIS_REQUIRED"},
    }
    exc = RegistaError("[GENESIS_REQUIRED] append refused")
    assert _epoch_failure_form_matches(entry, _fake_excinfo(exc))


def test_form_validator_rejects_changed_direct_form() -> None:
    """The deny cases: wrong code, and wrong exception class."""
    class RegistaError(Exception):
        pass

    entry = {
        "cause": "direct",
        "expected": {"exception": "RegistaError", "error_code": "GENESIS_REQUIRED"},
    }
    wrong_code = RegistaError("[KEY_LOAD_ERROR] something else entirely")
    assert not _epoch_failure_form_matches(entry, _fake_excinfo(wrong_code))
    wrong_class = _FakeError("[GENESIS_REQUIRED] right code, wrong class")
    assert not _epoch_failure_form_matches(entry, _fake_excinfo(wrong_class))


def test_form_validator_rejects_changed_indirect_form() -> None:
    entry = {"cause": "indirect", "expected": {"signature": "assert 409 == 200"}}
    ok = AssertionError("assert 409 == 200")
    assert _epoch_failure_form_matches(entry, _fake_excinfo(ok))
    changed = AssertionError("assert 500 == 200")
    assert not _epoch_failure_form_matches(entry, _fake_excinfo(changed))
