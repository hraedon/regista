"""Epoch-blocked manifest meta-guards (SUITE-RECONCILIATION.md §2.1).

The manifest is the machine-readable epoch debt. These tests keep it honest:
its nodes must exist (collected without the slow filter — the slow tier is
inside the reconciliation, round-4 B6), its count can only shrink from the
ratified bootstrap, every entry must carry a structural failure-form pin,
and the form validator must be able to REJECT — proven both against the
pure matcher and END-TO-END through the real pytest hooks (round-4 B2).

The cross-branch ratchet (node-set comparison + sha256 bootstrap) lives in
scripts/check-epoch-debt.py and CI.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from _epoch_blocked import epoch_failure_form_matches

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "tests" / "epoch_blocked_manifest.json"

# One-time ratified bootstrap (SUITE-RECONCILIATION.md §2.1): the manifest
# was established at exactly this size (874 default tier + 7 slow tier). It
# may only shrink afterwards.
RATIFIED_BOOTSTRAP_COUNT = 881


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


@pytest.fixture(scope="module")
def collected_manifest_file_nodes(manifest: dict) -> set[str]:
    """Collect (without running, without the slow filter) every test file
    the manifest references."""
    files = sorted({e["node_id"].split("::")[0] for e in manifest["entries"]})
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "", *files],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 5), (
        f"collection failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
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


def test_every_entry_carries_a_structural_failure_form_pin(manifest: dict) -> None:
    """Round-4 B1: every entry pins the exception class; direct entries pin
    the structured refusal code, indirect entries the observed signature."""
    for e in manifest["entries"]:
        expected = e.get("expected", {})
        assert expected.get("exception"), f"{e['node_id']}: no exception class pin"
        if e["cause"] == "direct":
            assert expected.get("error_code") in ("GENESIS_REQUIRED", "V6_EPOCH_OPEN"), (
                e["node_id"]
            )
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
    # Final = X.Y.Z with an optional .postN (a post-release of a final IS
    # final, PEP 440); anything carrying a/b/rc/dev segments is a
    # pre-release and may ship with labeled debt per §2.1.
    is_final = re.fullmatch(r"\d+\.\d+\.\d+(\.post\d+)?", version) is not None
    major, minor = (int(p) for p in version.split(".")[:2])
    if is_final and (major, minor) >= (0, 6) and manifest["entries"]:
        pytest.fail(
            f"version {version} is a final >=0.6.0 release but the epoch-blocked "
            f"manifest still carries {len(manifest['entries'])} node(s) — "
            "P1.7 must empty the manifest before a final ships "
            "(SUITE-RECONCILIATION.md §2.1)"
        )


# ---------------------------------------------------------------------------
# Pure-matcher falsifiers (structural pinning, round-4 B1)
# ---------------------------------------------------------------------------


class _FakeError(RuntimeError):
    pass


def _fake_excinfo(exc: BaseException) -> SimpleNamespace:
    return SimpleNamespace(value=exc, type=type(exc))


def _fake_regista_error(code_name: str, message: str) -> BaseException:
    class RegistaError(Exception):
        pass

    exc = RegistaError(message)
    exc.code = SimpleNamespace(name=code_name)
    return exc


_DIRECT_ENTRY = {
    "cause": "direct",
    "expected": {"exception": "RegistaError", "error_code": "GENESIS_REQUIRED"},
}


def test_form_validator_accepts_recorded_direct_form() -> None:
    exc = _fake_regista_error("GENESIS_REQUIRED", "[GENESIS_REQUIRED] append refused")
    assert epoch_failure_form_matches(_DIRECT_ENTRY, _fake_excinfo(exc))


def test_form_validator_rejects_changed_direct_form() -> None:
    """Deny cases: wrong structured code (even when the MESSAGE still says
    GENESIS_REQUIRED — the text-mention bypass round-4 B1 called out), and
    wrong exception class."""
    wrong_code_right_text = _fake_regista_error(
        "KEY_LOAD_ERROR", "message mentions GENESIS_REQUIRED but the code differs"
    )
    assert not epoch_failure_form_matches(_DIRECT_ENTRY, _fake_excinfo(wrong_code_right_text))
    wrong_class = _FakeError("[GENESIS_REQUIRED] right code, wrong class")
    assert not epoch_failure_form_matches(_DIRECT_ENTRY, _fake_excinfo(wrong_class))


def test_form_validator_rejects_changed_indirect_form() -> None:
    """Deny cases: changed text, and changed exception CLASS with identical
    text (round-4 B1: class is part of the pin)."""
    entry = {
        "cause": "indirect",
        "expected": {"exception": "AssertionError", "signature": "assert 409 == 200"},
    }
    ok = AssertionError("assert 409 == 200")
    assert epoch_failure_form_matches(entry, _fake_excinfo(ok))
    changed_text = AssertionError("assert 500 == 200")
    assert not epoch_failure_form_matches(entry, _fake_excinfo(changed_text))
    changed_class = _FakeError("assert 409 == 200")
    assert not epoch_failure_form_matches(entry, _fake_excinfo(changed_class))


# ---------------------------------------------------------------------------
# End-to-end falsifier through the real hooks (round-4 B2)
# ---------------------------------------------------------------------------


def test_hooks_end_to_end_mismatch_is_red_match_is_xfail(tmp_path: Path) -> None:
    """Run a synthetic mini-project through the ACTUAL hook functions: a
    manifest node failing with the recorded form must XFAIL; one failing
    with a changed form must exit red with the validator section."""
    (tmp_path / "conftest.py").write_text(
        textwrap.dedent(
            f"""
            import sys
            sys.path.insert(0, {str(REPO_ROOT / "tests")!r})
            import pytest
            from _epoch_blocked import apply_epoch_marks, validate_xfail_report

            def pytest_collection_modifyitems(config, items):
                apply_epoch_marks(items, pytest)

            @pytest.hookimpl(wrapper=True, tryfirst=True)
            def pytest_runtest_makereport(item, call):
                rep = yield
                validate_xfail_report(item, call, rep)
                return rep
            """
        )
    )
    (tmp_path / "test_epoch_e2e.py").write_text(
        textwrap.dedent(
            """
            from types import SimpleNamespace

            class RegistaError(Exception):
                pass

            def _refusal(code):
                exc = RegistaError(f"[{code}] refused")
                exc.code = SimpleNamespace(name=code)
                return exc

            def test_matched_form():
                raise _refusal("GENESIS_REQUIRED")

            def test_changed_form():
                raise _refusal("KEY_LOAD_ERROR")
            """
        )
    )
    manifest = {
        "baseline_count": 2,
        "entries": [
            {
                "node_id": "test_epoch_e2e.py::test_matched_form",
                "cause": "direct",
                "phase": "failure",
                "expected": {"exception": "RegistaError", "error_code": "GENESIS_REQUIRED"},
            },
            {
                "node_id": "test_epoch_e2e.py::test_changed_form",
                "cause": "direct",
                "phase": "failure",
                "expected": {"exception": "RegistaError", "error_code": "GENESIS_REQUIRED"},
            },
        ],
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest))

    import os

    env = dict(os.environ, REGISTA_EPOCH_MANIFEST=str(manifest_file))
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "test_epoch_e2e.py", "-q", "-p", "no:cacheprovider"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "1 failed" in proc.stdout and "1 xfailed" in proc.stdout, proc.stdout
    assert "epoch_blocked form validator" in proc.stdout, (
        "changed-form failure did not carry the validator section:\n" + proc.stdout
    )
