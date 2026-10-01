"""Published migrations are immutable (GitHub issue #65).

The guard lives in ``scripts/check_published_migrations.py``. This file runs its
offline half against the real tree on every test run. It also proves that each
rule fires: every synthetic case below starts from a passing fixture and makes
exactly one change, and the paired passing case shows the rule is not refusing
everything.

The network half (``verify-ledger``: the committed ledger equals what PyPI
serves) runs as its own CI job, because the ordinary suite stays offline.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_published_migrations", REPO_ROOT / "scripts" / "check_published_migrations.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


# --------------------------------------------------------------------------
# The real tree


def test_the_tree_honours_the_published_ledger() -> None:
    problems = guard.check_tree(guard.load_ledger())
    assert problems == [], "\n".join(problems)


def test_the_ledger_covers_every_migration_the_tree_ships_or_is_ahead_of_it() -> None:
    """Sanity on the committed ledger itself: it is non-trivial and current-shaped."""
    ledger = guard.load_ledger()
    versions = sorted(ledger["releases"], key=guard._version_key)
    # At least the nine releases measured when the guard landed (2026-10-01).
    assert {"0.5.1", "0.5.5", "0.6.0", "0.7.2"} <= set(versions)
    latest = ledger["releases"][versions[-1]]["migrations"]
    assert len(latest) >= 50
    assert all(path.startswith("regista/migrations/") for path in latest)


def test_frozen_violations_are_exactly_the_two_measured_in_0_6_0() -> None:
    """The historical damage is pinned by name and digest and cannot grow quietly."""
    assert set(guard.FROZEN_HISTORICAL_VIOLATIONS) == {
        "regista/migrations/001_initial.sql",
        "regista/migrations/035_event_chain_head_genesis_sentinel.sql",
    }
    ledger = guard.load_ledger()
    for path, digests in guard.FROZEN_HISTORICAL_VIOLATIONS.items():
        assert len(digests) == 2
        by_release = {v: e["migrations"][path] for v, e in ledger["releases"].items()}
        old = {d for v, d in by_release.items() if guard._version_key(v) < (0, 6, 0)}
        new = {d for v, d in by_release.items() if guard._version_key(v) >= (0, 6, 0)}
        assert len(old) == 1 and len(new) == 1 and old | new == digests


# --------------------------------------------------------------------------
# Synthetic fixtures

_PYPROJECT = """\
[tool.hatch.build.targets.wheel]
packages = ["src/pkg"]

[tool.hatch.build.targets.wheel.force-include]
"migrations" = "pkg/migrations"
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_repo(tmp_path: Path, files: dict[str, bytes]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT)
    (tmp_path / "migrations").mkdir()
    for name, data in files.items():
        (tmp_path / "migrations" / name).write_bytes(data)
    return tmp_path


def _ledger(releases: dict[str, dict[str, bytes]]) -> dict[str, Any]:
    rel = {
        v: {"files": {}, "migrations": {f"pkg/migrations/{n}": _sha(b) for n, b in m.items()}}
        for v, m in releases.items()
    }
    return {
        "format": guard.LEDGER_FORMAT,
        "project": guard.PROJECT,
        "releases": rel,
        "historical_violations": guard._multiplicity(rel),
    }


A, B, C = b"-- a\n", b"-- b\n", b"-- c\n"
BASE_FILES = {"001_a.sql": A, "002_b.sql": B}
BASE_RELEASES = {"0.1.0": {"001_a.sql": A}, "0.2.0": {"001_a.sql": A, "002_b.sql": B}}


def _check(
    tmp_path: Path,
    files: dict[str, bytes],
    releases: dict[str, dict[str, bytes]],
    frozen: dict[str, frozenset[str]] | None = None,
) -> list[str]:
    repo = _make_repo(tmp_path, files)
    result: list[str] = guard.check_tree(_ledger(releases), repo, frozen or {})
    return result


def test_baseline_fixture_passes(tmp_path: Path) -> None:
    assert _check(tmp_path, BASE_FILES, BASE_RELEASES) == []


def test_an_appended_migration_passes(tmp_path: Path) -> None:
    assert _check(tmp_path, {**BASE_FILES, "003_c.sql": C}, BASE_RELEASES) == []


def test_an_edited_published_migration_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {"001_a.sql": A + b"-- edit\n", "002_b.sql": B}, BASE_RELEASES)
    assert len(problems) == 1 and "001_a.sql: bytes changed after publication" in problems[0]


def test_a_single_byte_change_is_refused(tmp_path: Path) -> None:
    """Trailing-newline and line-ending edits are mutations too: checksums are byte-exact."""
    problems = _check(tmp_path, {"001_a.sql": A.rstrip(b"\n"), "002_b.sql": B}, BASE_RELEASES)
    assert any("bytes changed after publication" in p for p in problems)


def test_a_deleted_published_migration_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {"002_b.sql": B}, BASE_RELEASES)
    assert len(problems) == 1 and "001_a.sql: published in 0.2.0" in problems[0]
    assert "may not be deleted or renamed" in problems[0]


def test_a_renamed_published_migration_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {"001_renamed.sql": A, "002_b.sql": B}, BASE_RELEASES)
    assert any("001_a.sql: published in" in p for p in problems)
    assert not any("version 1 is claimed by 2 files" in p for p in problems)
    # the renamed file is also an unpublished migration numbered at/below the head
    assert any("001_renamed.sql: unpublished migration numbered 1" in p for p in problems)


def test_an_inserted_migration_below_the_published_head_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {**BASE_FILES, "001_z_inserted.sql": C}, BASE_RELEASES)
    assert any("unpublished migration numbered 1 sorts at or before" in p for p in problems)
    assert any("version 1 is claimed by 2 files" in p for p in problems)


def test_a_gap_filling_insert_below_the_head_is_refused(tmp_path: Path) -> None:
    releases = {"0.1.0": {"001_a.sql": A, "005_b.sql": B}}
    problems = _check(tmp_path, {"001_a.sql": A, "005_b.sql": B, "003_c.sql": C}, releases)
    assert len(problems) == 1 and "003_c.sql: unpublished migration numbered 3" in problems[0]


def test_duplicate_unpublished_versions_are_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {**BASE_FILES, "003_c.sql": C, "003_d.sql": A}, BASE_RELEASES)
    assert len(problems) == 1 and "version 3 is claimed by 2 files" in problems[0]


def test_a_non_numeric_migration_name_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {**BASE_FILES, "hotfix.sql": C}, BASE_RELEASES)
    assert len(problems) == 1 and "hotfix.sql: no numeric version prefix" in problems[0]


def test_a_mutation_blessed_in_one_ledger_release_is_refused(tmp_path: Path) -> None:
    """Editing the latest release's recorded digest to match an edit creates multiplicity."""
    releases = copy.deepcopy(BASE_RELEASES)
    releases["0.2.0"]["001_a.sql"] = A + b"-- edit\n"
    problems = _check(tmp_path, {"001_a.sql": A + b"-- edit\n", "002_b.sql": B}, releases)
    assert len(problems) == 1 and "beyond the frozen historical violations" in problems[0]


def test_a_frozen_violation_passes_only_with_its_latest_bytes(tmp_path: Path) -> None:
    releases = {"0.1.0": {"001_a.sql": A}, "0.2.0": {"001_a.sql": C}}
    frozen = {"pkg/migrations/001_a.sql": frozenset({_sha(A), _sha(C)})}
    assert _check(tmp_path, {"001_a.sql": C}, releases, frozen) == []
    problems = _check(tmp_path / "old", {"001_a.sql": A}, releases, frozen)
    assert len(problems) == 1 and "bytes changed after publication" in problems[0]


def test_the_frozen_set_cannot_shrink_silently(tmp_path: Path) -> None:
    """A frozen entry the ledger no longer shows means the ledger lost a release."""
    frozen = {"pkg/migrations/001_a.sql": frozenset({_sha(A), _sha(C)})}
    problems = _check(tmp_path, BASE_FILES, BASE_RELEASES, frozen)
    assert len(problems) == 1 and "beyond the frozen historical violations" in problems[0]


def test_a_ledger_whose_recorded_violations_disagree_with_its_releases_is_refused(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    ledger = _ledger(BASE_RELEASES)
    ledger["historical_violations"] = {"pkg/migrations/001_a.sql": [_sha(A), _sha(C)]}
    problems = guard.check_tree(ledger, repo, {})
    assert len(problems) == 1 and "does not match its own releases" in problems[0]


def test_moving_the_build_mapping_away_from_published_files_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "pyproject.toml").write_text(
        '[tool.hatch.build.targets.wheel]\npackages = ["src/pkg"]\n'
    )
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    # src/pkg/migrations/... does not exist, so both published files read as deleted
    assert sum("may not be deleted or renamed" in p for p in problems) == 2


def test_an_unmappable_published_path_is_refused_not_skipped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    ledger = _ledger(BASE_RELEASES)
    ledger["releases"]["0.2.0"]["migrations"]["elsewhere/x.sql"] = _sha(C)
    problems = guard.check_tree(ledger, repo, {})
    assert any("maps to no repository path" in p for p in problems)


def test_an_empty_ledger_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    empty = {"format": guard.LEDGER_FORMAT, "project": guard.PROJECT, "releases": {}}
    path.write_text(json.dumps(empty))
    with pytest.raises(guard.GuardError, match="no releases"):
        guard.load_ledger(path)


def test_release_check_refuses_a_republish_and_a_downgrade(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    ledger = _ledger(BASE_RELEASES)
    assert guard.check_release(ledger, "0.3.0", repo, {}) == []
    assert any("already published" in p for p in guard.check_release(ledger, "0.2.0", repo, {}))
    assert any("does not sort after" in p for p in guard.check_release(ledger, "0.1.5", repo, {}))


def test_release_versions_outside_the_plain_form_are_refused_not_guessed() -> None:
    with pytest.raises(guard.GuardError, match="not a plain"):
        guard._version_key("0.8.0rc1")
