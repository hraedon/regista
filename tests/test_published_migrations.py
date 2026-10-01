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
packages = ["src/regista"]

[tool.hatch.build.targets.wheel.force-include]
"migrations" = "regista/migrations"
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_repo(tmp_path: Path, files: dict[str, bytes]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT)
    (tmp_path / "migrations").mkdir(exist_ok=True)
    for name, data in files.items():
        (tmp_path / "migrations" / name).write_bytes(data)
    return tmp_path


def _ledger(releases: dict[str, dict[str, bytes]]) -> dict[str, Any]:
    rel = {
        v: {"files": {}, "migrations": {f"regista/migrations/{n}": _sha(b) for n, b in m.items()}}
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
    assert len(problems) == 1
    assert "hotfix.sql (ships as regista/migrations/hotfix.sql): not a canonical" in problems[0]


def test_a_mutation_blessed_in_one_ledger_release_is_refused(tmp_path: Path) -> None:
    """Editing the latest release's recorded digest to match an edit creates multiplicity."""
    releases = copy.deepcopy(BASE_RELEASES)
    releases["0.2.0"]["001_a.sql"] = A + b"-- edit\n"
    problems = _check(tmp_path, {"001_a.sql": A + b"-- edit\n", "002_b.sql": B}, releases)
    assert len(problems) == 1 and "beyond the frozen historical violations" in problems[0]


def test_a_frozen_violation_passes_only_with_its_latest_bytes(tmp_path: Path) -> None:
    releases = {"0.1.0": {"001_a.sql": A}, "0.2.0": {"001_a.sql": C}}
    frozen = {"regista/migrations/001_a.sql": frozenset({_sha(A), _sha(C)})}
    assert _check(tmp_path, {"001_a.sql": C}, releases, frozen) == []
    problems = _check(tmp_path / "old", {"001_a.sql": A}, releases, frozen)
    assert len(problems) == 1 and "bytes changed after publication" in problems[0]


def test_the_frozen_set_cannot_shrink_silently(tmp_path: Path) -> None:
    """A frozen entry the ledger no longer shows means the ledger lost a release."""
    frozen = {"regista/migrations/001_a.sql": frozenset({_sha(A), _sha(C)})}
    problems = _check(tmp_path, BASE_FILES, BASE_RELEASES, frozen)
    assert len(problems) == 1 and "beyond the frozen historical violations" in problems[0]


def test_a_ledger_whose_recorded_violations_disagree_with_its_releases_is_refused(
    tmp_path: Path,
) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    ledger = _ledger(BASE_RELEASES)
    ledger["historical_violations"] = {"regista/migrations/001_a.sql": [_sha(A), _sha(C)]}
    problems = guard.check_tree(ledger, repo, {})
    assert len(problems) == 1 and "does not match its own releases" in problems[0]


def test_moving_the_build_mapping_away_from_published_files_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "pyproject.toml").write_text(
        '[tool.hatch.build.targets.wheel]\npackages = ["src/regista"]\n'
    )
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    # src/regista/migrations/... does not exist, so both published files read as deleted
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


# --------------------------------------------------------------------------
# Round 1 review (DeepSeek v4.1 B1/B2/N1/N2): every SHIPPED .sql, not only the
# directories published paths map to, and the runner's own naming rule.


def test_runner_directory_constant_matches_the_runner() -> None:
    from regista import _migrations

    assert _migrations._migrations_dir().name == "migrations"
    assert guard.RUNNER_WHEEL_DIR == "regista/migrations/"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("001_a.sql", 1),
        ("050.sql", 50),  # the runner applies a bare number; the old regex skipped it
        ("007_x_y.z.sql", 7),
        ("hotfix.sql", None),
        ("001_a.SQL", None),  # glob("*.sql") is case-sensitive
        ("²_a.sql", None),  # superscript two: isdigit() but not a version
        ("_001.sql", None),
    ],
)
def test_runner_version_mirrors_discover_migrations(name: str, expected: int | None) -> None:
    assert guard.runner_version(name) == expected


def test_a_package_migrations_dir_is_inspected(tmp_path: Path) -> None:
    """src/regista/migrations/ ships to the same wheel dir and is PREFERRED by the runner."""
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "src" / "regista" / "migrations").mkdir(parents=True)
    (repo / "src" / "regista" / "migrations" / "001_a.sql").write_bytes(A + b"-- evil\n")
    (repo / "src" / "regista" / "migrations" / "003_backdoor.sql").write_bytes(C)
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    assert any("shipped from 2 source files" in p for p in problems)
    assert any("assembled from 2 source directories" in p for p in problems)


def test_a_package_migrations_dir_with_unique_low_names_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "src" / "regista" / "migrations").mkdir(parents=True)
    (repo / "src" / "regista" / "migrations" / "001_z.sql").write_bytes(C)
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    assert any("assembled from 2 source directories" in p for p in problems)
    assert any("unpublished migration numbered 1" in p for p in problems)


def test_a_second_force_include_shipping_sql_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "pyproject.toml").write_text(
        _PYPROJECT + '"extra" = "regista/evil"\n'
    )
    (repo / "extra").mkdir()
    (repo / "extra" / "003_backdoor.sql").write_bytes(C)
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    assert len(problems) == 1 and "a packaged .sql outside regista/migrations/" in problems[0]


def test_a_package_sql_outside_the_runner_dir_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "src" / "regista").mkdir(parents=True)
    (repo / "src" / "regista" / "schema.sql").write_bytes(C)
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    assert len(problems) == 1 and "outside regista/migrations/" in problems[0]


def test_a_subdirectory_of_the_runner_dir_is_refused(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, BASE_FILES)
    (repo / "migrations" / "sub").mkdir()
    (repo / "migrations" / "sub" / "003_c.sql").write_bytes(C)
    problems = guard.check_tree(_ledger(BASE_RELEASES), repo, {})
    assert len(problems) == 1 and "outside regista/migrations/" in problems[0]


def test_an_upper_case_suffix_is_refused(tmp_path: Path) -> None:
    problems = _check(tmp_path, {**BASE_FILES, "003_c.SQL": C}, BASE_RELEASES)
    assert len(problems) == 1 and "not a canonical migration name" in problems[0]


def test_a_bare_numbered_name_is_shape_checked(tmp_path: Path) -> None:
    """050.sql is applied by the runner, so it must obey the append-only rule."""
    problems = _check(tmp_path, {**BASE_FILES, "001.sql": C}, BASE_RELEASES)
    assert any("version 1 is claimed by 2 files" in p for p in problems)
    assert _check(tmp_path / "ok", {**BASE_FILES, "003.sql": C}, BASE_RELEASES) == []


def test_non_ascii_digit_versions_raise_guard_error_not_value_error() -> None:
    with pytest.raises(guard.GuardError):
        guard._version_key("².5.0")


# --------------------------------------------------------------------------
# Round 1 review (gpt-5.6-sol B2): published history only grows, even if PyPI
# deletes a release.


def _fake_index(monkeypatch: pytest.MonkeyPatch, releases: dict[str, dict[str, bytes]]) -> None:
    import io
    import zipfile

    blobs: dict[str, bytes] = {}
    index: dict[str, Any] = {"releases": {}}
    for version, files in releases.items():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in files.items():
                zf.writestr(f"regista/migrations/{name}", data)
        blob = buf.getvalue()
        url = f"https://example.invalid/{version}.whl"
        blobs[url] = blob
        index["releases"][version] = [
            {
                "filename": f"r-{version}-py3-none-any.whl",
                "url": url,
                "packagetype": "bdist_wheel",
                "digests": {"sha256": _sha(blob)},
            }
        ]
    blobs[guard.PYPI_JSON] = json.dumps(index).encode()
    monkeypatch.setattr(guard, "_fetch", lambda url, attempts=4: blobs[url])


def _mapping(tmp_path: Path) -> list[tuple[str, str]]:
    repo = _make_repo(tmp_path / "mapping", {})
    result: list[tuple[str, str]] = guard._path_mapping(repo / "pyproject.toml")
    return result


def test_build_retains_a_release_pypi_no_longer_serves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_index(monkeypatch, BASE_RELEASES)
    prior = guard.build_ledger(_mapping(tmp_path))
    assert prior["withdrawn_from_pypi"] == []
    _fake_index(monkeypatch, {"0.2.0": BASE_RELEASES["0.2.0"]})  # 0.1.0 deleted on PyPI
    rebuilt = guard.build_ledger(_mapping(tmp_path), prior)
    assert rebuilt["withdrawn_from_pypi"] == ["0.1.0"]
    assert rebuilt["releases"]["0.1.0"] == prior["releases"]["0.1.0"]
    without_prior = guard.build_ledger(_mapping(tmp_path))
    assert "0.1.0" not in without_prior["releases"]  # hence verify passes `committed`


def test_monotonic_refuses_a_dropped_or_rewritten_release() -> None:
    base = _ledger(BASE_RELEASES)
    assert guard.check_monotonic(base, copy.deepcopy(base)) == []
    assert guard.check_monotonic(None, base) == []
    dropped = copy.deepcopy(base)
    del dropped["releases"]["0.1.0"]
    assert any("dropped release 0.1.0" in p for p in guard.check_monotonic(base, dropped))
    rewritten = copy.deepcopy(base)
    rewritten["releases"]["0.1.0"]["migrations"]["regista/migrations/001_a.sql"] = _sha(C)
    assert any("rewrote release 0.1.0" in p for p in guard.check_monotonic(base, rewritten))
    grown = _ledger({**BASE_RELEASES, "0.3.0": {**BASE_FILES, "003_c.sql": C}})
    assert guard.check_monotonic(base, grown) == []


def test_monotonic_refuses_forgetting_a_withdrawal() -> None:
    base = _ledger(BASE_RELEASES)
    base["withdrawn_from_pypi"] = ["0.1.0"]
    head = copy.deepcopy(base)
    head["withdrawn_from_pypi"] = []
    assert any("un-recorded withdrawn" in p for p in guard.check_monotonic(base, head))


def test_two_disagreeing_sdists_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import tarfile

    def sdist(data: bytes) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("r-0.1.0/migrations/001_a.sql")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    _fake_index(monkeypatch, {"0.1.0": {"001_a.sql": A}})
    fetch = guard._fetch
    index = json.loads(fetch(guard.PYPI_JSON))
    extra = {"a.tar.gz": sdist(C), "z.tar.gz": sdist(A)}
    for name, blob in extra.items():
        index["releases"]["0.1.0"].append(
            {"filename": name, "url": f"https://example.invalid/{name}",
             "packagetype": "sdist", "digests": {"sha256": _sha(blob)}}
        )
    table = {guard.PYPI_JSON: json.dumps(index).encode(),
             **{f"https://example.invalid/{n}": b for n, b in extra.items()},
             "https://example.invalid/0.1.0.whl": fetch("https://example.invalid/0.1.0.whl")}
    monkeypatch.setattr(guard, "_fetch", lambda url, attempts=4: table[url])
    with pytest.raises(guard.GuardError, match="two sdists ship different migrations"):
        guard.build_ledger(_mapping(tmp_path))
