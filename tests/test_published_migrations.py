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
import subprocess
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
            zf.writestr(
                "r-0.0.0.dist-info/RECORD",
                "".join(
                    f"regista/migrations/{n},sha256={_record_digest(d)},{len(d)}\n"
                    for n, d in files.items()
                ),
            )
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


# --------------------------------------------------------------------------
# Round 2 review (gpt-5.6-sol B1-B4): the built artifact is the authority, and
# a withdrawal must be of a release already on record.


def _record_digest(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _write_wheel(path: Path, files: dict[str, bytes], record: bool = True) -> None:
    import zipfile

    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
        if record:
            lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
            zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")


def _write_sdist(path: Path, files: dict[str, bytes]) -> None:
    import io
    import tarfile

    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(f"r-0.0.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _dist(tmp_path: Path, wheel: dict[str, bytes], sdist: dict[str, bytes] | None = None) -> Path:
    d = tmp_path / "dist"
    d.mkdir(parents=True, exist_ok=True)
    _write_wheel(d / "r-0.0.0-py3-none-any.whl", wheel)
    if sdist is None:  # a faithful sdist mirroring the wheel's runner directory
        sdist = {
            "migrations/" + p[len("regista/migrations/") :]: b
            for p, b in wheel.items()
            if p.startswith("regista/migrations/") and p.count("/") == 2
        }
    _write_sdist(d / "r-0.0.0.tar.gz", sdist)
    return d


WHEEL_OK = {f"regista/migrations/{n}": b for n, b in BASE_FILES.items()}
SDIST_OK = {f"migrations/{n}": b for n, b in BASE_FILES.items()}


def test_check_dist_passes_a_faithful_build(tmp_path: Path) -> None:
    d = _dist(tmp_path, WHEEL_OK, SDIST_OK)
    assert guard.check_dist(_ledger(BASE_RELEASES), d, {}) == []


def test_check_dist_sees_a_backdoor_the_source_model_cannot(tmp_path: Path) -> None:
    """The four round-2 shapes (file-valued/global force-include, only-include+sources,
    symlinked dir) and sdist-only injection all end the same way: an extra file in
    the wheel. The artifact check judges that file directly."""
    d = _dist(tmp_path, {**WHEEL_OK, "regista/migrations/000_backdoor.sql": C}, SDIST_OK)
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert any("000_backdoor.sql: unpublished migration numbered 0" in p for p in problems)
    assert any("migrations differ from the wheel" in p for p in problems)


def test_check_dist_sees_a_mutated_published_migration(tmp_path: Path) -> None:
    d = _dist(tmp_path, {**WHEEL_OK, "regista/migrations/001_a.sql": A + b"-- x\n"})
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert len(problems) == 1 and "bytes changed after publication" in problems[0]


def test_check_dist_sees_a_dropped_published_migration(tmp_path: Path) -> None:
    d = _dist(tmp_path, {"regista/migrations/002_b.sql": B})
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert any("001_a.sql: published in 0.2.0 and no longer packaged" in p for p in problems)


def test_check_dist_refuses_sql_outside_the_runner_dir(tmp_path: Path) -> None:
    d = _dist(tmp_path, {**WHEEL_OK, "regista/schema.sql": C})
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert len(problems) == 1 and "outside regista/migrations/" in problems[0]


def test_check_dist_refuses_an_sdist_that_diverges_from_the_wheel(tmp_path: Path) -> None:
    d = _dist(tmp_path, WHEEL_OK, {**SDIST_OK, "migrations/000_x.sql": C})
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert len(problems) == 1 and "only-sdist=['regista/migrations/000_x.sql']" in problems[0]


def test_check_dist_with_no_wheel_refuses_to_pass(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(guard.GuardError, match="no wheel"):
        guard.check_dist(_ledger(BASE_RELEASES), tmp_path / "empty", {})


def test_monotonic_refuses_a_fabricated_withdrawal() -> None:
    base = _ledger(BASE_RELEASES)
    head = copy.deepcopy(base)
    head["releases"]["0.0.1"] = {"files": {}, "migrations": {"regista/migrations/000_x.sql": "0"}}
    head["withdrawn_from_pypi"] = ["0.0.1"]
    problems = guard.check_monotonic(base, head)
    assert any("never recorded as published" in p for p in problems)


def test_monotonic_allows_withdrawing_a_release_on_record() -> None:
    base = _ledger(BASE_RELEASES)
    head = copy.deepcopy(base)
    head["withdrawn_from_pypi"] = ["0.1.0"]
    assert guard.check_monotonic(base, head) == []


def test_a_founding_ledger_may_not_record_withdrawals() -> None:
    head = _ledger(BASE_RELEASES)
    head["withdrawn_from_pypi"] = ["0.1.0"]
    assert any("founding ledger" in p for p in guard.check_monotonic(None, head))


def test_a_missing_base_ledger_is_refused_once_the_guard_exists() -> None:
    head = _ledger(BASE_RELEASES)
    assert guard.check_monotonic(None, head, base_has_guard=False) == []
    problems = guard.check_monotonic(None, head, base_has_guard=True)
    assert any("ledger was deleted" in p for p in problems)


# --------------------------------------------------------------------------
# Round 3 review (gpt-5.6-sol B1-B4): archive member names, sdist mapping depth,
# a renamed guard, and merge parents.


@pytest.mark.parametrize(
    "name",
    [
        "r-0.0.0.dist-info/../regista/migrations/000_unexpected.sql",
        "/regista/migrations/000_unexpected.sql",
        "regista/./migrations/000_unexpected.sql",
        "regista//migrations/000_unexpected.sql",
        "regista\\migrations\\000_unexpected.sql",
    ],
)
def test_check_dist_refuses_non_canonical_member_names(tmp_path: Path, name: str) -> None:
    d = _dist(tmp_path, {**WHEEL_OK, name: C})
    with pytest.raises(guard.GuardError, match="non-canonical archive member name"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_check_dist_judges_sql_inside_dist_info_and_any_suffix_case(tmp_path: Path) -> None:
    d = _dist(
        tmp_path,
        {
            **WHEEL_OK,
            "regista/x.dist-info/000_unexpected.sql": C,
            "regista/migrations/003_unexpected.SQL": C,
        },
    )
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert any("x.dist-info/000_unexpected.sql" in p and "outside" in p for p in problems)
    assert any("003_unexpected.SQL" in p and "not a canonical" in p for p in problems)


def test_check_dist_refuses_duplicate_archive_members(tmp_path: Path) -> None:
    import warnings
    import zipfile

    d = tmp_path / "dist"
    d.mkdir()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns on the duplicate we are making
        with zipfile.ZipFile(d / "r-0.0.0-py3-none-any.whl", "w") as zf:
            for name, data in WHEEL_OK.items():
                zf.writestr(name, data)
            zf.writestr("regista/migrations/003_c.sql", b"-- first\n")
            zf.writestr("regista/migrations/003_c.sql", b"-- second\n")
    with pytest.raises(guard.GuardError, match="duplicate archive member"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_check_dist_maps_a_nested_sdist_migration_dir(tmp_path: Path) -> None:
    """src/regista/migrations/ in the sdist builds into the runner dir, whatever
    the depth: it must agree with the wheel."""
    repo = _make_repo(tmp_path / "repo", BASE_FILES)
    d = _dist(tmp_path, WHEEL_OK, {**SDIST_OK, "src/regista/migrations/000_unexpected.sql": C})
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {}, repo)
    assert any("only-sdist=['regista/migrations/000_unexpected.sql']" in p for p in problems)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "hist"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    return repo


def _commit(repo: Path, files: dict[str, str], msg: str) -> str:
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def test_a_renamed_guard_still_counts_as_present_in_the_base(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    base = _commit(repo, {"scripts/old_name.py": f"# {guard.GUARD_MARKER}\n"}, "guard, no ledger")
    ledger, has_guard = guard._ledger_at(base, repo)
    assert ledger is None and has_guard
    assert any("ledger was deleted" in p for p in guard.check_monotonic(
        ledger, _ledger(BASE_RELEASES), base_has_guard=has_guard))


def test_every_parent_of_a_merge_is_a_base(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    root = _commit(repo, {"README": "x\n"}, "root")
    _git(repo, "checkout", "-q", "-b", "side")
    side = _commit(repo, {"release/published-migrations.json": "{}\n"}, "ledger on side")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, {"other": "y\n"}, "main moves")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    parents = guard._parents("HEAD", repo)
    assert len(parents) == 2 and side in parents
    with pytest.raises(guard.GuardError, match="no parent"):
        guard._parents(root, repo)


# --------------------------------------------------------------------------
# Round 4 review (gpt-5.6-sol B1; DeepSeek round-3 NB5/NB6)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_an_sdist_link_member_is_refused(tmp_path: Path, kind: str) -> None:
    import io
    import tarfile

    d = _dist(tmp_path, WHEEL_OK, SDIST_OK)
    sdist = next(d.glob("*.tar.gz"))
    buf = io.BytesIO()
    with tarfile.open(sdist, "r:gz") as src, tarfile.open(fileobj=buf, mode="w:gz") as dst:
        for m in src.getmembers():
            fh = src.extractfile(m)
            dst.addfile(m, fh)
        link = tarfile.TarInfo("r-0.0.0/src/regista/migrations/000_unexpected.sql")
        link.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        link.linkname = (
            "../../../migrations/001_a.sql" if kind == "symlink" else "r-0.0.0/migrations/001_a.sql"
        )
        dst.addfile(link)
    sdist.write_bytes(buf.getvalue())
    with pytest.raises(guard.GuardError, match="non-regular member"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_a_wheel_sql_not_vouched_for_by_record_is_refused(tmp_path: Path) -> None:
    d = tmp_path / "dist"
    d.mkdir()
    _write_wheel(d / "r-0.0.0-py3-none-any.whl", WHEEL_OK, record=False)
    with pytest.raises(guard.GuardError, match="exactly one top-level RECORD"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_a_record_naming_other_bytes_is_refused(tmp_path: Path) -> None:
    import zipfile

    d = tmp_path / "dist"
    d.mkdir()
    with zipfile.ZipFile(d / "r-0.0.0-py3-none-any.whl", "w") as zf:
        for name, data in WHEEL_OK.items():
            zf.writestr(name, data)
        lines = [f"{n},sha256={_record_digest(C)},1" for n in WHEEL_OK]
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    with pytest.raises(guard.GuardError, match="RECORD does not vouch"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_check_dist_requires_an_sdist(tmp_path: Path) -> None:
    d = tmp_path / "dist"
    d.mkdir()
    _write_wheel(d / "r-0.0.0-py3-none-any.whl", WHEEL_OK)
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert len(problems) == 1 and "no sdist" in problems[0]


# --------------------------------------------------------------------------
# Round 5 review (gpt-5.6-sol B1-B3): Unicode folding, things that are not
# migration files inside the runner directory, and ledger ancestry.


@pytest.mark.parametrize(
    "name",
    [
        "regista/migrations/000_unexpected.\u017fql",  # long s: Windows case-folds to .sql
        "regista/migrations/051_café.sql",  # non-ASCII migration name
        "regista/migrations/000_unexpected.sql/note.txt",  # implies a directory named *.sql
        "regista/migrations/README.txt",  # anything else in the runner directory
    ],
)
def test_check_dist_refuses_anything_but_canonical_migrations_in_the_runner_dir(
    tmp_path: Path, name: str
) -> None:
    d = _dist(tmp_path, {**WHEEL_OK, name: C}, SDIST_OK)
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert any(name in p for p in problems), problems


def test_is_sql_sees_what_a_folding_filesystem_would_glob() -> None:
    assert guard._is_sql("x.\u017fql") and guard._is_sql("x.SQL") and guard._is_sql("x.sql")
    assert guard.runner_version("000_x.\u017fql") is None
    assert guard.runner_version("051_café.sql") is None


def test_ledger_history_sees_a_dropped_state_behind_a_merge_and_a_child(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    full = json.dumps(_ledger(BASE_RELEASES))
    reduced_ledger = _ledger({"0.2.0": BASE_RELEASES["0.2.0"]})
    reduced = json.dumps(reduced_ledger)
    marker = f"# {guard.GUARD_MARKER}\n"
    _commit(repo, {"g.py": marker, "release/published-migrations.json": full}, "full ledger")
    _git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, {"side": "1\n"}, "side keeps full ledger")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, {"release/published-migrations.json": reduced}, "branch drops a release")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    child = _commit(repo, {"prep": "1\n"}, "release-prep child")
    direct = guard._parents(child, repo)
    assert len(direct) == 1  # --all-parents-of would see only the merge...
    bases = guard._ledger_history(child, repo)
    problems = []
    for ref in bases:
        base, has_guard = guard._ledger_at(ref, repo)
        problems += guard.check_monotonic(base, reduced_ledger, base_has_guard=has_guard)
    assert any("dropped release 0.1.0" in p for p in problems)  # ...the history does


# --------------------------------------------------------------------------
# Round 6 review (gpt-5.6-sol R6-B1..B3, DeepSeek NB1/NB2). Candidate fixes
# for a round 7 that only the owner can authorise (round 6 was the hard stop).


def test_an_explicit_wheel_directory_named_like_a_migration_is_refused(tmp_path: Path) -> None:
    import zipfile

    d = _dist(tmp_path, WHEEL_OK, SDIST_OK)
    whl = next(d.glob("*.whl"))
    with zipfile.ZipFile(whl, "a") as zf:
        info = zipfile.ZipInfo("regista/migrations/000_probe.sql/")
        info.external_attr = 0o40755 << 16 | 0x10
        zf.writestr(info, b"")
    with pytest.raises(guard.GuardError, match="directory member"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_an_explicit_sdist_directory_in_the_runner_dir_is_refused(tmp_path: Path) -> None:
    import io
    import tarfile

    d = _dist(tmp_path, WHEEL_OK, SDIST_OK)
    sdist = next(d.glob("*.tar.gz"))
    buf = io.BytesIO()
    with tarfile.open(sdist, "r:gz") as src, tarfile.open(fileobj=buf, mode="w:gz") as dst:
        for m in src.getmembers():
            dst.addfile(m, src.extractfile(m))
        dirent = tarfile.TarInfo("r-0.0.0/migrations/000_x.sql")
        dirent.type = tarfile.DIRTYPE
        dst.addfile(dirent)
    sdist.write_bytes(buf.getvalue())
    with pytest.raises(guard.GuardError, match="directory member"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def test_a_case_folded_alias_of_the_runner_dir_is_judged(tmp_path: Path) -> None:
    d = _dist(tmp_path, {**WHEEL_OK, "REGISTA/MIGRATIONS/000_unexpected.sql/note.txt": C}, SDIST_OK)
    problems = guard.check_dist(_ledger(BASE_RELEASES), d, {})
    assert any("REGISTA/MIGRATIONS/000_unexpected.sql/note.txt" in p for p in problems)


def test_fold_colliding_members_are_refused(tmp_path: Path) -> None:
    d = _dist(
        tmp_path,
        {**WHEEL_OK, "regista/migrations/003_c.sql": C, "regista/migrations/003_C.sql": C},
    )
    with pytest.raises(guard.GuardError, match="one path on a folding filesystem"):
        guard.check_dist(_ledger(BASE_RELEASES), d, {})


def _history_problems(repo: Path, rev: str, head: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for ref in guard._ledger_history(rev, repo):
        base, has_guard = guard._ledger_at(ref, repo)
        problems += guard.check_monotonic(base, head, base_has_guard=has_guard)
    return problems


def test_a_merge_resolved_to_its_first_parent_cannot_hide_a_side_ledger(tmp_path: Path) -> None:
    """`git log -- <path>` simplification prunes the side branch here; --full-history
    must not (DeepSeek round-6 NB2)."""
    repo = _git_repo(tmp_path)
    marker = f"# {guard.GUARD_MARKER}\n"
    base_ledger = _ledger({"0.1.0": BASE_RELEASES["0.1.0"]})
    side_ledger = _ledger(BASE_RELEASES)
    ledger_path = "release/published-migrations.json"
    _commit(repo, {"g.py": marker, ledger_path: json.dumps(base_ledger)}, "b")
    _git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, {ledger_path: json.dumps(side_ledger)}, "side records 0.2.0")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, {"m": "1\n"}, "main moves")
    _git(repo, "merge", "-q", "-s", "ours", "-m", "merge resolved to main", "side")
    child = _commit(repo, {"prep": "1\n"}, "child")
    assert any("dropped release 0.2.0" in p for p in _history_problems(repo, child, base_ledger))


def test_renaming_the_ledger_path_is_refused(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    marker = f"# {guard.GUARD_MARKER}\n"
    full = json.dumps(_ledger(BASE_RELEASES))
    _commit(repo, {"g.py": marker, "old/ledger.json": full}, "guard at an old ledger path")
    reduced = _ledger({"0.2.0": BASE_RELEASES["0.2.0"]})
    (repo / "old" / "ledger.json").unlink()
    child = _commit(
        repo, {"release/published-migrations.json": json.dumps(reduced)}, "rename + drop"
    )
    child = _commit(repo, {"prep": "1\n"}, "child")
    assert any("ledger was deleted" in p for p in _history_problems(repo, child, reduced))
