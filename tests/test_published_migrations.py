"""Published migrations are immutable (GitHub #65): the allowlist guard.

Every bypass found across six review rounds of the previous design is kept here
as a vector that must FAIL (``BYPASSES``). The history-judgement vectors became
``verify-ledger`` vectors when that judgement was dropped from the guard's claim.
A property fuzz checks, using an independent model of how installers normalise
names and relocate wheel ``.data/{purelib,platlib}`` members, that no member name
the guard accepts can land in the migrations directory or be a .sql file.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import unicodedata
import warnings
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

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
A, B, C = b"-- a\n", b"-- b\n", b"-- c\n"
WHEEL_METADATA = (
    b"Wheel-Version: 1.0\n"
    b"Generator: regista-test\n"
    b"Root-Is-Purelib: true\n"
    b"Tag: py3-none-any\n"
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# The real tree, the real ledger


def test_the_tree_honours_the_ledger() -> None:
    assert guard.check_tree(guard.load_ledger()) == []


def test_the_ledger_is_well_formed_and_records_the_measured_releases() -> None:
    ledger = guard.load_ledger()
    assert guard.check_ledger(ledger) == []
    assert {"0.5.1", "0.6.0", "0.7.2"} <= set(ledger["releases"])
    assert len(guard.expected_migrations(ledger)) >= 50


def test_frozen_violations_are_exactly_the_two_measured_in_0_6_0() -> None:
    assert set(guard.FROZEN_HISTORICAL_VIOLATIONS) == {
        "001_initial.sql",
        "035_event_chain_head_genesis_sentinel.sql",
    }
    ledger = guard.load_ledger()
    for name, digests in guard.FROZEN_HISTORICAL_VIOLATIONS.items():
        old = {e["migrations"][name] for v, e in ledger["releases"].items() if v < "0.6.0"}
        new = {e["migrations"][name] for v, e in ledger["releases"].items() if v >= "0.6.0"}
        assert len(old) == len(new) == 1 and old | new == digests


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build real artifacts")
def test_a_real_build_passes_check_dist_including_the_sdist_rebuild(tmp_path: Path) -> None:
    subprocess.run(
        ["uv", "build", "-q", "--out-dir", str(tmp_path), str(REPO_ROOT)], check=True
    )
    assert guard.check_dist(guard.load_ledger(), tmp_path) == []


# --------------------------------------------------------------------------
# Fixtures

BASE = {"001_a.sql": A, "002_b.sql": B}
PYPROJECT = (REPO_ROOT / "pyproject.toml").read_bytes()
RELEASES = {"0.1.0": {"001_a.sql": A}, "0.2.0": BASE}


def _ledger(releases: dict[str, dict[str, bytes]] = RELEASES,
            unreleased: dict[str, bytes] | None = None) -> dict[str, Any]:
    rel = {
        v: {"files": {}, "migrations": {n: _sha(b) for n, b in m.items()}}
        for v, m in releases.items()
    }
    return {
        "format": guard.LEDGER_FORMAT,
        "project": guard.PROJECT,
        "source": "test",
        "releases": rel,
        "historical_violations": guard._multiplicity(rel),
        "unreleased": {n: _sha(b) for n, b in (unreleased or {}).items()},
    }


def _record_digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _wheel_bytes(files: dict[str, bytes], *, record: bool = True,
                 wheel_metadata: bytes | None = WHEEL_METADATA,
                 extra: list[tuple[zipfile.ZipInfo, bytes]] = ()) -> bytes:  # type: ignore[assignment]
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in files.items():
                # Assigning after construction keeps a NUL that ZipInfo() would
                # truncate, so the archive stores exactly ``name``.
                info = zipfile.ZipInfo("placeholder")
                info.filename = name
                info.external_attr = 0o100644 << 16
                zf.writestr(info, data)
            for info, data in extra:
                zf.writestr(info, data)
            zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
            if wheel_metadata is not None:
                zf.writestr("r-0.0.0.dist-info/WHEEL", wheel_metadata)
            if record:
                lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
                zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    return buf.getvalue()


def _sdist_bytes(files: dict[str, bytes], extra: list[tarfile.TarInfo] = ()) -> bytes:  # type: ignore[assignment]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        base = {"PKG-INFO": b"Name: r\n", "pyproject.toml": PYPROJECT}
        for name, data in {**base, **files}.items():
            info = tarfile.TarInfo(f"r-0.0.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for info in extra:
            tf.addfile(info)
    return buf.getvalue()


def _wheel_files(migs: dict[str, bytes]) -> dict[str, bytes]:
    return {**{f"regista/migrations/{n}": b for n, b in migs.items()}, "regista/__init__.py": b""}


def _sdist_files(migs: dict[str, bytes]) -> dict[str, bytes]:
    return {**{f"migrations/{n}": b for n, b in migs.items()}, "src/regista/__init__.py": b""}


def _dist(tmp_path: Path, wheel: bytes | None = None, sdist: bytes | None = None) -> Path:
    d = tmp_path / "dist"
    d.mkdir(parents=True, exist_ok=True)
    (d / "r-0.0.0-py3-none-any.whl").write_bytes(
        wheel if wheel is not None else _wheel_bytes(_wheel_files(BASE))
    )
    (d / "r-0.0.0.tar.gz").write_bytes(
        sdist if sdist is not None else _sdist_bytes(_sdist_files(BASE))
    )
    return d


def _verdict(d: Path, ledger: dict[str, Any] | None = None) -> str:
    """'pass', or the first problem / error text."""
    try:
        problems = guard.check_dist(ledger or _ledger(), d, {}, rebuild_sdists=False)
    except guard.GuardError as exc:
        return f"error: {exc}"
    return problems[0] if problems else "pass"


def test_a_faithful_dist_passes(tmp_path: Path) -> None:
    assert _verdict(_dist(tmp_path)) == "pass"


def test_a_declared_unreleased_migration_passes(tmp_path: Path) -> None:
    migs = {**BASE, "003_c.sql": C}
    d = _dist(tmp_path, _wheel_bytes(_wheel_files(migs)), _sdist_bytes(_sdist_files(migs)))
    assert _verdict(d, _ledger(unreleased={"003_c.sql": C})) == "pass"


# --------------------------------------------------------------------------
# Every prior bypass: must FAIL. (round found, reviewer, shape)


def _wheel_with(name: str, data: bytes = C) -> bytes:
    return _wheel_bytes({**_wheel_files(BASE), name: data})


def _sdist_with(name: str, data: bytes = C) -> bytes:
    return _sdist_bytes({**_sdist_files(BASE), name: data})


def _dir_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.external_attr = (0o40755 << 16) | 0x10
    return info


def _symlink_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.external_attr = 0o120777 << 16
    return info


def _tar_member(name: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(f"r-0.0.0/{name}")
    info.type = kind
    info.linkname = linkname
    return info


BYPASSES: dict[str, tuple[bytes | None, bytes | None]] = {
    # r0: the rule itself
    "edited published migration": (
        _wheel_bytes(_wheel_files({**BASE, "001_a.sql": A + b"x"})),
        _sdist_bytes(_sdist_files({**BASE, "001_a.sql": A + b"x"})),
    ),
    "dropped published migration": (
        _wheel_bytes(_wheel_files({"002_b.sql": B})), _sdist_bytes(_sdist_files({"002_b.sql": B}))
    ),
    "inserted below head (r1 Sol/DS)": (_wheel_with("regista/migrations/000_unexpected.sql"),
                                        _sdist_with("migrations/000_unexpected.sql")),
    "undeclared append above head": (_wheel_with("regista/migrations/003_c.sql"),
                                     _sdist_with("migrations/003_c.sql")),
    "duplicate version number": (_wheel_with("regista/migrations/002_z.sql"), None),
    "bare-number name 050.sql (r1 DS)": (_wheel_with("regista/migrations/050.sql"), None),
    "non-numeric name hotfix.sql": (_wheel_with("regista/migrations/hotfix.sql"), None),
    "sql outside migrations in wheel (r1)": (_wheel_with("regista/schema.sql"), None),
    "sql under a second package (r1 DS B2)": (_wheel_with("regista/evil/003_c.sql"), None),
    "subdirectory of migrations": (_wheel_with("regista/migrations/sub/003_c.sql"), None),
    # r2: sdist-only shapes
    "sdist has an extra migration (r2 Sol B2)": (None, _sdist_with("migrations/000_x.sql")),
    # r3
    "dist-info traversal name (r3 Sol B1)": (
        _wheel_with("r-0.0.0.dist-info/../regista/migrations/000_x.sql"), None),
    "sql inside a dist-info dir (r3 Sol B1)": (_wheel_with("regista/x.dist-info/000_x.sql"), None),
    "upper-case .SQL suffix (r3 Sol B1)": (_wheel_with("regista/migrations/003_c.SQL"), None),
    "nested sdist src/regista/migrations (r3 Sol B2)": (
        None, _sdist_with("src/regista/migrations/000_x.sql")),
    "leading slash": (_wheel_with("/regista/migrations/000_x.sql"), None),
    "dot segment": (_wheel_with("regista/./migrations/000_x.sql"), None),
    "empty segment": (_wheel_with("regista//migrations/000_x.sql"), None),
    "backslash": (_wheel_with("regista\\migrations\\000_x.sql"), None),
    "NUL in name": (_wheel_with("regista/migrations/000_x\x00.sql"), None),
    "NUL hides a .sql suffix (fuzz find)": (_wheel_with("regista/a\x00.sql"), None),
    "control char in name": (_wheel_with("regista/migrations/000_x\n.sql"), None),
    # r4
    "tar symlink member (r4 Sol B1)": (None, _sdist_bytes(
        _sdist_files(BASE),
        [_tar_member("src/regista/migrations/000_x.sql", tarfile.SYMTYPE, "../../001_a.sql")])),
    "tar hardlink member (r4 Sol B1)": (None, _sdist_bytes(
        _sdist_files(BASE),
        [_tar_member("migrations/000_x.sql", tarfile.LNKTYPE, "r-0.0.0/migrations/001_a.sql")])),
    "tar symlink far from migrations": (None, _sdist_bytes(
        _sdist_files(BASE), [_tar_member("docs/link", tarfile.SYMTYPE, "../migrations")])),
    "tar device member": (None, _sdist_bytes(
        _sdist_files(BASE), [_tar_member("dev0", tarfile.CHRTYPE)])),
    "tar fifo member": (
        None, _sdist_bytes(_sdist_files(BASE), [_tar_member("fifo0", tarfile.FIFOTYPE)])),
    "missing RECORD (r3 DS NB5)": (_wheel_bytes(_wheel_files(BASE), record=False), None),
    # r5
    "long-s suffix .\u017fql (r5 Sol B1)": (_wheel_with("regista/migrations/000_x.\u017fql"), None),
    "non-ASCII migration name": (_wheel_with("regista/migrations/051_caf\u00e9.sql"), None),
    "NFD name": (_wheel_with(unicodedata.normalize("NFD", "regista/caf\u00e9.txt")), None),
    "implied directory named *.sql (r5 Sol B2)": (
        _wheel_with("regista/migrations/000_x.sql/note.txt"), None),
    "stray file in migrations": (_wheel_with("regista/migrations/README.txt"), None),
    # r6
    "explicit wheel directory entry (r6 Sol/DS)": (_wheel_bytes(
        _wheel_files(BASE), extra=[(_dir_info("regista/migrations/000_x.sql/"), b"")]), None),
    "any wheel directory entry": (_wheel_bytes(
        _wheel_files(BASE), extra=[(_dir_info("regista/"), b"")]), None),
    "explicit sdist directory entry (r6 DS)": (None, _sdist_bytes(
        _sdist_files(BASE), [_tar_member("migrations/000_x.sql", tarfile.DIRTYPE)])),
    "folded runner alias REGISTA/MIGRATIONS (r6 Sol B2)": (
        _wheel_with("REGISTA/MIGRATIONS/000_x.sql/note.txt"), None),
    "fold collision 002_b vs 002_B": (_wheel_with("regista/migrations/002_B.sql"), None),
    "zip symlink with a benign name": (_wheel_bytes(
        _wheel_files(BASE), extra=[(_symlink_info("regista/data.py"), b"migrations")]), None),
    "zip symlink member (r5 Sol NB)": (_wheel_bytes(
        _wheel_files(BASE), extra=[(_symlink_info("regista/migrations/000_x.sql"), b"001_a.sql")]),
        None),
}


@pytest.mark.parametrize("shape", sorted(BYPASSES))
def test_every_prior_bypass_still_fails(tmp_path: Path, shape: str) -> None:
    wheel, sdist = BYPASSES[shape]
    assert _verdict(_dist(tmp_path, wheel, sdist)) != "pass", shape


def test_a_duplicate_zip_member_fails(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w") as zf:
            for n, d in _wheel_files(BASE).items():
                zf.writestr(n, d)
            zf.writestr("regista/migrations/001_a.sql", b"-- second copy\n")
    assert "collide" in _verdict(_dist(tmp_path, buf.getvalue()))


def test_a_record_naming_other_bytes_fails(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in _wheel_files(BASE).items():
            zf.writestr(n, d)
        zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
        zf.writestr("r-0.0.0.dist-info/WHEEL", WHEEL_METADATA)
        zf.writestr("r-0.0.0.dist-info/RECORD",
                    "".join(f"{n},sha256={_record_digest(C)},1\n" for n in _wheel_files(BASE)))
    assert "RECORD does not vouch" in _verdict(_dist(tmp_path, buf.getvalue()))


def test_two_wheels_that_disagree_fail(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (d / "r-0.0.0-cp314-cp314-linux_x86_64.whl").write_bytes(
        _wheel_with("regista/migrations/003_c.sql"))
    assert _verdict(d) != "pass"


@pytest.mark.parametrize("missing", ["whl", "tar.gz"])
def test_a_dist_without_both_artifact_kinds_fails(tmp_path: Path, missing: str) -> None:
    d = _dist(tmp_path)
    next(d.glob(f"*.{missing}")).unlink()
    assert _verdict(d).startswith("error:")


def test_a_stray_file_beside_the_artifacts_fails(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (d / "notes.txt").write_text("x")
    assert _verdict(d).startswith("error:")
    (d / "notes.txt").unlink()
    (d / ".gitignore").write_bytes(b"*")  # what `uv build` writes is tolerated
    assert _verdict(d) == "pass"


def test_unreleased_bytes_that_differ_fail(tmp_path: Path) -> None:
    migs = {**BASE, "003_c.sql": C}
    d = _dist(tmp_path, _wheel_bytes(_wheel_files(migs)), _sdist_bytes(_sdist_files(migs)))
    assert "bytes differ" in _verdict(d, _ledger(unreleased={"003_c.sql": A}))


def test_a_declared_unreleased_migration_that_is_missing_fails(tmp_path: Path) -> None:
    assert "missing migration 003_c.sql" in _verdict(
        _dist(tmp_path), _ledger(unreleased={"003_c.sql": C}))


# --------------------------------------------------------------------------
# Ledger rules (previously the history vectors)


@pytest.mark.parametrize(
    ("unreleased", "fragment"),
    [
        ({"001_a.sql": A}, "already published"),
        ({"002_z.sql": C}, "does not sort after"),
        ({"003_C.sql": C}, "bad name"),
        ({"003_c.sql": C, "003_d.sql": A}, "share a version number"),
    ],
)
def test_bad_unreleased_declarations_fail(unreleased: dict[str, bytes], fragment: str) -> None:
    assert any(fragment in p for p in guard.check_ledger(_ledger(unreleased=unreleased), {}))


def test_multiplicity_beyond_the_frozen_set_fails() -> None:
    releases = {"0.1.0": {"001_a.sql": A}, "0.2.0": {"001_a.sql": C}}
    assert any("beyond the frozen pair" in p for p in guard.check_ledger(_ledger(releases), {}))
    frozen = {"001_a.sql": frozenset({_sha(A), _sha(C)})}
    assert guard.check_ledger(_ledger(releases), frozen) == []


def test_the_frozen_set_cannot_shrink_silently() -> None:
    frozen = {"001_a.sql": frozenset({_sha(A), _sha(C)})}
    assert guard.check_ledger(_ledger(), frozen) != []


def test_a_release_that_drops_a_published_migration_fails() -> None:
    releases = {"0.1.0": BASE, "0.2.0": {"002_b.sql": B}}
    assert any("dropped" in p for p in guard.check_ledger(_ledger(releases), {}))


def _fresh(releases: dict[str, dict[str, bytes]]) -> dict[str, Any]:
    out: dict[str, Any] = _ledger(releases)["releases"]
    return out


def test_verify_ledger_passes_when_equal() -> None:
    assert guard.verify_ledger(_ledger(), _fresh(RELEASES)) == []


def test_verify_ledger_fails_on_a_fabricated_release() -> None:
    """Was: a fabricated withdrawn release self-authenticated (r2 Sol B3)."""
    committed = _ledger({**RELEASES, "0.0.1": {"000_x.sql": C}})
    assert any("no longer on PyPI" in p for p in guard.verify_ledger(committed, _fresh(RELEASES)))


def test_verify_ledger_fails_on_a_dropped_release() -> None:
    committed = _ledger({"0.2.0": BASE})
    assert any("not in the ledger" in p for p in guard.verify_ledger(committed, _fresh(RELEASES)))


def test_verify_ledger_fails_loudly_on_a_release_deleted_from_pypi() -> None:
    """The guard makes no claim about deleted releases; it must not pass silently."""
    problems = guard.verify_ledger(_ledger(), _fresh({"0.2.0": BASE}))
    assert any("no longer on PyPI" in p and "human" in p for p in problems)


def test_verify_ledger_fails_on_a_rewritten_release() -> None:
    committed = _ledger()
    committed["releases"]["0.1.0"]["migrations"]["001_a.sql"] = _sha(C)
    assert any("differs" in p for p in guard.verify_ledger(committed, _fresh(RELEASES)))


# --------------------------------------------------------------------------
# Tree


def _tree(tmp_path: Path, files: dict[str, bytes]) -> Path:
    (tmp_path / "migrations").mkdir(parents=True)
    for n, d in files.items():
        (tmp_path / "migrations" / n).write_bytes(d)
    return tmp_path


@pytest.mark.parametrize(
    "files",
    [
        {**BASE, "001_a.sql": A + b"x"},
        {"002_b.sql": B},
        {"001_renamed.sql": A, "002_b.sql": B},
        {**BASE, "000_x.sql": C},
        {**BASE, "hotfix.sql": C},
        {**BASE, "003_C.sql": C},
    ],
)
def test_bad_trees_fail(tmp_path: Path, files: dict[str, bytes]) -> None:
    assert guard.check_tree(_ledger(), _tree(tmp_path, files), {}) != []


def test_a_good_tree_passes_and_package_migrations_dir_fails(tmp_path: Path) -> None:
    repo = _tree(tmp_path, BASE)
    assert guard.check_tree(_ledger(), repo, {}) == []
    (repo / "src" / "regista" / "migrations").mkdir(parents=True)
    assert guard.check_tree(_ledger(), repo, {}) != []


def test_a_symlink_or_directory_in_migrations_fails(tmp_path: Path) -> None:
    repo = _tree(tmp_path, BASE)
    (repo / "migrations" / "003_c.sql").symlink_to("001_a.sql")
    assert guard.check_tree(_ledger(unreleased={"003_c.sql": A}), repo, {}) != []
    (repo / "migrations" / "003_c.sql").unlink()
    (repo / "migrations" / "003_c.sql").mkdir()
    assert guard.check_tree(_ledger(unreleased={"003_c.sql": A}), repo, {}) != []


def test_check_release_refuses_a_republish_and_a_downgrade(tmp_path: Path) -> None:
    repo = _tree(tmp_path, BASE)
    assert guard.check_release(_ledger(), "0.3.0", repo, {}) == []
    assert guard.check_release(_ledger(), "0.2.0", repo, {}) != []
    assert guard.check_release(_ledger(), "0.1.5", repo, {}) != []
    with pytest.raises(guard.GuardError):
        guard._version_key("0.8.0rc1")


# --------------------------------------------------------------------------
# Property: nothing the guard accepts can reach the migrations dir or be SQL,
# under an independent model of installer path normalisation.

NASTY = st.sampled_from(
    [*"abcAZ09_.-+/\\", "..", "\x00", "\n", "\u017f", "\u212a", "\u00e9", "e\u0301",
                              "regista/", "migrations/", "MIGRATIONS", ".sql", ".SQL", "%2e",
                              ".dist-info/", "\uff0e", "\u2215"]
)


def _installer_view(name: str) -> str:
    n = unicodedata.normalize("NFKC", name.replace("\\", "/")).casefold()
    parts = n.split("/")
    if len(parts) >= 3 and parts[0].endswith(".data") and parts[1] in {"purelib", "platlib"}:
        n = "/".join(parts[2:])
    return posixpath.normpath("/" + n).lstrip("/")


@pytest.mark.parametrize("scheme", ["purelib", "platlib"])
def test_installer_view_models_wheel_data_relocation(scheme: str) -> None:
    name = f"r-0.0.0.data/{scheme}/regista/migrations/000_x.sql/note.txt"
    assert _installer_view(name) == "regista/migrations/000_x.sql/note.txt"


ACCEPTED_FUZZ_MEMBER = st.from_regex(
    r"regista/pkg_[a-z][a-z0-9_]{0,8}\.(py|txt|json)",
    fullmatch=True,
)
CANONICAL_FUZZ_MIGRATION = st.from_regex(
    r"regista/migrations/[3-9][0-9]{2}_[a-z][a-z0-9_]{0,8}\.sql", fullmatch=True
)
RELOCATED_FUZZ_MEMBER = st.builds(
    lambda scheme, leaf: f"r-0.0.0.data/{scheme}/regista/migrations/{leaf}",
    st.sampled_from(["purelib", "platlib"]),
    st.sampled_from(["000_x.sql", "000_x.sql/note.txt", "probe.pth"]),
)
FUZZ_CASE = st.one_of(
    st.lists(NASTY, min_size=1, max_size=8).map(lambda parts: ("".join(parts), False)),
    ACCEPTED_FUZZ_MEMBER.map(lambda name: (name, True)),
    CANONICAL_FUZZ_MIGRATION.map(lambda name: (name, True)),
    RELOCATED_FUZZ_MEMBER.map(lambda name: (name, False)),
)


@settings(max_examples=2000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(case=FUZZ_CASE)
def test_fuzz_no_accepted_name_reaches_migrations_or_is_sql(case: tuple[str, bool]) -> None:
    name, must_accept = case
    blob = _wheel_with(name)
    try:
        migs = guard.read_wheel(blob, "fuzz", wheel_filename="r-0.0.0-py3-none-any.whl")
    except (guard.GuardError, ValueError):
        assert not must_accept, name
        return
    view = _installer_view(name)
    if name.startswith("regista/migrations/") and name[len("regista/migrations/"):] in migs:
        assert guard.MIGRATION_NAME.fullmatch(name[len("regista/migrations/"):])
        return
    assert not view.startswith("regista/migrations/"), name
    assert not view.endswith(".sql"), name
    assert not view.startswith("src/regista/migrations"), name


def test_negative_fuzz_acceptance_branches_are_reachable() -> None:
    """Pin both non-migration acceptance and the canonical-migration early return."""
    assert guard.read_wheel(
        _wheel_with("regista/module.py"),
        "fuzz control",
        wheel_filename="r-0.0.0-py3-none-any.whl",
    ) == {name: _sha(data) for name, data in BASE.items()}
    migs = guard.read_wheel(
        _wheel_with("regista/migrations/300_fuzz.sql"),
        "fuzz migration control",
        wheel_filename="r-0.0.0-py3-none-any.whl",
    )
    assert "300_fuzz.sql" in migs


def test_ledger_round_trips_through_copy() -> None:
    led = guard.load_ledger()
    assert guard.check_ledger(copy.deepcopy(led)) == []
    assert json.loads(json.dumps(led)) == led


# --------------------------------------------------------------------------
# New-design round 1 (Daybreak Blue B1-B3, DeepSeek B1/N1-N6)


def _good_wheel() -> bytes:
    return _wheel_bytes(_wheel_files(BASE))


def _pax_sdist(pax: dict[str, str], global_: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers=pax if global_ else None) as tf:
        for name, data in {"PKG-INFO": b"x", "pyproject.toml": PYPROJECT,
                           **_sdist_files(BASE)}.items():
            info = tarfile.TarInfo(f"r-0.0.0/{name}")
            info.size = len(data)
            if not global_ and name == "PKG-INFO":
                info.pax_headers = pax
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _descriptor_wheel() -> bytes:
    class Unseekable(io.RawIOBase):
        def __init__(self) -> None:
            self.buf = bytearray()

        def writable(self) -> bool:
            return True

        def write(self, b: Any) -> int:
            self.buf += bytes(b)
            return len(b)

    sink = Unseekable()
    with zipfile.ZipFile(sink, "w") as zf:
        files = _wheel_files(BASE)
        for name, data in files.items():
            zf.writestr(name, data)
        zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
        zf.writestr("r-0.0.0.dist-info/WHEEL", WHEEL_METADATA)
        lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    return bytes(sink.buf)


def _unicode_path_wheel() -> bytes:
    import zlib

    files = dict(_wheel_files(BASE))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            if name.endswith("002_b.sql"):
                target = b"regista/migrations/000_x.sql"
                body = b"\x01" + struct_pack_crc(zlib.crc32(name.encode())) + target
                info.extra = b"\x75\x70" + len(body).to_bytes(2, "little") + body
            zf.writestr(info, data)
        zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
        zf.writestr("r-0.0.0.dist-info/WHEEL", WHEEL_METADATA)
        lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    return buf.getvalue()


def struct_pack_crc(crc: int) -> bytes:
    return crc.to_bytes(4, "little")


def _zip64_wheel() -> bytes:
    files = _wheel_files(BASE)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", allowZip64=True) as zf:
        for name, data in files.items():
            with zf.open(name, "w", force_zip64=True) as fh:
                fh.write(data)
        zf.writestr("r-0.0.0.dist-info/METADATA", "Name: r\n")
        zf.writestr("r-0.0.0.dist-info/WHEEL", WHEEL_METADATA)
        lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    return buf.getvalue()


ROUND_N1: dict[str, tuple[bytes | None, bytes | None]] = {
    "regular file at exactly regista/migrations (DB B2, DS N2)": (
        _wheel_with("regista/migrations"), None),
    "regular file at a required ancestor": (_wheel_with("regista"), None),
    "sdist regular file at exactly migrations": (None, _sdist_with("migrations")),
    "concatenated wheels / two EOCDs (DB B3)": (_good_wheel() + _good_wheel(), None),
    "preamble before the first record": (b"\0" * 16 + _good_wheel(), None),
    "trailing bytes after EOCD": (_good_wheel() + b"\0", None),
    "zip comment": (_good_wheel()[:-2] + b"\x03\x00abc", None),
    "data descriptors": (_descriptor_wheel(), None),
    "ZIP64 records": (_zip64_wheel(), None),
    "Info-ZIP Unicode Path extra field": (_unicode_path_wheel(), None),
    "Windows trailing dot segment (DS N1)": (_wheel_with("regista/migrations./000_x.sql."), None),
    "Windows device name": (_wheel_with("regista/con.txt"), None),
    "PAX path override": (None, _pax_sdist({"path": "r-0.0.0/migrations/000_x.sql"})),
    "PAX global header": (None, _pax_sdist({"comment": "x"}, global_=True)),
    "sdist pyproject with a hatch hook (DB B1, DS B1)": (None, _sdist_with(
        "pyproject.toml", PYPROJECT + b"\n[tool.hatch.build.hooks.custom]\n")),
    "sdist carries hatch_build.py": (None, _sdist_with("hatch_build.py", b"x = 1\n")),
    "sdist carries hatch.toml": (None, _sdist_with("hatch.toml", b"")),
    "corrupt wheel": (b"PK\x03\x04garbage", None),
    "local header CRC disagrees with central": (_good_wheel()[:14] + b"\xff\xff\xff\xff"
                                                 + _good_wheel()[18:], None),
}


@pytest.mark.parametrize("shape", sorted(ROUND_N1))
def test_round_n1_shapes_fail(tmp_path: Path, shape: str) -> None:
    wheel, sdist = ROUND_N1[shape]
    verdict = _verdict(_dist(tmp_path, wheel, sdist))
    assert verdict != "pass", shape
    assert "Traceback" not in verdict


def test_an_sdist_with_two_roots_or_a_top_level_file_fails(tmp_path: Path) -> None:
    for extra_name in ("other-0.0.0/x.txt", "toplevel.txt"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, data in {"r-0.0.0/PKG-INFO": b"x", "r-0.0.0/pyproject.toml": PYPROJECT,
                               **{f"r-0.0.0/{k}": v for k, v in _sdist_files(BASE).items()},
                               extra_name: b"x"}.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        assert "one top-level directory" in _verdict(_dist(tmp_path / extra_name[:3], None,
                                                           buf.getvalue()))


def test_a_corrupt_sdist_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    assert _verdict(_dist(tmp_path, None, b"\x1f\x8bnot a tar")).startswith("error:")


def test_a_symlinked_gitignore_is_not_exempt(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (tmp_path / "star").write_bytes(b"*")
    (d / ".gitignore").symlink_to(tmp_path / "star")
    assert _verdict(d).startswith("error:")


@pytest.mark.parametrize(
    ("pyproject", "fragment"),
    [
        (b'[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n',
         "trusted frozen requirement set"),
        (b'[build-system]\nrequires = ["hatchling==1"]\nbuild-backend = "x.build"\n',
         "must be hatchling.build"),
        (b'[build-system]\nrequires = ["hatchling==1"]\nbuild-backend = "hatchling.build"\n'
         b'backend-path = ["."]\n', "no backend-path"),
        (b'[build-system]\nrequires = ["setuptools==1"]\nbuild-backend = "hatchling.build"\n',
         "trusted frozen requirement set"),
        (PYPROJECT + b"\n[tool.hatch.metadata.hooks.custom]\n", "hooks"),
    ],
)
def test_the_build_contract_refuses_unpinned_or_executable_builds(
    pyproject: bytes, fragment: str
) -> None:
    with pytest.raises(guard.GuardError, match=re.escape(fragment)):
        guard.check_build_contract(pyproject, "pyproject.toml")


def test_the_repository_pyproject_honours_the_build_contract() -> None:
    guard.check_build_contract(PYPROJECT, "pyproject.toml")


@pytest.mark.parametrize(
    "pyproject",
    [
        PYPROJECT.replace(
            b'requires = [\n', b'requires = [\n    "neutral-build-helper==1.0.2",\n'
        ),
        PYPROJECT.replace(b'    "packaging==26.3",\n', b""),
        PYPROJECT.replace(b'    "packaging==26.3",', b'    "packaging==26.2",'),
        PYPROJECT.replace(
            b'    "packaging==26.3",\n',
            b'    "packaging==26.3",\n    "packaging==26.3",\n',
        ),
    ],
    ids=["extra", "missing", "different", "duplicate"],
)
def test_build_contract_requires_exact_trusted_set(pyproject: bytes) -> None:
    with pytest.raises(guard.GuardError, match="trusted frozen requirement set"):
        guard.check_build_contract(pyproject, "pyproject.toml")


def test_check_dist_enforces_the_trusted_build_requirement_set(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_bytes(
        PYPROJECT.replace(
            b'requires = [\n', b'requires = [\n    "neutral-build-helper==1.0.2",\n'
        )
    )
    with pytest.raises(guard.GuardError, match="trusted frozen requirement set"):
        guard.check_dist(_ledger(), _dist(tmp_path), {}, repo_root=repo, rebuild_sdists=False)


# --------------------------------------------------------------------------
# New-design round 2 (Daybreak Blue B1-B3, DeepSeek B1/NB1/NB2/NB7)


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("zzz_probe.pth", "startup-executable"),
        ("regista/zzz_probe.PTH", "startup-executable"),
        ("regista/sitecustomize.py", "startup-executable"),
        ("regista/usercustomize.py", "startup-executable"),
        (
            "r-0.0.0.data/purelib/regista/migrations/000_unexpected.sql/note.txt",
            "outside the allowed layout",
        ),
        (
            "r-0.0.0.data/platlib/regista/migrations/000_unexpected.sql/note.txt",
            "outside the allowed layout",
        ),
        ("other-0.0.0.dist-info/METADATA", "outside the allowed layout"),
        ("README.txt", "outside the allowed layout"),
        ("r-0.0.0.dist-info/unknown.json", "outside the allowed layout"),
    ],
    ids=[
        "top-level-pth",
        "package-pth",
        "sitecustomize",
        "usercustomize",
        "data-purelib",
        "data-platlib",
        "second-dist-info",
        "top-level-file",
        "unknown-dist-info-file",
    ],
)
def test_round_n2_wheel_members_fail(name: str, fragment: str) -> None:
    with pytest.raises(guard.GuardError, match=fragment):
        guard.read_wheel(_wheel_with(name), "r-0.0.0-py3-none-any.whl")


@pytest.mark.parametrize(
    "name", ["src/regista/zzz_probe.pth", "sitecustomize.py", "src/usercustomize.py"]
)
def test_round_n2_sdist_startup_executables_fail(name: str) -> None:
    with pytest.raises(guard.GuardError, match="startup-executable"):
        guard.read_sdist(_sdist_with(name), "r-0.0.0.tar.gz")


def test_wheel_dist_info_must_match_its_filename() -> None:
    with pytest.raises(guard.GuardError, match="outside the allowed layout"):
        guard.read_wheel(_good_wheel(), "other-9.9-py3-none-any.whl")


def test_wheel_layout_allows_only_named_metadata_and_licenses() -> None:
    wheel = _wheel_with("r-0.0.0.dist-info/licenses/LICENSE", b"license\n")
    assert guard.read_wheel(wheel, "r-0.0.0-py3-none-any.whl") == {
        name: _sha(data) for name, data in BASE.items()
    }


def test_wheel_metadata_is_mandatory_and_exact() -> None:
    with pytest.raises(guard.GuardError, match="required WHEEL metadata is missing"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), wheel_metadata=None),
            "r-0.0.0-py3-none-any.whl",
        )
    wrong_version = WHEEL_METADATA.replace(b"Wheel-Version: 1.0", b"Wheel-Version: 1.1")
    with pytest.raises(guard.GuardError, match=re.escape("exactly Wheel-Version: 1.0")):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), wheel_metadata=wrong_version),
            "r-0.0.0-py3-none-any.whl",
        )
    not_purelib = WHEEL_METADATA.replace(b"Root-Is-Purelib: true", b"Root-Is-Purelib: false")
    with pytest.raises(guard.GuardError, match="exactly Root-Is-Purelib: true"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), wheel_metadata=not_purelib),
            "r-0.0.0-py3-none-any.whl",
        )
    terminated_headers = WHEEL_METADATA.replace(
        b"Root-Is-Purelib: true", b"\nRoot-Is-Purelib: true"
    )
    with pytest.raises(guard.GuardError, match="content after its header block"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), wheel_metadata=terminated_headers),
            "r-0.0.0-py3-none-any.whl",
        )


def _unsupported_compression_wheel() -> bytes:
    blob = bytearray(_good_wheel())
    central = struct.unpack_from("<I", blob, len(blob) - 22 + 16)[0]
    struct.pack_into("<H", blob, 8, 99)
    struct.pack_into("<H", blob, central + 10, 99)
    return bytes(blob)


def test_unsupported_wheel_compression_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    verdict = _verdict(_dist(tmp_path, _unsupported_compression_wheel()))
    assert verdict.startswith("error:")
    assert "NotImplementedError" in verdict
    assert "Traceback" not in verdict


@pytest.mark.parametrize("artifact", ["x.whl", "x.tar.gz"])
def test_a_directory_named_like_an_artifact_is_an_error_not_a_traceback(
    tmp_path: Path, artifact: str
) -> None:
    d = _dist(tmp_path)
    (d / artifact).mkdir()
    verdict = _verdict(d)
    assert verdict.startswith("error:")
    assert "every entry must be a regular file" in verdict
    assert "Traceback" not in verdict


@pytest.mark.parametrize("bad_frontend", ["uv", "pip"])
def test_a_rebuild_that_diverges_under_either_frontend_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_frontend: str
) -> None:
    """A backend that behaves differently per frontend (DB B1 / DS B1) is caught by
    building with each frontend; the rebuild rule is no longer untested."""
    good, bad = _good_wheel(), _wheel_with("regista/migrations/000_x.sql")

    def fake(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
        path = out / "r-0.0.0-py3-none-any.whl"
        path.write_bytes(bad if label == bad_frontend else good)
        return path

    monkeypatch.setattr(guard, "_rebuild", fake)
    d = _dist(tmp_path)
    assert guard.check_dist(_ledger(), d, {}, rebuild_sdists=True) != []
    monkeypatch.setattr(guard, "_rebuild", lambda label, argv, sdist, out: (
        out / "r-0.0.0-py3-none-any.whl").write_bytes(good)
        and out / "r-0.0.0-py3-none-any.whl")
    assert guard.check_dist(_ledger(), d, {}, rebuild_sdists=True) == []


def test_both_frontends_are_configured() -> None:
    assert [label for label, _ in guard.REBUILDERS] == ["uv", "pip"]


BENIGN = ACCEPTED_FUZZ_MEMBER


@settings(max_examples=300, deadline=None)
@given(name=BENIGN)
def test_fuzz_benign_names_are_accepted(name: str) -> None:
    """Positive half of the property, so the negative fuzz cannot pass by refusing
    everything (DB/DS round-1 notes)."""
    assume(name.split("/")[1].split(".")[0] not in guard.WINDOWS_DEVICES)
    assume(all(p.split(".")[0] not in guard.WINDOWS_DEVICES for p in name.split("/")))
    assume(not name.startswith("regista/migrations"))
    assert guard.read_wheel(
        _wheel_with(name), "fuzz", wheel_filename="r-0.0.0-py3-none-any.whl"
    ) == {n: _sha(b) for n, b in BASE.items()}


def _overlapping_wheel() -> bytes:
    """Point the second central-directory entry at the first local record: the
    EOCD stays consistent, so only the contiguity rule can see the overlap."""
    blob = bytearray(_good_wheel())
    first = blob.index(b"PK\x01\x02")
    second = blob.index(b"PK\x01\x02", first + 4)
    blob[second + 42 : second + 46] = (0).to_bytes(4, "little")
    return bytes(blob)


@pytest.mark.parametrize(
    ("blob_fn", "message"),
    [
        (lambda: b"\0" * 16 + _good_wheel(), "central directory does not end"),
        (lambda: _overlapping_wheel(), "is not contiguous"),
        (lambda: _good_wheel() + b"\0", "no end-of-central-directory record at the very end"),
        (_unicode_path_wheel, "carries a ZIP extra field"),
        (_zip64_wheel, "local header disagrees"),
        (_descriptor_wheel, "uses a data descriptor"),
        (lambda: _good_wheel()[:-2] + b"\x03\x00abc", "no end-of-central-directory record"),
        (lambda: _good_wheel()[:14] + b"\xff\xff\xff\xff" + _good_wheel()[18:],
         "local header disagrees"),
    ],
)
def test_each_zip_container_rule_names_its_own_refusal(blob_fn: Any, message: str) -> None:
    """Each container rule is pinned by its own message, so disabling any single
    rule turns this red even where another layer would also refuse the archive."""
    with pytest.raises(guard.GuardError, match=re.escape(message)):
        guard.read_wheel(
            blob_fn(), "w", wheel_filename="r-0.0.0-py3-none-any.whl"
        )
