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
import os
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
        "check_published_migrations", Path(os.environ.get(
            "REGISTA_GUARD_TEST_ROOT", REPO_ROOT)) / "scripts/check_published_migrations.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()

_ORIGINAL_WRITESTR = zipfile.ZipFile.writestr


@pytest.fixture(autouse=True)
def _wheel_members_are_0644(monkeypatch: pytest.MonkeyPatch) -> None:
    """zipfile gives string-named members mode 0600; hatch writes 0644. Fixtures
    that build wheels from names get the real mode, so the mode rule (which
    refuses anything but 0644) judges fixtures as it judges real wheels.
    Fixtures that want another mode pass an explicit ZipInfo."""

    def writestr(self: zipfile.ZipFile, name: Any, data: Any, *a: Any, **kw: Any) -> None:
        if isinstance(name, str):
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = self.compression
            name = info
        _ORIGINAL_WRITESTR(self, name, data, *a, **kw)

    monkeypatch.setattr(zipfile.ZipFile, "writestr", writestr)
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






@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build real artifacts")
def test_a_real_build_passes_check_dist_including_the_sdist_rebuild(tmp_path: Path) -> None:
    """Builds from a clean clone of HEAD: reviewed bytes are committed bytes."""
    dist, clone = tmp_path / "dist", tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(REPO_ROOT), str(clone)], check=True)
    subprocess.run(
        ["uv", "build", "-q", "--out-dir", str(dist), str(clone)],
        check=True,
        env={**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")},
    )
    assert guard.check_dist(guard.load_ledger(), dist, repo_root=clone) == []


# --------------------------------------------------------------------------
# Fixtures

BASE = {"schema.sql": A, "workflow.schema.json": B}
REPO_PYPROJECT = (REPO_ROOT / "pyproject.toml").read_bytes()
PYPROJECT = (b'[build-system]\nrequires = [\n' +
             b'\n'.join(f'    "{r}",'.encode() for r in guard.TRUSTED_BUILD_REQUIREMENTS) +
             b'\n]\nbuild-backend = "hatchling.build"\n\n'
             b'[project]\nname = "r"\nversion = "0.0.0"\n' +
             b'\n[tool.hatch]\n' + b'')
# Keep the reviewed table's complete shape, including the sdist include list.
PYPROJECT += b'[tool.hatch.build.targets.wheel]\npackages = ["src/regista"]\n'
PYPROJECT += (b'[tool.hatch.build.targets.sdist]\ninclude = [' +
              b', '.join(json.dumps(p).encode() for p in
                         guard.REVIEWED_HATCH_CONFIG['build']['targets']['sdist']['include']) +
              b']\n')
METADATA = b"Metadata-Version: 2.4\nName: r\nVersion: 0.0.0\n"
RELEASES = {"0.1.0": {"001_a.sql": A}, "0.2.0": BASE}


def _ledger() -> dict[str, Any]:
    ledger = copy.deepcopy(guard.load_ledger())
    ledger["baseline"] = {n: _sha(b) for n, b in BASE.items()}
    ledger["schema_versions"] = {"1": _sha(A)}
    return ledger


def _record_digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _finish_wheel(
    zf: zipfile.ZipFile,
    files: dict[str, bytes],
    *,
    record: bool = True,
    wheel_metadata: bytes | None = WHEEL_METADATA,
    metadata: bytes | None = METADATA,
) -> None:
    generated: dict[str, bytes] = {}
    if metadata is not None:
        generated["r-0.0.0.dist-info/METADATA"] = metadata
    if wheel_metadata is not None:
        generated["r-0.0.0.dist-info/WHEEL"] = wheel_metadata
    for name, data in generated.items():
        zf.writestr(name, data)
    if record:
        all_hashed = {**files, **generated}
        lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in all_hashed.items()]
        lines.append("r-0.0.0.dist-info/RECORD,,")
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")


def _wheel_bytes(files: dict[str, bytes], *, record: bool = True,
                 wheel_metadata: bytes | None = WHEEL_METADATA,
                 metadata: bytes | None = METADATA,
                 extra: list[tuple[zipfile.ZipInfo, bytes]] = (),  # type: ignore[assignment]
                 record_extra: dict[str, bytes] | None = None) -> bytes:
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
            _finish_wheel(
                zf, {**files, **(record_extra or {})}, record=record,
                wheel_metadata=wheel_metadata, metadata=metadata,
            )
    return buf.getvalue()


def _sdist_bytes(
    files: dict[str, bytes],
    extra: list[tarfile.TarInfo] = (),  # type: ignore[assignment]
    *,
    pkg_info: bytes | None = METADATA,
) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        base = {"pyproject.toml": PYPROJECT}
        if pkg_info is not None:
            base["PKG-INFO"] = pkg_info
        for name, data in {**base, **files}.items():
            info = tarfile.TarInfo(f"r-0.0.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for info in extra:
            tf.addfile(info)
    return buf.getvalue()


def _wheel_files(migs: dict[str, bytes]) -> dict[str, bytes]:
    return {**{f"regista/{n}": b for n, b in migs.items()}, "regista/__init__.py": b""}


def _sdist_files(migs: dict[str, bytes]) -> dict[str, bytes]:
    return {**{f"src/regista/{n}": b for n, b in migs.items()}, "src/regista/__init__.py": b""}


def _dist(tmp_path: Path, wheel: bytes | None = None, sdist: bytes | None = None) -> Path:
    _test_repo(tmp_path)
    d = tmp_path / "dist"
    d.mkdir(parents=True, exist_ok=True)
    (d / "r-0.0.0-py3-none-any.whl").write_bytes(
        wheel if wheel is not None else _wheel_bytes(_wheel_files(BASE))
    )
    (d / "r-0.0.0.tar.gz").write_bytes(
        sdist if sdist is not None else _sdist_bytes(_sdist_files(BASE))
    )
    return d


def _test_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    if (repo / ".git").exists():
        return repo
    (repo / "src" / "regista").mkdir(parents=True)
    (repo / "pyproject.toml").write_bytes(PYPROJECT)
    (repo / "src" / "regista" / "__init__.py").write_bytes(b"")
    for name, data in BASE.items():
        (repo / "src/regista" / name).write_bytes(data)
    (repo / "LICENSE").write_bytes(b"license\n")
    _git_commit_all(repo, init=True)
    return repo


def _git_commit_all(repo: Path, *, init: bool = False) -> None:
    """Reviewed bytes are COMMITTED bytes: fixtures commit what they track."""
    if init:
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "fixture"],
        check=True,
    )


def _verdict(d: Path, ledger: dict[str, Any] | None = None) -> str:
    """'pass', or the first problem / error text."""
    try:
        problems = guard.check_dist(
            ledger or _ledger(), d, {}, repo_root=d.parent / "repo", rebuild_sdists=False
        )
    except guard.GuardError as exc:
        return f"error: {exc}"
    return problems[0] if problems else "pass"


def test_a_faithful_dist_passes(tmp_path: Path) -> None:
    assert _verdict(_dist(tmp_path)) == "pass"




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
    "edited pinned schema": (
        _wheel_bytes(_wheel_files({**BASE, "schema.sql": A + b"x"})),
        _sdist_bytes(_sdist_files({**BASE, "schema.sql": A + b"x"})),
    ),
    "dropped pinned schema": (
        _wheel_bytes(_wheel_files({"workflow.schema.json": B})),
        _sdist_bytes(_sdist_files({"workflow.schema.json": B}))
    ),
    "inserted below head (r1 Sol/DS)": (_wheel_with("regista/migrations/000_unexpected.sql"),
                                        _sdist_with("migrations/000_unexpected.sql")),
    "undeclared append above head": (_wheel_with("regista/migrations/003_c.sql"),
                                     _sdist_with("migrations/003_c.sql")),
    "duplicate version number": (_wheel_with("regista/migrations/002_z.sql"), None),
    "bare-number name 050.sql (r1 DS)": (_wheel_with("regista/migrations/050.sql"), None),
    "non-numeric name hotfix.sql": (_wheel_with("regista/migrations/hotfix.sql"), None),
    "undeclared sql outside baseline in wheel (r1)": (
        _wheel_with("regista/other.sql"), None),
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
    "fold collision schema.sql vs SCHEMA.sql": (_wheel_with("regista/SCHEMA.sql"), None),
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
            zf.writestr("regista/schema.sql", b"-- second copy\n")
    assert "collide" in _verdict(_dist(tmp_path, buf.getvalue()))


def test_a_record_naming_other_bytes_fails(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        files = _wheel_files(BASE)
        for n, d in files.items():
            zf.writestr(n, d)
        generated = {
            "r-0.0.0.dist-info/METADATA": METADATA,
            "r-0.0.0.dist-info/WHEEL": WHEEL_METADATA,
        }
        for name, data in generated.items():
            zf.writestr(name, data)
        all_hashed = {**files, **generated}
        lines = [
            f"{name},sha256={_record_digest(C if name == 'regista/__init__.py' else data)},"
            f"{len(data)}"
            for name, data in all_hashed.items()
        ]
        lines.append("r-0.0.0.dist-info/RECORD,,")
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
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






# --------------------------------------------------------------------------
# Ledger rules (previously the history vectors)










def _fresh(releases: dict[str, dict[str, bytes]]) -> dict[str, Any]:
    out: dict[str, Any] = _ledger(releases)["releases"]
    return out












# --------------------------------------------------------------------------
# Tree


def _tree(tmp_path: Path, files: dict[str, bytes]) -> Path:
    package = tmp_path / "src/regista"
    package.mkdir(parents=True)
    (package / "kernel.py").write_text("KERNEL_SCHEMA_VERSION = 1\n")
    for name, data in files.items():
        (package / name).write_bytes(data)
    return tmp_path


@pytest.mark.parametrize("files", [
    {**BASE, "schema.sql": A + b"x"},
    {"workflow.schema.json": B},
    {"renamed.sql": A, "workflow.schema.json": B},
    {**BASE, "000_x.sql": C}, {**BASE, "hotfix.sql": C}, {**BASE, "003_C.sql": C},
])
def test_bad_trees_fail(tmp_path: Path, files: dict[str, bytes]) -> None:
    assert guard.check_tree(_ledger(), _tree(tmp_path, files))


def test_a_good_tree_passes_and_package_migrations_dir_fails(tmp_path: Path) -> None:
    repo = _tree(tmp_path, BASE)
    assert guard.check_tree(_ledger(), repo) == []
    (repo / "src/regista/migrations").mkdir()
    assert guard.check_tree(_ledger(), repo)


def test_a_symlink_or_directory_in_baseline_fails(tmp_path: Path) -> None:
    repo = _tree(tmp_path, BASE)
    resource = repo / "src/regista/schema.sql"
    resource.unlink()
    resource.symlink_to("workflow.schema.json")
    assert guard.check_tree(_ledger(), repo)
    resource.unlink()
    resource.mkdir()
    assert guard.check_tree(_ledger(), repo)


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
ADVERSARIAL_FUZZ_MEMBER = st.one_of(
    st.lists(NASTY, min_size=1, max_size=8).map("".join),
    RELOCATED_FUZZ_MEMBER,
)


@settings(max_examples=2000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(name=ADVERSARIAL_FUZZ_MEMBER)
def test_fuzz_no_accepted_adversarial_name_reaches_migrations_or_is_sql(name: str) -> None:
    blob = _wheel_with(name)
    try:
        migs = guard.read_wheel(blob, "fuzz", wheel_filename="r-0.0.0-py3-none-any.whl")
    except (guard.GuardError, ValueError):
        return
    view = _installer_view(name)
    assert migs == {n: _sha(b) for n, b in BASE.items()}
    if name == "regista/schema.sql":
        return
    assert not view.startswith("regista/migrations/"), name
    assert not view.endswith(".sql"), name
    assert not view.startswith("src/regista/migrations"), name


def test_negative_fuzz_acceptance_branches_are_reachable() -> None:
    """Pin the non-SQL acceptance branch independently from negative fuzz."""
    assert guard.read_wheel(
        _wheel_with("regista/module.py"),
        "fuzz control",
        wheel_filename="r-0.0.0-py3-none-any.whl",
    ) == {name: _sha(data) for name, data in BASE.items()}


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
        _finish_wheel(zf, files)
    return bytes(sink.buf)


def _unicode_path_wheel() -> bytes:
    import zlib

    files = dict(_wheel_files(BASE))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            if name.endswith("workflow.schema.json"):
                target = b"regista/migrations/000_x.sql"
                body = b"\x01" + struct_pack_crc(zlib.crc32(name.encode())) + target
                info.extra = b"\x75\x70" + len(body).to_bytes(2, "little") + body
            zf.writestr(info, data)
        _finish_wheel(zf, files)
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
        _finish_wheel(zf, files)
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
        (PYPROJECT + b"\n[tool.hatch.metadata.hooks.custom]\n", "reviewed static build table"),
    ],
)
def test_the_build_contract_refuses_unpinned_or_executable_builds(
    pyproject: bytes, fragment: str
) -> None:
    with pytest.raises(guard.GuardError, match=re.escape(fragment)):
        guard.check_build_contract(pyproject, "pyproject.toml")


def test_the_repository_pyproject_honours_the_build_contract() -> None:
    guard.check_build_contract(REPO_PYPROJECT, "pyproject.toml")


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
    repo = _test_repo(tmp_path)
    (repo / "pyproject.toml").write_bytes(
        PYPROJECT.replace(
            b'requires = [\n', b'requires = [\n    "neutral-build-helper==1.0.2",\n'
        )
    )
    _git_commit_all(repo)
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
    with pytest.raises(guard.GuardError, match=r"required metadata is missing: \['WHEEL'\]"):
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
    good, bad = _good_wheel(), _wheel_with("regista/untracked.py")

    def fake(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
        path = out / "r-0.0.0-py3-none-any.whl"
        path.write_bytes(bad if label == bad_frontend else good)
        return path

    monkeypatch.setattr(guard, "_rebuild", fake)
    d = _dist(tmp_path)
    with pytest.raises(guard.GuardError, match="not tracked by Git"):
        guard.check_dist(
            _ledger(), d, {}, repo_root=tmp_path / "repo", rebuild_sdists=True
        )
    monkeypatch.setattr(guard, "_rebuild", lambda label, argv, sdist, out: (
        out / "r-0.0.0-py3-none-any.whl").write_bytes(good)
        and out / "r-0.0.0-py3-none-any.whl")
    assert guard.check_dist(
        _ledger(), d, {}, repo_root=tmp_path / "repo", rebuild_sdists=True
    ) == []


def test_both_frontends_are_configured() -> None:
    assert [label for label, _ in guard.REBUILDERS] == ["uv", "pip"]


BENIGN = ACCEPTED_FUZZ_MEMBER


@settings(max_examples=300, deadline=None)
@given(name=BENIGN)
def test_fuzz_benign_names_are_accepted(name: str) -> None:
    """Separate positive property: the adversarial property is not asked to
    prove that its generated names reach an acceptance branch."""
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


def _wheel_with_gap_before_central_directory() -> bytes:
    """Insert one byte after the last local record and retarget the EOCD."""
    blob = bytearray(_good_wheel())
    old_cd = struct.unpack_from("<I", blob, len(blob) - 22 + 16)[0]
    blob[old_cd:old_cd] = b"x"
    struct.pack_into("<I", blob, len(blob) - 22 + 16, old_cd + 1)
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
        (_wheel_with_gap_before_central_directory, "bytes between the last record"),
    ],
)
def test_each_zip_container_rule_names_its_own_refusal(blob_fn: Any, message: str) -> None:
    """Each container rule is pinned by its own message, so disabling any single
    rule turns this red even where another layer would also refuse the archive."""
    with pytest.raises(guard.GuardError, match=re.escape(message)):
        guard.read_wheel(
            blob_fn(), "w", wheel_filename="r-0.0.0-py3-none-any.whl"
        )


# --------------------------------------------------------------------------
# New-design round 3: reviewed bytes, complete metadata, and static builds


def _wheel_with_record_omitting(
    omitted: str, *, self_row: str = "r-0.0.0.dist-info/RECORD,,"
) -> bytes:
    files = _wheel_files(BASE)
    generated = {
        "r-0.0.0.dist-info/METADATA": METADATA,
        "r-0.0.0.dist-info/WHEEL": WHEEL_METADATA,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in {**files, **generated}.items():
            zf.writestr(name, data)
        rows = [
            f"{name},sha256={_record_digest(data)},{len(data)}"
            for name, data in {**files, **generated}.items()
            if name != omitted
        ]
        rows.append(self_row)
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(rows) + "\n")
    return buf.getvalue()


def _wheel_with_identity(distribution: str, version: str) -> bytes:
    files = _wheel_files(BASE)
    prefix = f"{distribution}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n".encode()
    generated = {f"{prefix}/METADATA": metadata, f"{prefix}/WHEEL": WHEEL_METADATA}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in {**files, **generated}.items():
            zf.writestr(name, data)
        rows = [
            f"{name},sha256={_record_digest(data)},{len(data)}"
            for name, data in {**files, **generated}.items()
        ]
        rows.append(f"{prefix}/RECORD,,")
        zf.writestr(f"{prefix}/RECORD", "\n".join(rows) + "\n")
    return buf.getvalue()


def test_round_n3_edited_package_bytes_fail(tmp_path: Path) -> None:
    wheel = _wheel_bytes({**_wheel_files(BASE), "regista/__init__.py": b"edited\n"})
    assert "differs from tracked" in _verdict(_dist(tmp_path / "wheel", wheel=wheel))

    sdist = _sdist_bytes({**_sdist_files(BASE), "src/regista/__init__.py": b"edited\n"})
    assert "differs from its tracked source" in _verdict(
        _dist(tmp_path / "sdist", sdist=sdist)
    )


def test_round_n3_untracked_artifact_members_fail(tmp_path: Path) -> None:
    wheel_dist = _dist(tmp_path / "wheel", wheel=_wheel_with("regista/untracked.py"))
    wheel_source = tmp_path / "wheel" / "repo" / "src" / "regista" / "untracked.py"
    wheel_source.write_bytes(C)  # matching but deliberately not `git add`ed
    assert "not tracked by Git" in _verdict(
        wheel_dist
    )
    sdist_dist = _dist(tmp_path / "sdist", sdist=_sdist_with("untracked.txt"))
    (tmp_path / "sdist" / "repo" / "untracked.txt").write_bytes(C)
    assert "not tracked by Git" in _verdict(
        sdist_dist
    )


def test_check_dist_requires_the_root_of_a_git_checkout(tmp_path: Path) -> None:
    repo = _test_repo(tmp_path)
    nested = repo / "src"
    with pytest.raises(guard.GuardError, match="root of a Git checkout"):
        guard._git_tracked_files(nested)


def test_a_tracked_path_reached_through_a_parent_symlink_is_refused(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    repo = tmp_path / "repo"
    package = repo / "src" / "regista"
    shutil.rmtree(package)
    outside = tmp_path / "outside-package"
    outside.mkdir()
    (outside / "__init__.py").write_bytes(b"")
    package.symlink_to(outside, target_is_directory=True)
    _git_commit_all(repo)  # HEAD now records a symlink, which is not reviewed bytes
    assert "not tracked by Git" in _verdict(d)


def test_sdist_pkg_info_exists_exactly_once_at_the_root(tmp_path: Path) -> None:
    missing = _sdist_bytes(_sdist_files(BASE), pkg_info=None)
    assert "PKG-INFO must exist exactly once" in _verdict(_dist(tmp_path, sdist=missing))


def test_wheel_metadata_and_record_are_complete() -> None:
    with pytest.raises(guard.GuardError, match="required metadata is missing"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), metadata=None),
            "r-0.0.0-py3-none-any.whl",
        )
    with pytest.raises(guard.GuardError, match="list every wheel member"):
        guard.read_wheel(
            _wheel_with_record_omitting("regista/__init__.py"),
            "r-0.0.0-py3-none-any.whl",
        )
    with pytest.raises(guard.GuardError, match="exactly one Name and Version"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), metadata=b"Name: r\n"),
            "r-0.0.0-py3-none-any.whl",
        )
    with pytest.raises(guard.GuardError, match="self-row must have empty"):
        guard.read_wheel(
            _wheel_with_record_omitting(
                "not-present", self_row="r-0.0.0.dist-info/RECORD,sha256=eA,1"
            ),
            "r-0.0.0-py3-none-any.whl",
        )


@pytest.mark.parametrize(
    "filename",
    ["r-0.0.0-py2-none-any.whl", "r-0.0.0-cp314-cp314-linux_x86_64.whl"],
)
def test_only_the_universal_wheel_filename_tag_is_allowed(filename: str) -> None:
    with pytest.raises(guard.GuardError, match="filename tag must be exactly py3-none-any"):
        guard.read_wheel(_good_wheel(), filename)


def test_wheel_tag_and_identity_metadata_must_match() -> None:
    wrong_tag = WHEEL_METADATA.replace(b"Tag: py3-none-any", b"Tag: py2-none-any")
    with pytest.raises(guard.GuardError, match="Tag lines must be exactly py3-none-any"):
        guard.read_wheel(
            _wheel_bytes(_wheel_files(BASE), wheel_metadata=wrong_tag),
            "r-0.0.0-py3-none-any.whl",
        )
    for metadata in (
        METADATA.replace(b"Name: r", b"Name: other"),
        METADATA.replace(b"Version: 0.0.0", b"Version: 9.9.9"),
    ):
        with pytest.raises(guard.GuardError, match="filename and METADATA"):
            guard.read_wheel(
                _wheel_bytes(_wheel_files(BASE), metadata=metadata),
                "r-0.0.0-py3-none-any.whl",
            )


@pytest.mark.parametrize(
    ("distribution", "version"),
    [("other", "0.0.0"), ("r", "9.9.9")],
    ids=["distribution", "version"],
)
def test_wheel_filename_identity_must_match_literal_project_metadata(
    distribution: str, version: str
) -> None:
    with pytest.raises(guard.GuardError, match=r"differs from \[project\]"):
        guard.read_wheel(
            _wheel_with_identity(distribution, version),
            f"{distribution}-{version}-py3-none-any.whl",
            project_identity=("r", "0.0.0"),
        )


def test_wheel_license_bytes_are_reviewed(tmp_path: Path) -> None:
    good = _wheel_with("r-0.0.0.dist-info/licenses/LICENSE", b"license\n")
    assert _verdict(_dist(tmp_path / "good", wheel=good)) == "pass"
    bad = _wheel_with("r-0.0.0.dist-info/licenses/LICENSE", b"substituted\n")
    assert "differs from tracked 'LICENSE'" in _verdict(
        _dist(tmp_path / "bad", wheel=bad)
    )


@pytest.mark.parametrize(
    "addition",
    [
        b'\n[tool.hatch.version]\nsource = "code"\npath = "src/regista/__init__.py"\n',
        b"\n[tool.hatch.envs.default]\ndependencies = []\n",
        b"\n[tool.hatch.build.hooks.custom]\n",
    ],
    ids=["version-source-code", "environment", "build-hook"],
)
def test_tool_hatch_must_equal_the_single_reviewed_table(addition: bytes) -> None:
    with pytest.raises(guard.GuardError, match="reviewed static build table"):
        guard.check_build_contract(PYPROJECT + addition, "pyproject.toml")


def test_project_version_must_be_literal_and_not_dynamic() -> None:
    dynamic = PYPROJECT.replace(
        b'[project]\nname = "r"\nversion = "0.0.0"',
        b'[project]\nname = "r"\nversion = "0.0.0"\ndynamic = ["version"]',
    )
    with pytest.raises(guard.GuardError, match="must not contain dynamic"):
        guard.check_build_contract(dynamic, "pyproject.toml")
    without_version = PYPROJECT.replace(b'version = "0.0.0"\n', b"")
    with pytest.raises(guard.GuardError, match="literal strings"):
        guard.check_build_contract(without_version, "pyproject.toml")


def test_repository_hatch_config_files_are_independently_refused(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (tmp_path / "repo" / "hatch.toml").write_text("[build]\n")
    with pytest.raises(guard.GuardError, match=r"hatch\.toml must not exist"):
        guard.check_dist(
            _ledger(), d, {}, repo_root=tmp_path / "repo", rebuild_sdists=False
        )


def test_gitignore_exemption_requires_the_exact_one_byte_content(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (d / ".gitignore").write_bytes(b"**\n")
    assert ".gitignore" in _verdict(d)


def test_folded_migration_alias_rule_is_independently_pinned() -> None:
    with pytest.raises(guard.GuardError, match="retired migration path"):
        guard._classify(
            "REGISTA/MIGRATIONS/001_a.sql", "regista/", "folded alias", sql_elsewhere=True
        )


def test_rebuilt_wheel_filename_is_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
        path = out / "r-0.0.0-py2-none-any.whl"
        path.write_bytes(_good_wheel())
        return path

    monkeypatch.setattr(guard, "_rebuild", fake)
    d = _dist(tmp_path)
    with pytest.raises(guard.GuardError, match="filename tag must be exactly py3-none-any"):
        guard.check_dist(
            _ledger(), d, {}, repo_root=tmp_path / "repo", rebuild_sdists=True
        )


# --------------------------------------------------------------------------
# New-design round 4 (Daybreak Blue B1/B2): generated metadata bound to the
# trusted rebuilds; "reviewed" means the committed blob.

REQUIRES_DIST_URL = b"Requires-Dist: neutral-fixture @ file:///tmp/neutral_fixture-0.0.0-py3-none-any.whl\n"


def _rewrite_wheel(blob: bytes, changes: dict[str, bytes]) -> bytes:
    """Rewrite members of a wheel and regenerate a fully valid RECORD for them,
    exactly as an attacker editing a built wheel would."""
    src = zipfile.ZipFile(io.BytesIO(blob))
    record = next(n for n in src.namelist() if n.endswith(".dist-info/RECORD"))
    contents = {i.filename: src.read(i) for i in src.infolist()}
    contents.update(changes)
    lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in contents.items()
             if n != record]
    contents[record] = ("\n".join(lines) + f"\n{record},,\n").encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        originals = {i.filename: i for i in src.infolist()}
        order = [n for n in originals if n != record] + [
            n for n in contents if n not in originals
        ] + [record]
        for name in order:
            new = zipfile.ZipInfo(name, originals[name].date_time if name in originals
                                  else (2020, 1, 1, 0, 0, 0))
            new.external_attr = originals[name].external_attr if name in originals \
                else 0o100644 << 16
            new.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(new, contents[name])
    return out.getvalue()


def _with_metadata_line(blob: bytes, line: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(blob))
    meta = next(n for n in src.namelist() if n.endswith(".dist-info/METADATA"))
    head, sep, body = src.read(meta).partition(b"\n\n")
    return _rewrite_wheel(blob, {meta: head + b"\n" + line.rstrip(b"\n") + sep + body})


def _with_entry_points(blob: bytes, text: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(blob))
    ep = next(n for n in src.namelist() if n.endswith(".dist-info/entry_points.txt"))
    return _rewrite_wheel(blob, {ep: text})


def _stub_rebuilds(monkeypatch: pytest.MonkeyPatch, wheel: bytes) -> None:
    def fake(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
        path = out / "r-0.0.0-py3-none-any.whl"
        path.write_bytes(wheel)
        return path

    monkeypatch.setattr(guard, "_rebuild", fake)


@pytest.mark.parametrize("kind", ["requires-dist", "entry-points"])
def test_edited_generated_metadata_differs_from_the_rebuilds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    pristine = _wheel_bytes(_wheel_files(BASE))
    if kind == "requires-dist":
        edited = _with_metadata_line(pristine, REQUIRES_DIST_URL)
    else:
        edited = _rewrite_wheel(pristine, {"r-0.0.0.dist-info/entry_points.txt":
                                           b"[console_scripts]\nx = regista:main\n"})
    d = _dist(tmp_path, wheel=edited)
    _stub_rebuilds(monkeypatch, pristine)
    if kind == "requires-dist":
        with pytest.raises(guard.GuardError, match="PKG-INFO differs"):
            guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo")
        # A rebuild matching the edited wheel cannot bypass direct metadata binding.
        _stub_rebuilds(monkeypatch, edited)
        with pytest.raises(guard.GuardError, match="PKG-INFO differs"):
            guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo")
        return
    problems = guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo")
    assert any("differs from the uv rebuild" in p for p in problems), problems
    assert any("differs from the pip rebuild" in p for p in problems), problems
    _stub_rebuilds(monkeypatch, edited)  # control: binding is the only thing refusing it
    assert guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo") == []


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build real artifacts")
@pytest.mark.parametrize("kind", ["requires-dist", "entry-points"])
def test_round4_repros_fail_against_a_real_build(tmp_path: Path, kind: str) -> None:
    """Daybreak round-4 B1, end to end: a direct-URL dependency (a 51st migration
    after install) and an edited entry_points.txt, each with a valid RECORD, are
    refused by the real pip and uv rebuilds."""
    dist, clone = tmp_path / "dist", tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(REPO_ROOT), str(clone)], check=True)
    env = {**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    subprocess.run(["uv", "build", "-q", "--out-dir", str(dist), str(clone)], check=True, env=env)
    whl = next(dist.glob("*.whl"))
    blob = whl.read_bytes()
    whl.write_bytes(
        _with_metadata_line(blob, REQUIRES_DIST_URL) if kind == "requires-dist"
        else _with_entry_points(blob, b"[console_scripts]\nregista = os:system\n")
    )
    assert guard.read_wheel(whl.read_bytes(), whl.name) is not None  # structurally valid
    if kind == "requires-dist":
        with pytest.raises(guard.GuardError, match="PKG-INFO differs"):
            guard.check_dist(guard.load_ledger(), dist, repo_root=clone)
    else:
        problems = guard.check_dist(guard.load_ledger(), dist, repo_root=clone)
        assert any("rebuild" in p for p in problems), problems


def test_a_dirty_tracked_file_is_refused(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    (tmp_path / "repo" / "src" / "regista" / "__init__.py").write_bytes(b"# dirty\n")
    assert "uncommitted changes" in _verdict(d)


def test_a_staged_but_uncommitted_change_is_refused(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    repo = tmp_path / "repo"
    (repo / "src" / "regista" / "new.py").write_bytes(b"")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    assert "uncommitted changes" in _verdict(d)


def test_reviewed_bytes_are_the_committed_blob_not_the_disk(tmp_path: Path) -> None:
    """`assume-unchanged` hides a disk edit from `git status`; the guard still
    compares against the HEAD blob. An artifact matching the commit passes; one
    carrying the disk-only edit fails."""
    edit = b"# edited on disk only\n"

    def hide_edit(repo: Path) -> None:
        subprocess.run(["git", "-C", str(repo), "update-index", "--assume-unchanged",
                        "src/regista/__init__.py"], check=True)
        (repo / "src" / "regista" / "__init__.py").write_bytes(edit)

    committed = _dist(tmp_path / "committed")
    hide_edit(tmp_path / "committed" / "repo")
    assert _verdict(committed) == "pass"
    edited = _dist(tmp_path / "edited",
                   wheel=_wheel_bytes({**_wheel_files(BASE), "regista/__init__.py": edit}))
    hide_edit(tmp_path / "edited" / "repo")
    assert "differs from tracked" in _verdict(edited)


# --------------------------------------------------------------------------
# New-design round 5 (Daybreak B1/B2, DeepSeek B1-B3): replacement objects,
# modes, clean errors; the authoritative environment.


def _git_in(repo: Path, *args: str, input_: bytes | None = None) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], input=input_, capture_output=True,
                          check=True).stdout


def test_a_replacement_ref_is_refused_whatever_the_artifact(tmp_path: Path) -> None:
    """Round-5 repro: refs/replace/* made cat-file return bytes absent from HEAD."""
    edit = b"# replacement content\n"
    edited = _dist(tmp_path / "e",
                   wheel=_wheel_bytes({**_wheel_files(BASE), "regista/__init__.py": edit}))
    repo = tmp_path / "e" / "repo"
    orig = _git_in(repo, "rev-parse", "HEAD:src/regista/__init__.py").decode().strip()
    new = _git_in(repo, "hash-object", "-w", "--stdin", input_=edit).decode().strip()
    _git_in(repo, "replace", orig, new)
    assert "refs/replace" in _verdict(edited)
    pristine = _dist(tmp_path / "p")
    repo_p = tmp_path / "p" / "repo"
    orig_p = _git_in(repo_p, "rev-parse", "HEAD:src/regista/__init__.py").decode().strip()
    new_p = _git_in(repo_p, "hash-object", "-w", "--stdin", input_=edit).decode().strip()
    _git_in(repo_p, "replace", orig_p, new_p)
    assert "refs/replace" in _verdict(pristine)  # presence alone is refused


def test_reads_ignore_replacement_objects_even_if_the_refusal_were_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: with the presence check disabled, the guard still reads
    the raw HEAD blob (--no-replace-objects), so the edited artifact fails."""
    monkeypatch.setattr(guard, "_check_no_object_rewrites", lambda root: None)
    edit = b"# replacement content\n"
    d = _dist(tmp_path, wheel=_wheel_bytes({**_wheel_files(BASE), "regista/__init__.py": edit}))
    repo = tmp_path / "repo"
    orig = _git_in(repo, "rev-parse", "HEAD:src/regista/__init__.py").decode().strip()
    new = _git_in(repo, "hash-object", "-w", "--stdin", input_=edit).decode().strip()
    _git_in(repo, "replace", orig, new)
    assert "differs from tracked" in _verdict(d)


def test_a_grafts_file_is_refused(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "grafts").write_text("")
    assert "grafts" in _verdict(d)


def _wheel_with_mode(name: str, mode: int) -> bytes:
    files = dict(_wheel_files(BASE))
    data = files.pop(name)
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
    info.external_attr = mode << 16
    return _wheel_bytes(files, extra=[(info, data)], record_extra={name: data})


@pytest.mark.parametrize("mode", [0o100755, 0o100744, 0o100600, 0o100664])
def test_a_wheel_member_with_any_mode_but_0644_is_refused(tmp_path: Path, mode: int) -> None:
    """Round-5 repro: a 0755 member passed and pip preserved the executable bit."""
    assert "wheel members must be 0o644" in _verdict(
        _dist(tmp_path, wheel=_wheel_with_mode("regista/__init__.py", mode)))


def test_the_rebuild_binding_compares_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same names and bytes, different external attributes: refused."""
    direct = _wheel_bytes(_wheel_files(BASE))
    typeless = _wheel_with_mode("regista/__init__.py", 0o644)  # 0644 without S_IFREG
    d = _dist(tmp_path, wheel=direct)
    _stub_rebuilds(monkeypatch, typeless)
    problems = guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo")
    assert any("differs from the uv rebuild" in p for p in problems), problems


def test_an_executable_sdist_member_in_package_data_is_refused(tmp_path: Path) -> None:
    info = tarfile.TarInfo("r-0.0.0/src/regista/__init__.py")
    info.mode = 0o755
    files = dict(_sdist_files(BASE))
    files.pop("src/regista/__init__.py", None)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {"PKG-INFO": METADATA, "pyproject.toml": PYPROJECT, **files}.items():
            ti = tarfile.TarInfo(f"r-0.0.0/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        tf.addfile(info, io.BytesIO(b""))
    assert "is executable" in _verdict(_dist(tmp_path, sdist=buf.getvalue()))


def test_an_sdist_member_mode_must_match_the_committed_mode(tmp_path: Path) -> None:
    repo = _test_repo(tmp_path)
    (repo / "tool.sh").write_bytes(b"#!/bin/sh\n")
    (repo / "tool.sh").chmod(0o755)
    _git_commit_all(repo)
    plain = _sdist_with("tool.sh", b"#!/bin/sh\n")  # TarInfo default mode 0644
    assert "executable bit differs" in _verdict(_dist(tmp_path, sdist=plain))


def _encrypted(blob: bytes) -> bytes:
    raw = bytearray(blob)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = raw.find(sig)
        while i != -1:
            raw[i + off] |= 0x01
            i = raw.find(sig, i + 4)
    return bytes(raw)


def _corrupt_deflate() -> bytes:
    buf = io.BytesIO()
    files = _wheel_files(BASE)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data + b"x" * 64)
        lines = [f"{n},sha256={_record_digest(d)},{len(d)}" for n, d in files.items()]
        zf.writestr("r-0.0.0.dist-info/RECORD", "\n".join(lines) + "\n")
    raw = bytearray(buf.getvalue())
    first = zipfile.ZipFile(io.BytesIO(bytes(raw))).infolist()[0]
    start = first.header_offset + 30 + len(first.filename)
    raw[start : start + 4] = b"\xff\xff\xff\xff"
    return bytes(raw)


@pytest.mark.parametrize("kind", ["encrypted", "corrupt"])
def test_unreadable_members_are_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Round-5 DeepSeek B1 regression: RuntimeError/zlib.error escaped."""
    blob = _encrypted(_wheel_bytes(_wheel_files(BASE))) if kind == "encrypted" \
        else _corrupt_deflate()
    with pytest.raises(guard.GuardError):
        guard._wheel_members(blob, "w")
    with pytest.raises(guard.GuardError):
        guard.read_wheel(blob, "r-0.0.0-py3-none-any.whl")


def _clean_clone_with_current_guard(tmp_path: Path) -> Path:
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(REPO_ROOT), str(clone)], check=True)
    for rel in ("scripts/check_published_migrations.py",):
        (clone / rel).write_bytes((REPO_ROOT / rel).read_bytes())
    _git_commit_all(clone)
    return clone


@pytest.mark.parametrize("kind", ["encrypted", "corrupt"])
def test_the_cli_never_prints_a_traceback(tmp_path: Path, kind: str) -> None:
    clone = _clean_clone_with_current_guard(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    blob = _encrypted(_wheel_bytes(_wheel_files(BASE))) if kind == "encrypted" \
        else _corrupt_deflate()
    (dist / "regista_hraedon-0.7.2-py3-none-any.whl").write_bytes(blob)
    (dist / "regista_hraedon-0.7.2.tar.gz").write_bytes(_sdist_bytes(_sdist_files(BASE)))
    proc = subprocess.run(
        [sys.executable, str(clone / "scripts" / "check_published_migrations.py"),
         "check-dist", str(dist)],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr + proc.stdout
    lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith("ADVISORY"), proc.stderr


def _authoritative_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for k in list(os.environ):
        if k.startswith("GIT_"):
            monkeypatch.delenv(k)
    for k, v in guard.AUTHORITATIVE_GIT_ENV.items():
        monkeypatch.setenv(k, v)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))


def test_the_authoritative_environment_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _test_repo(tmp_path)
    _authoritative_env(monkeypatch, tmp_path)
    guard.check_authoritative_environment(repo)  # control: the right environment passes
    for key in guard.AUTHORITATIVE_GIT_ENV:
        with monkeypatch.context() as m:
            m.delenv(key)
            with pytest.raises(guard.GuardError, match=key):
                guard.check_authoritative_environment(repo)
    with monkeypatch.context() as m:
        m.setenv("GIT_DIR", str(repo / ".git"))
        with pytest.raises(guard.GuardError, match="inherited git variables"):
            guard.check_authoritative_environment(repo)
    with monkeypatch.context() as m:
        (tmp_path / "home" / ".gitconfig").write_text("")
        with pytest.raises(guard.GuardError, match="empty directory"):
            guard.check_authoritative_environment(repo)
        (tmp_path / "home" / ".gitconfig").unlink()
    shallow = tmp_path / "shallow"
    _git_commit_all(repo)
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
                   check=True, env={k: v for k, v in os.environ.items()})
    with pytest.raises(guard.GuardError, match="full-depth"):
        guard.check_authoritative_environment(shallow)


def test_check_dist_authoritative_flag_runs_the_environment_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _dist(tmp_path)
    monkeypatch.delenv("GIT_NO_REPLACE_OBJECTS", raising=False)
    with pytest.raises(guard.GuardError, match="authoritative mode requires"):
        guard.check_dist(_ledger(), d, {}, repo_root=tmp_path / "repo",
                         rebuild_sdists=False, authoritative=True)


# --------------------------------------------------------------------------
# Object-store integrity (Daybreak #82 round-6 B1): bytes from the store are
# re-hashed against the ID HEAD names; alternate stores are refused; the
# authoritative run fscks everything reachable from HEAD.

EDIT = b"# forged same-length\n"


def _forge_loose(objects: Path, sha: str, data: bytes) -> None:
    """Write `data` as a loose blob under the WRONG id `sha` (what Daybreak did)."""
    import zlib

    path = objects / sha[:2] / sha[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(zlib.compress(f"blob {len(data)}\0".encode() + data))


def _forged_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    """A dist carrying edited __init__ bytes, and a fixture repo whose loose
    object for HEAD's __init__ blob has been replaced by those bytes."""
    d = _dist(tmp_path, wheel=_wheel_bytes({**_wheel_files(BASE), "regista/__init__.py": EDIT}))
    repo = tmp_path / "repo"
    (repo / "src" / "regista" / "__init__.py").write_bytes(b"")
    sha = _git_in(repo, "rev-parse", "HEAD:src/regista/__init__.py").decode().strip()
    subprocess.run(["git", "-C", str(repo), "update-index", "--assume-unchanged",
                    "src/regista/__init__.py"], check=True)
    return d, repo, sha


def test_a_forged_loose_object_is_refused(tmp_path: Path) -> None:
    d, repo, sha = _forged_fixture(tmp_path)
    _forge_loose(repo / ".git" / "objects", sha, EDIT)
    # git itself serves the forged bytes...
    assert _git_in(repo, "cat-file", "blob", sha) == EDIT
    # ...the guard does not accept them.
    assert "does not hash to" in _verdict(d)


def test_a_forged_object_in_an_alternate_store_is_refused(tmp_path: Path) -> None:
    d, repo, sha = _forged_fixture(tmp_path)
    alt = tmp_path / "alt-objects"
    _forge_loose(alt, sha, EDIT)
    loose = repo / ".git" / "objects" / sha[:2] / sha[2:]
    loose.chmod(0o644)
    loose.unlink()
    (repo / ".git" / "objects" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "objects" / "info" / "alternates").write_text(f"{alt}\n")
    assert _git_in(repo, "cat-file", "blob", sha) == EDIT
    assert "alternate object stores are refused" in _verdict(d)


def test_an_alternates_file_is_refused_even_when_honest(tmp_path: Path) -> None:
    d = _dist(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git" / "objects" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "objects" / "info" / "alternates").write_text("")
    assert "alternate object stores are refused" in _verdict(d)


@pytest.mark.parametrize("var", ["GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_OBJECT_DIRECTORY"])
def test_object_store_environment_variables_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, var: str
) -> None:
    d = _dist(tmp_path)
    monkeypatch.setenv(var, str(tmp_path / "elsewhere"))
    assert "alternate object stores are refused" in _verdict(d)


def test_the_rehash_holds_even_if_the_presence_checks_were_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: with alternates allowed, the per-blob re-hash still
    refuses the alternate-store forgery."""
    monkeypatch.setattr(guard, "_check_no_object_rewrites", lambda root: None)
    d, repo, sha = _forged_fixture(tmp_path)
    alt = tmp_path / "alt-objects"
    _forge_loose(alt, sha, EDIT)
    loose = repo / ".git" / "objects" / sha[:2] / sha[2:]
    loose.chmod(0o644)
    loose.unlink()
    (repo / ".git" / "objects" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "objects" / "info" / "alternates").write_text(f"{alt}\n")
    assert "does not hash to" in _verdict(d)


def test_authoritative_fsck_refuses_a_forged_object_the_rehash_never_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fsck covers commits and trees (which ls-tree reads) and history; prove
    it independently by forging an object the blob re-hash does not touch:
    a blob only in history."""
    repo = _test_repo(tmp_path)
    (repo / "history.txt").write_bytes(b"old\n")
    _git_commit_all(repo)
    sha = _git_in(repo, "rev-parse", "HEAD:history.txt").decode().strip()
    (repo / "history.txt").unlink()
    _git_commit_all(repo)
    _forge_loose(repo / ".git" / "objects", sha, b"new\n")
    _authoritative_env(monkeypatch, tmp_path)
    with pytest.raises(guard.GuardError, match="fsck --strict failed"):
        guard.check_authoritative_environment(repo)


def test_object_ids_are_recomputed_for_sha1_and_sha256() -> None:
    assert guard._object_id("sha1", "blob", b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert guard._object_id("sha256", "blob", b"") == (
        "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
    )
    with pytest.raises(guard.GuardError):
        guard._object_id("md5", "blob", b"")


def test_a_sha256_repository_is_read_and_verified(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--object-format=sha256", str(repo)], check=True)
    (repo / "migrations").mkdir()
    (repo / "src" / "regista").mkdir(parents=True)
    (repo / "pyproject.toml").write_bytes(PYPROJECT)
    (repo / "src" / "regista" / "__init__.py").write_bytes(b"")
    for name, data in BASE.items():
        (repo / "src/regista" / name).write_bytes(data)
    (repo / "LICENSE").write_bytes(b"license\n")
    _git_commit_all(repo)
    tracked = guard._git_tracked_files(repo)
    assert tracked["src/regista/__init__.py"] == b""


@pytest.mark.parametrize("trailer", ["gzip", "raw", "tar-data", "tar-zero"])
def test_c1_sdist_envelope_refuses_trailers(trailer: str) -> None:
    import gzip

    blob = _sdist_bytes(_sdist_files(BASE), pkg_info=METADATA)
    if trailer == "gzip":
        blob += gzip.compress(b"unreviewed trailer", mtime=0)
    elif trailer == "raw":
        blob += b"unreviewed trailer"
    else:
        blob = gzip.compress(gzip.decompress(blob) +
                             (b"unreviewed trailer" if trailer == "tar-data" else b"\0" * 10240))
    with pytest.raises(guard.GuardError, match=r"gzip|tar envelope"):
        guard.read_sdist(blob, "r-0.0.0.tar.gz")


@pytest.mark.parametrize("field,value", [
    ("Name", "counterfeit"), ("Version", "9.9.9"), ("Summary", "altered"),
    ("Requires-Python", ">=99"), ("Requires-Dist", "counterfeit-dependency"),
    ("Classifier", "Counterfeit"), ("Project-URL", "Counterfeit, https://example.invalid"),
    ("Author-email", "counterfeit@example.invalid"), ("License", "Counterfeit"),
    ("License-File", "counterfeit.txt"), ("License-Expression", "Counterfeit"),
    ("Provides-Extra", "counterfeit"), ("Description-Content-Type", "text/plain"),
    ("Metadata-Version", "2.1"), ("Description", "altered readme"),
])
def test_c1_sdist_metadata_is_bound(tmp_path: Path, field: str, value: str) -> None:
    metadata = METADATA + f"{field}: {value}\n".encode()
    dist = _dist(tmp_path, sdist=_sdist_bytes(_sdist_files(BASE), pkg_info=metadata))
    with pytest.raises(guard.GuardError, match=r"PKG-INFO|metadata"):
        guard.check_dist(_ledger(), dist, repo_root=tmp_path / "repo", rebuild_sdists=False)


def test_c1_sdist_root_is_bound() -> None:
    blob = _sdist_bytes(_sdist_files(BASE), pkg_info=METADATA)
    # Naming correctness must apply even without repository binding.
    with pytest.raises(guard.GuardError, match=r"root|name|version"):
        guard.read_sdist(blob, "wrong-9.9.9.tar.gz")
