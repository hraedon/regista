"""Schema-baseline immutability and reviewed-artifact guard (GitHub #65).

Plan 032 F1 and D1 explicitly retire the pre-0.8 migration chain: extraction
establishes a fresh baseline, with no migration through trust-system schemas.
The old ledger is preserved under plans/032-f0-inventory/ as historical evidence.
It is not an allowlist for the new distribution. scripts/schema-baseline.json
pins the new schema and workflow resources, starting with baseline version 1.
Schema hashes are append-only pairs keyed by KERNEL_SCHEMA_VERSION. Full git
ancestry protects committed pairs before publication; verify-ledger and
check-release also bind every post-cutover published wheel to its pinned pair.
F4/F5 still own release version and publication.

check-dist retains the existing reviewed-tree byte binding, ZIP/tar/path/mode
checks, RECORD verification and exact pip/uv rebuild comparison. Only the
controlled full-clone CI environment may use --authoritative; ordinary local
runs are advisory. This guard protects artifacts, not runtime behavior or git
history. The pinned Hatch backend closure remains trusted executable build code.
"""

from __future__ import annotations

import argparse
import ast
import base64
import email.parser
import email.policy
import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import unicodedata
import urllib.request
import zipfile
import zlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO_ROOT / "scripts" / "schema-baseline.json"
PROJECT = "regista-hraedon"
LEDGER_FORMAT = 4
PYPI_JSON = f"https://pypi.org/pypi/{PROJECT}/json"
PREPUBLICATION_MESSAGE = "no published 0.8.x release yet; PyPI binding not applicable"

WHEEL_MIGRATIONS = "regista/"
SDIST_MIGRATIONS = "src/regista/"
FORBIDDEN_SOURCE_DIRS = ("migrations/", "src/regista/migrations/", "regista/migrations/")
SAFE_NAME = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*")

TRUSTED_BUILD_REQUIREMENTS = (
    "hatchling==1.32.4",
    "packaging==26.3",
    "pathspec==1.1.1",
    "pluggy==1.6.0",
    "tomlkit==0.15.1",
    "trove-classifiers==2026.9.21.13",
)
DIST_INFO_FILES = frozenset({"METADATA", "WHEEL", "RECORD", "entry_points.txt"})
UNIVERSAL_WHEEL_TAG = "py3-none-any"
REVIEWED_HATCH_CONFIG: Mapping[str, Any] = {
    "build": {
        "targets": {
            "wheel": {"packages": ["src/regista"]},
            "sdist": {
                "include": [
                    "/src/regista",
                    "/examples",
                    "/tests",
                    "/scripts",
                    "/githooks",
                    "/publication.toml",
                    "/pyproject.toml",
                    "/README.md",
                    "/LICENSE",
                    "/Makefile",
                    "/docker-compose.test.yml",
                    "/.github",
                ]
            },
        }
    }
}

FROZEN_HISTORICAL_VIOLATIONS: Mapping[str, frozenset[str]] = {}


class GuardError(Exception):
    """A violation. Raised for anything not on the allowlist."""


def _fold(s: str) -> str:
    return unicodedata.normalize("NFKC", s).casefold()


def _version_key(version: str) -> tuple[int, ...]:
    parts = version.split(".")
    if not all(p.isascii() and p.isdigit() for p in parts):
        raise GuardError(f"release version {version!r} is not a plain N.N.N release")
    return tuple(int(p) for p in parts)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# The member allowlist


WINDOWS_DEVICES = frozenset(
    ["con", "prn", "aux", "nul"] + [f"{d}{i}" for d in ("com", "lpt") for i in range(10)]
)


def _check_names(names: list[str], where: str, required_dirs: tuple[str, ...] = ()) -> None:
    """Every name is ASCII and canonical, no two collide when folded, and no
    regular member sits where a directory must be (an implied ancestor of another
    member, or one of ``required_dirs``)."""
    seen: dict[str, str] = {}
    for name in names:
        parts = name.split("/")
        if (
            not name.isascii()
            or SAFE_NAME.fullmatch(name) is None
            or unicodedata.normalize("NFC", name) != name
            or any(part in (".", "..") for part in parts)
            # Windows strips a trailing dot from a path segment, and maps device
            # names (with any extension) to devices.
            or any(part.endswith(".") for part in parts)
            or any(part.split(".", 1)[0].lower() in WINDOWS_DEVICES for part in parts)
        ):
            raise GuardError(f"{where}: member name {name!r} is not on the allowlist")
        key = _fold(name)
        if key in seen:
            raise GuardError(
                f"{where}: members {seen[key]!r} and {name!r} collide (same name, or the "
                "same path on a case- or Unicode-folding filesystem)"
            )
        seen[key] = name
    dirs = {_fold(d.rstrip("/")) for d in required_dirs}
    for name in names:
        parts = name.split("/")
        dirs.update(_fold("/".join(parts[:i])) for i in range(1, len(parts)))
    for name in names:
        if _fold(name) in dirs:
            raise GuardError(f"{where}: regular member {name!r} sits where a directory must be")


def _check_startup_executable(name: str, where: str) -> None:
    """Refuse names Python's site initialisation can execute automatically."""
    leaf = _fold(name.rsplit("/", 1)[-1])
    if leaf.endswith(".pth") or leaf in {"sitecustomize.py", "usercustomize.py"}:
        raise GuardError(f"{where}: startup-executable member {name!r} is not allowed")


def _normalize_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "_", value).lower()


def _wheel_filename(filename: str, where: str) -> tuple[str, str, str, str]:
    """Return normalized distribution, version, tag and dist-info directory."""
    name = Path(filename).name
    if not name.endswith(".whl"):
        raise GuardError(f"{where}: wheel filename {name!r} is not canonical")
    parts = name[:-4].split("-")
    if len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
    elif len(parts) == 6 and re.fullmatch(r"[0-9][A-Za-z0-9_]*", parts[2]):
        distribution, version, _build_tag, python_tag, abi_tag, platform_tag = parts
    else:
        raise GuardError(f"{where}: wheel filename {name!r} is not canonical")

    def normalized(component: str) -> str:
        return re.sub(r"[^A-Za-z0-9.]+", "_", component)

    tags = (python_tag, abi_tag, platform_tag)
    if (
        not distribution
        or not version
        or normalized(distribution) != distribution
        or normalized(version) != version
        or any(not tag or re.fullmatch(r"[A-Za-z0-9_.]+", tag) is None for tag in tags)
    ):
        raise GuardError(f"{where}: wheel filename {name!r} is not canonical")
    tag = "-".join(tags)
    if tag != UNIVERSAL_WHEEL_TAG:
        raise GuardError(f"{where}: wheel filename tag must be exactly {UNIVERSAL_WHEEL_TAG}")
    return distribution, version, tag, f"{distribution}-{version}.dist-info"


def _check_wheel_layout(names: list[str], dist_info: str, where: str) -> None:
    """Allow only package files and the filename-matched metadata directory."""
    prefix = f"{dist_info}/"
    for name in names:
        if name.startswith("regista/"):
            continue
        if name.startswith(prefix):
            rel = name[len(prefix) :]
            if rel in DIST_INFO_FILES or rel.startswith("licenses/"):
                continue
        raise GuardError(f"{where}: wheel member {name!r} is outside the allowed layout")


def _check_wheel_metadata(data: bytes, where: str) -> None:
    """Require install-critical WHEEL headers and the one supported tag."""
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GuardError(f"{where}: WHEEL metadata is not ASCII") from exc
    headers: dict[str, list[str]] = {}
    header_block_ended = False
    for line in lines:
        if not line:
            header_block_ended = True
            continue
        if header_block_ended:
            raise GuardError(f"{where}: WHEEL contains content after its header block")
        key, separator, value = line.partition(":")
        if not separator or not key:
            raise GuardError(f"{where}: WHEEL contains a malformed header line")
        headers.setdefault(key.casefold(), []).append(value.strip())
    if headers.get("wheel-version") != ["1.0"]:
        raise GuardError(f"{where}: WHEEL must contain exactly Wheel-Version: 1.0")
    if headers.get("root-is-purelib") != ["true"]:
        raise GuardError(f"{where}: WHEEL must contain exactly Root-Is-Purelib: true")
    if headers.get("tag") != [UNIVERSAL_WHEEL_TAG]:
        raise GuardError(f"{where}: WHEEL Tag lines must be exactly {UNIVERSAL_WHEEL_TAG}")


def _metadata_identity(data: bytes, where: str) -> tuple[str, str]:
    try:
        metadata = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(data)
    except Exception as exc:
        raise GuardError(f"{where}: malformed METADATA ({exc.__class__.__name__})") from exc
    names = metadata.get_all("Name", [])
    versions = metadata.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0]:
        raise GuardError(f"{where}: METADATA must contain exactly one Name and Version")
    return str(names[0]), str(versions[0])


def _project_identity(data: Mapping[str, Any], where: str) -> tuple[str, str]:
    project = data.get("project")
    if not isinstance(project, dict):
        raise GuardError(f"{where}: [project] must be a table")
    if "dynamic" in project:
        raise GuardError(f"{where}: [project] must not contain dynamic")
    name, version = project.get("name"), project.get("version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise GuardError(f"{where}: [project] name and version must be literal strings")
    return name, version


BASELINE_FILES = frozenset({"schema.sql", "workflow.schema.json"})


def _classify(rel: str, migrations_dir: str, where: str, *, sql_elsewhere: bool) -> str | None:
    for retired in FORBIDDEN_SOURCE_DIRS:
        if _fold(rel).startswith(_fold(retired)):
            raise GuardError(f"{where}: retired migration path {rel!r}")
    for name in BASELINE_FILES:
        expected = migrations_dir + name
        if _fold(rel) == _fold(expected):
            if rel != expected:
                raise GuardError(f"{where}: noncanonical baseline path {rel!r}")
            return name
    if rel.lower().endswith(".sql"):
        raise GuardError(f"{where}: {rel!r} is SQL outside the baseline")
    return None


def _check_zip_container(blob: bytes, infos: list[zipfile.ZipInfo], where: str) -> None:
    """One canonical archive, read the same way by every unzip implementation.

    The byte stream must be exactly: local records laid end to end from offset 0,
    then the central directory, then one 22-byte end-of-central-directory record
    with no comment. There must be no preamble, no second archive, no gap or
    overlap, no data descriptor, and no extra field in any header (which also
    rules out ZIP64 and Info-ZIP Unicode Path names).
    """
    eocd = blob[-22:]
    if len(blob) < 22 or eocd[:4] != b"PK\x05\x06":
        raise GuardError(f"{where}: no end-of-central-directory record at the very end")
    disk, cd_disk, n_disk, n_total, cd_size, cd_off, comment_len = struct.unpack(
        "<HHHHIIH", eocd[4:]
    )
    if (disk, cd_disk, comment_len) != (0, 0, 0) or not n_disk == n_total == len(infos):
        raise GuardError(f"{where}: non-canonical end-of-central-directory record")
    if cd_off + cd_size != len(blob) - 22:
        raise GuardError(f"{where}: central directory does not end at the EOCD record")
    expected = 0
    for info in sorted(infos, key=lambda i: i.header_offset):
        if info.header_offset != expected:
            raise GuardError(
                f"{where}: {info.orig_filename!r} is not contiguous (preamble, gap or overlap)"
            )
        too_big = max(info.file_size, info.compress_size) >= 0xFFFFFFFF
        if info.flag_bits & 0x08 or too_big:
            raise GuardError(f"{where}: {info.orig_filename!r} uses a data descriptor or ZIP64")
        (sig, _ver, flags, method, _t, _d, crc, csize, usize, name_len, extra_len) = struct.unpack(
            "<4sHHHHHIIIHH", blob[expected : expected + 30]
        )
        # A streaming unzipper trusts the LOCAL header; it must say exactly what
        # the central directory says.
        if (
            sig != b"PK\x03\x04"
            or (flags, method, crc, csize, usize)
            != (info.flag_bits, info.compress_type, info.CRC, info.compress_size, info.file_size)
            or blob[expected + 30 : expected + 30 + name_len] != info.orig_filename.encode()
        ):
            raise GuardError(
                f"{where}: {info.orig_filename!r} local header disagrees with the central directory"
            )
        # No extra field in either header: none of our wheels carries one, and
        # they are where ZIP64 sizes and alternate (Unicode Path) names live.
        if info.extra or extra_len:
            raise GuardError(f"{where}: {info.orig_filename!r} carries a ZIP extra field")
        expected += 30 + name_len + extra_len + info.compress_size
    if expected != cd_off:
        raise GuardError(f"{where}: bytes between the last record and the central directory")


#: The git environment the guard requires in AUTHORITATIVE mode, and always
#: imposes on its own git invocations: replacement objects off, no system or
#: global config, an empty HOME, and no other inherited GIT_* variable.
AUTHORITATIVE_GIT_ENV = {
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}

#: Wheel members are package data. None may carry an executable bit; this
#: allowlist of wheel paths that may is deliberately empty.
EXECUTABLE_WHEEL_MEMBERS: frozenset[str] = frozenset()
WHEEL_MEMBER_MODE = 0o644


def _git_env() -> dict[str, str]:
    """Environment for every git call the guard makes: an allowlist, not a filter."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "TZ")}
    env.update(AUTHORITATIVE_GIT_ENV)
    env["HOME"] = _EMPTY_HOME
    return env


_EMPTY_HOME = tempfile.mkdtemp(prefix="regista-guard-home-")


def check_authoritative_environment(repo_root: Path) -> None:
    """Refuse to give an AUTHORITATIVE verdict unless the process itself runs in
    the controlled environment (not just the guard's own git calls): the three
    variables set exactly, HOME an existing empty directory, no other GIT_*
    variable inherited, a full-depth clone, and no replacement refs or grafts."""
    for key, value in AUTHORITATIVE_GIT_ENV.items():
        if os.environ.get(key) != value:
            raise GuardError(f"authoritative mode requires {key}={value}")
    extra = sorted(k for k in os.environ if k.startswith("GIT_") and k not in AUTHORITATIVE_GIT_ENV)
    if extra:
        raise GuardError(f"authoritative mode refuses inherited git variables {extra}")
    home = os.environ.get("HOME", "")
    if not home or not Path(home).is_dir() or any(Path(home).iterdir()):
        raise GuardError("authoritative mode requires HOME to be an existing empty directory")
    if _git(repo_root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise GuardError(f"{repo_root}: authoritative mode requires a full-depth clone")
    _check_no_object_rewrites(repo_root.resolve())
    _check_object_store_integrity(repo_root.resolve())


def _git_path_exists(root: Path, rel: str) -> bool:
    path = _git(root, "rev-parse", "--git-path", rel).decode().strip()
    return (root / path).exists() or Path(path).exists()


#: Environment variables that point git at another object store.
OBJECT_STORE_ENV = ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_OBJECT_DIRECTORY")


def _check_no_object_rewrites(root: Path) -> None:
    """Replacement refs, grafts and alternate object stores make git return
    objects other than the ones the commit names, or from somewhere other than
    this repository. Their mere presence is refused, in every mode."""
    if _git(root, "for-each-ref", "--format=%(refname)", "refs/replace/"):
        raise GuardError(f"{root}: refs/replace/* exists; replacement objects are refused")
    if _git_path_exists(root, "info/grafts"):
        raise GuardError(f"{root}: a grafts file exists; grafted history is refused")
    for alt in ("objects/info/alternates", "objects/info/http-alternates"):
        if _git_path_exists(root, alt):
            raise GuardError(f"{root}: {alt} exists; alternate object stores are refused")
    present = [k for k in OBJECT_STORE_ENV if k in os.environ]
    if present:
        raise GuardError(f"{root}: {present} set; alternate object stores are refused")


def _object_id(fmt: str, kind: str, data: bytes) -> str:
    """The git object ID of ``data``, recomputed: ``<kind> <len>\\0<data>``."""
    if fmt not in ("sha1", "sha256"):
        raise GuardError(f"unsupported git object format {fmt!r}")
    return hashlib.new(fmt, f"{kind} {len(data)}\0".encode() + data).hexdigest()


def _check_object_store_integrity(root: Path) -> None:
    """AUTHORITATIVE only: every object reachable from HEAD (commit, trees,
    blobs, history) hashes to its ID. Covers the trees ls-tree reads, which
    the per-blob re-hash does not."""
    try:
        proc = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                str(root),
                "fsck",
                "--strict",
                "--no-dangling",
                "--no-progress",
                "HEAD",
            ],
            capture_output=True,
            check=False,
            env=_git_env(),
        )
    except OSError as exc:
        raise GuardError(f"{root}: cannot run git fsck ({exc.__class__.__name__})") from exc
    if proc.returncode != 0:
        first = (proc.stderr or proc.stdout).decode(errors="replace").strip().splitlines()[:1]
        raise GuardError(f"{root}: git fsck --strict failed: {first}")


def _git(root: Path, *args: str) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *args],
            capture_output=True,
            check=False,
            env=_git_env(),
        )
    except OSError as exc:
        raise GuardError(f"{root}: cannot run git ({exc.__class__.__name__})") from exc
    if proc.returncode != 0:
        raise GuardError(f"{root}: git {args[0]} failed")
    return proc.stdout


class Tracked(dict[str, bytes]):
    """Committed HEAD blobs by path, plus their git tree modes in ``modes``."""

    modes: dict[str, str]


def _git_tracked_files(repo_root: Path) -> Tracked:
    """The reviewed bytes: every regular file of the COMMITTED tree at HEAD.

    "Reviewed" means committed, not merely tracked: a working tree with any staged
    or unstaged change to a tracked file is refused, and member bytes are compared
    with the HEAD blobs, never with the files on disk. Symlinks and submodules in
    the tree are not reviewed bytes and are omitted (so a member that maps to one
    is refused as untracked).
    """
    root = repo_root.resolve()
    top = _git(root, "rev-parse", "--show-toplevel").decode().strip()
    if Path(top).resolve() != root:
        raise GuardError(f"{repo_root}: repo_root must be the root of a Git checkout")
    _check_no_object_rewrites(root)
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no"):
        raise GuardError(
            f"{repo_root}: the working tree has uncommitted changes to tracked files; "
            "reviewed bytes are the committed tree, so commit or discard them first"
        )
    listing = _git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    blobs: dict[str, str] = {}
    modes: dict[str, str] = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, _, path_bytes = entry.partition(b"\t")
        mode, kind, sha = meta.decode().split()
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GuardError(f"{repo_root}: a tracked path is not UTF-8") from exc
        if kind == "blob" and mode in ("100644", "100755"):
            blobs[path] = sha
            modes[path] = mode
    if not blobs:
        raise GuardError(f"{repo_root}: HEAD has no tracked files")
    batch = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), "cat-file", "--batch"],
        input="".join(f"{sha}\n" for sha in blobs.values()).encode(),
        capture_output=True,
        check=False,
        env=_git_env(),
    )
    if batch.returncode != 0:
        raise GuardError(f"{repo_root}: git cat-file failed")
    fmt = _git(root, "rev-parse", "--show-object-format").decode().strip()
    out = Tracked()
    out.modes = modes
    stream, pos = batch.stdout, 0
    for path, sha in blobs.items():
        header_end = stream.index(b"\n", pos)
        got_sha, kind, size = stream[pos:header_end].decode().split()
        if got_sha != sha or kind != "blob":
            raise GuardError(f"{repo_root}: git cat-file returned an unexpected object")
        start = header_end + 1
        data = stream[start : start + int(size)]
        # Never trust the store: a loose object can sit under an ID it does not
        # hash to (round-6 review). Recompute the ID from the bytes returned.
        if _object_id(fmt, "blob", data) != sha:
            raise GuardError(
                f"{repo_root}: object for {path!r} does not hash to {sha}; "
                "the object store is corrupt or forged"
            )
        out[path] = data
        pos = start + int(size) + 1
    return out


def _reviewed_bytes(repo_root: Path, tracked: Mapping[str, bytes], rel: str, where: str) -> bytes:
    if rel not in tracked:
        raise GuardError(f"{where}: source {rel!r} is not tracked by Git")
    return tracked[rel]


def read_wheel(
    blob: bytes,
    where: str,
    *,
    wheel_filename: str | None = None,
    repo_root: Path | None = None,
    tracked: Mapping[str, bytes] | None = None,
    project_identity: tuple[str, str] | None = None,
) -> dict[str, str]:
    """Allowlisted wheel -> {migration filename: sha256}."""
    try:
        return _read_wheel(
            blob,
            where,
            wheel_filename or where,
            repo_root=repo_root,
            tracked=tracked,
            project_identity=project_identity,
        )
    except GuardError:
        raise
    # zipfile exposes several implementation-specific read failures (including
    # NotImplementedError for an unsupported compression method). At this trust
    # boundary every malformed/unreadable archive is one fail-closed GuardError.
    except Exception as exc:
        raise GuardError(f"{where}: unreadable wheel ({exc.__class__.__name__}: {exc})") from exc


def _read_wheel(
    blob: bytes,
    where: str,
    wheel_filename: str,
    *,
    repo_root: Path | None,
    tracked: Mapping[str, bytes] | None,
    project_identity: tuple[str, str] | None,
) -> dict[str, str]:
    out: dict[str, str] = {}
    filename_dist, filename_version, _filename_tag, dist_info = _wheel_filename(
        wheel_filename, where
    )
    if (repo_root is None) != (tracked is None):
        raise GuardError(f"{where}: reviewed-tree arguments are incomplete")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        infos = zf.infolist()
        _check_zip_container(blob, infos, where)
        # orig_filename is the central-directory name before zipfile truncates it
        # at NUL; judging the truncated ``filename`` would accept a string other
        # unzip implementations read differently (found by the property fuzz).
        # zf.read() below also refuses a local header whose name differs from it.
        names = [i.orig_filename for i in infos]
        _check_names(names, where, (WHEEL_MIGRATIONS,))
        for name in names:
            _check_startup_executable(name, where)
        _check_wheel_layout(names, dist_info, where)
        for info in infos:
            if info.orig_filename != info.filename:
                raise GuardError(f"{where}: member name {info.orig_filename!r} is not canonical")
        files: dict[str, bytes] = {}
        for info in infos:
            mode = info.external_attr >> 16
            # A mode with no file-type bits (hatch writes 0o644 for some
            # dist-info members) is a regular file to every installer.
            if info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise GuardError(f"{where}: {info.filename!r} is not a regular file")
            perm = stat.S_IMODE(mode)
            if info.filename in EXECUTABLE_WHEEL_MEMBERS:
                pass
            elif perm != WHEEL_MEMBER_MODE:
                raise GuardError(
                    f"{where}: {info.filename!r} has mode {perm:#o}; wheel members must be "
                    f"{WHEEL_MEMBER_MODE:#o} (no executable bit)"
                )
            files[info.filename] = zf.read(info)
        required_metadata = {
            name: f"{dist_info}/{name}" for name in ("METADATA", "WHEEL", "RECORD")
        }
        missing_metadata = [name for name, path in required_metadata.items() if path not in files]
        if missing_metadata:
            raise GuardError(f"{where}: required metadata is missing: {missing_metadata}")
        _check_wheel_metadata(files[required_metadata["WHEEL"]], where)
        metadata_name, metadata_version = _metadata_identity(
            files[required_metadata["METADATA"]], where
        )
        if (
            _normalize_distribution(metadata_name) != _normalize_distribution(filename_dist)
            or metadata_version != filename_version
        ):
            raise GuardError(f"{where}: wheel filename and METADATA Name/Version differ")
        if project_identity is not None:
            project_name, project_version = project_identity
            if (
                _normalize_distribution(filename_dist) != _normalize_distribution(project_name)
                or filename_version != project_version
            ):
                raise GuardError(f"{where}: wheel filename differs from [project] name/version")
        for name, data in files.items():
            mig = _classify(name, WHEEL_MIGRATIONS, where, sql_elsewhere=False)
            if mig is not None:
                out[mig] = _sha(data)
            if repo_root is not None and tracked is not None and name.startswith("regista/"):
                package_rel = name[len("regista/") :]
                source_rel = f"src/regista/{package_rel}"
                if data != _reviewed_bytes(repo_root, tracked, source_rel, where):
                    raise GuardError(f"{where}: {name!r} differs from tracked {source_rel!r}")
            license_prefix = f"{dist_info}/licenses/"
            if repo_root is not None and tracked is not None and name.startswith(license_prefix):
                license_name = name[len(license_prefix) :]
                if "/" in license_name or not license_name:
                    raise GuardError(f"{where}: license path {name!r} is not a root filename")
                if data != _reviewed_bytes(repo_root, tracked, license_name, where):
                    raise GuardError(f"{where}: {name!r} differs from tracked {license_name!r}")
        record_path = required_metadata["RECORD"]
        listed: dict[str, tuple[str, str]] = {}
        try:
            record_lines = files[record_path].decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise GuardError(f"{where}: RECORD is not ASCII") from exc
        for line in record_lines:
            parts = line.rsplit(",", 2)
            if len(parts) != 3 or not parts[0] or parts[0] in listed:
                raise GuardError(f"{where}: RECORD contains a malformed or duplicate row")
            listed[parts[0]] = (parts[1], parts[2])
        if set(listed) != set(files):
            raise GuardError(f"{where}: RECORD must list every wheel member exactly once")
        for name, data in files.items():
            digest, size = listed[name]
            if name == record_path:
                if digest or size:
                    raise GuardError(f"{where}: RECORD's self-row must have empty hash and size")
                continue
            expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if digest != f"sha256={expected}" or size != str(len(data)):
                raise GuardError(f"{where}: RECORD does not vouch for {name!r} with its bytes")
    return out


def read_sdist(
    blob: bytes,
    where: str,
    *,
    repo_root: Path | None = None,
    tracked: Mapping[str, bytes] | None = None,
) -> dict[str, str]:
    """Allowlisted sdist -> {migration filename: sha256}."""
    try:
        return _read_sdist(blob, where, repo_root=repo_root, tracked=tracked)
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        raise GuardError(f"{where}: unreadable sdist ({exc.__class__.__name__}: {exc})") from exc


def sdist_file(blob: bytes, rel: str) -> bytes | None:
    """The bytes of ``<root>/<rel>`` in an (already allowlisted) sdist, or None."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.name.split("/", 1)[-1] == rel and m.name.count("/") == rel.count("/") + 1:
                fh = tf.extractfile(m)
                return fh.read() if fh is not None else None
    return None


_SDIST_PACKAGE_DIRS = ("src/regista/",)
_SDIST_MTIME = 1580601600  # Hatchling's reproducible default, not wall-clock time.


def _sdist_tar(blob: bytes, where: str) -> bytes:
    """Exactly one ordinary gzip member, containing one canonical tar envelope."""
    if len(blob) < 18 or blob[:4] != b"\x1f\x8b\x08\x00":
        raise GuardError(f"{where}: noncanonical gzip header")
    decoder = zlib.decompressobj(31)
    try:
        raw = decoder.decompress(blob) + decoder.flush()
    except zlib.error as exc:
        raise GuardError(f"{where}: invalid gzip member") from exc
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise GuardError(f"{where}: gzip must contain exactly one complete member and no trailer")
    encoded = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=encoded,
                       compresslevel=9, mtime=_SDIST_MTIME) as stream:
        stream.write(raw)
    if encoded.getvalue() != blob:
        raise GuardError(f"{where}: noncanonical gzip encoding (qualified level 9/header required)")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        end = 0
        for member in tf.getmembers():
            if member.offset != end or member.offset_data != end + 512:
                raise GuardError(f"{where}: unexpected header outside the tar envelope")
            end = member.offset_data + ((member.size + 511) // 512) * 512
            if any(raw[member.offset_data + member.size:end]):
                raise GuardError(f"{where}: nonzero file padding in tar envelope")
            if raw[member.offset:member.offset_data] != member.tobuf(format=tarfile.USTAR_FORMAT):
                raise GuardError(f"{where}: noncanonical tar envelope header")
            if member.uid or member.gid or member.uname or member.gname:
                raise GuardError(f"{where}: unexpected ownership fields in tar envelope")
            if (member.mtime != _SDIST_MTIME or member.mode not in (0o644, 0o755)
                    or member.type != tarfile.REGTYPE or member.linkname
                    or member.devmajor or member.devminor):
                raise GuardError(f"{where}: noncanonical tar envelope metadata")
        # Two zero end-of-archive blocks followed only by the required record padding.
        expected_length = ((end + 1024 + 10239) // 10240) * 10240
        if len(raw) != expected_length or any(raw[end:]):
            raise GuardError(f"{where}: bytes outside the canonical tar envelope")
    return raw


def _read_sdist(
    blob: bytes,
    where: str,
    *,
    repo_root: Path | None,
    tracked: Mapping[str, bytes] | None,
) -> dict[str, str]:
    out: dict[str, str] = {}
    if (repo_root is None) != (tracked is None):
        raise GuardError(f"{where}: reviewed-tree arguments are incomplete")
    with tarfile.open(fileobj=io.BytesIO(_sdist_tar(blob, where)), mode="r:") as tf:
        members = tf.getmembers()
        if tf.pax_headers or any(m.pax_headers for m in members):
            raise GuardError(f"{where}: PAX extended headers can rename members; refused")
        roots = {m.name.split("/", 1)[0] for m in members}
        if len(roots) != 1 or any("/" not in m.name for m in members):
            raise GuardError(f"{where}: expected one top-level directory, found {sorted(roots)}")
        root = next(iter(roots))
        pkg_info = [m for m in members if m.name == f"{root}/PKG-INFO"]
        if len(pkg_info) != 1 or not pkg_info[0].isfile():
            raise GuardError(f"{where}: PKG-INFO must exist exactly once as a regular file")
        fh = tf.extractfile(pkg_info[0])
        assert fh is not None
        name, version = _metadata_identity(fh.read(), f"{where}: PKG-INFO")
        expected_root = f"{_normalize_distribution(name)}-{version}"
        if root != expected_root or (where.endswith(".tar.gz") and
                                    Path(where).name != expected_root + ".tar.gz"):
            raise GuardError(f"{where}: sdist root/name/version differ from PKG-INFO")
        _check_names(
            [m.name for m in members],
            where,
            tuple(f"{root}/{d}" for d in (SDIST_MIGRATIONS, *FORBIDDEN_SOURCE_DIRS)),
        )
        for m in members:
            if not m.isfile():
                raise GuardError(f"{where}: {m.name!r} is not a regular file (type {m.type!r})")
            rel = m.name.split("/", 1)[1]
            _check_startup_executable(rel, where)
            fh = tf.extractfile(m)
            assert fh is not None
            data = fh.read()
            executable = bool(m.mode & 0o111)
            if executable and rel.startswith((SDIST_MIGRATIONS, *_SDIST_PACKAGE_DIRS)):
                raise GuardError(
                    f"{where}: {rel!r} is executable; migrations and package data may not be"
                )
            if repo_root is not None and tracked is not None and rel != "PKG-INFO":
                if data != _reviewed_bytes(repo_root, tracked, rel, where):
                    raise GuardError(f"{where}: {rel!r} differs from its tracked source")
                committed_exec = getattr(tracked, "modes", {}).get(rel) == "100755"
                if executable != committed_exec:
                    raise GuardError(
                        f"{where}: {rel!r} executable bit differs from the committed tree mode"
                    )
            elif rel == "PKG-INFO" and executable:
                raise GuardError(f"{where}: PKG-INFO is executable")
            mig = _classify(rel, SDIST_MIGRATIONS, where, sql_elsewhere=True)
            if mig is not None:
                out[mig] = _sha(data)
    return out


# --------------------------------------------------------------------------
# Ledger


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    ledger: dict[str, Any] = json.loads(path.read_text())
    if check_ledger(ledger):
        raise GuardError(f"{path}: invalid baseline manifest")
    return ledger


def check_ledger(
    ledger: Mapping[str, Any],
    frozen: Mapping[str, frozenset[str]] | None = None,
) -> list[str]:
    expected_keys = {"format", "project", "source", "baseline_version", "baseline",
                     "schema_versions"}
    if (
        set(ledger) != expected_keys
        or ledger.get("format") != LEDGER_FORMAT
        or ledger.get("project") != PROJECT
        or type(ledger.get("baseline_version")) is not int
        or ledger["baseline_version"] < 1
    ):
        return ["unrecognized baseline manifest format/project/version"]
    baseline = ledger.get("baseline")
    if (
        not isinstance(baseline, dict)
        or set(baseline) != BASELINE_FILES
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
            for v in baseline.values()
        )
    ):
        return ["baseline must pin exactly schema.sql and workflow.schema.json"]
    pairs = ledger.get("schema_versions")
    if (not isinstance(pairs, dict) or not pairs
        or any(not re.fullmatch(r"[1-9][0-9]*", v)
               or not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h)
               for v, h in pairs.items())):
        return ["schema_versions must contain positive version / SHA256 pairs"]
    if pairs.get(str(ledger["baseline_version"])) != baseline["schema.sql"]:
        return ["selected baseline version/hash does not match a schema_versions entry"]
    if max(map(int, pairs)) != ledger["baseline_version"]:
        return ["a new schema pin requires the current kernel version to bump with it"]
    return []


def kernel_version(code: bytes, where: str) -> int:
    """Read a literal version without executing the package being inspected."""
    versions = []
    for node in ast.parse(code).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "KERNEL_SCHEMA_VERSION" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            if type(value) is not int or value < 1:
                raise GuardError(f"{where}: kernel version must be a positive literal integer")
            versions.append(value)
    if len(versions) != 1:
        raise GuardError(f"{where}: exactly one kernel schema version is required")
    return versions[0]


def check_pin_history(ledger: Mapping[str, Any], repo_root: Path = REPO_ROOT) -> list[str]:
    """Previously committed pairs are append-only, including the F1 v1 pin.

    Full ancestry is mandatory for this check; a shallow checkout cannot supply
    the pre-publication immutability evidence. Git replacements/alternate stores
    are refused and historical blobs are rehashed, as in the artifact guard.
    Once published, verify-ledger independently binds pairs to PyPI bytes.
    """
    _check_no_object_rewrites(repo_root)
    if _git(repo_root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise GuardError("schema pin history requires a full-depth checkout")
    revisions = _git(
        repo_root, "log", "--format=%H", "--", "scripts/schema-baseline.json"
    ).decode().splitlines()
    if not revisions:
        raise GuardError("schema pin history has no committed baseline")
    problems = []
    for revision in revisions:
        oid = _git(
            repo_root, "rev-parse", f"{revision}:scripts/schema-baseline.json"
        ).decode().strip()
        blob = _git(repo_root, "cat-file", "blob", oid)
        if _object_id(_git(repo_root, "rev-parse", "--show-object-format").decode().strip(),
                      "blob", blob) != oid:
            raise GuardError("historical pin blob does not match its object ID")
        old = json.loads(blob)
        pairs = old.get("schema_versions")
        if pairs is None and old.get("format") == 3:
            pairs = {str(old["baseline_version"]): old["baseline"]["schema.sql"]}
        for version, digest in (pairs or {}).items():
            if ledger["schema_versions"].get(version) != digest:
                problems.append(f"kernel schema version {version} is immutable; "
                                "changed or removed a committed pair; bump the version "
                                "and append a new pin entry")
    return sorted(set(problems))


def verify_baseline(ledger: Mapping[str, Any], repo_root: Path = REPO_ROOT) -> list[str]:
    problems = check_tree(ledger, repo_root)
    if not check_ledger(ledger):
        problems += check_pin_history(ledger, repo_root)
    return problems


def expected_migrations(ledger: Mapping[str, Any]) -> dict[str, str]:
    return dict(ledger["baseline"])


def _compare(actual: Mapping[str, str], expected: Mapping[str, str], where: str) -> list[str]:
    problems = []
    for name in sorted(set(expected) - set(actual)):
        problems.append(f"{where}: missing baseline resource {name}")
    for name in sorted(set(actual) - set(expected)):
        problems.append(f"{where}: undeclared baseline resource {name}")
    for name in sorted(set(actual) & set(expected)):
        if actual[name] != expected[name]:
            problems.append(f"{where}: {name} bytes differ from the ledger")
    return problems


# --------------------------------------------------------------------------
# Checks


#: Each frontend runs in a fresh environment containing the hash-locked closure.
REBUILDERS: list[tuple[str, list[str]]] = [
    ("uv", ["uv", "build", "--python", "{python}", "--no-build-isolation",
            "--wheel", "--out-dir", "{out}", "{sdist}"]),
    ("pip", ["{python}", "-m", "pip", "wheel", "--no-build-isolation",
             "--no-deps", "--wheel-dir", "{out}", "{sdist}"]),
]


def _rebuild(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
    # Keep uv's cache out of the reviewed checkout and artifact directory. A
    # caller-level UV_CACHE_DIR inside the source tree would otherwise mutate
    # the very input this guard is authenticating.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["UV_CACHE_DIR"] = str(out / ".uv-cache")
    python = out / ".build-env" / "bin" / "python"
    for preparation in (
        ["uv", "venv", "--python", sys.executable, str(python.parent.parent)],
        ["uv", "pip", "install", "--python", str(python), "--require-hashes",
         "-r", str(REPO_ROOT / ".github/build-requirements.txt")],
    ):
        proc = subprocess.run(preparation, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise GuardError(f"{sdist.name}: {label} could not install hash-locked build tools")
    cmd = [a.format(out=out, sdist=sdist, python=python) for a in argv]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise GuardError(f"{sdist.name}: {label} could not build a wheel from it")
    wheels = sorted(out.glob("*.whl"))
    if len(wheels) != 1:
        raise GuardError(f"{sdist.name}: {label} produced {len(wheels)} wheels")
    return wheels[0]


def _wheel_members(blob: bytes, where: str) -> dict[str, str]:
    """{name: "<sha256> <mode>"}: rebuild equality covers content AND the
    external attributes installers apply (round-5: a 0755 mode passed)."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return {
                i.orig_filename: f"{_sha(zf.read(i))} {i.external_attr >> 16:o}"
                for i in zf.infolist()
            }
    except Exception as exc:  # any read failure is one fail-closed verdict
        raise GuardError(f"{where}: unreadable wheel ({exc.__class__.__name__})") from exc


def check_build_contract(pyproject: bytes, where: str) -> tuple[str, str]:
    """The build uses one named, frozen, trusted executable closure.

    Build requirements are not inert. Their exact string set must equal
    ``TRUSTED_BUILD_REQUIREMENTS``; the backend is hatchling with no
    ``backend-path``; and Hatch has exactly the reviewed static build table.
    """
    try:
        data = tomllib.loads(pyproject.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise GuardError(f"{where}: pyproject.toml is not valid UTF-8 TOML") from exc
    bs = data.get("build-system", {})
    if bs.get("build-backend") != "hatchling.build" or "backend-path" in bs:
        raise GuardError(f"{where}: build backend must be hatchling.build, no backend-path")
    reqs = bs.get("requires", [])
    if (
        not isinstance(reqs, list)
        or not all(isinstance(requirement, str) for requirement in reqs)
        or len(reqs) != len(TRUSTED_BUILD_REQUIREMENTS)
        or set(reqs) != set(TRUSTED_BUILD_REQUIREMENTS)
    ):
        raise GuardError(
            f"{where}: build-system.requires must equal the trusted frozen requirement set"
        )
    tool = data.get("tool", {})
    hatch = tool.get("hatch") if isinstance(tool, dict) else None
    if hatch != REVIEWED_HATCH_CONFIG:
        raise GuardError(f"{where}: [tool.hatch] must equal the reviewed static build table")
    return _project_identity(data, where)


def check_dist(
    ledger: Mapping[str, Any],
    dist_dir: Path,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
    *,
    repo_root: Path = REPO_ROOT,
    rebuild_sdists: bool = True,
    authoritative: bool = False,
) -> list[str]:
    if authoritative:
        check_authoritative_environment(repo_root)
    problems = check_ledger(ledger, frozen)
    tracked = _git_tracked_files(repo_root)
    pyproject = _reviewed_bytes(repo_root, tracked, "pyproject.toml", "pyproject.toml")
    project_identity = check_build_contract(pyproject, "pyproject.toml")
    for config in ("hatch.toml", "hatch_build.py"):
        if (repo_root / config).exists():
            raise GuardError(f"{config} must not exist: it can change what hatch builds")
    expected = expected_migrations(ledger)
    try:
        entries = sorted(dist_dir.iterdir())
    except OSError as exc:
        raise GuardError(f"{dist_dir}: cannot read distribution directory ({exc})") from exc
    non_files = [p.name for p in entries if p.is_symlink() or not p.is_file()]
    if non_files:
        raise GuardError(f"{dist_dir}: every entry must be a regular file; found {non_files}")
    wheels = [p for p in entries if p.name.endswith(".whl")]
    sdists = [p for p in entries if p.name.endswith(".tar.gz")]
    # `uv build` drops a one-byte `*` .gitignore into its out-dir; nothing else
    # may sit beside the artifacts.
    others = sorted(
        p.name
        for p in entries
        if p not in (*wheels, *sdists)
        and not (
            p.name == ".gitignore" and not p.is_symlink() and p.is_file() and p.read_bytes() == b"*"
        )
    )
    if not wheels or not sdists or others:
        raise GuardError(
            f"{dist_dir}: need >=1 wheel and >=1 sdist and nothing else; "
            f"wheels={len(wheels)} sdists={len(sdists)} other={others}"
        )
    direct_members: dict[str, dict[str, str]] = {}
    for whl in wheels:
        direct_members[whl.name] = _wheel_members(whl.read_bytes(), whl.name)
        problems += _compare(
            read_wheel(
                whl.read_bytes(),
                whl.name,
                repo_root=repo_root,
                tracked=tracked,
                project_identity=project_identity,
            ),
            expected,
            whl.name,
        )
    for sdist in sdists:
        blob = sdist.read_bytes()
        problems += _compare(
            read_sdist(blob, sdist.name, repo_root=repo_root, tracked=tracked),
            expected,
            sdist.name,
        )
        pkg_info = sdist_file(blob, "PKG-INFO")
        for whl in wheels:
            with zipfile.ZipFile(whl) as archive:
                metadata_name = next(n for n in archive.namelist()
                                     if n.endswith(".dist-info/METADATA"))
                if pkg_info != archive.read(metadata_name):
                    raise GuardError(
                        f"{sdist.name}: PKG-INFO differs byte-for-byte from wheel METADATA"
                    )
        # The installer's build of this sdist runs ITS pyproject.toml. Require it
        # to be the reviewed one, byte for byte, with no extra hatch config file.
        if sdist_file(blob, "pyproject.toml") != pyproject:
            raise GuardError(f"{sdist.name}: pyproject.toml differs from the repository's")
        for config in ("hatch.toml", "hatch_build.py"):
            if sdist_file(blob, config) is not None:
                raise GuardError(f"{sdist.name}: contains {config}")
        if rebuild_sdists:
            for label, argv in REBUILDERS:
                with tempfile.TemporaryDirectory() as tmp:
                    rebuilt = _rebuild(label, argv, sdist, Path(tmp))
                    where = f"wheel {label} built from {sdist.name}"
                    # Bind EVERY wheel member, including generated METADATA
                    # (Requires-Dist), entry_points.txt, WHEEL and RECORD, to what
                    # each trusted frontend builds from the accepted sdist. A
                    # post-build edit to generated metadata cannot match.
                    rebuilt_members = _wheel_members(rebuilt.read_bytes(), where)
                    for name, members in direct_members.items():
                        if members != rebuilt_members:
                            changed = sorted(
                                k
                                for k in set(members) | set(rebuilt_members)
                                if members.get(k) != rebuilt_members.get(k)
                            )
                            problems.append(
                                f"{name}: differs from the {label} rebuild of {sdist.name} "
                                f"in {changed[:5]}"
                            )
                    problems += _compare(
                        # The rebuilt wheel is held to the same checkout bytes and
                        # identity as the direct wheel; its filename is evidence.
                        read_wheel(
                            rebuilt.read_bytes(),
                            where,
                            wheel_filename=rebuilt.name,
                            repo_root=repo_root,
                            tracked=tracked,
                            project_identity=project_identity,
                        ),
                        expected,
                        where,
                    )
    return problems


def check_tree(
    ledger: Mapping[str, Any],
    repo_root: Path = REPO_ROOT,
    frozen: Mapping[str, frozenset[str]] | None = None,
) -> list[str]:
    problems = check_ledger(ledger)
    if problems:
        return problems
    version = kernel_version((repo_root / "src/regista/kernel.py").read_bytes(), "kernel.py")
    if version != ledger["baseline_version"]:
        problems.append("code KERNEL_SCHEMA_VERSION does not match the selected baseline pin")
    for retired in FORBIDDEN_SOURCE_DIRS:
        if (repo_root / retired).exists():
            problems.append(f"{retired} must not exist: the old chain is retired")
    package = repo_root / "src/regista"
    actual = {}
    for path in package.iterdir():
        if path.name in BASELINE_FILES or path.suffix.lower() == ".sql":
            if path.is_symlink() or not path.is_file():
                problems.append(f"{path.name}: baseline must be a regular file")
            else:
                actual[path.name] = _sha(path.read_bytes())
    return problems + _compare(actual, expected_migrations(ledger), "src/regista/")


def _fetch(url: str, attempts: int = 4) -> bytes:
    last: Exception | None = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                body: bytes = resp.read()
                return body
        except OSError as exc:
            last = exc
            time.sleep(2**i)
    raise GuardError(f"could not fetch {url} after {attempts} attempts: {last}")


def build_releases() -> dict[str, Any]:
    """Download every post-cutover wheel and inspect its actual schema/version.

    Yanked wheels remain relevant to existing stores and are checked too. Empty
    release entries and pre-0.8 artifacts belong to the retired chain.
    """
    index = json.loads(_fetch(PYPI_JSON))
    releases: dict[str, Any] = {}
    for version, files in index["releases"].items():
        if not files:
            continue
        # Ignore pre-cutover prereleases too. Post-cutover version syntax must
        # match our plain-release contract rather than disappear from the scan.
        match = re.match(r"^(\d+)\.(\d+)", version)
        if match and tuple(map(int, match.groups())) < (0, 8):
            continue
        _version_key(version)
        wheels = [f for f in files if f["packagetype"] == "bdist_wheel"]
        if not wheels:
            raise GuardError(f"{version}: published release has no wheel to bind")
        for file in wheels:
            blob = _fetch(file["url"])
            if _sha(blob) != file["digests"]["sha256"]:
                raise GuardError(f"{file['filename']}: download does not match PyPI's digest")
            resources = read_wheel(blob, file["filename"])
            with zipfile.ZipFile(io.BytesIO(blob)) as wheel:
                version_number = kernel_version(wheel.read("regista/kernel.py"), file["filename"])
            entry = {"kernel_schema_version": version_number,
                     "schema_sha256": resources.get("schema.sql")}
            if version in releases and releases[version] != entry:
                raise GuardError(f"{version}: published wheels disagree on schema/version")
            releases[version] = entry
    return releases


def verify_ledger(ledger: Mapping[str, Any], fresh: Mapping[str, Any]) -> list[str]:
    problems = check_ledger(ledger)
    if problems:
        return problems
    for release, pair in fresh.items():
        pinned = ledger["schema_versions"].get(str(pair["kernel_schema_version"]))
        if pinned is None or pinned != pair["schema_sha256"]:
            problems.append(f"PyPI release {release}: published schema/version differs from pin")
    return problems


def check_release(
    ledger: Mapping[str, Any], version: str, repo_root: Path = REPO_ROOT,
    *, fresh: Mapping[str, Any] | None = None,
) -> list[str]:
    problems = verify_baseline(ledger, repo_root)
    if _version_key(version) < (0, 8, 0):
        problems.append("the reduced baseline must not publish as a pre-0.8 release")
    published = build_releases() if fresh is None else fresh
    if not published:
        print(PREPUBLICATION_MESSAGE)
    problems += verify_ledger(ledger, published)
    if published:
        latest = max(published, key=_version_key)
        if _version_key(version) <= _version_key(latest):
            problems.append(f"{version} is already published or does not sort after {latest}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="published-migration immutability guard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-tree")
    sub.add_parser("verify-baseline")
    sub.add_parser("verify-ledger")
    rel = sub.add_parser("check-release")
    rel.add_argument("--version", required=True)
    dist = sub.add_parser("check-dist")
    dist.add_argument("dist_dir", type=Path)
    dist.add_argument(
        "--authoritative",
        action="store_true",
        help="give the binding verdict; refuses unless run in the controlled CI environment",
    )
    args = parser.parse_args(argv)
    advisory = args.cmd == "check-dist" and not args.authoritative
    label = "ADVISORY (not authoritative; only the CI run is) " if advisory else ""
    try:
        return _main(args, label)
    except Exception as exc:  # never a traceback: one line, non-zero exit
        print(f"{label}error: internal {exc.__class__.__name__}: {exc}"[:500], file=sys.stderr)
        return 3


def _main(args: argparse.Namespace, label: str) -> int:
    try:
        ledger = load_ledger()
        if args.cmd == "verify-baseline":
            problems = verify_baseline(ledger)
        elif args.cmd == "verify-ledger":
            fresh = build_releases()
            if not fresh:
                print(PREPUBLICATION_MESSAGE)
            problems = verify_baseline(ledger) + verify_ledger(ledger, fresh)
        elif args.cmd == "check-release":
            problems = check_release(ledger, args.version)
        elif args.cmd == "check-dist":
            problems = check_dist(ledger, args.dist_dir, authoritative=args.authoritative)
        else:
            problems = check_tree(ledger)
    except GuardError as exc:
        print(f"{label}error: {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"{label}VIOLATION: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"{label}{args.cmd}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
