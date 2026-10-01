"""Published-migration immutability guard (GitHub issue #65): an allowlist.

**The rule.** Once a release containing a migration is published, that
migration's path and bytes are immutable. Every later schema change ships as a
new, appended migration. A store migrated by an old release records each
migration's checksum, so rewriting a published file makes those stores report
``MIGRATION_DRIFT``.

**What this guard proves, and nothing more.**

1. ``release/published-migrations.json`` ("the ledger") records, for each
   release, exactly what PyPI serves for ``regista-hraedon`` *now*: per release,
   the sha256 of every file and of every migration it ships (``verify-ledger``;
   network).
2. The artifacts about to be published (``check-dist``) are well formed, and they
   ship EXACTLY the expected migration set, byte for byte. Anything not on the
   allowlist fails, including anything the guard does not recognise. The expected
   set is every migration of the latest released ledger entry, plus the
   ``unreleased`` entries declared in the ledger.

It deliberately makes **no claim about git history**, and none about releases
that have been deleted from PyPI. ``verify-ledger`` fails loudly if a recorded
release is no longer on PyPI, and a human decides what to do. Earlier versions
judged ledger history (withdrawals, merge parents, renames). Six review rounds
found a new gap in that judgement every time, so it was dropped rather than
patched further.

**Scope of the sdist half.** A PEP 517 build runs backend code, so what an
installer gets from the sdist cannot be proven for every frontend and every
environment. The claim covers ISOLATED builds by pip and uv, the two frontends
actually run here. It rests on a build contract:

* ``build-system.requires`` equals the named, exact
  ``TRUSTED_BUILD_REQUIREMENTS`` closure, and the backend is
  ``hatchling.build`` with no ``backend-path``. Build requirements execute code:
  this frozen closure is TRUSTED, not inert.
* No hatch build hook or plugin is configured, and there is no ``hatch.toml``
  or ``hatch_build.py``.
* The sdist's ``pyproject.toml`` is byte-identical to the reviewed one.

Builds with ``--no-build-isolation``, other frontends, and other backends are
outside the claim.

**The allowlist (``check-dist``)**, applied to every member of every wheel and
sdist in ``DIST_DIR``:

* A member name is ASCII, matches ``SAFE_NAME`` (``[A-Za-z0-9._+-]`` segments
  joined by ``/``), is NFC, and has no empty, ``.`` or ``..`` segment. So there
  is no leading ``/``, no backslash, no NUL or control character, and no
  Unicode.
* A member is a regular file. Every symlink, hard link, directory entry, device
  or FIFO is refused.
* No two members collide after NFKC + casefold, and no name repeats.
* A wheel contains files only under ``regista/`` and one
  ``<dist>-<version>.dist-info/`` directory matching its filename. The latter
  contains only the named metadata files and ``licenses/`` subtree; ``WHEEL``
  declares version 1.0 and a purelib root. In particular, no ``.data/`` install
  relocation is allowed.
* Site-startup executable names (``*.pth``, ``sitecustomize.py`` and
  ``usercustomize.py``) are refused anywhere in a wheel or sdist.
* A migration is a member whose parent is EXACTLY the migrations directory
  (``regista/migrations/`` in a wheel, ``<root>/migrations/`` in an sdist), with
  a filename matching ``MIGRATION_NAME`` (``^\\d{3}_[a-z0-9_]+\\.sql$``). Any
  other member whose folded path lies under a folded migrations directory is
  refused. So is ``src/regista/migrations/``, the runner's preferred copy. In a
  wheel, so is any folded ``.sql`` anywhere else.
* The wheel's migrations must equal the expected set exactly, with matching
  bytes: no extras and no missing files. Each one must be vouched for by the
  wheel's single ``RECORD`` with the same sha256.
* A wheel is one canonical ZIP container:
  - local records start at offset 0 and are contiguous;
  - each local header agrees with its central-directory entry;
  - one end-of-central-directory record sits at the very end, with no comment;
  - there are no data descriptors and no extra fields (so no ZIP64 and no
    Unicode Path names).
* An sdist has one top-level directory and no PAX headers.
* No regular member may sit where a directory must be, for example a file named
  exactly ``regista/migrations``. No segment may end in ``.``, and none may be a
  Windows device name.
* There must be at least one wheel and at least one sdist. Each sdist's
  migrations must equal the wheel's, and each sdist must honour the build
  contract above. A wheel built FROM each sdist by uv AND by pip, in isolation,
  must pass all of the above and carry the same migrations.

**Historical violations.** Two migrations were rewritten in place in 0.6.0
(``001_initial.sql`` and ``035_event_chain_head_genesis_sentinel.sql``):
0.5.x ships one set of bytes, 0.6.0-0.7.2 another. Both are pinned by exact
digest set in ``FROZEN_HISTORICAL_VIOLATIONS``. Any further multiplicity fails.

Subcommands: ``check-dist DIST_DIR`` (authoritative; CI and the publish build
job), ``check-tree`` (fast early signal over ``migrations/``), ``verify-ledger``
(network), ``check-release --version X``, ``build`` (network; regenerate).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
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
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO_ROOT / "release" / "published-migrations.json"
PROJECT = "regista-hraedon"
PYPI_JSON = f"https://pypi.org/pypi/{PROJECT}/json"
LEDGER_FORMAT = 2

WHEEL_MIGRATIONS = "regista/migrations/"
SDIST_MIGRATIONS = "migrations/"
FORBIDDEN_SOURCE_DIRS = ("src/regista/migrations/",)
SAFE_NAME = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*")
MIGRATION_NAME = re.compile(r"\d{3}_[a-z0-9_]+\.sql")

TRUSTED_BUILD_REQUIREMENTS = (
    "hatchling==1.32.4",
    "packaging==26.3",
    "pathspec==1.1.1",
    "pluggy==1.6.0",
    "tomlkit==0.15.1",
    "trove-classifiers==2026.9.21.13",
)
DIST_INFO_FILES = frozenset({"METADATA", "WHEEL", "RECORD", "entry_points.txt"})

FROZEN_HISTORICAL_VIOLATIONS: Mapping[str, frozenset[str]] = {
    "001_initial.sql": frozenset(
        {
            "b8d3fbf2e07382d486b88c06cef493eb0dd474bd597f9ceb5d358f2acce9b49f",
            "db8e3daeb85c962f4034af65b5bb7fae8929e9d8d6fb8015053b0703091cb373",
        }
    ),
    "035_event_chain_head_genesis_sentinel.sql": frozenset(
        {
            "8dd73c22dd46efd797709b61daf811e4f939649e6def3f258bdd05801def2f31",
            "6dd6ccc9ad9fb07a6196a94b8968588c5b7913f7fc28beb990aa69679a637a0f",
        }
    ),
}


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


def _wheel_dist_info_dir(filename: str, where: str) -> str:
    """Return the wheel-filename-derived, normalized dist-info directory."""
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
    return f"{distribution}-{version}.dist-info"


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
    """Require the two install-critical WHEEL headers with exact values."""
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


def _classify(rel: str, migrations_dir: str, where: str, *, sql_elsewhere: bool) -> str | None:
    """Return the migration filename if ``rel`` is one, None if it is some other
    allowed file; raise if it is anything else touching the migrations path."""
    folded = _fold(rel)
    for forbidden in (migrations_dir, *FORBIDDEN_SOURCE_DIRS):
        if folded.startswith(_fold(forbidden)):
            name = rel[len(forbidden) :]
            if rel.startswith(migrations_dir) and MIGRATION_NAME.fullmatch(name):
                return name
            raise GuardError(f"{where}: {rel!r} is not a canonical migration in {migrations_dir}")
    if not sql_elsewhere and folded.endswith(".sql"):
        raise GuardError(f"{where}: {rel!r} is a .sql outside {migrations_dir}")
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
            raise GuardError(f"{where}: {info.orig_filename!r} is not contiguous (preamble, gap "
                             "or overlap)")
        too_big = max(info.file_size, info.compress_size) >= 0xFFFFFFFF
        if info.flag_bits & 0x08 or too_big:
            raise GuardError(f"{where}: {info.orig_filename!r} uses a data descriptor or ZIP64")
        (sig, _ver, flags, method, _t, _d, crc, csize, usize, name_len,
         extra_len) = struct.unpack("<4sHHHHHIIIHH", blob[expected : expected + 30])
        # A streaming unzipper trusts the LOCAL header; it must say exactly what
        # the central directory says.
        if sig != b"PK\x03\x04" or (flags, method, crc, csize, usize) != (
            info.flag_bits, info.compress_type, info.CRC, info.compress_size, info.file_size
        ) or blob[expected + 30 : expected + 30 + name_len] != info.orig_filename.encode():
            raise GuardError(f"{where}: {info.orig_filename!r} local header disagrees with "
                             "the central directory")
        # No extra field in either header: none of our wheels carries one, and
        # they are where ZIP64 sizes and alternate (Unicode Path) names live.
        if info.extra or extra_len:
            raise GuardError(f"{where}: {info.orig_filename!r} carries a ZIP extra field")
        expected += 30 + name_len + extra_len + info.compress_size
    if expected != cd_off:
        raise GuardError(f"{where}: bytes between the last record and the central directory")


def read_wheel(
    blob: bytes, where: str, *, wheel_filename: str | None = None
) -> dict[str, str]:
    """Allowlisted wheel -> {migration filename: sha256}."""
    try:
        return _read_wheel(blob, where, wheel_filename or where)
    except GuardError:
        raise
    # zipfile exposes several implementation-specific read failures (including
    # NotImplementedError for an unsupported compression method). At this trust
    # boundary every malformed/unreadable archive is one fail-closed GuardError.
    except Exception as exc:
        raise GuardError(f"{where}: unreadable wheel ({exc.__class__.__name__}: {exc})") from exc


def _read_wheel(blob: bytes, where: str, wheel_filename: str) -> dict[str, str]:
    out: dict[str, str] = {}
    dist_info = _wheel_dist_info_dir(wheel_filename, where)
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
            files[info.filename] = zf.read(info)
        wheel_metadata = f"{dist_info}/WHEEL"
        if wheel_metadata not in files:
            raise GuardError(f"{where}: required WHEEL metadata is missing")
        _check_wheel_metadata(files[wheel_metadata], where)
        for name, data in files.items():
            mig = _classify(name, WHEEL_MIGRATIONS, where, sql_elsewhere=False)
            if mig is not None:
                out[mig] = _sha(data)
        records = [n for n in files if n == f"{dist_info}/RECORD"]
        if len(records) != 1:
            raise GuardError(f"{where}: expected exactly one matching RECORD, found {records}")
        listed: dict[str, str] = {}
        for line in files[records[0]].decode().splitlines():
            parts = line.rsplit(",", 2)
            if len(parts) == 3 and parts[1].startswith("sha256="):
                listed[parts[0]] = parts[1][len("sha256=") :]
        for mig, digest in out.items():
            expected = base64.urlsafe_b64encode(bytes.fromhex(digest)).rstrip(b"=").decode()
            if listed.get(WHEEL_MIGRATIONS + mig) != expected:
                raise GuardError(f"{where}: RECORD does not vouch for {mig} with its bytes")
    return out


def read_sdist(blob: bytes, where: str) -> dict[str, str]:
    """Allowlisted sdist -> {migration filename: sha256}."""
    try:
        return _read_sdist(blob, where)
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


def _read_sdist(blob: bytes, where: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        members = tf.getmembers()
        if tf.pax_headers or any(m.pax_headers for m in members):
            raise GuardError(f"{where}: PAX extended headers can rename members; refused")
        roots = {m.name.split("/", 1)[0] for m in members}
        if len(roots) != 1 or any("/" not in m.name for m in members):
            raise GuardError(f"{where}: expected one top-level directory, found {sorted(roots)}")
        root = next(iter(roots))
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
            mig = _classify(rel, SDIST_MIGRATIONS, where, sql_elsewhere=True)
            if mig is not None:
                fh = tf.extractfile(m)
                assert fh is not None
                out[mig] = _sha(fh.read())
    return out


# --------------------------------------------------------------------------
# Ledger


def _fetch(url: str, attempts: int = 4) -> bytes:
    last: Exception | None = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                body: bytes = resp.read()
                return body
        except OSError as exc:
            last = exc
            time.sleep(2**i)
    raise GuardError(f"could not fetch {url} after {attempts} attempts: {last}")


def _multiplicity(releases: Mapping[str, Any]) -> dict[str, list[str]]:
    seen: dict[str, set[str]] = {}
    for entry in releases.values():
        for name, digest in entry["migrations"].items():
            seen.setdefault(name, set()).add(digest)
    return {n: sorted(d) for n, d in sorted(seen.items()) if len(d) > 1}


def build_releases() -> dict[str, Any]:
    """What PyPI serves now, read through the same allowlist as check-dist."""
    index = json.loads(_fetch(PYPI_JSON))
    releases: dict[str, Any] = {}
    for version in sorted(index["releases"], key=_version_key):
        files = index["releases"][version]
        if not files:
            continue
        entry: dict[str, Any] = {"files": {}, "migrations": None}
        for f in sorted(files, key=lambda f: str(f["filename"])):
            blob = _fetch(f["url"])
            if _sha(blob) != f["digests"]["sha256"]:
                raise GuardError(f"{f['filename']}: download does not match PyPI's digest")
            entry["files"][f["filename"]] = {"sha256": _sha(blob), "packagetype": f["packagetype"]}
            reader = {"bdist_wheel": read_wheel, "sdist": read_sdist}.get(f["packagetype"])
            if reader is None:
                raise GuardError(f"{f['filename']}: unexpected package type {f['packagetype']}")
            mig = reader(blob, f["filename"])
            if entry["migrations"] is not None and mig != entry["migrations"]:
                raise GuardError(f"{version}: its files ship different migrations")
            entry["migrations"] = mig
        entry["migrations"] = dict(sorted(entry["migrations"].items()))
        releases[version] = entry
    return releases


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    ledger: dict[str, Any] = json.loads(path.read_text())
    if ledger.get("format") != LEDGER_FORMAT or ledger.get("project") != PROJECT:
        raise GuardError(f"{path}: unrecognised ledger format/project")
    if not ledger.get("releases"):
        raise GuardError(f"{path}: ledger records no releases; refusing to vacuously pass")
    if set(ledger) != {"format", "project", "source", "releases", "historical_violations",
                       "unreleased"}:
        raise GuardError(f"{path}: unexpected ledger keys {sorted(ledger)}")
    return ledger


def check_ledger(
    ledger: Mapping[str, Any],
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
) -> list[str]:
    """Internal consistency, and the expected migration set it implies."""
    problems: list[str] = []
    releases = ledger["releases"]
    multi = {n: frozenset(d) for n, d in _multiplicity(releases).items()}
    if multi != dict(frozen):
        problems.append(
            f"released migration bytes differ between releases beyond the frozen pair: {multi}"
        )
    if {n: frozenset(d) for n, d in ledger["historical_violations"].items()} != multi:
        problems.append("ledger historical_violations does not match its own releases")
    latest = releases[max(releases, key=_version_key)]["migrations"]
    ever = {n for e in releases.values() for n in e["migrations"]}
    if ever - set(latest):
        dropped = sorted(ever - set(latest))
        problems.append(f"the latest release dropped published migrations {dropped}")
    head = max((int(n[:3]) for n in ever), default=-1)
    unreleased = ledger["unreleased"]
    for name, digest in unreleased.items():
        if MIGRATION_NAME.fullmatch(name) is None or not re.fullmatch(r"[0-9a-f]{64}", digest):
            problems.append(f"unreleased entry {name!r}: bad name or digest")
        elif name in ever:
            problems.append(f"unreleased entry {name} is already published")
        elif int(name[:3]) <= head:
            problems.append(f"unreleased {name} does not sort after the published head {head:03d}")
    numbers = [n[:3] for n in [*latest, *unreleased]]
    if len(numbers) != len(set(numbers)):
        problems.append("two migrations share a version number")
    return problems


def expected_migrations(ledger: Mapping[str, Any]) -> dict[str, str]:
    releases = ledger["releases"]
    latest = dict(releases[max(releases, key=_version_key)]["migrations"])
    return {**latest, **ledger["unreleased"]}


def _compare(actual: Mapping[str, str], expected: Mapping[str, str], where: str) -> list[str]:
    problems = []
    for name in sorted(set(expected) - set(actual)):
        problems.append(f"{where}: missing migration {name}")
    for name in sorted(set(actual) - set(expected)):
        problems.append(f"{where}: undeclared migration {name} (declare it under 'unreleased')")
    for name in sorted(set(actual) & set(expected)):
        if actual[name] != expected[name]:
            problems.append(f"{where}: {name} bytes differ from the ledger")
    return problems


# --------------------------------------------------------------------------
# Checks


#: Build frontends whose isolated build of each sdist must reproduce the
#: expected migrations. The pip entry runs the interpreter running this guard.
REBUILDERS: list[tuple[str, list[str]]] = [
    ("uv", ["uv", "build", "--wheel", "--out-dir", "{out}", "{sdist}"]),
    ("pip", [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", "{out}", "{sdist}"]),
]


def _rebuild(label: str, argv: list[str], sdist: Path, out: Path) -> Path:
    cmd = [a.format(out=out, sdist=sdist) for a in argv]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise GuardError(f"{sdist.name}: {label} could not build a wheel from it")
    wheels = sorted(out.glob("*.whl"))
    if len(wheels) != 1:
        raise GuardError(f"{sdist.name}: {label} produced {len(wheels)} wheels")
    return wheels[0]


def _keys(node: Any, prefix: str = "") -> list[str]:
    if isinstance(node, dict):
        return [k for key, v in node.items() for k in [prefix + key, *_keys(v, prefix + key + ".")]]
    return []


def check_build_contract(pyproject: bytes, where: str) -> None:
    """The build uses one named, frozen, trusted executable closure.

    Build requirements are not inert. Their exact string set must equal
    ``TRUSTED_BUILD_REQUIREMENTS``; the backend is hatchling with no
    ``backend-path``, and no hatch build hook or plugin is configured.
    """
    data = tomllib.loads(pyproject.decode())
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
    hooks = [k for k in _keys(data.get("tool", {}).get("hatch", {})) if "hook" in k.lower()]
    if hooks:
        raise GuardError(f"{where}: hatch build hooks/plugins are not allowed: {hooks}")


def check_dist(
    ledger: Mapping[str, Any],
    dist_dir: Path,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
    *,
    repo_root: Path = REPO_ROOT,
    rebuild_sdists: bool = True,
) -> list[str]:
    problems = check_ledger(ledger, frozen)
    pyproject = (repo_root / "pyproject.toml").read_bytes()
    check_build_contract(pyproject, "pyproject.toml")
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
            p.name == ".gitignore"
            and not p.is_symlink()
            and p.is_file()
            and p.read_bytes() == b"*"
        )
    )
    if not wheels or not sdists or others:
        raise GuardError(
            f"{dist_dir}: need >=1 wheel and >=1 sdist and nothing else; "
            f"wheels={len(wheels)} sdists={len(sdists)} other={others}"
        )
    for whl in wheels:
        problems += _compare(read_wheel(whl.read_bytes(), whl.name), expected, whl.name)
    for sdist in sdists:
        blob = sdist.read_bytes()
        problems += _compare(read_sdist(blob, sdist.name), expected, sdist.name)
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
                    problems += _compare(
                        read_wheel(rebuilt.read_bytes(), where, wheel_filename=rebuilt.name),
                        expected,
                        where,
                    )
    return problems


def check_tree(ledger: Mapping[str, Any], repo_root: Path = REPO_ROOT,
               frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS) -> list[str]:
    """Early signal: migrations/ holds exactly the expected files, nothing else."""
    problems = check_ledger(ledger, frozen)
    for forbidden in FORBIDDEN_SOURCE_DIRS:
        if (repo_root / forbidden).exists():
            problems.append(f"{forbidden} must not exist (the runner would prefer it)")
    actual: dict[str, str] = {}
    for p in sorted((repo_root / SDIST_MIGRATIONS).iterdir()):
        if p.is_symlink() or not p.is_file() or MIGRATION_NAME.fullmatch(p.name) is None:
            problems.append(f"migrations/{p.name}: not a canonical migration file")
        else:
            actual[p.name] = _sha(p.read_bytes())
    return problems + _compare(actual, expected_migrations(ledger), "migrations/")


def check_release(ledger: Mapping[str, Any], version: str, repo_root: Path = REPO_ROOT,
                  frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS) -> list[str]:
    problems = []
    known = sorted(ledger["releases"], key=_version_key)
    if version in ledger["releases"]:
        problems.append(f"{version} is already published")
    elif _version_key(version) <= _version_key(known[-1]):
        problems.append(f"{version} does not sort after the latest release {known[-1]}")
    return problems + check_tree(ledger, repo_root, frozen)


def verify_ledger(committed: Mapping[str, Any], fresh: Mapping[str, Any]) -> list[str]:
    problems = []
    for v in sorted(set(fresh) - set(committed["releases"]), key=_version_key):
        problems.append(f"PyPI release {v} is not in the ledger; run `build` and commit")
    for v in sorted(set(committed["releases"]) - set(fresh), key=_version_key):
        problems.append(
            f"ledger release {v} is no longer on PyPI. This guard makes no claim about "
            "deleted releases: a human must decide (stores may still hold its bytes)"
        )
    for v in sorted(set(fresh) & set(committed["releases"]), key=_version_key):
        if fresh[v] != committed["releases"][v]:
            problems.append(f"ledger release {v} differs from what PyPI serves")
    if _multiplicity(fresh) != committed["historical_violations"]:
        problems.append("historical_violations differs from PyPI")
    return problems


def _canonical(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="published-migration immutability guard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-tree")
    sub.add_parser("verify-ledger")
    sub.add_parser("build")
    rel = sub.add_parser("check-release")
    rel.add_argument("--version", required=True)
    dist = sub.add_parser("check-dist")
    dist.add_argument("dist_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "build":
            prior = load_ledger() if LEDGER_PATH.exists() else None
            releases = build_releases()
            unreleased = dict((prior or {}).get("unreleased", {}))
            for entry in releases.values():
                for name, digest in entry["migrations"].items():
                    if name in unreleased:
                        if unreleased.pop(name) != digest:
                            raise GuardError(f"{name} was released with undeclared bytes")
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            LEDGER_PATH.write_text(_canonical({
                "format": LEDGER_FORMAT, "project": PROJECT,
                "source": "PyPI artifacts; regenerate with "
                          "`python scripts/check_published_migrations.py build`",
                "releases": releases, "historical_violations": _multiplicity(releases),
                "unreleased": dict(sorted(unreleased.items())),
            }))
            print(f"wrote {LEDGER_PATH} ({len(releases)} releases)")
            return 0
        ledger = load_ledger()
        if args.cmd == "verify-ledger":
            problems = verify_ledger(ledger, build_releases()) + check_ledger(ledger)
        elif args.cmd == "check-release":
            problems = check_release(ledger, args.version)
        elif args.cmd == "check-dist":
            problems = check_dist(ledger, args.dist_dir)
        else:
            problems = check_tree(ledger)
    except GuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for p in problems:
        print(f"VIOLATION: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"{args.cmd}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
