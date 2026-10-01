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
patched further. The claim is now small enough to check exhaustively.

**The allowlist (``check-dist``)**, applied to every member of every wheel and
sdist in ``DIST_DIR``:

* A member name is ASCII, matches ``SAFE_NAME`` (``[A-Za-z0-9._+-]`` segments
  joined by ``/``), is NFC, and has no empty, ``.`` or ``..`` segment. So there
  is no leading ``/``, no backslash, no NUL or control character, and no
  Unicode.
* A member is a regular file. Every symlink, hard link, directory entry, device
  or FIFO is refused.
* No two members collide after NFKC + casefold, and no name repeats.
* A migration is a member whose parent is EXACTLY the migrations directory
  (``regista/migrations/`` in a wheel, ``<root>/migrations/`` in an sdist), with
  a filename matching ``MIGRATION_NAME`` (``^\\d{3}_[a-z0-9_]+\\.sql$``). Any
  other member whose folded path lies under a folded migrations directory is
  refused. So is ``src/regista/migrations/``, the runner's preferred copy. In a
  wheel, so is any folded ``.sql`` anywhere else.
* The wheel's migrations must equal the expected set exactly, with matching
  bytes: no extras and no missing files. Each one must be vouched for by the
  wheel's single ``RECORD`` with the same sha256.
* There must be at least one wheel and at least one sdist. Each sdist's
  migrations must equal the wheel's. A wheel rebuilt FROM each sdist (what pip
  and uv do when installing it) must pass all of the above and carry the same
  migrations.

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
import subprocess
import sys
import tarfile
import tempfile
import time
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


def _check_names(names: list[str], where: str) -> None:
    seen: dict[str, str] = {}
    for name in names:
        if (
            not name.isascii()
            or SAFE_NAME.fullmatch(name) is None
            or unicodedata.normalize("NFC", name) != name
            or any(part in (".", "..") for part in name.split("/"))
        ):
            raise GuardError(f"{where}: member name {name!r} is not on the allowlist")
        key = _fold(name)
        if key in seen:
            raise GuardError(
                f"{where}: members {seen[key]!r} and {name!r} collide (same name, or the "
                "same path on a case- or Unicode-folding filesystem)"
            )
        seen[key] = name


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


def read_wheel(blob: bytes, where: str) -> dict[str, str]:
    """Allowlisted wheel -> {migration filename: sha256}."""
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        infos = zf.infolist()
        # orig_filename is the raw header name: zipfile truncates ``filename`` at
        # NUL, so judging the truncated name would accept a different string than
        # other unzip implementations see (found by the property fuzz). Reading
        # each member below also makes zipfile refuse a local header whose name
        # differs from the central directory's.
        _check_names([i.orig_filename for i in infos], where)
        for info in infos:
            if info.orig_filename != info.filename:
                raise GuardError(f"{where}: member name {info.orig_filename!r} contains NUL")
        files: dict[str, bytes] = {}
        for info in infos:
            mode = info.external_attr >> 16
            # A mode with no file-type bits (hatch writes 0o644 for some
            # dist-info members) is a regular file to every installer.
            if info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise GuardError(f"{where}: {info.filename!r} is not a regular file")
            files[info.filename] = zf.read(info)
        for name, data in files.items():
            mig = _classify(name, WHEEL_MIGRATIONS, where, sql_elsewhere=False)
            if mig is not None:
                out[mig] = _sha(data)
        records = [n for n in files if n.count("/") == 1 and n.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise GuardError(f"{where}: expected exactly one top-level RECORD, found {records}")
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
    out: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        members = tf.getmembers()
        _check_names([m.name for m in members], where)
        roots = {m.name.split("/", 1)[0] for m in members}
        if len(roots) != 1 or any("/" not in m.name for m in members):
            raise GuardError(f"{where}: expected one top-level directory, found {sorted(roots)}")
        for m in members:
            if not m.isfile():
                raise GuardError(f"{where}: {m.name!r} is not a regular file (type {m.type!r})")
            rel = m.name.split("/", 1)[1]
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


def check_dist(
    ledger: Mapping[str, Any],
    dist_dir: Path,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
    *,
    rebuild_sdists: bool = True,
) -> list[str]:
    problems = check_ledger(ledger, frozen)
    expected = expected_migrations(ledger)
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    # `uv build` drops a one-byte `*` .gitignore into its out-dir; nothing else
    # may sit beside the artifacts.
    others = sorted(
        p.name
        for p in dist_dir.iterdir()
        if p not in (*wheels, *sdists)
        and not (p.name == ".gitignore" and p.is_file() and p.read_bytes() == b"*")
    )
    if not wheels or not sdists or others:
        raise GuardError(
            f"{dist_dir}: need >=1 wheel and >=1 sdist and nothing else; "
            f"wheels={len(wheels)} sdists={len(sdists)} other={others}"
        )
    for whl in wheels:
        problems += _compare(read_wheel(whl.read_bytes(), whl.name), expected, whl.name)
    for sdist in sdists:
        problems += _compare(read_sdist(sdist.read_bytes(), sdist.name), expected, sdist.name)
        if rebuild_sdists:
            with tempfile.TemporaryDirectory() as tmp:
                proc = subprocess.run(
                    ["uv", "build", "--wheel", "--out-dir", tmp, str(sdist)],
                    capture_output=True, text=True,
                )
                if proc.returncode != 0:
                    raise GuardError(f"{sdist.name}: building a wheel from it failed")
                rebuilt = sorted(Path(tmp).glob("*.whl"))
                if len(rebuilt) != 1:
                    raise GuardError(f"{sdist.name}: rebuild produced {len(rebuilt)} wheels")
                where = f"wheel rebuilt from {sdist.name}"
                problems += _compare(read_wheel(rebuilt[0].read_bytes(), where), expected, where)
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
