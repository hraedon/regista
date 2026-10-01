"""Published-migration immutability guard (GitHub issue #65).

**The rule.** Once a release containing a migration is published, that
migration's path and bytes are immutable. Every later schema change ships as a
new, appended migration. A store migrated by an old release records each
migration's checksum; rewriting a published file makes every such store report
``MIGRATION_DRIFT`` and creates pressure to soften the drift check. That
pressure is how PR #62 came to propose grandfathering checksums.

**What "published" means here.** The bytes PyPI serves are the source of truth,
not git tags. Tags and releases have diverged in this repository before:
``v0.5.1-rc1`` is not PyPI 0.5.1, and ``v0.4.0`` was never uploaded. The
committed ledger ``release/published-migrations.json`` records, for every
release of ``regista-hraedon`` on PyPI, the sha256 of the wheel and sdist and of
every ``*.sql`` file each one ships. The ledger is a cache of PyPI and is
checked against PyPI. It is not an authority anyone can edit to bless a change.

Subcommands:

``check-tree`` (offline, runs in the ordinary test suite)
    The working tree honours the ledger:

    * every published migration still exists at its repository path;
    * each one's bytes equal its **latest** published bytes;
    * a path whose published bytes differ between releases is allowed only if
      it is one of the exactly-pinned historical violations below;
    * every migration in the tree has a numeric version prefix, versions are
      unique, and an unpublished migration sorts **after** every published one.
      The runner (``_migrations.discover_migrations``) silently skips
      non-numeric names and does not refuse duplicate numbers, so this guard
      refuses both.

``verify-ledger`` (network: pypi.org)
    Re-download every release PyPI lists, verify each file against PyPI's
    sha256 digest, recompute the ledger, and require it to equal the committed
    one exactly. A missing release, a ledger edit, or a new PyPI release that
    has not been recorded yet all fail. A new release therefore turns CI red
    until the ledger records it, and from then on its migrations are frozen.

``check-release --version X`` (publish workflow, before build)
    ``X`` must not already be in the ledger, and ``check-tree`` must pass on
    the tagged tree.

``build`` (network)
    Rewrite the ledger from PyPI. This is the only supported way to change it.
    ``verify-ledger`` is ``build`` followed by an exact comparison.

**Historical violations.** Two migrations were rewritten in place in 0.6.0, as
measured from the PyPI wheels of all nine releases on 2026-10-01:
``001_initial.sql`` and ``035_event_chain_head_genesis_sentinel.sql``.
0.5.1-0.5.5 ship one set of bytes and 0.6.0-0.7.2 another. Those releases are
already public and cannot be retracted, so the guard cannot make them
consistent. What it can do is freeze the damage: both paths are pinned with
their exact hash sets in ``FROZEN_HISTORICAL_VIOLATIONS``, the tree must carry
their latest bytes, and any further multiplicity, on these paths or any other,
fails. The set of violations cannot grow quietly. It is pinned here in code
and recomputed from PyPI by ``verify-ledger``.

Run:  python scripts/check_published_migrations.py check-tree
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import time
import tomllib
import urllib.request
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO_ROOT / "release" / "published-migrations.json"
PROJECT = "regista-hraedon"
PYPI_JSON = f"https://pypi.org/pypi/{PROJECT}/json"
LEDGER_FORMAT = 1

#: The in-place rewrites already shipped, keyed by wheel path, with the exact
#: set of sha256 digests PyPI has served for each. Growing or changing this set
#: is a deliberate, reviewable act; ``check-tree`` and ``verify-ledger`` both
#: compare against it exactly.
FROZEN_HISTORICAL_VIOLATIONS: Mapping[str, frozenset[str]] = {
    "regista/migrations/001_initial.sql": frozenset(
        {
            # 0.5.1 - 0.5.5
            "b8d3fbf2e07382d486b88c06cef493eb0dd474bd597f9ceb5d358f2acce9b49f",
            # 0.6.0 - 0.7.2 (current)
            "db8e3daeb85c962f4034af65b5bb7fae8929e9d8d6fb8015053b0703091cb373",
        }
    ),
    "regista/migrations/035_event_chain_head_genesis_sentinel.sql": frozenset(
        {
            # 0.5.1 - 0.5.5
            "8dd73c22dd46efd797709b61daf811e4f939649e6def3f258bdd05801def2f31",
            # 0.6.0 - 0.7.2 (current)
            "6dd6ccc9ad9fb07a6196a94b8968588c5b7913f7fc28beb990aa69679a637a0f",
        }
    ),
}

_VERSION_RE = re.compile(r"^(\d+)_[A-Za-z0-9_.-]+\.sql$")


class GuardError(Exception):
    """A violation. The message says what changed and what to do instead."""


# --------------------------------------------------------------------------
# Version ordering (PEP 440 subset: the release segment is all this project uses)


def _version_key(version: str) -> tuple[int, ...]:
    parts = version.split(".")
    if not all(p.isdigit() for p in parts):
        raise GuardError(
            f"release version {version!r} is not a plain N.N.N release; extend "
            "_version_key deliberately rather than guessing an order"
        )
    return tuple(int(p) for p in parts)


# --------------------------------------------------------------------------
# Wheel path -> repository path


def _path_mapping(pyproject: Path) -> list[tuple[str, str]]:
    """(wheel_prefix, repo_prefix) pairs from the hatch build configuration.

    The mapping is read rather than hard-coded so that moving the migrations
    (Plan 032 F1 may well do so) cannot quietly disconnect the guard from them.
    A published path that maps to nothing is an error, not a skip.
    """
    data = tomllib.loads(pyproject.read_text())
    wheel = data["tool"]["hatch"]["build"]["targets"]["wheel"]
    pairs: list[tuple[str, str]] = []
    for src, dst in (wheel.get("force-include") or {}).items():
        pairs.append((dst.rstrip("/") + "/", src.rstrip("/") + "/"))
    for pkg in wheel.get("packages") or []:
        # "src/regista" ships as "regista/"
        name = pkg.rstrip("/").rsplit("/", 1)[-1]
        pairs.append((name + "/", pkg.rstrip("/") + "/"))
    # Longest wheel prefix first, so a force-include nested in a package wins.
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def wheel_to_repo_path(wheel_path: str, mapping: list[tuple[str, str]]) -> str:
    for wheel_prefix, repo_prefix in mapping:
        if wheel_path.startswith(wheel_prefix):
            return repo_prefix + wheel_path[len(wheel_prefix) :]
    raise GuardError(
        f"published file {wheel_path!r} maps to no repository path under the current "
        "[tool.hatch.build.targets.wheel] configuration. A published migration "
        "cannot be untracked by moving the build configuration away from it."
    )


# --------------------------------------------------------------------------
# Ledger construction from PyPI


def _fetch(url: str, attempts: int = 4) -> bytes:
    last: Exception | None = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                body: bytes = resp.read()
                return body
        except OSError as exc:  # URLError is an OSError
            last = exc
            time.sleep(2**i)
    raise GuardError(f"could not fetch {url} after {attempts} attempts: {last}")


def _sql_members_wheel(blob: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for name in zf.namelist():
            if name.endswith(".sql") and ".dist-info/" not in name:
                out[name] = hashlib.sha256(zf.read(name)).hexdigest()
    return out


def _sql_members_sdist(blob: bytes, mapping: list[tuple[str, str]]) -> dict[str, str]:
    """sdist members keyed by their WHEEL path, so the two can be compared."""
    out: dict[str, str] = {}
    reverse = sorted(((r, w) for w, r in mapping), key=lambda p: len(p[0]), reverse=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not member.name.endswith(".sql"):
                continue
            # "<name>-<version>/migrations/001.sql" -> "migrations/001.sql"
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            for repo_prefix, wheel_prefix in reverse:
                if rel.startswith(repo_prefix):
                    fh = tf.extractfile(member)
                    assert fh is not None
                    key = wheel_prefix + rel[len(repo_prefix) :]
                    out[key] = hashlib.sha256(fh.read()).hexdigest()
                    break
    return out


def build_ledger(mapping: list[tuple[str, str]]) -> dict[str, Any]:
    index = json.loads(_fetch(PYPI_JSON))
    releases: dict[str, Any] = {}
    for version in sorted(index["releases"], key=_version_key):
        files = index["releases"][version]
        if not files:
            continue  # a release with every file deleted ships nothing
        entry: dict[str, Any] = {"files": {}, "migrations": {}}
        wheel_sql: dict[str, str] | None = None
        sdist_sql: dict[str, str] | None = None
        for f in sorted(files, key=lambda f: str(f["filename"])):
            blob = _fetch(f["url"])
            digest = hashlib.sha256(blob).hexdigest()
            if digest != f["digests"]["sha256"]:
                raise GuardError(
                    f"{f['filename']}: downloaded sha256 {digest} != PyPI digest "
                    f"{f['digests']['sha256']}"
                )
            entry["files"][f["filename"]] = {
                "sha256": digest,
                "packagetype": f["packagetype"],
                "yanked": bool(f.get("yanked", False)),
            }
            if f["packagetype"] == "bdist_wheel":
                members = _sql_members_wheel(blob)
                if wheel_sql is not None and members != wheel_sql:
                    raise GuardError(f"{version}: two wheels ship different migrations")
                wheel_sql = members
            elif f["packagetype"] == "sdist":
                sdist_sql = _sql_members_sdist(blob, mapping)
        if wheel_sql is None:
            raise GuardError(f"{version}: no wheel on PyPI; cannot establish what installs")
        if sdist_sql is not None and sdist_sql != wheel_sql:
            differing = sorted(
                k for k in wheel_sql if sdist_sql.get(k) not in (None, wheel_sql[k])
            )
            raise GuardError(
                f"{version}: the sdist and the wheel ship different migration bytes: "
                f"only-wheel={sorted(set(wheel_sql) - set(sdist_sql))} "
                f"only-sdist={sorted(set(sdist_sql) - set(wheel_sql))} "
                f"differing={differing}"
            )
        entry["migrations"] = dict(sorted(wheel_sql.items()))
        releases[version] = entry
    return {
        "format": LEDGER_FORMAT,
        "project": PROJECT,
        "source": "PyPI wheel and sdist bytes; regenerate with "
        "`python scripts/check_published_migrations.py build`",
        "releases": releases,
        "historical_violations": _multiplicity(releases),
    }


def _multiplicity(releases: Mapping[str, Any]) -> dict[str, list[str]]:
    seen: dict[str, set[str]] = {}
    for entry in releases.values():
        for path, digest in entry["migrations"].items():
            seen.setdefault(path, set()).add(digest)
    return {p: sorted(d) for p, d in sorted(seen.items()) if len(d) > 1}


# --------------------------------------------------------------------------
# Offline tree check


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    ledger: dict[str, Any] = json.loads(path.read_text())
    if ledger.get("format") != LEDGER_FORMAT or ledger.get("project") != PROJECT:
        raise GuardError(f"{path}: unrecognised ledger format/project")
    if not ledger.get("releases"):
        raise GuardError(f"{path}: ledger records no releases; refusing to vacuously pass")
    return ledger


def latest_published(ledger: Mapping[str, Any]) -> dict[str, tuple[str, str, set[str]]]:
    """wheel path -> (latest digest, version that shipped it, every digest ever shipped)."""
    out: dict[str, tuple[str, str, set[str]]] = {}
    for version in sorted(ledger["releases"], key=_version_key):
        for path, digest in ledger["releases"][version]["migrations"].items():
            prior = out.get(path)
            seen = (prior[2] if prior else set()) | {digest}
            out[path] = (digest, version, seen)
    return out


def check_tree(
    ledger: Mapping[str, Any],
    repo_root: Path = REPO_ROOT,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
) -> list[str]:
    """Return every violation (empty list = pass). Never stops at the first."""
    problems: list[str] = []
    mapping = _path_mapping(repo_root / "pyproject.toml")
    published = latest_published(ledger)

    # 1. Historical multiplicity is exactly the frozen set: no more, no fewer,
    #    and the ledger's own record agrees with what its releases say.
    multi = {p: frozenset(s) for p, (_, _, s) in published.items() if len(s) > 1}
    if multi != dict(frozen):
        problems.append(
            "published migration bytes differ between releases beyond the frozen "
            f"historical violations. Observed multiplicity {_fmt(multi)}; frozen "
            f"{_fmt(frozen)}. A published migration was rewritten in place. Restore "
            "its published bytes and ship the change as a new migration."
        )
    recorded = {p: frozenset(d) for p, d in (ledger.get("historical_violations") or {}).items()}
    if recorded != multi:
        problems.append(
            "ledger historical_violations does not match its own releases: "
            f"recorded {_fmt(recorded)}, derived {_fmt(multi)}"
        )

    # 2. Every published path exists at its repository path with its latest bytes.
    for wheel_path, (digest, version, _seen) in sorted(published.items()):
        try:
            repo_path = wheel_to_repo_path(wheel_path, mapping)
        except GuardError as exc:
            problems.append(str(exc))
            continue
        target = repo_root / repo_path
        if not target.is_file():
            problems.append(
                f"{repo_path}: published in {version} (as {wheel_path}) and now missing. "
                "Published migrations may not be deleted or renamed; a store that "
                "applied it records its checksum."
            )
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            problems.append(
                f"{repo_path}: bytes changed after publication. Latest published "
                f"({version}) sha256 {digest}, tree has {actual}. Restore the "
                "published bytes and put the change in a new migration."
            )

    # 3. Shape of the migration directories: numeric, unique, append-only.
    # Unmappable published paths were already reported in step 2.
    mapped: dict[str, str] = {}
    for wheel_path in published:
        try:
            mapped[wheel_path] = wheel_to_repo_path(wheel_path, mapping)
        except GuardError:
            continue
    migration_dirs = sorted({repo_path.rsplit("/", 1)[0] for repo_path in mapped.values()})
    for rel_dir in migration_dirs:
        directory = repo_root / rel_dir
        pub_versions: dict[int, str] = {}
        for repo_path in mapped.values():
            if repo_path.rsplit("/", 1)[0] == rel_dir:
                m = _VERSION_RE.match(repo_path.rsplit("/", 1)[1])
                if m:
                    pub_versions[int(m.group(1))] = repo_path
        max_published = max(pub_versions, default=-1)
        by_version: dict[int, list[str]] = {}
        for sql in sorted(directory.glob("*.sql")) if directory.is_dir() else []:
            rel = f"{rel_dir}/{sql.name}"
            m = _VERSION_RE.match(sql.name)
            if not m:
                problems.append(
                    f"{rel}: no numeric version prefix. The runner silently skips such "
                    "a file, so it would ship and never apply."
                )
                continue
            by_version.setdefault(int(m.group(1)), []).append(rel)
        for number, paths in sorted(by_version.items()):
            if len(paths) > 1:
                problems.append(
                    f"migration version {number} is claimed by {len(paths)} files: {paths}"
                )
            for rel in paths:
                if rel in pub_versions.values():
                    continue
                if number <= max_published:
                    problems.append(
                        f"{rel}: unpublished migration numbered {number} sorts at or "
                        f"before the latest published migration ({max_published}, "
                        f"{pub_versions[max_published]}). Stores already past "
                        f"{max_published} would never apply it. Number it above "
                        f"{max_published}."
                    )
    return problems


def _fmt(m: Mapping[str, frozenset[str]]) -> str:
    return json.dumps({k: sorted(v) for k, v in sorted(m.items())}, indent=None)


def check_release(
    ledger: Mapping[str, Any],
    version: str,
    repo_root: Path = REPO_ROOT,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
) -> list[str]:
    problems = []
    if version in ledger["releases"]:
        problems.append(f"{version} is already published on PyPI; it cannot be re-released")
    known = sorted(ledger["releases"], key=_version_key)
    if known and _version_key(version) <= _version_key(known[-1]):
        problems.append(
            f"{version} does not sort after the latest published release {known[-1]}"
        )
    return problems + check_tree(ledger, repo_root, frozen)


# --------------------------------------------------------------------------
# CLI


def _canonical(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check-tree", help="offline: the tree honours the ledger")
    sub.add_parser("verify-ledger", help="network: the ledger equals PyPI")
    rel = sub.add_parser("check-release", help="publish workflow pre-build gate")
    rel.add_argument("--version", required=True)
    sub.add_parser("build", help="network: rewrite the ledger from PyPI")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "build":
            ledger = build_ledger(_path_mapping(REPO_ROOT / "pyproject.toml"))
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            LEDGER_PATH.write_text(_canonical(ledger))
            print(f"wrote {LEDGER_PATH} ({len(ledger['releases'])} releases)")
            return 0
        if args.cmd == "verify-ledger":
            committed = load_ledger()
            fresh = build_ledger(_path_mapping(REPO_ROOT / "pyproject.toml"))
            if _canonical(fresh) != _canonical(committed):
                missing = sorted(set(fresh["releases"]) - set(committed["releases"]))
                extra = sorted(set(committed["releases"]) - set(fresh["releases"]))
                changed = sorted(
                    v
                    for v in set(fresh["releases"]) & set(committed["releases"])
                    if fresh["releases"][v] != committed["releases"][v]
                )
                print(
                    "ledger does not match PyPI. "
                    f"Unrecorded releases: {missing}; recorded but absent from PyPI: "
                    f"{extra}; recorded differently: {changed}; other fields differ: "
                    f"{not (missing or extra or changed)}. If a release was just "
                    "published, run `build` and commit the result.",
                    file=sys.stderr,
                )
                return 1
            problems = check_tree(fresh)
        elif args.cmd == "check-release":
            problems = check_release(load_ledger(), args.version)
        else:
            problems = check_tree(load_ledger())
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
