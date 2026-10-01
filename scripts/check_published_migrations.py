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
every ``*.sql`` file each one ships. The ledger is a cache of PyPI. It is checked
against PyPI (``verify-ledger``) and against its own git history
(``check-monotonic``), so editing it to bless a change, or to forget a release,
is DETECTED by CI. Detection becomes enforcement only when those CI jobs are
required status checks on ``main``. As of this writing ``main`` has no branch
protection, so a red run is a signal a reviewer must honour, not a lock.

Subcommands:

``check-dist DIST_DIR`` (offline; the AUTHORITY - CI and the publish build job)
    The rules below, applied to the .sql files the built wheel(s) actually
    contain. Each sdist's ``migrations/`` must match the wheel. ``uv build``
    builds the wheel from the sdist, so sdist-only mappings are covered.

``check-tree`` (offline, runs in pytest; a conservative EARLY signal)
    The same rules over a model of the hatch build: every ``packages`` dir and
    every directory-valued ``force-include`` of the wheel target. Hatch has
    selection rules this model does not reproduce (file-valued or global
    force-include, only-include, sources rewrites, symlink traversal,
    exclude/VCS-ignore), so it can miss a file (check-dist catches that) or
    count an excluded one (which fails safe). The rules:

    * every published migration is still packaged, with the bytes of its
      **latest** release;
    * a path whose published bytes differ between releases is allowed only if
      it is one of the exactly-pinned historical violations below;
    * every packaged ``.sql`` lands directly in the one directory the runner
      reads, from one source (tree check), under a canonical name (lower-case
      ``.sql``, ASCII-digit version before the first ``_``), with a unique
      version. An unpublished migration must sort **after** every published
      one. The runner applies by set membership, so a late low number would
      run out of order on existing stores.

``check-monotonic --base REF`` (git)
    Every release and withdrawal recorded at ``REF`` is still recorded,
    unchanged. Published history only grows. A release PyPI no longer serves
    (an owner can delete one) stays in the ledger under
    ``withdrawn_from_pypi``, because stores may already have applied its bytes.
    A withdrawal is accepted only for a release ``REF`` already recorded, so the
    ledger cannot invent "published" history. A base without a ledger is
    accepted only if it also predates this guard (the one-time bootstrap).

``verify-ledger`` (network: pypi.org)
    Re-download every release PyPI lists, verify each file against PyPI's
    sha256 digest, recompute the ledger, and require it to equal the committed
    one exactly. An edit to any release PyPI still serves, or a new PyPI
    release not yet recorded, fails. A new release therefore turns CI red until
    the ledger records it, and from then on its migrations are frozen. Releases
    PyPI no longer serves are carried over as withdrawn, and only
    ``check-monotonic`` can judge them, so the two always run together.

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
import subprocess
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


class GuardError(Exception):
    """A violation. The message says what changed and what to do instead."""


# --------------------------------------------------------------------------
# Version ordering (PEP 440 subset: the release segment is all this project uses)


def _version_key(version: str) -> tuple[int, ...]:
    parts = version.split(".")
    if not all(p.isascii() and p.isdigit() for p in parts):
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


def build_ledger(
    mapping: list[tuple[str, str]], prior: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Rebuild from PyPI. Releases ``prior`` recorded that PyPI no longer serves are
    KEPT and listed in ``withdrawn_from_pypi``: a deletion on PyPI does not unpublish
    bytes that stores may already have applied, so it must never shrink the ledger."""
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
                members = _sql_members_sdist(blob, mapping)
                if sdist_sql is not None and members != sdist_sql:
                    raise GuardError(f"{version}: two sdists ship different migrations")
                sdist_sql = members
        if wheel_sql is None:
            raise GuardError(f"{version}: no wheel on PyPI; cannot establish what installs")
        if sdist_sql is not None and sdist_sql != wheel_sql:
            differing = sorted(
                k for k in wheel_sql if k in sdist_sql and sdist_sql[k] != wheel_sql[k]
            )
            raise GuardError(
                f"{version}: the sdist and the wheel ship different migration bytes: "
                f"only-wheel={sorted(set(wheel_sql) - set(sdist_sql))} "
                f"only-sdist={sorted(set(sdist_sql) - set(wheel_sql))} "
                f"differing={differing}"
            )
        entry["migrations"] = dict(sorted(wheel_sql.items()))
        releases[version] = entry
    withdrawn = sorted(
        set((prior or {}).get("releases", {})) - set(releases), key=_version_key
    )
    for version in withdrawn:
        assert prior is not None
        releases[version] = prior["releases"][version]
    releases = {v: releases[v] for v in sorted(releases, key=_version_key)}
    return {
        "format": LEDGER_FORMAT,
        "project": PROJECT,
        "source": "PyPI wheel and sdist bytes; regenerate with "
        "`python scripts/check_published_migrations.py build`",
        "releases": releases,
        "withdrawn_from_pypi": withdrawn,
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


#: The one directory the runner reads, as a wheel path. _migrations._migrations_dir()
#: resolves ``<package>/migrations`` and globs ``*.sql`` in it (not recursively).
#: tests/test_published_migrations.py pins this against the runner itself.
RUNNER_WHEEL_DIR = "regista/migrations/"


def _in_runner_dir(wheel_path: str) -> bool:
    rest = wheel_path[len(RUNNER_WHEEL_DIR) :]
    return wheel_path.startswith(RUNNER_WHEEL_DIR) and "/" not in rest


def runner_version(name: str) -> int | None:
    """The version the runner would assign to ``name``, or None if it skips it.

    Mirrors ``_migrations.discover_migrations``: the glob is ``*.sql`` (case-
    sensitive) and the version is ``int(stem.split("_", 1)[0])``. ASCII digits are
    required here even though ``int()`` accepts other Unicode digits: a migration
    numbered in superscripts is a defect to refuse, not a version to honour.
    """
    if not name.endswith(".sql"):
        return None
    head = name[: -len(".sql")].split("_", 1)[0]
    if not (head.isascii() and head.isdigit()):
        return None
    return int(head)


def shipped_sql(repo_root: Path, mapping: list[tuple[str, str]]) -> dict[str, list[str]]:
    """wheel path -> repository source paths, for every .sql the build would package.

    Any suffix case counts (``.SQL`` ships too); the runner rule decides later
    whether it would ever apply.
    """
    out: dict[str, list[str]] = {}
    for wheel_prefix, repo_prefix in mapping:
        base = repo_root / repo_prefix
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if f.is_file() and f.suffix.lower() == ".sql":
                rel = f.relative_to(base).as_posix()
                out.setdefault(wheel_prefix + rel, []).append(repo_prefix + rel)
    return out


def _check_ledger_consistency(
    published: Mapping[str, tuple[str, str, set[str]]],
    ledger: Mapping[str, Any],
    frozen: Mapping[str, frozenset[str]],
) -> list[str]:
    """Historical multiplicity is exactly the frozen set, and the ledger agrees with itself."""
    problems: list[str] = []
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
    return problems


def _check_shape(
    published: Mapping[str, tuple[str, str, set[str]]],
    shipped: Mapping[str, tuple[str, str]],
) -> list[str]:
    """Rules over the packaged .sql set, keyed by wheel path -> (sha256, label).

    The same rules judge the source tree (an early, conservative model of the
    build) and a built wheel (the authority: what actually installs).
    """
    problems: list[str] = []
    for wheel_path, (digest, version, _seen) in sorted(published.items()):
        if wheel_path not in shipped:
            problems.append(
                f"{wheel_path}: published in {version} and no longer packaged. Published "
                "migrations may not be deleted or renamed; a store that applied it "
                "records its checksum."
            )
        elif shipped[wheel_path][0] != digest:
            problems.append(
                f"{shipped[wheel_path][1]}: bytes changed after publication. Latest "
                f"published ({version}) sha256 {digest}, now {shipped[wheel_path][0]}. "
                "Restore the published bytes and put the change in a new migration."
            )
    pub_versions: dict[int, str] = {}
    for wheel_path in published:
        if _in_runner_dir(wheel_path):
            number = runner_version(wheel_path.rsplit("/", 1)[1])
            if number is not None:
                pub_versions[number] = wheel_path
    max_published = max(pub_versions, default=-1)
    by_version: dict[int, list[str]] = {}
    for wheel_path, (_digest, label) in sorted(shipped.items()):
        where = f"{label} (ships as {wheel_path})"
        if not _in_runner_dir(wheel_path):
            problems.append(
                f"{where}: a packaged .sql outside {RUNNER_WHEEL_DIR}. The runner applies "
                f"only top-level {RUNNER_WHEEL_DIR}*.sql, so this would ship and never "
                "apply. Move it or stop shipping it."
            )
            continue
        number = runner_version(wheel_path.rsplit("/", 1)[1])
        if number is None:
            problems.append(
                f"{where}: not a canonical migration name (a lower-case .sql suffix and "
                "an ASCII-digit version before the first '_'). Depending on the name "
                "the runner either skips it or derives a version via int(), e.g. from "
                "'+4'. Both are refused."
            )
            continue
        by_version.setdefault(number, []).append(wheel_path)
    for number, paths in sorted(by_version.items()):
        if len(paths) > 1:
            problems.append(f"migration version {number} is claimed by {len(paths)} files: {paths}")
        for wheel_path in paths:
            if wheel_path in published:
                continue
            if number <= max_published:
                problems.append(
                    f"{shipped[wheel_path][1]}: unpublished migration numbered {number} "
                    f"sorts at or before the latest published migration ({max_published}, "
                    f"{pub_versions[max_published]}). The runner applies by set "
                    "membership, so stores already past it would run this late and out "
                    f"of order. Number it above {max_published}."
                )
    return problems


def check_tree(
    ledger: Mapping[str, Any],
    repo_root: Path = REPO_ROOT,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
) -> list[str]:
    """The source tree, judged through a CONSERVATIVE model of the hatch build.

    This is the fast early signal (it runs in pytest). It is not the authority:
    hatch has selection rules this model does not reproduce (file-valued and
    global force-include, only-include, sources rewrites, symlink traversal,
    exclude and VCS-ignore). ``check-dist`` over the built wheel is the
    authority and gates publication. Where this model overcounts, it fails safe.
    """
    published = latest_published(ledger)
    problems = _check_ledger_consistency(published, ledger, frozen)
    mapping = _path_mapping(repo_root / "pyproject.toml")
    sources = shipped_sql(repo_root, mapping)
    for wheel_path, srcs in sorted(sources.items()):
        if len(srcs) > 1:
            problems.append(
                f"{wheel_path} would be shipped from {len(srcs)} source files "
                f"{srcs}. Exactly one source may produce a packaged migration."
            )
    runner_sources = sorted(
        {src.rsplit("/", 1)[0] for w, srcs in sources.items() if _in_runner_dir(w) for src in srcs}
    )
    if len(runner_sources) > 1:
        problems.append(
            f"{RUNNER_WHEEL_DIR} is assembled from {len(runner_sources)} source "
            f"directories {runner_sources}. An editable install reads only one of them "
            "(src/regista/migrations/ is preferred when it exists), so the runner and the "
            "wheel would apply different sets. Keep one source directory."
        )
    for wheel_path in published:
        if wheel_path not in sources:
            try:
                wheel_to_repo_path(wheel_path, mapping)
            except GuardError as exc:
                problems.append(str(exc))
    shipped = {
        w: (hashlib.sha256((repo_root / srcs[0]).read_bytes()).hexdigest(), srcs[0])
        for w, srcs in sources.items()
    }
    return problems + _check_shape(published, shipped)


def dist_sql(dist_dir: Path) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """The packaged .sql set of the built wheel(s) in ``dist_dir``, plus agreement problems.

    Every wheel must carry the same set. Each sdist's ``migrations/`` must equal the
    wheel's runner directory byte-for-byte, so an sdist a user builds from cannot
    install something the checked wheel does not.
    """
    problems: list[str] = []
    wheels = sorted(dist_dir.glob("*.whl"))
    if not wheels:
        raise GuardError(f"{dist_dir}: no wheel to check; refusing to vacuously pass")
    shipped: dict[str, tuple[str, str]] | None = None
    for whl in wheels:
        digests = _sql_members_wheel(whl.read_bytes())
        members = {p: (d, f"{whl.name}:{p}") for p, d in digests.items()}
        if shipped is not None and {p: d for p, (d, _) in members.items()} != {
            p: d for p, (d, _) in shipped.items()
        }:
            problems.append(f"{whl.name} ships different .sql files than {wheels[0].name}")
        shipped = shipped or members
    assert shipped is not None
    runner = {p: d for p, (d, _) in shipped.items() if _in_runner_dir(p)}
    for sdist in sorted(dist_dir.glob("*.tar.gz")):
        with tarfile.open(sdist, mode="r:gz") as tf:
            found: dict[str, str] = {}
            for member in tf.getmembers():
                parts = member.name.split("/")
                if member.isfile() and len(parts) == 3 and parts[1] == "migrations":
                    fh = tf.extractfile(member)
                    assert fh is not None
                    found[RUNNER_WHEEL_DIR + parts[2]] = hashlib.sha256(fh.read()).hexdigest()
        sql_found = {p: d for p, d in found.items() if p.lower().endswith(".sql")}
        differing = sorted(k for k in runner if k in sql_found and sql_found[k] != runner[k])
        if sql_found != runner:
            problems.append(
                f"{sdist.name}: migrations/ differs from the wheel's {RUNNER_WHEEL_DIR} "
                f"(only-sdist={sorted(set(sql_found) - set(runner))}, "
                f"only-wheel={sorted(set(runner) - set(sql_found))}, "
                f"differing={differing})"
            )
    return shipped, problems


def check_dist(
    ledger: Mapping[str, Any],
    dist_dir: Path,
    frozen: Mapping[str, frozenset[str]] = FROZEN_HISTORICAL_VIOLATIONS,
) -> list[str]:
    """The AUTHORITATIVE check: the rules applied to what the built wheel installs."""
    published = latest_published(ledger)
    problems = _check_ledger_consistency(published, ledger, frozen)
    shipped, agreement = dist_sql(dist_dir)
    return problems + agreement + _check_shape(published, shipped)


def check_monotonic(
    base: Mapping[str, Any] | None, head: Mapping[str, Any], *, base_has_guard: bool = False
) -> list[str]:
    """The ledger only grows, and a withdrawal must be of a release already on record.

    Every release the base ledger records must still be recorded, unchanged, at
    head. A release in head's ``withdrawn_from_pypi`` must have been recorded as
    a release in the base: head cannot vouch for history that PyPI no longer
    serves, so a fabricated "withdrawn" release (which would otherwise make an
    arbitrary path count as published) is refused. With no base ledger, head may
    record no withdrawals at all, and the bootstrap is allowed only when the
    base predates the guard itself.
    """
    head_withdrawn = set(head.get("withdrawn_from_pypi") or [])
    if base is None:
        problems = []
        if base_has_guard:
            problems.append(
                "base has the published-migration guard but no ledger; the ledger was "
                "deleted. Bootstrap without a base ledger is allowed only once, from a "
                "base that predates the guard."
            )
        if head_withdrawn:
            problems.append(
                f"founding ledger records withdrawn releases {sorted(head_withdrawn)}; a "
                "ledger cannot vouch for releases PyPI no longer serves on its own say-so"
            )
        return problems
    problems = []
    for version, entry in base["releases"].items():
        if version not in head["releases"]:
            problems.append(f"ledger dropped release {version}; published history only grows")
        elif head["releases"][version] != entry:
            problems.append(f"ledger rewrote release {version}; recorded releases are immutable")
    lost = set(base.get("withdrawn_from_pypi") or []) - head_withdrawn
    if lost:
        problems.append(f"ledger un-recorded withdrawn releases {sorted(lost)}")
    unvouched = head_withdrawn - set(base["releases"])
    if unvouched:
        problems.append(
            f"ledger records withdrawn releases {sorted(unvouched)} that the base never "
            "recorded as published; only a release already on record can be withdrawn"
        )
    return problems


def _ledger_at(ref: str, repo_root: Path = REPO_ROOT) -> tuple[dict[str, Any] | None, bool]:
    """(ledger at ``ref`` or None, whether ``ref`` already carries this guard)."""
    def show(path: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{ref}:{path}"], capture_output=True
        )

    exists = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
    )
    if exists.returncode != 0:
        raise GuardError(f"base ref {ref!r} is not a commit in this checkout")
    guard_rel = Path(__file__).resolve().relative_to(REPO_ROOT).as_posix()
    has_guard = show(guard_rel).returncode == 0
    proc = show(LEDGER_PATH.relative_to(REPO_ROOT).as_posix())
    if proc.returncode != 0:
        return None, has_guard
    loaded: dict[str, Any] = json.loads(proc.stdout)
    return loaded, has_guard


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
    mono = sub.add_parser("check-monotonic", help="git: the ledger only grows vs a base ref")
    mono.add_argument("--base", required=True)
    dist = sub.add_parser("check-dist", help="AUTHORITATIVE: the rules over built artifacts")
    dist.add_argument("dist_dir", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "build":
            prior = load_ledger() if LEDGER_PATH.exists() else None
            ledger = build_ledger(_path_mapping(REPO_ROOT / "pyproject.toml"), prior)
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            LEDGER_PATH.write_text(_canonical(ledger))
            print(f"wrote {LEDGER_PATH} ({len(ledger['releases'])} releases)")
            return 0
        if args.cmd == "verify-ledger":
            committed = load_ledger()
            fresh = build_ledger(_path_mapping(REPO_ROOT / "pyproject.toml"), committed)
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
        elif args.cmd == "check-monotonic":
            base, base_has_guard = _ledger_at(args.base)
            problems = check_monotonic(base, load_ledger(), base_has_guard=base_has_guard)
        elif args.cmd == "check-dist":
            problems = check_dist(load_ledger(), args.dist_dir)
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
