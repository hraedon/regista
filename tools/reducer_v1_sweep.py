#!/usr/bin/env python3
"""Cross-interpreter determinism sweep for reducer v1 (Gate 0, P0.2).

Runs the conformance vectors under every interpreter it is given and reports whether the
resulting digests are byte-identical. Used two ways:

* ``--emit`` — run under one interpreter and print its results as JSON. This is what the
  child processes do.
* ``--sweep py1 py2 …`` — run ``--emit`` under each interpreter and compare. Non-zero exit if
  any digest differs, or if any interpreter disagrees about which inputs are rejected.

The sweep needs no dependencies beyond the standard library and the vendored canonicalizer, so
it runs under a bare interpreter with no virtualenv — which is the point: an auditor
reproducing a signed verdict has whatever Python they have.

    python3 tools/reducer_v1_sweep.py --sweep python3.12 python3.13 python3.14 pypy3.11

``--freeze <path>`` writes the agreed digests to a JSON file for the pytest conformance test to
assert against.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))


def _load_reducer():
    """Import `_reducer` without executing `regista/__init__.py`.

    The package pulls in psycopg, structlog and the rest; the reducer needs none of them, and
    an auditor recomputing a digest should not have to install a database driver to do it.
    Loading it under a synthetic package keeps the relative imports working while proving the
    module's dependency surface is the standard library plus the vendored canonicalizer.
    """
    import importlib.util
    import types

    pkg_dir = ROOT / "src" / "regista"
    pkg = types.ModuleType("regista_min")
    pkg.__path__ = [str(pkg_dir)]  # type: ignore[attr-defined]
    sys.modules["regista_min"] = pkg

    vendor = types.ModuleType("regista_min._vendor")
    vendor.__path__ = [str(pkg_dir / "_vendor")]  # type: ignore[attr-defined]
    sys.modules["regista_min._vendor"] = vendor

    # `_jcs` imports the canonicalizer by absolute name, so the aliases must exist
    # *before* it is executed.
    sys.modules.setdefault("regista", pkg)
    sys.modules.setdefault("regista._vendor", vendor)

    for name, path in (
        ("regista_min._vendor.rfc8785", pkg_dir / "_vendor" / "rfc8785.py"),
        ("regista_min._jcs", pkg_dir / "_jcs.py"),
        ("regista_min._reducer", pkg_dir / "_reducer.py"),
    ):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        alias = name.replace("regista_min", "regista", 1)
        sys.modules.setdefault(alias, module)

    return sys.modules["regista_min._reducer"]


def emit() -> dict[str, object]:
    import platform

    reducer = _load_reducer()
    reducer_error = reducer.ReducerError
    content_state_digest = reducer.content_state_digest

    from reducer_v1_vectors import REJECT_RAW, REJECT_VECTORS, VECTORS

    result: dict[str, object] = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "digests": {},
        "digests_content_only": {},
        "rejected": {},
        "rejected_raw": {},
    }

    digests: dict[str, str] = {}
    content_only: dict[str, str] = {}
    for name, envelopes, definitions in VECTORS:
        digests[name] = content_state_digest(envelopes, workflow_definitions=definitions)
        content_only[name] = content_state_digest(
            envelopes, workflow_definitions=definitions, include_claim_state=False
        )
    result["digests"] = digests
    result["digests_content_only"] = content_only

    rejected: dict[str, str] = {}
    for name, envelopes, definitions in REJECT_VECTORS:
        try:
            content_state_digest(envelopes, workflow_definitions=definitions)
        except reducer_error:
            rejected[name] = "rejected"
        except Exception as exc:  # pragma: no cover - a non-ReducerError is itself a finding
            rejected[name] = f"WRONG-ERROR:{type(exc).__name__}"
        else:
            rejected[name] = "ACCEPTED"
    result["rejected"] = rejected

    rejected_raw: dict[str, str] = {}
    for name, raw in REJECT_RAW:
        # Through the whole reducer, not just the parser: some of these are rejected at
        # parse and some at reduction, and a caller only ever sees the composed function.
        try:
            content_state_digest([raw], workflow_definitions={})
        except reducer_error:
            rejected_raw[name] = "rejected"
        except Exception as exc:  # pragma: no cover
            rejected_raw[name] = f"WRONG-ERROR:{type(exc).__name__}"
        else:
            rejected_raw[name] = "ACCEPTED"
    result["rejected_raw"] = rejected_raw
    return result


def sweep(interpreters: list[str], freeze: str | None) -> int:
    runs: list[tuple[str, dict]] = []
    for interp in interpreters:
        for seed in ("0", "1", "random"):
            proc = subprocess.run(
                [interp, __file__, "--emit"],
                capture_output=True,
                text=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
                cwd=str(ROOT),
            )
            if proc.returncode != 0:
                print(f"FAILED to run {interp} (PYTHONHASHSEED={seed}):\n{proc.stderr}")
                return 2
            data = json.loads(proc.stdout)
            label = f"{data['implementation']} {data['version']} (hashseed={seed})"
            runs.append((label, data))

    reference_label, reference = runs[0]
    problems = 0
    for label, data in runs[1:]:
        for key in ("digests", "digests_content_only", "rejected", "rejected_raw"):
            if data[key] != reference[key]:
                problems += 1
                print(f"DIVERGENCE in {key}: {label} vs {reference_label}")
                for name in sorted(set(data[key]) | set(reference[key])):  # type: ignore[arg-type]
                    a = reference[key].get(name)  # type: ignore[union-attr]
                    b = data[key].get(name)  # type: ignore[union-attr]
                    if a != b:
                        print(f"    {name}: {reference_label}={a!r}  {label}={b!r}")

    bad = {k: v for k, v in reference["rejected"].items() if v != "rejected"}  # type: ignore[union-attr]
    bad_raw = {k: v for k, v in reference["rejected_raw"].items() if v != "rejected"}  # type: ignore[union-attr]
    if bad or bad_raw:
        problems += 1
        print(f"FAIL-CLOSED VIOLATION: {bad} {bad_raw}")

    print()
    for label, _ in runs:
        print(f"  ran: {label}")
    print(
        f"\n{len(reference['digests'])} vectors x 2 field sets, "  # type: ignore[arg-type]
        f"{len(reference['rejected']) + len(reference['rejected_raw'])} rejection cases, "  # type: ignore[arg-type]
        f"{len(runs)} runs across {len(interpreters)} interpreters."
    )
    print("RESULT:", "IDENTICAL" if problems == 0 else f"{problems} DIVERGENCE(S)")

    if freeze and problems == 0:
        Path(freeze).write_text(
            json.dumps(
                {
                    "reducer_version": 1,
                    "interpreters": sorted(
                        {f"{d['implementation']} {d['version']}" for _, d in runs}
                    ),
                    "digests": reference["digests"],
                    "digests_content_only": reference["digests_content_only"],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"froze digests to {freeze}")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--sweep", nargs="+", metavar="PYTHON")
    ap.add_argument("--freeze", default=None)
    args = ap.parse_args()

    if args.emit:
        print(json.dumps(emit(), sort_keys=True))
        return 0
    if args.sweep:
        return sweep(args.sweep, args.freeze)
    ap.error("one of --emit or --sweep is required")
    return 2


if __name__ == "__main__":
    sys.exit(main())
