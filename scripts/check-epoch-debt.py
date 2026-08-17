#!/usr/bin/env python3
"""Cross-branch epoch-debt ratchet (SUITE-RECONCILIATION.md §2.1).

Compares the working tree's tests/epoch_blocked_manifest.json entry count
against the same file at a base git ref. Rules:

- base HAS a manifest  -> current count must be <= base count (shrink-only).
- base has NO manifest -> one-time ratified bootstrap: current count must be
  EXACTLY the ratified 874. Anything else is refused — absence of a base
  manifest is not license to establish arbitrary debt.

Prints the debt figure; appends it to $GITHUB_STEP_SUMMARY when set. Exits
nonzero on violation, so CI is the enforcement, not convention.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

RATIFIED_BOOTSTRAP_COUNT = 874
MANIFEST_REL = "tests/epoch_blocked_manifest.json"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _count(manifest_text: str) -> int:
    data = json.loads(manifest_text)
    entries = data["entries"]
    if data.get("baseline_count") != len(entries):
        sys.exit(
            "epoch-debt: baseline_count != len(entries) "
            f"({data.get('baseline_count')} vs {len(entries)})"
        )
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="git ref to ratchet against")
    args = parser.parse_args()

    current = _count((REPO_ROOT / MANIFEST_REL).read_text())

    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{args.base}:{MANIFEST_REL}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        base = _count(proc.stdout)
        verdict_ok = current <= base
        rule = f"shrink-only vs {args.base} ({base})"
    else:
        base = None
        verdict_ok = current == RATIFIED_BOOTSTRAP_COUNT
        rule = (
            "bootstrap: base ref has no manifest, count must be exactly "
            f"{RATIFIED_BOOTSTRAP_COUNT}"
        )

    verdict = "OK" if verdict_ok else "VIOLATION"
    line = f"epoch debt: {current} blocked test node(s) [{rule}] -> {verdict}"
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(
                "**Epoch debt (SUITE-RECONCILIATION.md §2.1):** "
                f"{current} blocked node(s); {rule}\n"
            )

    if not verdict_ok:
        if base is not None:
            print(
                f"epoch-debt: manifest grew {base} -> {current}; new epoch-blocked tests "
                "require a ratified amendment to docs/0.6.0/SUITE-RECONCILIATION.md, "
                "not a manifest edit",
                file=sys.stderr,
            )
        else:
            print(
                f"epoch-debt: bootstrap must establish exactly {RATIFIED_BOOTSTRAP_COUNT} "
                f"entries, found {current}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
