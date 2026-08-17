#!/usr/bin/env python3
"""Cross-branch epoch-debt ratchet (SUITE-RECONCILIATION.md §2.1).

Compares the working tree's tests/epoch_blocked_manifest.json against the
same file at a base git ref. Rules (design-review round-4 B3: sets, not
counts — a count-only ratchet would allow one-for-one debt replacement):

- base HAS a manifest  -> the current NODE SET must be a subset of the base
  node set (shrink-only, entry-identity preserved).
- base has NO manifest -> one-time ratified bootstrap: the manifest file's
  sha256 must equal the ratified digest below. Absence of a base manifest is
  not license to establish arbitrary debt, and an arbitrary same-size set is
  refused too.

Prints the debt figure; appends it to $GITHUB_STEP_SUMMARY when set. Exits
nonzero on violation, so CI is the enforcement, not convention.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# sha256 of tests/epoch_blocked_manifest.json as ratified at the
# establishing reconciliation commit (881 entries). Recorded in
# docs/0.6.0/SUITE-RECONCILIATION.md §5.
RATIFIED_BOOTSTRAP_SHA256 = "a78b5d9e9d76ca132dd4b4b7dd78bfaea4e1471e7db61645fd33bd700b34f949"
# sha256 of tests/epoch_blocked_inventory.txt (3073 nodes) — used only in
# the one-time bootstrap case. After bootstrap, inventory immutability is
# anchored to the TARGET BRANCH (byte-identity via git show), which no PR
# can edit alongside its bypass (round-5 B5).
RATIFIED_INVENTORY_SHA256 = "8696641ae892240f8c6f42d5dc432c12a3345b95b9cd8d3f352789152824dec3"
MANIFEST_REL = "tests/epoch_blocked_manifest.json"
INVENTORY_REL = "tests/epoch_blocked_inventory.txt"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _nodes(manifest_text: str) -> set[str]:
    data = json.loads(manifest_text)
    entries = data["entries"]
    if data.get("baseline_count") != len(entries):
        sys.exit(
            "epoch-debt: baseline_count != len(entries) "
            f"({data.get('baseline_count')} vs {len(entries)})"
        )
    nodes = {e["node_id"] for e in entries}
    if len(nodes) != len(entries):
        sys.exit("epoch-debt: duplicate node_id entries in manifest")
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="git ref to ratchet against")
    args = parser.parse_args()

    manifest_bytes = (REPO_ROOT / MANIFEST_REL).read_bytes()
    current = _nodes(manifest_bytes.decode("utf-8"))

    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{args.base}:{MANIFEST_REL}"],
        capture_output=True,
        text=True,
        check=False,
    )
    new_nodes: set[str] = set()
    inventory_bytes = (REPO_ROOT / INVENTORY_REL).read_bytes()
    if proc.returncode == 0:
        # Inventory immutability, anchored to the TARGET BRANCH — not to an
        # in-repo pin a PR could edit alongside its bypass (round-5 B5). The
        # inventory never changes after bootstrap; byte-identity or refusal.
        inv_proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"{args.base}:{INVENTORY_REL}"],
            capture_output=True,
            check=False,
        )
        if inv_proc.returncode != 0 or inv_proc.stdout != inventory_bytes:
            print(
                "epoch-debt: tests/epoch_blocked_inventory.txt differs from the "
                f"base ref {args.base}. The pre-reconciliation inventory is "
                "immutable; deleting a test requires a retirement-ledger entry, "
                "never an inventory edit (SUITE-RECONCILIATION.md §2.2)",
                file=sys.stderr,
            )
            return 1
        base_nodes = _nodes(proc.stdout)
        new_nodes = current - base_nodes
        verdict_ok = not new_nodes
        rule = f"shrink-only node set vs {args.base} ({len(base_nodes)})"
    else:
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        inv_digest = hashlib.sha256(inventory_bytes).hexdigest()
        verdict_ok = (
            digest == RATIFIED_BOOTSTRAP_SHA256
            and inv_digest == RATIFIED_INVENTORY_SHA256
        )
        rule = "bootstrap: base ref has no manifest, files must match the ratified digests"

    verdict = "OK" if verdict_ok else "VIOLATION"
    line = f"epoch debt: {len(current)} blocked test node(s) [{rule}] -> {verdict}"
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(
                "**Epoch debt (SUITE-RECONCILIATION.md §2.1):** "
                f"{len(current)} blocked node(s); {rule}: {verdict}\n"
            )

    if not verdict_ok:
        if new_nodes:
            print(
                f"epoch-debt: {len(new_nodes)} node(s) added to the manifest "
                f"(first 5: {sorted(new_nodes)[:5]}); new epoch-blocked tests "
                "require a ratified amendment to docs/0.6.0/SUITE-RECONCILIATION.md, "
                "not a manifest edit",
                file=sys.stderr,
            )
        else:
            print(
                "epoch-debt: manifest does not match the ratified bootstrap digest "
                f"{RATIFIED_BOOTSTRAP_SHA256}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
