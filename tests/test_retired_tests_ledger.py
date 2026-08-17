"""Retired-test ledger validator (SUITE-RECONCILIATION.md §2.2).

Every node in the committed pre-reconciliation collection inventory must be
(a) still collected, (b) in the epoch-blocked manifest (whose
collection-existence meta-guard already ties it to collection), or (c)
recorded in the retirement ledger with a disposition. A test cannot vanish
from the suite without a recorded decision.

Round-4 hardening:
- The inventory is IMMUTABLE-BY-HASH: its sha256 is pinned here, so a PR
  cannot delete a test and quietly drop its inventory line — shrinking the
  inventory requires editing the pinned digest in the same diff, which is
  exactly the visible, reviewable act the ledger exists to force.
- Collection runs without the ``-m 'not slow'`` filter: the slow tier is
  inside the reconciliation, not outside it.
- Ledger entries must be unique, refer to real (inventory) nodes, be absent
  from current collection, and use the exact documented dispositions.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO_ROOT / "tests" / "epoch_blocked_inventory.txt"
MANIFEST_PATH = REPO_ROOT / "tests" / "epoch_blocked_manifest.json"
LEDGER_PATH = REPO_ROOT / "tests" / "retired_tests_ledger.json"

# sha256 of tests/epoch_blocked_inventory.txt as ratified at the establishing
# reconciliation commit (3073 collected nodes, no marker filter). Changing
# the inventory requires changing this digest in the same, reviewable diff.
RATIFIED_INVENTORY_SHA256 = "8696641ae892240f8c6f42d5dc432c12a3345b95b9cd8d3f352789152824dec3"

# Exact documented dispositions (SUITE-RECONCILIATION.md §2.2).
_DISPOSITION_RE = re.compile(r"^(dies_with_v5|deleted_by: P1\.4|coverage_owed)$")
_WORK_ITEM_RE = re.compile(
    r"^(WI-\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


@pytest.fixture(scope="module")
def inventory() -> set[str]:
    data = INVENTORY_PATH.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == RATIFIED_INVENTORY_SHA256, (
        "tests/epoch_blocked_inventory.txt does not match its ratified sha256 — "
        "the pre-reconciliation inventory is immutable; if you are deliberately "
        "re-ratifying it, update RATIFIED_INVENTORY_SHA256 in the same diff "
        f"(found {digest})"
    )
    return {line.strip() for line in data.decode().splitlines() if "::" in line}


@pytest.fixture(scope="module")
def full_collection() -> set[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", ""],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 5), (
        f"collection failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
    return {line.strip() for line in proc.stdout.splitlines() if "::" in line}


def test_ledger_entries_are_well_formed(inventory: set[str], full_collection: set[str]) -> None:
    ledger = json.loads(LEDGER_PATH.read_text())
    node_ids = [e.get("node_id") for e in ledger["entries"]]
    assert len(node_ids) == len(set(node_ids)), "duplicate node_id in ledger"
    for entry in ledger["entries"]:
        node_id = entry.get("node_id")
        assert node_id, "ledger entry without node_id"
        assert node_id in inventory, (
            f"{node_id}: ledger entry for a node that never existed in the "
            "ratified inventory"
        )
        assert node_id not in full_collection, (
            f"{node_id}: ledger says retired, but the node is still collected"
        )
        disposition = entry.get("disposition", "")
        assert _DISPOSITION_RE.match(disposition), (
            f"{node_id}: disposition {disposition!r} is not one of "
            "'dies_with_v5' | 'deleted_by: P1.4' | 'coverage_owed' "
            "(SUITE-RECONCILIATION.md §2.2)"
        )
        if disposition == "coverage_owed":
            assert _WORK_ITEM_RE.match(entry.get("work_item", "")), (
                f"{node_id}: coverage_owed requires a work_item reference "
                "(WI-<n> or a regista work-item UUID)"
            )


def test_no_test_vanishes_without_a_disposition(
    inventory: set[str], full_collection: set[str]
) -> None:
    manifest_nodes = {
        e["node_id"] for e in json.loads(MANIFEST_PATH.read_text())["entries"]
    }
    ledger_nodes = {
        e["node_id"] for e in json.loads(LEDGER_PATH.read_text())["entries"]
    }
    unaccounted = sorted(
        n
        for n in inventory
        if n not in full_collection and n not in manifest_nodes and n not in ledger_nodes
    )
    assert not unaccounted, (
        f"{len(unaccounted)} test node(s) vanished from collection with no "
        "retirement-ledger disposition (SUITE-RECONCILIATION.md §2.2): "
        f"{unaccounted[:10]}"
    )
