"""Retired-test ledger validator (SUITE-RECONCILIATION.md §2.2).

Every node in the committed pre-reconciliation collection inventory must be
(a) still collected, (b) in the epoch-blocked manifest (which the
collection-existence meta-guard already ties to collection), or (c) recorded
in the retirement ledger with a disposition. A test cannot vanish from the
suite without a recorded decision — deletion without a ledger entry is a
failing test here, not a review-time hope.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO_ROOT / "tests" / "epoch_blocked_inventory.txt"
MANIFEST_PATH = REPO_ROOT / "tests" / "epoch_blocked_manifest.json"
LEDGER_PATH = REPO_ROOT / "tests" / "retired_tests_ledger.json"

_VALID_DISPOSITIONS = ("dies_with_v5", "deleted_by", "coverage_owed")


@pytest.fixture(scope="module")
def full_collection() -> set[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 5), (
        f"collection failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
    return {line.strip() for line in proc.stdout.splitlines() if "::" in line}


def test_ledger_entries_are_well_formed() -> None:
    ledger = json.loads(LEDGER_PATH.read_text())
    for entry in ledger["entries"]:
        assert entry.get("node_id"), "ledger entry without node_id"
        disposition = entry.get("disposition", "")
        assert any(disposition.startswith(v) for v in _VALID_DISPOSITIONS), (
            f"{entry['node_id']}: disposition {disposition!r} is not one of "
            f"{_VALID_DISPOSITIONS} (SUITE-RECONCILIATION.md §2.2)"
        )
        if disposition.startswith("coverage_owed"):
            assert entry.get("work_item"), (
                f"{entry['node_id']}: coverage_owed requires a work_item reference"
            )


def test_no_test_vanishes_without_a_disposition(full_collection: set[str]) -> None:
    inventory = {
        line.strip() for line in INVENTORY_PATH.read_text().splitlines() if "::" in line
    }
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
