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

WI-289 Phase A hardening — the coverage pointer is strict by default:
- A ``coverage_owed`` entry with no ``covered_by`` FAILS unless it carries an
  explicit ``deferred_to`` marker naming the work item (optionally
  ``/<phase>``) that owes the coverage. The previous rule silently accepted
  *every* null pointer except WI-008's, so a new tranche could be retired with
  no replacement and no deferral and nothing would go red.
- The set of deferrals is pinned by exact count in
  ``DEFERRED_COVERAGE_ALLOWLIST``, so growing the allowlist is a visible diff
  in two places: the ledger entry and the pin.
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
_WORK_ITEM_PAT = (
    r"(?:WI-\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_WORK_ITEM_RE = re.compile(rf"^{_WORK_ITEM_PAT}$")

# A deferral marker: the work item that owes the coverage, optionally narrowed
# to the phase inside it ("WI-289/P3.3"). String sanity only — nothing here
# reaches the tracker, so this proves the marker is a work-item reference, not
# that the work item is open. That is deliberate: an offline gate that lies
# about liveness would be worse than one that admits its scope.
_DEFERRED_TO_RE = re.compile(rf"^({_WORK_ITEM_PAT})(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?$")

#: Every ``coverage_owed`` deferral currently on the books, with its EXACT entry
#: count. This is the pin that stops the allowlist growing quietly: a new
#: deferral has to be written twice — once on the ledger entry, once here — and
#: the second edit is the one a reviewer notices.
#:
#: - ``WI-289/P3.3`` — cluster 4, bundle v3 (11 in ``tests/test_bundle.py``) —
#:   **DISCHARGED in WI-289 Phase D** (2026-08-23): each entry now carries a
#:   ``covered_by`` counterpart in
#:   ``tests/test_bundle.py::TestWI289Cluster4Counterparts`` and its
#:   ``deferred_to`` marker was removed, so the pin drops from 11 to 0 (the key
#:   is gone). ``TestWI289Cluster4LedgerMapping`` machine-checks the mapping.
#: - ``WI-293`` — the P2.2 trust-log / key-lifecycle tranche.
#: - ``WI-305`` — the plan-023 review-validator and claim-lineage tranche.
DEFERRED_COVERAGE_ALLOWLIST = {
    "WI-293": 33,
    "WI-305": 21,
}


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


def test_coverage_owed_entries_point_to_collected_coverage(
    full_collection: set[str],
) -> None:
    """Every promised replacement must be a real, collected test node.

    Or, failing that, an explicit deferral. There is no third option: the
    pointer is mandatory unless the entry says out loud where the coverage went
    and who owes it.
    """
    ledger = json.loads(LEDGER_PATH.read_text())
    for entry in ledger["entries"]:
        if entry.get("disposition") != "coverage_owed":
            continue
        node_id = entry["node_id"]
        covered_by = entry.get("covered_by")
        deferred_to = entry.get("deferred_to")
        if not covered_by:
            assert deferred_to, (
                f"{node_id}: coverage_owed with no covered_by pointer and no "
                "deferred_to marker. Either name the test node that discharges "
                "the invariant, or add \"deferred_to\": \"WI-<n>[/<phase>]\" "
                "naming the work item that owes it (and add it to "
                "DEFERRED_COVERAGE_ALLOWLIST in the same diff). Retiring a "
                "test with neither is silent coverage debt."
            )
            marker = (
                _DEFERRED_TO_RE.match(deferred_to) if isinstance(deferred_to, str) else None
            )
            assert marker, (
                f"{node_id}: deferred_to {deferred_to!r} is not a work-item "
                "reference — expected 'WI-<n>' or a regista work-item UUID, "
                "optionally narrowed to a phase as 'WI-289/P3.3'"
            )
            owing = marker.group(1)
            assert owing == entry.get("work_item"), (
                f"{node_id}: deferred_to names {owing} but the entry's "
                f"work_item is {entry.get('work_item')!r}. The deferral and the "
                "attribution must agree; if the debt genuinely moved, move both."
            )
            continue
        assert isinstance(covered_by, str) and covered_by, (
            f"{node_id}: coverage_owed requires a covered_by test node"
        )
        assert not deferred_to, (
            f"{node_id}: has both covered_by and deferred_to — an entry is "
            "either discharged or deferred, not both"
        )
        collected = covered_by in full_collection or any(
            node.startswith(covered_by + "[") for node in full_collection
        )
        assert collected, (
            f"{node_id}: covered_by node is not collected: {covered_by}"
        )


def test_deferred_coverage_allowlist_cannot_grow_silently() -> None:
    """The deferral allowlist is pinned by exact count, per target.

    The gate above lets a null ``covered_by`` through on the strength of a
    ``deferred_to`` marker. Without this pin, that would be a hole one JSON key
    wide: any new tranche could be retired with a marker and nothing would go
    red. Pinning the exact counts means adding a deferral costs a second,
    deliberate edit in a file a reviewer is already reading.
    """
    ledger = json.loads(LEDGER_PATH.read_text())
    observed: dict[str, int] = {}
    for entry in ledger["entries"]:
        marker = entry.get("deferred_to")
        if not marker:
            continue
        assert entry.get("disposition") == "coverage_owed", (
            f"{entry['node_id']}: deferred_to is only meaningful for "
            "coverage_owed; a dies_with_v5 / deleted_by entry owes nothing"
        )
        observed[marker] = observed.get(marker, 0) + 1
    assert observed == DEFERRED_COVERAGE_ALLOWLIST, (
        "the set of deferred coverage debts changed. Observed "
        f"{dict(sorted(observed.items()))}, pinned "
        f"{dict(sorted(DEFERRED_COVERAGE_ALLOWLIST.items()))}. If a deferral "
        "was discharged, drop it from both; if one was added, add it to both — "
        "and say which in the commit message."
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
