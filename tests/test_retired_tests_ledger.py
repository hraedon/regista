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
- The set of deferrals is pinned by exact node identity per work item in
  ``DEFERRED_COVERAGE_NODE_IDS``, so growing the allowlist, shrinking it, or
  swapping one owed node for another is a visible diff in two places: the
  ledger entry and the pin.
- Every entry whose disposition is exactly ``coverage_owed`` (a near-miss
  spelling such as a trailing newline fails the well-formedness check, which
  uses ``fullmatch``), deferred or discharged, is also pinned by content
  digest (``COVERAGE_OWED_DIGEST``). Re-pointing a discharged entry's
  ``covered_by``, or permuting node IDs among entries so an invariant is
  credited to the wrong test, leaves the identity sets unchanged. It cannot
  leave the digest unchanged. The digest proves the record did not change
  silently. It does not prove that a ``covered_by`` target asserts the
  invariant: that is still review, and collection is not execution (WI-336
  N2).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

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

#: Every ``coverage_owed`` deferral currently on the books, keyed by its exact
#: former node ID. This pin stops the allowlist growing or swapping quietly: a
#: new deferral has to be written twice — once on the ledger entry, once here.
#:
#: - ``WI-289/P3.3`` — cluster 4, bundle v3 (11 in ``tests/test_bundle.py``) —
#:   **DISCHARGED in WI-289 Phase D** (2026-08-23): each entry now carries a
#:   ``covered_by`` counterpart in
#:   ``tests/test_bundle.py::TestWI289Cluster4Counterparts`` and its
#:   ``deferred_to`` marker was removed, so the pin drops from 11 to 0 (the key
#:   is gone). ``TestWI289Cluster4LedgerMapping`` machine-checks the mapping.
#: - ``WI-293`` — the P2.2 trust-log / key-lifecycle tranche.
#: - ``WI-305`` — the plan-023 review-validator and claim-lineage tranche.
DEFERRED_COVERAGE_NODE_IDS = {
    "WI-293": frozenset(
        {
            "tests/test_cli_integration.py::TestPrincipalRotate::test_rotate_json_shape",
            "tests/test_cli_integration.py::TestPrincipalRotate::test_rotate_supersedes_with_validity_window",
            "tests/test_custody.py::TestProvisionPrincipalBackendAware::test_file_backend_provision_round_trip",
            "tests/test_custody.py::TestProvisionPrincipalBackendAware::test_operator_backend_provision_raises_loud",
            "tests/test_custody.py::TestProvisionPrincipalBackendAware::test_vault_backend_provision_writes_no_plaintext_key",
            "tests/test_enroll_principal.py::TestEnrollPrincipal::test_does_not_break_replay",
            "tests/test_enroll_principal.py::TestEnrollPrincipal::test_enroll_principal_entity_id_stable",
            "tests/test_enroll_principal.py::TestEnrollPrincipal::test_idempotent_re_enroll_no_duplicate_event",
            "tests/test_enroll_principal.py::TestEnrollPrincipal::test_new_enrollment_issues_keypair_and_emits_event",
            "tests/test_enroll_principal.py::TestEnrollPrincipal::test_self_heal_re_emits_event_after_gap",
            "tests/test_enroll_principal.py::TestEnrollPrincipalCLI::test_cli_enroll_idempotent",
            "tests/test_enroll_principal.py::TestEnrollPrincipalCLI::test_cli_enroll_principal",
            "tests/test_enroll_principal.py::TestProvisionPrincipalScheme::test_provision_principal_returns_scheme",
            "tests/test_principal_keys.py::TestFacadeAPI::test_register_via_facade",
            "tests/test_principal_keys.py::TestFacadeAPI::test_revoke_via_facade",
            "tests/test_principal_keys.py::TestFacadeAPI::test_rotate_via_facade",
            "tests/test_provision.py::TestProvisionPrincipal::test_provision_principal_idempotent",
            "tests/test_provision.py::TestProvisionPrincipal::test_provision_principal_issues_keypair",
            "tests/test_wi223_principal_binding.py::TestProvisionPrincipalRefusesCollision::test_reprovisioning_same_project_is_still_idempotent",
            "tests/test_wi223_principal_binding.py::TestProvisionPrincipalRefusesCollision::test_reuse_existing_key_registers_the_same_public_key",
            "tests/test_wi223_principal_binding.py::TestProvisionPrincipalRefusesCollision::test_second_project_provisioning_is_refused",
            "tests/test_witness_integration.py::TestBC297AsymmetricWitnessKeys::test_register_witness_with_ed25519_public_key",
            "tests/test_witness_key_enrollment.py::TestEnrollOnRegister::test_ed25519_witness_enrolls_into_registry",
            "tests/test_witness_key_enrollment.py::TestEnrollOnRegister::test_enrolled_key_discoverable_via_principals_facade",
            "tests/test_witness_key_enrollment.py::TestEnrollOnRegister::test_enrolled_key_fingerprint_matches",
            "tests/test_witness_key_enrollment.py::TestEnrollOnRegister::test_hmac_witness_not_enrolled",
            "tests/test_witness_key_enrollment.py::TestRevokeOnUnregister::test_unregister_hmac_witness_no_principal_change",
            "tests/test_witness_key_enrollment.py::TestRevokeOnUnregister::test_unregister_revokes_enrolled_key",
            "tests/test_witness_key_enrollment.py::TestRotateWitnessKey::test_rotate_hmac_witness_rejected",
            "tests/test_witness_key_enrollment.py::TestRotateWitnessKey::test_rotate_nonexistent_raises",
            "tests/test_witness_key_enrollment.py::TestRotateWitnessKey::test_rotate_supersedes_old_key",
            "tests/test_witness_key_enrollment.py::TestRotateWitnessKey::test_rotate_updates_witness_registration_pubkey",
            "tests/test_witness_key_enrollment.py::TestRotateWitnessKey::test_rotate_wrong_length_rejected",
        }
    ),
    "WI-305": frozenset(
        {
            "tests/test_plan023_review_validators.py::TestFullReviewCycle::test_multi_cycle_independence",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_adversarial_passer_cannot_accept",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_agent_self_close_after_cross_lineage_review",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_finding_only_workflow_allows_author_to_request_changes",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_finding_only_workflow_request_changes_still_requires_note",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_human_accept_after_agent_review",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_same_lineage_adversarial_review_without_ack_rejected",
            "tests/test_plan023_review_validators.py::TestRelaxedFlowIntegration::test_self_review_at_adversarial_review_rejected",
            "tests/test_plan023_review_validators.py::TestReviewerDelegationLineage::test_end_to_end_delegated_same_lineage_review_blocked",
            "tests/test_plan023_review_validators.py::TestStrictFlowIntegration::test_agent_accept_rejected_not_human",
            "tests/test_plan023_review_validators.py::TestStrictFlowIntegration::test_human_accept_after_agent_review",
            "tests/test_wi223_principal_binding.py::TestReportNeverClaimsAnUncheckedZero::test_cli_opt_out_is_labelled_not_verified",
            "tests/test_wi223_principal_binding.py::TestReportNeverClaimsAnUncheckedZero::test_cli_replay_verifies_by_default",
            "tests/test_wi223_principal_binding.py::TestReportNeverClaimsAnUncheckedZero::test_in_memory_backend_never_claims_verification",
            "tests/test_wi223_principal_binding.py::TestReportNeverClaimsAnUncheckedZero::test_unverified_report_says_so",
            "tests/test_wi223_principal_binding.py::TestReportNeverClaimsAnUncheckedZero::test_verified_report_publishes_the_zero",
            "tests/test_wi224_claim_lineage.py::TestCrossLineageGateOnClaimedItem::test_claimed_item_passes_cross_lineage_review",
            "tests/test_wi224_claim_lineage.py::TestCrossLineageGateOnClaimedItem::test_heartbeat_with_lineage_does_not_poison_the_gate",
            "tests/test_wi224_claim_lineage.py::TestCrossLineageGateOnClaimedItem::test_unattributed_claim_still_requires_acknowledgment",
            "tests/test_wi224_claim_lineage.py::TestDeriveAuthorsReadsClaimLineage::test_claim_acquired_with_lineage_declares_the_author",
            "tests/test_wi224_claim_lineage.py::TestDeriveAuthorsReadsClaimLineage::test_claim_acquired_without_lineage_still_flags_undeclared",
        }
    ),
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
        assert _DISPOSITION_RE.fullmatch(disposition), (
            f"{node_id}: disposition {disposition!r} is not one of "
            "'dies_with_v5' | 'deleted_by: P1.4' | 'coverage_owed' "
            "(SUITE-RECONCILIATION.md §2.2)"
        )
        if disposition == "coverage_owed":
            assert _WORK_ITEM_RE.fullmatch(entry.get("work_item", "")), (
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
                "DEFERRED_COVERAGE_NODE_IDS in the same diff). Retiring a "
                "test with neither is silent coverage debt."
            )
            marker = (
                _DEFERRED_TO_RE.fullmatch(deferred_to) if isinstance(deferred_to, str) else None
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


#: sha256 of the canonical JSON (sorted keys, compact, UTF-8) of every
#: ``coverage_owed`` entry, sorted by node_id. Update it in the same diff as any
#: deliberate change to such an entry, and say why in the commit message.
COVERAGE_OWED_DIGEST = "8b09c8e7f193bd25ad985246257c759691c18bc34faa165945fd827087c264f6"


def _coverage_owed_digest(ledger: dict[str, Any]) -> str:
    owed = sorted(
        (e for e in ledger["entries"] if e.get("disposition") == "coverage_owed"),
        key=lambda e: str(e["node_id"]),
    )
    canonical = json.dumps(owed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_coverage_owed_entries_cannot_change_silently() -> None:
    ledger = json.loads(LEDGER_PATH.read_text())
    observed = _coverage_owed_digest(ledger)
    assert observed == COVERAGE_OWED_DIGEST, (
        "a coverage_owed ledger entry changed (node_id, invariant, covered_by, "
        "deferred_to or any other field). If the change is deliberate, set "
        f"COVERAGE_OWED_DIGEST = {observed!r} in this file and say which entry "
        "changed and why in the commit message."
    )


def test_coverage_owed_digest_sees_a_permutation_and_a_repoint() -> None:
    ledger = json.loads(LEDGER_PATH.read_text())
    deferred = [e for e in ledger["entries"] if e.get("deferred_to") == "WI-293"]
    discharged = [
        e for e in ledger["entries"]
        if e.get("disposition") == "coverage_owed" and e.get("covered_by")
    ]
    assert len(deferred) >= 2 and len(discharged) >= 2, "fixture premise: retire with the ledger"
    # The pristine ledger hashes to the pin, so each `!=` below is a change the
    # digest saw, not a digest that never matched anything.
    assert _coverage_owed_digest(ledger) == COVERAGE_OWED_DIGEST
    permuted = json.loads(json.dumps(ledger))
    a, b = [e for e in permuted["entries"] if e.get("deferred_to") == "WI-293"][:2]
    a["node_id"], b["node_id"] = b["node_id"], a["node_id"]
    _assert_deferred_coverage_node_ids(permuted)  # the identity pin cannot see this...
    assert _coverage_owed_digest(permuted) != COVERAGE_OWED_DIGEST  # ...the digest does
    repointed = json.loads(json.dumps(ledger))
    x, y = [
        e for e in repointed["entries"]
        if e.get("disposition") == "coverage_owed" and e.get("covered_by")
    ][:2]
    x["covered_by"] = y["covered_by"]
    assert _coverage_owed_digest(repointed) != COVERAGE_OWED_DIGEST


def _assert_deferred_coverage_node_ids(ledger: dict[str, Any]) -> None:
    """Require every deferred coverage debt to retain its exact identity."""
    observed: dict[str, set[str]] = {}
    for entry in ledger["entries"]:
        marker = entry.get("deferred_to")
        if not marker:
            continue
        assert entry.get("disposition") == "coverage_owed", (
            f"{entry['node_id']}: deferred_to is only meaningful for "
            "coverage_owed; a dies_with_v5 / deleted_by entry owes nothing"
        )
        assert isinstance(marker, str), f"{entry['node_id']}: deferred_to must be a string"
        observed.setdefault(marker, set()).add(entry["node_id"])
    assert observed == DEFERRED_COVERAGE_NODE_IDS, (
        "the set of deferred coverage debt node identities changed. Observed "
        f"{dict(sorted(observed.items()))}, pinned "
        f"{dict(sorted(DEFERRED_COVERAGE_NODE_IDS.items()))}. If a deferral "
        "was discharged, drop it from both; if one was added, add it to both — "
        "and say which in the commit message."
    )


def test_deferred_coverage_allowlist_cannot_change_silently() -> None:
    """The deferral allowlist is pinned by exact node identity, per target.

    The gate above lets a null ``covered_by`` through on the strength of a
    ``deferred_to`` marker. Without this pin, that would be a hole one JSON key
    wide: any new tranche could be retired with a marker and nothing would go
    red. Pinning exact identities means additions and same-work-item swaps cost
    a second, deliberate edit in a file a reviewer is already reading.
    """
    ledger = json.loads(LEDGER_PATH.read_text())
    _assert_deferred_coverage_node_ids(ledger)


def test_deferred_coverage_allowlist_rejects_same_work_item_identity_swap() -> None:
    ledger = json.loads(LEDGER_PATH.read_text())
    deferred = next(
        (entry for entry in ledger["entries"] if entry.get("deferred_to") == "WI-293"), None
    )
    replacement = next(
        (
            entry["node_id"]
            for entry in ledger["entries"]
            if entry.get("disposition") == "deleted_by: P1.4"
        ),
        None,
    )
    assert deferred is not None and replacement is not None, (
        "fixture premise gone (no WI-293 deferral or no deleted_by: P1.4 entry); "
        "retire this test together with that ledger tranche"
    )
    deferred["node_id"] = replacement

    observed_count = sum(entry.get("deferred_to") == "WI-293" for entry in ledger["entries"])
    assert observed_count == len(DEFERRED_COVERAGE_NODE_IDS["WI-293"])
    with pytest.raises(AssertionError, match="node identities changed"):
        _assert_deferred_coverage_node_ids(ledger)


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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("disposition", "coverage_owed\n"),
        ("disposition", "dies_with_v5\n"),
        ("work_item", "WI-293\n"),
        ("deferred_to", "WI-293\n"),
    ],
)
def test_near_miss_spellings_are_refused_not_treated_as_another_class(
    field: str, value: str
) -> None:
    """Regex `$` also matches before a trailing newline. Every gate here compares
    dispositions with `==`, so a value the classifier accepted but every consumer
    skipped would leave an entry under no check at all (WI-336 round 2, DeepSeek B3)."""
    pattern = {
        "disposition": _DISPOSITION_RE,
        "work_item": _WORK_ITEM_RE,
        "deferred_to": _DEFERRED_TO_RE,
    }[field]
    assert pattern.match(value), "premise: the old .match() accepted this"
    assert pattern.fullmatch(value) is None
