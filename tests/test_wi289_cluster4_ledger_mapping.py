"""Cluster-4 ledger self-check (WI-289 Phase D discharge).

``tests/retired_tests_ledger.json`` retired 11 bundle-v3 offline-verification tests as
cluster 4, deferred to WI-289/P3.3. Phase D discharges them: each entry now carries a
``covered_by`` counterpart in
``tests/test_bundle.py::TestWI289Cluster4Counterparts`` and its ``deferred_to`` marker was
removed, and the ``DEFERRED_COVERAGE_ALLOWLIST`` pin drops from 11 to 0.

This module lives beside the ledger/census change (not in ``test_bundle.py``) so the two
commit together and each commit stays green: a ``covered_by`` pointer is a string in a JSON
file, and nothing but a machine check stops it naming a test that was renamed away. Mirrors
``tests/test_wi289_v6_counterparts.py::TestLedgerMapping`` (clusters 1/2/3/5) and cluster 6's
self-check.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

LEDGER_PATH = Path(__file__).resolve().parents[1] / "tests" / "retired_tests_ledger.json"

#: node_id → the counterpart method that discharges it. The single source of truth the ledger
#: is checked against; the counterparts live in ``tests/test_bundle.py``.
CLUSTER4_COUNTERPARTS: dict[str, str] = {
    "tests/test_bundle.py::TestCliExportExitCodes::test_unverifiable_store_exits_3_by_default": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_cli_export_exit_code_is_the_self_verification_applicability"
    ),
    "tests/test_bundle.py::TestExportAuditBundle::test_export_with_since_seq": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_since_seq_is_an_exclusive_lower_bound"
    ),
    "tests/test_bundle.py::TestExportBounds::test_chunked_exports_both_verify_offline": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_chunked_exports_both_verify_and_a_preflight_matches"
    ),
    "tests/test_bundle.py::TestExportBounds::test_since_and_until_form_a_window": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_since_and_until_form_a_window"
    ),
    "tests/test_bundle.py::TestExportBounds::test_until_seq_is_an_inclusive_upper_bound": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_until_seq_is_an_inclusive_upper_bound"
    ),
    "tests/test_bundle.py::TestOfflineSignatureVerification::test_binding_mismatch_fails_closed": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_a_principal_key_binding_mismatch_fails_closed"
    ),
    "tests/test_bundle.py::TestOfflineSignatureVerification::"
    "test_clean_mixed_bundle_verifies_signatures": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_offline_event_signature_verification_reports_via_the_axes"
    ),
    "tests/test_bundle.py::TestOfflineSignatureVerification::"
    "test_registry_absent_is_recorded_and_fails_closed": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_absent_key_evidence_is_recorded_and_fails_closed"
    ),
    "tests/test_bundle.py::TestOfflineSignatureVerification::test_unknown_scheme_fails_closed": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_relabelling_an_event_scheme_id_fails_closed"
    ),
    "tests/test_bundle.py::TestOfflineSignatureVerification::"
    "test_v1_bundle_signature_check_skipped": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_a_format_version_downgrade_is_rejected_outright"
    ),
    "tests/test_bundle.py::TestVerifyAuditBundleOffline::test_verify_clean_bundle_passes": (
        "tests/test_bundle.py::TestWI289Cluster4Counterparts::"
        "test_a_clean_v3_bundle_verifies_offline"
    ),
}


def _ledger() -> dict:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))


def test_every_cluster4_entry_is_discharged_and_points_at_a_real_test() -> None:
    ledger = _ledger()
    by_node = {e["node_id"]: e for e in ledger["entries"]}
    module = importlib.import_module("tests.test_bundle")
    for node_id, counterpart in CLUSTER4_COUNTERPARTS.items():
        entry = by_node.get(node_id)
        assert entry is not None, f"{node_id}: no ledger entry"
        assert entry["disposition"] == "coverage_owed", node_id
        assert entry.get("covered_by") == counterpart, (
            f"{node_id}: covered_by is {entry.get('covered_by')!r}, expected {counterpart!r}"
        )
        assert not entry.get("deferred_to"), (
            f"{node_id}: still carries a deferred_to marker; cluster 4 is discharged"
        )
        _, _, rest = counterpart.partition("::")
        class_name, _, method = rest.partition("::")
        owner = getattr(module, class_name, None)
        assert owner is not None, f"{counterpart}: {class_name} does not exist"
        assert callable(getattr(owner, method, None)), counterpart


def test_no_cluster4_entry_still_defers_to_p33() -> None:
    deferred = [
        e["node_id"]
        for e in _ledger()["entries"]
        if e.get("deferred_to") == "WI-289/P3.3"
    ]
    assert deferred == [], f"cluster 4 is discharged in Phase D; still deferred: {deferred}"


def test_the_11_cluster4_node_ids_are_exactly_the_mapping() -> None:
    """The mapping and the ledger's Phase-D discharge agree on the set of 11 nodes.

    A pointer to a node the ledger discharged elsewhere, or a discharged node this mapping
    forgot, is caught here rather than read as covered.
    """
    ledger = _ledger()
    discharged_here = {
        e["node_id"]
        for e in ledger["entries"]
        if isinstance(e.get("covered_in"), str)
        and e["covered_in"].startswith("P3.3 (WI-289 Phase D")
    }
    assert discharged_here == set(CLUSTER4_COUNTERPARTS), (
        f"ledger Phase-D discharges {sorted(discharged_here)}, mapping names "
        f"{sorted(CLUSTER4_COUNTERPARTS)}"
    )
