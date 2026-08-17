"""Reducer v1 determinism conformance (Gate 0, P0.2).

`REVIEW-VERDICTS.md` §8 L2 names this the single assumption most likely to be wrong: the whole
subject binding assumes the reducer produces byte-identical output for the same signed prefix,
on any machine, at any version. `IMPLEMENTATION-PLAN.md` P0.2 makes it the go/no-go for signed
review verdicts, and requires the proof to hold **across at least two interpreters**.

How that requirement is discharged here:

* `tests/reducer_v1_frozen_digests.json` holds the corrected digests agreed by CPython 3.12,
  CPython 3.13 and CPython 3.14, with three `PYTHONHASHSEED` values each, produced by
  `tools/reducer_v1_sweep.py`. PyPy covered the original shape but is not current evidence.
* This module asserts the *current* interpreter reproduces them exactly. CI runs the suite on
  3.13 and 3.14, so every CI run is itself a two-interpreter agreement check, and any future
  interpreter that disagrees fails the build rather than silently minting a second digest.

Re-freeze deliberately and never casually: changing a frozen digest invalidates every verdict
signed against the old one. That is what a reducer version is for.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
from reducer_v1_vectors import REJECT_RAW, REJECT_VECTORS, VECTORS

from regista._reducer import (
    REDUCER_VERSION,
    ReducerError,
    content_state_digest,
    normalize_timestamp,
    reduce_and_canonicalize,
    reduce_v1,
)

FROZEN = json.loads(
    (Path(__file__).parent / "reducer_v1_frozen_digests.json").read_text(encoding="utf-8")
)


def test_frozen_digests_cover_every_vector() -> None:
    """A vector with no frozen digest proves nothing, and would pass silently."""
    assert set(FROZEN["digests"]) == {name for name, _, _ in VECTORS}
    assert set(FROZEN["digests_content_only"]) == {name for name, _, _ in VECTORS}
    assert FROZEN["reducer_version"] == REDUCER_VERSION


def test_frozen_digests_were_agreed_by_multiple_interpreters() -> None:
    """The frozen file must record the agreement it claims — P0.2's acceptance criterion."""
    interpreters = FROZEN["interpreters"]
    assert len(interpreters) >= 2, interpreters
    implementations = {entry.split()[0] for entry in interpreters}
    versions = {entry for entry in interpreters}
    assert len(versions) >= 2, "at least two interpreter versions must have agreed"
    assert implementations, interpreters


def test_frozen_digests_include_the_estate_runtime() -> None:
    assert "CPython 3.14.4" in FROZEN["interpreters"]


@pytest.mark.parametrize("name,envelopes,definitions", VECTORS, ids=[v[0] for v in VECTORS])
def test_vector_matches_frozen_digest(name, envelopes, definitions) -> None:
    # The default field set is content-only (claim state excluded) — decided 2026-08-09,
    # reasoning in `reduced_field_names`. `digests` is the with-claim-state variant, kept
    # frozen so the decision is reversible without re-freezing.
    assert (
        content_state_digest(envelopes, workflow_definitions=definitions)
        == FROZEN["digests_content_only"][name]
    )
    assert (
        content_state_digest(envelopes, workflow_definitions=definitions, include_claim_state=True)
        == FROZEN["digests"][name]
    )


def test_default_field_set_excludes_claim_state() -> None:
    """The decision itself, pinned. Flipping the default must break a test, not a deployment."""
    _name, envelopes, definitions = next(v for v in VECTORS if v[0] == "claim-churn")
    reduced = reduce_v1(envelopes, workflow_definitions=definitions)
    assert set(reduced) == {
        "reducer_version",
        "current_state",
        "custom_fields",
        "needs_review",
        "not_before",
    }
    assert reduced == reduce_v1(
        envelopes, workflow_definitions=definitions, include_claim_state=False
    )


def test_claim_churn_does_not_change_content_digest() -> None:
    _name, envelopes, definitions = next(v for v in VECTORS if v[0] == "claim-churn")
    before_claim = content_state_digest(envelopes[:1], workflow_definitions=definitions)

    for prefix_end in range(2, len(envelopes) + 1):
        assert (
            content_state_digest(envelopes[:prefix_end], workflow_definitions=definitions)
            == before_claim
        )


@pytest.mark.parametrize("name,envelopes,definitions", VECTORS, ids=[v[0] for v in VECTORS])
def test_reduction_is_a_jcs_fixed_point(name, envelopes, definitions) -> None:
    """Canonicalising the reduced state twice must produce the same bytes.

    This is the property the 1e16 finding broke: a value can be canonical on the way in and
    uncanonicalisable on the way back, so a digest exists that can never be recomputed.
    """
    from regista._jcs import canonicalize

    once = reduce_and_canonicalize(envelopes, workflow_definitions=definitions)
    reparsed = json.loads(once.decode("utf-8"))
    assert canonicalize(reparsed) == once


def test_key_insertion_order_does_not_reach_the_digest() -> None:
    a = FROZEN["digests"]["key-order-irrelevant-a"]
    b = FROZEN["digests"]["key-order-irrelevant-b"]
    assert a == b, "JCS sorts keys; insertion order must not survive into the digest"


def test_claim_state_field_set_is_a_real_choice() -> None:
    """The two field sets must actually differ, or `include_claim_state` is decoration."""
    _name, envelopes, definitions = next(v for v in VECTORS if v[0] == "claim-churn")
    full = content_state_digest(
        envelopes, workflow_definitions=definitions, include_claim_state=True
    )
    content = content_state_digest(envelopes, workflow_definitions=definitions)
    assert full != content
    assert "claimed_by" in reduce_v1(
        envelopes, workflow_definitions=definitions, include_claim_state=True
    )
    assert "claimed_by" not in reduce_v1(envelopes, workflow_definitions=definitions)


@pytest.mark.parametrize(
    "name,envelopes,definitions", REJECT_VECTORS, ids=[v[0] for v in REJECT_VECTORS]
)
def test_reject_vectors_fail_closed(name, envelopes, definitions) -> None:
    with pytest.raises(ReducerError):
        content_state_digest(envelopes, workflow_definitions=definitions)


@pytest.mark.parametrize("name,raw", REJECT_RAW, ids=[v[0] for v in REJECT_RAW])
def test_reject_raw_fail_closed(name, raw) -> None:
    with pytest.raises(ReducerError):
        content_state_digest([raw], workflow_definitions={})


def test_timestamp_normal_form() -> None:
    assert normalize_timestamp("2026-08-09T12:00:00Z", field="t") == "2026-08-09T12:00:00.000000Z"
    assert (
        normalize_timestamp("2026-08-09T07:00:00-05:00", field="t") == "2026-08-09T12:00:00.000000Z"
    )
    assert (
        normalize_timestamp("2026-08-09T12:00:00.9999999Z", field="t")
        == "2026-08-09T12:00:00.999999Z"
    ), "sub-microsecond digits truncate, never round"
    assert (
        normalize_timestamp("2026-12-31T23:30:00-01:00", field="t") == "2027-01-01T00:30:00.000000Z"
    ), "an offset may carry across a year boundary"
    assert (
        normalize_timestamp("2028-02-28T23:00:00-02:00", field="t") == "2028-02-29T01:00:00.000000Z"
    ), "and across a leap day"


def test_hour_24_is_the_measured_cross_version_divergence() -> None:
    """The finding that made the strict parser necessary, pinned as a regression test.

    `datetime.fromisoformat` is not a stable grammar across interpreters: CPython 3.14 accepts
    `24:00:00` as the following midnight; CPython 3.12, CPython 3.13 and PyPy 3.11 raise. Replay
    then converts that disagreement into a *silent* one, because `_parse_not_before` logs and
    substitutes `None` — so the same signed prefix reduces to two different states, and a verdict
    signed on one host reads as stale on another.

    The assertion below is deliberately about *this* interpreter's stdlib behaviour, so the test
    records which side of the divergence the running interpreter is on, and the reducer's own
    rejection is what must hold everywhere.
    """
    value = "2026-08-09T24:00:00Z"

    stdlib_accepts = True
    try:
        datetime.fromisoformat(value)
    except ValueError:
        stdlib_accepts = False

    if sys.version_info >= (3, 14) and sys.implementation.name == "cpython":
        assert stdlib_accepts, "CPython 3.14 was measured to accept end-of-day 24:00"
    else:
        assert not stdlib_accepts, "pre-3.14 CPython and PyPy were measured to reject it"

    # Whatever the stdlib does, the reducer does the same thing everywhere.
    with pytest.raises(ReducerError):
        normalize_timestamp(value, field="not_before")


def test_the_reducer_never_consults_a_database_or_a_registry() -> None:
    """Reducer v1's dependency surface is the stdlib plus the vendored canonicalizer.

    An offline auditor holding only a bundle must be able to recompute the digest. If this
    module ever grows a psycopg or workflow-registry import, that property is gone and the
    subject binding stops being checkable outside the estate.
    """
    import ast

    source = (Path(__file__).parents[1] / "src" / "regista" / "_reducer.py").read_text()
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0] or "." * node.level)

    allowed = {"json", "re", "collections", "hashlib", "typing", "__future__", "_jcs", "."}
    assert imported <= allowed, f"reducer grew a dependency: {sorted(imported - allowed)}"


@pytest.mark.slow
def test_cross_interpreter_sweep_if_alternates_available() -> None:
    """Re-run the full sweep locally when other interpreters happen to be installed.

    Skipped rather than failed when they are not: CI's guarantee comes from the frozen digests
    plus the 3.13/3.14 matrix, and a developer machine should not be required to hold four
    interpreters. When they are present this is the strongest check in the file.
    """
    candidates = ["python3.12", "python3.13", "python3.14", "pypy3.11"]
    available = [c for c in candidates if _which(c)]
    if len(available) < 2:
        pytest.skip(f"need two alternate interpreters, found {available}")

    sweep = Path(__file__).parents[1] / "tools" / "reducer_v1_sweep.py"
    proc = subprocess.run(
        [sys.executable, str(sweep), "--sweep", *available], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: IDENTICAL" in proc.stdout


def test_sweep_fails_loudly_on_unresolvable_interpreter() -> None:
    """The WI-288 resolution step must refuse, not soft-pass, a missing interpreter.

    Exit 2 is the harness-failure contract, distinct from exit 1 (divergence);
    a refactor that collapses them would let a broken sweep read as evidence.
    """
    sweep = Path(__file__).parents[1] / "tools" / "reducer_v1_sweep.py"
    proc = subprocess.run(
        [sys.executable, str(sweep), "--sweep", "no-such-interpreter-wi288"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "FAILED to resolve interpreter" in proc.stdout
    assert "RESULT:" not in proc.stdout


def test_sweep_refuses_duplicate_resolved_interpreters() -> None:
    """Two names aliasing one binary must not count as a two-interpreter sweep."""
    sweep = Path(__file__).parents[1] / "tools" / "reducer_v1_sweep.py"
    name = Path(sys.executable).name
    proc = subprocess.run(
        [sys.executable, str(sweep), "--sweep", name, name],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "DUPLICATE interpreter" in proc.stdout
    assert "RESULT:" not in proc.stdout


def _which(name: str) -> str | None:
    import shutil

    return shutil.which(name)
