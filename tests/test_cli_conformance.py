"""regista's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance``, consumed
pinned (never copied) — so there is exactly one kit to drift from. These cases
are regista's component-side fixtures against its own CLI.

Every case is hermetic: it strips the operator box's live store config
(``REGISTA_DSN``/``REGISTA_PROJECT``/``REGISTA_HMAC_KEY_PATH``) so results
depend on the contract, not on whether a Postgres happens to be reachable.
"""

from __future__ import annotations

import sys

import pytest

# The conformance kit is installed by CI as a dedicated pinned step (it is a
# git+SHA direct reference, which PyPI forbids in package metadata, so it is not
# a pyproject dependency). Skip cleanly if it is absent — but note CI installs it
# in a step that fails loudly, so a missing kit in CI never silently skips here.
conformance = pytest.importorskip("agent_suite.conformance")

BrokenPipeCase = conformance.BrokenPipeCase
ErrorCase = conformance.ErrorCase
SuccessCase = conformance.SuccessCase
UsageCase = conformance.UsageCase
run_broken_pipe_case = conformance.run_broken_pipe_case
run_error_case = conformance.run_error_case
run_success_case = conformance.run_success_case
run_usage_case = conformance.run_usage_case

# conftest's DB-skip heuristic flags any module whose source contains "DSN" as
# database-dependent and skips it when no Postgres is reachable. This module
# only mentions REGISTA_DSN to *strip* it — the cases never connect. Declaring
# it hermetic keeps the conformance gate running in CI (where there is no PG),
# instead of silently skipping the contract check. The conftest reads this
# attribute directly as its cache.
_regista_db_dependent = False

_CLI = (sys.executable, "-m", "regista._cli")

# Strip any store configuration inherited from the operator environment so the
# cases below never touch (or depend on) a live database.
_HERMETIC_UNSET = ("REGISTA_DSN", "REGISTA_PROJECT", "REGISTA_HMAC_KEY_PATH")


SUCCESS_CASES = [
    # `version` reports library/schema/workflow identity without any store.
    SuccessCase(
        name="version-json",
        argv=(*_CLI, "version", "--json"),
        unset_env=_HERMETIC_UNSET,
    ),
]

ERROR_CASES = [
    # A missing workflow file is a documented input error: envelope + exit 1,
    # never an uncaught FileNotFoundError. Fully hermetic — no store, no keys.
    ErrorCase(
        name="workflow-validate-missing-file",
        argv=(*_CLI, "workflow", "validate", "/nonexistent/regista-workflow.yaml", "--json"),
        expect_code="INVALID_ARGUMENT",
        unset_env=_HERMETIC_UNSET,
    ),
]

USAGE_CASES = [
    UsageCase(name="unknown-verb", argv=(*_CLI, "bogusverb")),
    UsageCase(name="no-command", argv=(*_CLI,)),
]

BROKEN_PIPE_CASES = [
    BrokenPipeCase(name="version-json-broken-pipe", argv=(*_CLI, "version", "--json")),
]


@pytest.mark.parametrize("case", SUCCESS_CASES, ids=lambda c: c.name)
def test_success_conformance(case: SuccessCase) -> None:
    assert run_success_case(case) == []


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: ErrorCase) -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: UsageCase) -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: BrokenPipeCase) -> None:
    assert run_broken_pipe_case(case) == []
