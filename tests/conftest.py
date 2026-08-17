from __future__ import annotations

import inspect
import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
from _epoch_blocked import apply_epoch_marks, validate_xfail_report
from _helpers import DSN, KEY_PATH

# ---------------------------------------------------------------------------
# PostgreSQL reachability — skip DB-dependent tests cleanly when no PG is
# available, instead of hanging 30s on a pool timeout and erroring.
#
# Skip condition (all must hold):
#   1. REGISTA_TEST_DSN is NOT explicitly set (operator didn't point at a PG),
#   2. testcontainers is NOT importable (can't spin up an ephemeral PG), AND
#   3. the default DSN host:port is not reachable.
# When REGISTA_TEST_DSN *is* set, tests run (and fail normally if that PG is
# down) — an explicit DSN is an operator's deliberate choice to run DB tests.
# ---------------------------------------------------------------------------

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"

# Source tokens that indicate a test module touches the real Postgres store
# (as opposed to pure-logic or InMemoryRegista-only tests).
_DB_TOKENS = ("DSN", "create_project", "psycopg.connect", "regista_instance", "regista_module")

# Session-level cache of the skip decision.
_pg_skip_reason: str | None = None
_pg_skip_computed = False


def _probe_pg(dsn: str, timeout: float = 2.0) -> bool:
    """Quick TCP probe of the DSN's host:port — avoids the 30s pool timeout."""
    try:
        parsed = urlparse(dsn)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _testcontainers_available() -> bool:
    try:
        import testcontainers  # noqa: F401
    except ImportError:
        return False
    return True


def _pg_skip_decision() -> str | None:
    """Return a skip reason if DB-dependent tests should be skipped, else None.

    Computed once per session and cached.
    """
    global _pg_skip_reason, _pg_skip_computed
    if _pg_skip_computed:
        return _pg_skip_reason
    _pg_skip_computed = True
    # Operator explicitly pointed at a PG — don't skip; let tests fail normally
    # if that PG is unreachable (explicit choice to run DB tests).
    if os.environ.get("REGISTA_TEST_DSN"):
        _pg_skip_reason = None
        return None
    # testcontainers can spin up an ephemeral PG — don't skip.
    if _testcontainers_available():
        _pg_skip_reason = None
        return None
    # Default DSN — probe it quickly.
    if _probe_pg(_DEFAULT_DSN):
        _pg_skip_reason = None
        return None
    _pg_skip_reason = (
        "PostgreSQL not reachable at the default DSN "
        f"({_DEFAULT_DSN}) and REGISTA_TEST_DSN is not set; "
        "install testcontainers or set REGISTA_TEST_DSN to run DB-dependent tests"
    )
    return _pg_skip_reason


def _module_is_db_dependent(module: object) -> bool:
    """Heuristic: does this test module's source reference the PG store?

    Detects modules that import/use DSN, call create_project, use
    psycopg.connect directly, or request the regista_instance/regista_module
    fixtures. Pure-logic and InMemoryRegista-only modules are left alone.
    """
    cached = getattr(module, "_regista_db_dependent", None)
    if cached is not None:
        return cached
    try:
        source = inspect.getsource(module)  # type: ignore[arg-type]
    except (OSError, TypeError):
        source = ""
    has_db = any(token in source for token in _DB_TOKENS)
    module._regista_db_dependent = has_db  # type: ignore[attr-defined]
    return has_db


# ---------------------------------------------------------------------------
# Epoch-blocked manifest (SUITE-RECONCILIATION.md §2.1)
#
# Every node in tests/epoch_blocked_manifest.json is proven blocked on the
# missing v6 ordinary-event writer (P1.7): non-passing at the reconciliation
# base AND passing in the guard-reverted control run. The hook marks exactly
# those nodes strict-xfail, so they keep running and the moment one starts
# passing, strict XPASS fails the suite — the manifest must shrink in the
# same change. Enforcement of the manifest's own integrity lives in
# tests/test_epoch_blocked_meta.py; the retirement side in
# tests/test_retired_tests_ledger.py.
# ---------------------------------------------------------------------------

# tryfirst on a wrapper makes it OUTERMOST: its post-yield code runs after
# every inner implementation — in particular after _pytest.skipping has set
# rep.wasxfail — so the form validation always sees the finished XFAIL
# report (design-review round-4 B2: ordering is explicit, not incidental).
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    rep = yield
    validate_xfail_report(item, call, rep)
    return rep


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply the epoch-blocked strict xfails and the PG-reachability skip."""
    apply_epoch_marks(items, pytest)

    reason = _pg_skip_decision()
    if not reason:
        return
    skip_marker = pytest.mark.skip(reason=reason)
    for item in items:
        if _module_is_db_dependent(item.module):
            item.add_marker(skip_marker)


@pytest.fixture
def regista_instance():
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"test_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def regista_module():
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"test_mod_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


# ---------------------------------------------------------------------------
# WI-243: the schema-leak guard.
#
# The suite used to leak one Postgres schema per test project — schemas were
# dropped but the `public.projects` catalog row (and occasionally the schema
# itself) survived. Tens of thousands accumulated in the shared instance and
# hung `run_doctor`, which iterated the catalog serially. The 3bfdb6f-era
# "fix" mocked `_list_projects` to [] in the doctor test, hiding the leak
# while it kept growing.
#
# This guard makes a leak loud instead: it snapshots the set of project
# schema names at session start and fails at session end if any *new* names
# remain. It runs in the controller process only, so it is xdist-safe (a
# worker mid-run does not see sibling workers' in-flight schemas).
# ---------------------------------------------------------------------------

_SESSION_START_SCHEMAS: set[str] | None = None


def _project_schema_names() -> set[str]:
    """Live regista project schemas: union of `public.projects` catalog rows
    and schemas that look like regista projects (not system schemas)."""
    import psycopg

    names: set[str] = set()
    try:
        with psycopg.connect(DSN, connect_timeout=3, autocommit=True) as conn:
            try:
                rows = conn.execute(
                    "SELECT schema_name FROM public.projects"
                ).fetchall()
                names.update(r[0] for r in rows)
            except psycopg.errors.UndefinedTable:
                pass
            rows = conn.execute(
                "SELECT schema_name FROM information_schema.schemata"
            ).fetchall()
            for (schema_name,) in rows:
                if schema_name.startswith("pg_") or schema_name == "public":
                    continue
                names.add(schema_name)
    except Exception:
        return set()
    return names


def _controller_process(session) -> bool:
    """True in the controller (single-process or xdist master), False in an
    xdist worker. Session-level DB checks must run exactly once, in the
    controller, after all workers have torn down their schemas."""
    return not hasattr(session.config, "workerinput")


def pytest_sessionstart(session) -> None:
    if not _controller_process(session):
        return
    global _SESSION_START_SCHEMAS
    if not _pg_skip_decision():
        _SESSION_START_SCHEMAS = _project_schema_names()


def pytest_sessionfinish(session, exitstatus) -> None:
    if not _controller_process(session):
        return
    if session.config.option.collectonly:
        # A collect-only session runs no tests and cannot leak schemas; any
        # schema delta it observes was created by a concurrent real session
        # (e.g. the epoch-blocked meta-guards collect in a subprocess while
        # the suite runs). Flagging it here is a false positive by
        # construction.
        return
    global _SESSION_START_SCHEMAS
    if _SESSION_START_SCHEMAS is None:
        return
    if os.environ.get("REGISTA_TEST_SKIP_LEAK_GUARD"):
        return
    end = _project_schema_names()
    leaked = sorted(end - _SESSION_START_SCHEMAS)
    if leaked:
        # session.exitstatus, not pytest.exit(): an Exit raised this late is
        # caught after the exit status is computed — the message prints but
        # the process still exits 0, and CI reads codes, not prose (verified
        # empirically; the fail-open shape this guard exists to prevent).
        import sys as _sys

        print(
            "WI-243: test suite leaked Postgres schemas — "
            f"{len(leaked)} new project schema(s) survive the session: "
            + ", ".join(leaked[:20])
            + ("…" if len(leaked) > 20 else "")
            + ". Every test that creates a project must drop it "
            "(and drop_project_schema must unregister the catalog row).",
            file=_sys.stderr,
        )
        session.exitstatus = 1
