"""Regression tests for WI-218: clean interpreter shutdown on Python 3.14.

``_connection.ConnectionManager`` owns a ``psycopg_pool.ConnectionPool``.
``ConnectionPool.__del__`` joins its live daemon workers, and on Python 3.14+
``Thread.join()`` raises ``PythonFinalizationError`` once interpreter
finalization has begun. So a pool left unclosed at process exit printed

    Exception ignored while calling deallocator <ConnectionPool.__del__>:
    ...
    PythonFinalizationError: cannot join thread at interpreter shutdown

on stderr *after* the process had already finished its work — making a clean
validation error look like a crash.

The fix registers ``_close_pool_quietly`` via ``weakref.finalize`` at pool
construction, so the pool closes from an atexit hook (before the finalization
window) rather than from the deallocator inside it.

Both subprocess cases below FAIL on the pre-fix build: the observed trigger in
the wild was an *error* path, so the failing-command case is the one that
matters most, but the successful command regressed identically.

Deliberately not marked ``slow``: this guards a documented release criterion
(Python 3.14 is a supported runtime), so it belongs in the default gate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
import weakref

import pytest
from _helpers import DSN, KEY_PATH

from regista._connection import ConnectionManager

# A command that opens a real client and exits WITHOUT closing it -- the shape
# every consumer CLI has. The client is held in a module global so it is still
# alive at interpreter teardown, which is what put the pool's deallocator
# inside the finalization window.
#
# structlog is silenced before importing regista (an embedding app's explicit
# configure() wins -- see test_stream_discipline) so that stderr is genuinely
# empty on success and carries only the command's own error line on failure.
# regista logs to stderr by design, so asserting "no traceback" alone would be
# a weaker check than asserting stderr exactly.
_COMMAND = """
import logging
import os
import sys

import structlog

structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from regista import Regista

# DSN comes through the environment, not argv: pytest renders the child's args
# in failure output, and the DSN carries a password.
client = Regista(os.environ["WI218_DSN"], sys.argv[1], sys.argv[2])
mode = sys.argv[3]

if mode == "fail":
    # Mirrors the observed trigger: argument validation rejected after the
    # client is already open (agent-notes `work-item file --type <invalid>`).
    print("error: invalid --type 'bogus'", file=sys.stderr)
    raise SystemExit(2)

client.query_work_items(page_size=1)  # real work through the pool
print("ok")
"""

_FINALIZATION_MARKERS = (
    "PythonFinalizationError",
    "calling deallocator",
    "Exception ignored",
    "Traceback",
)


@pytest.fixture(scope="module")
def wi218_project():
    """A provisioned project the child processes can simply connect to."""
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"test_wi218_{uuid.uuid4().hex[:8]}"
    client = Regista.create_project(DSN, project, KEY_PATH)
    client.close()
    yield project
    drop_project_schema(DSN, project)


def _run_command(project: str, mode: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["WI218_DSN"] = DSN
    return subprocess.run(
        [sys.executable, "-c", _COMMAND, project, KEY_PATH, mode],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


def _assert_no_finalization_traceback(proc: subprocess.CompletedProcess[str]) -> None:
    for marker in _FINALIZATION_MARKERS:
        assert marker not in proc.stderr, (
            f"shutdown traceback marker {marker!r} on stderr:\n{proc.stderr}"
        )


def test_successful_command_exits_clean(wi218_project: str) -> None:
    proc = _run_command(wi218_project, "ok")
    _assert_no_finalization_traceback(proc)
    assert proc.stderr == "", f"expected empty stderr, got:\n{proc.stderr}"
    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_failing_command_exits_clean(wi218_project: str) -> None:
    """The observed trigger: a validation error must not look like a crash."""
    proc = _run_command(wi218_project, "fail")
    _assert_no_finalization_traceback(proc)
    assert proc.stderr == "error: invalid --type 'bogus'\n", (
        f"expected only the command's error line, got:\n{proc.stderr}"
    )
    assert proc.returncode == 2


def test_close_is_idempotent() -> None:
    """close() twice must not raise, and must not double-close the pool."""
    mgr = ConnectionManager(DSN, "wi218_idempotent")
    mgr.open()
    mgr.close()
    mgr.close()  # must be a no-op, not an error
    assert not mgr._finalizer.alive


def test_close_detaches_the_exit_finalizer() -> None:
    """An explicitly closed manager leaves no work for the exit path.

    Without detaching, the finalizer would close an already-closed pool at
    exit; worse, a bare ``atexit.register`` could never be unregistered at all.
    """
    mgr = ConnectionManager(DSN, "wi218_detach")
    assert mgr._finalizer.alive
    mgr.close()
    assert not mgr._finalizer.alive


def test_finalizer_does_not_keep_the_manager_alive() -> None:
    """The atexit-leak property that makes weakref.finalize the right tool.

    A library that registered a module-level ``atexit`` handler per instance
    (the agent-notes WI-046 shape, where the pool was a single module global)
    would hold a strong reference to every ConnectionManager ever constructed,
    so none could be garbage collected for the life of the process. The
    finalizer must hold only a weak reference.
    """
    mgr = ConnectionManager(DSN, "wi218_no_leak")
    mgr.open()  # a never-opened pool reports closed=True trivially
    ref = weakref.ref(mgr)
    pool = mgr._pool
    # Deliberately NOT closed: the still-live finalizer must not pin the
    # instance. Dropping the last strong reference must collect it and run the
    # finalizer, closing the pool.
    del mgr
    assert ref() is None, "ConnectionManager outlived its last strong reference"
    assert pool.closed, "finalizer did not close the pool when the manager died"


def test_context_manager_closes_the_pool() -> None:
    with ConnectionManager(DSN, "wi218_ctx") as mgr:
        with mgr.connect() as conn:
            conn.execute("SELECT 1").fetchone()
        pool = mgr._pool
    assert pool.closed
    assert not mgr._finalizer.alive


def test_context_manager_closes_the_pool_on_error() -> None:
    mgr = ConnectionManager(DSN, "wi218_ctx_err")
    with pytest.raises(RuntimeError):
        with mgr:
            raise RuntimeError("boom")
    assert mgr._pool.closed
