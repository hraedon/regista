"""Stream discipline + error envelope (suite CLI contract v1, Plan 018 P0).

Contract: regista used as a library must not write to stdout by default
(unconfigured structlog defaults to stdout and contaminates the embedding
CLI's --json output — the agent-notes WI-019 root cause), and CLI errors
under --json emit the common error envelope on stdout with exit 1.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from regista._cli import _handle_error
from regista._errors import ErrorCode, RegistaError


def _run_snippet(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )


def test_library_logging_defaults_to_stderr() -> None:
    proc = _run_snippet(
        "import regista, structlog\n"
        "structlog.get_logger().info('probe.event', k='v')\n"
    )
    assert "probe.event" not in proc.stdout
    assert proc.stdout == ""
    assert "probe.event" in proc.stderr


def test_app_structlog_configuration_wins() -> None:
    """An embedding app's explicit configure() is never overridden."""
    proc = _run_snippet(
        "import sys, structlog\n"
        "structlog.configure(\n"
        "    logger_factory=structlog.PrintLoggerFactory(file=sys.stdout))\n"
        "import regista\n"
        "structlog.get_logger().info('probe.event', k='v')\n"
    )
    assert "probe.event" in proc.stdout


def test_handle_error_human_mode(capsys: pytest.CaptureFixture) -> None:
    err = RegistaError(ErrorCode.WORK_ITEM_NOT_FOUND, "no such item")
    with pytest.raises(SystemExit) as excinfo:
        _handle_error(err)
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[WORK_ITEM_NOT_FOUND] no such item" in captured.err


def test_handle_error_json_mode_emits_envelope(
    capsys: pytest.CaptureFixture,
) -> None:
    err = RegistaError(
        ErrorCode.INVALID_TRANSITION,
        "cannot go there",
        detail={"from": "open", "to": "done"},
    )
    with pytest.raises(SystemExit) as excinfo:
        _handle_error(err, json_mode=True)
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    document = json.loads(captured.out)
    assert document["ok"] is False
    assert document["error"]["code"] == "INVALID_TRANSITION"
    assert document["error"]["message"] == "cannot go there"
    assert document["error"]["retryable"] is False
    assert json.loads(document["error"]["detail"]) == {
        "from": "open",
        "to": "done",
    }
    assert document["error"]["partial"] is None


def test_handle_error_retryable_codes(capsys: pytest.CaptureFixture) -> None:
    err = RegistaError(ErrorCode.CONCURRENT_MODIFICATION, "expected_seq stale")
    with pytest.raises(SystemExit):
        _handle_error(err, json_mode=True)
    document = json.loads(capsys.readouterr().out)
    assert document["error"]["retryable"] is True
