"""The publish.yml trusted-publisher preflight (GitHub issue #70) leaks nothing.

The step is a Python program embedded in .github/workflows/publish.yml. It
mints a live PyPI upload credential, so its failure handling is security-
relevant and was found wrong twice in review. This file extracts the exact
step from the workflow and runs it against a local fake standing in for both
upload.pypi.org and the GitHub OIDC endpoint. It asserts four things for
every shape: the exit code, that no secret appears outside an ::add-mask::
line, that nothing is written to disk, and when the token is burned.
No network and no database are needed.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
SECRETS = ("GH.JWT.SECRET", "pypi-MINTED-SECRET", "REQTOK", "QUERY-SECRET", "DESC-SECRET",
           "pypi-NESTED", "set-output", "Traceback")


def _step() -> dict[str, object]:
    doc = yaml.safe_load(WORKFLOW.read_text())
    job = doc["jobs"]["oidc-preflight"]
    steps: list[dict[str, object]] = job["steps"]
    assert len(steps) == 1
    return steps[0]


def test_the_preflight_job_is_dispatch_from_main_only_and_never_reaches_publish() -> None:
    doc = yaml.safe_load(WORKFLOW.read_text())
    jobs = doc["jobs"]
    assert jobs["oidc-preflight"]["if"] == (
        "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
    )
    assert jobs["oidc-preflight"]["environment"].split()[0] == "pypi"
    assert "needs" not in jobs["oidc-preflight"]
    assert jobs["verify"]["if"].startswith("github.event_name == 'push'")
    assert jobs["build"]["needs"] == "verify" and "if" not in jobs["build"]
    assert jobs["publish"]["needs"] == "build" and "if" not in jobs["publish"]
    assert _step()["shell"] == "python3 {0}"


class _Fake(http.server.BaseHTTPRequestHandler):
    mode = "ok"
    burned: ClassVar[list[str]] = []

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.startswith("/_/oidc/audience"):
            self._send(200, "[]" if self.mode == "aud-list" else '{"audience":"pypi"}')
        elif self.path.startswith("/oidc?"):
            if self.mode == "oidc-drop":
                self.connection.shutdown(socket.SHUT_RDWR)
            elif self.mode == "oidc-incomplete":
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b'{"val')
            else:
                self._send(200, "[]" if self.mode == "oidc-list" else '{"value":"GH.JWT.SECRET"}')

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/_/oidc/burn-token":
            type(self).burned.append(json.loads(body)["token"])
            self._send(503 if self.mode == "burn-503" else 202, '{"message":"Accepted"}')
            return
        responses = {
            "ok": (200, '{"success":true,"token":"pypi-MINTED-SECRET"}'),
            "burn-503": (200, '{"success":true,"token":"pypi-MINTED-SECRET"}'),
            "reject": (422, '{"errors":[{"code":"invalid-publisher","description":"no match"}]}'),
            "desc-secret": (
                422,
                '{"errors":[{"code":"invalid-publisher","description":"a\\nDESC-SECRET"},'
                '{"code":"x\\n::set-output y","description":"z"}]}',
            ),
            "nested": (
                422,
                '{"errors":[{"code":"x","token":"pypi-NESTED"}],"e":{"token":"pypi-NESTED"}}',
            ),
            "html": (503, "<html>down</html>"),
            "token-not-str": (200, '{"token":{"pypi-NESTED":1}}'),
        }
        code, text = responses[self.mode]
        self._send(code, text, "text/html" if self.mode == "html" else "application/json")


@pytest.fixture
def fake() -> Iterator[tuple[type[_Fake], int]]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Fake.burned = []
    try:
        yield _Fake, server.server_address[1]
    finally:
        server.shutdown()


CASES = {
    # mode: (exit code, burned token expected, required output fragment)
    "ok": (0, True, "PASS: PyPI accepted this workflow"),
    "burn-503": (1, True, "did not accept the burn request (HTTP 503)"),
    "reject": (1, False, "invalid-publisher: no trusted publisher on PyPI matches"),
    "desc-secret": (1, False, "(unrecognised error code; details withheld)"),
    "nested": (1, False, "(unrecognised error code; details withheld)"),
    "html": (1, False, "mint-token: non-JSON body (HTTP 503); body withheld"),
    "token-not-str": (1, False, "HTTP 200 without a usable token"),
    "aud-list": (1, False, "audience endpoint: JSON body is not an object"),
    "oidc-list": (1, False, "GitHub OIDC endpoint: JSON body is not an object"),
    "oidc-drop": (1, False, "GitHub OIDC endpoint: request failed (RemoteDisconnected)"),
    "oidc-incomplete": (1, False, "GitHub OIDC endpoint: request failed (IncompleteRead)"),
    "missing-env": (1, False, "ACTIONS_ID_TOKEN_REQUEST_URL is not set"),
}


@pytest.mark.parametrize("mode", sorted(CASES))
def test_preflight_outcome_and_no_leak(
    mode: str, fake: tuple[type[_Fake], int], tmp_path: Path
) -> None:
    handler, port = fake
    handler.mode = mode
    source = str(_step()["run"])
    marker = 'HOST = "https://upload.pypi.org"'
    assert source.count(marker) == 1
    script = tmp_path / "step.py"
    script.write_text(source.replace(marker, f'HOST = "http://127.0.0.1:{port}"'))
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACTIONS_ID_TOKEN")}
    if mode != "missing-env":
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = f"http://127.0.0.1:{port}/oidc?sig=QUERY-SECRET"
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "REQTOK"
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    proc = subprocess.run(
        [sys.executable, str(script)], cwd=workdir, env=env,
        capture_output=True, text=True, timeout=60,
    )
    expected_rc, expect_burn, fragment = CASES[mode]
    output = proc.stdout + proc.stderr
    assert proc.returncode == expected_rc, output
    assert fragment in output, output
    visible = "\n".join(
        line for line in output.splitlines() if not line.startswith("::add-mask::")
    )
    leaked = [s for s in SECRETS if s in visible]
    assert not leaked, f"leaked {leaked}:\n{output}"
    assert list(workdir.iterdir()) == [], "the preflight wrote to disk"
    assert handler.burned == (["pypi-MINTED-SECRET"] if expect_burn else [])
    if "pypi-MINTED-SECRET" in output:
        first = output.index("pypi-MINTED-SECRET")
        assert output[:first].endswith("::add-mask::"), "minted token printed before its mask"
