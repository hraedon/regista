from __future__ import annotations

import json
import os
from pathlib import Path

from regista._cli import main

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _resolve_dsn() -> str:
    try:
        import conftest
    except ImportError:
        return os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN)
    return getattr(conftest, "DSN", os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN))


DSN = _resolve_dsn()

VALID_WORKFLOW = """
name: kernel_cli_wf
version: 1
regista_version: "0.8.0"
states:
  - name: new
    initial: true
  - name: done
    terminal: true
transitions:
  - name: finish
    from: new
    to: done
roles: []
work_item_types:
  - name: task
    custom_fields: []
"""

INVALID_WORKFLOW = """
name: only_a_name
"""


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def test_workflow_validate_valid_returns_zero(tmp_path: Path, capsys) -> None:
    path = _write(tmp_path, "valid.yaml", VALID_WORKFLOW)
    rc = main(["workflow", "validate", str(path)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "Valid" in captured.out


def test_workflow_validate_invalid_returns_one(tmp_path: Path, capsys) -> None:
    path = _write(tmp_path, "invalid.yaml", INVALID_WORKFLOW)
    rc = main(["workflow", "validate", str(path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out.strip() != ""


def test_workflow_validate_missing_file_uses_stderr(capsys) -> None:
    rc = main(["workflow", "validate", "/no/such/workflow.yaml"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.strip() != ""


def test_version_json_emits_parseable_json(capsys) -> None:
    rc = main(["version", "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    data = json.loads(captured.out)
    assert data["component"] == "regista"
    assert data["schema_version"] == 1


def test_doctor_json_runs_against_db(capsys) -> None:
    rc = main(["doctor", "--json", "--dsn", DSN])
    captured = capsys.readouterr()
    assert rc in (0, 1)
    data = json.loads(captured.out)
    assert data["component"] == "regista"
    assert data["reachable"] is True
    assert any(c["name"] == "db:reachable" for c in data["checks"])
