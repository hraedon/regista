from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
PYTHON = sys.executable


def _run(*args, env=None):
    base_env = {
        "REGISTA_DSN": DSN,
        "REGISTA_HMAC_KEY_PATH": KEY_PATH,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if env:
        base_env.update(env)
    result = subprocess.run(
        [PYTHON, "-m", "regista._cli", *args],
        capture_output=True,
        text=True,
        env=base_env,
        timeout=30,
    )
    return result


def _extract_json(stdout):
    lines = stdout.strip().split("\n")
    filtered = "\n".join(
        line for line in lines
        if not re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    )
    return json.loads(filtered)


def _project_args(project):
    return ["--project", project]


@pytest.fixture
def project():
    name = f"cli_test_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture
def initialized_project(project):
    result = _run(*_project_args(project), "schema", "init")
    assert result.returncode == 0, result.stderr
    return project


@pytest.fixture
def populated_project(initialized_project):
    from regista import Regista

    sub = Regista(DSN, initialized_project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "worker-1",
        custom_fields={"title": "cli-test-item"},
    )
    sub.register_actor_role("worker-1", "agent")
    sub.close()
    return initialized_project, wi.work_item_id


class TestSchemaInit:
    def test_schema_init_success(self, project):
        result = _run(*_project_args(project), "schema", "init")
        assert result.returncode == 0
        assert "initialized" in result.stdout.lower()

    def test_schema_init_idempotent(self, project):
        _run(*_project_args(project), "schema", "init")
        result = _run(*_project_args(project), "schema", "init")
        assert result.returncode == 0


class TestSchemaStatus:
    def test_schema_status_after_init(self, initialized_project):
        result = _run(*_project_args(initialized_project), "schema", "status")
        assert result.returncode == 0
        assert "regista_version" in result.stdout


class TestWorkflowValidate:
    def test_validate_valid_yaml(self):
        result = _run(
            "workflow", "validate", WORKFLOW_PATH,
            env={"REGISTA_DSN": "", "REGISTA_HMAC_KEY_PATH": ""},
        )
        assert result.returncode == 0
        assert "Valid:" in result.stdout

    def test_validate_valid_json_output(self):
        result = _run(
            "workflow", "validate", WORKFLOW_PATH, "--json",
            env={"REGISTA_DSN": "", "REGISTA_HMAC_KEY_PATH": ""},
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["valid"] is True

    def test_validate_invalid_yaml(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("name: x\nstates: []\n")
        result = _run(
            "workflow", "validate", str(bad),
            env={"REGISTA_DSN": "", "REGISTA_HMAC_KEY_PATH": ""},
        )
        assert result.returncode == 1


class TestWorkItemShow:
    def test_show_existing_work_item(self, populated_project):
        project, wi_id = populated_project
        result = _run(*_project_args(project), "work-item", "show", str(wi_id))
        assert result.returncode == 0
        assert str(wi_id) in result.stdout
        assert "test_workflow" in result.stdout

    def test_show_json_output(self, populated_project):
        project, wi_id = populated_project
        result = _run(*_project_args(project), "--json", "work-item", "show", str(wi_id))
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert data["work_item_id"] == str(wi_id)
        assert data["workflow_name"] == "test_workflow"

    def test_show_nonexistent_work_item(self, initialized_project):
        fake_id = str(uuid.uuid4())
        result = _run(*_project_args(initialized_project), "work-item", "show", fake_id)
        assert result.returncode == 1


class TestWorkItemList:
    def test_list_work_items(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "work-item", "list")
        assert result.returncode == 0
        assert "test_workflow" in result.stdout

    def test_list_json_output(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "--json", "work-item", "list")
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert "items" in data
        assert len(data["items"]) >= 1

    def test_list_filter_by_workflow(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "work-item", "list", "--workflow", "test_workflow")
        assert result.returncode == 0
        assert "test_workflow" in result.stdout

    def test_list_filter_by_state_no_match(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "work-item", "list", "--state", "completed")
        assert result.returncode == 0
        lines = [line for line in result.stdout.strip().split("\n")
                 if line and not line.startswith("--") and not line.startswith("202")]
        assert len(lines) == 0


class TestEventsShow:
    def test_show_events_for_work_item(self, populated_project):
        project, wi_id = populated_project
        result = _run(*_project_args(project), "events", "show", str(wi_id))
        assert result.returncode == 0
        assert "created" in result.stdout

    def test_show_events_json_output(self, populated_project):
        project, wi_id = populated_project
        result = _run(*_project_args(project), "--json", "events", "show", str(wi_id))
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["transition"] == "created"


class TestEventsTail:
    def test_tail_events(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "events", "tail")
        assert result.returncode == 0
        assert "created" in result.stdout

    def test_tail_json_output(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "--json", "events", "tail")
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 1


class TestReplay:
    def test_replay_no_drift(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "replay")
        assert result.returncode == 0
        assert "drift=0" in result.stdout

    def test_replay_json_output(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "--json", "replay")
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert data["replayed_drift"] == 0
        assert data["replayed_ok"] >= 1


class TestActorRolesList:
    def test_list_actor_roles(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "actor-roles", "list")
        assert result.returncode == 0
        assert "worker-1" in result.stdout

    def test_list_actor_roles_json(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "--json", "actor-roles", "list")
        assert result.returncode == 0
        data = _extract_json(result.stdout)
        assert isinstance(data, list)
        assert any(r["actor_id"] == "worker-1" for r in data)


class TestHooksDeadLetterList:
    def test_list_empty(self, populated_project):
        project, _ = populated_project
        result = _run(*_project_args(project), "hooks", "dead-letter", "list")
        assert result.returncode == 0


class TestEnvVarConfig:
    def test_project_from_env(self, project):
        result = _run("schema", "init", env={"REGISTA_PROJECT": project})
        assert result.returncode == 0

    def test_missing_all_config(self):
        result = subprocess.run(
            [PYTHON, "-m", "regista._cli", "schema", "status"],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
            timeout=10,
        )
        assert result.returncode == 2
        assert "Missing" in result.stderr
