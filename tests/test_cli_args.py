from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._cli import main as cli_main

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


class TestCLIExitCodes:
    def test_no_args_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main([])
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "usage:" in captured.err or "usage:" in captured.out

    def test_workflow_validate_ok(self, capsys):
        cli_main(["workflow", "validate", WORKFLOW_PATH])
        captured = capsys.readouterr()
        assert "Valid:" in captured.out

    def test_workflow_validate_json(self, capsys):
        cli_main(["workflow", "validate", WORKFLOW_PATH, "--json"])
        captured = capsys.readouterr()
        assert "\"valid\":" in captured.out

    def test_workflow_validate_bad(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["workflow", "validate", "--json", "/dev/null"])
        assert exc_info.value.code == 1

    def test_work_item_show_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["work-item", "show", str(uuid.uuid4())])
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "Missing" in captured.err

    def test_schema_status_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["schema", "status"])
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "Missing" in captured.err

    def test_schema_init_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["schema", "init"])
        assert exc_info.value.code == 2

    def test_replay_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["replay"])
        assert exc_info.value.code == 2

    def test_events_show_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["events", "show", str(uuid.uuid4())])
        assert exc_info.value.code == 2

    def test_events_tail_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["events", "tail"])
        assert exc_info.value.code == 2

    def test_hooks_dead_letter_list_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["hooks", "dead-letter", "list"])
        assert exc_info.value.code == 2

    def test_hooks_dead_letter_requeue_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["hooks", "dead-letter", "requeue", "42"])
        assert exc_info.value.code == 2

    def test_actor_roles_list_missing_config(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["actor-roles", "list"])
        assert exc_info.value.code == 2

    def test_unknown_command_prints_help(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["bogus"])
        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "usage:" in captured.out or "usage:" in captured.err
