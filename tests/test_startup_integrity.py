from __future__ import annotations

import json
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


class TestMigrationRequired:
    def test_refuses_start_with_pending_migrations(self):
        from regista import Regista

        project = f"test_ac20_mig_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.close()

        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(
                SQL("DELETE FROM {}.{} WHERE version = 6").format(
                    Identifier(project), Identifier("_regista_migrations")
                )
            )

        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.code == ErrorCode.MIGRATION_REQUIRED
        assert "pending" in exc_info.value.message.lower() or "Migrations" in exc_info.value.message

        drop_project_schema(DSN, project)

    def test_refuses_start_with_multiple_pending_migrations(self):
        from regista import Regista

        project = f"test_ac20_migs_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.close()

        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(
                SQL("DELETE FROM {}.{} WHERE version >= 4").format(
                    Identifier(project), Identifier("_regista_migrations")
                )
            )

        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.code == ErrorCode.MIGRATION_REQUIRED

        drop_project_schema(DSN, project)

    def test_starts_normally_with_all_migrations(self):
        from regista import Regista

        project = f"test_ac20_ok_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        sub2 = Regista(DSN, project, KEY_PATH)
        sub2.close()

        sub.close()
        drop_project_schema(DSN, project)


class TestWorkflowVersionIncompatible:
    def _make_incompatible_workflow_yaml(self, regista_version: str) -> str:
        return (
            "name: incompatible_wf\n"
            "version: 1\n"
            f"regista_version: '{regista_version}'\n"
            "\n"
            "states:\n"
            "  - name: new\n"
            "    initial: true\n"
            "  - name: done\n"
            "    terminal: true\n"
            "\n"
            "transitions:\n"
            "  - name: finish\n"
            "    from: new\n"
            "    to: done\n"
            "    allowed_roles: [agent]\n"
            "\n"
            "roles:\n"
            "  - name: agent\n"
            "\n"
            "work_item_types:\n"
            "  - name: task\n"
            "    custom_fields: []\n"
        )

    def test_refuses_start_on_major_version_mismatch(self):
        from regista import Regista
        from regista._workflow import parse_and_validate

        project = f"test_ac20_maj_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)

        wf = parse_and_validate(self._make_incompatible_workflow_yaml("99.0.0"))
        with raw_transaction(sub) as conn:
            conn.execute(
                SQL(
                    "INSERT INTO workflow_registry "
                    "(workflow_name, version, regista_version, definition) "
                    "VALUES (%s, %s, %s, %s)"
                ),
                [wf.name, wf.version, wf.regista_version, json.dumps(wf.to_dict())],
            )

        sub.close()

        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.code == ErrorCode.WORKFLOW_VERSION_INCOMPATIBLE
        assert "major mismatch" in exc_info.value.message

        drop_project_schema(DSN, project)

    def test_refuses_start_on_library_older_than_workflow(self):
        from regista import Regista
        from regista._workflow import parse_and_validate

        project = f"test_ac20_old_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)

        wf = parse_and_validate(self._make_incompatible_workflow_yaml("0.99.0"))
        with raw_transaction(sub) as conn:
            conn.execute(
                SQL(
                    "INSERT INTO workflow_registry "
                    "(workflow_name, version, regista_version, definition) "
                    "VALUES (%s, %s, %s, %s)"
                ),
                [wf.name, wf.version, wf.regista_version, json.dumps(wf.to_dict())],
            )

        sub.close()

        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.code == ErrorCode.WORKFLOW_VERSION_INCOMPATIBLE
        assert "requires regista" in exc_info.value.message

        drop_project_schema(DSN, project)

    def test_starts_normally_with_compatible_workflow(self):
        from regista import Regista

        project = f"test_ac20_compat_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        sub2 = Regista(DSN, project, KEY_PATH)
        sub2.close()

        sub.close()
        drop_project_schema(DSN, project)

    def test_error_detail_contains_issue_list(self):
        from regista import Regista
        from regista._workflow import parse_and_validate

        project = f"test_ac20_det_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)

        wf = parse_and_validate(self._make_incompatible_workflow_yaml("2.0.0"))
        with raw_transaction(sub) as conn:
            conn.execute(
                SQL(
                    "INSERT INTO workflow_registry "
                    "(workflow_name, version, regista_version, definition) "
                    "VALUES (%s, %s, %s, %s)"
                ),
                [wf.name, wf.version, wf.regista_version, json.dumps(wf.to_dict())],
            )

        sub.close()

        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.detail is not None
        assert "issues" in exc_info.value.detail
        assert len(exc_info.value.detail["issues"]) >= 1

        drop_project_schema(DSN, project)
