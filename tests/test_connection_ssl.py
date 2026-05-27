from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")


class TestRequireSsl:
    def test_require_ssl_rejects_plaintext_connection(self):
        from regista import Regista

        project = f"test_ssl_{uuid.uuid4().hex[:8]}"
        Regista.create_project(DSN, project, KEY_PATH)
        try:
            with pytest.raises(RegistaError) as exc_info:
                Regista(DSN, project, KEY_PATH, require_ssl=True)
            assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
            assert "SSL is required" in exc_info.value.message
        finally:
            drop_project_schema(DSN, project)

    def test_require_ssl_false_allows_plaintext(self):
        from regista import Regista

        project = f"test_ssl_off_{uuid.uuid4().hex[:8]}"
        Regista.create_project(DSN, project, KEY_PATH)
        try:
            sub = Regista(DSN, project, KEY_PATH, require_ssl=False)
            sub.close()
        finally:
            drop_project_schema(DSN, project)

    def test_require_ssl_passed_through_create_project(self):
        from regista import Regista

        project = f"test_ssl_cp_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH, require_ssl=False)
        sub.close()
        drop_project_schema(DSN, project)
