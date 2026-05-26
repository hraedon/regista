from __future__ import annotations

import uuid
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate_instance():
    from substrate import Substrate
    from substrate.testing import drop_project_schema

    project = f"test_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def substrate_module():
    from substrate import Substrate
    from substrate.testing import drop_project_schema

    project = f"test_mod_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)
