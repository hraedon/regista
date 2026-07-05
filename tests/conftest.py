from __future__ import annotations

import uuid

import pytest
from _helpers import DSN, KEY_PATH


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
