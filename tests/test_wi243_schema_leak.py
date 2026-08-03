from __future__ import annotations

import uuid

import pytest
from _helpers import DSN, KEY_PATH

from regista import Regista
from regista.testing import drop_project_schema


def _catalog_schema_names() -> set[str]:
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as conn:
        try:
            rows = conn.execute(
                "SELECT schema_name FROM public.projects"
            ).fetchall()
        except psycopg.errors.UndefinedTable:
            return set()
        return {r[0] for r in rows}


def _live_schema_names() -> set[str]:
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as conn:
        rows = conn.execute(
            "SELECT schema_name FROM information_schema.schemata"
        ).fetchall()
        return {r[0] for r in rows}


class TestDropProjectSchemaUnregistersCatalog:
    def test_drop_removes_catalog_row(self):
        """drop_project_schema must unregister the catalog row (WI-243).

        The suite was leaking one public.projects row per test project even
        after a clean schema drop, accumulating tens of thousands of rows in a
        shared instance. The catalog is the authoritative project list a
        doctor iterates, so a dropped project must leave the catalog too.
        """
        project = f"wi243_{uuid.uuid4().hex[:8]}"
        try:
            before = _catalog_schema_names()
            Regista.create_project(DSN, project, KEY_PATH)
            assert project in _catalog_schema_names()
        finally:
            drop_project_schema(DSN, project)
        assert project not in _catalog_schema_names()
        assert project not in _live_schema_names()
        assert project not in before  # name collision would invalidate the test

    def test_drop_is_idempotent_and_safe_on_missing_schema(self):
        project = f"wi243_none_{uuid.uuid4().hex[:8]}"
        drop_project_schema(DSN, project)
        drop_project_schema(DSN, project)
        assert project not in _catalog_schema_names()


class TestCreateProjectRegistersCatalog:
    def test_create_registers_and_drop_cleans(self):
        project = f"wi243_reg_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        assert project in _catalog_schema_names()
        sub.close()
        drop_project_schema(DSN, project)
        assert project not in _catalog_schema_names()
        assert project not in _live_schema_names()


class TestCatalogRowCountStableAcrossCreateDrop:
    def test_create_drop_roundtrip_leaves_no_net_growth(self):
        """The leak signal: a create+drop roundtrip must fully unregister.

        Assert on the project's own row/schema, not on global catalog counts:
        the suite runs under xdist, where sibling workers create and drop
        their own projects concurrently. A global count assertion would race
        with them; a membership assertion on the specific project does not.
        """
        project = f"wi243_net_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        assert project in _catalog_schema_names()
        assert project in _live_schema_names()
        sub.close()
        drop_project_schema(DSN, project)
        assert project not in _catalog_schema_names()
        assert project not in _live_schema_names()


@pytest.fixture
def pg_project_that_always_drops():
    """A fixture that MUST drop its schema; a leak here is a test bug."""
    project = f"wi243_fix_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    yield sub, project
    sub.close()
    drop_project_schema(DSN, project)


def test_fixture_pattern_leaves_no_schema(pg_project_that_always_drops):
    sub, project = pg_project_that_always_drops
    sub.register_workflow(
        "name: wi243_wf\nversion: 1\nregista_version: '0.1.0'\n"
        "states:\n  - name: open\n    initial: true\n    terminal: true\n"
        "transitions: []\nroles: []\nwork_item_types: []\n"
    )
    assert project in _catalog_schema_names()
