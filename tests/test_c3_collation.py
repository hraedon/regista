"""Baseline admission is independent of server version and database collation."""

from __future__ import annotations

import json
import uuid
from contextlib import closing
from importlib.resources import files

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier, Literal

from regista import Kernel
from regista.kernel import _catalog_fingerprint, _catalog_manifest


def assert_committed_baseline(dsn: str, schema: str) -> None:
    expected = json.loads(files("regista").joinpath("baseline.manifest.json").read_text())
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute(SQL("SET search_path TO {}, pg_catalog").format(Identifier(schema)))
        assert _catalog_manifest(conn, schema) == expected["catalog"]
        assert _catalog_fingerprint(conn, schema) == expected["catalog_fingerprint"]


def test_fresh_baseline_matches_committed_manifest(dsn: str, absent_schema: str) -> None:
    """Runs on the actual REGISTA_TEST_DSN server, including every CI matrix entry."""
    with closing(Kernel.connect(dsn, schema=absent_schema)) as kernel:
        kernel.initialize()
    assert_committed_baseline(dsn, absent_schema)
    with closing(Kernel.connect(dsn, schema=absent_schema, require_existing=True)) as kernel:
        kernel.initialize()


@pytest.mark.parametrize("provider", ["libc", "icu"])
def test_non_c_database_baseline(dsn: str, provider: str) -> None:
    """Use template0 to exercise a real default locale, even on a C test server.

    Only missing locale/provider support skips. Permission, creation, admission
    and cleanup errors fail; the disposable test role must have CREATEDB.
    """
    database = "c3_locale_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        if provider == "libc":
            locale = admin.execute(
                "SELECT collcollate FROM pg_catalog.pg_collation "
                "WHERE collprovider='c' AND collcollate IN ('en_US.utf8', 'en_US.UTF-8') "
                'ORDER BY collcollate COLLATE "C" LIMIT 1'
            ).fetchone()
            if locale is None:
                pytest.skip("server lacks a libc en_US UTF-8 locale in pg_collation")
            settings = SQL("LOCALE_PROVIDER libc LC_COLLATE {} LC_CTYPE {}").format(
                Literal(locale[0]), Literal(locale[0]))
        else:
            available = admin.execute(
                "SELECT 1 FROM pg_catalog.pg_collation "
                "WHERE collprovider='i' AND collname='und-x-icu'"
            ).fetchone()
            if available is None:
                pytest.skip("server lacks ICU und-x-icu locale/provider support")
            # Shift punctuation out of primary comparison so '_' exposes the defect.
            settings = SQL("LOCALE_PROVIDER icu ICU_LOCALE 'und-u-ka-shifted' "
                           "LC_COLLATE 'C' LC_CTYPE 'C'")
        admin.execute(SQL("CREATE DATABASE {} TEMPLATE template0 ENCODING 'UTF8' {}").format(
            Identifier(database), settings))
        try:
            locale_dsn = make_conninfo(dsn, dbname=database)
            with psycopg.connect(locale_dsn) as conn:
                # Prove this fixture actually distinguishes default and byte order.
                names = "(VALUES ('work_items_current'::text), ('workflow_registry')) AS v(name)"
                default = conn.execute(f"SELECT name FROM {names} ORDER BY name").fetchall()
                byte_order = conn.execute(
                    f'SELECT name FROM {names} ORDER BY name COLLATE "C"').fetchall()
                assert default != byte_order, "locale must differ from C for baseline names"
            schema = "c3_baseline"
            with closing(Kernel.connect(locale_dsn, schema=schema)) as kernel:
                kernel.initialize()
            assert_committed_baseline(locale_dsn, schema)
            with closing(Kernel.connect(
                locale_dsn, schema=schema, require_existing=True,
            )) as kernel:
                kernel.initialize()
        finally:
            admin.execute(SQL("DROP DATABASE {} WITH (FORCE)").format(Identifier(database)))
