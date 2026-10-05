"""Run the published examples and mutation checks on separate disposable databases."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.sql import SQL, Identifier

REPO = Path(__file__).resolve().parents[1]
SCENARIOS = [
    "examples/example_handoff.py",
    "examples/example_documents.py",
    "tests/test_mutations.py",
]


@pytest.mark.parametrize("script", SCENARIOS)
def test_scenario(script: str, dsn: str) -> None:
    name = "f1b_scenario_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("CREATE DATABASE {}").format(Identifier(name)))
    try:
        result = subprocess.run(
            [sys.executable, str(REPO / script), make_conninfo(dsn, dbname=name)],
            cwd=REPO,
            env={**os.environ, "PYTHONPATH": str(REPO / "src")},
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout)
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("DROP DATABASE {} WITH (FORCE)").format(Identifier(name)))
