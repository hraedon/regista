from __future__ import annotations

import os
from pathlib import Path

TESTS_DIR = Path(__file__).parent

# DSN is configurable via REGISTA_TEST_DSN so CI / operators can point at a
# real Postgres. When unset, the default localhost DSN is used and DB-dependent
# tests are skipped cleanly if that host is unreachable (see conftest.py).
DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
