"""The fresh-baseline guard must refuse drift, legacy paths and unreviewed builds."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "baseline_guard", ROOT / "scripts/check_published_migrations.py"
)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def fixture_tree(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    shutil.copytree(ROOT / "src/regista", tmp_path / "src/regista")
    return GUARD.load_ledger(), tmp_path


def test_distribution_guard_current_baseline() -> None:
    ledger = GUARD.load_ledger()
    assert GUARD.check_ledger(ledger) == []
    assert GUARD.check_tree(ledger) == []
    assert GUARD.check_build_contract((ROOT / "pyproject.toml").read_bytes(), "test") == (
        "regista-hraedon", "0.8.0",
    )


@pytest.mark.parametrize("name", ["schema.sql", "workflow.schema.json"])
@pytest.mark.parametrize("action", ["change", "delete", "symlink"])
def test_distribution_guard_refuses_baseline_drift(
    tmp_path: Path, name: str, action: str,
) -> None:
    ledger, tree = fixture_tree(tmp_path)
    path = tree / "src/regista" / name
    if action == "change":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path.unlink()
        if action == "symlink":
            path.symlink_to(ROOT / "src/regista" / name)
    assert GUARD.check_tree(ledger, tree)


def test_distribution_guard_refuses_undeclared_sql_and_old_tree(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path)
    (tree / "src/regista/extra.sql").write_text("SELECT 1;")
    assert GUARD.check_tree(ledger, tree)
    (tree / "src/regista/extra.sql").unlink()
    (tree / "migrations").mkdir()
    assert GUARD.check_tree(ledger, tree)


@pytest.mark.parametrize("name", [
    "regista/migrations/001_initial.sql", "src/regista/migrations/001_initial.sql",
    "migrations/001_initial.sql", "regista/Schema.SQL", "regista/other.sql",
])
def test_distribution_guard_rejects_retired_artifact_paths(name: str) -> None:
    with pytest.raises(GUARD.GuardError):
        GUARD._classify(name, "regista/", "test", sql_elsewhere=False)


def test_distribution_guard_requires_nonempty_pin(tmp_path: Path) -> None:
    ledger = copy.deepcopy(GUARD.load_ledger())
    ledger["baseline"] = {}
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(ledger))
    with pytest.raises(GUARD.GuardError):
        GUARD.load_ledger(path)


def test_distribution_guard_no_pre08_publication() -> None:
    ledger = GUARD.load_ledger()
    assert GUARD.check_release(ledger, "0.7.2", fresh={})
    assert GUARD.check_release(ledger, "0.8.0", fresh={}) == []


def test_distribution_guard_refuses_build_config_drift() -> None:
    source = (ROOT / "pyproject.toml").read_bytes()
    with pytest.raises(GUARD.GuardError):
        GUARD.check_build_contract(source.replace(b'"src/regista"', b'"src/other"'), "test")
