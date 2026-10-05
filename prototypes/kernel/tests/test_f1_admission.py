from __future__ import annotations

import ast
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from kernel import Kernel

ROOT = Path(os.environ.get("REGISTA_KERNEL_TEST_ROOT", Path(__file__).parents[1]))


@pytest.mark.parametrize("mode", ["local", "ci", "required", "configured"])
def test_database_requirement(tmp_path: Path, mode: str) -> None:
    source = Path(__file__).with_name("conftest.py").read_text()
    (tmp_path / "conftest.py").write_text(source)
    (tmp_path / "test_probe.py").write_text("def test_probe(dsn):\n    assert dsn == 'probe'\n")
    env = {**os.environ, "REGISTA_KERNEL_TEST_ROOT": str(ROOT)}
    for name in ("CI", "REGISTA_REQUIRE_DB", "REGISTA_TEST_DSN"):
        env.pop(name, None)
    if mode == "ci":
        env["CI"] = "true"
    elif mode == "required":
        env["REGISTA_REQUIRE_DB"] = "1"
    elif mode == "configured":
        env.update(CI="true", REGISTA_REQUIRE_DB="1", REGISTA_TEST_DSN="probe")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-c", "/dev/null", str(tmp_path), "-q"],
        env=env, capture_output=True, text=True, timeout=20,
    )
    if mode in ("ci", "required"):
        assert result.returncode == 4, result.stdout + result.stderr
        assert "REGISTA_TEST_DSN is required" in result.stderr
        assert "skipped" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert ("1 skipped" if mode == "local" else "1 passed") in result.stdout


def test_protection_suite_is_in_postgres_ci() -> None:
    path = Path(__file__).parents[3] / ".github/workflows/ci.yml"
    job = yaml.safe_load(path.read_text())["jobs"]["prototype-kernel"]
    assert job["services"]["postgres"]["image"] == "postgres:15"
    assert job["strategy"]["matrix"]["python-version"] == ["3.11", "3.12", "3.13", "3.14"]
    step = next(s for s in job["steps"] if "prototypes/kernel/tests" in s.get("run", ""))
    env = {**job.get("env", {}), **step.get("env", {})}
    assert env["REGISTA_TEST_DSN"] == (
        "postgresql://regista_test:regista_test@localhost:5432/regista_test"
    )
    assert str(env["REGISTA_REQUIRE_DB"]) == "1"


def test_public_methods_declare_access_and_gate_writes() -> None:
    tree = ast.parse(inspect.getsource(Kernel))
    declaration = tree.body[0]
    assert isinstance(declaration, ast.ClassDef)
    methods = {n.name: n for n in declaration.body if isinstance(n, ast.FunctionDef)}

    def writes(name: str, seen: frozenset[str] = frozenset()) -> bool:
        if name in seen or name not in methods:
            return False
        for node in ast.walk(methods[name]):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.match(r"\s*(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b", node.value):
                    return True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if isinstance(owner, ast.Name) and owner.id in ("self", "cls"):
                    if writes(node.func.attr, seen | {name}):
                        return True
        return False

    for name, method in inspect.getmembers(Kernel, predicate=callable):
        if name.startswith("_"):
            continue
        access = getattr(method, "_kernel_access", None)
        assert access in {"read", "write", "initialize", "lifecycle"}, name
        if writes(name):
            assert access in {"write", "initialize"}, f"{name} reaches persistent SQL writes"
        if access == "read":
            assert getattr(method, "_kernel_read_only", False), name
        if access == "write":
            assert getattr(method, "_kernel_schema_gated", False), name
        if access == "initialize":
            assert "UnsupportedSchemaError" in ast.unparse(methods[name]), name
