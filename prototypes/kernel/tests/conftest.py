"""Disposable PostgreSQL fixtures; no v6 bootstrap or private kernel imports."""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

# The proof runner sets this to a scratch copy, never edits the working kernel.
KERNEL_ROOT = Path(os.environ.get("REGISTA_KERNEL_TEST_ROOT", Path(__file__).parents[1]))
sys.path.insert(0, str(KERNEL_ROOT))
from kernel import Kernel, Workflow  # noqa: E402


def pytest_sessionstart(session: pytest.Session) -> None:
    required = bool(os.environ.get("CI")) or os.environ.get("REGISTA_REQUIRE_DB") == "1"
    if required and not os.environ.get("REGISTA_TEST_DSN"):
        raise pytest.UsageError(
            "REGISTA_TEST_DSN is required in CI or when REGISTA_REQUIRE_DB=1; "
            "kernel protection requires disposable PostgreSQL"
        )


@pytest.fixture(scope="session", autouse=True)
def dsn() -> str:
    value = os.environ.get("REGISTA_TEST_DSN")
    if not value:
        pytest.skip("REGISTA_TEST_DSN is unset; kernel protection requires disposable PostgreSQL")
    return value


@pytest.fixture
def schema_factory(dsn: str) -> Iterator[Callable[[], str]]:
    names: list[str] = []

    def create() -> str:
        name = "f1_" + uuid.uuid4().hex
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(name)))
        names.append(name)
        return name

    yield create
    with psycopg.connect(dsn, autocommit=True) as conn:
        for name in reversed(names):
            conn.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(name)))


@pytest.fixture
def schema(schema_factory: Callable[[], str]) -> str:
    return schema_factory()


@pytest.fixture
def kernel(dsn: str, schema: str) -> Iterator[Kernel]:
    handle = Kernel.connect(dsn, schema=schema)
    try:
        handle.initialize(str(KERNEL_ROOT / "schema.sql"))
        yield handle
    finally:
        handle.close()


@pytest.fixture
def workflow() -> Workflow:
    return Workflow(
        name="review",
        types=("task", "source", "review", "jury"),
        states=("new", "doing", "review", "changes", "done", "rejected"),
        initial="new",
        transitions={
            "start": (("new", "changes"), "doing"),
            "edit": (("doing",), "doing"),
            "submit": (("doing",), "review"),
            "reject": (("review",), "changes"),
            "approve": (("review",), "done"),
            "abandon": (("new",), "rejected"),
        },
        roles={"approve": ("reviewer",), "reject": ("reviewer",)},
        role_names=("reviewer",),
        required_fields={"submit": ("note",)},
        terminal=("done", "rejected"),
    )


@pytest.fixture
def registered(kernel: Kernel, workflow: Workflow) -> Kernel:
    assert kernel.register_workflow(workflow) == 1
    return kernel
