from __future__ import annotations

import os

from regista._doctor import run_doctor
from regista._version_info import SCHEMA_VERSION

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _resolve_dsn() -> str:
    try:
        import conftest
    except ImportError:
        return os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN)
    return getattr(conftest, "DSN", os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN))


DSN = _resolve_dsn()

UNREACHABLE_DSN = "postgresql://nobody:nobody@127.0.0.1:59999/none"


def test_run_doctor_reachable_db(capsys) -> None:
    report = run_doctor(DSN)

    assert report.reachable is True
    assert report.schema_version == SCHEMA_VERSION
    db_check = next(c for c in report.checks if c.name == "db:reachable")
    assert db_check.status == "ok"

    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    for check in report.checks:
        assert "Traceback" not in check.detail


def test_run_doctor_unreachable_dsn_is_clean_fail() -> None:
    report = run_doctor(UNREACHABLE_DSN)

    assert report.reachable is False
    assert report.schema_version is None
    db_check = next(c for c in report.checks if c.name == "db:reachable")
    assert db_check.status == "fail"
    assert "nobody" not in db_check.detail
    assert "59999" not in db_check.detail
    assert "password" not in db_check.detail.lower()
