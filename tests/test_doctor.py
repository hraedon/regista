from __future__ import annotations

import pytest

from regista._doctor import DoctorCheck, DoctorReport, run_doctor
from regista._version_info import SCHEMA_VERSION


class TestDoctorCheck:
    def test_valid_statuses(self):
        for status in ("ok", "warn", "fail", "skip"):
            check = DoctorCheck(name="test", status=status, detail="...")
            assert check.status == status

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError):
            DoctorCheck(name="test", status="invalid", detail="...")

    def test_to_dict(self):
        check = DoctorCheck(name="db", status="ok", detail="connected")
        d = check.to_dict()
        assert d == {"name": "db", "status": "ok", "detail": "connected"}


class TestDoctorReport:
    def test_to_dict_shape(self):
        report = DoctorReport(
            component="regista",
            version="0.5.0",
            reachable=True,
            schema_version=SCHEMA_VERSION,
            projects=[{"name": "test"}],
            checks=[
                DoctorCheck(name="db", status="ok", detail="connected"),
            ],
        )
        d = report.to_dict()
        assert d["component"] == "regista"
        assert d["reachable"] is True
        assert d["schema_version"] == SCHEMA_VERSION
        assert len(d["checks"]) == 1
        assert d["checks"][0]["name"] == "db"


class TestRunDoctor:
    def test_no_dsn_returns_skip(self):
        report = run_doctor(dsn=None)
        assert report.reachable is False
        assert report.schema_version is None
        assert any(c.name == "dsn" and c.status == "skip" for c in report.checks)

    def test_unreachable_dsn_is_clean_fail(self):
        report = run_doctor("postgresql://nobody:nobody@127.0.0.1:1/nonexistent")
        assert report.reachable is False
        db_check = next(c for c in report.checks if c.name == "db:reachable")
        assert db_check.status == "fail"

    def test_reachable_db_with_no_projects(self):
        from tests.conftest import DSN

        report = run_doctor(DSN)
        assert report.reachable is True
        assert report.schema_version == SCHEMA_VERSION

    def test_with_project_checks_schema(self):
        import uuid

        from regista import Regista
        from regista.testing import drop_project_schema
        from tests.conftest import DSN, KEY_PATH

        project = f"test_doc_{uuid.uuid4().hex[:8]}"
        Regista.create_project(DSN, project, KEY_PATH)
        try:
            report = run_doctor(DSN, project=project)
            assert report.reachable is True
            schema_check = next(
                c for c in report.checks if c.name == f"schema:{project}"
            )
            assert schema_check.status == "ok"
        finally:
            drop_project_schema(DSN, project)
