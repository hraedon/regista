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
        from _helpers import DSN

        report = run_doctor(DSN)
        assert report.reachable is True
        assert report.schema_version == SCHEMA_VERSION

    def test_reachable_db_bounds_project_iteration(self, monkeypatch):
        """Without project= the doctor caps per-project checks (WI-244).

        A shared instance carries thousands of leaked test schemas; a
        diagnostic path must not do unbounded serial work on them. The cap
        check names the bound instead of iterating every catalog row.
        """
        from _helpers import DSN

        import regista._doctor as doctor_mod

        names = [f"leaked_{i:03d}" for i in range(40)]
        monkeypatch.setattr(
            doctor_mod, "_list_projects",
            lambda *a, **k: [{"name": n} for n in names],
        )

        report = run_doctor(DSN, max_projects=5)
        assert report.reachable is True
        projects_check = next(c for c in report.checks if c.name == "projects")
        assert projects_check.status == "warn"
        assert "40 projects" in projects_check.detail
        assert "checked the first 5" in projects_check.detail
        schema_checks = [
            c for c in report.checks if c.name.startswith("schema:leaked_")
        ]
        assert len(schema_checks) == 5

    def test_reachable_db_project_iteration_unbounded_when_no_cap(self, monkeypatch):
        from _helpers import DSN

        import regista._doctor as doctor_mod

        names = [f"leaked_{i:03d}" for i in range(40)]
        monkeypatch.setattr(
            doctor_mod, "_list_projects",
            lambda *a, **k: [{"name": n} for n in names],
        )

        report = run_doctor(DSN, max_projects=0)
        assert report.reachable is True
        assert not any(c.name == "projects" for c in report.checks)
        schema_checks = [
            c for c in report.checks if c.name.startswith("schema:leaked_")
        ]
        assert len(schema_checks) == 40

    def test_with_project_checks_schema(self):
        import uuid

        from _helpers import DSN, KEY_PATH

        from regista import Regista
        from regista.testing import drop_project_schema

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


class TestRoleAttributes:
    """WI-230: doctor reports the connecting role's rolcreaterole so bootstrap
    can verify the CREATEROLE prerequisite before provisioning."""

    def _role_check(self, report):
        return next(c for c in report.checks if c.name == "role:createrole")

    def test_reachable_reports_role_createrole(self):
        # Call the check directly rather than run_doctor: the shared test DB
        # carries thousands of leaked project schemas, so run_doctor's
        # per-project schema loop is impractically slow here. The check itself
        # is a single short connection.
        from _helpers import DSN

        from regista._doctor import _check_role_attributes

        check = _check_role_attributes(DSN, require_ssl=False)
        # The test role is a superuser, so the prerequisite is satisfied.
        assert check.name == "role:createrole"
        assert check.status == "ok"
        assert "regista_test" in check.detail

    def test_no_dsn_omits_role_check(self):
        report = run_doctor(dsn=None)
        assert not any(c.name == "role:createrole" for c in report.checks)

    def test_unreachable_omits_role_check(self):
        report = run_doctor("postgresql://nobody:nobody@127.0.0.1:1/nonexistent")
        assert report.reachable is False
        assert not any(c.name == "role:createrole" for c in report.checks)

    @staticmethod
    def _patch_role_row(monkeypatch, row):
        # Drive the real _check_role_attributes without a second login role:
        # the test role is a superuser, so a non-superuser row is synthesized.
        import psycopg

        import regista._doctor as doctor_mod

        class _FakeCursor:
            def fetchone(self):
                return row

        class _FakeConn:
            def execute(self, *args, **kwargs):
                return _FakeCursor()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(psycopg, "connect", lambda *a, **k: _FakeConn())
        return doctor_mod

    def test_warns_when_role_lacks_createrole(self, monkeypatch):
        doctor_mod = self._patch_role_row(
            monkeypatch, ("svc_regista", False, False)
        )
        check = doctor_mod._check_role_attributes("postgresql://x", require_ssl=False)
        assert check.status == "warn"
        assert "rolcreaterole=false" in check.detail
        assert "svc_regista" in check.detail

    def test_ok_when_role_has_createrole(self, monkeypatch):
        doctor_mod = self._patch_role_row(
            monkeypatch, ("svc_regista", False, True)
        )
        check = doctor_mod._check_role_attributes("postgresql://x", require_ssl=False)
        assert check.status == "ok"
        assert "rolcreaterole=true" in check.detail


class TestCustodyConsistency:
    def _key_file(self, tmp_path, entries):
        import json

        path = tmp_path / "keys.json"
        path.write_text(json.dumps({"keys": entries}))
        return str(path)

    def _custody_check(self, report):
        return next(c for c in report.checks if c.name == "custody:consistency")

    def test_no_key_path_skips(self):
        report = run_doctor(dsn=None, key_path=None)
        check = self._custody_check(report)
        assert check.status == "skip"

    def test_missing_key_file_skips(self, tmp_path):
        report = run_doctor(dsn=None, key_path=str(tmp_path / "nope.json"))
        check = self._custody_check(report)
        assert check.status == "skip"

    def test_file_ref_matches_file_backend_ok(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "k1", "principal_id": "alice",
             "secret_ref": "file:/somewhere/key.bin", "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend="file")
        check = self._custody_check(report)
        assert check.status == "ok"

    def test_file_ref_on_vault_backend_warns(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "k1", "principal_id": "alice",
             "secret_ref": "file:/somewhere/key.bin", "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend="vault")
        check = self._custody_check(report)
        assert check.status == "warn"
        assert "alice" in check.detail
        assert "expected vault" in check.detail

    def test_vault_ref_matches_vault_backend_ok(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "k1", "principal_id": "alice",
             "secret_ref": "vault:secret/regista/principals/alice/private_key",
             "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend="vault")
        check = self._custody_check(report)
        assert check.status == "ok"

    def test_operator_backend_warns_on_any_custodied_key(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "k1", "principal_id": "alice",
             "secret_ref": "file:/somewhere/key.bin", "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend="operator")
        check = self._custody_check(report)
        assert check.status == "warn"
        assert "operator" in check.detail

    def test_no_principal_entries_ok(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "bootstrap", "secret": "dGVzdA==", "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend="vault")
        check = self._custody_check(report)
        assert check.status == "ok"

    def test_defaults_to_file_backend(self, tmp_path):
        path = self._key_file(tmp_path, [
            {"key_id": "k1", "principal_id": "alice",
             "secret_ref": "file:/k.bin", "status": "active"},
        ])
        report = run_doctor(dsn=None, key_path=path, secret_backend=None)
        check = self._custody_check(report)
        assert check.status == "ok"
