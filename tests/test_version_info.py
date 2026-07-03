from __future__ import annotations

import json

from regista._version_info import (
    ENVELOPE_VERSION,
    SCHEMA_VERSION,
    VersionInfo,
    versions,
)


class TestVersions:
    def test_returns_version_info(self):
        info = versions()
        assert isinstance(info, VersionInfo)

    def test_has_library_version(self):
        info = versions()
        assert info.library_version  # not empty

    def test_schema_version_is_int(self):
        info = versions()
        assert isinstance(info.schema_version, int)
        assert info.schema_version > 0

    def test_envelope_version_is_int(self):
        info = versions()
        assert isinstance(info.envelope_version, int)
        assert info.envelope_version > 0

    def test_canonical_workflow_version(self):
        info = versions()
        assert info.canonical_workflow_version

    def test_canonical_workflow_hash(self):
        info = versions()
        assert info.canonical_workflow_hash
        assert len(info.canonical_workflow_hash) == 64  # sha256 hex

    def test_available_signing_schemes(self):
        info = versions()
        assert "hmac-sha256" in info.available_signing_schemes

    def test_to_dict(self):
        info = versions()
        d = info.to_dict()
        assert d["component"] == "regista"
        assert "library_version" in d
        assert "schema_version" in d
        assert "canonical_workflow_version" in d
        assert "envelope_version" in d
        assert "canonical_workflow_hash" in d
        assert "available_signing_schemes" in d

    def test_schema_version_matches_latest_migration(self):
        from pathlib import Path
        migrations_dir = Path(__file__).parent.parent / "migrations"
        files = [f.name for f in migrations_dir.iterdir() if f.suffix == ".sql"]
        versions_list = []
        for f in files:
            try:
                versions_list.append(int(f.split("_", 1)[0]))
            except ValueError:
                continue
        if versions_list:
            assert SCHEMA_VERSION == max(versions_list)

    def test_envelope_version_is_4(self):
        assert ENVELOPE_VERSION == 4


class TestCLIVersion:
    def test_version_json(self):
        import contextlib
        import io

        from regista._cli import main
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            try:
                main(["version", "--json"])
            except SystemExit:
                pass
        data = json.loads(stdout.getvalue())
        assert data["component"] == "regista"
        assert "library_version" in data
        assert "schema_version" in data

    def test_version_text(self):
        import contextlib
        import io

        from regista._cli import main
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            try:
                main(["version"])
            except SystemExit:
                pass
        output = stdout.getvalue()
        assert "regista" in output
        assert "schema_version" in output
