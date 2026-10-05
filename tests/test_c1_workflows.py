"""Fail-closed publication inputs pinned to evidence from official tags/assets."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(os.environ.get("REGISTA_WORKFLOW_TEST_ROOT", Path(__file__).parents[1]))
UV_CHECKSUM = "9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6"


@pytest.mark.parametrize("name", ["ci", "publish"])
def test_actions_and_uv_are_pinned(name: str) -> None:
    content = (ROOT / f".github/workflows/{name}.yml").read_text()
    doc = yaml.safe_load(content)
    assert doc["permissions"] == {"contents": "read"}
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
                if step["uses"].startswith("astral-sh/setup-uv@"):
                    assert step["with"]["version"] == "0.12.23"
                    assert step["with"]["checksum"] == UV_CHECKSUM
                    assert "architecture" not in step["with"]
            assert "uvx" not in step.get("run", "")


def test_publish_requires_identifier_and_merged_commit() -> None:
    doc = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    steps = doc["jobs"]["verify"]["steps"]
    identifier = next(s for s in steps if "check_committed_identifiers.py" in s.get("run", ""))
    assert "REGISTA_FORBIDDEN_IDENTIFIERS" in identifier["env"]
    merged = next(s for s in steps if "merge-base --is-ancestor" in s.get("run", ""))
    assert "origin/main" in merged["run"]
    assert "git fetch" in merged["run"]
    assert steps.index(merged) < next(i for i,s in enumerate(steps) if s.get("name") == "Install")


def test_c4_guard_is_immediately_uploaded_and_twine_is_unprivileged() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())["jobs"]
    steps = jobs["build"]["steps"]
    index = next(i for i, s in enumerate(steps)
                 if "check-dist --authoritative" in s.get("run", ""))
    upload = steps[index + 1]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"] == {"name": "dist", "path": "dist/"}
    assert not any("twine" in s.get("run", "") for s in steps)
    twine = jobs["twine"]
    assert twine["needs"] == "build"
    assert twine["permissions"] == {"contents": "read"}
    assert "environment" not in twine
    assert set(jobs["publish"]["needs"]) == {"build", "twine"}
    for job in (twine, jobs["publish"]):
        download = next(s for s in job["steps"]
                        if s.get("uses", "").startswith("actions/download-artifact@"))
        assert download["with"] == upload["with"]
    assert any(".release-twine/bin/twine check dist/*" == s.get("run")
               for s in twine["steps"])


def test_c4_release_tool_installations_require_hashes_and_fresh_venvs() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())["jobs"]
    for job, venv, lock in (("twine", ".release-twine", "twine"),
                            ("build", ".release-build", "build")):
        run = next(s["run"] for s in jobs[job]["steps"]
                   if f".github/{lock}-requirements.txt" in s.get("run", ""))
        assert f"uv venv {venv} --python 3.14" in run
        assert (f"uv pip install --python {venv}/bin/python --require-hashes "
                f"-r .github/{lock}-requirements.txt") in run
    for name in ("twine", "build"):
        content = (ROOT / f".github/{name}-requirements.txt").read_text()
        logical = content.replace("\\\n", " ")
        entries = [line.strip() for line in logical.splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
        assert entries
        for entry in entries:
            assert re.match(r"[a-z0-9-]+==[0-9][^ ]*", entry)
            assert re.search(r"--hash=sha256:[0-9a-f]{64}", entry)
            assert not re.search(r"https?://|--index|--extra|--trusted", entry)
        if name == "twine":
            assert any(e.startswith("twine==7.0.0 ") for e in entries)
        else:
            declared = tomllib.loads((ROOT / "pyproject.toml").read_text())
            pinned = {e.split()[0] for e in entries}
            assert pinned == set(declared["build-system"]["requires"]) | {"pip==26.2.1"}


def test_c4_verification_uses_frozen_project_lock() -> None:
    for name, job in (("publish", "verify"), ("ci", "kernel")):
        steps = yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())
        run = next(s["run"] for s in steps["jobs"][job]["steps"] if s.get("name") == "Install")
        assert "uv sync --frozen --extra dev" in run
        assert "pip install -e" not in run
        assert "--upgrade pip" not in run
        assert "--require-hashes -r .github/build-requirements.txt" in run


def test_c4_approval_summary_contains_exact_hashes(tmp_path: Path) -> None:
    steps = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    steps = steps["jobs"]["build"]["steps"]
    summary = next(s for s in steps if "GITHUB_STEP_SUMMARY" in s.get("run", ""))
    guard = next(s for s in steps if "check-dist --authoritative" in s.get("run", ""))
    assert steps.index(summary) < steps.index(guard)
    assert summary["env"] == {
        "CANDIDATE_SHA": "${{ github.sha }}", "CANDIDATE_TAG": "${{ github.ref_name }}",
    }
    (tmp_path / "dist").mkdir()
    for name in ("regista.whl", "regista.tar.gz"):
        (tmp_path / "dist" / name).write_bytes(name.encode())
    output = tmp_path / "summary"
    subprocess.run(["bash", "-e", "-c", summary["run"]], cwd=tmp_path, check=True,
                   env={**os.environ, "GITHUB_STEP_SUMMARY": str(output),
                        "CANDIDATE_SHA": "a" * 40, "CANDIDATE_TAG": "v0.8.0"})
    text = output.read_text()
    assert "a" * 40 in text and "v0.8.0" in text
    assert "Reject any mismatch" in text
    for name in ("regista.whl", "regista.tar.gz"):
        assert hashlib.sha256(name.encode()).hexdigest() + "  dist/" + name in text
