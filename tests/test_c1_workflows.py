"""Fail-closed publication inputs pinned to evidence from official tags/assets."""
from __future__ import annotations

import os
import re
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
            if "twine check" in step.get("run", ""):
                assert "twine==6.2.0" in step["run"]


def test_publish_requires_identifier_and_merged_commit() -> None:
    doc = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    steps = doc["jobs"]["verify"]["steps"]
    identifier = next(s for s in steps if "check_committed_identifiers.py" in s.get("run", ""))
    assert "REGISTA_FORBIDDEN_IDENTIFIERS" in identifier["env"]
    merged = next(s for s in steps if "merge-base --is-ancestor" in s.get("run", ""))
    assert "origin/main" in merged["run"]
    assert "git fetch" in merged["run"]
    assert steps.index(merged) < next(i for i,s in enumerate(steps) if s.get("name") == "Install")
