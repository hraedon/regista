"""Pin the published quickstart, packaged scenarios and generated public references."""

from __future__ import annotations

import os
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from regista import Kernel

ROOT = Path(__file__).resolve().parents[1]


def test_readme_quickstart(dsn: str, schema: str) -> None:
    readme = (ROOT / "README.md").read_text()
    snippet = readme.split("```python\n", 1)[1].split("```", 1)[0]
    assert snippet == (ROOT / "examples/quickstart.py").read_text()
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        env={**os.environ, "REGISTA_DSN": dsn, "REGISTA_SCHEMA": schema},
        capture_output=True, text=True, check=True,
    )
    assert result.stdout.strip() == "done"
    # A fresh connection must see the completed handoff and released ownership.
    k = Kernel.connect(dsn, schema=schema, require_existing=True)
    try:
        [item] = k.list_items()
        assert item.state == "done"
        assert k.lease(item.id) is None
        assert [e.actor_id for e in k.history(item.id)] == ["worker", "worker", "alice"]
        assert k.replay(item.id)[2] == []
    finally:
        k.close()


def test_packaged_scenarios_are_verbatim() -> None:
    resources = files("regista").joinpath("examples")
    for name in ("example_handoff.py", "example_documents.py",
                 "remediation.workflow.yaml", "ingest.workflow.yaml"):
        assert resources.joinpath(name).read_bytes() == (ROOT / "examples" / name).read_bytes()


def test_generated_references_are_current() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts/generate_reference.py"), "--check"],
                   cwd=ROOT, check=True)


def test_retired_workflow_guidance_matches_rulings() -> None:
    from regista import WORKFLOW_DOCUMENT_REMOVED_KEYS

    # These public refusal explanations also appear in generated references.
    hook = WORKFLOW_DOCUMENT_REMOVED_KEYS["document"]["hook_defaults"]
    assert "validators are retired" in hook
    links = WORKFLOW_DOCUMENT_REMOVED_KEYS["document"]["link_types"]
    assert "link_type_names" in links
