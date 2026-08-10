from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "docs" / "0.6.0" / "check-conflicts.py"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_conflicts_060", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = _load_checker()


def _mutated_docs(tmp_path: Path, filename: str, old: str, new: str) -> Path:
    docs = tmp_path / "0.6.0"
    shutil.copytree(ROOT / "docs" / "0.6.0", docs)
    path = docs / filename
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, (filename, old, text.count(old))
    path.write_text(text.replace(old, new), encoding="utf-8")
    return docs


def test_current_spec_has_no_conflicts() -> None:
    assert CHECKER.check(ROOT / "docs" / "0.6.0") == []


def test_ordinary_blockquote_is_not_a_supersession_marker() -> None:
    lines = ["> A quoted design requirement.", "", "Exactly the 15-key top-level object."]
    assert CHECKER.is_marked(lines, 0) is False
    assert CHECKER.is_marked(lines, 2) is False


@pytest.mark.parametrize(
    ("filename", "old", "new", "expected"),
    [
        (
            "V6-ENVELOPE.md",
            "Exactly the 16-key top-level object of §1",
            "Exactly the 15-key top-level object of §1",
            "16 top-level members",
        ),
        (
            "V6-ENVELOPE.md",
            "payload, producer, project_instance_id",
            "payload, project_instance_id",
            "canonical key order must include producer",
        ),
        (
            "V6-ENVELOPE.md",
            (
                "| 13 | `transition` | string | yes | Workflow or lifecycle transition "
                "name | Non-empty on every v6 event, ≤ 255 chars. |"
            ),
            (
                "| 13 | `transition` | string \\| null | yes | Workflow transition name | "
                "`null` iff `workflow` is `null`. Non-empty string otherwise, ≤ 255 chars. |"
            ),
            "transition is a required non-empty string",
        ),
        (
            "V6-ENVELOPE.md",
            "| `metadata` | object \\| null | yes | Supplementary actor claims |",
            "| `metadata` | object \\| null | yes | Lineage and harness claims |",
            "producer identity belongs only in the producer block",
        ),
        (
            "REVIEW-VERDICTS.md",
            '    "content_state_digest": "sha256:...",            // [Δ] §2.3',
            '    "content_state_digest": "sha256:...",\n    "subject_profile": {},',
            "subject_profile is cut",
        ),
        (
            "TRUST-DOMAIN.md",
            '- `mode: "recovery"` requires the **current root threshold**.',
            '- `mode: "recovery"` requires the registrar.',
            "root threshold for recovery",
        ),
        (
            "TRUST-DOMAIN.md",
            "The design satisfies this without putting mutable governance into `trust_domain_id`",
            "The design satisfies this by making governance a determinant of `trust_domain_id`",
            "keeps governance out",
        ),
        (
            "CUTOVER-CLASSIFICATION.md",
            "| `trust_log_checkpoint` | The three-field trust-domain checkpoint object",
            "| `trust_log_checkpoint_hash` | The trust-domain checkpoint hash",
            "three-field trust_log_checkpoint object",
        ),
        (
            "IMPLEMENTATION-PLAN.md",
            (
                "### P3.2 — Signed review verdicts · **owner: team** · "
                "dep: **P0.2 passing — satisfied**"
            ),
            "### P3.2 — Signed review verdicts · **deferred, not in this window**",
            "P3.2 is no longer described as blocked",
        ),
        (
            "FIELD-MATRIX.md",
            "The pre-S1 classifier had this hole",
            "The current classifier is permissive and has this hole",
            "S1 shipped the strict classifier",
        ),
    ],
)
def test_known_regressions_fail_closed(
    tmp_path: Path,
    filename: str,
    old: str,
    new: str,
    expected: str,
) -> None:
    docs = _mutated_docs(tmp_path, filename, old, new)
    problems = CHECKER.check(docs)
    assert any(expected in problem for problem in problems), problems
