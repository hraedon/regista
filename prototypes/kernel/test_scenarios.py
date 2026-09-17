"""CI wrapper for the F0a runnable scenarios and mutation checks.

`example_handoff.py`, `example_documents.py` and `test_mutations.py` are
deliberately plain `python foo.py "$DSN"` scripts (see
prototypes/kernel/README.md) — Plan 032 F0a asked for scenarios runnable
through the same public interface a person or CI step would use, not pytest
fixtures reaching past it. This file does not restructure any of that; it
only gives them a place in the maintained CI test path (Plan 032
open-decisions D14): run each one against a real PostgreSQL service exactly
as documented, and fail loudly — with the scenario's own output attached —
if it exits non-zero.

Each scenario is invoked as a subprocess rather than imported, on purpose:
they are top-level modules (no package, no __init__.py) that each import a
sibling module named `kernel`, so importing more than one into the same
interpreter would collide. Subprocess also means a failure here reproduces
byte-for-byte with the command a person would type from the README.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)

SCENARIOS = ["example_handoff.py", "example_documents.py", "test_mutations.py"]


@pytest.mark.parametrize("script", SCENARIOS)
def test_prototype_scenario(script: str) -> None:
    """Run a scenario/check script exactly as documented; fail loudly.

    Each script reports failure the same way a person running it by hand
    would see it: a non-zero exit code (see its own `if __name__ ==
    "__main__":` block). This asserts that and attaches full stdout/stderr
    to the pytest failure so CI shows what actually broke, not just a
    return code.
    """
    result = subprocess.run(
        [sys.executable, str(HERE / script), DSN],
        cwd=HERE,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(
            f"{script} exited {result.returncode} against {DSN!r}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}",
            pytrace=False,
        )
