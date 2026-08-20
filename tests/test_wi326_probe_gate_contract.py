"""WI-326 — the probe's output, as the genesis gate actually consumes it.

``tests/test_invariant_probe.py`` proves the behavioral content of
``regista.actor_boundary_signing`` in-process. This module proves the *delivery*:
that the real console script, run as a subprocess against a real Postgres
project, emits stdout that agent-suite's real validator accepts, and that running
it leaves the target project untouched.

Three things are only observable at this level and each has an assertion below:

1. **stdout is exactly one JSON object.** The gate does ``json.loads`` on the
   whole of stdout. Any log line, warning or second document makes the report
   ``MALFORMED``, and the actor-boundary check loads a ``KeySet`` — which logs —
   so this is a live hazard, not a hypothetical one.
2. **Exit code and ``ok`` agree.** ``_parse_probe_result`` checks
   ``(returncode == 0) == body["ok"]`` and calls a disagreement ERROR.
3. **The probe writes nothing to the store it was pointed at.** The
   actor-boundary check has to *write* to prove a signing boundary; it does that
   against an ephemeral in-memory epoch. This asserts the separation held, by
   counting the target project's rows either side of the run.

The validator is imported from the sibling checkout when it is present rather
than transcribed, because a transcription is a second copy of the contract that
can drift. When it is absent the test skips and
``test_invariant_probe.py::test_report_emits_every_gate_required_check_id``
carries the transcribed form.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from _helpers import DSN, KEY_PATH

#: The sibling checkout holding the gate validator this probe feeds.
AGENT_SUITE_SRC = Path("/projects/agent-suite/src")

#: The exact argv ``agent_suite.genesis_gate.PROBE_SPECS`` runs for this component.
PROBE_COMMAND = ("regista", "invariants", "probe", "--json")


@pytest.fixture(scope="module")
def probe_project():
    """A real, empty project schema for the probe to measure."""
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"wi326_{uuid.uuid4().hex[:8]}"
    instance = Regista.create_project(DSN, project, KEY_PATH)
    try:
        yield project
    finally:
        instance.close()
        drop_project_schema(DSN, project)


def _event_count(project: str) -> int:
    with psycopg.connect(DSN, connect_timeout=5) as conn:
        row = conn.execute(f'SELECT COUNT(*) FROM "{project}".events').fetchone()
    assert row is not None
    return int(row[0])


def _run_probe(project: str) -> subprocess.CompletedProcess[str]:
    """Run the console script the way the gate's default runner does.

    Every ambient ``REGISTA_*`` variable is dropped first. The operator's own DSN
    and key path must not leak into a measurement of a throwaway project, and a
    probe that quietly picked them up would be reporting on the wrong store.
    """
    executable = shutil.which(PROBE_COMMAND[0])
    if executable is None:
        pytest.skip(f"{PROBE_COMMAND[0]!r} console script is not on PATH")
    env = {k: v for k, v in os.environ.items() if not k.startswith("REGISTA_")}
    env["REGISTA_DSN"] = DSN
    env["REGISTA_PROJECT"] = project
    return subprocess.run(
        (executable, *PROBE_COMMAND[1:]),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )


def test_probe_stdout_is_exactly_one_json_object_and_agrees_with_its_exit_code(
    probe_project: str,
) -> None:
    completed = _run_probe(probe_project)

    body = json.loads(completed.stdout)  # the gate's own parse: whole stdout, one object
    assert isinstance(body, dict)
    assert body["component"] == "regista"
    assert body["probe_version"] == 1
    assert (completed.returncode == 0) == body["ok"], completed.stderr[-2000:]
    assert body["ok"] is True, json.dumps(body["checks"], indent=2)


def test_probe_emits_a_passing_actor_boundary_check_over_the_cli(
    probe_project: str,
) -> None:
    body = json.loads(_run_probe(probe_project).stdout)
    by_id = {check["id"]: check for check in body["checks"]}

    check = by_id["regista.actor_boundary_signing"]
    assert check["status"] == "pass"
    assert check["basis"] == "behavioral_attempt_ephemeral_epoch"
    assert check["paths_proven"] == [
        "regista._genesis.append_v6_genesis",
        "regista._v6_writer.append_v6_event",
    ]


def test_running_the_probe_writes_nothing_to_the_project_it_measured(
    probe_project: str,
) -> None:
    """The actor-boundary check signs real events — into an in-memory epoch only."""
    before = _event_count(probe_project)

    completed = _run_probe(probe_project)
    assert completed.returncode == 0, completed.stderr[-2000:]

    assert _event_count(probe_project) == before == 0


def _genesis_gate_module():
    """agent-suite's gate validator, or ``None`` when the checkout is absent.

    Loaded by path rather than by installing the sibling package: the module
    imports only the standard library, and regista must not acquire a build-time
    dependency on the umbrella to test the report shape it owes it.
    """
    if not (AGENT_SUITE_SRC / "agent_suite" / "genesis_gate.py").is_file():
        return None
    if str(AGENT_SUITE_SRC) not in sys.path:
        sys.path.insert(0, str(AGENT_SUITE_SRC))
    if importlib.util.find_spec("agent_suite.genesis_gate") is None:
        return None
    import agent_suite.genesis_gate as genesis_gate

    return genesis_gate


def test_real_cli_output_satisfies_the_real_suite_validator(probe_project: str) -> None:
    """End to end: real subprocess output through agent-suite's own parser.

    ``_parse_probe_result`` is what stands between this probe and the gate. It
    checks the component name, ``probe_version``, unique namespaced check IDS, the
    closed status vocabulary, the required-check set (which since WI-074 includes
    ``regista.actor_boundary_signing``), the per-check required success status,
    and exit-code/body agreement. Reproducing any of that here would be a second
    copy of someone else's contract, so the real thing is called instead.
    """
    genesis_gate = _genesis_gate_module()
    if genesis_gate is None:
        pytest.skip(f"agent-suite checkout not present at {AGENT_SUITE_SRC}")

    spec = next(s for s in genesis_gate.PROBE_SPECS if s.component == "regista")
    assert "regista.actor_boundary_signing" in spec.required_checks
    assert spec.command == PROBE_COMMAND

    result = genesis_gate._parse_probe_result(spec, _run_probe(probe_project))

    assert result.status is genesis_gate.ProbeStatus.PASS, result.detail
