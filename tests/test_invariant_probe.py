from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from regista._cli import cmd_invariants_probe
from regista._invariant_probe import invariant_probe_report, measure_event_rows


def _row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "actor_kind": "agent",
        "actor_metadata": {"model_lineage": "glm"},
        "on_behalf_of": None,
        "canonical_envelope": None,
        "scheme_id": "ed25519",
        "transition": "review_passed",
        "payload": {},
    }
    row.update(overrides)
    return row


def test_measurements_pass_shape_for_canonical_event() -> None:
    measured = measure_event_rows("project", [_row()])

    assert measured.event_count == 1
    assert measured.declared_lineage_event_count == 1
    assert measured.distinct_lineage_tokens == ("glm",)
    assert measured.unresolvable_lineage_tokens == ()
    assert measured.unresolvable_lineage_value_count == 0
    assert measured.ambiguous_lineage_event_count == 0
    assert measured.scheme_counts == {"ed25519": 1}
    assert measured.undeclared_agent_author_event_count == 0


def test_each_historical_defect_is_measured() -> None:
    measured = measure_event_rows(
        "project",
        [
            _row(actor_metadata=None, scheme_id="hmac-sha256"),
            _row(actor_metadata={"model_lineage": "GLM-5.2"}),
            _row(
                actor_metadata={"model_lineage": "glm"},
                on_behalf_of={
                    "principal_kind": "agent",
                    "principal_lineage": "qwen",
                },
            ),
            _row(
                transition="model_observation",
                payload={"status": "unavailable"},
            ),
        ],
    )

    assert measured.event_count == 4
    assert measured.declared_lineage_event_count == 1
    assert measured.unresolvable_lineage_tokens == ("GLM-5.2",)
    assert measured.ambiguous_lineage_event_count == 1
    assert measured.scheme_counts == {"ed25519": 3, "hmac-sha256": 1}
    assert measured.undeclared_agent_author_event_count == 3
    assert measured.model_observation_status_counts == {"unavailable": 1}


def test_v6_producer_is_measurement_source() -> None:
    envelope = json.dumps(
        {
            "version": 6,
            "producer": {
                "harness": "opencode",
                "harness_version": "1",
                "model": "glm-5.2",
                "model_lineage": "glm",
            },
        }
    ).encode()

    measured = measure_event_rows(
        "project",
        [_row(actor_metadata={"model_lineage": "qwen"}, canonical_envelope=envelope)],
    )

    assert measured.distinct_lineage_tokens == ("glm",)


def test_model_observation_uses_observed_lineage_not_actor_metadata() -> None:
    measured = measure_event_rows(
        "project",
        [
            _row(
                actor_metadata=None,
                transition="model_observation",
                payload={"status": "mismatch", "observed_model_lineage": "glm"},
            )
        ],
    )

    assert measured.declared_lineage_event_count == 1
    assert measured.undeclared_agent_author_event_count == 0


def test_empty_store_is_measured_without_inventing_coverage() -> None:
    measured = measure_event_rows("project", [])

    assert measured.to_dict()["lineage_coverage"] == {"numerator": 0, "denominator": 0}
    assert measured.scheme_counts == {}


def test_report_passes_with_measured_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "regista._invariant_probe.probe_project",
        lambda _dsn, project: measure_event_rows(project, []),
    )

    report = invariant_probe_report("postgresql://unused", ["throwaway"])

    assert report["ok"] is True
    assert report["checks"][0]["status"] == "measured"
    assert report["checks"][1]["id"] == "regista.closed_lineage_registry"
    assert report["checks"][1]["status"] == "pass"


def test_report_names_project_measurement_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import psycopg

    def fail(_dsn: str, _project: str) -> object:
        raise psycopg.OperationalError("unreachable")

    monkeypatch.setattr("regista._invariant_probe.probe_project", fail)

    report = invariant_probe_report("postgresql://unused", ["throwaway"])

    assert report["ok"] is False
    assert report["checks"][0]["status"] == "fail"
    assert report["checks"][0]["errors"] == [
        {"project": "throwaway", "error_type": "OperationalError"}
    ]


def test_cli_json_shape_and_failure_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "regista._invariant_probe.invariant_probe_report",
        lambda _dsn, _projects: {"component": "regista", "ok": False, "checks": []},
    )
    args = SimpleNamespace(
        dsn="postgresql://unused",
        project="throwaway",
        hmac_key_path=None,
        json=True,
    )

    with pytest.raises(SystemExit, match="1"):
        cmd_invariants_probe(argparse.Namespace(**vars(args)))

    assert json.loads(capsys.readouterr().out) == {
        "checks": [],
        "component": "regista",
        "ok": False,
    }
