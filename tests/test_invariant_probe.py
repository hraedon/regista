from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from regista._cli import cmd_invariants_probe
from regista._errors import ErrorCode, RegistaError
from regista._invariant_probe import (
    ENVELOPE_LINEAGE_KEY,
    ENVELOPE_PRODUCER_PRESENT_KEY,
    _envelope_producer_lineage,
    _measure_closed_registry,
    _probe_first_write_admission,
    _probe_load_bearing_fields,
    invariant_probe_report,
    measure_event_rows,
    postgres_database_fingerprint,
)


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


def test_store_fingerprint_excludes_credentials() -> None:
    left = "postgresql://alice:one@suite-db.example:5433/agent_suite?sslmode=require"
    right = "postgresql://bob:two@suite-db.example:5433/agent_suite?sslmode=disable"
    assert postgres_database_fingerprint(left) == postgres_database_fingerprint(right)
    assert postgres_database_fingerprint(left) == postgres_database_fingerprint(
        "host=suite-db.example. port=5433 dbname=agent_suite user=bob password=two"
    )
    assert postgres_database_fingerprint(left) == postgres_database_fingerprint(
        "hostaddr=suite-db.example port=5433 dbname='agent_suite'"
    )
    assert postgres_database_fingerprint(left).startswith("sha256:")  # type: ignore[union-attr]
    assert postgres_database_fingerprint("not-a-postgres-dsn") is None


def test_first_write_probe_names_identity_and_blank_field_denials() -> None:
    load_bearing_ok, load_bearing_detail = _probe_load_bearing_fields()
    first_write_ok, first_write_detail = _probe_first_write_admission()

    assert load_bearing_ok is True
    assert "whitespace-only" in load_bearing_detail
    assert first_write_ok is True
    assert "existing data" in first_write_detail


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


def _v6_envelope(lineage: object, *, version: int = 6, producer: object = None) -> bytes:
    body: dict[str, object] = {"version": version}
    body["producer"] = (
        producer if producer is not None else {"model": "m", "model_lineage": lineage}
    )
    return json.dumps(body).encode()


@pytest.mark.parametrize(
    "envelope",
    [
        _v6_envelope("qwen"),
        _v6_envelope(None),
        _v6_envelope(42),
        _v6_envelope("GLM-5.2"),
        _v6_envelope("qwen", version=5),
        _v6_envelope(None, producer="not-an-object"),
        b"{not json",
        b"\xff\xfe not utf-8",
        None,
    ],
)
def test_projected_and_raw_envelope_rows_measure_identically(envelope: object) -> None:
    """The server-side projection must not change what the measurement sees.

    ``probe_project`` extracts the v6 producer lineage in SQL so it never ships
    whole envelopes; every other caller hands over the raw bytea. If those two
    paths ever disagree, the scheduled measurement and the tests pinning it are
    measuring different things.
    """
    raw_row = _row(actor_metadata={"model_lineage": "glm"}, canonical_envelope=envelope)
    present, lineage = _envelope_producer_lineage(raw_row)
    projected_row = _row(actor_metadata={"model_lineage": "glm"})
    projected_row.pop("canonical_envelope")
    projected_row[ENVELOPE_PRODUCER_PRESENT_KEY] = present
    projected_row[ENVELOPE_LINEAGE_KEY] = lineage

    assert measure_event_rows("p", [raw_row]) == measure_event_rows("p", [projected_row])


def test_projection_keys_win_over_a_raw_envelope() -> None:
    """A row carrying both must trust the projection, not re-parse the blob."""
    row = _row(
        canonical_envelope=_v6_envelope("qwen"),
        **{ENVELOPE_PRODUCER_PRESENT_KEY: True, ENVELOPE_LINEAGE_KEY: "kimi"},
    )
    assert measure_event_rows("p", [row]).distinct_lineage_tokens == ("kimi",)


def test_closed_registry_check_measures_the_write_path() -> None:
    ok, detail = _measure_closed_registry()
    assert ok is True
    assert "canonical families accepted" in detail


def test_closed_registry_check_fails_when_ingress_admits_a_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check must be capable of going red — the tautological form was not.

    Validating the registry against itself can never fail however broken ingress
    is. Neutering the write-path validator must turn this check red.
    """
    monkeypatch.setattr(
        "regista._invariant_probe.validate_actor_metadata", lambda _metadata: None
    )
    ok, detail = _measure_closed_registry()
    assert ok is False
    assert "variants admitted" in detail


def test_closed_registry_check_fails_when_a_canonical_family_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse_everything(_metadata: object) -> None:
        raise RegistaError(ErrorCode.INVALID_MODEL_LINEAGE, "no")

    monkeypatch.setattr(
        "regista._invariant_probe.validate_actor_metadata", refuse_everything
    )
    ok, detail = _measure_closed_registry()
    assert ok is False
    assert "canonical families refused" in detail
