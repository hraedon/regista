from __future__ import annotations

import argparse
import json
import os
from types import SimpleNamespace

import pytest

from regista._cli import cmd_invariants_probe
from regista._errors import ErrorCode, RegistaError
from regista._invariant_probe import (
    ENVELOPE_LINEAGE_KEY,
    ENVELOPE_PRODUCER_PRESENT_KEY,
    _envelope_producer_lineage,
    _measure_closed_registry,
    _probe_actor_boundary_signing,
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


# ---------------------------------------------------------------------------
# WI-326 — regista.actor_boundary_signing
#
# The gate's operator contract (agent-suite Plan 023 R-10,
# docs/operating-the-suite.md) requires a BEHAVIORAL unbound-principal signing
# attempt observing the named refusal, and says in terms that "key-binding
# configuration or key-file inspection is not evidence". So the tests that matter
# here are the mutation-direction ones: if the actor-boundary comparison were
# removed from the production signing paths, this check must go red. A check that
# cannot go red is the tautology WI-285 already caught once in this same module
# (see test_closed_registry_check_fails_when_ingress_admits_a_variant).
#
# The mutations below do not re-implement _writer_key / _genesis_key. They wrap
# the real functions and swallow exactly the ACTOR_SIGNER_MISMATCH raise, which
# is the smallest faithful spelling of "the boundary was deleted" and cannot
# drift from the originals the way a copied body would.
# ---------------------------------------------------------------------------

_UNBOUND_MARKER = "regista-invariant-probe-unbound"


def _boundary_deleted(original):
    """``original`` with its actor-boundary refusal removed, nothing else changed."""
    import dataclasses

    def patched(key_set, *args, **kwargs):
        try:
            return original(key_set, *args, **kwargs)
        except RegistaError as exc:
            if exc.code is not ErrorCode.ACTOR_SIGNER_MISMATCH:
                raise
            if args and isinstance(args[0], dict):  # _genesis_key(key_set, envelope)
                envelope = args[0]
                principal = envelope["actor"]["principal_id"]
                key_id = envelope["signing"]["key_id"]
            else:  # _writer_key(key_set, *, principal_id=..., key_id=...)
                principal = kwargs["principal_id"]
                key_id = kwargs.get("key_id")
            entry = key_set.resolve_signing_key(principal, key_id=key_id)
            # Re-labelled as if it were bound, which is what a service holding one
            # keyset for every principal amounts to.
            return dataclasses.replace(entry, principal_id=principal)

    return patched


def test_actor_boundary_check_passes_and_names_the_paths_it_proved() -> None:
    ok, detail = _probe_actor_boundary_signing()

    assert ok is True
    assert ErrorCode.ACTOR_SIGNER_MISMATCH.value in detail
    assert ErrorCode.KEY_ROLE_NOT_PERMITTED.value in detail
    assert "append_v6_genesis" in detail
    assert "append_v6_event" in detail


def test_actor_boundary_report_names_the_trust_bootstrap_exclusion() -> None:
    """A green R-10 check must not imply that WI-320 is resolved."""
    report = invariant_probe_report("postgresql://example.invalid/db", [])
    check = next(
        item for item in report["checks"] if item["id"] == "regista.actor_boundary_signing"
    )

    assert check["claim"] == "r10.no_arbitrary_principal.project_v6"
    assert check["paths_proven"] == [
        "regista._genesis.append_v6_genesis",
        "regista._v6_writer.append_v6_event",
    ]
    assert check["shared_boundary_consumers"] == [
        "regista._trust_log_writer.append_trust_log_event"
    ]
    assert check["excluded_paths"] == [
        "regista._cli.cmd_trust_init_log",
        "regista._cli.cmd_trust_delegate_registrar",
        "regista._cli._resolve_trust_root_actor",
        "regista._trust_log_writer.write_trust_genesis",
    ]
    assert "WI-320" in check["exclusion_reason"]


def test_actor_boundary_check_reds_when_the_ordinary_writer_boundary_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete the boundary from the ordinary-event writer; the check must fail.

    Note what this also pins: with the boundary gone, the append is still refused
    — by key-binding anchor resolution, one layer down — but under a DIFFERENT
    name. The check asserts the *named* code precisely so that defence in depth
    cannot keep it green while the boundary rots.
    """
    import regista._v6_writer as writer

    monkeypatch.setattr(writer, "_writer_key", _boundary_deleted(writer._writer_key))

    ok, detail = _probe_actor_boundary_signing()

    assert ok is False
    assert "unbound-principal append" in detail
    assert ErrorCode.ACTOR_SIGNER_MISMATCH.value in detail


def test_actor_boundary_check_reds_when_the_genesis_boundary_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete the boundary from the genesis writer; the unbound genesis is then
    signed and written, and the check must say so rather than pass."""
    import regista._genesis as genesis

    monkeypatch.setattr(genesis, "_genesis_key", _boundary_deleted(genesis._genesis_key))

    ok, detail = _probe_actor_boundary_signing()

    assert ok is False
    assert "unbound-principal genesis was ACCEPTED" in detail


def test_actor_boundary_check_reds_when_the_keyset_would_not_have_signed_anyway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The anti-vacuity guard.

    "The unbound principal was refused" is worthless evidence if the keyset had
    no key to offer it in the first place. The check asserts up front that the
    service keyset *does* hand over its own key, so that the refusal can only be
    attributed to the actor boundary. Break that premise and the check must
    refuse to claim a pass.
    """
    import dataclasses

    from regista._keys import KeySet

    original = KeySet.resolve_signing_key

    def not_the_holder(self, actor_id, key_id=None):
        entry = original(self, actor_id, key_id=key_id)
        if _UNBOUND_MARKER in actor_id:
            return dataclasses.replace(entry, key_id="pk_probe_some_other_key")
        return entry

    monkeypatch.setattr(KeySet, "resolve_signing_key", not_the_holder)

    ok, detail = _probe_actor_boundary_signing()

    assert ok is False
    assert "did not offer its own key to an unbound principal" in detail


def test_actor_boundary_check_fails_closed_on_an_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(_principal_id: str, _role: str) -> object:
        raise RuntimeError("nacl went missing")

    monkeypatch.setattr("regista._invariant_probe._generate_boundary_key", explode)

    ok, detail = _probe_actor_boundary_signing()

    assert ok is False
    assert "RuntimeError" in detail
    assert "proved nothing" in detail


def test_actor_boundary_check_fails_closed_when_refused_by_a_regista_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regista._keys import KeySet

    def refuse(self, actor_id, key_id=None):
        raise RegistaError(ErrorCode.UNKNOWN_KEY_ID, "nothing to sign with")

    monkeypatch.setattr(KeySet, "resolve_signing_key", refuse)

    ok, detail = _probe_actor_boundary_signing()

    assert ok is False
    assert ErrorCode.UNKNOWN_KEY_ID.value in detail


def test_actor_boundary_probe_leaves_no_seed_variable_in_the_environment() -> None:
    """The probe puts its throwaway Ed25519 seeds in process env rather than on
    disk. It must take them back out again, on the success path and after a
    refusal alike."""
    before = {k for k in os.environ if k.startswith("REGISTA_INVARIANT_PROBE_SEED_")}
    assert before == set()

    _probe_actor_boundary_signing()

    assert {k for k in os.environ if k.startswith("REGISTA_INVARIANT_PROBE_SEED_")} == set()


def test_actor_boundary_check_passes_with_no_ambient_regista_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """No ambient key path, key material, store or home directory is consulted.

    Run in-process as well as in the clean-env shell run, because a probe that
    silently reads the operator's own keys is not measuring the library.
    """
    for name in [k for k in os.environ if k.startswith("REGISTA_")]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    ok, _detail = _probe_actor_boundary_signing()

    assert ok is True


def _full_report(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setattr(
        "regista._invariant_probe.probe_project",
        lambda _d, project: measure_event_rows(project, []),
    )
    return invariant_probe_report("postgresql://unused", ["throwaway"])


#: agent-suite's ``PROBE_SPECS`` entry for this component
#: (agent_suite/genesis_gate.py). Transcribed so this assertion still runs where
#: the sibling checkout is absent; the subprocess test in
#: tests/test_wi326_probe_gate_contract.py feeds real CLI output through the real
#: validator when it is present.
_GATE_REQUIRED_CHECK_IDS = frozenset(
    {
        "regista.store_invariant_measurements",
        "regista.load_bearing_fields_refused",
        "regista.closed_lineage_registry",
        "regista.first_write_admission",
        "regista.actor_boundary_signing",
    }
)


def test_report_emits_every_gate_required_check_id(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _full_report(monkeypatch)
    ids = [check["id"] for check in report["checks"]]

    assert set(ids) >= _GATE_REQUIRED_CHECK_IDS
    assert len(ids) == len(set(ids))
    assert all(check_id.startswith("regista.") for check_id in ids)
    assert report["probe_version"] == 1
    assert report["ok"] is True


def test_actor_boundary_check_is_a_pass_not_a_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only ``store_invariant_measurements`` may use ``measured``; the gate
    requires literal ``pass`` for every other required check."""
    report = _full_report(monkeypatch)
    by_id = {check["id"]: check for check in report["checks"]}

    assert by_id["regista.actor_boundary_signing"]["status"] == "pass"
    assert by_id["regista.actor_boundary_signing"]["basis"] == (
        "behavioral_attempt_ephemeral_epoch"
    )
    assert by_id["regista.store_invariant_measurements"]["status"] == "measured"


def test_a_failing_boundary_check_fails_the_whole_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "regista._invariant_probe._probe_actor_boundary_signing",
        lambda: (False, "simulated boundary failure"),
    )
    report = _full_report(monkeypatch)
    by_id = {check["id"]: check for check in report["checks"]}

    assert report["ok"] is False
    assert by_id["regista.actor_boundary_signing"]["status"] == "fail"
