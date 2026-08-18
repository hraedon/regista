from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest
from _helpers import DSN
from nacl.signing import SigningKey

from regista import Regista, V6GenesisWrite
from regista._errors import ErrorCode, RegistaError
from regista._event_store import InMemoryEventStore
from regista._genesis import (
    admit_legacy_append,
    check_legacy_append,
    first_write_admission,
    validate_load_bearing_fields,
)
from regista._invariant_probe import invariant_probe_report, probe_project
from regista._replay import _event_head_hash
from regista._signing import compute_v6_event_hash, sign_v6_envelope
from regista._testing import raw_transaction

_VECTOR = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"


def _envelope(public_key: bytes) -> dict[str, Any]:
    case = json.loads(_VECTOR.read_text(encoding="utf-8"))
    envelope = cast(
        dict[str, Any],
        copy.deepcopy(case["input"]["envelope_declaration_order"]),
    )
    project_instance_id = str(uuid.uuid4())
    envelope["project_instance_id"] = project_instance_id
    envelope["entity"]["id"] = project_instance_id
    envelope["event_id"] = str(uuid.uuid4())
    envelope["trust_domain_id"] = str(uuid.uuid4())
    principal_id = "agent:genesis-probe"
    envelope["actor"]["principal_id"] = principal_id
    envelope["signing"]["key_id"] = "pk-genesis"
    acceptance = envelope["payload"]["bootstrap_key_acceptance"]
    acceptance["principal_id"] = principal_id
    acceptance["key_id"] = "pk-genesis"
    acceptance["scheme_id"] = "ed25519"
    acceptance["public_key"] = base64.b64encode(public_key).decode("ascii")
    acceptance["fingerprint"] = "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()
    acceptance["scopes"] = {
        "entity_kinds": ["project", "principal", "workflow", "work_item"],
        "transitions": None,
        "may_accept_keys": True,
        "may_sign_checkpoints": True,
        "may_sign_bundles": False,
    }
    return envelope


def _key_file(path: Path) -> bytes:
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key)
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "pk-genesis",
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": base64.b64encode(bytes(signing_key)).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(public_key).decode("ascii"),
                        "principal_id": "agent:genesis-probe",
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        )
    )
    return public_key


def _hmac_key_file(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "pk-genesis",
                        "scheme": "hmac-sha256",
                        "secret": base64.b64encode(b"genesis-hmac").decode("ascii"),
                        "encoding": "base64",
                        "principal_id": "agent:genesis-probe",
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        )
    )


def test_load_bearing_fields_are_named_and_fail_closed() -> None:
    envelope = _envelope(b"\0" * 32)
    del envelope["producer"]["harness"]
    with pytest.raises(RegistaError) as exc_info:
        validate_load_bearing_fields(envelope)
    assert exc_info.value.code is ErrorCode.LOAD_BEARING_FIELD_MISSING
    assert exc_info.value.detail == {"fields": ["producer.harness"]}


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        (
            {"gate_passed": False, "event_count": 0, "head_hash": None},
            ErrorCode.GENESIS_GATE_NOT_PASSED,
        ),
        (
            {"gate_passed": True, "event_count": 1, "head_hash": None},
            ErrorCode.GENESIS_ALREADY_WRITTEN,
        ),
        (
            {"gate_passed": True, "event_count": 0, "head_hash": b"head"},
            ErrorCode.GENESIS_ALREADY_WRITTEN,
        ),
        (
            {
                "gate_passed": True,
                "event_count": 0,
                "head_hash": None,
                "identity_present": True,
            },
            ErrorCode.GENESIS_ALREADY_WRITTEN,
        ),
    ],
)
def test_first_write_admission_has_named_denials(
    kwargs: dict[str, Any], code: ErrorCode,
) -> None:
    with pytest.raises(RegistaError) as exc_info:
        first_write_admission(transition="project_initialized", **kwargs)
    assert exc_info.value.code is code


def test_genesis_denies_incomplete_and_mismatched_bootstrap_data(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_denials_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(DSN, project, str(key_path), strict_asymmetric=True)
    try:
        incomplete = _envelope(public_key)
        del incomplete["producer"]["harness"]
        with pytest.raises(RegistaError) as missing:
            regista.write_genesis(incomplete, gate_passed=True)
        assert missing.value.code is ErrorCode.LOAD_BEARING_FIELD_MISSING

        principal_mismatch = _envelope(public_key)
        principal_mismatch["payload"]["bootstrap_key_acceptance"][
            "principal_id"
        ] = "agent:other"
        with pytest.raises(RegistaError) as principal:
            regista.write_genesis(principal_mismatch, gate_passed=True)
        assert principal.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH

        key_mismatch = _envelope(public_key)
        key_mismatch["payload"]["bootstrap_key_acceptance"]["public_key"] = (
            base64.b64encode(b"\x01" * 32).decode("ascii")
        )
        with pytest.raises(RegistaError) as key:
            regista.write_genesis(key_mismatch, gate_passed=True)
        assert key.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH

        entity_scope_mismatch = _envelope(public_key)
        entity_scope_mismatch["payload"]["bootstrap_key_acceptance"]["scopes"][
            "entity_kinds"
        ] = ["work_item"]
        with pytest.raises(RegistaError) as entity_scope:
            regista.write_genesis(entity_scope_mismatch, gate_passed=True)
        assert entity_scope.value.code is ErrorCode.GENESIS_INVALID

        transition_scope_mismatch = _envelope(public_key)
        transition_scope_mismatch["payload"]["bootstrap_key_acceptance"]["scopes"][
            "transitions"
        ] = ["principal_registered"]
        with pytest.raises(RegistaError) as transition_scope:
            regista.write_genesis(transition_scope_mismatch, gate_passed=True)
        assert transition_scope.value.code is ErrorCode.GENESIS_INVALID

        written = regista.write_genesis(_envelope(public_key), gate_passed=True)
        assert written.event_id
    finally:
        regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)


def test_v6_genesis_uses_the_v6_chain_hash_domain(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    key_data = json.loads(key_path.read_text())
    private_key = base64.b64decode(key_data["keys"][0]["secret"])
    signed = sign_v6_envelope(_envelope(public_key), private_key)

    assert _event_head_hash(
        {
            "canonical_envelope": signed.canonical_envelope,
            "signature": signed.signature,
        }
    ) == compute_v6_event_hash(signed.canonical_envelope, signed.signature)


def test_in_memory_legacy_writer_fails_closed() -> None:
    store = InMemoryEventStore()

    with pytest.raises(RegistaError) as preflight:
        store.check_legacy_append()
    assert preflight.value.code is ErrorCode.GENESIS_REQUIRED

    with pytest.raises(RegistaError) as admission:
        store.admit_legacy_append()
    assert admission.value.code is ErrorCode.GENESIS_REQUIRED


def test_genesis_rejects_non_actor_and_hmac_keys(tmp_path: Path) -> None:
    key_path = tmp_path / "auditor-keys.json"
    public_key = _key_file(key_path)
    data = json.loads(key_path.read_text())
    data["keys"][0]["role"] = "auditor"
    key_path.write_text(json.dumps(data))
    project = "test_genesis_role_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(DSN, project, str(key_path))
    try:
        with pytest.raises(RegistaError) as role:
            regista.write_genesis(_envelope(public_key), gate_passed=True)
        assert role.value.code is ErrorCode.KEY_ROLE_NOT_PERMITTED
    finally:
        regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)

    hmac_path = tmp_path / "hmac-keys.json"
    _hmac_key_file(hmac_path)
    hmac_project = "test_genesis_hmac_" + uuid.uuid4().hex[:10]
    hmac_regista = Regista.create_project(DSN, hmac_project, str(hmac_path))
    try:
        with pytest.raises(RegistaError) as hmac_error:
            hmac_regista.write_genesis(_envelope(b"\0" * 32), gate_passed=True)
        assert hmac_error.value.code is ErrorCode.GENESIS_INVALID
    finally:
        hmac_regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, hmac_project)


def test_postgres_genesis_is_single_and_recoverable(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(
        DSN,
        project,
        str(key_path),
        strict_asymmetric=True,
    )
    try:
        measurement = probe_project(DSN, project)
        assert measurement.event_count == 0
        assert measurement.snapshot_id.startswith("pg:")
        report = invariant_probe_report(DSN, [project])
        assert report["ok"] is True
        measurement_check = report["checks"][0]
        assert measurement_check["store_fingerprint"].startswith("sha256:")
        assert measurement_check["projects"][0]["snapshot_id"].startswith("pg:")
        with pytest.raises(RegistaError) as before:
            regista.append_event(uuid.uuid4(), "agent:genesis-probe")
        assert before.value.code is ErrorCode.GENESIS_REQUIRED
        written = regista.write_genesis(_envelope(public_key), gate_passed=True)
        recovered = regista.read_genesis()
        assert recovered is not None
        assert recovered.event_hash == written.event_hash
        assert recovered.project_instance_id == written.project_instance_id

        # Post-genesis the ordinary API is no longer the legacy writer: it routes to
        # `_v6_writer.append_v6_event`, so it gets PAST the epoch door and is then
        # refused by the v6 path's own contract check — this work item does not
        # exist. Asserting V6_EPOCH_OPEN here would now be asserting that P1.7's
        # wiring is absent.
        with pytest.raises(RegistaError) as routed:
            regista.append_event(uuid.uuid4(), "agent:genesis-probe")
        assert routed.value.code is ErrorCode.WORK_ITEM_NOT_FOUND

        # The invariant this test has always been about — a LEGACY writer cannot
        # extend the opened epoch (EPOCH-RESET.md §5.1) — is now pinned at the place
        # that enforces it, rather than through an ordinary-API call whose meaning
        # changed underneath it. Both doors: the check and the admit.
        with regista._mgr.transaction() as conn:
            with pytest.raises(RegistaError) as legacy_check:
                check_legacy_append(conn, writer="test.legacy_probe")
            assert legacy_check.value.code is ErrorCode.V6_EPOCH_OPEN
            with pytest.raises(RegistaError) as legacy_admit:
                admit_legacy_append(conn, writer="test.legacy_probe")
            assert legacy_admit.value.code is ErrorCode.V6_EPOCH_OPEN

        with pytest.raises(RegistaError) as second:
            regista.write_genesis(_envelope(public_key), gate_passed=True)
        assert second.value.code is ErrorCode.GENESIS_ALREADY_WRITTEN
    finally:
        regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)


@pytest.mark.parametrize("status", ["deprecated", "revoked"])
def test_genesis_recovery_uses_historical_key_material(
    tmp_path: Path, status: str,
) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_recovery_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(
        DSN,
        project,
        str(key_path),
        strict_asymmetric=True,
    )
    try:
        written = regista.write_genesis(_envelope(public_key), gate_passed=True)
    finally:
        regista.close()

    key_data = json.loads(key_path.read_text())
    key_data["keys"][0]["status"] = status
    # Recovery must not reuse the new-genesis actor-role policy either.
    key_data["keys"][0]["role"] = "auditor"
    key_path.write_text(json.dumps(key_data))
    recovered_regista = Regista(
        DSN,
        project,
        str(key_path),
        strict_asymmetric=True,
    )
    try:
        recovered = recovered_regista.read_genesis()
        assert recovered is not None
        assert recovered.event_hash == written.event_hash
    finally:
        recovered_regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)


def test_genesis_recovery_reads_an_archived_genesis_event(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_archive_" + uuid.uuid4().hex[:10]
    regista = Regista.create_project(
        DSN,
        project,
        str(key_path),
        strict_asymmetric=True,
    )
    try:
        written = regista.write_genesis(_envelope(public_key), gate_passed=True)
        with raw_transaction(regista) as conn:
            conn.execute(
                "INSERT INTO events_archive SELECT * FROM events WHERE event_id = %s",
                [written.event_id],
            )
            conn.execute("DELETE FROM events WHERE event_id = %s", [written.event_id])

        recovered = regista.read_genesis()
        assert recovered is not None
        assert recovered.source == "events_archive"
        assert recovered.event_hash == written.event_hash
    finally:
        regista.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)


def test_concurrent_genesis_has_one_winner(tmp_path: Path) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_race_" + uuid.uuid4().hex[:10]
    owner = Regista.create_project(DSN, project, str(key_path), strict_asymmetric=True)
    contender = Regista(DSN, project, str(key_path), strict_asymmetric=True)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(regista.write_genesis, _envelope(public_key), gate_passed=True)
                for regista in (owner, contender)
            ]
            outcomes: list[object] = []
            for future in futures:
                try:
                    outcomes.append(future.result())
                except RegistaError as error:
                    outcomes.append(error)
        assert sum(isinstance(outcome, V6GenesisWrite) for outcome in outcomes) == 1
        errors = [outcome for outcome in outcomes if isinstance(outcome, RegistaError)]
        assert len(errors) == 1
        assert errors[0].code is ErrorCode.GENESIS_ALREADY_WRITTEN
    finally:
        owner.close()
        contender.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)


def test_genesis_and_legacy_admission_cannot_both_cross_the_boundary(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "keys.json"
    public_key = _key_file(key_path)
    project = "test_genesis_legacy_race_" + uuid.uuid4().hex[:10]
    owner = Regista.create_project(DSN, project, str(key_path), strict_asymmetric=True)
    contender = Regista(DSN, project, str(key_path), strict_asymmetric=True)
    barrier = threading.Barrier(2)

    def legacy_attempt() -> object:
        try:
            with contender._mgr.transaction() as conn:
                barrier.wait()
                return admit_legacy_append(conn, writer="test.legacy")
        except RegistaError as error:
            return error

    def genesis_attempt() -> object:
        barrier.wait()
        try:
            return owner.write_genesis(_envelope(public_key), gate_passed=True)
        except RegistaError as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            legacy_future = pool.submit(legacy_attempt)
            genesis_future = pool.submit(genesis_attempt)
            legacy_result = legacy_future.result()
            genesis_result = genesis_future.result()

        assert isinstance(genesis_result, V6GenesisWrite)
        assert isinstance(legacy_result, RegistaError)
        assert legacy_result.code in {
            ErrorCode.GENESIS_REQUIRED,
            ErrorCode.V6_EPOCH_OPEN,
        }
    finally:
        owner.close()
        contender.close()
        from regista.testing import drop_project_schema

        drop_project_schema(DSN, project)
