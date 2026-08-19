"""WI-303: the projection rebuild consumes only authority-verified trust-log events.

Chains are built by the WI-301 writer (so they are WI-303-valid by construction); the
rebuild's job is to refuse anything that is not verifiable and stage-and-replace only
after full verification.
"""

from __future__ import annotations

import base64
import json
import uuid

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_genesis

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._trust_log_writer import (
    append_trust_log_event,
    build_trust_domain_established_payload,
    chain_order,
    read_trust_log_rows,
    write_trust_genesis,
)
from regista._trust_projection import check_projection_consistent, rebuild_projection
from regista.testing import drop_project_schema, seed_legacy_principal_key
from tests._trust_log_fixtures import (
    TrustLogKey,
    make_enrollment_payload,
    make_possession_challenge,
    make_registrar_delegation_payload,
    make_rotation_payload,
    persist_consumed_possession_challenge,
)

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT = "service:root-a"
REGISTRAR = "service:registrar-1"


@pytest.fixture(autouse=True)
def _producer_env():
    import os

    os.environ.setdefault("REGISTA_PRODUCER_HARNESS", "pytest")
    os.environ.setdefault("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL", "test-fixture")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


def _fingerprint(pk: bytes) -> str:
    from regista._principal_keys import _compute_fingerprint

    return _compute_fingerprint(pk, "ed25519")


def _tlogkey(key_id: str, seed: bytes) -> TrustLogKey:
    sk = nacl.signing.SigningKey(seed)
    return TrustLogKey(
        key_id=key_id,
        seed=seed,
        public_key=bytes(sk.verify_key),
        fingerprint=_fingerprint(bytes(sk.verify_key)),
    )


def _signed_genesis_payload(fixture):
    from regista._trust_log import root_signature_input

    payload = build_trust_domain_established_payload(fixture.document)
    message = root_signature_input(payload)
    signer_id = fixture.signer_ids[0]
    sig = nacl.signing.SigningKey(fixture.seeds[signer_id]).sign(message).signature
    payload["root_signatures"] = [
        {
            "signer_id": signer_id,
            "fingerprint": fixture.fingerprints[signer_id],
            "signature": base64.b64encode(sig).decode("ascii"),
        }
    ]
    return payload


def _wkey(path, entries):
    payload = {"keys": []}
    for pid, seed in entries.items():
        sk = nacl.signing.SigningKey(seed)
        key_id = {
            ROOT: "k_root-a",
            REGISTRAR: "k_registrar",
        }.get(pid, "k_" + uuid.uuid4().hex[:8])
        payload["keys"].append(
            {
                "key_id": key_id,
                "scheme": "ed25519",
                "alg": "Ed25519",
                "secret": base64.b64encode(seed).decode("ascii"),
                "encoding": "base64",
                "public_key": base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
                "principal_id": pid,
                "role": "actor",
                "status": "active",
            }
        )
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _env(tmp_path):
    fixture = mint_genesis(
        threshold=1, signer_count=2, seeds=[bytes([i]) * 32 for i in range(1, 3)]
    )
    registrar = _tlogkey("k_registrar", bytes([9]) * 32)
    key_file = _wkey(
        tmp_path / "keys.json",
        {
            ROOT: fixture.seeds[fixture.signer_ids[0]],
            REGISTRAR: bytes([9]) * 32,
        },
    )
    project = f"wi303_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, hmac_key_path=key_file)
    return fixture, handle, key_file, project, registrar


def _close(handle, project):
    handle.close()
    drop_project_schema(DSN, project)


def test_genesis_file_loaders_return_none_only_when_path_is_absent(tmp_path, monkeypatch):
    from regista._cli import _load_genesis_document
    from regista._doctor import _operator_genesis_document

    monkeypatch.delenv("REGISTRA_TRUST_GENESIS_PATH", raising=False)
    assert _operator_genesis_document() is None
    assert _load_genesis_document(None) is None

    missing = tmp_path / "missing.json"
    with pytest.raises(RegistaError) as exc_info:
        _load_genesis_document(str(missing))
    assert exc_info.value.code is ErrorCode.TRUST_GENESIS_SCHEMA_INVALID
    assert exc_info.value.detail["reason"] == "genesis_file_not_found"

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    with pytest.raises(RegistaError) as exc_info:
        _load_genesis_document(str(malformed))
    assert exc_info.value.detail["reason"] == "genesis_file_invalid_json"

    non_object = tmp_path / "array.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(RegistaError) as exc_info:
        _load_genesis_document(str(non_object))
    assert exc_info.value.detail["reason"] == "genesis_document_not_object"

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(RegistaError) as exc_info:
        _load_genesis_document(str(directory))
    assert exc_info.value.detail["reason"] == "genesis_path_not_file"


def test_doctor_reports_configured_bad_genesis_before_empty_log_check(tmp_path, monkeypatch):
    from regista._doctor import _check_projection_consistent

    configured = tmp_path / "missing.json"
    monkeypatch.setenv("REGISTRA_TRUST_GENESIS_PATH", str(configured))
    check = _check_projection_consistent(
        "postgresql://unused", "doctor_genesis_invalid", require_ssl=False
    )
    assert check.status == "fail"
    assert "TRUST_GENESIS_SCHEMA_INVALID" in check.detail
    assert "genesis_file_not_found" in check.detail


def test_doctor_skips_empty_trust_log_with_valid_configured_genesis(tmp_path, monkeypatch):
    from regista._doctor import _check_projection_consistent

    fixture, handle, _key_file, project, _registrar = _env(tmp_path)
    configured = tmp_path / "trust-genesis.json"
    configured.write_text(json.dumps(fixture.document), encoding="utf-8")
    monkeypatch.setenv("REGISTRA_TRUST_GENESIS_PATH", str(configured))
    try:
        check = _check_projection_consistent(DSN, project, require_ssl=False)
        assert check.status == "skip"
        assert "no stored events" in check.detail
    finally:
        _close(handle, project)


def _delegate(handle, fixture, registrar):
    payload = make_registrar_delegation_payload(
        trust_domain_id=fixture.trust_domain_id,
        registrar_principal_id=REGISTRAR,
        key=registrar,
        max_operations=100,
        root_keys=[_tlogkey("k_root", fixture.seeds[fixture.signer_ids[0]])],
        not_before="2026-01-01T00:00:00.000000Z",
        not_after="2027-01-01T00:00:00.000000Z",
    )
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="registrar_delegated",
        payload=payload,
        entity_kind="trust_domain",
        entity_id=uuid.UUID(fixture.trust_domain_id),
        principal_id=ROOT,
        authority="root",
    )


def _delegated_hash(handle):
    from regista._trust_log_writer import _row_event_hash

    with handle._mgr.transaction() as conn:
        order = chain_order(read_trust_log_rows(conn))
    for row in order:
        if str(row["transition"]) == "registrar_delegated":
            return _row_event_hash(row)
    raise AssertionError("no delegation")


def _enrollment_material(
    handle,
    fixture,
    *,
    principal="agent:alice",
    delegation_hash,
    key=None,
    authorized_by=None,
):
    key = key or TrustLogKey.mint(f"pk_{uuid.uuid4().hex[:8]}")
    challenge = make_possession_challenge(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        fingerprint=key.fingerprint,
        project=handle._mgr.project,
    )
    payload = make_enrollment_payload(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        key=key,
        authorized_by=authorized_by
        or {
            "authority": "registrar",
            "principal_id": REGISTRAR,
            "key_id": "k_registrar",
            "delegation_event_hash": delegation_hash,
        },
        challenge=challenge,
    )
    return payload, challenge


def _enroll(
    handle,
    fixture,
    *,
    principal="agent:alice",
    delegation_hash,
    key=None,
    authorized_by=None,
):
    payload, challenge = _enrollment_material(
        handle,
        fixture,
        principal=principal,
        delegation_hash=delegation_hash,
        key=key,
        authorized_by=authorized_by,
    )
    with handle._mgr.transaction() as conn:
        persist_consumed_possession_challenge(
            conn,
            challenge,
            payload["possession_proof"]["signature"],
        )
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="principal_key_enrolled",
        payload=payload,
        entity_kind="principal",
        entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal),
        principal_id=REGISTRAR,
        authority="registrar",
    )


def _rotation_material(
    handle,
    fixture,
    *,
    principal,
    key,
    supersedes_key_id,
    superseded_key=None,
    mode="dual",
    recovery_reason=None,
    root_keys=None,
    delegation_hash=None,
    authorized_by=None,
):
    challenge = make_possession_challenge(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        fingerprint=key.fingerprint,
        project=handle._mgr.project,
    )
    payload = make_rotation_payload(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        key=key,
        supersedes_key_id=supersedes_key_id,
        superseded_key=superseded_key,
        mode=mode,
        recovery_reason=recovery_reason,
        root_keys=root_keys,
        authorized_by=authorized_by
        or {
            "authority": "registrar",
            "principal_id": REGISTRAR,
            "key_id": "k_registrar",
            "delegation_event_hash": delegation_hash,
        },
        challenge=challenge,
    )
    return payload, challenge


def _persist_challenge(handle, challenge, payload, *, used=True):
    with handle._mgr.transaction() as conn:
        persist_consumed_possession_challenge(
            conn,
            challenge,
            payload["possession_proof"]["signature"],
            used=used,
        )


def _append_rotation(handle, fixture, *, principal, payload, authority, actor_id):
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="principal_key_rotated",
        payload=payload,
        entity_kind="principal",
        entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal),
        principal_id=actor_id,
        authority=authority,
    )


class TestVerifiedRebuild:
    def test_one_valid_enrollment_rebuilds(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture), root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            dhash = _delegated_hash(handle)
            _enroll(handle, fixture, principal="agent:alice", delegation_hash=dhash)

            report = rebuild_projection(
                handle._mgr, project=project, genesis_document=fixture.document
            )
            assert report.events_replayed == 1
            assert report.applied is True

            with handle._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT principal_id, source_event_hash, acceptance_event_hash "
                    "FROM principal_keys WHERE source_event_hash IS NOT NULL"
                ).fetchall()
            assert len(rows) == 1
            assert rows[0]["principal_id"] == "agent:alice"
            assert rows[0]["source_event_hash"].startswith("sha256:")
        finally:
            _close(handle, project)

    def test_dry_run_verifies_without_mutation(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture), root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(handle, fixture, delegation_hash=_delegated_hash(handle))
            report = rebuild_projection(
                handle._mgr, project=project, genesis_document=fixture.document, dry_run=True
            )
            assert report.applied is False
            with handle._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT COUNT(*) AS n FROM principal_keys WHERE source_event_hash IS NOT NULL"
                ).fetchone()
            assert int(rows["n"]) == 0
        finally:
            _close(handle, project)

    def test_missing_genesis_is_allowed_only_for_an_empty_trust_log(self, tmp_path):
        fixture, handle, _kf, project, _registrar = _env(tmp_path)
        try:
            empty = rebuild_projection(
                handle._mgr, project=project, genesis_document=None, dry_run=True
            )
            assert empty.consistent is True
            assert empty.events_replayed == 0

            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection(handle._mgr, project=project, genesis_document=None)
            assert exc_info.value.detail["reason"] == "genesis_document_required"
        finally:
            _close(handle, project)

    def test_missing_verified_chain_cannot_empty_a_populated_projection(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(handle, fixture, delegation_hash=_delegated_hash(handle))
            rebuild_projection(
                handle._mgr, project=project, genesis_document=fixture.document
            )
            with handle._mgr.transaction() as conn:
                conn.execute("DELETE FROM events")
                conn.execute("DELETE FROM events_archive")

            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection(handle._mgr, project=project, genesis_document=None)
            assert exc_info.value.detail["reason"] == "verified_lifecycle_evidence_missing"
            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM principal_keys "
                    "WHERE source_event_hash IS NOT NULL"
                ).fetchone()
            assert int(row["n"]) == 1
        finally:
            _close(handle, project)

    def test_doctor_refuses_nonempty_trust_log_without_pinned_genesis(
        self, tmp_path, monkeypatch
    ):
        from regista._doctor import _check_projection_consistent

        fixture, handle, _kf, project, _registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            monkeypatch.delenv("REGISTRA_TRUST_GENESIS_PATH", raising=False)
            check = _check_projection_consistent(DSN, project, require_ssl=False)
            assert check.status == "fail"
            assert "unverifiable" in check.detail
        finally:
            _close(handle, project)

    def test_archived_genesis_and_lifecycle_events_still_rebuild(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            enrollment = _enroll(handle, fixture, delegation_hash=_delegated_hash(handle))

            with handle._mgr.transaction() as conn:
                conn.execute("INSERT INTO events_archive SELECT * FROM events")
                conn.execute("DELETE FROM events")

            report = rebuild_projection(
                handle._mgr, project=project, genesis_document=fixture.document
            )
            assert report.events_replayed == 1
            assert report.rows_rebuilt == 1
            assert [difference.kind for difference in report.differences] == ["only_rebuilt"]
            check = rebuild_projection(
                handle._mgr,
                project=project,
                genesis_document=fixture.document,
                dry_run=True,
            )
            assert check.consistent is True
            assert enrollment
        finally:
            _close(handle, project)

    def test_legacy_primary_key_collision_is_reported_before_apply(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        principal = "agent:legacy-collision"
        key = TrustLogKey.mint("pk_legacy_collision")
        try:
            seed_legacy_principal_key(
                handle._mgr,
                principal,
                key.public_key,
                "ed25519",
                key_id=key.key_id,
            )
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=_delegated_hash(handle),
                key=key,
            )

            dry_run = rebuild_projection(
                handle._mgr,
                project=project,
                genesis_document=fixture.document,
                dry_run=True,
            )
            assert dry_run.consistent is False
            assert [d.kind for d in dry_run.differences] == ["legacy_v6_pk_collision"]

            with pytest.raises(RegistaError) as exc_info:
                rebuild_projection(
                    handle._mgr, project=project, genesis_document=fixture.document
                )
            assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED
            assert exc_info.value.detail["reason"] == "legacy_v6_primary_key_collision"

            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT source_event_hash FROM principal_keys "
                    "WHERE principal_id = %s AND key_id = %s",
                    [principal, key.key_id],
                ).fetchone()
            assert row is not None and row["source_event_hash"] is None
        finally:
            _close(handle, project)

    def test_forged_row_halts_and_leaves_projection_unchanged(self, tmp_path):

        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture), root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            dhash = _delegated_hash(handle)
            _enroll(handle, fixture, principal="agent:alice", delegation_hash=dhash)
            rebuild_projection(handle._mgr, project=project, genesis_document=fixture.document)

            with handle._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT canonical_envelope, signature, event_seq FROM events "
                    "WHERE transition = 'principal_key_enrolled'"
                ).fetchall()
                victim_env = bytes(rows[0]["canonical_envelope"])
                victim_sig = bytes(rows[0]["signature"])
                forged = bytearray(victim_env)
                forged[-2] ^= 0x01
                import hashlib as _hl

                forged_pch = _hl.sha256(bytes(forged)).hexdigest()
                conn.execute(
                    "INSERT INTO events (event_id, work_item_id, entity_kind, entity_id, "
                    "hash_alg, event_seq, actor_id, actor_kind, actor_metadata, key_id, "
                    "workflow_name, workflow_version, timestamp, transition, payload, "
                    "payload_canonical_hash, signature, canonical_envelope, on_behalf_of, "
                    "scheme_id, prev_event_hash, prev_global_event_hash) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    [
                        uuid.uuid4(), uuid.uuid4(), "principal", uuid.uuid4(), "sha-256",
                        99, "agent:evil", "agent", None, "k_evil", None, None,
                        "2026-06-01T00:00:00.000000Z", "principal_key_enrolled", None,
                        forged_pch, victim_sig, bytes(forged), None, "ed25519", None, None,
                    ],
                )

            with pytest.raises(RegistaError):
                rebuild_projection(handle._mgr, project=project, genesis_document=fixture.document)

            with handle._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT principal_id FROM principal_keys WHERE source_event_hash IS NOT NULL"
                ).fetchall()
            assert len(rows) == 1
            assert rows[0]["principal_id"] == "agent:alice"
        finally:
            _close(handle, project)

    def test_doctor_inherits_verified_dry_run(self, tmp_path, monkeypatch):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture), root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(handle, fixture, delegation_hash=_delegated_hash(handle))
            report = check_projection_consistent(
                handle._mgr, project=project, genesis_document=fixture.document
            )
            assert report.applied is False
        finally:
            _close(handle, project)

    def test_replay_requires_the_consumed_challenge(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(handle, fixture, delegation_hash=_delegated_hash(handle))
            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT payload FROM events "
                    "WHERE transition = 'principal_key_enrolled'"
                ).fetchone()
                assert row is not None
                conn.execute(
                    "DELETE FROM lifecycle_challenges WHERE challenge_id = %s",
                    [row["payload"]["possession_proof"]["challenge_id"]],
                )
            with pytest.raises(RegistaError) as exc:
                rebuild_projection(
                    handle._mgr,
                    project=project,
                    genesis_document=fixture.document,
                )
            assert exc.value.detail["reason"] == "possession_challenge_not_found"
        finally:
            _close(handle, project)

    def test_replay_requires_consumed_challenge_and_matching_proof(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(
                handle,
                fixture,
                principal="agent:unconsumed",
                delegation_hash=_delegated_hash(handle),
            )
            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT payload FROM events "
                    "WHERE transition = 'principal_key_enrolled'"
                ).fetchone()
                assert row is not None
                challenge_id = row["payload"]["possession_proof"]["challenge_id"]
                conn.execute(
                    "UPDATE lifecycle_challenges SET used = false "
                    "WHERE challenge_id = %s",
                    [challenge_id],
                )
            with pytest.raises(RegistaError) as exc:
                rebuild_projection(
                    handle._mgr,
                    project=project,
                    genesis_document=fixture.document,
                )
            assert exc.value.detail["reason"] == "possession_challenge_not_consumed"

            with handle._mgr.transaction() as conn:
                conn.execute(
                    "UPDATE lifecycle_challenges SET used = true, proof_signature = %s "
                    "WHERE challenge_id = %s",
                    ["A" * 88, challenge_id],
                )
            with pytest.raises(RegistaError) as exc:
                rebuild_projection(
                    handle._mgr,
                    project=project,
                    genesis_document=fixture.document,
                )
            assert exc.value.detail["reason"] == "possession_proof_signature_mismatch"
        finally:
            _close(handle, project)

    def test_replay_rejects_mutated_signed_challenge_field(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            _enroll(
                handle,
                fixture,
                principal="agent:mutated",
                delegation_hash=_delegated_hash(handle),
            )
            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT payload FROM events "
                    "WHERE transition = 'principal_key_enrolled'"
                ).fetchone()
                assert row is not None
                conn.execute(
                    "UPDATE lifecycle_challenges SET operation_digest = %s "
                    "WHERE challenge_id = %s",
                    ["sha256:" + "1" * 64, row["payload"]["possession_proof"]["challenge_id"]],
                )
            with pytest.raises(RegistaError) as exc:
                rebuild_projection(
                    handle._mgr,
                    project=project,
                    genesis_document=fixture.document,
                )
            assert exc.value.detail["reason"] == "possession_proof_verification_failed"
        finally:
            _close(handle, project)

    def test_replay_accepts_valid_dual_rotation_and_projects_new_key(self, tmp_path):
        fixture, handle, _kf, project, registrar = _env(tmp_path)
        principal = "agent:dual-replay"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, registrar)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_replay_old")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            new = TrustLogKey.mint("pk_replay_new")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id=old.key_id,
                superseded_key=old,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge, payload)
            _append_rotation(
                handle,
                fixture,
                principal=principal,
                payload=payload,
                authority="registrar",
                actor_id=REGISTRAR,
            )
            report = rebuild_projection(
                handle._mgr,
                project=project,
                genesis_document=fixture.document,
            )
            assert report.events_replayed == 2
            with handle._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT key_id, status FROM principal_keys "
                    "WHERE principal_id = %s ORDER BY key_id",
                    [principal],
                ).fetchall()
            assert {row["key_id"]: row["status"] for row in rows} == {
                old.key_id: "superseded",
                new.key_id: "active",
            }
        finally:
            _close(handle, project)

    def test_replay_accepts_valid_root_recovery(self, tmp_path):
        fixture, handle, _kf, project, _registrar = _env(tmp_path)
        principal = "agent:recovery-replay"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture),
                root_principal_id=ROOT,
            )
            new = TrustLogKey.mint("pk_recovery_replay")
            challenge = make_possession_challenge(
                trust_domain_id=fixture.trust_domain_id,
                principal_id=principal,
                fingerprint=new.fingerprint,
                project=handle._mgr.project,
            )
            payload = make_rotation_payload(
                trust_domain_id=fixture.trust_domain_id,
                principal_id=principal,
                key=new,
                supersedes_key_id="pk_lost",
                mode="recovery",
                recovery_reason="key-lost",
                root_keys=[_tlogkey("k_root-a", fixture.seeds[fixture.signer_ids[0]])],
                authorized_by={
                    "authority": "root",
                    "principal_id": ROOT,
                    "key_id": "k_root-a",
                    "delegation_event_hash": None,
                },
                challenge=challenge,
            )
            _persist_challenge(handle, challenge, payload)
            _append_rotation(
                handle,
                fixture,
                principal=principal,
                payload=payload,
                authority="root",
                actor_id=ROOT,
            )
            report = rebuild_projection(
                handle._mgr,
                project=project,
                genesis_document=fixture.document,
            )
            assert report.events_replayed == 1
        finally:
            _close(handle, project)
