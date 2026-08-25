"""WI-301 trust-log writer: threshold-rooted authority, genesis, max_operations.

A separate-project trust-log store, pinned genesis, threshold root authority via
``payload.root_signatures``, registrar authority with atomic ``max_operations``,
predecessor-link ordering, and fail-closed replay verification.
"""

from __future__ import annotations

import base64
import copy
import json
import threading
import uuid

import nacl.signing
import psycopg
import pytest
from _helpers import DSN
from _trust_fixtures import mint_genesis

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._principal_keys import list_principal_keys
from regista._trust_log_writer import (
    append_trust_log_event,
    chain_order,
    read_trust_log_rows,
    replay_trust_state,
    write_trust_genesis,
)
from regista._trust_projection import rebuild_projection
from regista.testing import drop_project_schema
from tests._trust_log_fixtures import (
    TrustLogKey,
    _ts,
    make_enrollment_payload,
    make_possession_challenge,
    make_registrar_delegation_payload,
    make_registrar_revocation_payload,
    make_revocation_payload,
    make_rotation_payload,
    persist_consumed_possession_challenge,
)

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT = "service:root-a"
ROOT_B = "service:root-b"
REGISTRAR = "service:registrar-1"


@pytest.fixture(autouse=True)
def _producer_env(monkeypatch):
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS", "pytest")
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-fixture")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


def _tlogkey(key_id: str, seed: bytes) -> TrustLogKey:
    sk = nacl.signing.SigningKey(seed)
    return TrustLogKey(
        key_id=key_id,
        seed=seed,
        public_key=bytes(sk.verify_key),
        fingerprint=_fingerprint(bytes(sk.verify_key)),
    )


def _fingerprint(public_key: bytes) -> str:
    from regista._principal_keys import _compute_fingerprint

    return _compute_fingerprint(public_key, "ed25519")


def _write_key_file(path, entries: dict[str, bytes]) -> str:
    payload = {"keys": []}
    for principal_id, seed in entries.items():
        sk = nacl.signing.SigningKey(seed)
        key_id = {
            ROOT: "k_root-a",
            ROOT_B: "k_root-b",
            REGISTRAR: "k_registrar",
        }.get(principal_id, "k_" + uuid.uuid4().hex[:8])
        payload["keys"].append(
            {
                "key_id": key_id,
                "scheme": "ed25519",
                "alg": "Ed25519",
                "secret": base64.b64encode(seed).decode("ascii"),
                "encoding": "base64",
                "public_key": base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
                "principal_id": principal_id,
                "role": "actor",
                "status": "active",
            }
        )
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _make_environment(tmp_path, *, threshold=1, signer_count=2):
    fixture = mint_genesis(
        threshold=threshold,
        signer_count=signer_count,
        seeds=[bytes([i]) * 32 for i in range(1, signer_count + 1)],
        # WI-320 (a-prime): write_trust_genesis now requires root_principal_id to equal
        # the signing root's initial_custody declared_holder, so the fixture must declare
        # the principal these tests write as.
        declared_holder=ROOT,
    )
    root_seed = fixture.seeds[fixture.signer_ids[0]]
    second_seed = fixture.seeds.get(fixture.signer_ids[1]) if signer_count > 1 else None
    entries = {ROOT: root_seed}
    if second_seed is not None:
        entries[ROOT_B] = second_seed
    entries[REGISTRAR] = bytes([9]) * 32
    key_file = _write_key_file(tmp_path / "keys.json", entries)
    project = f"wi301_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, hmac_key_path=key_file)
    return fixture, handle, key_file, project


def _close(handle, project):
    handle.close()
    drop_project_schema(DSN, project)


def _root_keys(fixture, signer_ids=("root-a",)):
    keys = []
    for signer_id in signer_ids:
        seed = fixture.seeds[signer_id]
        keys.append(_tlogkey("k_" + signer_id, seed))
    return keys


def _delegate(handle, fixture, *, threshold=1, root_keys=None, max_operations=2):
    roots = root_keys if root_keys is not None else _root_keys(fixture)
    registrar_key = _tlogkey("k_registrar", bytes([9]) * 32)
    payload = make_registrar_delegation_payload(
        trust_domain_id=fixture.trust_domain_id,
        registrar_principal_id=REGISTRAR,
        key=registrar_key,
        max_operations=max_operations,
        root_keys=roots,
        # A wide window anchored to real ``now`` (a day back, a year ahead). The
        # registrar-liveness check at admission compares the *current* wall clock
        # against this window (_trust_log_writer.py:1977), so a fixed 2026/2027 span
        # would fail once real time left it — the same time-bomb class as the
        # possession-challenge clock.
        not_before=_ts(-24 * 60 * 60),
        not_after=_ts(365 * 24 * 60 * 60),
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
    from regista._trust_log_writer import _row_event_hash, chain_order, read_trust_log_rows

    with handle._mgr.transaction() as conn:
        order = chain_order(read_trust_log_rows(conn))
    for row in order:
        if str(row["transition"]) == "registrar_delegated":
            return _row_event_hash(row)
    raise AssertionError("no registrar_delegated event found")


def _enrollment_material(
    handle,
    fixture,
    *,
    principal="agent:alice",
    delegation_hash=None,
    challenge=None,
    key=None,
    authorized_by=None,
):
    key = key or TrustLogKey.mint(f"pk_{uuid.uuid4().hex[:8]}")
    challenge = challenge or make_possession_challenge(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        fingerprint=key.fingerprint,
        project=handle._mgr.project,
    )
    payload = make_enrollment_payload(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        key=key,
        authorized_by=authorized_by or _make_auth(REGISTRAR, delegation_hash),
        challenge=challenge,
    )
    return payload, challenge


def _enroll(
    handle,
    fixture,
    *,
    registrar=True,
    principal="agent:alice",
    delegation_hash=None,
    persist_challenge=True,
    challenge=None,
    key=None,
    authorized_by=None,
):
    payload, challenge = _enrollment_material(
        handle,
        fixture,
        principal=principal,
        delegation_hash=delegation_hash,
        challenge=challenge,
        key=key,
        authorized_by=authorized_by,
    )
    if persist_challenge:
        with handle._mgr.transaction() as conn:
            persist_consumed_possession_challenge(
                conn,
                challenge,
                payload["possession_proof"]["signature"],
            )
    return _append_enrollment(
        handle,
        fixture,
        principal=principal,
        payload=payload,
        registrar=registrar,
    )


def _append_enrollment(handle, fixture, *, principal, payload, registrar=True):
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="principal_key_enrolled",
        payload=payload,
        entity_kind="principal",
        entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal),
        principal_id=REGISTRAR if registrar else ROOT,
        authority="registrar" if registrar else "root",
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
        authorized_by=authorized_by or _make_auth(REGISTRAR, delegation_hash),
        challenge=challenge,
    )
    return payload, challenge


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


def _append_revocation(handle, fixture, *, principal, key_id, delegation_hash):
    payload = make_revocation_payload(
        trust_domain_id=fixture.trust_domain_id,
        principal_id=principal,
        key_id=key_id,
        authorized_by=_make_auth(REGISTRAR, delegation_hash),
    )
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="principal_key_revoked",
        payload=payload,
        entity_kind="principal",
        entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal),
        principal_id=REGISTRAR,
        authority="registrar",
    )


def _persist_challenge(handle, challenge, payload, *, used=True):
    with handle._mgr.transaction() as conn:
        persist_consumed_possession_challenge(
            conn,
            challenge,
            payload["possession_proof"]["signature"],
            used=used,
        )


def _make_auth(principal, delegation_hash):
    if delegation_hash is None:
        return {
            "authority": "registrar",
            "principal_id": principal,
            "key_id": "k_registrar",
            "delegation_event_hash": None,
        }
    return {
        "authority": "registrar",
        "principal_id": principal,
        "key_id": "k_registrar",
        "delegation_event_hash": delegation_hash,
    }


def _make_root_auth(principal=ROOT, key_id="k_root-a"):
    return {
        "authority": "root",
        "principal_id": principal,
        "key_id": key_id,
        "delegation_event_hash": None,
    }


def _signed_genesis_payload(fixture, signer_ids=("root-a",)):
    from regista._trust_log import root_signature_input
    from regista._trust_log_writer import build_trust_domain_established_payload

    payload = build_trust_domain_established_payload(fixture.document)
    message = root_signature_input(payload)
    signatures = []
    for signer_id in signer_ids:
        seed = fixture.seeds[signer_id]
        sig = nacl.signing.SigningKey(seed).sign(message).signature
        signatures.append(
            {
                "signer_id": signer_id,
                "fingerprint": fixture.fingerprints[signer_id],
                "signature": base64.b64encode(sig).decode("ascii"),
            }
        )
    payload["root_signatures"] = signatures
    return payload


class TestGenesis:
    def test_actor_contradicting_declared_custody_is_refused(self, tmp_path):
        """WI-320 (a-prime) at the DURABLE boundary — the P7 library attack, fail-closed.

        The attack needs no forged key material and never touches the CLI: a keyset that
        labels the GENUINE root seed with an arbitrary principal_id satisfies
        ``_writer_key`` (a key really is held for that principal) and satisfies the
        signer check (the fingerprint really is a genesis signer), so before this guard
        ``write_trust_genesis`` signed the estate genesis with an ``actor_id`` the domain
        never declared. A CLI-only check could not close it: this is a public library
        entry point, and ``trust init-log`` routes k-of-n operators straight to it.

        The fixture deliberately contradicts the written principal — declared_holder is
        ROOT, the write claims ATTACKER — which is exactly the regression this pins.
        """
        attacker = "service:totally-unrelated-attacker"
        fixture = mint_genesis(
            threshold=1, signer_count=1, seeds=[bytes([1]) * 32], declared_holder=ROOT
        )
        key_file = _write_key_file(
            tmp_path / "attacker_keys.json",
            {attacker: fixture.seeds[fixture.signer_ids[0]]},
        )
        project = f"wi301_{uuid.uuid4().hex[:8]}"
        handle = Regista.create_project(DSN, project, hmac_key_path=key_file)
        try:
            with pytest.raises(RegistaError) as exc:
                write_trust_genesis(
                    handle._mgr, keys=handle._keys,
                    genesis_document=fixture.document, root_principal_id=attacker,
                )
            assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
            detail = exc.value.detail
            assert detail["reason"] == "root_principal_id_contradicts_declared_holder"
            assert detail["root_principal_id"] == attacker
            assert detail["declared_holder"] == ROOT
            assert detail["fingerprint"] == fixture.fingerprints[fixture.signer_ids[0]]
            # Nothing was written: the guard precedes every write in the transaction.
            with handle._mgr.transaction() as conn:
                assert read_trust_log_rows(conn) == []
        finally:
            _close(handle, project)

    def test_genesis_writes_and_payload_parses(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            genesis_id = write_trust_genesis(
                handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture), root_principal_id=ROOT,
            )
            assert genesis_id
            from regista._trust_log import parse_trust_domain_established

            with handle._mgr.transaction() as conn:
                order = chain_order(read_trust_log_rows(conn))
            assert [r["transition"] for r in order] == ["trust_domain_established"]
            payload = order[0]["payload"]
            parsed = parse_trust_domain_established(payload)
            assert str(parsed.trust_domain_id) == fixture.trust_domain_id
        finally:
            _close(handle, project)

    def test_double_genesis_refused(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document,
                                payload=_signed_genesis_payload(fixture),
                                root_principal_id=ROOT)
            with pytest.raises(RegistaError) as exc:
                write_trust_genesis(handle._mgr, keys=handle._keys,
                                    genesis_document=fixture.document,
                                    payload=_signed_genesis_payload(fixture),
                                    root_principal_id=ROOT)
            assert exc.value.code is ErrorCode.GENESIS_ALREADY_WRITTEN
            with pytest.raises(RegistaError) as exc:
                append_trust_log_event(
                    handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                    transition="trust_domain_established", payload={},
                    entity_kind="trust_domain", entity_id=uuid.uuid4(),
                    principal_id=ROOT, authority="root",
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        finally:
            _close(handle, project)


    def test_genesis_digest_equals_canonical_publication_bytes(self, tmp_path):
        import hashlib

        from regista._jcs import canonicalize
        from regista._trust_domain import genesis_document_digest

        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            payload = _signed_genesis_payload(fixture)
            expected = genesis_document_digest(fixture.document)
            assert payload["genesis_document_digest"] == expected
            assert expected == "sha256:" + hashlib.sha256(
                canonicalize(fixture.document)
            ).hexdigest()
        finally:
            _close(handle, project)


    def test_non_null_pinned_head_is_named_invalid(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            doc = copy.deepcopy(fixture.document)
            doc["trust_log"]["initial_head_event_hash"] = "sha256:" + "ff" * 32
            with pytest.raises(RegistaError) as exc:
                write_trust_genesis(handle._mgr, keys=handle._keys,
                                    genesis_document=doc, root_principal_id=ROOT)
            assert exc.value.code is ErrorCode.TRUST_GENESIS_SCHEMA_INVALID
            assert exc.value.detail["reason"] == "genesis_head_must_be_null"
        finally:
            _close(handle, project)


class TestRootThreshold:
    def test_threshold_met_positive(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path, threshold=2, signer_count=2)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document,
                                payload=_signed_genesis_payload(fixture, ("root-a", "root-b")),
                                root_principal_id=ROOT)
            _delegate(handle, fixture, root_keys=_root_keys(fixture, ("root-a", "root-b")))
        finally:
            _close(handle, project)

    def test_threshold_not_met_negative(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path, threshold=2, signer_count=2)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document,
                                payload=_signed_genesis_payload(fixture, ("root-a", "root-b")),
                                root_principal_id=ROOT)
            with pytest.raises(RegistaError) as exc:
                _delegate(handle, fixture, root_keys=_root_keys(fixture, ("root-a",)))
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
        finally:
            _close(handle, project)



    def test_one_of_two_genesis_root_signatures_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path, threshold=2, signer_count=2)
        try:
            with pytest.raises(RegistaError) as exc:
                write_trust_genesis(
                    handle._mgr, keys=handle._keys, genesis_document=fixture.document,
                    payload=_signed_genesis_payload(fixture, ("root-a",)),
                    root_principal_id=ROOT,
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc.value.detail["reason"] == "root_threshold_not_met"
        finally:
            _close(handle, project)


class TestRegistrarMaxOperations:
    def test_max_operations_enforced_sequential(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document, root_principal_id=ROOT)
            _delegate(handle, fixture, max_operations=2)
            _enroll(handle, fixture, principal="agent:c1", delegation_hash=_delegated_hash(handle))
            _enroll(handle, fixture, principal="agent:c2", delegation_hash=_delegated_hash(handle))
            with pytest.raises(RegistaError) as exc:
                _enroll(handle, fixture, principal="agent:c3",
                        delegation_hash=_delegated_hash(handle))
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
        finally:
            _close(handle, project)

    def test_two_concurrent_final_ops_only_one_succeeds(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document, root_principal_id=ROOT)
            _delegate(handle, fixture, max_operations=1)
            second = Regista(DSN, project, hmac_key_path=_kf)
            results: list[bool] = []
            errors: list[RegistaError] = []
            lock = threading.Lock()

            def _attempt(h):
                try:
                    _enroll(h, fixture, principal="agent:race", delegation_hash=_delegated_hash(h))
                    with lock:
                        results.append(True)
                except RegistaError as e:
                    with lock:
                        errors.append(e)

            t1 = threading.Thread(target=_attempt, args=(handle,))
            t2 = threading.Thread(target=_attempt, args=(second,))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            assert len(results) == 1
            assert len(errors) == 1
            assert errors[0].code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            second.close()
        finally:
            _close(handle, project)


class TestRegistrarRevocationReplay:
    def test_root_revocation_must_name_the_current_live_delegation(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            payload = make_registrar_revocation_payload(
                trust_domain_id=fixture.trust_domain_id,
                key_id="k_registrar",
                delegation_event_hash="sha256:" + "f" * 64,
                root_keys=_root_keys(fixture),
            )
            append_trust_log_event(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                transition="registrar_revoked",
                payload=payload,
                entity_kind="trust_domain",
                entity_id=uuid.UUID(fixture.trust_domain_id),
                principal_id=ROOT,
                authority="root",
            )

            with handle._mgr.transaction() as conn:
                with pytest.raises(RegistaError) as exc_info:
                    replay_trust_state(conn, fixture.document)
            assert exc_info.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc_info.value.detail["reason"] == (
                "registrar_revocation_delegation_mismatch"
            )

            # A later registrar event must not make the mismatched revocation a no-op.
            with pytest.raises(RegistaError) as exc_info:
                _enroll(
                    handle,
                    fixture,
                    principal="agent:after-bad-revocation",
                    delegation_hash=_delegated_hash(handle),
                )
            assert exc_info.value.detail["reason"] == (
                "registrar_revocation_delegation_mismatch"
            )
        finally:
            _close(handle, project)

    def test_root_revocation_without_a_live_target_is_refused(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            payload = make_registrar_revocation_payload(
                trust_domain_id=fixture.trust_domain_id,
                registrar_principal_id="service:missing-registrar",
                key_id="k_missing",
                delegation_event_hash="sha256:" + "a" * 64,
                root_keys=_root_keys(fixture),
            )
            append_trust_log_event(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                transition="registrar_revoked",
                payload=payload,
                entity_kind="trust_domain",
                entity_id=uuid.UUID(fixture.trust_domain_id),
                principal_id=ROOT,
                authority="root",
            )
            with handle._mgr.transaction() as conn:
                with pytest.raises(RegistaError) as exc_info:
                    replay_trust_state(conn, fixture.document)
            assert exc_info.value.detail["reason"] == (
                "registrar_revocation_target_missing"
            )
        finally:
            _close(handle, project)


class TestPrincipalKeyStatusReplay:
    def test_revoked_key_remains_verifiable_but_cannot_dual_rotate(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:compromised"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_compromised_old")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            revoke_payload = make_revocation_payload(
                trust_domain_id=fixture.trust_domain_id,
                principal_id=principal,
                key_id=old.key_id,
                authorized_by=_make_auth(REGISTRAR, delegation_hash),
            )
            append_trust_log_event(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                transition="principal_key_revoked",
                payload=revoke_payload,
                entity_kind="principal",
                entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal),
                principal_id=REGISTRAR,
                authority="registrar",
            )

            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_public_keys[(principal, old.key_id)] == old.public_key
            assert state.principal_key_status[(principal, old.key_id)] == "revoked"

            new = TrustLogKey.mint("pk_compromised_new")
            rotation_payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id=old.key_id,
                superseded_key=old,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge, rotation_payload)
            with pytest.raises(RegistaError) as exc_info:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=rotation_payload,
                    authority="registrar",
                    actor_id=REGISTRAR,
                )
            assert exc_info.value.detail["reason"] == "superseded_key_revoked"
        finally:
            _close(handle, project)


class TestPossessionAdmission:
    def test_missing_challenge_is_denied_before_registrar_count(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=1)
            with pytest.raises(RegistaError) as exc:
                _enroll(
                    handle,
                    fixture,
                    principal="agent:missing",
                    delegation_hash=_delegated_hash(handle),
                    persist_challenge=False,
                )
            assert exc.value.detail["reason"] == "possession_challenge_not_found"
            _enroll(
                handle,
                fixture,
                principal="agent:after-missing",
                delegation_hash=_delegated_hash(handle),
            )
        finally:
            _close(handle, project)

    def test_missing_challenge_table_is_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            with handle._mgr.transaction() as conn:
                conn.execute("DROP TABLE lifecycle_challenges")
            with pytest.raises(RegistaError) as exc:
                _enroll(
                    handle,
                    fixture,
                    principal="agent:no-table",
                    delegation_hash=_delegated_hash(handle),
                    persist_challenge=False,
                )
            assert exc.value.detail["reason"] == "possession_challenge_table_missing"
        finally:
            _close(handle, project)

    def test_unconsumed_challenge_is_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            payload, challenge = _enrollment_material(
                handle,
                fixture,
                principal="agent:unconsumed",
                delegation_hash=_delegated_hash(handle),
            )
            with handle._mgr.transaction() as conn:
                persist_consumed_possession_challenge(
                    conn,
                    challenge,
                    payload["possession_proof"]["signature"],
                    used=False,
                )
            with pytest.raises(RegistaError) as exc:
                append_trust_log_event(
                    handle._mgr,
                    keys=handle._keys,
                    genesis_document=fixture.document,
                    transition="principal_key_enrolled",
                    payload=payload,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:agent:unconsumed"
                    ),
                    principal_id=REGISTRAR,
                    authority="registrar",
                )
            assert exc.value.detail["reason"] == "possession_challenge_not_consumed"
        finally:
            _close(handle, project)

    def test_proof_signature_mismatch_is_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            payload, challenge = _enrollment_material(
                handle,
                fixture,
                principal="agent:proof-mismatch",
                delegation_hash=_delegated_hash(handle),
            )
            with handle._mgr.transaction() as conn:
                persist_consumed_possession_challenge(
                    conn,
                    challenge,
                    payload["possession_proof"]["signature"],
                )
                conn.execute(
                    "UPDATE lifecycle_challenges SET proof_signature = %s "
                    "WHERE challenge_id = %s",
                    ["A" * len(payload["possession_proof"]["signature"]), challenge.challenge_id],
                )
            with pytest.raises(RegistaError) as exc:
                append_trust_log_event(
                    handle._mgr,
                    keys=handle._keys,
                    genesis_document=fixture.document,
                    transition="principal_key_enrolled",
                    payload=payload,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:agent:proof-mismatch"
                    ),
                    principal_id=REGISTRAR,
                    authority="registrar",
                )
            assert exc.value.detail["reason"] == "possession_proof_signature_mismatch"
        finally:
            _close(handle, project)

    def test_mutated_signed_challenge_field_is_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            payload, challenge = _enrollment_material(
                handle,
                fixture,
                principal="agent:mutated-challenge",
                delegation_hash=_delegated_hash(handle),
            )
            with handle._mgr.transaction() as conn:
                persist_consumed_possession_challenge(
                    conn,
                    challenge,
                    payload["possession_proof"]["signature"],
                )
                conn.execute(
                    "UPDATE lifecycle_challenges SET operation_digest = %s "
                    "WHERE challenge_id = %s",
                    ["sha256:" + "1" * 64, challenge.challenge_id],
                )
            with pytest.raises(RegistaError) as exc:
                append_trust_log_event(
                    handle._mgr,
                    keys=handle._keys,
                    genesis_document=fixture.document,
                    transition="principal_key_enrolled",
                    payload=payload,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:agent:mutated-challenge"
                    ),
                    principal_id=REGISTRAR,
                    authority="registrar",
                )
            assert exc.value.detail["reason"] == "possession_proof_verification_failed"
        finally:
            _close(handle, project)

    def test_expired_challenge_is_denied_at_admission(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture)
            key = TrustLogKey.mint("pk_expired")
            challenge = make_possession_challenge(
                trust_domain_id=fixture.trust_domain_id,
                principal_id="agent:expired",
                fingerprint=key.fingerprint,
                project=handle._mgr.project,
                issued_at="2026-01-01T00:00:00.000000Z",
                expires_at="2026-01-01T00:05:00.000000Z",
            )
            payload = make_enrollment_payload(
                trust_domain_id=fixture.trust_domain_id,
                principal_id="agent:expired",
                key=key,
                authorized_by=_make_auth(REGISTRAR, _delegated_hash(handle)),
                challenge=challenge,
            )
            with handle._mgr.transaction() as conn:
                persist_consumed_possession_challenge(
                    conn,
                    challenge,
                    payload["possession_proof"]["signature"],
                )
            with pytest.raises(RegistaError) as exc:
                append_trust_log_event(
                    handle._mgr,
                    keys=handle._keys,
                    genesis_document=fixture.document,
                    transition="principal_key_enrolled",
                    payload=payload,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:agent:expired"
                    ),
                    principal_id=REGISTRAR,
                    authority="registrar",
                )
            assert exc.value.detail["reason"] == "possession_challenge_expired_at_admission"
        finally:
            _close(handle, project)


class TestRotationAdmission:
    def test_valid_dual_rotation_requires_and_verifies_superseded_key(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:dual-valid"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=2)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_dual_old")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            new = TrustLogKey.mint("pk_dual_new")
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
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_public_keys[(principal, old.key_id)] == old.public_key
            assert state.principal_public_keys[(principal, new.key_id)] == new.public_key
        finally:
            _close(handle, project)

    def test_dual_rotation_superseding_a_non_current_key_is_refused(self, tmp_path):
        """WI-347: admission refuses a dual rotation that names a SUPERSEDED key.

        The pre-existing gap (Sol #3 / Opus finding #1): enrol K1 → rotate K1→K2 →
        rotate K1→K3 all admitted, because the prior guard rejected only a REVOKED
        superseded key. That left K2 AND K3 active — a rotated-out key forking the active
        set. The writer's ``append_trust_log_event`` must refuse the third event; the
        replay half is proven in ``tests/test_wi337_trust_log_export.py`` (same
        ``_classify_rotation`` chokepoint).
        """

        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:dual-non-current"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_k1")
            _enroll(
                handle, fixture, principal=principal, delegation_hash=delegation_hash, key=k1
            )
            k2 = TrustLogKey.mint("pk_k2")
            payload2, challenge2 = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=k2,
                supersedes_key_id=k1.key_id,
                superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge2, payload2)
            _append_rotation(
                handle,
                fixture,
                principal=principal,
                payload=payload2,
                authority="registrar",
                actor_id=REGISTRAR,
            )
            # K1 is now SUPERSEDED. A second rotation naming K1 must be refused.
            k3 = TrustLogKey.mint("pk_k3")
            payload3, challenge3 = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=k3,
                supersedes_key_id=k1.key_id,
                superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge3, payload3)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload3,
                    authority="registrar",
                    actor_id=REGISTRAR,
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY
            assert exc.value.detail["reason"] == "superseded_key_superseded"
        finally:
            _close(handle, project)

    def test_recovery_rotation_naming_an_already_superseded_key_is_refused(self, tmp_path):
        """WI-347: the same guard binds a root-authorised recovery.

        A recovery that names an already-superseded key would fork the active set exactly
        like the dual case, so it is refused BEFORE the root-threshold check — the supersedes
        key must be the principal's current active key regardless of authority.
        """

        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:recovery-non-current"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_rk1")
            _enroll(
                handle, fixture, principal=principal, delegation_hash=delegation_hash, key=k1
            )
            k2 = TrustLogKey.mint("pk_rk2")
            payload2, challenge2 = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=k2,
                supersedes_key_id=k1.key_id,
                superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge2, payload2)
            _append_rotation(
                handle,
                fixture,
                principal=principal,
                payload=payload2,
                authority="registrar",
                actor_id=REGISTRAR,
            )
            # K1 superseded, K2 active. A recovery naming K1 (root authority) is refused.
            k3 = TrustLogKey.mint("pk_rk3")
            payload3, challenge3 = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=k3,
                supersedes_key_id=k1.key_id,
                mode="recovery",
                recovery_reason="key-lost",
                root_keys=_root_keys(fixture),
                authorized_by=_make_root_auth(),
            )
            _persist_challenge(handle, challenge3, payload3)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload3,
                    authority="root",
                    actor_id=ROOT,
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY
            assert exc.value.detail["reason"] == "superseded_key_superseded"
        finally:
            _close(handle, project)

    def test_bad_dual_signature_does_not_consume_last_registrar_operation(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:dual-bad-signature"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=2)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_bad_old")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            impostor = TrustLogKey.mint("pk_impostor")
            bad_new = TrustLogKey.mint("pk_bad_new")
            bad_payload, bad_challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=bad_new,
                supersedes_key_id=old.key_id,
                superseded_key=impostor,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, bad_challenge, bad_payload)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=bad_payload,
                    authority="registrar",
                    actor_id=REGISTRAR,
                )
            assert exc.value.detail["reason"] == "old_key_signature_invalid"

            good_new = TrustLogKey.mint("pk_good_new")
            good_payload, good_challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=good_new,
                supersedes_key_id=old.key_id,
                superseded_key=old,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, good_challenge, good_payload)
            _append_rotation(
                handle,
                fixture,
                principal=principal,
                payload=good_payload,
                authority="registrar",
                actor_id=REGISTRAR,
            )
        finally:
            _close(handle, project)

    def test_missing_superseded_key_is_denied_before_operation_increment(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:dual-missing"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=2)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_existing")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            new = TrustLogKey.mint("pk_missing_new")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id="pk_not_in_chain",
                superseded_key=old,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge, payload)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload,
                    authority="registrar",
                    actor_id=REGISTRAR,
                )
            # WI-347: naming a key that is not the principal's CURRENT active key is now
            # refused by the earlier supersedes-must-be-active guard. `pk_not_in_chain`
            # was never enrolled, so its status is unknown — refused before the
            # superseded-public-key lookup (which produced the older
            # `superseded_public_key_unavailable` reason) is ever reached. The denial
            # still precedes any registrar-operation increment, which is what this test
            # exists to prove.
            assert exc.value.detail["reason"] == "superseded_key_unknown"
        finally:
            _close(handle, project)

    def test_valid_root_recovery_uses_current_root_threshold(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:recovered"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            # WI-347: a recovery must name the principal's CURRENTLY ACTIVE key, so the
            # principal must first HAVE one. The realistic scenario is "holder lost the
            # private key of a still-active key": enrol it (registrar), then recover it
            # (root authority) because the lost key cannot co-sign a dual rotation.
            _delegate(handle, fixture, max_operations=2)
            delegation_hash = _delegated_hash(handle)
            lost = TrustLogKey.mint("pk_lost")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=lost,
            )
            new = TrustLogKey.mint("pk_recovered")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id=lost.key_id,
                mode="recovery",
                recovery_reason="key-lost",
                root_keys=_root_keys(fixture),
                authorized_by=_make_root_auth(),
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
        finally:
            _close(handle, project)

    def test_below_threshold_recovery_is_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path, threshold=2, signer_count=2)
        principal = "agent:recovery-threshold"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture, ("root-a", "root-b")),
                root_principal_id=ROOT,
            )
            # WI-347: enrol the active key the recovery supersedes (2-root delegation, to
            # match the threshold-2 genesis) so the request reaches the root-threshold
            # check the truncated signature set is meant to fail — the supersedes-active
            # guard would otherwise refuse an unknown key first.
            _delegate(handle, fixture, root_keys=_root_keys(fixture, ("root-a", "root-b")))
            delegation_hash = _delegated_hash(handle)
            lost = TrustLogKey.mint("pk_lost")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=lost,
            )
            new = TrustLogKey.mint("pk_recovery_threshold")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id=lost.key_id,
                mode="recovery",
                recovery_reason="key-lost",
                root_keys=_root_keys(fixture, ("root-a", "root-b")),
                authorized_by=_make_root_auth(),
            )
            payload["root_signatures"] = payload["root_signatures"][:1]
            _persist_challenge(handle, challenge, payload)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload,
                    authority="root",
                    actor_id=ROOT,
                )
            assert exc.value.detail["reason"] == "root_threshold_not_met"
        finally:
            _close(handle, project)

    def test_registrar_cannot_authorize_recovery(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:registrar-recovery"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=1)
            delegation_hash = _delegated_hash(handle)
            new = TrustLogKey.mint("pk_registrar_recovery")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id="pk_lost",
                mode="recovery",
                recovery_reason="key-compromised",
                root_keys=_root_keys(fixture),
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge, payload)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload,
                    authority="registrar",
                    actor_id=REGISTRAR,
                )
            assert exc.value.detail["reason"] == "recovery_requires_root_authority"
        finally:
            _close(handle, project)

    @pytest.mark.parametrize(
        ("label", "authorized_by", "reason"),
        [
            (
                "actor",
                {
                    "authority": "registrar",
                    "principal_id": "service:other",
                    "key_id": "k_registrar",
                    "delegation_event_hash": "DELEGATION",
                },
                "authorized_by_actor_mismatch",
            ),
            (
                "key",
                {
                    "authority": "registrar",
                    "principal_id": REGISTRAR,
                    "key_id": "k_wrong",
                    "delegation_event_hash": "DELEGATION",
                },
                "authorized_by_key_id_mismatch",
            ),
            (
                "delegation",
                {
                    "authority": "registrar",
                    "principal_id": REGISTRAR,
                    "key_id": "k_registrar",
                    "delegation_event_hash": "sha256:" + "b" * 64,
                },
                "authorized_by_delegation_mismatch",
            ),
            (
                "authority",
                {
                    "authority": "root",
                    "principal_id": REGISTRAR,
                    "key_id": "k_registrar",
                    "delegation_event_hash": None,
                },
                "authorized_by_authority_mismatch",
            ),
        ],
    )
    def test_authorized_by_fields_must_match_exactly(
        self, tmp_path, label, authorized_by, reason
    ):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=10)
            delegation_hash = _delegated_hash(handle)
            authorized_by = dict(authorized_by)
            if authorized_by["delegation_event_hash"] == "DELEGATION":
                authorized_by["delegation_event_hash"] = delegation_hash
            principal = "agent:auth-" + label
            payload, challenge = _enrollment_material(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                authorized_by=authorized_by,
            )
            _persist_challenge(handle, challenge, payload)
            with pytest.raises(RegistaError) as exc:
                _append_enrollment(
                    handle,
                    fixture,
                    principal=principal,
                    payload=payload,
                    registrar=True,
                )
            assert exc.value.detail["reason"] == reason
        finally:
            _close(handle, project)


class TestReplayVerifies:
    def test_malformed_stored_occurred_at_has_a_named_failure(self):
        from regista._trust_log_writer import _envelope_occurred_at

        with pytest.raises(RegistaError) as exc_info:
            _envelope_occurred_at({"occurred_at": "not-a-timestamp"})
        assert exc_info.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        assert exc_info.value.detail["reason"] == "occurred_at_malformed"

    def test_tampered_stored_event_denied(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        try:
            write_trust_genesis(handle._mgr, keys=handle._keys,
                                genesis_document=fixture.document, root_principal_id=ROOT)
            _delegate(handle, fixture)
            with handle._mgr.transaction() as conn:
                victim = conn.execute(
                    "SELECT event_id, canonical_envelope FROM events "
                    "WHERE transition = 'registrar_delegated' LIMIT 1"
                ).fetchone()
                assert victim is not None
                tampered = bytearray(bytes(victim["canonical_envelope"]))
                tampered[-2] ^= 0x01
                conn.execute(
                    "UPDATE events SET canonical_envelope = %s WHERE event_id = %s",
                    [bytes(tampered), victim["event_id"]],
                )
            with pytest.raises(RegistaError) as exc:
                with handle._mgr.transaction() as conn:
                    replay_trust_state(conn, fixture.document)
            assert exc.value.code in (
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            )
        finally:
            _close(handle, project)

    def test_stored_below_threshold_recovery_is_denied_on_replay(self, tmp_path):
        """Replay must enforce recovery threshold, not only append admission.

        The row is first written with valid root evidence, then rewritten as an
        attacker could rewrite a stored payload: the envelope and signature are
        recomputed, but only one of the two required root signatures remains.
        This exercises the persisted-row replay path directly rather than merely
        re-testing the append gate.
        """

        from regista._signing import sign_v6_envelope
        from regista._verification import parse_v6_envelope_strict

        fixture, handle, _kf, project = _make_environment(
            tmp_path, threshold=2, signer_count=2
        )
        principal = "agent:stored-recovery-threshold"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                payload=_signed_genesis_payload(fixture, ("root-a", "root-b")),
                root_principal_id=ROOT,
            )
            # WI-347: the recovery supersedes an ACTIVE key, so enrol one first (2-root
            # delegation matching the threshold-2 genesis). The row-rewrite below then
            # attacks the STORED recovery, and replay must still refuse it on threshold.
            _delegate(handle, fixture, root_keys=_root_keys(fixture, ("root-a", "root-b")))
            delegation_hash = _delegated_hash(handle)
            lost = TrustLogKey.mint("pk_lost")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=lost,
            )
            new = TrustLogKey.mint("pk_stored_recovery_threshold")
            payload, challenge = _rotation_material(
                handle,
                fixture,
                principal=principal,
                key=new,
                supersedes_key_id=lost.key_id,
                mode="recovery",
                recovery_reason="key-lost",
                root_keys=_root_keys(fixture, ("root-a", "root-b")),
                authorized_by=_make_root_auth(),
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

            with handle._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT event_id, canonical_envelope FROM events "
                    "WHERE transition = 'principal_key_rotated' ORDER BY global_seq DESC LIMIT 1"
                ).fetchone()
                assert row is not None
                envelope = parse_v6_envelope_strict(bytes(row["canonical_envelope"]))
                envelope["payload"]["root_signatures"] = envelope["payload"][
                    "root_signatures"
                ][:1]
                signed = sign_v6_envelope(envelope, fixture.seeds["root-a"])
                conn.execute(
                    "UPDATE events SET payload = %s, payload_canonical_hash = %s, "
                    "signature = %s, canonical_envelope = %s WHERE event_id = %s",
                    [
                        psycopg.types.json.Jsonb(envelope["payload"]),
                        signed.payload_canonical_hash,
                        signed.signature,
                        signed.canonical_envelope,
                        row["event_id"],
                    ],
                )
                conn.execute(
                    "UPDATE event_chain_head SET head_hash = %s WHERE id = TRUE",
                    [signed.event_hash],
                )

            with pytest.raises(RegistaError) as exc_info:
                with handle._mgr.transaction() as conn:
                    replay_trust_state(conn, fixture.document)
            assert exc_info.value.detail["reason"] == "root_threshold_not_met"
        finally:
            _close(handle, project)


class TestEnrollmentBindsFreshKey:
    """B1 (PR #58): enrolment binds a principal's key where there is none.

    The writer must refuse a `principal_key_enrolled` that would displace a live key —
    that is a §5.6 rotation, which carries the outgoing key's dual authorization. The
    guard sits in the shared append path, so a direct `append_trust_log_event` (no CLI)
    is bound by it too; the poison event never reaches the durable log. Rotation is
    untouched.
    """

    def test_direct_append_enroll_over_active_key_is_refused(self, tmp_path):
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:seize-target"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            key_a = TrustLogKey.mint("pk_incumbent_a")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=key_a,
            )

            # A DIFFERENT key B for the SAME principal, appended directly (bypassing the
            # CLI guard): the writer must refuse it at admission.
            key_b = TrustLogKey.mint("pk_usurper_b")
            payload_b, challenge_b = _enrollment_material(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=key_b,
            )
            _persist_challenge(handle, challenge_b, payload_b)
            with pytest.raises(RegistaError) as exc:
                _append_enrollment(
                    handle, fixture, principal=principal, payload=payload_b
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc.value.detail["reason"] == "enrollment_key_already_present"

            # The poison was never written: the log still replays and A is the sole
            # active key.
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_key_status[(principal, key_a.key_id)] == "active"
            assert (principal, key_b.key_id) not in state.principal_public_keys
        finally:
            _close(handle, project)

    def test_reenroll_same_key_direct_append_is_admitted(self, tmp_path):
        """The guard keys on the fingerprint: re-enrolling the SAME bytes is not a
        change, so it is not refused (idempotent, mirrors the CLI no-op)."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:same-key"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            key_a = TrustLogKey.mint("pk_same_a")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=key_a,
            )
            # Same public bytes, fresh challenge — admitted (no different-fingerprint
            # collision to guard against).
            payload2, challenge2 = _enrollment_material(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=key_a,
            )
            _persist_challenge(handle, challenge2, payload2)
            _append_enrollment(handle, fixture, principal=principal, payload=payload2)
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_key_status[(principal, key_a.key_id)] == "active"
        finally:
            _close(handle, project)

    def test_reenroll_same_bytes_different_key_id_repro(self, tmp_path):
        """WI-348 REPRO: same public bytes under a DIFFERENT key_id must NOT yield two
        active key_ids in the offline replay (that diverges from the projection, which
        supersedes-then-inserts, and lets a rotated-out material survive via the alias).

        A registrar plants K1 (active), then an ALIAS with identical bytes but a fresh
        key_id. The offline replay must not admit the alias as a second active key.
        """
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:alias-target"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_k1")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=k1,
            )
            # Alias: SAME seed/public bytes/fingerprint, DIFFERENT key_id.
            k1_alias = _tlogkey("pk_k1_alias", k1.seed)
            payload_alias, challenge_alias = _enrollment_material(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=k1_alias,
            )
            _persist_challenge(handle, challenge_alias, payload_alias)
            with pytest.raises(RegistaError) as exc:
                _append_enrollment(
                    handle, fixture, principal=principal, payload=payload_alias
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc.value.detail["reason"] == "enrollment_alias_key_id_mismatch"

            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            actives = [
                k_id
                for (p_id, k_id), st in state.principal_key_status.items()
                if p_id == principal and st == "active"
            ]
            assert actives == [k1.key_id]
            assert (principal, k1_alias.key_id) not in state.principal_public_keys
        finally:
            _close(handle, project)

    def test_wi348_replay_and_projection_agree_on_active_set(self, tmp_path):
        """WI-348 replay≡projection: for an enrol→rotate history the offline replay's
        active set equals the projection table's active set (exactly one active key). The
        alias the fix now refuses never enters the durable log, so the two views cannot
        diverge — the divergence WI-348 would otherwise have created is unreachable.
        """
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:reconcile"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=6)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_rc1")
            _enroll(
                handle, fixture, principal=principal,
                delegation_hash=delegation_hash, key=k1,
            )
            # The alias the fix refuses — the poison never enters the durable log.
            k1_alias = _tlogkey("pk_rc1_alias", k1.seed)
            payload_alias, challenge_alias = _enrollment_material(
                handle, fixture, principal=principal,
                delegation_hash=delegation_hash, key=k1_alias,
            )
            _persist_challenge(handle, challenge_alias, payload_alias)
            with pytest.raises(RegistaError):
                _append_enrollment(
                    handle, fixture, principal=principal, payload=payload_alias
                )
            # A legitimate §5.6 rotation K1 -> K2.
            k2 = TrustLogKey.mint("pk_rc2")
            payload_rot, challenge_rot = _rotation_material(
                handle, fixture, principal=principal, key=k2,
                supersedes_key_id=k1.key_id, superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, challenge_rot, payload_rot)
            _append_rotation(
                handle, fixture, principal=principal, payload=payload_rot,
                authority="registrar", actor_id=REGISTRAR,
            )
            # Replay (offline) active set.
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            replay_active = {
                k_id
                for (p_id, k_id), st in state.principal_key_status.items()
                if p_id == principal and st == "active"
            }
            # Projection (rebuilt from the SAME durable trust log) active set.
            rebuild_projection(
                handle._mgr,
                project=handle._mgr.project,
                genesis_document=fixture.document,
            )
            proj_active = {
                entry.key_id
                for entry in list_principal_keys(
                    handle._mgr, principal_id=principal, status="active"
                )
            }
            assert replay_active == proj_active == {k2.key_id}
        finally:
            _close(handle, project)

    def test_rotation_still_supersedes_after_enroll_guard(self, tmp_path):
        """A proper §5.6 dual rotation still supersedes A -> B — the enrol guard is
        specific to the enrol transition and leaves rotation intact."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:rotates-cleanly"
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=4)
            delegation_hash = _delegated_hash(handle)
            old = TrustLogKey.mint("pk_rotate_old")
            _enroll(
                handle,
                fixture,
                principal=principal,
                delegation_hash=delegation_hash,
                key=old,
            )
            new = TrustLogKey.mint("pk_rotate_new")
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
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            # The rotation was admitted and the new key is live; both keys' bytes remain in
            # the replayed state. WI-337 (Sol #3): the replay now marks the outgoing key
            # SUPERSEDED (previously only the projection applier did), so a rotated-out key
            # is not classified as current authority offline. The point here is that the
            # enrol guard did NOT block a legitimate rotation.
            assert state.principal_key_status[(principal, new.key_id)] == "active"
            assert state.principal_key_status[(principal, old.key_id)] == "superseded"
            assert state.principal_public_keys[(principal, new.key_id)] == new.public_key
            assert state.principal_public_keys[(principal, old.key_id)] == old.public_key
        finally:
            _close(handle, project)

    def test_reenroll_revoked_key_id_is_refused_at_admission(self, tmp_path):
        """WI-349: enrol K1 -> revoke K1 -> re-enrol the SAME key_id K1.

        The guard used to skip non-active keys and ``_remember_principal_key`` set the
        reused key_id ``active`` unconditionally, so the revoked K1 was REACTIVATED in the
        offline replay while a projection rebuild of the same log raised
        ``PRINCIPAL_KEY_ALREADY_EXISTS`` — the divergence. Admission must now refuse the
        reuse, and the poison never lands.
        """
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:wi349-revoked"
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys,
                genesis_document=fixture.document, root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=8)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_wi349_k1")
            _enroll(handle, fixture, principal=principal,
                    delegation_hash=delegation_hash, key=k1)
            _append_revocation(handle, fixture, principal=principal,
                               key_id=k1.key_id, delegation_hash=delegation_hash)
            payload2, ch2 = _enrollment_material(
                handle, fixture, principal=principal,
                delegation_hash=delegation_hash, key=k1,
            )
            _persist_challenge(handle, ch2, payload2)
            with pytest.raises(RegistaError) as exc:
                _append_enrollment(handle, fixture, principal=principal, payload=payload2)
            assert exc.value.code is ErrorCode.TRUST_LOG_PRINCIPAL_KEY_ID_REUSED
            assert exc.value.detail["reason"] == "principal_key_id_reused"
            assert exc.value.detail["existing_status"] == "revoked"

            # The poison never landed: replay still shows K1 revoked (not reactivated), and
            # the projection rebuild of the same durable log succeeds and agrees.
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_key_status[(principal, k1.key_id)] == "revoked"
            rebuild_projection(handle._mgr, project=handle._mgr.project,
                               genesis_document=fixture.document)
            assert list_principal_keys(
                handle._mgr, principal_id=principal, status="active"
            ) == []
        finally:
            _close(handle, project)

    def test_reenroll_superseded_key_id_is_refused_at_admission(self, tmp_path):
        """WI-349: enrol K1 -> rotate K1->K2 (K1 superseded) -> re-enrol key_id K1.

        A superseded key_id is as write-once as a revoked one; re-enrolling it would revive
        a rotated-out key offline. Admission refuses it.
        """
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:wi349-superseded"
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys,
                genesis_document=fixture.document, root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=8)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_wi349s_k1")
            _enroll(handle, fixture, principal=principal,
                    delegation_hash=delegation_hash, key=k1)
            k2 = TrustLogKey.mint("pk_wi349s_k2")
            payload_rot, ch_rot = _rotation_material(
                handle, fixture, principal=principal, key=k2,
                supersedes_key_id=k1.key_id, superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, ch_rot, payload_rot)
            _append_rotation(handle, fixture, principal=principal, payload=payload_rot,
                             authority="registrar", actor_id=REGISTRAR)
            # Re-enrol K1 (now superseded).
            payload2, ch2 = _enrollment_material(
                handle, fixture, principal=principal,
                delegation_hash=delegation_hash, key=k1,
            )
            _persist_challenge(handle, ch2, payload2)
            with pytest.raises(RegistaError) as exc:
                _append_enrollment(handle, fixture, principal=principal, payload=payload2)
            assert exc.value.code is ErrorCode.TRUST_LOG_PRINCIPAL_KEY_ID_REUSED
            assert exc.value.detail["existing_status"] == "superseded"
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            assert state.principal_key_status[(principal, k1.key_id)] == "superseded"
            assert state.principal_key_status[(principal, k2.key_id)] == "active"
        finally:
            _close(handle, project)

    def test_rotation_reusing_an_existing_key_id_as_new_key_is_refused(self, tmp_path):
        """WI-349 (rotation arm): a rotation may not introduce a key_id already present.

        Enrol K1 -> rotate K1->K2 -> rotate K2->K1 (reusing K1 as the NEW key). The
        projection's rotation applier INSERTs unconditionally, so reusing K1's key_id
        would trip principal_keys' primary key; the replay must refuse it for the same
        reason rather than reactivating the superseded K1.
        """
        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:wi349-rot-reuse"
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys,
                genesis_document=fixture.document, root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=8)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_wi349r_k1")
            _enroll(handle, fixture, principal=principal,
                    delegation_hash=delegation_hash, key=k1)
            k2 = TrustLogKey.mint("pk_wi349r_k2")
            payload_r1, ch_r1 = _rotation_material(
                handle, fixture, principal=principal, key=k2,
                supersedes_key_id=k1.key_id, superseded_key=k1,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, ch_r1, payload_r1)
            _append_rotation(handle, fixture, principal=principal, payload=payload_r1,
                             authority="registrar", actor_id=REGISTRAR)
            # Rotate K2 -> a key whose key_id is K1 again (fresh material, stale key_id).
            k1_again = _tlogkey(k1.key_id, bytes([77]) * 32)
            payload_r2, ch_r2 = _rotation_material(
                handle, fixture, principal=principal, key=k1_again,
                supersedes_key_id=k2.key_id, superseded_key=k2,
                delegation_hash=delegation_hash,
            )
            _persist_challenge(handle, ch_r2, payload_r2)
            with pytest.raises(RegistaError) as exc:
                _append_rotation(handle, fixture, principal=principal, payload=payload_r2,
                                 authority="registrar", actor_id=REGISTRAR)
            assert exc.value.code is ErrorCode.TRUST_LOG_PRINCIPAL_KEY_ID_REUSED
            assert exc.value.detail["reason"] == "principal_key_id_reused"
            assert exc.value.detail["transition"] == "principal_key_rotated"
        finally:
            _close(handle, project)

    def test_replay_refuses_reactivation_planted_by_admission_bypass(self, tmp_path):
        """Defence in depth: a re-enrolment of a revoked key_id planted by disabling the
        writer-admission guard is DETECTED at replay with the named error — the guard binds
        BOTH the append path and the standalone verified walk, not just admission.
        """
        import regista._trust_log_writer as _w

        fixture, handle, _kf, project = _make_environment(tmp_path)
        principal = "agent:wi349-replay"
        try:
            write_trust_genesis(
                handle._mgr, keys=handle._keys,
                genesis_document=fixture.document, root_principal_id=ROOT,
            )
            _delegate(handle, fixture, max_operations=8)
            delegation_hash = _delegated_hash(handle)
            k1 = TrustLogKey.mint("pk_wi349rp_k1")
            _enroll(handle, fixture, principal=principal,
                    delegation_hash=delegation_hash, key=k1)
            _append_revocation(handle, fixture, principal=principal,
                               key_id=k1.key_id, delegation_hash=delegation_hash)
            payload2, ch2 = _enrollment_material(
                handle, fixture, principal=principal,
                delegation_hash=delegation_hash, key=k1,
            )
            _persist_challenge(handle, ch2, payload2)
            # Plant the poison by turning the write-once guard into a no-op only for the
            # append; the real guard is restored before the standalone replay.
            original = _w._check_key_id_write_once
            _w._check_key_id_write_once = lambda *a, **k: None
            try:
                _append_enrollment(handle, fixture, principal=principal, payload=payload2)
            finally:
                _w._check_key_id_write_once = original
            with handle._mgr.transaction() as conn:
                with pytest.raises(RegistaError) as exc:
                    replay_trust_state(conn, fixture.document)
            assert exc.value.code is ErrorCode.TRUST_LOG_PRINCIPAL_KEY_ID_REUSED
            assert exc.value.detail["reason"] == "principal_key_id_reused"
        finally:
            _close(handle, project)


# --- B1 (PR #59): no two live conflicting registrar delegations ---------------------


def _delegation_payload(
    fixture, *, key, not_before, not_after, scopes=None, max_operations=None
):
    return make_registrar_delegation_payload(
        trust_domain_id=fixture.trust_domain_id,
        registrar_principal_id=REGISTRAR,
        key=key,
        scopes=scopes,
        max_operations=max_operations,
        root_keys=_root_keys(fixture),
        not_before=not_before,
        not_after=not_after,
    )


def _append_delegation(handle, fixture, payload):
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


def _count_delegations(handle):
    with handle._mgr.transaction() as conn:
        rows = read_trust_log_rows(conn)
    return sum(1 for r in rows if str(r["transition"]) == "registrar_delegated")


class TestRegistrarDelegationNoLiveFork:
    """B1 (PR #59): "no two live conflicting registrars" is enforced at the DURABLE
    layer, not only in the CLI pre-check.

    A second ``registrar_delegated`` for a principal that already holds a live
    delegation with differing terms forks the credential; the writer previously
    admitted it and replay resolved it last-write-wins (silent scope/key widening). The
    guard now sits in the shared append path (writer admission) AND in the verified
    replay, so a direct ``append_trust_log_event`` — or two honest concurrent
    delegations — cannot fork it, and a forked log is detected at verification. A
    revoked prior delegation still allows a fresh one (revoke -> re-delegate), and
    byte-identical terms remain idempotent.
    """

    def test_direct_append_second_live_delegation_is_refused(self, tmp_path):
        """The DEMONSTRATED exploit: delegate key A (enrolled-only), then bypass the CLI
        and directly append a SECOND root-signed delegation for the SAME principal with
        key B and a wider scope. The writer must refuse it at admission — the poison
        never lands, and replay still reports the original key-A/enrolled-only terms."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        nb, na = _ts(-24 * 60 * 60), _ts(365 * 24 * 60 * 60)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            key_a = _tlogkey("k_reg_a", bytes([21]) * 32)
            _append_delegation(
                handle,
                fixture,
                _delegation_payload(
                    fixture,
                    key=key_a,
                    not_before=nb,
                    not_after=na,
                    scopes=["principal_key_enrolled"],
                    max_operations=None,
                ),
            )
            assert _count_delegations(handle) == 1

            # A SECOND, validly root-signed delegation for the SAME principal, different
            # key AND wider scope — the fork the CLI never sees.
            key_b = _tlogkey("k_reg_b", bytes([22]) * 32)
            with pytest.raises(RegistaError) as exc:
                _append_delegation(
                    handle,
                    fixture,
                    _delegation_payload(
                        fixture,
                        key=key_b,
                        not_before=nb,
                        not_after=na,
                        scopes=[
                            "principal_key_enrolled",
                            "principal_key_rotated",
                            "principal_key_revoked",
                        ],
                        max_operations=None,
                    ),
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc.value.detail["reason"] == "registrar_already_delegated_live"

            # The poison never landed: still one delegation, and the live registrar is
            # unchanged (key A, enrolled-only) — no silent widening.
            assert _count_delegations(handle) == 1
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            live = state.registrars[REGISTRAR]
            assert live.revoked is False
            assert live.public_key == key_a.public_key
            assert live.scopes == frozenset({"principal_key_enrolled"})
        finally:
            _close(handle, project)

    def test_identical_redelegation_direct_append_is_admitted(self, tmp_path):
        """Byte-identical terms are not a fork: the durable guard admits them
        (idempotent — mirrors the CLI no-op), so re-running is never wedged."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        nb, na = _ts(-24 * 60 * 60), _ts(365 * 24 * 60 * 60)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            key_a = _tlogkey("k_reg_a", bytes([21]) * 32)
            payload = _delegation_payload(
                fixture, key=key_a, not_before=nb, not_after=na, max_operations=3
            )
            _append_delegation(handle, fixture, payload)
            # Identical terms (same key, scope, window, max_operations): admitted.
            _append_delegation(handle, fixture, dict(payload))
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            live = state.registrars[REGISTRAR]
            assert live.revoked is False
            assert live.public_key == key_a.public_key
            assert live.max_operations == 3
        finally:
            _close(handle, project)

    def test_forked_log_is_refused_at_replay(self, tmp_path, monkeypatch):
        """Defence in depth: a forked log (two live delegations, no intervening revoke)
        that somehow reached the store is DETECTED at replay with a named error, not
        silently resolved last-write-wins. The poison is written by disabling the
        writer-admission guard only; the real guard is restored before replay."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        nb, na = _ts(-24 * 60 * 60), _ts(365 * 24 * 60 * 60)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            key_a = _tlogkey("k_reg_a", bytes([21]) * 32)
            _append_delegation(
                handle,
                fixture,
                _delegation_payload(fixture, key=key_a, not_before=nb, not_after=na),
            )
            key_b = _tlogkey("k_reg_b", bytes([22]) * 32)
            second = _delegation_payload(
                fixture, key=key_b, not_before=nb, not_after=na, max_operations=7
            )
            # Bypass the writer's admission guard to plant the fork, then restore it so
            # the standalone replay is exercised with the real check in place.
            import regista._trust_log_writer as _w

            monkeypatch.setattr(
                _w, "_check_registrar_delegation_no_live_fork", lambda *a, **k: None
            )
            _append_delegation(handle, fixture, second)
            monkeypatch.undo()
            assert _count_delegations(handle) == 2

            with handle._mgr.transaction() as conn:
                with pytest.raises(RegistaError) as exc:
                    replay_trust_state(conn, fixture.document)
            assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert exc.value.detail["reason"] == "registrar_already_delegated_live"
        finally:
            _close(handle, project)

    def test_revoke_then_redelegate_succeeds(self, tmp_path):
        """The supported refresh path is untouched: revoke the live delegation, then a
        FRESH delegation (different key/scope/window) for the same principal is admitted
        and becomes the live registrar."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        nb, na = _ts(-24 * 60 * 60), _ts(365 * 24 * 60 * 60)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            key_a = _tlogkey("k_reg_a", bytes([21]) * 32)
            _append_delegation(
                handle,
                fixture,
                _delegation_payload(fixture, key=key_a, not_before=nb, not_after=na),
            )
            deleg_hash = _delegated_hash(handle)
            # Revoke the live delegation (root threshold).
            revoke = make_registrar_revocation_payload(
                trust_domain_id=fixture.trust_domain_id,
                registrar_principal_id=REGISTRAR,
                key_id=key_a.key_id,
                delegation_event_hash=deleg_hash,
                root_keys=_root_keys(fixture),
            )
            append_trust_log_event(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                transition="registrar_revoked",
                payload=revoke,
                entity_kind="trust_domain",
                entity_id=uuid.UUID(fixture.trust_domain_id),
                principal_id=ROOT,
                authority="root",
            )
            # A fresh delegation with DIFFERENT terms is now admitted (the prior is
            # revoked), and replays as the live registrar.
            key_b = _tlogkey("k_reg_b", bytes([22]) * 32)
            _append_delegation(
                handle,
                fixture,
                _delegation_payload(
                    fixture,
                    key=key_b,
                    not_before=nb,
                    not_after=na,
                    scopes=["principal_key_enrolled"],
                    max_operations=9,
                ),
            )
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            live = state.registrars[REGISTRAR]
            assert live.revoked is False
            assert live.public_key == key_b.public_key
            assert live.scopes == frozenset({"principal_key_enrolled"})
            assert live.max_operations == 9
        finally:
            _close(handle, project)

    def test_two_concurrent_delegations_only_one_succeeds(self, tmp_path):
        """Two honest, CONCURRENT delegations for the same principal with differing
        terms hit the same fork with no bypass: the chain-head lock serialises them and
        exactly one wins; the loser is refused ``registrar_already_delegated_live``."""
        fixture, handle, _kf, project = _make_environment(tmp_path)
        nb, na = _ts(-24 * 60 * 60), _ts(365 * 24 * 60 * 60)
        try:
            write_trust_genesis(
                handle._mgr,
                keys=handle._keys,
                genesis_document=fixture.document,
                root_principal_id=ROOT,
            )
            second = Regista(DSN, project, hmac_key_path=_kf)
            results: list[bool] = []
            errors: list[RegistaError] = []
            lock = threading.Lock()

            def _attempt(h, max_ops):
                key = _tlogkey(f"k_reg_{max_ops}", bytes([30 + max_ops]) * 32)
                payload = _delegation_payload(
                    fixture, key=key, not_before=nb, not_after=na, max_operations=max_ops
                )
                try:
                    _append_delegation(h, fixture, payload)
                    with lock:
                        results.append(True)
                except RegistaError as e:
                    with lock:
                        errors.append(e)

            t1 = threading.Thread(target=_attempt, args=(handle, 3))
            t2 = threading.Thread(target=_attempt, args=(second, 8))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            assert len(results) == 1
            assert len(errors) == 1
            assert errors[0].code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
            assert errors[0].detail["reason"] == "registrar_already_delegated_live"
            assert _count_delegations(handle) == 1
            second.close()
        finally:
            _close(handle, project)


# --- WI-349 convergence guarantee: replay ≡ projection over random histories ----------


class TestReplayProjectionConvergence:
    """The property that proves the WI-347/348/349 family is closed.

    A randomised, DETERMINISTICALLY SEEDED generator drives enrol / rotate(dual) /
    revoke / recovery sequences for three principals through the real durable writer
    (append admission + verified replay), and after every ADMITTED event rebuilds the
    projection from the same durable log and asserts:

    * the projection rebuild never raises — every event the WRITER ADMITS, replayed and
      rebuilt into the projection, the projection admits too (the exact guarantee WI-349
      restores; before the fix a re-enrolment of a revoked key_id was admitted by replay yet
      raised PRINCIPAL_KEY_ALREADY_EXISTS in the rebuild), and
    * the replay's ``(status, public_key)`` map EQUALS the projection table's and an
      independent in-test model's after every step. The comparison carries the key MATERIAL,
      not status alone: a same-key_id/same-status but different-BYTES disagreement would
      otherwise slip past (it cannot occur while write-once holds, but the evidence asserts
      byte-equality defensively rather than assuming it).

    Scope of the guarantee (honest form): this proves that *every writer-ADMITTED history,
    replayed and rebuilt into the projection, yields identical ``(status, public_key)``
    state*. It does NOT claim raw-applier bidirectional equivalence: the writer's ADMISSION
    is strictly STRONGER than the raw projection appliers, which would absorb some histories
    the writer rejects (e.g. enrol-over-active, an active key_id re-used with different bytes,
    a duplicate revocation). That is a safe TIGHTENING — writer-admitted ⊆ raw-applier-accepted
    — not an equivalence, so no admitted history can diverge on rebuild.

    It also asserts the *rejection* side with per-category coverage counters: the generator
    emits the poison shapes (write-once stale reuse via enrol AND rotate, same-material alias,
    wrong-supersedes, enrol-over-active, and same-active-key_id-different-bytes) and each is
    refused by the writer; the counters PROVE each valid op was admitted, each poison op was
    refused at least once, and ``principal_key_id_reused`` appears among the refusal reasons,
    so the property cannot pass vacuously.
    Determinism: a fixed seed LIST, each seeding its own ``random.Random`` that selects ops and
    (via ``randbytes``) key material; no ``os.urandom`` or wall-clock feeds a decision, so a
    failure reproduces from (seed, op index).

    Invariants exercised: I1 key_id write-once per principal (PK (principal_id, key_id)),
    I2 at most one active key per principal (partial unique index), I3 no reactivation of
    a superseded/revoked key (falls out of I1).
    """

    def test_replay_and_projection_converge_over_random_histories(self, tmp_path):
        import random

        # A FIXED seed list (finding 3): each seed drives one independent sequence with its
        # own freshly-seeded ``random.Random``, so the whole run is deterministic and a
        # failure reproduces from (seed, op index). 12 seeds x 40 ops x 3 principals meets or
        # exceeds the Opus probe (12/40/3) while staying well inside a reasonable runtime.
        seeds = [1234, 2718, 3141, 4669, 5772, 6022, 7071, 8090, 9109, 11235, 13195, 16180]
        ops_per_sequence = 40
        principals = ["agent:conv-a", "agent:conv-b", "agent:conv-c"]

        accepts = 0
        rejects = 0
        reject_reasons: set[str] = set()
        # Per-category counters (finding 3): PROVE the run exercised each valid op AND each
        # poison shape rather than possibly skipping the interesting ones. Asserted > 0 at the
        # end, split by admitted/refused so a category cannot masquerade as covered by only
        # ever hitting the branch that no-ops.
        op_admitted: dict[str, int] = {}
        op_refused: dict[str, int] = {}
        counter = [0]
        rng = random.Random(seeds[0])

        def _fresh_key(principal, *, key_id=None, seed=None):
            counter[0] += 1
            kid = key_id or f"pk_conv_{counter[0]}"
            return _tlogkey(kid, seed if seed is not None else rng.randbytes(32))

        def _replay_map(handle, fixture):
            # (principal_id, key_id) -> (status, public_key). The public-key half is the
            # defensive byte-equality check (finding 1): comparing status ALONE would let a
            # same-key_id/same-status but different-MATERIAL disagreement slip past. It cannot
            # occur while write-once holds, but the evidence asserts it rather than assuming it.
            with handle._mgr.transaction() as conn:
                state = replay_trust_state(conn, fixture.document)
            return {
                k: (status, state.principal_public_keys[k])
                for k, status in state.principal_key_status.items()
            }

        def _projection_map(handle):
            return {
                (e.principal_id, e.key_id): (e.status, e.public_key)
                for e in list_principal_keys(handle._mgr)
            }

        for seq, seed in enumerate(seeds):
            # Reseed per sequence so each is independently reproducible. ``_fresh_key`` and the
            # op selection below read this method-local ``rng`` at call time, so the reassignment
            # is visible to them.
            rng = random.Random(seed)
            seq_dir = tmp_path / f"seq{seq}"
            seq_dir.mkdir()
            fixture, handle, _kf, project = _make_environment(seq_dir)
            model: dict[str, dict] = {
                p: {"keys": {}, "active": None} for p in principals
            }
            try:
                write_trust_genesis(
                    handle._mgr, keys=handle._keys,
                    genesis_document=fixture.document, root_principal_id=ROOT,
                )
                # Unlimited registrar operations so op selection is never constrained by a
                # budget (rejected admissions never commit, so they never consume a slot
                # anyway; None simply removes the ceiling for the accepted ones).
                _delegate(handle, fixture, max_operations=None)
                delegation_hash = _delegated_hash(handle)

                for _ in range(ops_per_sequence):
                    p = rng.choice(principals)
                    m = model[p]
                    active = m["active"]
                    stale = [
                        kid for kid, rec in m["keys"].items()
                        if rec["status"] in ("superseded", "revoked")
                    ]
                    # Applicable ops as (name, expect_accept) given the model state.
                    ops: list[str] = []
                    if active is None:
                        ops.append("enroll_fresh")
                    else:
                        ops += [
                            "rotate_dual", "revoke_active", "recovery",
                            "reenroll_active_same", "enroll_over_active", "enroll_alias",
                            "enroll_active_diffbytes",
                        ]
                    if stale:
                        ops.append("enroll_reuse_stale")
                        if active is not None:
                            ops += ["rotate_reuse_stale_new", "rotate_wrong_supersede"]
                    op = rng.choice(ops)

                    expect_accept = op in {
                        "enroll_fresh", "rotate_dual", "revoke_active", "recovery",
                        "reenroll_active_same",
                    }

                    def _run_enroll(key):
                        payload, ch = _enrollment_material(
                            handle, fixture, principal=p,
                            delegation_hash=delegation_hash, key=key,
                        )
                        _persist_challenge(handle, ch, payload)
                        _append_enrollment(handle, fixture, principal=p, payload=payload)

                    def _run_rotation(key, supersedes_key_id, superseded_key,
                                      *, mode="dual"):
                        payload, ch = _rotation_material(
                            handle, fixture, principal=p, key=key,
                            supersedes_key_id=supersedes_key_id,
                            superseded_key=superseded_key, mode=mode,
                            recovery_reason="key-lost" if mode == "recovery" else None,
                            root_keys=_root_keys(fixture) if mode == "recovery" else None,
                            delegation_hash=delegation_hash,
                            authorized_by=_make_root_auth() if mode == "recovery" else None,
                        )
                        _persist_challenge(handle, ch, payload)
                        _append_rotation(
                            handle, fixture, principal=p, payload=payload,
                            authority="root" if mode == "recovery" else "registrar",
                            actor_id=ROOT if mode == "recovery" else REGISTRAR,
                        )

                    # Prepare op-specific inputs and the mutation to apply on acceptance.
                    # `action` runs the append; `apply_on_accept` mutates the in-test model
                    # only if the append is admitted. Both are called within THIS iteration,
                    # so they close over the current locals directly.
                    def apply_on_accept():
                        return None

                    if op == "enroll_fresh":
                        key = _fresh_key(p)

                        def action():
                            _run_enroll(key)

                        def apply_on_accept():
                            m["keys"][key.key_id] = {"obj": key, "status": "active"}
                            m["active"] = key.key_id
                    elif op == "enroll_over_active":
                        key = _fresh_key(p)

                        def action():
                            _run_enroll(key)
                    elif op == "enroll_alias":
                        active_obj = m["keys"][active]["obj"]
                        key = _fresh_key(p, seed=active_obj.seed)

                        def action():
                            _run_enroll(key)
                    elif op == "reenroll_active_same":
                        key = m["keys"][active]["obj"]

                        def action():
                            _run_enroll(key)
                        # apply_on_accept stays the no-op default: idempotent re-enrol.
                    elif op == "enroll_active_diffbytes":
                        # Poison (finding 3): re-enrol the CURRENTLY ACTIVE key_id with DIFFERENT
                        # material. The write-once helper's single tolerated reuse requires the
                        # bytes to match the stored active key, so fresh bytes under the same
                        # key_id must be refused (`principal_key_id_reused`) — the case a
                        # status-only comparison could never have caught.
                        active_obj = m["keys"][active]["obj"]
                        key = _fresh_key(p, key_id=active_obj.key_id)

                        def action():
                            _run_enroll(key)
                    elif op == "enroll_reuse_stale":
                        key = m["keys"][rng.choice(stale)]["obj"]

                        def action():
                            _run_enroll(key)
                    elif op == "rotate_dual":
                        old_obj = m["keys"][active]["obj"]
                        key = _fresh_key(p)

                        def action():
                            _run_rotation(key, old_obj.key_id, old_obj)

                        def apply_on_accept():
                            m["keys"][old_obj.key_id]["status"] = "superseded"
                            m["keys"][key.key_id] = {"obj": key, "status": "active"}
                            m["active"] = key.key_id
                    elif op == "recovery":
                        old_obj = m["keys"][active]["obj"]
                        key = _fresh_key(p)

                        def action():
                            _run_rotation(key, old_obj.key_id, old_obj, mode="recovery")

                        def apply_on_accept():
                            m["keys"][old_obj.key_id]["status"] = "superseded"
                            m["keys"][key.key_id] = {"obj": key, "status": "active"}
                            m["active"] = key.key_id
                    elif op == "revoke_active":
                        revoked_kid = active

                        def action():
                            _append_revocation(
                                handle, fixture, principal=p, key_id=revoked_kid,
                                delegation_hash=delegation_hash,
                            )

                        def apply_on_accept():
                            m["keys"][revoked_kid]["status"] = "revoked"
                            m["active"] = None
                    elif op == "rotate_reuse_stale_new":
                        old_obj = m["keys"][active]["obj"]
                        # stale key_id, fresh material — reuse a retired key_id as the NEW key.
                        key = _fresh_key(p, key_id=rng.choice(stale))

                        def action():
                            _run_rotation(key, old_obj.key_id, old_obj)
                    elif op == "rotate_wrong_supersede":
                        stale_obj = m["keys"][rng.choice(stale)]["obj"]
                        key = _fresh_key(p)

                        def action():
                            _run_rotation(key, stale_obj.key_id, stale_obj)
                    else:  # pragma: no cover - guarded by the ops list
                        raise AssertionError(op)

                    try:
                        action()
                        admitted = True
                    except RegistaError as exc:
                        admitted = False
                        rejects += 1
                        op_refused[op] = op_refused.get(op, 0) + 1
                        reject_reasons.add(str(exc.detail.get("reason")))
                        assert not expect_accept, (
                            f"op {op!r} was expected to be admitted but raised "
                            f"{exc.code}/{exc.detail.get('reason')}"
                        )

                    if not admitted:
                        continue

                    assert expect_accept, f"op {op!r} was expected to be refused but was admitted"
                    accepts += 1
                    op_admitted[op] = op_admitted.get(op, 0) + 1
                    apply_on_accept()

                    # Convergence: rebuild the projection from the SAME durable log — it
                    # must not raise — and its key-status map must equal the replay's.
                    rebuild_projection(
                        handle._mgr, project=handle._mgr.project,
                        genesis_document=fixture.document,
                    )
                    # Each map is (principal_id, key_id) -> (status, public_key), so this asserts
                    # STATUS *and* byte-identical key MATERIAL agree across all three sources.
                    replay_map = _replay_map(handle, fixture)
                    projection_map = _projection_map(handle)
                    assert replay_map == projection_map, (
                        f"replay/projection diverged after {op!r}: "
                        f"replay={replay_map} projection={projection_map}"
                    )
                    # The replay map must also match the independent in-test model, material
                    # included.
                    model_map = {
                        (pr, kid): (rec["status"], rec["obj"].public_key)
                        for pr, mm in model.items()
                        for kid, rec in mm["keys"].items()
                    }
                    assert replay_map == model_map, (
                        f"replay diverged from the model after {op!r}: "
                        f"replay={replay_map} model={model_map}"
                    )
            finally:
                _close(handle, project)

        # The run must have exercised BOTH sides, including the WI-349 write-once refusal,
        # or it proves nothing.
        assert accepts > 0
        assert rejects > 0
        assert "principal_key_id_reused" in reject_reasons

        # Coverage (finding 3): prove each VALID op was actually ADMITTED at least once and
        # each POISON op was actually REFUSED at least once, so the property cannot pass
        # vacuously by never generating the interesting shapes. A category present only in the
        # wrong column would fail here, not slip by.
        for valid_op in ("enroll_fresh", "rotate_dual", "recovery", "revoke_active"):
            assert op_admitted.get(valid_op, 0) > 0, (
                f"valid op {valid_op!r} was never admitted: "
                f"admitted={op_admitted} refused={op_refused}"
            )
        for poison_op in (
            "enroll_reuse_stale",          # write-once stale reuse via ENROL
            "rotate_reuse_stale_new",      # write-once stale reuse via ROTATE (new key_id)
            "enroll_alias",                # same-material alias under a different key_id
            "rotate_wrong_supersede",      # rotation naming a non-current (stale) key
            "enroll_over_active",          # a second enrol while a key is already active
            "enroll_active_diffbytes",     # same active key_id, DIFFERENT bytes
        ):
            assert op_refused.get(poison_op, 0) > 0, (
                f"poison op {poison_op!r} was never refused: "
                f"admitted={op_admitted} refused={op_refused}"
            )
