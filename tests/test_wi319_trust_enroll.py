"""WI-319 (2/3) ``regista trust enroll``: the v6-native enrollment verifier.

Piece 1 (`trust init-log`) wrote the trust log's genesis; this is the verifier/commit
counterpart of the `signer` client commands. It consumes the possession proof the
enrollee produced and appends a registrar-authorised ``principal_key_enrolled`` event
through the trust-log-native writer, which `rebuild-projection` then materialises into
``principal_keys`` (TRUST-DOMAIN.md §5.5/§5.9).

These are real, DSN-backed exercises of the CLI handlers: a fresh principal enrolls
end to end (issue challenge -> sign-possession -> verifier commit) and then shows up in
the projection; a wrong/absent proof is refused with no write; an unauthorised
authorising key is refused; enrolling before the trust log exists is refused cleanly;
re-enrolling the same key is a clean no-op; and --dry-run writes nothing.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import uuid
from datetime import datetime

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_solo
from _trust_log_fixtures import TrustLogKey, _ts, make_registrar_delegation_payload

from regista import Regista
from regista._cli import (
    cmd_signer_sign_possession,
    cmd_trust_enroll,
    cmd_trust_init_log,
    cmd_trust_rebuild_projection,
)
from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._principal_keys import _compute_fingerprint, list_principal_keys
from regista._trust_log_writer import append_trust_log_event
from regista.principal_lifecycle import PossessionChallenge
from regista.testing import drop_project_schema

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR = "service:registrar-1"
REGISTRAR_SEED = bytes([7]) * 32
ENROLLEE = "agent:host-01"


@pytest.fixture(autouse=True)
def _producer_env():
    import os

    os.environ.setdefault("REGISTA_PRODUCER_HARNESS", "pytest")
    os.environ.setdefault("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL", "test-fixture")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def _seed_file(path, seed: bytes) -> str:
    path.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    return str(path)


def _write_json(path, obj) -> str:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def _root_keyfile(path, fx, *, extra: dict[str, bytes] | None = None) -> str:
    """A key file carrying the root signer plus any extra principals (registrar)."""
    sid = fx.signer_ids[0]
    keys = [
        {
            "key_id": f"k_{sid}",
            "scheme": "ed25519",
            "alg": "Ed25519",
            "secret": base64.b64encode(fx.seeds[sid]).decode("ascii"),
            "encoding": "base64",
            "public_key": base64.b64encode(fx.public_keys[sid]).decode("ascii"),
            "principal_id": ROOT_PRINCIPAL,
            "role": "actor",
            "status": "active",
        }
    ]
    for principal_id, seed in (extra or {}).items():
        sk = nacl.signing.SigningKey(seed)
        keys.append(
            {
                "key_id": "k_registrar",
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
    path.write_text(json.dumps({"keys": keys}), encoding="utf-8")
    return str(path)


def _ns(**kwargs) -> argparse.Namespace:
    base = dict(
        dsn=DSN,
        project=None,
        hmac_key_path=None,
        principal=ENROLLEE,
        public_key=None,
        issue_challenge=False,
        ttl_minutes=None,
        proof=None,
        proof_file=None,
        key=None,
        registrar_principal_id=None,
        custody_backend=None,
        policy_ref=None,
        genesis=None,
        dry_run=False,
        json=True,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


def _sign_possession_via_cli(tmp_path, enrollee_secret_ref, challenge_json: str) -> dict:
    """Drive the real `signer sign-possession` handler and return the proof dict."""
    ns = argparse.Namespace(
        principal=ENROLLEE,
        secret_ref=enrollee_secret_ref,
        custody_mode="file",
        challenge=challenge_json,
        json=True,
    )
    return json.loads(_capture(cmd_signer_sign_possession, ns))


@pytest.fixture
def env(tmp_path):
    """An initialised trust log with a live registrar delegated for enrolment."""
    project = f"wi319e_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=project)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    keyfile = _root_keyfile(tmp_path / "keys.json", fx, extra={REGISTRAR: REGISTRAR_SEED})

    # Genesis (piece 1).
    cmd_trust_init_log(
        argparse.Namespace(
            dsn=DSN,
            project=project,
            hmac_key_path=None,
            genesis=genesis,
            key=_seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]]),
            root_principal_id=ROOT_PRINCIPAL,
            dry_run=False,
            json=False,
        )
    )

    # Delegate a registrar (root authority) so enrolments have an authoriser. This is
    # the same public writer the WI-301 suite uses to build a registrar.
    reg_key = TrustLogKey(
        key_id="k_registrar",
        seed=REGISTRAR_SEED,
        public_key=bytes(nacl.signing.SigningKey(REGISTRAR_SEED).verify_key),
        fingerprint=_compute_fingerprint(
            bytes(nacl.signing.SigningKey(REGISTRAR_SEED).verify_key), "ed25519"
        ),
    )
    root_tl = TrustLogKey(
        key_id=f"k_{fx.signer_ids[0]}",
        seed=fx.seeds[fx.signer_ids[0]],
        public_key=fx.public_keys[fx.signer_ids[0]],
        fingerprint=fx.fingerprints[fx.signer_ids[0]],
    )
    deleg = make_registrar_delegation_payload(
        trust_domain_id=fx.trust_domain_id,
        registrar_principal_id=REGISTRAR,
        key=reg_key,
        max_operations=None,
        root_keys=[root_tl],
        not_before=_ts(-3600),
        not_after=_ts(365 * 24 * 3600),
    )
    handle = Regista(DSN, project, keyfile)
    try:
        append_trust_log_event(
            handle._mgr,
            keys=handle._keys,
            genesis_document=fx.document,
            transition="registrar_delegated",
            payload=deleg,
            entity_kind="trust_domain",
            entity_id=uuid.UUID(fx.trust_domain_id),
            principal_id=ROOT_PRINCIPAL,
            authority="root",
        )
    finally:
        handle.close()

    reg_seed_path = _seed_file(tmp_path / "reg.seed", REGISTRAR_SEED)
    yield {
        "project": project,
        "fx": fx,
        "genesis": genesis,
        "keyfile": keyfile,
        "reg_seed_path": reg_seed_path,
        "tmp_path": tmp_path,
    }
    drop_project_schema(DSN, project)


def _make_enrollee(tmp_path):
    """A custodied enrollee key via the real client signer; returns (public_b64, ref)."""
    from regista.client_signer import ClientSigner

    signer = ClientSigner.generate(
        ENROLLEE, backend="file", private_key_dir=str(tmp_path / "custody")
    )
    return signer.identity.to_dict()["public_key"], signer.identity.secret_ref


def _issue_and_sign(env, public_b64, secret_ref, *, principal=ENROLLEE):
    """Phase 1 (issue) + client sign-possession -> the proof dict."""
    challenge_out = _capture(
        cmd_trust_enroll,
        _ns(
            project=env["project"],
            genesis=env["genesis"],
            principal=principal,
            public_key=public_b64,
            issue_challenge=True,
        ),
    )
    challenge = json.loads(challenge_out)
    proof = _sign_possession_via_cli(env["tmp_path"], secret_ref, json.dumps(challenge))
    return challenge, proof


def _count_enrolled_events(project: str) -> int:
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE transition = 'principal_key_enrolled'"
            ).fetchone()
        return int(row["n"])
    finally:
        mgr.close()


def _challenge_used(project: str, challenge_id: str) -> bool:
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT used FROM lifecycle_challenges WHERE challenge_id = %s",
                [uuid.UUID(challenge_id)],
            ).fetchone()
        return bool(row["used"]) if row else False
    finally:
        mgr.close()


# --------------------------------------------------------------------------- tests


def test_enroll_end_to_end_then_projection_shows_key(env):
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)

    result = json.loads(
        _capture(
            cmd_trust_enroll,
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            ),
        )
    )
    assert result["ok"] is True
    assert result["already_enrolled"] is False
    assert result["transition"] == "principal_key_enrolled"
    assert _count_enrolled_events(env["project"]) == 1

    # The projection is materialised by rebuild-projection (§5.9), not by the append.
    cmd_trust_rebuild_projection(
        argparse.Namespace(
            dsn=DSN,
            project=env["project"],
            hmac_key_path=None,
            genesis=env["genesis"],
            dry_run=False,
            json=False,
        )
    )
    mgr = ConnectionManager(DSN, env["project"])
    try:
        mgr.open()
        entries = list_principal_keys(mgr, principal_id=ENROLLEE)
    finally:
        mgr.close()
    assert len(entries) == 1
    assert entries[0].principal_id == ENROLLEE
    assert entries[0].status == "active"
    assert entries[0].fingerprint == _compute_fingerprint(
        base64.b64decode(public_b64), "ed25519"
    )


def test_wrong_possession_proof_is_refused_without_writing(env):
    public_b64, _secret_ref = _make_enrollee(env["tmp_path"])
    # Issue for the real enrollee key, but sign with an IMPOSTOR key.
    challenge_out = _capture(
        cmd_trust_enroll,
        _ns(
            project=env["project"],
            genesis=env["genesis"],
            public_key=public_b64,
            issue_challenge=True,
        ),
    )
    challenge = json.loads(challenge_out)
    pc = PossessionChallenge(
        challenge_id=challenge["challenge_id"],
        operation_id=challenge["operation_id"],
        operation_digest=challenge["operation_digest"],
        project=challenge["project"],
        principal_id=challenge["principal_id"],
        fingerprint=challenge["fingerprint"],
        scheme=challenge["scheme"],
        verifier_nonce=challenge["verifier_nonce"],
        issued_at=datetime.fromisoformat(challenge["issued_at"].replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(challenge["expires_at"].replace("Z", "+00:00")),
        trust_domain_id=challenge["trust_domain_id"],
        enrollment_request_digest=challenge["enrollment_request_digest"],
    )
    impostor = nacl.signing.SigningKey.generate()
    bad_proof = {
        "format": "signature-v1",
        "challenge_id": challenge["challenge_id"],
        "operation_id": challenge["operation_id"],
        "operation_digest": challenge["operation_digest"],
        "signature": base64.b64encode(impostor.sign(pc.signing_bytes()).signature).decode(),
    }
    with pytest.raises(RegistaError) as exc:
        cmd_trust_enroll(
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(bad_proof),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            )
        )
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    # No event written and the challenge is NOT burned (fail-closed pre-check).
    assert _count_enrolled_events(env["project"]) == 0
    assert _challenge_used(env["project"], challenge["challenge_id"]) is False


def test_absent_proof_is_refused(env):
    public_b64, _secret_ref = _make_enrollee(env["tmp_path"])
    _issue_and_sign(env, public_b64, _secret_ref)
    with pytest.raises(RegistaError) as exc:
        cmd_trust_enroll(
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof="   ",
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            )
        )
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert _count_enrolled_events(env["project"]) == 0


def test_unauthorized_registrar_is_refused(env):
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    with pytest.raises(RegistaError) as exc:
        cmd_trust_enroll(
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=env["reg_seed_path"],
                # A principal that was never delegated as a registrar.
                registrar_principal_id="service:rogue-registrar",
            )
        )
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert exc.value.detail["reason"] == "no_live_registrar_delegation"
    assert _count_enrolled_events(env["project"]) == 0
    assert _challenge_used(env["project"], _challenge["challenge_id"]) is False


def test_authorizing_key_not_the_delegated_key_is_refused(env):
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    # The registrar principal IS delegated, but --key is a different seed.
    wrong_seed = _seed_file(env["tmp_path"] / "wrong.seed", bytes([9]) * 32)
    with pytest.raises(RegistaError) as exc:
        cmd_trust_enroll(
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=wrong_seed,
                registrar_principal_id=REGISTRAR,
            )
        )
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert exc.value.detail["reason"] == "authorizing_key_not_the_delegated_key"
    assert _count_enrolled_events(env["project"]) == 0


def test_enroll_before_trust_log_exists_is_refused_cleanly(tmp_path):
    # A minted genesis whose trust log was never init-log'd.
    project = f"wi319e_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=project)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    enrollee = nacl.signing.SigningKey.generate()
    pub = base64.b64encode(bytes(enrollee.verify_key)).decode()
    try:
        with pytest.raises(RegistaError) as exc:
            cmd_trust_enroll(
                _ns(
                    project=project,
                    genesis=genesis,
                    public_key=pub,
                    issue_challenge=True,
                )
            )
        assert exc.value.code is ErrorCode.TRUST_LOG_STORE_UNAVAILABLE
    finally:
        drop_project_schema(DSN, project)


def test_reenroll_same_key_is_idempotent_noop(env):
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    first = json.loads(
        _capture(
            cmd_trust_enroll,
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            ),
        )
    )
    assert first["already_enrolled"] is False
    assert _count_enrolled_events(env["project"]) == 1

    # A fresh challenge + proof for the SAME (principal, key): the verifier sees the key
    # is already active and no-ops rather than forking a second enrolment.
    _challenge2, proof2 = _issue_and_sign(env, public_b64, secret_ref)
    second = json.loads(
        _capture(
            cmd_trust_enroll,
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof2),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            ),
        )
    )
    assert second["already_enrolled"] is True
    # Still exactly one enrolment event — no duplicate, no fork.
    assert _count_enrolled_events(env["project"]) == 1


def test_dry_run_writes_nothing(env):
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    plan = json.loads(
        _capture(
            cmd_trust_enroll,
            _ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
                dry_run=True,
            ),
        )
    )
    assert plan["dry_run"] is True
    assert plan["would_write"] is True
    # A dry run consumes nothing and writes nothing.
    assert _count_enrolled_events(env["project"]) == 0
    assert _challenge_used(env["project"], challenge["challenge_id"]) is False
