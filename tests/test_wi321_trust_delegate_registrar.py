"""WI-321 (3/3) ``regista trust delegate-registrar``: root delegates registrar power.

The missing middle link of the v6 provisioning chain: root-genesis (``trust init-log``)
-> ROOT delegates a registrar (THIS command) -> the registrar enrols host keys
(``trust enroll``). Enrolment is registrar-authorised, so until a root-signed
``registrar_delegated`` event exists nothing can be enrolled.

These are real, DSN-backed exercises of the CLI handler. The keystone is the end-to-end
chain: init a trust log, delegate a registrar via THIS command, and then confirm
``trust enroll`` SUCCEEDS under that delegation and the key lands in the projection.
Fail-closed paths: delegating before the log exists, a wrong/non-root key, a k-of-n
genesis signed by a single seed, ``--dry-run`` writing nothing, scope enforcement on the
enrol path, non-canonical ids, and re-delegation (identical no-op / different refusal).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import uuid

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_co_signed, mint_solo

from regista._cli import (
    cmd_signer_sign_possession,
    cmd_trust_delegate_registrar,
    cmd_trust_enroll,
    cmd_trust_init_log,
    cmd_trust_rebuild_projection,
)
from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._principal_keys import _compute_fingerprint, list_principal_keys
from regista.testing import drop_project_schema

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR = "service:registrar-1"
REGISTRAR_KEY_ID = "k_registrar"
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


def _root_keyfile(path, fx) -> str:
    """A key file carrying only the root signer, bound to ROOT_PRINCIPAL.

    Used solely by ``rebuild-projection`` (which opens a Regista handle needing a key
    path). ``delegate-registrar`` and ``init-log`` synthesise their own root key file
    from the seed, so this never carries the registrar.
    """
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
    path.write_text(json.dumps({"keys": keys}), encoding="utf-8")
    return str(path)


def _init_log(fx, genesis, tmp_path, project) -> None:
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


def _deleg_ns(**kwargs) -> argparse.Namespace:
    base = dict(
        dsn=DSN,
        project=None,
        hmac_key_path=None,
        registrar_principal_id=REGISTRAR,
        registrar_public_key=None,
        registrar_key_id=REGISTRAR_KEY_ID,
        key=None,
        root_principal_id=ROOT_PRINCIPAL,
        scope=None,
        not_before=None,
        not_after=None,
        max_operations=None,
        genesis=None,
        dry_run=False,
        json=True,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


def _enroll_ns(**kwargs) -> argparse.Namespace:
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


def _count_events(project: str, transition: str) -> int:
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE transition = %s",
                [transition],
            ).fetchone()
        return int(row["n"])
    finally:
        mgr.close()


@pytest.fixture
def env(tmp_path):
    """An INITIALISED trust log with NO registrar yet (that is the command under test)."""
    project = f"wi321_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=project)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    keyfile = _root_keyfile(tmp_path / "keys.json", fx)
    _init_log(fx, genesis, tmp_path, project)

    # A fresh registrar keypair. Its public key is what we grant; its seed is what the
    # registrar later signs enrolments with (the enrol --key).
    reg_sk = nacl.signing.SigningKey.generate()
    reg_public_b64 = base64.b64encode(bytes(reg_sk.verify_key)).decode("ascii")
    reg_seed_path = _seed_file(tmp_path / "reg.seed", bytes(reg_sk))

    root_seed_path = _seed_file(tmp_path / "root2.seed", fx.seeds[fx.signer_ids[0]])

    yield {
        "project": project,
        "fx": fx,
        "genesis": genesis,
        "keyfile": keyfile,
        "reg_public_b64": reg_public_b64,
        "reg_seed_path": reg_seed_path,
        "root_seed_path": root_seed_path,
        "tmp_path": tmp_path,
    }
    drop_project_schema(DSN, project)


def _delegate(env, **overrides) -> dict:
    ns = _deleg_ns(
        project=env["project"],
        genesis=env["genesis"],
        registrar_public_key=env["reg_public_b64"],
        key=env["root_seed_path"],
        **overrides,
    )
    return json.loads(_capture(cmd_trust_delegate_registrar, ns))


# --- enrol drivers (mirror the WI-319 enroll suite) --------------------------------


def _make_enrollee(tmp_path, *, sub="custody"):
    from regista.client_signer import ClientSigner

    signer = ClientSigner.generate(
        ENROLLEE, backend="file", private_key_dir=str(tmp_path / sub)
    )
    return signer.identity.to_dict()["public_key"], signer.identity.secret_ref


def _sign_possession_via_cli(secret_ref, challenge_json: str) -> dict:
    ns = argparse.Namespace(
        principal=ENROLLEE,
        secret_ref=secret_ref,
        custody_mode="file",
        challenge=challenge_json,
        json=True,
    )
    return json.loads(_capture(cmd_signer_sign_possession, ns))


def _issue_and_sign(env, public_b64, secret_ref):
    challenge_out = _capture(
        cmd_trust_enroll,
        _enroll_ns(
            project=env["project"],
            genesis=env["genesis"],
            public_key=public_b64,
            issue_challenge=True,
        ),
    )
    challenge = json.loads(challenge_out)
    proof = _sign_possession_via_cli(secret_ref, json.dumps(challenge))
    return challenge, proof


def _commit_enroll(env, public_b64, proof):
    return json.loads(
        _capture(
            cmd_trust_enroll,
            _enroll_ns(
                project=env["project"],
                genesis=env["genesis"],
                public_key=public_b64,
                proof=json.dumps(proof),
                key=env["reg_seed_path"],
                registrar_principal_id=REGISTRAR,
            ),
        )
    )


# --------------------------------------------------------------------------- tests


def test_delegate_then_enroll_succeeds_end_to_end(env):
    """The keystone: delegate a registrar, then a full enrolment SUCCEEDS under it."""
    result = _delegate(env)
    assert result["ok"] is True
    assert result["already_delegated"] is False
    assert result["transition"] == "registrar_delegated"
    assert result["registrar_principal_id"] == REGISTRAR
    assert result["authority"] == "root"
    assert _count_events(env["project"], "registrar_delegated") == 1

    # Now the whole chain works: issue -> sign-possession -> registrar-authorised commit.
    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    enroll_result = _commit_enroll(env, public_b64, proof)
    assert enroll_result["ok"] is True
    assert enroll_result["already_enrolled"] is False
    assert enroll_result["transition"] == "principal_key_enrolled"
    assert _count_events(env["project"], "principal_key_enrolled") == 1

    # And the projection materialises the enrolled key (self-contained: explicit keyfile).
    cmd_trust_rebuild_projection(
        argparse.Namespace(
            dsn=DSN,
            project=env["project"],
            hmac_key_path=env["keyfile"],
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
    assert entries[0].status == "active"
    assert entries[0].fingerprint == _compute_fingerprint(
        base64.b64decode(public_b64), "ed25519"
    )


def test_delegate_before_init_is_refused_cleanly(env):
    """Delegating into an UNINITIALISED trust log is a clean TRUST_LOG_STORE_UNAVAILABLE."""
    project = f"wi321none_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=project)
    genesis = _write_json(env["tmp_path"] / "g2.json", fx.document)
    with pytest.raises(RegistaError) as exc:
        cmd_trust_delegate_registrar(
            _deleg_ns(
                project=project,
                genesis=genesis,
                registrar_public_key=env["reg_public_b64"],
                key=_seed_file(env["tmp_path"] / "r2.seed", fx.seeds[fx.signer_ids[0]]),
            )
        )
    assert exc.value.code is ErrorCode.TRUST_LOG_STORE_UNAVAILABLE
    # No schema/log was created for the un-init project.
    with contextlib.suppress(Exception):
        drop_project_schema(DSN, project)


def test_non_root_key_is_refused(env):
    """A key whose fingerprint is not a genesis signer is refused, nothing written."""
    impostor = nacl.signing.SigningKey.generate()
    bad_seed = _seed_file(env["tmp_path"] / "impostor.seed", bytes(impostor))
    with pytest.raises(RegistaError) as exc:
        cmd_trust_delegate_registrar(_delegate_ns_for(env, key=bad_seed))
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    assert _count_events(env["project"], "registrar_delegated") == 0


def _delegate_ns_for(env, **overrides) -> argparse.Namespace:
    fields = dict(
        project=env["project"],
        genesis=env["genesis"],
        registrar_public_key=env["reg_public_b64"],
        key=env["root_seed_path"],
    )
    fields.update(overrides)
    return _deleg_ns(**fields)


def test_k_of_n_refused_from_single_root_seed(tmp_path):
    """A co-signed (threshold 2) genesis cannot be delegated with one --key seed.

    The threshold check is genesis-intrinsic and runs before the store probe (mirroring
    ``init-log``), so a single seed is refused deterministically with the specific
    threshold reason regardless of init state.
    """
    project = f"wi321kofn_{uuid.uuid4().hex[:8]}"
    fx = mint_co_signed(threshold=2, signer_count=2, project_name_hint=project)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    reg_sk = nacl.signing.SigningKey.generate()
    reg_public_b64 = base64.b64encode(bytes(reg_sk.verify_key)).decode("ascii")
    root_seed = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_delegate_registrar(
            _deleg_ns(
                project=project,
                genesis=genesis,
                registrar_public_key=reg_public_b64,
                key=root_seed,
            )
        )
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert exc.value.detail["reason"] == "threshold_exceeds_single_key"
    with contextlib.suppress(Exception):
        drop_project_schema(DSN, project)


def test_dry_run_writes_nothing(env):
    result = _delegate(env, dry_run=True)
    assert result["dry_run"] is True
    assert result["would_write"] is True
    assert result["registrar_principal_id"] == REGISTRAR
    assert _count_events(env["project"], "registrar_delegated") == 0


def test_scope_enforced_on_enrolment(env):
    """A delegation that does NOT scope principal_key_enrolled cannot authorise an enrol."""
    # Grant only rotate/revoke — deliberately omitting principal_key_enrolled.
    result = _delegate(env, scope=["principal_key_rotated", "principal_key_revoked"])
    assert result["ok"] is True
    assert set(result["scopes"]) == {"principal_key_rotated", "principal_key_revoked"}

    public_b64, secret_ref = _make_enrollee(env["tmp_path"])
    _challenge, proof = _issue_and_sign(env, public_b64, secret_ref)
    with pytest.raises(RegistaError) as exc:
        _commit_enroll(env, public_b64, proof)
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert _count_events(env["project"], "principal_key_enrolled") == 0


def test_scope_default_includes_enrolment(env):
    """The default scope set grants the key-lifecycle transitions incl. enrolment."""
    result = _delegate(env)
    assert set(result["scopes"]) == {
        "principal_key_enrolled",
        "principal_key_rotated",
        "principal_key_revoked",
    }


def test_non_canonical_registrar_id_refused(env):
    with pytest.raises(RegistaError) as exc:
        cmd_trust_delegate_registrar(
            _delegate_ns_for(env, registrar_principal_id="not-canonical")
        )
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert _count_events(env["project"], "registrar_delegated") == 0


def test_out_of_scope_value_refused(env):
    """A scope outside the registrar lifecycle-administration set is a named refusal."""
    with pytest.raises(RegistaError):
        cmd_trust_delegate_registrar(
            _delegate_ns_for(env, scope=["work_item_created"])
        )
    assert _count_events(env["project"], "registrar_delegated") == 0


def test_re_delegate_identical_is_noop(env):
    """Re-running with byte-identical terms is a clean no-op, not a second event."""
    # Pin an explicit window so the two invocations are byte-identical.
    from datetime import UTC, datetime, timedelta

    from regista._cli import _iso_micro_z

    now = datetime.now(UTC)
    nb = _iso_micro_z(now - timedelta(hours=1))
    na = _iso_micro_z(now + timedelta(days=100))
    first = _delegate(env, not_before=nb, not_after=na)
    assert first["ok"] is True and first["already_delegated"] is False
    second = _delegate(env, not_before=nb, not_after=na)
    assert second["ok"] is True
    assert second["already_delegated"] is True
    assert second["delegation_event_hash"].startswith("sha256:")
    # Only ONE registrar_delegated event exists — the no-op wrote nothing.
    assert _count_events(env["project"], "registrar_delegated") == 1


def test_re_delegate_different_terms_refused(env):
    """A live delegation with DIFFERENT terms is refused (revoke first), never forked."""
    first = _delegate(env, max_operations=5)
    assert first["ok"] is True
    with pytest.raises(RegistaError) as exc:
        _delegate(env, max_operations=99)
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert exc.value.detail["reason"] == "registrar_already_delegated_live"
    assert _count_events(env["project"], "registrar_delegated") == 1
