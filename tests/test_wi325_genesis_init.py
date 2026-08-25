"""WI-325 ``regista genesis init``: opening a per-project v6 epoch, fail-closed.

The per-project analog of ``trust init-log``, and the last CLI-unreachable step of the
EPOCH-RESET ceremony. Two things are under test, and they are different in kind:

**The assembly** (``_genesis_open``) — the envelope's trust reference is derived from a
VERIFIED trust-log chain walk, not from a projection row or an operator flag. Before
this, ``_genesis._validate_bootstrap_acceptance`` only shape-checked
``trust_event_hash`` and the checkpoint triplet, so a project could be opened with a
self-consistent but fabricated reference. The tests that matter here are the ones that
prove a LIE is refused: an unenrolled principal, a revoked key, a ``trust_event_hash``
naming the wrong event, a checkpoint describing a stale head.

**The gate** — ``initialize_epoch`` takes a bare ``gate_passed`` boolean, so the whole
of EPOCH-RESET §5 rests on the CLI never defaulting it true. The gate tests assert
refusal for every way a report can fail to be evidence about THIS store: absent,
unreadable, wrong kind, unsupported version, BLOCKED, self-contradictory, or bound to
another store or project.

The DB-backed tests share ONE module-scoped trust log (genesis + registrar + enrolment),
because a project genesis only ever READS it — building it per test would triple the
suite's runtime for no additional coverage. Each test that writes gets its own freshly
provisioned target schema.

Timestamps are anchored at CALL time (the ``tests/_trust_log_fixtures._ts`` rule): the
enrolment's validity window and the possession challenge are both live-window checked,
and a module-import constant would make every one of these a time bomb roughly ten
minutes into a full-suite run.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_solo

from regista import Regista
from regista._cli import (
    cmd_genesis_init,
    cmd_keys_adopt_enrollment,
    cmd_trust_delegate_registrar,
    cmd_trust_enroll,
    cmd_trust_init_log,
    cmd_trust_rebuild_projection,
)
from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._genesis_open import (
    DEFAULT_SCOPE_ENTITY_KINDS,
    build_project_initialized_envelope,
    derive_trust_log_checkpoint,
    load_gate_evidence,
    resolve_enrolled_key,
    validate_scope_entity_kinds,
)
from regista._invariant_probe import postgres_database_fingerprint
from regista._principal_keys import _compute_fingerprint
from regista._trust_log import POSSESSION_DOMAIN_V2
from regista.testing import drop_project_schema

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR = "service:registrar-1"
HOST = "agent:wi325-host"


# --------------------------------------------------------------------------- helpers


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


def _git(repo, *args) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _keyfile(path, *, key_id: str, principal_id: str, seed: bytes, public: bytes,
             role: str = "actor", status: str = "active", scheme: str = "ed25519") -> str:
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "scheme": scheme,
                        "alg": "Ed25519",
                        "secret": base64.b64encode(seed).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(public).decode("ascii"),
                        "principal_id": principal_id,
                        "role": role,
                        "status": status,
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(path)


def _gate_report(path, *, project: str, dsn: str = DSN, ok: bool = True,
                 report_version: int = 1, findings=None, kind: str = "genesis_gate",
                 store_fingerprint: str | None = None,
                 probes_ok: bool = True) -> str:
    """A minimally-shaped `agent-suite genesis-gate --json` report.

    Shaped from ``GenesisGateReport.to_dict()`` in
    ``agent-suite/src/agent_suite/genesis_gate.py``. Written by hand rather than by
    importing agent-suite: regista must not take a dependency on the component whose
    verdict it consumes, and the report is a wire contract, so a hand-written fixture
    is the honest test of what regista accepts off the wire.
    """
    fingerprint = (
        store_fingerprint
        if store_fingerprint is not None
        else postgres_database_fingerprint(dsn)
    )
    required_checks = {
        "regista": [
            {
                "id": "regista.store_invariant_measurements",
                "status": "measured",
                "store_fingerprint": fingerprint,
                "projects": [
                    {
                        "project": project,
                        "event_count": 0,
                        "declared_lineage_event_count": 0,
                        "lineage_coverage": {"numerator": 0, "denominator": 0},
                        "distinct_lineage_tokens": [],
                        "unresolvable_lineage_tokens": [],
                        "unresolvable_lineage_value_count": 0,
                        "ambiguous_lineage_event_count": 0,
                        "scheme_counts": {},
                        "undeclared_agent_author_event_count": 0,
                        "model_observation_status_counts": {},
                        "snapshot_id": "pg:100:100:",
                    }
                ],
                "errors": [],
            },
            {
                "id": "regista.load_bearing_fields_refused",
                "status": "pass",
                "detail": "write attempt refused",
            },
            {
                "id": "regista.closed_lineage_registry",
                "status": "pass",
                "detail": "closed registry enforced",
            },
            {
                "id": "regista.first_write_admission",
                "status": "pass",
                "detail": "first-write matrix passed",
            },
            {
                "id": "regista.actor_boundary_signing",
                "status": "pass",
                "detail": "unbound principal refused",
                "claim": "r10.project_v6.boundary_rejects_mismatched_binding",
                "basis": "behavioral_attempt_ephemeral_epoch",
                "paths_proven": [
                    "regista._genesis.append_v6_genesis",
                    "regista._v6_writer.append_v6_event",
                ],
                "shared_boundary_consumers": [
                    "regista._trust_log_writer.append_trust_log_event"
                ],
                "excluded_paths": [
                    "regista._cli.cmd_trust_init_log",
                    "regista._cli.cmd_trust_delegate_registrar",
                    "regista._cli._resolve_trust_root_actor",
                    "regista._trust_log_writer.write_trust_genesis",
                ],
                "exclusion_reason": "WI-320 remains explicit",
            },
        ],
        "cairn": [
            {
                "id": "cairn.runtime_model_observed",
                "status": "pass",
                "detail": "runtime model observed",
            },
            {
                "id": "cairn.unavailable_model_named",
                "status": "pass",
                "detail": "unavailable model named",
            },
            {
                "id": "cairn.observation_failure_nonblocking",
                "status": "pass",
                "detail": "capture remained nonblocking",
            },
        ],
        "agent-notes": [
            {
                "id": "agent_notes.session_identity_resolvable",
                "status": "pass",
                "detail": "session identity resolved",
            }
        ],
    }
    required_findings = [
        "regista.target_store_bound",
        "regista.target_project_bound",
        "regista.observation_snapshot_bound",
        f"regista.store_empty:{project}",
        f"regista.lineage_population_empty:{project}",
        f"regista.lineage_tokens_resolvable:{project}",
        f"regista.lineage_unambiguous:{project}",
        f"regista.asymmetric_only:{project}",
        f"regista.authors_declared:{project}",
        f"regista.model_observation_population_empty:{project}",
        "regista.load_bearing_fields_refused",
        "regista.closed_lineage_registry",
        "regista.first_write_admission",
        "regista.actor_boundary_signing",
        "cairn.runtime_model_observed",
        "cairn.unavailable_model_named",
        "cairn.observation_failure_nonblocking",
        "agent_notes.session_identity_resolvable",
    ]
    return _write_json(
        path,
        {
            "report_version": report_version,
            "kind": kind,
            "ok": ok,
            "epoch_may_open": ok,
            "binding": {
                "expected_store_fingerprint": fingerprint,
                "reported_store_fingerprint": fingerprint,
                "project": project,
                "observation_snapshot": "pg:100:100:",
            },
            "findings": (
                findings
                if findings is not None
                else [
                    {"check_id": check_id, "status": "pass", "detail": "passed"}
                    for check_id in required_findings
                ]
            ),
            "probes": {
                "report_version": 1,
                "kind": "invariant_probes",
                "ok": probes_ok,
                "probes": [
                    {
                        "component": component,
                        "status": "pass",
                        "ok": True,
                        "detail": "probe passed",
                        "checks": checks,
                    }
                    for component, checks in required_checks.items()
                ],
            },
        },
    )


def _count_events(project: str) -> int:
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])
    finally:
        mgr.close()


def _identity_row(project: str):
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            return conn.execute(
                "SELECT project_instance_id, trust_domain_id, principal_id, key_id, "
                "scheme_id, key_fingerprint FROM project_identity WHERE id = TRUE"
            ).fetchone()
    finally:
        mgr.close()


def _init_ns(**kwargs) -> argparse.Namespace:
    base = dict(
        dsn=DSN,
        project=None,
        hmac_key_path=None,
        principal=HOST,
        gate_report=None,
        genesis=None,
        trust_project=None,
        key_id=None,
        trust_event_hash=None,
        trust_domain_id=None,
        trust_checkpoint=None,
        trust_publication_repo=None,
        trust_publication_commit=None,
        checkpoint_seq=1,
        project_instance_id=None,
        scope_entity_kind=None,
        may_sign_bundles=False,
        dry_run=False,
        json=True,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


def _adopt_ns(**kwargs) -> argparse.Namespace:
    base = dict(
        dsn=DSN,
        project=None,
        hmac_key_path=None,
        principal=HOST,
        key_id=None,
        genesis=None,
        trust_project=None,
        dry_run=False,
        json=True,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def _producer_env(monkeypatch):
    """The v6 writer needs a process-level producer identity or it refuses.

    monkeypatch (not ``os.environ.setdefault``) so the one test that asserts the
    refusal can delete these without leaking into the rest of the module.
    """
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS", "pytest")
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-fixture")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")
    # The command resolves the pinned genesis from --genesis in these tests; an
    # ambient pin must not shadow that.
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)


@pytest.fixture(scope="module")
def trust(tmp_path_factory):
    """ONE trust log: genesis, a delegated registrar, and HOST's enrolled key.

    Module-scoped and never written to by the tests: `genesis init` reads the trust
    log under ``SET TRANSACTION READ ONLY``. Building this per test would triple the
    module's runtime and prove nothing extra.
    """
    tmp_path = tmp_path_factory.mktemp("wi325-trust")
    project = f"wi325t_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=project, declared_holder=ROOT_PRINCIPAL)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    root_seed = fx.seeds[fx.signer_ids[0]]
    root_seed_path = _seed_file(tmp_path / "root.seed", root_seed)
    root_keyfile = _keyfile(
        tmp_path / "root_keys.json",
        key_id=f"k_{fx.signer_ids[0]}",
        principal_id=ROOT_PRINCIPAL,
        seed=root_seed,
        public=fx.public_keys[fx.signer_ids[0]],
    )

    # Producer env is process-level and the module-scoped fixture runs before the
    # function-scoped autouse one, so set it here for the setup writes.
    for name, value in (
        ("REGISTA_PRODUCER_HARNESS", "pytest"),
        ("REGISTA_PRODUCER_HARNESS_VERSION", "0"),
        ("REGISTA_PRODUCER_MODEL", "test-fixture"),
        ("REGISTA_PRODUCER_MODEL_LINEAGE", "fable"),
    ):
        os.environ.setdefault(name, value)

    cmd_trust_init_log(
        argparse.Namespace(
            dsn=DSN, project=project, hmac_key_path=None, genesis=genesis,
            key=root_seed_path, root_principal_id=ROOT_PRINCIPAL, dry_run=False,
            json=False,
        )
    )

    registrar_sk = nacl.signing.SigningKey.generate()
    registrar_seed_path = _seed_file(tmp_path / "registrar.seed", bytes(registrar_sk))
    cmd_trust_delegate_registrar(
        argparse.Namespace(
            dsn=DSN, project=project, hmac_key_path=None,
            registrar_principal_id=REGISTRAR,
            registrar_public_key=base64.b64encode(
                bytes(registrar_sk.verify_key)
            ).decode("ascii"),
            registrar_key_id="k_registrar", key=root_seed_path,
            root_principal_id=ROOT_PRINCIPAL, scope=None, not_before=None,
            not_after=None, max_operations=None, genesis=genesis, dry_run=False,
            json=False,
        )
    )

    # HOST's keypair. Generated here, in this process, so the test owns both halves:
    # the public key goes into the trust log via `trust enroll`, the seed goes into
    # the local keyset. That is exactly the real topology.
    host_sk = nacl.signing.SigningKey.generate()
    host_seed = bytes(host_sk)
    host_public = bytes(host_sk.verify_key)
    host_public_b64 = base64.b64encode(host_public).decode("ascii")

    def _enroll_ns(**kwargs):
        base = dict(
            dsn=DSN, project=project, hmac_key_path=None, principal=HOST,
            public_key=host_public_b64, issue_challenge=False, ttl_minutes=None,
            proof=None, proof_file=None, key=None, registrar_principal_id=None,
            custody_backend=None, policy_ref=None, genesis=genesis, dry_run=False,
            json=True,
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    challenge = json.loads(_capture(cmd_trust_enroll, _enroll_ns(issue_challenge=True)))
    from regista._trust_log import PossessionChallengeV2

    # to_dict() adds the in-object `domain` field, which is a constant rather than a
    # constructor argument; drop it to rebuild the challenge and derive its signing
    # input. Signing directly with nacl (rather than through `signer sign-possession`)
    # keeps this fixture free of the client-custody machinery, which is not under test.
    proof_signature = host_sk.sign(
        PossessionChallengeV2(
            **{k: v for k, v in challenge.items() if k != "domain"}
        ).signing_input()
    ).signature
    enrolled = json.loads(
        _capture(
            cmd_trust_enroll,
            _enroll_ns(
                proof=json.dumps(
                    {
                        "challenge_id": challenge["challenge_id"],
                        "signature": base64.b64encode(proof_signature).decode("ascii"),
                    }
                ),
                key=registrar_seed_path,
                registrar_principal_id=REGISTRAR,
            ),
        )
    )
    assert enrolled["ok"] is True, enrolled

    # Materialise principal_keys so the projection cross-check has a row to agree with.
    cmd_trust_rebuild_projection(
        argparse.Namespace(
            dsn=DSN, project=project, hmac_key_path=root_keyfile, genesis=genesis,
            dry_run=False, json=False,
        )
    )

    # Publish a real root-signed §4.3 checkpoint in a two-commit append-only
    # channel. WI-325 verifies the signature, exact canonical bytes, index prefix,
    # path/sequence, git ancestry, and the out-of-band commit pin.
    from regista._genesis_open import _checkpoint_signature_input
    from regista._jcs import canonicalize
    from regista._trust_domain import derive_governance_mode
    from regista._trust_log_writer import verify_trust_log_chain

    publication_repo = tmp_path / "publication"
    publication_repo.mkdir()
    _git(publication_repo, "init", "-b", "main")
    published_at = _iso(datetime.now(UTC))
    canonical_genesis = canonicalize(fx.document)
    (publication_repo / "trust-domain.json").write_bytes(canonical_genesis)
    index = {
        "type": "regista.publication-index",
        "version": 1,
        "entries": [
            {
                "path": "trust-domain.json",
                "sha256": "sha256:" + hashlib.sha256(canonical_genesis).hexdigest(),
                "published_at": published_at,
                "prev_commit": None,
            }
        ],
    }
    (publication_repo / "index.json").write_bytes(canonicalize(index))
    _git(publication_repo, "add", "trust-domain.json", "index.json")
    _git(
        publication_repo,
        "-c",
        "user.name=Regista Test",
        "-c",
        "user.email=regista-test@example.invalid",
        "commit",
        "-m",
        "regista: publish genesis test",
    )
    genesis_commit = _git(publication_repo, "rev-parse", "HEAD")

    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            chain = verify_trust_log_chain(conn, fx.document)
    finally:
        mgr.close()
    checkpoint = {
        "type": "regista.trust-checkpoint",
        "version": 1,
        "trust_domain_id": fx.document["trust_domain_id"],
        "trust_domain_core_digest": fx.document["trust_domain_core_digest"],
        "checkpoint_seq": 1,
        "trust_log": {
            "project_instance_id": fx.document["trust_log"]["project_instance_id"],
            "event_count": chain.event_count,
            "genesis_event_hash": chain.state.genesis_event_hash,
            "head_event_hash": chain.head_event_hash,
            "max_global_seq": chain.event_count,
        },
        "root_governance": {
            "mode": derive_governance_mode(
                chain.state.governance.threshold,
                len(chain.state.governance.signer_fingerprints),
            ),
            "threshold": chain.state.governance.threshold,
            "signer_count": len(chain.state.governance.signer_fingerprints),
        },
        "active_root_fingerprints": sorted(chain.state.governance.signer_fingerprints),
        "prev_checkpoint_digest": None,
        "prev_commit": genesis_commit,
        "created_at": published_at,
        "root_signatures": [],
        "countersignatures": [],
        "anchors": [],
    }
    signer_id = fx.signer_ids[0]
    signature = nacl.signing.SigningKey(root_seed).sign(
        _checkpoint_signature_input(checkpoint)
    ).signature
    checkpoint["root_signatures"] = [
        {
            "signer_id": signer_id,
            "fingerprint": fx.fingerprints[signer_id],
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ]
    checkpoint_bytes = canonicalize(checkpoint)
    checkpoint_rel = (
        f"checkpoints/{fx.document['trust_domain_id']}/"
        "00000001-20260821T000000.000000Z.json"
    )
    checkpoint_path = publication_repo / checkpoint_rel
    checkpoint_path.parent.mkdir(parents=True)
    checkpoint_path.write_bytes(checkpoint_bytes)
    checkpoint_digest = "sha256:" + hashlib.sha256(checkpoint_bytes).hexdigest()
    index["entries"].append(
        {
            "path": checkpoint_rel,
            "sha256": checkpoint_digest,
            "published_at": published_at,
            "prev_commit": genesis_commit,
        }
    )
    (publication_repo / "index.json").write_bytes(canonicalize(index))
    _git(publication_repo, "add", checkpoint_rel, "index.json")
    _git(
        publication_repo,
        "-c",
        "user.name=Regista Test",
        "-c",
        "user.email=regista-test@example.invalid",
        "commit",
        "-m",
        "regista: publish checkpoint test",
    )
    publication_commit = _git(publication_repo, "rev-parse", "HEAD")

    yield SimpleNamespace(
        project=project,
        genesis=genesis,
        fx=fx,
        host_seed=host_seed,
        host_public=host_public,
        host_key_id=enrolled["key_id"],
        host_fingerprint=_compute_fingerprint(host_public, "ed25519"),
        tmp_path=tmp_path,
        root_keyfile=root_keyfile,
        root_seed=root_seed,
        checkpoint=str(checkpoint_path),
        publication_repo=str(publication_repo),
        publication_commit=publication_commit,
    )
    drop_project_schema(DSN, project)


@pytest.fixture
def target(trust, tmp_path):
    """A freshly provisioned, EMPTY target project plus a valid gate report + keyset."""
    project = f"wi325p_{uuid.uuid4().hex[:8]}"
    keys = _keyfile(
        tmp_path / "host_keys.json",
        key_id=trust.host_key_id,
        principal_id=HOST,
        seed=trust.host_seed,
        public=trust.host_public,
    )
    handle = Regista.create_project(DSN, project, keys)
    handle.close()
    yield SimpleNamespace(
        project=project,
        keys=keys,
        gate=_gate_report(tmp_path / "gate.json", project=project),
        tmp_path=tmp_path,
    )
    drop_project_schema(DSN, project)


def _init(trust, target, **overrides) -> dict:
    bound = {
        "project": target.project,
        "hmac_key_path": target.keys,
        "genesis": trust.genesis,
        "trust_project": trust.project,
        "gate_report": target.gate,
        "trust_checkpoint": trust.checkpoint,
        "trust_publication_repo": trust.publication_repo,
        "trust_publication_commit": trust.publication_commit,
    }
    bound.update(overrides)
    return json.loads(_capture(cmd_genesis_init, _init_ns(**bound)))


# ------------------------------------------------------------------- the keystone


def test_genesis_init_opens_the_epoch_end_to_end(trust, target):
    """The whole ceremony: one signed project_initialized, verified on read back.

    Asserts the facts that only a LIVE-trust-log assembly can get right: the
    acceptance's ``trust_event_hash`` is the actual ``principal_key_enrolled`` event,
    the checkpoint head is the actual trust-log head, and ``project_identity`` binds
    the project to the real trust domain and the real enrolled key.
    """
    result = _init(trust, target)

    assert result["ok"] is True
    assert result["transition"] == "project_initialized"
    assert result["verified_on_read"] is True
    assert result["principal_id"] == HOST
    assert result["key_id"] == trust.host_key_id
    assert result["key_fingerprint"] == trust.host_fingerprint
    assert result["trust_domain_id"] == trust.fx.document["trust_domain_id"]
    assert _count_events(target.project) == 1

    identity = _identity_row(target.project)
    assert str(identity["trust_domain_id"]) == trust.fx.document["trust_domain_id"]
    assert identity["principal_id"] == HOST
    assert identity["key_id"] == trust.host_key_id
    assert identity["scheme_id"] == "ed25519"
    assert identity["key_fingerprint"] == trust.host_fingerprint

    # The trust reference is REAL, not merely well-shaped.
    from regista._trust_log_writer import verify_trust_log_chain

    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            chain = verify_trust_log_chain(conn, trust.fx.document)
    finally:
        mgr.close()
    enrolment = next(
        r for r in chain.verified if r.transition == "principal_key_enrolled"
    )
    assert result["trust_event_hash"] == enrolment.event_hash
    assert result["checkpoint"]["head_event_hash"] == chain.head_event_hash
    assert result["checkpoint"]["source"] == "published"
    assert result["checkpoint"]["publication_commit"] == trust.publication_commit


def test_read_genesis_reverifies_the_written_epoch(trust, target):
    """``read_genesis`` re-derives the signed record without writing (EPOCH-RESET §5.1)."""
    written = _init(trust, target)
    handle = Regista(DSN, target.project, target.keys)
    try:
        recovered = handle.read_genesis()
    finally:
        handle.close()
    assert recovered is not None
    assert recovered.verified is True
    assert "sha256:" + recovered.event_hash.hex() == written["event_hash"]
    assert recovered.principal_id == HOST
    assert recovered.key_id == trust.host_key_id


# ------------------------------------------------------------- idempotence / refusal


def test_dry_run_writes_nothing(trust, target):
    plan = _init(trust, target, dry_run=True)
    assert plan["dry_run"] is True
    assert plan["would_write"] is True
    assert "would_refuse_reason" not in plan
    assert _count_events(target.project) == 0
    assert _identity_row(target.project) is None
    # An accurate dry run does every check, so it can report the whole reference.
    assert plan["trust_reference"]["key"]["key_id"] == trust.host_key_id
    assert plan["gate"]["epoch_may_open"] is True


def test_dry_run_reports_the_same_refusal_a_real_run_would_raise(trust, target):
    """Dry-run accuracy: after the epoch opens, the plan says would_write false.

    The failure mode this pins is a --dry-run that probes nothing and always claims it
    would succeed — the WI-319 review's deepseek N4 finding, in this command.
    """
    _init(trust, target)
    plan = _init(trust, target, dry_run=True)
    assert plan["would_write"] is False
    assert plan["would_refuse_reason"] == "project_identity_already_established"


def test_second_init_is_refused_not_a_second_genesis(trust, target):
    _init(trust, target)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target)
    assert exc.value.code is ErrorCode.GENESIS_ALREADY_WRITTEN
    assert exc.value.detail["reason"] == "project_identity_already_established"
    assert _count_events(target.project) == 1


def test_the_command_surface_offers_no_force_and_no_gate_override():
    """The two escape hatches that must not exist, asserted on the parser itself.

    A ``--force`` would let a second genesis fork a project's permanent identity, and
    any spelling of "assume the gate passed" would make EPOCH-RESET §5 advisory. This
    is a structural assertion rather than a comment, so adding either flag turns red.
    """
    from regista._cli import main

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        main(["genesis", "init", "--help"])
    help_text = buf.getvalue()
    assert "--gate-report" in help_text
    for forbidden in ("--force", "--gate-passed", "--skip-gate", "--no-gate",
                      "--assume-gate", "--allow-unverified"):
        assert forbidden not in help_text, forbidden


def test_unprovisioned_schema_is_refused_with_a_pointer_to_provision(trust, target):
    """`genesis init` opens an epoch in a provisioned store; it does not create one."""
    absent = f"wi325_absent_{uuid.uuid4().hex[:8]}"
    with pytest.raises(RegistaError) as exc:
        _init(
            trust, target, project=absent,
            gate_report=_gate_report(target.tmp_path / "absent.json", project=absent),
        )
    assert exc.value.code is ErrorCode.MIGRATION_REQUIRED
    assert exc.value.detail["reason"] == "project_schema_absent"


def test_opening_the_trust_log_as_a_project_is_refused(trust, target):
    """`genesis init` writes project_initialized; the trust log's genesis is different."""
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, project=trust.project)
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == "target_project_is_trust_log"


def test_producer_env_unset_is_a_named_preflight_refusal(trust, target, monkeypatch):
    monkeypatch.delenv("REGISTA_PRODUCER_HARNESS", raising=False)
    monkeypatch.delenv("REGISTA_PRODUCER_HARNESS_VERSION", raising=False)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target)
    assert exc.value.code is ErrorCode.LOAD_BEARING_FIELD_MISSING
    assert "REGISTA_PRODUCER_HARNESS" in exc.value.message
    assert _count_events(target.project) == 0


# ------------------------------------------------------------------ the §5 gate


def test_gate_report_absent_is_refused(trust, target):
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=None)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_report_absent"
    assert _count_events(target.project) == 0


def test_blocked_gate_report_is_refused(trust, target):
    blocked = _gate_report(target.tmp_path / "blocked.json", project=target.project,
                           ok=False)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=blocked)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_did_not_pass"


def test_gate_report_for_a_different_store_is_refused(trust, target):
    """A real PASS about the wrong store must not open an epoch here."""
    other = _gate_report(
        target.tmp_path / "other-store.json", project=target.project,
        store_fingerprint="sha256:" + "ab" * 32,
    )
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=other)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_report_store_mismatch"


def test_gate_report_for_a_different_project_is_refused(trust, target):
    other = _gate_report(target.tmp_path / "other-project.json",
                         project="some_other_project")
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=other)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_report_project_mismatch"


def test_self_contradictory_gate_report_is_refused(trust, target):
    """ok=true is not taken on trust when a finding says otherwise."""
    contradictory = _gate_report(
        target.tmp_path / "contradictory.json", project=target.project,
        findings=[
            {"check_id": "regista.target_store_bound", "status": "pass", "detail": ""},
            {"check_id": "agent_notes.session_identity_resolvable", "status": "fail",
             "detail": "absent"},
        ],
    )
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=contradictory)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_report_findings_invalid"


def test_unsupported_gate_report_version_is_refused(trust, target):
    future = _gate_report(target.tmp_path / "v2.json", project=target.project,
                          report_version=2)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=future)
    assert exc.value.code is ErrorCode.GENESIS_GATE_EVIDENCE_INVALID
    assert exc.value.detail["reason"] == "gate_report_version_unsupported"


def test_invariant_probe_report_is_not_gate_evidence(trust, target):
    """`agent-suite invariant-probes` carries no first-write verdict."""
    wrong_kind = _gate_report(target.tmp_path / "probes.json", project=target.project,
                              kind="invariant_probes")
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=wrong_kind)
    assert exc.value.detail["reason"] == "gate_report_wrong_kind"


def test_gate_report_with_unhealthy_probes_is_refused(trust, target):
    unhealthy = _gate_report(target.tmp_path / "unhealthy.json",
                             project=target.project, probes_ok=False)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=unhealthy)
    assert exc.value.detail["reason"] == "gate_probe_report_invalid"


def test_gate_report_with_no_findings_is_refused(trust, target):
    empty = _gate_report(target.tmp_path / "empty.json", project=target.project,
                         findings=[])
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=empty)
    assert exc.value.detail["reason"] == "gate_report_findings_empty"


def test_gate_report_refuses_a_non_object_finding(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    raw["findings"][0] = None
    path = _write_json(target.tmp_path / "null-finding.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_report_findings_invalid"


def test_gate_report_refuses_incomplete_nested_probe_coverage(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    raw["probes"]["probes"] = [
        probe
        for probe in raw["probes"]["probes"]
        if probe["component"] != "agent-notes"
    ]
    path = _write_json(target.tmp_path / "missing-probe.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_probe_component_coverage_invalid"


@pytest.mark.parametrize(
    "snapshot", [None, "", "not-a-postgres-snapshot", "pg:not-a-snapshot"]
)
def test_gate_report_requires_a_named_postgres_snapshot(trust, target, snapshot):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    raw["binding"]["observation_snapshot"] = snapshot
    path = _write_json(target.tmp_path / f"bad-snapshot-{snapshot!s}.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_report_snapshot_invalid"


def test_gate_report_unknown_field_is_refused_not_ignored(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    raw["attacker_override"] = True
    path = _write_json(target.tmp_path / "extra-field.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_report_shape_invalid"


def test_gate_report_refuses_empty_behavioral_check_bodies(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    cairn = next(
        probe for probe in raw["probes"]["probes"] if probe["component"] == "cairn"
    )
    cairn["checks"][0].pop("detail")
    path = _write_json(target.tmp_path / "empty-check-body.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_probe_check_body_invalid"


def test_gate_report_reconciles_the_full_empty_store_measurement(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    regista = next(
        probe for probe in raw["probes"]["probes"] if probe["component"] == "regista"
    )
    measurement = next(
        check
        for check in regista["checks"]
        if check["id"] == "regista.store_invariant_measurements"
    )
    measurement["projects"][0]["event_count"] = 1
    path = _write_json(target.tmp_path / "false-empty-measurement.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_measurement_body_invalid"


def test_gate_report_boolean_version_is_not_integer_one(trust, target):
    raw = json.loads(open(target.gate, encoding="utf-8").read())
    raw["report_version"] = True
    path = _write_json(target.tmp_path / "boolean-version.json", raw)

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, gate_report=path)

    assert exc.value.detail["reason"] == "gate_report_version_absent"


def test_unreadable_and_non_json_gate_reports_are_refused(tmp_path):
    with pytest.raises(RegistaError) as exc:
        load_gate_evidence(str(tmp_path / "nope.json"), dsn=DSN, project="p")
    assert exc.value.detail["reason"] == "gate_report_unreadable"
    junk = tmp_path / "junk.json"
    junk.write_text("not json", encoding="utf-8")
    with pytest.raises(RegistaError) as exc:
        load_gate_evidence(str(junk), dsn=DSN, project="p")
    assert exc.value.detail["reason"] == "gate_report_invalid_json"


# --------------------------------------------------- verify-the-reference hardening


def test_unenrolled_principal_is_refused(trust, target):
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, principal="agent:never-enrolled")
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "principal_has_no_key_introduction"
    assert _count_events(target.project) == 0


def test_wrong_key_id_is_refused(trust, target):
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, key_id="pk_not_a_real_key")
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "key_id_not_introduced"
    assert trust.host_key_id in exc.value.detail["introduced_key_ids"]


def test_a_claimed_trust_event_hash_is_verified_not_trusted(trust, target):
    """The hole ``_genesis.py:396`` leaves: there, any well-formed digest passes."""
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_event_hash="sha256:" + "cd" * 32)
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "trust_event_hash_mismatch"
    assert _count_events(target.project) == 0


def test_a_correct_trust_event_hash_is_accepted(trust, target):
    from regista._trust_log_writer import verify_trust_log_chain

    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            chain = verify_trust_log_chain(conn, trust.fx.document)
    finally:
        mgr.close()
    enrolment = next(r for r in chain.verified if r.transition == "principal_key_enrolled")
    result = _init(trust, target, trust_event_hash=enrolment.event_hash)
    assert result["ok"] is True


def test_wrong_expected_trust_domain_is_refused(trust, target):
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_domain_id=str(uuid.uuid4()))
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "trust_domain_id_mismatch"


def test_a_genesis_document_for_another_domain_is_refused(trust, target, tmp_path):
    """The stored trust genesis must match the SUPPLIED document, not merely parse."""
    stranger = mint_solo(project_name_hint=trust.project)
    other_doc = _write_json(tmp_path / "stranger.json", stranger.document)
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, genesis=other_doc)
    # verify_trust_log_chain refuses the stored genesis against the pinned document.
    assert exc.value.code in {
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
    }
    assert _count_events(target.project) == 0


def test_projection_that_disagrees_with_the_chain_is_refused(trust, target):
    """§5.9 rule 1 does not make a lying projection harmless."""
    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            conn.execute(
                "UPDATE principal_keys SET fingerprint = %s WHERE principal_id = %s",
                ["ed25519:sha256:" + "00" * 32, HOST],
            )
        with pytest.raises(RegistaError) as exc:
            _init(trust, target)
        assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
        assert exc.value.detail["reason"] == "projection_disagrees_with_chain"
        assert "fingerprint" in exc.value.detail["fields"]
    finally:
        # Restore, because the trust log is module-scoped.
        with mgr.transaction() as conn:
            conn.execute(
                "UPDATE principal_keys SET fingerprint = %s WHERE principal_id = %s",
                [trust.host_fingerprint, HOST],
            )
        mgr.close()


def test_an_absent_projection_row_is_not_an_error(trust, target):
    """The projection is never the authority, so a missing row cannot block genesis."""
    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM principal_keys WHERE principal_id = %s", [HOST]
            ).fetchone()
            conn.execute("DELETE FROM principal_keys WHERE principal_id = %s", [HOST])
        plan = _init(trust, target, dry_run=True)
        assert plan["trust_reference"]["key"]["projection"] == "absent"
        assert plan["would_write"] is True
    finally:
        with mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO principal_keys (principal_id, key_id, scheme, public_key, "
                "fingerprint, status, valid_from, registered_by, registered_at, "
                "trust_domain_id, source_event_hash, projection_version) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    row["principal_id"], row["key_id"], row["scheme"], row["public_key"],
                    row["fingerprint"], row["status"], row["valid_from"],
                    row["registered_by"], row["registered_at"], row["trust_domain_id"],
                    row["source_event_hash"], row["projection_version"],
                ],
            )
        mgr.close()


# ------------------------------------------- resolve_enrolled_key branch coverage
#
# These drive the resolver against SYNTHETIC verified chains. Building a revoked,
# expired or ambiguous enrolment through the real writer would need a `trust revoke`
# CLI (which does not exist) and several more root ceremonies per case; the resolver's
# contract is "given a verified chain, which key may sign", and that is exactly what a
# synthetic chain exercises. The DB-backed tests above prove the real chain reaches
# this function correctly.


def _synthetic_chain(records, *, statuses, public_keys, head="sha256:" + "11" * 32):
    from regista._trust_domain import GovernanceState
    from regista._trust_log_writer import TrustLogIdentity, TrustState, VerifiedChain

    state = TrustState(
        identity=TrustLogIdentity(
            project_instance_id=str(uuid.uuid4()), trust_domain_id=str(uuid.uuid4())
        ),
        governance=GovernanceState(threshold=1, signer_fingerprints=("ed25519:sha256:x",)),
        root_public_keys={},
        registrars={},
        genesis_event_hash="sha256:" + "22" * 32,
        principal_public_keys=public_keys,
        principal_key_status=statuses,
    )
    return VerifiedChain(
        verified=tuple(records), state=state, head_event_hash=head,
        event_count=len(records) + 1,
    )


def _enrolment_record(*, principal_id, key_id, public_key, event_hash,
                      not_before, not_after=None, fingerprint=None):
    return SimpleNamespace(
        event_id=str(uuid.uuid4()),
        event_hash=event_hash,
        transition="principal_key_enrolled",
        entity_kind="principal",
        entity_id=str(uuid.uuid4()),
        entity_seq=1,
        actor_id=REGISTRAR,
        key_id="k_registrar",
        occurred_at=datetime.now(UTC),
        payload={
            "type": "regista.key-enrollment",
            "version": 1,
            "trust_domain_id": str(uuid.uuid4()),
            "principal_id": principal_id,
            "principal_kind": "agent",
            "key_id": key_id,
            "scheme_id": "ed25519",
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "fingerprint": fingerprint or _compute_fingerprint(public_key, "ed25519"),
            "not_before": _iso(not_before),
            "not_after": None if not_after is None else _iso(not_after),
            "possession_proof": {
                "domain": POSSESSION_DOMAIN_V2,
                "challenge_id": str(uuid.uuid4()),
                "verifier_nonce": "00" * 32,
                "enrollment_request_digest": "sha256:" + "33" * 32,
                "signature": base64.b64encode(b"\x00" * 64).decode("ascii"),
            },
            "authorized_by": {
                "authority": "registrar",
                "principal_id": REGISTRAR,
                "key_id": "k_registrar",
                "delegation_event_hash": "sha256:" + "44" * 32,
            },
            "custody": {
                "declared_backend": "file",
                "declared_policy_ref": "policy://test/v1",
            },
            "supersedes_key_id": None,
        },
        authority="registrar",
        governing_fingerprint="ed25519:sha256:x",
    )


class _NoConn:
    """A connection that must never be reached: these refusals precede any query."""

    def execute(self, *_a, **_k):  # pragma: no cover - reaching it IS the failure
        raise AssertionError("the resolver queried the store after it should have refused")


def _one_key(offset_seconds=0, not_after_offset=None, fingerprint=None, key_id="pk_a"):
    """Anchored at CALL time — never a module constant (the ``_ts`` rule)."""
    now = datetime.now(UTC)
    sk = nacl.signing.SigningKey.generate()
    public = bytes(sk.verify_key)
    record = _enrolment_record(
        principal_id=HOST, key_id=key_id, public_key=public,
        event_hash="sha256:" + "55" * 32,
        not_before=now + timedelta(seconds=offset_seconds),
        not_after=None if not_after_offset is None else now + timedelta(
            seconds=not_after_offset
        ),
        fingerprint=fingerprint,
    )
    return record, public


def _rotation_record(*, supersedes_key_id="pk_old", key_id="pk_new"):
    record, public = _one_key(offset_seconds=-60, key_id=key_id)
    record.transition = "principal_key_rotated"
    record.event_hash = "sha256:" + "66" * 32
    record.payload["type"] = "regista.key-rotation"
    record.payload["supersedes_key_id"] = supersedes_key_id
    record.payload["dual_authorization"] = {
        "old_key_signature": base64.b64encode(b"\x00" * 64).decode("ascii"),
        "mode": "dual",
        "recovery_reason": None,
    }
    record.payload["root_signatures"] = []
    return record, public


def test_revoked_enrolled_key_is_refused():
    record, public = _one_key(offset_seconds=-60)
    chain = _synthetic_chain(
        [record],
        statuses={(HOST, "pk_a"): "revoked"},
        public_keys={(HOST, "pk_a"): public},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(_NoConn(), {}, principal_id=HOST, verified=chain)
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "trust_key_not_active"


def test_two_active_enrolled_keys_refuse_rather_than_choose():
    first, pub_a = _one_key(offset_seconds=-60, key_id="pk_a")
    second, pub_b = _one_key(offset_seconds=-30, key_id="pk_b")
    chain = _synthetic_chain(
        [first, second],
        statuses={(HOST, "pk_a"): "active", (HOST, "pk_b"): "active"},
        public_keys={(HOST, "pk_a"): pub_a, (HOST, "pk_b"): pub_b},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(_NoConn(), {}, principal_id=HOST, verified=chain)
    assert exc.value.detail["reason"] == "trust_key_ambiguous"
    assert sorted(exc.value.detail["key_ids"]) == ["pk_a", "pk_b"]


def test_not_yet_valid_enrolment_is_refused():
    record, public = _one_key(offset_seconds=3600)
    chain = _synthetic_chain(
        [record], statuses={(HOST, "pk_a"): "active"},
        public_keys={(HOST, "pk_a"): public},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(_NoConn(), {}, principal_id=HOST, verified=chain)
    assert exc.value.detail["reason"] == "trust_key_not_yet_valid"


def test_expired_enrolment_is_refused():
    record, public = _one_key(offset_seconds=-7200, not_after_offset=-3600)
    chain = _synthetic_chain(
        [record], statuses={(HOST, "pk_a"): "active"},
        public_keys={(HOST, "pk_a"): public},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(_NoConn(), {}, principal_id=HOST, verified=chain)
    assert exc.value.detail["reason"] == "trust_key_expired"


def test_replayed_public_key_disagreeing_with_the_payload_is_refused():
    record, _public = _one_key(offset_seconds=-60)
    other = bytes(nacl.signing.SigningKey.generate().verify_key)
    chain = _synthetic_chain(
        [record], statuses={(HOST, "pk_a"): "active"},
        public_keys={(HOST, "pk_a"): other},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(_NoConn(), {}, principal_id=HOST, verified=chain)
    assert exc.value.detail["reason"] == "replayed_public_key_mismatch"


def test_an_active_rotation_sourced_key_is_a_valid_trust_referent():
    rotation, public = _rotation_record()
    chain = _synthetic_chain(
        [rotation],
        statuses={(HOST, "pk_new"): "active"},
        public_keys={(HOST, "pk_new"): public},
    )

    class _ProjectionAbsent:
        def execute(self, *_a, **_k):
            return SimpleNamespace(fetchone=lambda: {"present": False})

    resolved = resolve_enrolled_key(
        _ProjectionAbsent(), {}, principal_id=HOST, verified=chain
    )
    assert resolved.key_id == "pk_new"
    assert resolved.trust_event_hash == rotation.event_hash
    assert resolved.trust_event_transition == "principal_key_rotated"


def test_rotation_selects_new_key_even_though_old_status_stays_active():
    """Defence in depth: ``resolve_enrolled_key`` reads supersession off the rotation
    events, NOT off ``principal_key_status``.

    This test DELIBERATELY models an inconsistent status map — BOTH keys marked active —
    to prove the resolver is independent of that bookkeeping. Since WI-337 fix B the real
    replay no longer leaves this state (``_remember_principal_key`` flips the outgoing key
    to ``"superseded"``, and WI-347 further forbids rotating a non-active key), so the
    both-active map here is a synthetic legacy/regression scenario, not what the writer
    produces. The point stands: even if the status map were wrong, the resolver must still
    select the incoming key and never resolve the rotated-away one — this test fails if
    the direct reading of rotation events is removed.
    """
    enrolment, public = _one_key(offset_seconds=-3600, key_id="pk_old")
    rotation, new_public = _rotation_record()
    chain = _synthetic_chain(
        [enrolment, rotation],
        # A DELIBERATELY inconsistent map (both active) — no longer what the real replay
        # leaves (WI-337 fix B marks pk_old superseded); used to test resolver independence.
        statuses={(HOST, "pk_old"): "active", (HOST, "pk_new"): "active"},
        public_keys={(HOST, "pk_old"): public, (HOST, "pk_new"): new_public},
    )
    class _ProjectionAbsent:
        def execute(self, *_a, **_k):
            return SimpleNamespace(fetchone=lambda: {"present": False})

    resolved = resolve_enrolled_key(
        _ProjectionAbsent(), {}, principal_id=HOST, verified=chain
    )
    assert resolved.key_id == "pk_new"
    assert resolved.trust_event_transition == "principal_key_rotated"


def test_an_explicit_key_id_naming_a_superseded_key_is_still_refused():
    """--key-id must not be a way past the supersession check."""
    enrolment, public = _one_key(offset_seconds=-3600, key_id="pk_old")
    rotation, new_public = _rotation_record()
    chain = _synthetic_chain(
        [enrolment, rotation],
        statuses={(HOST, "pk_old"): "active"},
        public_keys={(HOST, "pk_old"): public, (HOST, "pk_new"): new_public},
    )
    with pytest.raises(RegistaError) as exc:
        resolve_enrolled_key(
            _NoConn(), {}, principal_id=HOST, key_id="pk_old", verified=chain
        )
    assert exc.value.detail["reason"] == "key_superseded"


def test_a_rotation_of_another_principal_does_not_supersede_this_one(trust, target):
    """Supersession is per principal; a neighbour's rotation must not block genesis."""
    enrolment, public = _one_key(offset_seconds=-3600, key_id="pk_mine")
    other_rotation, _other_public = _rotation_record(supersedes_key_id="pk_mine")
    other_rotation.payload["principal_id"] = "agent:someone-else"
    chain = _synthetic_chain(
        [enrolment, other_rotation],
        statuses={(HOST, "pk_mine"): "active"},
        public_keys={(HOST, "pk_mine"): public},
    )

    class _ProjectionAbsent:
        def execute(self, *_a, **_k):
            return SimpleNamespace(fetchone=lambda: {"present": False})

    resolved = resolve_enrolled_key(
        _ProjectionAbsent(), {}, principal_id=HOST, verified=chain
    )
    assert resolved.key_id == "pk_mine"
    assert resolved.projection == "absent"


# ----------------------------------------------------------------- the checkpoint


def test_derived_checkpoint_digest_covers_the_emitted_document(trust):
    """``document_digest`` is the JCS digest of the document the command reports."""
    import hashlib

    from regista._jcs import canonicalize

    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            checkpoint = derive_trust_log_checkpoint(conn, trust.fx.document)
    finally:
        mgr.close()
    assert checkpoint.source == "derived"
    assert checkpoint.checkpoint_seq == 1
    assert checkpoint.document["type"] == "regista.trust-log-observation"
    recomputed = "sha256:" + hashlib.sha256(
        canonicalize(dict(checkpoint.document))
    ).hexdigest()
    assert checkpoint.document_digest == recomputed
    assert checkpoint.document["trust_log"]["head_event_hash"] == checkpoint.head_event_hash


def test_checkpoint_seq_below_one_is_refused(trust):
    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            with pytest.raises(RegistaError) as exc:
                derive_trust_log_checkpoint(conn, trust.fx.document, checkpoint_seq=0)
    finally:
        mgr.close()
    assert exc.value.detail["reason"] == "checkpoint_seq_below_one"


def test_derived_checkpoint_cannot_claim_a_later_unlinked_sequence(trust):
    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            with pytest.raises(RegistaError) as exc:
                derive_trust_log_checkpoint(conn, trust.fx.document, checkpoint_seq=2)
    finally:
        mgr.close()
    assert exc.value.detail["reason"] == "derived_checkpoint_sequence_unlinked"


def test_a_published_checkpoint_is_verified_against_the_live_log(trust, target):
    """A published checkpoint is stronger evidence because every layer is checked."""
    result = _init(trust, target)
    assert result["checkpoint"]["source"] == "published"
    assert result["checkpoint"]["checkpoint_seq"] == 1
    assert result["checkpoint"]["publication_commit"] == trust.publication_commit


def test_unsigned_checkpoint_is_refused(trust, target):
    from regista._jcs import canonicalize

    raw = json.loads(open(trust.checkpoint, encoding="utf-8").read())
    raw["root_signatures"] = []
    path = target.tmp_path / "unsigned-checkpoint.json"
    path.write_bytes(canonicalize(raw))

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_checkpoint=str(path))

    assert exc.value.detail["reason"] == "checkpoint_root_signatures_absent"


def test_tampered_checkpoint_signature_is_refused(trust, target):
    from regista._jcs import canonicalize

    raw = json.loads(open(trust.checkpoint, encoding="utf-8").read())
    raw["root_signatures"][0]["signature"] = base64.b64encode(b"x" * 64).decode(
        "ascii"
    )
    path = target.tmp_path / "bad-signature-checkpoint.json"
    path.write_bytes(canonicalize(raw))

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_checkpoint=str(path))

    assert exc.value.detail["reason"] == "checkpoint_root_signature_invalid"


def test_checkpoint_boolean_version_is_not_integer_one(trust, target):
    from regista._jcs import canonicalize

    raw = json.loads(open(trust.checkpoint, encoding="utf-8").read())
    raw["version"] = True
    path = target.tmp_path / "boolean-checkpoint-version.json"
    path.write_bytes(canonicalize(raw))

    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_checkpoint=str(path))

    assert exc.value.detail["reason"] == "checkpoint_type_or_version_invalid"


def test_checkpoint_publication_index_must_bind_the_exact_digest(trust, target):
    from regista._jcs import canonicalize

    clone = target.tmp_path / "publication-clone"
    shutil.copytree(trust.publication_repo, clone)
    index_path = clone / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["entries"][-1]["sha256"] = "sha256:" + "00" * 32
    index_path.write_bytes(canonicalize(index))
    _git(clone, "add", "index.json")
    _git(
        clone,
        "-c",
        "user.name=Regista Test",
        "-c",
        "user.email=regista-test@example.invalid",
        "commit",
        "-m",
        "tamper publication index",
    )
    commit = _git(clone, "rev-parse", "HEAD")
    relative = os.path.relpath(trust.checkpoint, trust.publication_repo)

    with pytest.raises(RegistaError) as exc:
        _init(
            trust,
            target,
            trust_checkpoint=str(clone / relative),
            trust_publication_repo=str(clone),
            trust_publication_commit=commit,
        )

    assert exc.value.detail["reason"] == (
        "checkpoint_publication_historical_digest_mismatch"
    )


def test_checkpoint_publication_assume_unchanged_cannot_hide_modified_bytes(
    trust, target
):
    clone = target.tmp_path / "assume-unchanged-clone"
    shutil.copytree(trust.publication_repo, clone)
    _git(clone, "update-index", "--assume-unchanged", "index.json")
    with open(clone / "index.json", "ab") as handle:
        handle.write(b" ")
    relative = os.path.relpath(trust.checkpoint, trust.publication_repo)

    with pytest.raises(RegistaError) as exc:
        _init(
            trust,
            target,
            trust_checkpoint=str(clone / relative),
            trust_publication_repo=str(clone),
            trust_publication_commit=trust.publication_commit,
        )

    assert exc.value.detail["reason"] == "checkpoint_publication_worktree_mismatch"


def test_real_genesis_requires_a_published_checkpoint(trust, target):
    with pytest.raises(RegistaError) as exc:
        _init(
            trust,
            target,
            trust_checkpoint=None,
            trust_publication_repo=None,
            trust_publication_commit=None,
        )

    assert exc.value.detail["reason"] == "published_checkpoint_required"


def test_dry_run_may_report_an_explicitly_derived_unbound_observation(trust, target):
    result = _init(
        trust,
        target,
        dry_run=True,
        trust_checkpoint=None,
        trust_publication_repo=None,
        trust_publication_commit=None,
    )

    assert result["trust_reference"]["checkpoint"]["source"] == "derived"
    assert result["would_write"] is False
    assert result["would_refuse_reason"] == "published_checkpoint_required"
    assert _count_events(target.project) == 0


def test_checkpoint_seq_alongside_a_published_checkpoint_is_refused(trust, target):
    """Two conflicting instructions; the tool refuses rather than ignoring one."""
    path = _write_json(target.tmp_path / "any.json", {"checkpoint_seq": 2})
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_checkpoint=path, checkpoint_seq=5)
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == (
        "checkpoint_seq_conflicts_with_published_checkpoint"
    )


def test_wrong_trust_project_is_refused_by_name(trust, target):
    """The common operator error: --trust-project naming no initialised trust log.

    Without this the failure surfaces from inside the chain walk as ``empty_trust_log``,
    which does not tell the operator they pointed at the wrong schema.
    """
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_project=f"wi325_nolog_{uuid.uuid4().hex[:8]}")
    assert exc.value.code is ErrorCode.TRUST_LOG_STORE_UNAVAILABLE
    assert exc.value.detail["reason"] == "trust_log_not_initialized"
    assert "--trust-project" in exc.value.message
    assert _count_events(target.project) == 0


def test_a_stale_published_checkpoint_is_refused(trust, target):
    from regista._genesis_open import _checkpoint_signature_input
    from regista._jcs import canonicalize

    stale = json.loads(open(trust.checkpoint, encoding="utf-8").read())
    stale["trust_log"]["head_event_hash"] = "sha256:" + "88" * 32
    stale["root_signatures"] = []
    signer_id = trust.fx.signer_ids[0]
    signature = nacl.signing.SigningKey(trust.root_seed).sign(
        _checkpoint_signature_input(stale)
    ).signature
    stale["root_signatures"] = [
        {
            "signer_id": signer_id,
            "fingerprint": trust.fx.fingerprints[signer_id],
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ]
    path_obj = target.tmp_path / "stale.json"
    path_obj.write_bytes(canonicalize(stale))
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, trust_checkpoint=str(path_obj))
    assert exc.value.code is ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert exc.value.detail["reason"] == "checkpoint_disagrees_with_live_log"
    assert _count_events(target.project) == 0


# ---------------------------------------------------- keyset / enrolment adoption


def test_a_stale_keyset_label_is_refused_and_names_the_remedy(trust, target, tmp_path):
    """The live case: byte-identical key material under the wrong key_id/principal."""
    stale = _keyfile(
        tmp_path / "stale_keys.json",
        key_id="pk_stale_label",
        principal_id="mvmcc03-agent",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    with pytest.raises(RegistaError) as exc:
        _init(trust, target, hmac_key_path=stale)
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    assert exc.value.detail["reason"] == "enrolled_key_held_under_stale_label"
    assert exc.value.detail["keyset_key_id"] == "pk_stale_label"
    assert "adopt-enrollment" in exc.value.message
    assert _count_events(target.project) == 0


def test_adopt_enrollment_relabels_and_then_genesis_succeeds(trust, target, tmp_path):
    """The remedy works, and it is the ONLY thing standing between the two states."""
    stale = _keyfile(
        tmp_path / "adopt_keys.json",
        key_id="pk_stale_label",
        principal_id="mvmcc03-agent",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    before = json.loads(open(stale, encoding="utf-8").read())["keys"][0]

    result = json.loads(
        _capture(
            cmd_keys_adopt_enrollment,
            _adopt_ns(hmac_key_path=stale, genesis=trust.genesis,
                      trust_project=trust.project),
        )
    )
    assert result["ok"] is True
    assert result["verified_private_key_unchanged"] is True
    assert result["enrolled_key_id"] == trust.host_key_id

    after = json.loads(open(stale, encoding="utf-8").read())["keys"][0]
    assert after["key_id"] == trust.host_key_id
    assert after["principal_id"] == HOST
    # Nothing else moved: private material is relabelled, never re-encoded or rewritten.
    for field in ("secret", "encoding", "public_key", "scheme", "alg", "role", "status"):
        assert after[field] == before[field], field
    # And the backup holds the original.
    backup = json.loads(open(result["backup"], encoding="utf-8").read())["keys"][0]
    assert backup == before

    assert _init(trust, target, hmac_key_path=stale)["ok"] is True


def test_adopt_enrollment_dry_run_writes_nothing(trust, tmp_path):
    stale = _keyfile(
        tmp_path / "dry_keys.json", key_id="pk_stale", principal_id="old-label",
        seed=trust.host_seed, public=trust.host_public,
    )
    original = open(stale, encoding="utf-8").read()
    plan = json.loads(
        _capture(
            cmd_keys_adopt_enrollment,
            _adopt_ns(hmac_key_path=stale, genesis=trust.genesis,
                      trust_project=trust.project, dry_run=True),
        )
    )
    assert plan["dry_run"] is True
    assert plan["would_write"] is True
    assert {c["field"] for c in plan["changes"]} == {"key_id", "principal_id"}
    assert open(stale, encoding="utf-8").read() == original


def test_adopt_enrollment_is_idempotent(trust, tmp_path):
    correct = _keyfile(
        tmp_path / "ok_keys.json", key_id=trust.host_key_id, principal_id=HOST,
        seed=trust.host_seed, public=trust.host_public,
    )
    original = open(correct, encoding="utf-8").read()
    result = json.loads(
        _capture(
            cmd_keys_adopt_enrollment,
            _adopt_ns(hmac_key_path=correct, genesis=trust.genesis,
                      trust_project=trust.project),
        )
    )
    assert result["already_adopted"] is True
    assert result["changes"] == []
    assert open(correct, encoding="utf-8").read() == original


def test_adopt_enrollment_refuses_when_no_entry_holds_the_enrolled_key(trust, tmp_path):
    stranger = nacl.signing.SigningKey.generate()
    other = _keyfile(
        tmp_path / "other_keys.json", key_id="pk_other", principal_id="whoever",
        seed=bytes(stranger), public=bytes(stranger.verify_key),
    )
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=other, genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.code is ErrorCode.KEYSET_ADOPTION_REFUSED
    assert exc.value.detail["reason"] == "no_keyset_entry_holds_enrolled_key"


def test_adopt_enrollment_refuses_ambiguity(trust, tmp_path):
    """Two entries holding one key is a custody question, not a labelling one."""
    path = tmp_path / "dup_keys.json"
    entry = {
        "scheme": "ed25519",
        "alg": "Ed25519",
        "secret": base64.b64encode(trust.host_seed).decode("ascii"),
        "encoding": "base64",
        "public_key": base64.b64encode(trust.host_public).decode("ascii"),
        "role": "actor",
        "status": "active",
    }
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {**entry, "key_id": "pk_one", "principal_id": "a"},
                    {**entry, "key_id": "pk_two", "principal_id": "b"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=str(path), genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.code is ErrorCode.KEYSET_ADOPTION_REFUSED
    assert exc.value.detail["reason"] == "ambiguous_keyset_entries"


def test_adopt_enrollment_refuses_an_unusable_matched_entry(trust, tmp_path):
    revoked = _keyfile(
        tmp_path / "revoked_keys.json", key_id="pk_stale", principal_id="old",
        seed=trust.host_seed, public=trust.host_public, status="revoked",
    )
    original = open(revoked, encoding="utf-8").read()
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=revoked, genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.detail["reason"] == "matched_entry_not_active_actor"
    assert open(revoked, encoding="utf-8").read() == original


def test_adopt_enrollment_refuses_an_entry_whose_secret_is_not_the_enrolled_key(
    trust, tmp_path
):
    """Matching on public_key proves a DECLARATION; the secret has to be derived.

    ``KeySet.describe_keys()``'s fingerprint cannot catch this: for an asymmetric entry
    ``KeyEntry.fingerprint()`` digests the ``public_key`` FIELD, so an entry that
    declares the enrolled key while holding someone else's private material fingerprints
    identically to a correct one. Deriving the public key from the effective secret is
    the only check that separates them — and it runs BEFORE the file is touched.
    """
    stranger = nacl.signing.SigningKey.generate()
    path = tmp_path / "lying_keys.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "pk_stale",
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        # Someone else's private half...
                        "secret": base64.b64encode(bytes(stranger)).decode("ascii"),
                        "encoding": "base64",
                        # ...under the enrolled key's declared public half.
                        "public_key": base64.b64encode(trust.host_public).decode("ascii"),
                        "principal_id": "old-label",
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    original = open(path, encoding="utf-8").read()
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=str(path), genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.code is ErrorCode.KEYSET_ADOPTION_REFUSED
    assert exc.value.detail["reason"] == (
        "matched_entry_secret_does_not_match_declared_public_key"
    )
    # Refused at preflight: no write, and therefore no backup to clean up.
    assert open(path, encoding="utf-8").read() == original
    assert not [p for p in tmp_path.iterdir() if ".bak." in p.name]


def test_adopt_enrollment_post_write_check_catches_a_changed_effective_secret(
    trust, tmp_path, monkeypatch
):
    """The post-write guard, driven by the hazard that motivates it.

    ``KeySet`` resolves a per-key env override named ``REGISTA_HMAC_KEY_<KEY_ID>``, so
    renaming an entry's key_id changes WHICH variable supplies its secret. Here the entry
    holds the enrolled seed inline (so the preflight passes) while an override keyed to
    the NEW key_id holds different material — used textually, per the WI-236
    effective-key rule, which is why the value is 32 raw ASCII bytes rather than base64.
    After the rewrite the entry signs with a different key, and a relabel that swapped a
    project's signing key would be the worst possible outcome of a convenience command.
    """
    correct = _keyfile(
        tmp_path / "override_keys.json", key_id="pk_stale", principal_id="old-label",
        seed=trust.host_seed, public=trust.host_public,
    )
    env_name = "REGISTA_HMAC_KEY_" + trust.host_key_id.upper().replace("-", "_")
    monkeypatch.setenv(env_name, "A" * 32)

    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=correct, genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.code is ErrorCode.KEYSET_ADOPTION_REFUSED
    assert exc.value.detail["reason"] == "post_write_secret_changed"

    # The refusal must hand the operator a recoverable original.
    backup = exc.value.detail["backup"]
    assert os.path.exists(backup)
    restored = json.loads(open(backup, encoding="utf-8").read())["keys"][0]
    assert restored["key_id"] == "pk_stale"
    assert restored["principal_id"] == "old-label"
    assert restored["secret"] == base64.b64encode(trust.host_seed).decode("ascii")
    assert open(correct, "rb").read() == open(backup, "rb").read()
    assert exc.value.detail["restored"] is True
    assert exc.value.detail["partial"] is False


def test_adopt_enrollment_restores_when_relabelled_keyset_will_not_load(
    trust, tmp_path, monkeypatch
):
    from regista._keys import KeySet

    path = _keyfile(
        tmp_path / "unloadable_after.json",
        key_id="pk_stale",
        principal_id="old-label",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    original_get_key = KeySet.get_key
    calls = 0

    def fail_second_load(self, key_id):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RegistaError(ErrorCode.KEY_LOAD_ERROR, "synthetic post-write failure")
        return original_get_key(self, key_id)

    monkeypatch.setattr(KeySet, "get_key", fail_second_load)
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(
                hmac_key_path=path,
                genesis=trust.genesis,
                trust_project=trust.project,
            )
        )

    assert exc.value.detail["reason"] == "post_write_keyset_unloadable"
    assert exc.value.detail["restored"] is True
    assert open(path, "rb").read() == open(exc.value.detail["backup"], "rb").read()


def test_adopt_enrollment_restores_on_post_write_public_key_mismatch(
    trust, tmp_path, monkeypatch
):
    from regista._keys import KeySet

    path = _keyfile(
        tmp_path / "public_mismatch_after.json",
        key_id="pk_stale",
        principal_id="old-label",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    original_get_key = KeySet.get_key
    calls = 0

    def change_second_public_key(self, key_id):
        nonlocal calls
        calls += 1
        entry = original_get_key(self, key_id)
        if calls == 2:
            return replace(entry, public_key=b"x" * 32)
        return entry

    monkeypatch.setattr(KeySet, "get_key", change_second_public_key)
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(
                hmac_key_path=path,
                genesis=trust.genesis,
                trust_project=trust.project,
            )
        )

    assert exc.value.detail["reason"] == "post_write_public_key_not_enrolled"
    assert exc.value.detail["restored"] is True
    assert open(path, "rb").read() == open(exc.value.detail["backup"], "rb").read()


def test_adopt_enrollment_names_partial_mutation_when_rollback_fails(
    trust, tmp_path, monkeypatch
):
    path = _keyfile(
        tmp_path / "rollback_failure.json",
        key_id="pk_stale",
        principal_id="old-label",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    env_name = "REGISTA_HMAC_KEY_" + trust.host_key_id.upper().replace("-", "_")
    monkeypatch.setenv(env_name, "A" * 32)
    original_copy2 = shutil.copy2

    def fail_restore(src, dst, *args, **kwargs):
        if ".bak." in os.fspath(src):
            raise OSError("synthetic rollback failure")
        return original_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", fail_restore)
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(
                hmac_key_path=path,
                genesis=trust.genesis,
                trust_project=trust.project,
            )
        )

    assert exc.value.detail["reason"] == "post_write_restore_failed"
    assert exc.value.detail["original_reason"] == "post_write_secret_changed"
    assert exc.value.detail["partial"] is True
    assert os.path.exists(exc.value.detail["backup"])
    assert json.loads(open(path, encoding="utf-8").read())["keys"][0]["key_id"] == (
        trust.host_key_id
    )


def test_adopt_enrollment_names_partial_mutation_when_restore_temp_allocation_fails(
    trust, tmp_path, monkeypatch
):
    path = _keyfile(
        tmp_path / "rollback_allocation_failure.json",
        key_id="pk_stale",
        principal_id="old-label",
        seed=trust.host_seed,
        public=trust.host_public,
    )
    env_name = "REGISTA_HMAC_KEY_" + trust.host_key_id.upper().replace("-", "_")
    monkeypatch.setenv(env_name, "A" * 32)
    original_mkstemp = tempfile.mkstemp

    def fail_restore_temp(*args, **kwargs):
        if str(kwargs.get("prefix", "")).startswith(".regista-keys-restore-"):
            raise OSError("synthetic restore allocation failure")
        return original_mkstemp(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", fail_restore_temp)
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(
                hmac_key_path=path,
                genesis=trust.genesis,
                trust_project=trust.project,
            )
        )

    assert exc.value.detail["reason"] == "post_write_restore_failed"
    assert exc.value.detail["partial"] is True
    assert os.path.exists(exc.value.detail["backup"])


def test_adopt_enrollment_refuses_a_target_key_id_collision(trust, tmp_path):
    path = tmp_path / "collide_keys.json"
    stranger = nacl.signing.SigningKey.generate()
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": "pk_stale",
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": base64.b64encode(trust.host_seed).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(trust.host_public).decode("ascii"),
                        "principal_id": "old",
                        "role": "actor",
                        "status": "active",
                    },
                    {
                        "key_id": trust.host_key_id,
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": base64.b64encode(bytes(stranger)).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(
                            bytes(stranger.verify_key)
                        ).decode("ascii"),
                        "principal_id": "someone-else",
                        "role": "actor",
                        "status": "active",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RegistaError) as exc:
        cmd_keys_adopt_enrollment(
            _adopt_ns(hmac_key_path=str(path), genesis=trust.genesis,
                      trust_project=trust.project)
        )
    assert exc.value.detail["reason"] == "target_key_id_already_present"


# ------------------------------------------------------------ envelope assembly


def test_the_assembled_envelope_passes_the_writer_validator(trust, target):
    """Assembly and validation must not be able to drift apart."""
    from regista._genesis import _validate_genesis_envelope
    from regista._genesis_open import measure_previous_epoch, resolve_trust_reference

    mgr = ConnectionManager(DSN, trust.project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            reference = resolve_trust_reference(
                conn,
                trust.fx.document,
                principal_id=HOST,
                published_checkpoint_path=trust.checkpoint,
                publication_repo=trust.publication_repo,
                publication_commit=trust.publication_commit,
            )
    finally:
        mgr.close()
    target_mgr = ConnectionManager(DSN, target.project)
    try:
        target_mgr.open()
        with target_mgr.transaction() as conn:
            previous = measure_previous_epoch(conn)
    finally:
        target_mgr.close()

    project_instance_id = str(uuid.uuid4())
    envelope = build_project_initialized_envelope(
        project_instance_id=project_instance_id,
        reference=reference,
        producer={
            "harness": "pytest", "harness_version": "0",
            "model": "test-fixture", "model_lineage": "fable",
        },
        previous_epoch=previous,
        gate=load_gate_evidence(target.gate, dsn=DSN, project=target.project),
        occurred_at=datetime.now(UTC),
    )
    _validate_genesis_envelope(envelope)

    assert envelope["transition"] == "project_initialized"
    assert envelope["entity"] == {"kind": "project", "id": project_instance_id}
    assert envelope["entity_seq"] == 1
    assert envelope["workflow"] is None
    assert envelope["signing"]["key_binding_event_hash"] is None
    assert envelope["actor"]["kind"] == "agent"
    gate_metadata = envelope["actor"]["metadata"]["genesis_gate"]
    loaded_gate = load_gate_evidence(target.gate, dsn=DSN, project=target.project)
    assert gate_metadata["report_digest"] == loaded_gate.report_digest
    assert gate_metadata["observation_snapshot"] == loaded_gate.observation_snapshot
    payload = envelope["payload"]
    assert set(payload) == {
        "bootstrap_key_acceptance", "genesis_document_digest", "previous_epoch",
        "trust_domain_core_digest", "trust_log_checkpoint",
    }
    acceptance = payload["bootstrap_key_acceptance"]
    assert acceptance["scopes"]["may_accept_keys"] is True
    assert acceptance["scopes"]["may_sign_checkpoints"] is True
    assert acceptance["scopes"]["may_sign_bundles"] is False
    assert acceptance["scopes"]["entity_kinds"] == list(DEFAULT_SCOPE_ENTITY_KINDS)
    # previous_epoch is MEASURED on an empty store, not asserted.
    assert previous.empty is True
    assert payload["previous_epoch"]["event_count"] == 0
    assert payload["previous_epoch"]["scheme_counts"] == {}


def test_scope_entity_kinds_are_validated_against_the_closed_registry():
    assert validate_scope_entity_kinds(["project,work_item", " principal "]) == (
        "project", "work_item", "principal",
    )
    with pytest.raises(RegistaError) as exc:
        validate_scope_entity_kinds(["project", "not_a_kind"])
    assert exc.value.detail["reason"] == "entity_kind_not_in_registry"
    with pytest.raises(RegistaError) as exc:
        validate_scope_entity_kinds(["work_item"])
    assert exc.value.detail["reason"] == "entity_kinds_missing_project"
    with pytest.raises(RegistaError) as exc:
        validate_scope_entity_kinds([" , "])
    assert exc.value.detail["reason"] == "entity_kinds_empty"


def test_narrowed_scopes_reach_the_signed_acceptance(trust, target):
    result = _init(trust, target, scope_entity_kind=["project,work_item"],
                   may_sign_bundles=True)
    assert result["ok"] is True
    handle = Regista(DSN, target.project, target.keys)
    try:
        recovered = handle.read_genesis()
    finally:
        handle.close()
    from regista._verification import parse_v6_envelope_strict

    envelope = parse_v6_envelope_strict(recovered.canonical_envelope)
    scopes = envelope["payload"]["bootstrap_key_acceptance"]["scopes"]
    assert scopes["entity_kinds"] == ["project", "work_item"]
    assert scopes["may_sign_bundles"] is True
