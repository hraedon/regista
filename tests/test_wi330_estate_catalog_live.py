"""WI-330 ``regista trust catalog`` against a LIVE estate (DB-backed).

The byte contract and every fail-closed refusal are pinned database-free in
``test_wi330_estate_catalog.py``. What can only be proven here is that the fields the
operator does **not** supply are *measured*: the ``project_instance_id`` that
``genesis init`` minted, the event that opened the epoch, the current chain head, and
the digest of a checkpoint reconciled against the real trust log. An honest measurement
and a plausible operator flag look identical in the signed bytes and are not the same
claim (``EPOCH-RESET.md`` §6 rule 3), so the only way to test the difference is to run
the ceremony.

The fixture assembles the estate through the real CLI verbs — ``trust init-log``,
``trust delegate-registrar``, ``trust enroll``, ``trust rebuild-projection``,
``genesis init`` — plus a real two-commit §4.2 publication channel with a root-signed
§4.3 checkpoint. It is module-scoped because ``trust catalog`` only ever READS it;
building it per test would multiply the module's runtime for no extra coverage.

Timestamps are anchored at CALL time (the ``tests/_trust_log_fixtures._ts`` rule): the
enrolment window and the possession challenge are both live-window checked, so a
module-import constant would be a time bomb minutes into a full-suite run.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import pathlib
import subprocess
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_solo

from regista._cli import cmd_trust_catalog, cmd_trust_verify_catalog
from regista._errors import ErrorCode, RegistaError
from regista._estate_catalog import (
    estate_catalog_digest,
    genesis_root_authority,
    trust_log_root_authority,
    verify_estate_catalog,
)
from regista._jcs import canonicalize

ROOT_PRINCIPAL = "service:root-a"
REGISTRAR = "service:registrar-1"
HOST = "agent:wi330-host"

#: The frozen legacy population an operator recorded before the freeze (runbook §2.4).
#: Deliberately not derivable from any live store — that is the point of the field.
RECORDED_LEGACY: dict[str, Any] = {
    "legacy_head_event_hash": "sha256:" + "dd" * 32,
    "legacy_event_count": 1000,
    "scheme_counts": {"hmac-sha256": 800, "ed25519": 200},
}


# --------------------------------------------------------------------------- helpers


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def _refusal(fn, *args, **kwargs) -> RegistaError:
    with pytest.raises(RegistaError) as excinfo:
        fn(*args, **kwargs)
    return excinfo.value


def _reason(error: RegistaError) -> str:
    detail = error.detail or {}
    return str(detail.get("reason"))


def _write_json(path, obj) -> str:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def _seed_file(path, seed: bytes) -> str:
    path.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    return str(path)


def _keyfile(path, *, key_id: str, principal_id: str, seed: bytes, public: bytes) -> str:
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": base64.b64encode(seed).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(public).decode("ascii"),
                        "principal_id": principal_id,
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _git(repo, *args) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args), capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()


def _commit(repo, message: str) -> None:
    _git(
        repo,
        "-c",
        "user.name=Regista Test",
        "-c",
        "user.email=regista-test@example.invalid",
        "commit",
        "-m",
        message,
    )


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _inputs(*projects: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "regista.estate-catalog-inputs",
        "version": 1,
        "projects": list(projects),
    }


def _gate_report(path, *, project: str) -> str:
    """A minimal ``agent-suite genesis-gate --json`` report for an empty target.

    Hand-written rather than imported: regista must not depend on the component whose
    verdict it consumes, and the report is a wire contract — so a hand-written fixture
    is the honest test of what regista accepts off the wire.
    """
    from regista._invariant_probe import postgres_database_fingerprint

    fingerprint = postgres_database_fingerprint(DSN)
    probe_checks = {
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
            {"id": "regista.load_bearing_fields_refused", "status": "pass", "detail": "refused"},
            {"id": "regista.closed_lineage_registry", "status": "pass", "detail": "closed"},
            {"id": "regista.first_write_admission", "status": "pass", "detail": "passed"},
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
            {"id": "cairn.runtime_model_observed", "status": "pass", "detail": "observed"},
            {"id": "cairn.unavailable_model_named", "status": "pass", "detail": "named"},
            {
                "id": "cairn.observation_failure_nonblocking",
                "status": "pass",
                "detail": "nonblocking",
            },
        ],
        "agent-notes": [
            {
                "id": "agent_notes.session_identity_resolvable",
                "status": "pass",
                "detail": "resolved",
            }
        ],
    }
    findings = [
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
            "report_version": 1,
            "kind": "genesis_gate",
            "ok": True,
            "epoch_may_open": True,
            "binding": {
                "expected_store_fingerprint": fingerprint,
                "reported_store_fingerprint": fingerprint,
                "project": project,
                "observation_snapshot": "pg:100:100:",
            },
            "findings": [
                {"check_id": check_id, "status": "pass", "detail": "passed"}
                for check_id in findings
            ],
            "probes": {
                "report_version": 1,
                "kind": "invariant_probes",
                "ok": True,
                "probes": [
                    {
                        "component": component,
                        "status": "pass",
                        "ok": True,
                        "detail": "probe passed",
                        "checks": checks,
                    }
                    for component, checks in probe_checks.items()
                ],
            },
        },
    )


# -------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def _producer_env(monkeypatch):
    """The v6 writer needs a process-level producer identity or it refuses."""
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS", "pytest")
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-fixture")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")
    # The commands resolve the pinned genesis from --genesis here; an ambient pin
    # must not shadow that.
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    """One trust log, one published checkpoint channel, two opened project epochs."""
    from regista import Regista
    from regista._cli import (
        cmd_genesis_init,
        cmd_trust_delegate_registrar,
        cmd_trust_enroll,
        cmd_trust_init_log,
        cmd_trust_rebuild_projection,
    )
    from regista._connection import ConnectionManager
    from regista._genesis_open import _checkpoint_signature_input
    from regista._trust_domain import derive_governance_mode
    from regista._trust_log import PossessionChallengeV2
    from regista._trust_log_writer import verify_trust_log_chain
    from regista.testing import drop_project_schema

    tmp_path = tmp_path_factory.mktemp("wi330")
    trust_project = f"wi330t_{uuid.uuid4().hex[:8]}"
    fx = mint_solo(project_name_hint=trust_project, declared_holder=ROOT_PRINCIPAL)
    genesis = _write_json(tmp_path / "genesis.json", fx.document)
    root_signer = fx.signer_ids[0]
    root_seed = fx.seeds[root_signer]
    root_seed_path = _seed_file(tmp_path / "root.seed", root_seed)
    root_keyfile = _keyfile(
        tmp_path / "root_keys.json",
        key_id=f"k_{root_signer}",
        principal_id=ROOT_PRINCIPAL,
        seed=root_seed,
        public=fx.public_keys[root_signer],
    )
    # The module-scoped fixture runs before the function-scoped autouse one, so the
    # producer identity has to be set here for the setup writes.
    for name, value in (
        ("REGISTA_PRODUCER_HARNESS", "pytest"),
        ("REGISTA_PRODUCER_HARNESS_VERSION", "0"),
        ("REGISTA_PRODUCER_MODEL", "test-fixture"),
        ("REGISTA_PRODUCER_MODEL_LINEAGE", "fable"),
    ):
        os.environ.setdefault(name, value)

    cmd_trust_init_log(
        argparse.Namespace(
            dsn=DSN, project=trust_project, hmac_key_path=None, genesis=genesis,
            key=root_seed_path, root_principal_id=ROOT_PRINCIPAL, dry_run=False, json=False,
        )
    )
    registrar_sk = nacl.signing.SigningKey.generate()
    registrar_seed_path = _seed_file(tmp_path / "registrar.seed", bytes(registrar_sk))
    cmd_trust_delegate_registrar(
        argparse.Namespace(
            dsn=DSN, project=trust_project, hmac_key_path=None,
            registrar_principal_id=REGISTRAR,
            registrar_public_key=base64.b64encode(bytes(registrar_sk.verify_key)).decode("ascii"),
            registrar_key_id="k_registrar", key=root_seed_path,
            root_principal_id=ROOT_PRINCIPAL, scope=None, not_before=None, not_after=None,
            max_operations=None, genesis=genesis, dry_run=False, json=False,
        )
    )
    host_sk = nacl.signing.SigningKey.generate()
    host_seed = bytes(host_sk)
    host_public = bytes(host_sk.verify_key)

    def _enroll_ns(**kwargs):
        base = dict(
            dsn=DSN, project=trust_project, hmac_key_path=None, principal=HOST,
            public_key=base64.b64encode(host_public).decode("ascii"), issue_challenge=False,
            ttl_minutes=None, proof=None, proof_file=None, key=None,
            registrar_principal_id=None, custody_backend=None, policy_ref=None,
            genesis=genesis, dry_run=False, json=True,
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    challenge = json.loads(_capture(cmd_trust_enroll, _enroll_ns(issue_challenge=True)))
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
    cmd_trust_rebuild_projection(
        argparse.Namespace(
            dsn=DSN, project=trust_project, hmac_key_path=root_keyfile, genesis=genesis,
            dry_run=False, json=False,
        )
    )

    # A real §4.2 publication channel: genesis commit, then checkpoint commit.
    publication_repo = tmp_path / "publication"
    publication_repo.mkdir()
    _git(publication_repo, "init", "-b", "main")
    published_at = _iso(datetime.now(UTC))
    canonical_genesis = canonicalize(fx.document)
    (publication_repo / "trust-domain.json").write_bytes(canonical_genesis)
    index: dict[str, Any] = {
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
    _commit(publication_repo, "regista: publish genesis test")
    genesis_commit = _git(publication_repo, "rev-parse", "HEAD")

    mgr = ConnectionManager(DSN, trust_project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            chain = verify_trust_log_chain(conn, fx.document)
    finally:
        mgr.close()
    checkpoint: dict[str, Any] = {
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
    checkpoint["root_signatures"] = [
        {
            "signer_id": root_signer,
            "fingerprint": fx.fingerprints[root_signer],
            "signature": base64.b64encode(
                nacl.signing.SigningKey(root_seed)
                .sign(_checkpoint_signature_input(checkpoint))
                .signature
            ).decode("ascii"),
        }
    ]
    checkpoint_bytes = canonicalize(checkpoint)
    checkpoint_rel = (
        f"checkpoints/{fx.document['trust_domain_id']}/00000001-20260821T000000.000000Z.json"
    )
    checkpoint_path = publication_repo / checkpoint_rel
    checkpoint_path.parent.mkdir(parents=True)
    checkpoint_path.write_bytes(checkpoint_bytes)
    index["entries"].append(
        {
            "path": checkpoint_rel,
            "sha256": "sha256:" + hashlib.sha256(checkpoint_bytes).hexdigest(),
            "published_at": published_at,
            "prev_commit": genesis_commit,
        }
    )
    (publication_repo / "index.json").write_bytes(canonicalize(index))
    _git(publication_repo, "add", checkpoint_rel, "index.json")
    _commit(publication_repo, "regista: publish checkpoint test")
    publication_commit = _git(publication_repo, "rev-parse", "HEAD")

    # Two ordinary projects with opened epochs. The second exists so a
    # legacy-store cross-check has a real, non-empty schema to measure that is NOT
    # the entry's own target (the inputs parser refuses those being the same).
    host_keyfile = _keyfile(
        tmp_path / "host_keys.json",
        key_id=enrolled["key_id"], principal_id=HOST, seed=host_seed, public=host_public,
    )
    opened: dict[str, dict[str, Any]] = {}
    project_names = []
    for tag in ("a", "b"):
        project = f"wi330p{tag}_{uuid.uuid4().hex[:8]}"
        project_names.append(project)
        handle = Regista.create_project(DSN, project, host_keyfile)
        handle.close()
        result = json.loads(
            _capture(
                cmd_genesis_init,
                argparse.Namespace(
                    dsn=DSN, project=project, hmac_key_path=host_keyfile, principal=HOST,
                    gate_report=_gate_report(tmp_path / f"gate_{tag}.json", project=project),
                    genesis=genesis, trust_project=trust_project, key_id=None,
                    trust_event_hash=None, trust_domain_id=None,
                    trust_checkpoint=str(checkpoint_path),
                    trust_publication_repo=str(publication_repo),
                    trust_publication_commit=publication_commit,
                    checkpoint_seq=1, project_instance_id=None, scope_entity_kind=None,
                    may_sign_bundles=False, dry_run=False, json=True,
                ),
            )
        )
        assert result["ok"] is True, result
        opened[project] = result

    yield SimpleNamespace(
        fx=fx,
        genesis=genesis,
        trust_project=trust_project,
        target_project=project_names[0],
        second_project=project_names[1],
        opened=opened,
        # The genesis event hash `genesis init` reported, per project. It IS the chain
        # head after one event, so it doubles as the approved preflight head — which is
        # exactly how an operator would obtain it (review F1).
        heads={project: result["event_hash"] for project, result in opened.items()},
        root_signer=root_signer,
        root_seed_path=root_seed_path,
        checkpoint=str(checkpoint_path),
        checkpoint_bytes=checkpoint_bytes,
        checkpoint_digest="sha256:" + hashlib.sha256(checkpoint_bytes).hexdigest(),
        publication_repo=str(publication_repo),
        publication_commit=publication_commit,
        host_keyfile=host_keyfile,
        tmp_path=tmp_path,
    )
    for project in project_names:
        drop_project_schema(DSN, project)
    drop_project_schema(DSN, trust_project)


def _catalog_ns(estate, **overrides) -> argparse.Namespace:
    base: dict[str, Any] = {
        "dsn": DSN,
        "project": None,
        "hmac_key_path": None,
        "inputs": None,
        "expected_estate": None,
        "out": None,
        "key": [estate.root_seed_path],
        "incomplete_signatures": False,
        "allow_partial": False,
        "trust_checkpoint": estate.checkpoint,
        "trust_publication_repo": estate.publication_repo,
        "trust_publication_commit": estate.publication_commit,
        "genesis": estate.genesis,
        "trust_project": estate.trust_project,
        "created_at": None,
        "prev_commit": None,
        "force": False,
        "dry_run": False,
        "json": True,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _verify_ns(estate, **overrides) -> argparse.Namespace:
    base: dict[str, Any] = {
        "dsn": None,
        "project": None,
        "hmac_key_path": None,
        "file": None,
        "genesis": estate.genesis,
        "trust_checkpoint": estate.checkpoint,
        "expected_estate": None,
        "trust_log_project": None,
        "trust_log_dsn": None,
        "expect_digest": None,
        "json": True,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _preflight(estate, project: str) -> dict[str, Any]:
    """The approved preflight numbers for ``project``, as recorded at genesis time.

    ``genesis init`` printed the event hash it wrote; that is the head and the count is
    1. Supplying them is what makes the command's own derivation checkable
    (``ARCHITECTURE-0.6.0.md``:802-810).
    """
    return {
        "expected_new_epoch_head_event_hash": estate.heads[project],
        "expected_new_epoch_event_count": 1,
    }


def _inputs_file(estate, tmp_path, *entries: dict[str, Any], name="inputs.json") -> str:
    return _write_json(tmp_path / name, _inputs(*entries))


def _estate_inputs(estate, tmp_path, name: str = "inputs.json", **overrides) -> str:
    entry: dict[str, Any] = {
        "project": estate.target_project,
        **RECORDED_LEGACY,
        **_preflight(estate, estate.target_project),
    }
    entry.update(overrides)
    return _write_json(tmp_path / name, _inputs(entry))


def _manifest_file(estate, tmp_path, *projects: str, name="estate.json") -> str:
    """The expected-estate manifest naming exactly ``projects``."""
    return _write_json(
        tmp_path / name,
        {
            "type": "regista.estate-manifest",
            "version": 1,
            "trust_domain_id": estate.fx.document["trust_domain_id"],
            "project_instance_ids": [
                estate.opened[project]["project_instance_id"] for project in projects
            ],
        },
    )


def _run(estate, tmp_path, *, out, **overrides) -> dict[str, Any]:
    inputs = overrides.pop("inputs", None) or _estate_inputs(estate, tmp_path)
    manifest = overrides.pop("expected_estate", None) or _manifest_file(
        estate, tmp_path, estate.target_project
    )
    return json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, expected_estate=manifest, out=str(out), **overrides
            ),
        )
    )


# ------------------------------------------------------------------- the keystone


def test_trust_catalog_end_to_end(estate, tmp_path) -> None:
    """The live ceremony: facts are RECOMPUTED from signed events, and it verifies.

    Asserts the values only a store read can get right — the ``project_instance_id``
    ``genesis init`` minted, the epoch-opening event hash, the current head — and then
    re-verifies the written bytes through the public verifier with the checkpoint and
    the expected-estate manifest presented, which is what runbook §5.4 step 5 does from
    an independent checkout.
    """
    out = tmp_path / "catalog.json"
    result = _run(estate, tmp_path, out=out)

    assert result["verdict"] == "VALID"
    assert result["catalog_kind"] == "cutover"
    assert result["catalog_status"] == "complete"
    assert result["project_count"] == 1
    assert result["expected_project_count"] == 1
    assert result["missing_project_instance_ids"] == []
    assert result["trust_domain_id"] == estate.fx.document["trust_domain_id"]
    assert result["trust_log_checkpoint_digest"] == estate.checkpoint_digest
    assert result["trust_log_checkpoint_source"] == "published"
    assert result["trust_log_checkpoint_signatures_verified"] == 1
    assert result["trust_log_publication_commit"] == estate.publication_commit
    assert result["publication"] == "operator_step"
    assert result["epoch_facts_source"] == "recomputed_from_signed_events"
    assert result["threshold_met"] is True
    assert result["legacy_measurement_sources"] == {estate.target_project: "operator_recorded"}

    entry = result["projects"][0]
    assert entry["project_instance_id"] == estate.opened[estate.target_project][
        "project_instance_id"
    ]
    assert entry["legacy_head_event_hash"] == RECORDED_LEGACY["legacy_head_event_hash"]
    assert entry["legacy_event_count"] == 1000
    # `genesis init` wrote exactly one event, so the epoch-opening event IS the head.
    # Both are RECOMPUTED from event bytes (judgment call 3 / review F1).
    assert entry["cutover_event_hash"] == estate.heads[estate.target_project]
    assert entry["cutover_event_hash"] == entry["new_epoch_head_event_hash"]

    written = out.read_bytes()
    document = json.loads(written.decode("utf-8"))
    assert written == canonicalize(document), "the artifact must be exact canonical JCS"
    assert "catalog_status" not in document, "a complete catalog OMITS catalog_status"
    report = verify_estate_catalog(
        document,
        genesis_document=estate.fx.document,
        authority=genesis_root_authority(estate.fx.document),
        trust_log_checkpoint_bytes=estate.checkpoint_bytes,
        expected_estate=json.loads(
            pathlib.Path(_manifest_file(estate, tmp_path, estate.target_project)).read_text()
        ),
        file_bytes=written,
        expect_digest=result["estate_catalog_digest"],
    )
    assert report.verdict == "VALID"
    assert report.digest_pin_status == "matched"
    assert report.checkpoint.document_digest == estate.checkpoint_digest


# ------------------------------------------------------- F1: forged posture rows


def _forge(project: str, statement: str, params: list[Any]) -> None:
    from regista._connection import ConnectionManager

    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            conn.execute(statement, params)
    finally:
        mgr.close()


@pytest.fixture
def forgeable(estate, tmp_path):
    """A throwaway project with an opened epoch whose posture rows a test may forge.

    Separate from the module-scoped estate so a forgery cannot leak into the other
    tests, and dropped afterwards.
    """
    from regista import Regista
    from regista._cli import cmd_genesis_init
    from regista.testing import drop_project_schema

    project = f"wi330f_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, estate.host_keyfile)
    handle.close()
    opened = json.loads(
        _capture(
            cmd_genesis_init,
            argparse.Namespace(
                dsn=DSN, project=project, hmac_key_path=estate.host_keyfile, principal=HOST,
                gate_report=_gate_report(tmp_path / "gate_forge.json", project=project),
                genesis=estate.genesis, trust_project=estate.trust_project, key_id=None,
                trust_event_hash=None, trust_domain_id=None,
                trust_checkpoint=estate.checkpoint,
                trust_publication_repo=estate.publication_repo,
                trust_publication_commit=estate.publication_commit,
                checkpoint_seq=1, project_instance_id=None, scope_entity_kind=None,
                may_sign_bundles=False, dry_run=False, json=True,
            ),
        )
    )
    assert opened["ok"] is True, opened
    try:
        yield SimpleNamespace(project=project, opened=opened)
    finally:
        drop_project_schema(DSN, project)


def _forgeable_inputs(estate, forgeable, tmp_path) -> tuple[str, str]:
    inputs = _write_json(
        tmp_path / "forge_inputs.json",
        _inputs(
            {
                "project": forgeable.project,
                **RECORDED_LEGACY,
                "expected_new_epoch_head_event_hash": forgeable.opened["event_hash"],
                "expected_new_epoch_event_count": 1,
            }
        ),
    )
    manifest = _write_json(
        tmp_path / "forge_estate.json",
        {
            "type": "regista.estate-manifest",
            "version": 1,
            "trust_domain_id": estate.fx.document["trust_domain_id"],
            "project_instance_ids": [forgeable.opened["project_instance_id"]],
        },
    )
    return inputs, manifest


def test_forged_chain_head_row_is_refused(estate, forgeable, tmp_path) -> None:
    """Reviewer probe (F1): a forged ``event_chain_head`` produced a VALID catalog.

    ``event_chain_head.head_hash`` is a mutable posture row. The events are left
    untouched here — only the row is rewritten — which is exactly the shape of edit
    ``ARCHITECTURE-0.6.0.md``:802-810 says a verifier must not trust: "the signed event,
    not the mutable posture row, tells future verifiers where strict v6 rules begin".
    The head is now RECOMPUTED with ``compute_chain_head_hash`` over the max-global_seq
    event's signed bytes and the row is checked against it.
    """
    inputs, manifest = _forgeable_inputs(estate, forgeable, tmp_path)
    _forge(
        forgeable.project,
        "UPDATE event_chain_head SET head_hash = %s WHERE id = TRUE",
        [bytes.fromhex("ab" * 32)],
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=inputs,
            expected_estate=manifest,
            out=str(tmp_path / "x.json"),
        ),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "new_epoch_head_row_contradicts_events"
    assert error.detail["stated"] == "sha256:" + "ab" * 32
    assert error.detail["recomputed"] == forgeable.opened["event_hash"]
    assert not (tmp_path / "x.json").exists()


def test_forged_project_identity_genesis_hash_is_refused(
    estate, forgeable, tmp_path
) -> None:
    """Reviewer probe (F1), other row: ``project_identity.genesis_event_hash`` forged.

    That column is what ``cutover_event_hash`` used to be read from verbatim. It is now
    recomputed from the first event's signed bytes.
    """
    inputs, manifest = _forgeable_inputs(estate, forgeable, tmp_path)
    _forge(
        forgeable.project,
        "UPDATE project_identity SET genesis_event_hash = %s WHERE id = TRUE",
        [bytes.fromhex("cd" * 32)],
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(tmp_path / "x.json")
        ),
    )
    assert _reason(error) == "genesis_event_hash_row_contradicts_events"
    assert error.detail["stated"] == "sha256:" + "cd" * 32


def test_forged_project_identity_instance_id_is_refused(
    estate, forgeable, tmp_path
) -> None:
    """The project's IDENTITY is taken from inside the signed genesis envelope."""
    inputs, manifest = _forgeable_inputs(estate, forgeable, tmp_path)
    imposter = str(uuid.uuid4())
    _forge(
        forgeable.project,
        "UPDATE project_identity SET project_instance_id = %s WHERE id = TRUE",
        [imposter],
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(tmp_path / "x.json")
        ),
    )
    assert _reason(error) == "project_identity_contradicts_genesis_envelope"
    assert error.detail["field"] == "project_instance_id"
    assert error.detail["row"] == imposter


def test_preflight_mismatch_is_refused(estate, forgeable, tmp_path) -> None:
    """The second witness: an operator-recorded preflight head that disagrees.

    ``ARCHITECTURE-0.6.0.md``:802-810 — "Confirm the head/count equal the approved
    preflight result." The command derived one value from event bytes; the operator
    recorded another; the ceremony stops rather than picking a winner.
    """
    inputs = _write_json(
        tmp_path / "bad_preflight.json",
        _inputs(
            {
                "project": forgeable.project,
                **RECORDED_LEGACY,
                "expected_new_epoch_head_event_hash": "sha256:" + "9e" * 32,
                "expected_new_epoch_event_count": 1,
            }
        ),
    )
    _, manifest = _forgeable_inputs(estate, forgeable, tmp_path)
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(tmp_path / "x.json")
        ),
    )
    assert _reason(error) == "new_epoch_preflight_mismatch"
    assert error.detail["derived"]["new_epoch_head_event_hash"] == forgeable.opened[
        "event_hash"
    ]


def test_preflight_count_mismatch_is_refused(estate, forgeable, tmp_path) -> None:
    inputs = _write_json(
        tmp_path / "bad_count.json",
        _inputs(
            {
                "project": forgeable.project,
                **RECORDED_LEGACY,
                "expected_new_epoch_head_event_hash": forgeable.opened["event_hash"],
                "expected_new_epoch_event_count": 99,
            }
        ),
    )
    _, manifest = _forgeable_inputs(estate, forgeable, tmp_path)
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(tmp_path / "x.json")
        ),
    )
    assert _reason(error) == "new_epoch_preflight_mismatch"
    assert error.detail["derived"]["event_count"] == 1


# ------------------------------------------------------ F4: completeness at build


def test_trust_catalog_refuses_a_partial_estate_by_default(estate, tmp_path) -> None:
    """Reviewer finding (F4): a catalog missing a project used to be produced silently.

    ``RECONCILIATION.md``:682-684 — the ceremony publishes the COMPLETE catalog, and "a
    partial catalog says catalog_status: partial and is ceremony failure, not success".
    """
    manifest = _manifest_file(
        estate, tmp_path, estate.target_project, estate.second_project
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=manifest,
            out=str(tmp_path / "x.json"),
        ),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "catalog_would_be_partial"
    assert error.detail["expected"] == 2
    assert error.detail["covered"] == 1
    assert error.detail["missing_project_instance_ids"] == [
        estate.opened[estate.second_project]["project_instance_id"]
    ]
    assert not (tmp_path / "x.json").exists()


def test_allow_partial_stamps_the_signed_bytes(estate, tmp_path) -> None:
    """``--allow-partial`` produces a catalog that says so, inside the signature."""
    out = tmp_path / "partial.json"
    manifest = _manifest_file(
        estate, tmp_path, estate.target_project, estate.second_project
    )
    result = _run(estate, tmp_path, out=out, expected_estate=manifest, allow_partial=True)
    assert result["catalog_status"] == "partial"
    assert result["verdict"] == "PARTIAL"
    document = json.loads(out.read_bytes().decode("utf-8"))
    assert document["catalog_status"] == "partial"
    # Inside the signed core, so it cannot be stripped after the fact.
    stripped = {k: v for k, v in document.items() if k != "catalog_status"}
    assert estate_catalog_digest(stripped) != estate_catalog_digest(document)


def test_trust_catalog_refuses_a_project_outside_the_expected_estate(
    estate, tmp_path
) -> None:
    manifest = _write_json(
        tmp_path / "other_estate.json",
        {
            "type": "regista.estate-manifest",
            "version": 1,
            "trust_domain_id": estate.fx.document["trust_domain_id"],
            "project_instance_ids": [str(uuid.uuid4())],
        },
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=manifest,
            out=str(tmp_path / "x.json"),
        ),
    )
    assert _reason(error) == "catalog_project_not_in_expected_estate"


def test_trust_catalog_refuses_a_manifest_for_another_trust_domain(
    estate, tmp_path
) -> None:
    manifest = _write_json(
        tmp_path / "wrong_domain.json",
        {
            "type": "regista.estate-manifest",
            "version": 1,
            "trust_domain_id": str(uuid.uuid4()),
            "project_instance_ids": [
                estate.opened[estate.target_project]["project_instance_id"]
            ],
        },
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=manifest,
            out=str(tmp_path / "x.json"),
        ),
    )
    assert _reason(error) == "expected_estate_trust_domain_mismatch"


def test_trust_catalog_covers_multiple_projects(estate, tmp_path) -> None:
    """A catalog is one document for the whole estate (ARCHITECTURE-0.6.0.md:798)."""
    inputs = _inputs_file(
        estate,
        tmp_path,
        {
            "project": estate.target_project,
            **RECORDED_LEGACY,
            **_preflight(estate, estate.target_project),
        },
        {
            "project": estate.second_project,
            "legacy_head_event_hash": "sha256:" + "ab" * 32,
            "legacy_event_count": 7,
            "scheme_counts": {"hmac-sha256": 7},
            **_preflight(estate, estate.second_project),
        },
    )
    manifest = _manifest_file(
        estate, tmp_path, estate.target_project, estate.second_project
    )
    result = _run(
        estate, tmp_path, out=tmp_path / "catalog.json", inputs=inputs,
        expected_estate=manifest,
    )
    assert result["project_count"] == 2
    assert result["catalog_status"] == "complete"
    hints = [entry["project_name_hint"] for entry in result["projects"]]
    # Sorted by hint so an operator listing them in a different order gets the same
    # bytes — JCS does not sort arrays.
    assert hints == sorted(hints)
    assert {entry["project_instance_id"] for entry in result["projects"]} == {
        estate.opened[estate.target_project]["project_instance_id"],
        estate.opened[estate.second_project]["project_instance_id"],
    }


# ------------------------------------------------------------ F5: k-of-n signing


def test_trust_catalog_refuses_an_under_signed_catalog_by_default(
    estate, tmp_path
) -> None:
    """A 1-of-1 domain needs one key; this asserts the named refusal's shape.

    The estate here is solo, so the threshold is already met — what is pinned is that
    the refusal exists and names the workaround when it is not. The co-signed path is
    covered offline in ``test_wi330_estate_catalog.py`` (a live k-of-n estate would
    mean a second trust log for no extra coverage of this code path).
    """
    from regista._estate_catalog import verify_published_checkpoint

    checkpoint = verify_published_checkpoint(
        estate.checkpoint_bytes,
        genesis_document=estate.fx.document,
        authority=genesis_root_authority(estate.fx.document),
    )
    assert checkpoint.governance.threshold == 1
    assert checkpoint.active_root_fingerprints == (
        estate.fx.fingerprints[estate.root_signer],
    )


def test_trust_catalog_and_sign_catalog_compose(estate, tmp_path) -> None:
    """``--incomplete-signatures`` then ``trust sign-catalog``: the airgapped flow.

    A 1-of-1 estate lets this be exercised end to end: produce with NO keys, which is
    under threshold and therefore refused unless the operator says so, then append the
    root signature offline and verify.
    """
    from regista._cli import cmd_trust_sign_catalog

    out = tmp_path / "unsigned.json"
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    inputs = _estate_inputs(estate, tmp_path)

    # Without --incomplete-signatures, an under-signed catalog is refused.
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(out), key=[]
        ),
    )
    assert _reason(error) == "root_threshold_not_met"
    assert error.detail["keys_supplied"] == 0
    assert not out.exists()

    partial = json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, expected_estate=manifest, out=str(out), key=[],
                incomplete_signatures=True,
            ),
        )
    )
    assert partial["threshold_met"] is False
    assert partial["verdict"] == "UNSIGNED_THRESHOLD_PENDING"
    assert json.loads(out.read_bytes())["root_signatures"] == []

    signed_path = tmp_path / "signed.json"
    result = json.loads(
        _capture(
            cmd_trust_sign_catalog,
            argparse.Namespace(
                dsn=None, project=None, hmac_key_path=None,
                file=str(out), out=str(signed_path), key=[estate.root_seed_path],
                trust_checkpoint=estate.checkpoint, trust_log_project=None,
                trust_log_dsn=None, genesis=estate.genesis, force=False, json=True,
            ),
        )
    )
    assert result["signatures_total"] == 1
    assert result["threshold_met"] is True
    # The claim did not move: only root_signatures grew.
    before = json.loads(out.read_bytes())
    after = json.loads(signed_path.read_bytes())
    assert estate_catalog_digest(before) == estate_catalog_digest(after)

    report = json.loads(
        _capture(
            cmd_trust_verify_catalog,
            _verify_ns(
                estate, file=str(signed_path), expected_estate=manifest,
                expect_digest=result["estate_catalog_digest"],
            ),
        )
    )
    assert report["verdict"] == "VALID"


def test_sign_catalog_refuses_a_key_outside_the_active_root_set(
    estate, tmp_path
) -> None:
    from regista._cli import cmd_trust_sign_catalog

    out = tmp_path / "catalog.json"
    _run(estate, tmp_path, out=out)
    stranger = _seed_file(tmp_path / "stranger.seed", bytes(nacl.signing.SigningKey.generate()))
    error = _refusal(
        cmd_trust_sign_catalog,
        argparse.Namespace(
            dsn=None, project=None, hmac_key_path=None,
            file=str(out), out=str(tmp_path / "signed.json"), key=[stranger],
            trust_checkpoint=estate.checkpoint, trust_log_project=None,
            trust_log_dsn=None, genesis=estate.genesis, force=False, json=True,
        ),
    )
    assert _reason(error) == "root_key_not_active"


# ------------------------------------------------------------------- the rest


def test_trust_catalog_dry_run_writes_nothing_and_reports_the_real_digest(
    estate, tmp_path
) -> None:
    out = tmp_path / "dry.json"
    plan = _run(
        estate, tmp_path, out=out, dry_run=True,
        created_at="2026-08-20T12:00:00.000000Z",
    )
    assert plan["dry_run"] is True
    assert plan["would_write"] == str(out)
    assert not out.exists()

    real = _run(
        estate, tmp_path, out=out, created_at="2026-08-20T12:00:00.000000Z"
    )
    # Signatures live outside the signed bytes, so the dry run's digest is the real
    # one rather than an approximation of it.
    assert plan["estate_catalog_digest"] == real["estate_catalog_digest"]
    assert real["written"] == str(out)


def test_trust_catalog_human_output_names_the_publication_step(estate, tmp_path) -> None:
    """The default (non-``--json``) report is what the runbook operator reads."""
    out = tmp_path / "catalog.json"
    output = _capture(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(out), json=False,
            created_at="2026-08-20T12:00:00.000000Z",
        ),
    )
    assert "trust catalog: signed estate cutover catalog written" in output
    assert "estate_catalog_digest:" in output
    assert estate.checkpoint_digest in output
    assert estate.target_project in output
    assert "epoch facts:             recomputed_from_signed_events" in output
    assert "self-verify:             VALID" in output
    assert "PUBLISH IS A SEPARATE OPERATOR STEP" in output
    assert "catalogs/20260820T120000Z-cutover.json" in output


def test_partial_catalog_human_output_shouts(estate, tmp_path) -> None:
    output = _capture(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(
                estate, tmp_path, estate.target_project, estate.second_project
            ),
            out=str(tmp_path / "partial.json"), json=False, allow_partial=True,
        ),
    )
    assert "CEREMONY FAILURE: catalog_status = partial" in output
    assert "! MISSING:" in output


def test_trust_catalog_is_byte_reproducible_with_a_pinned_created_at(estate, tmp_path) -> None:
    """Ed25519 is deterministic, so a pinned created_at makes the whole artifact repeat."""
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    for path in (first, second):
        _run(estate, tmp_path, out=path, created_at="2026-08-20T12:00:00.000000Z")
    assert first.read_bytes() == second.read_bytes()


def test_trust_catalog_write_is_atomic(estate, tmp_path, monkeypatch) -> None:
    """Review N-a, and NEW-3: assert properties a plain truncating write does NOT have.

    The first version of this test only checked that the bytes changed and no temp file
    was left — both true of ``open(path, "wb")``, so it proved nothing. Two
    discriminating properties are asserted instead:

    1. **The inode changes across ``--force``.** ``os.replace`` swaps a new file into
       place; a truncating write keeps the same inode. This is what makes a concurrent
       reader see either the old artifact or the new one, never a half-written one.
    2. **A failure leaves the previous artifact byte-intact.** With ``os.replace`` made
       to fail, the target still holds the ORIGINAL catalog — whereas a truncating write
       would already have destroyed it before failing.
    """
    out = tmp_path / "catalog.json"
    first = _run(estate, tmp_path, out=out, created_at="2026-08-20T12:00:00.000000Z")
    original = out.read_bytes()
    original_inode = out.stat().st_ino

    second = _run(
        estate, tmp_path, out=out, force=True,
        created_at="2026-08-20T13:00:00.000000Z",
    )
    assert out.read_bytes() != original
    assert second["estate_catalog_digest"] != first["estate_catalog_digest"]
    assert out.stat().st_ino != original_inode, (
        "the artifact was written in place; a truncating write has no atomicity"
    )
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".catalog.json.")] == []

    # (2) The prior artifact survives a failed publish.
    surviving = out.read_bytes()
    real_replace = os.replace

    def exploding_replace(src, dst, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", exploding_replace)
    with pytest.raises(OSError):
        _run(
            estate, tmp_path, out=out, force=True,
            created_at="2026-08-20T14:00:00.000000Z",
        )
    monkeypatch.setattr(os, "replace", real_replace)
    assert out.read_bytes() == surviving, "a failed write destroyed the previous catalog"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".catalog.json.")] == [], (
        "the temp file was left behind after a failed replace"
    )


def test_trust_catalog_refuses_to_clobber_an_existing_artifact(estate, tmp_path) -> None:
    out = tmp_path / "catalog.json"
    out.write_text("{}", encoding="utf-8")
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(out),
        ),
    )
    assert _reason(error) == "output_exists"
    _run(estate, tmp_path, out=out, force=True)
    assert out.read_bytes() != b"{}"


def test_trust_catalog_refuses_an_unusable_out_path(estate, tmp_path) -> None:
    """Review N-c: a directory or a missing parent is a NAMED error, not a traceback."""
    inputs = _estate_inputs(estate, tmp_path)
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    directory = tmp_path / "adir"
    directory.mkdir()
    assert _reason(
        _refusal(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, expected_estate=manifest,
                        out=str(directory)),
        )
    ) == "out_path_is_directory"
    assert _reason(
        _refusal(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, expected_estate=manifest,
                        out=str(tmp_path / "nope" / "catalog.json")),
        )
    ) == "out_parent_missing"


def test_trust_catalog_refuses_a_key_that_is_not_an_active_root(estate, tmp_path) -> None:
    stranger = _seed_file(tmp_path / "stranger.seed", bytes(nacl.signing.SigningKey.generate()))
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(tmp_path / "x.json"), key=[stranger],
        ),
    )
    assert _reason(error) == "root_key_not_active"


def test_trust_catalog_refuses_cataloguing_the_trust_log_itself(estate, tmp_path) -> None:
    """The trust log's state is bound through the checkpoint digest, not as an entry."""
    inputs = _write_json(
        tmp_path / "inputs.json",
        _inputs(
            {
                "project": estate.trust_project,
                **RECORDED_LEGACY,
                "expected_new_epoch_head_event_hash": "sha256:" + "11" * 32,
                "expected_new_epoch_event_count": 1,
            }
        ),
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs,
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(tmp_path / "x.json"),
        ),
    )
    assert _reason(error) == "input_project_is_trust_log"


def test_trust_catalog_refuses_a_project_with_no_opened_epoch(estate, tmp_path) -> None:
    """A project that never opened its v6 epoch has no cutover to report."""
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"wi330e_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, estate.host_keyfile)
    handle.close()
    try:
        inputs = _write_json(
            tmp_path / "inputs.json",
            _inputs(
                {
                    "project": project,
                    **RECORDED_LEGACY,
                    "expected_new_epoch_head_event_hash": "sha256:" + "11" * 32,
                    "expected_new_epoch_event_count": 1,
                }
            ),
        )
        error = _refusal(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs,
                expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
                out=str(tmp_path / "x.json"),
            ),
        )
        assert _reason(error) == "new_epoch_not_opened"
    finally:
        drop_project_schema(DSN, project)


def test_trust_catalog_requires_the_publication_pin(estate, tmp_path) -> None:
    """A published checkpoint is the only accepted source of the bound digest."""
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(tmp_path / "x.json"),
            trust_publication_commit=None,
        ),
    )
    assert _reason(error) == "checkpoint_publication_pin_absent"


def test_trust_catalog_validates_operator_literals_before_touching_the_store(
    estate, tmp_path
) -> None:
    """A typo in ``--created-at`` or ``--prev-commit`` is caught up front.

    ``--created-at`` now requires EXACTLY six fractional digits (review N-b): the old
    ``strptime`` check accepted ``.1Z`` while promising microsecond precision.
    """
    inputs = _estate_inputs(estate, tmp_path)
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    out = tmp_path / "x.json"
    for bad in ("2026-08-20T12:00:00Z", "2026-08-20T12:00:00.1Z", "2026-08-20T12:00:00.12345Z"):
        error = _refusal(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, expected_estate=manifest, out=str(out),
                created_at=bad,
            ),
        )
        assert _reason(error) == "created_at_malformed", bad
    short = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(out),
            prev_commit="abc123",
        ),
    )
    assert _reason(short) == "prev_commit_malformed"
    assert not out.exists()


def test_trust_catalog_refuses_a_checkpoint_from_another_publication_commit(
    estate, tmp_path
) -> None:
    """The out-of-band commit pin is load-bearing, not decorative."""
    out = tmp_path / "x.json"
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate,
            inputs=_estate_inputs(estate, tmp_path),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(out), trust_publication_commit="0" * 40,
        ),
    )
    assert error.code == ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert not out.exists(), "a refused build must leave no artifact behind"


def test_trust_catalog_measures_a_reachable_legacy_store(estate, tmp_path) -> None:
    """``legacy_project`` re-measures the frozen store instead of trusting a record."""
    inputs = _inputs_file(
        estate,
        tmp_path,
        {
            "project": estate.target_project,
            "legacy_project": estate.second_project,
            **_preflight(estate, estate.target_project),
        },
    )
    result = _run(
        estate, tmp_path, out=tmp_path / "catalog.json", inputs=inputs,
        expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
    )
    assert result["legacy_measurement_sources"] == {estate.target_project: "measured"}
    entry = result["projects"][0]
    # `genesis init` wrote one Ed25519 event into the stand-in legacy schema.
    assert entry["legacy_event_count"] == 1
    assert entry["scheme_counts"] == {"ed25519": 1}
    # And it is the RECOMPUTED head, not the posture row.
    assert entry["legacy_head_event_hash"] == estate.heads[estate.second_project]


def test_trust_catalog_refuses_recorded_numbers_that_contradict_the_frozen_store(
    estate, tmp_path
) -> None:
    """Supplying both makes them cross-checked, and a disagreement is not signed over."""
    inputs = _inputs_file(
        estate,
        tmp_path,
        {
            "project": estate.target_project,
            "legacy_project": estate.second_project,
            **RECORDED_LEGACY,
            **_preflight(estate, estate.target_project),
        },
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs,
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(tmp_path / "x.json"),
        ),
    )
    assert _reason(error) == "legacy_measurement_mismatch"
    assert error.detail["recorded"]["legacy_event_count"] == 1000
    assert error.detail["measured"]["legacy_event_count"] == 1


def test_forged_legacy_head_row_is_refused(estate, forgeable, tmp_path) -> None:
    """F1 on the legacy side: the frozen store's head is recomputed too."""
    inputs = _inputs_file(
        estate,
        tmp_path,
        {
            "project": estate.target_project,
            "legacy_project": forgeable.project,
            **_preflight(estate, estate.target_project),
        },
    )
    _forge(
        forgeable.project,
        "UPDATE event_chain_head SET head_hash = %s WHERE id = TRUE",
        [bytes.fromhex("ef" * 32)],
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs,
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            out=str(tmp_path / "x.json"),
        ),
    )
    assert _reason(error) == "legacy_head_row_contradicts_events"


def test_trust_catalog_refuses_an_empty_legacy_store(estate, tmp_path) -> None:
    """An empty schema has no frozen population for a cutover catalog to bind."""
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"wi330l_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, estate.host_keyfile)
    handle.close()
    try:
        inputs = _inputs_file(
            estate,
            tmp_path,
            {
                "project": estate.target_project,
                "legacy_project": project,
                **_preflight(estate, estate.target_project),
            },
        )
        error = _refusal(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs,
                expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
                out=str(tmp_path / "x.json"),
            ),
        )
        assert _reason(error) == "legacy_store_empty"
    finally:
        drop_project_schema(DSN, project)


# ------------------- FR2-1: the log-derived authority adapter, live -------------


def test_trust_log_root_authority_matches_genesis_on_an_unrotated_log(estate) -> None:
    """The adapter that turns a real chain walk into a ``RootAuthorityState``.

    The DB-free module expresses post-rotation states by constructing that object
    directly; this pins the one thing only a live log can prove — that
    ``trust_log_root_authority`` derives the SAME state from a real
    ``verify_trust_log_chain`` walk that ``genesis_root_authority`` derives from the
    document, on a log with no rotation events. If the two ever disagreed, every offline
    verdict would differ from the ceremony host's, and FR2-1's fix would be nominal.
    """
    from regista._connection import ConnectionManager

    expected = genesis_root_authority(estate.fx.document)
    mgr = ConnectionManager(DSN, estate.trust_project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            derived = trust_log_root_authority(conn, estate.fx.document)
    finally:
        mgr.close()

    assert derived.signer_fingerprints == expected.signer_fingerprints
    assert derived.threshold == expected.threshold
    assert dict(derived.public_keys) == dict(expected.public_keys)
    assert derived.source == "verified_trust_log"
    assert derived.trust_log_event_count is not None and derived.trust_log_event_count >= 2


def test_trust_catalog_reports_a_log_derived_authority(estate, tmp_path) -> None:
    """`trust catalog` must never fall back to genesis: it HAS the log, so it walks it."""
    result = _run(estate, tmp_path, out=tmp_path / "catalog.json")
    assert result["root_authority"]["source"] == "verified_trust_log"
    assert result["root_authority"]["signer_fingerprints"] == [
        estate.fx.fingerprints[estate.root_signer]
    ]
    assert result["active_root_fingerprints"] == result["root_authority"][
        "signer_fingerprints"
    ]


def test_verify_catalog_can_use_the_live_trust_log_as_authority(estate, tmp_path) -> None:
    """`--trust-log-project` is the CLI surface for "present the log"."""
    out = tmp_path / "catalog.json"
    built = _run(estate, tmp_path, out=out)
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    report = json.loads(
        _capture(
            cmd_trust_verify_catalog,
            _verify_ns(
                estate, file=str(out), expected_estate=manifest,
                trust_log_project=estate.trust_project, trust_log_dsn=DSN,
                expect_digest=built["estate_catalog_digest"],
            ),
        )
    )
    assert report["verdict"] == "VALID"
    assert report["root_authority"]["source"] == "verified_trust_log"


def test_verify_catalog_refuses_a_trust_log_project_without_a_dsn(estate, tmp_path) -> None:
    out = tmp_path / "catalog.json"
    _run(estate, tmp_path, out=out)
    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(
            estate, file=str(out),
            expected_estate=_manifest_file(estate, tmp_path, estate.target_project),
            trust_log_project=estate.trust_project, trust_log_dsn=None, dsn=None,
        ),
    )
    assert _reason(error) == "trust_log_dsn_absent"


# ---------------- FR2-2: sign-catalog must not count unverified entries ----------


def test_sign_catalog_refuses_a_catalog_carrying_an_invalid_signature(
    estate, tmp_path
) -> None:
    """Sol's round-2 probe (FR2-2): ``threshold_met: true`` beside a bad signature.

    ``sign-catalog`` appended a valid signature next to a structurally well-formed but
    cryptographically INVALID one and reported ``ok: true, threshold_met: true`` — a
    claim an independent ``verify-catalog`` then refused with ``root_signature_invalid``.
    A count of array entries is not a count of signatures, so every existing entry is
    now verified BEFORE anything is appended.
    """
    from regista._cli import cmd_trust_sign_catalog

    out = tmp_path / "unsigned.json"
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    inputs = _estate_inputs(estate, tmp_path)
    _capture(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, expected_estate=manifest, out=str(out), key=[],
            incomplete_signatures=True,
        ),
    )

    # Splice in a well-formed entry naming the genuine root but with garbage bytes.
    document = json.loads(out.read_bytes())
    document["root_signatures"] = [
        {
            "signer_id": estate.root_signer,
            "fingerprint": estate.fx.fingerprints[estate.root_signer],
            "signature": base64.b64encode(b"\x00" * 64).decode("ascii"),
        }
    ]
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(canonicalize(document))

    # A second, genuine root key would push the ARRAY to 2 entries. It must not push the
    # verified count anywhere, because entry 0 does not verify.
    signed_out = tmp_path / "signed.json"
    error = _refusal(
        cmd_trust_sign_catalog,
        argparse.Namespace(
            dsn=None, project=None, hmac_key_path=None,
            file=str(tampered), out=str(signed_out), key=[estate.root_seed_path],
            trust_checkpoint=estate.checkpoint, trust_log_project=None,
            trust_log_dsn=None, genesis=estate.genesis, force=False, json=True,
        ),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "root_signature_invalid"
    assert not signed_out.exists(), "a refused sign must leave no artifact behind"


def test_sign_catalog_counts_only_verified_signatures(estate, tmp_path) -> None:
    """The reported number is ``signatures_verified``, not ``len(root_signatures)``."""
    from regista._cli import cmd_trust_sign_catalog

    out = tmp_path / "unsigned.json"
    manifest = _manifest_file(estate, tmp_path, estate.target_project)
    _capture(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=_estate_inputs(estate, tmp_path), expected_estate=manifest,
            out=str(out), key=[], incomplete_signatures=True,
        ),
    )
    signed_out = tmp_path / "signed.json"
    result = json.loads(
        _capture(
            cmd_trust_sign_catalog,
            argparse.Namespace(
                dsn=None, project=None, hmac_key_path=None,
                file=str(out), out=str(signed_out), key=[estate.root_seed_path],
                trust_checkpoint=estate.checkpoint, trust_log_project=None,
                trust_log_dsn=None, genesis=estate.genesis, force=False, json=True,
            ),
        )
    )
    assert result["signatures_verified"] == 1
    assert result["signatures_total"] == 1
    assert result["threshold_met"] is True
    assert result["root_authority"]["source"] == "genesis"
    # And the artifact an independent verifier sees agrees.
    report = json.loads(
        _capture(
            cmd_trust_verify_catalog,
            _verify_ns(estate, file=str(signed_out), expected_estate=manifest),
        )
    )
    assert report["verdict"] == "VALID"
    assert report["signatures_verified"] == 1
