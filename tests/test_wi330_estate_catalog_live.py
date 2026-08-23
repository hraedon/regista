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
import subprocess
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_solo

from regista._cli import cmd_trust_catalog
from regista._errors import RegistaError
from regista._estate_catalog import verify_estate_catalog
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
        "out": None,
        "key": estate.root_seed_path,
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


def _estate_inputs(estate, tmp_path, name: str = "inputs.json", **overrides) -> str:
    entry: dict[str, Any] = {"project": estate.target_project, **RECORDED_LEGACY}
    entry.update(overrides)
    return _write_json(tmp_path / name, _inputs(entry))


# ------------------------------------------------------------------- the keystone


def test_trust_catalog_end_to_end(estate, tmp_path) -> None:
    """The live ceremony: measured fields come from the store, and the artifact verifies.

    Asserts the facts only a store read can get right — the ``project_instance_id``
    ``genesis init`` minted, the epoch-opening event hash, the current head — and then
    re-verifies the written bytes through the public verifier, which is what runbook
    §5.4 step 5 does from an independent checkout.
    """
    inputs = _estate_inputs(estate, tmp_path)
    out = tmp_path / "catalog.json"
    result = json.loads(
        _capture(cmd_trust_catalog, _catalog_ns(estate, inputs=inputs, out=str(out)))
    )

    assert result["verdict"] == "VALID"
    assert result["catalog_kind"] == "cutover"
    assert result["project_count"] == 1
    assert result["trust_domain_id"] == estate.fx.document["trust_domain_id"]
    assert result["trust_log_checkpoint_digest"] == estate.checkpoint_digest
    assert result["trust_log_checkpoint_source"] == "published"
    assert result["trust_log_publication_commit"] == estate.publication_commit
    assert result["publication"] == "operator_step"
    assert result["legacy_measurement_sources"] == {estate.target_project: "operator_recorded"}

    entry = result["projects"][0]
    assert entry["project_instance_id"] == estate.opened[estate.target_project][
        "project_instance_id"
    ]
    assert entry["legacy_head_event_hash"] == RECORDED_LEGACY["legacy_head_event_hash"]
    assert entry["legacy_event_count"] == 1000
    # `genesis init` wrote exactly one event, so the epoch-opening event IS the head.
    # Both are MEASURED (judgment call 3), not asserted by the operator.
    assert entry["cutover_event_hash"].startswith("sha256:")
    assert entry["cutover_event_hash"] == entry["new_epoch_head_event_hash"]

    written = out.read_bytes()
    document = json.loads(written.decode("utf-8"))
    assert written == canonicalize(document), "the artifact must be exact canonical JCS"
    report = verify_estate_catalog(
        document,
        genesis_document=estate.fx.document,
        file_bytes=written,
        expect_digest=result["estate_catalog_digest"],
        trust_log_checkpoint_bytes=estate.checkpoint_bytes,
    )
    assert report.verdict == "VALID"
    assert report.trust_log_checkpoint_status == "matched"
    assert report.digest_pin_status == "matched"


def test_trust_catalog_covers_multiple_projects(estate, tmp_path) -> None:
    """A catalog is one document for the whole estate (ARCHITECTURE-0.6.0.md:798)."""
    inputs = _write_json(
        tmp_path / "inputs.json",
        _inputs(
            {"project": estate.target_project, **RECORDED_LEGACY},
            {
                "project": estate.second_project,
                "legacy_head_event_hash": "sha256:" + "ab" * 32,
                "legacy_event_count": 7,
                "scheme_counts": {"hmac-sha256": 7},
            },
        ),
    )
    result = json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "catalog.json")),
        )
    )
    assert result["project_count"] == 2
    hints = [entry["project_name_hint"] for entry in result["projects"]]
    # Sorted by hint so an operator listing them in a different order gets the same
    # bytes — JCS does not sort arrays.
    assert hints == sorted(hints)
    instance_ids = {entry["project_instance_id"] for entry in result["projects"]}
    assert instance_ids == {
        estate.opened[estate.target_project]["project_instance_id"],
        estate.opened[estate.second_project]["project_instance_id"],
    }


def test_trust_catalog_dry_run_writes_nothing_and_reports_the_real_digest(
    estate, tmp_path
) -> None:
    inputs = _estate_inputs(estate, tmp_path)
    out = tmp_path / "dry.json"
    plan = json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, out=str(out), dry_run=True,
                created_at="2026-08-20T12:00:00.000000Z",
            ),
        )
    )
    assert plan["dry_run"] is True
    assert plan["would_write"] == str(out)
    assert not out.exists()

    real = json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, out=str(out),
                created_at="2026-08-20T12:00:00.000000Z",
            ),
        )
    )
    # Signatures live outside the signed bytes, so the dry run's digest is the real
    # one rather than an approximation of it.
    assert plan["estate_catalog_digest"] == real["estate_catalog_digest"]
    assert real["written"] == str(out)


def test_trust_catalog_is_byte_reproducible_with_a_pinned_created_at(estate, tmp_path) -> None:
    """Ed25519 is deterministic, so a pinned created_at makes the whole artifact repeat.

    That is what lets an auditor re-run the build and compare bytes rather than trust
    the operator's copy.
    """
    inputs = _estate_inputs(estate, tmp_path)
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    for path in (first, second):
        _capture(
            cmd_trust_catalog,
            _catalog_ns(
                estate, inputs=inputs, out=str(path),
                created_at="2026-08-20T12:00:00.000000Z",
            ),
        )
    assert first.read_bytes() == second.read_bytes()


def test_trust_catalog_refuses_to_clobber_an_existing_artifact(estate, tmp_path) -> None:
    inputs = _estate_inputs(estate, tmp_path)
    out = tmp_path / "catalog.json"
    out.write_text("{}", encoding="utf-8")
    error = _refusal(cmd_trust_catalog, _catalog_ns(estate, inputs=inputs, out=str(out)))
    assert _reason(error) == "output_exists"
    _capture(cmd_trust_catalog, _catalog_ns(estate, inputs=inputs, out=str(out), force=True))
    assert out.read_bytes() != b"{}"


def test_trust_catalog_refuses_a_key_that_is_not_a_genesis_signer(estate, tmp_path) -> None:
    inputs = _estate_inputs(estate, tmp_path)
    stranger = _seed_file(tmp_path / "stranger.seed", bytes(nacl.signing.SigningKey.generate()))
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "x.json"), key=stranger),
    )
    assert _reason(error) == "root_key_not_a_genesis_signer"


def test_trust_catalog_refuses_cataloguing_the_trust_log_itself(estate, tmp_path) -> None:
    """The trust log's state is bound through the checkpoint digest, not as an entry."""
    inputs = _write_json(
        tmp_path / "inputs.json", _inputs({"project": estate.trust_project, **RECORDED_LEGACY})
    )
    error = _refusal(
        cmd_trust_catalog, _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "x.json"))
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
            tmp_path / "inputs.json", _inputs({"project": project, **RECORDED_LEGACY})
        )
        error = _refusal(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "x.json")),
        )
        assert _reason(error) == "new_epoch_not_opened"
    finally:
        drop_project_schema(DSN, project)


def test_trust_catalog_requires_the_publication_pin(estate, tmp_path) -> None:
    """A published checkpoint is the only accepted source of the bound digest.

    A local observation is not a checkpoint (``TRUST_LOG_OBSERVATION_TYPE``), so
    binding one would put an unobserved claim in a field that reads as published.
    """
    inputs = _estate_inputs(estate, tmp_path)
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, out=str(tmp_path / "x.json"),
            trust_publication_commit=None,
        ),
    )
    assert _reason(error) == "checkpoint_publication_pin_absent"


def test_trust_catalog_validates_operator_literals_before_touching_the_store(
    estate, tmp_path
) -> None:
    """A typo in ``--created-at`` or ``--prev-commit`` is caught up front.

    Both are validated again inside the builder, but that happens after the trust-log
    walk and every project measurement — and an offline ceremony discovers the typo
    with the keys already back in the safe. Same reasoning as ``trust sign-genesis``'s
    early ``--signed-at`` check.
    """
    inputs = _estate_inputs(estate, tmp_path)
    out = tmp_path / "x.json"
    coarse = _refusal(
        cmd_trust_catalog,
        _catalog_ns(estate, inputs=inputs, out=str(out), created_at="2026-08-20T12:00:00Z"),
    )
    assert _reason(coarse) == "created_at_malformed"
    short = _refusal(
        cmd_trust_catalog,
        _catalog_ns(estate, inputs=inputs, out=str(out), prev_commit="abc123"),
    )
    assert _reason(short) == "prev_commit_malformed"
    assert not out.exists()


def test_trust_catalog_refuses_a_checkpoint_from_another_publication_commit(
    estate, tmp_path
) -> None:
    """The out-of-band commit pin is load-bearing, not decorative."""
    from regista._errors import ErrorCode

    inputs = _estate_inputs(estate, tmp_path)
    out = tmp_path / "x.json"
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(
            estate, inputs=inputs, out=str(out),
            trust_publication_commit="0" * 40,
        ),
    )
    assert error.code == ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED
    assert not out.exists(), "a refused build must leave no artifact behind"


def test_trust_catalog_measures_a_reachable_legacy_store(estate, tmp_path) -> None:
    """``legacy_project`` re-measures the frozen store instead of trusting a record.

    The second opened project stands in for the frozen legacy schema: what is under
    test is that the numbers in the signed bytes came from a live read and are
    reported as ``measured``, not as an operator claim.
    """
    inputs = _write_json(
        tmp_path / "inputs.json",
        _inputs(
            {
                "project": estate.target_project,
                "legacy_project": estate.second_project,
            }
        ),
    )
    result = json.loads(
        _capture(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "catalog.json")),
        )
    )
    assert result["legacy_measurement_sources"] == {estate.target_project: "measured"}
    entry = result["projects"][0]
    # `genesis init` wrote one Ed25519 event into the stand-in legacy schema.
    assert entry["legacy_event_count"] == 1
    assert entry["scheme_counts"] == {"ed25519": 1}
    assert entry["legacy_head_event_hash"] != RECORDED_LEGACY["legacy_head_event_hash"]
    assert entry["legacy_head_event_hash"].startswith("sha256:")


def test_trust_catalog_refuses_recorded_numbers_that_contradict_the_frozen_store(
    estate, tmp_path
) -> None:
    """Supplying both makes them cross-checked, and a disagreement is not signed over."""
    inputs = _write_json(
        tmp_path / "inputs.json",
        _inputs(
            {
                "project": estate.target_project,
                "legacy_project": estate.second_project,
                **RECORDED_LEGACY,
            }
        ),
    )
    error = _refusal(
        cmd_trust_catalog,
        _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "x.json")),
    )
    assert _reason(error) == "legacy_measurement_mismatch"
    assert error.detail["recorded"]["legacy_event_count"] == 1000
    assert error.detail["measured"]["legacy_event_count"] == 1


def test_trust_catalog_refuses_an_empty_legacy_store(estate, tmp_path) -> None:
    """An empty schema has no frozen population for a cutover catalog to bind."""
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"wi330l_{uuid.uuid4().hex[:8]}"
    handle = Regista.create_project(DSN, project, estate.host_keyfile)
    handle.close()
    try:
        inputs = _write_json(
            tmp_path / "inputs.json",
            _inputs({"project": estate.target_project, "legacy_project": project}),
        )
        error = _refusal(
            cmd_trust_catalog,
            _catalog_ns(estate, inputs=inputs, out=str(tmp_path / "x.json")),
        )
        assert _reason(error) == "legacy_store_empty"
    finally:
        drop_project_schema(DSN, project)
