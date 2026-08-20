"""WI-319 ``regista trust init-log``: write the trust log's genesis event.

The command bootstraps a trust domain into a database — it appends the
``trust_domain_established`` event that ``principal_keys`` is later a projection of
(TRUST-DOMAIN.md §5.2, §5.9). Without it no key can be enrolled, so per-host
provisioning (WI-276) is blocked. These are real, DSN-backed exercises of the CLI
handler: a fresh store initializes and then verifies/rebuilds; a second init is
refused; an invalid document and a wrong root key are refused with no write; and a
dry run creates nothing.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import uuid

import nacl.signing
import pytest
from _helpers import DSN
from _trust_fixtures import mint_co_signed, mint_solo

from regista._cli import cmd_trust_init_log
from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._trust_log import parse_trust_domain_established
from regista._trust_log_writer import chain_order, read_trust_log_rows
from regista.testing import drop_project_schema

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

ROOT_PRINCIPAL = "service:root-a"


@pytest.fixture(autouse=True)
def _producer_env():
    """The v6 writer refuses to sign without a real process-level producer identity
    (V6-ENVELOPE.md §1.8 — no invented default). Set it as the other writer suites do."""
    import os

    os.environ.setdefault("REGISTA_PRODUCER_HARNESS", "pytest")
    os.environ.setdefault("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL", "test-fixture")
    os.environ.setdefault("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


def _write(path, obj) -> str:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def _seed_file(path, seed: bytes) -> str:
    path.write_text(base64.b64encode(seed).decode("ascii"), encoding="utf-8")
    return str(path)


def _ns(*, dsn, project, genesis, key, root_principal_id=ROOT_PRINCIPAL,
        dry_run=False, json_mode=False) -> argparse.Namespace:
    """A Namespace matching what the argparse wiring produces for `trust init-log`."""
    return argparse.Namespace(
        dsn=dsn,
        project=project,
        hmac_key_path=None,
        genesis=genesis,
        key=key,
        root_principal_id=root_principal_id,
        dry_run=dry_run,
        json=json_mode,
    )


def _schema_exists(project: str) -> bool:
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        return mgr.schema_exists()
    finally:
        mgr.close()


def _trust_rows(project: str):
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            return chain_order(read_trust_log_rows(conn))
    finally:
        mgr.close()


@pytest.fixture
def project_name():
    project = f"wi319_{uuid.uuid4().hex[:8]}"
    yield project
    drop_project_schema(DSN, project)


def test_init_log_writes_genesis_then_verifies_and_rebuilds(tmp_path, project_name):
    fx = mint_solo()
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))

    # The store now holds exactly the genesis event, and it parses as such.
    rows = _trust_rows(project_name)
    assert [r["transition"] for r in rows] == ["trust_domain_established"]
    parsed = parse_trust_domain_established(rows[0]["payload"])
    assert str(parsed.trust_domain_id) == fx.trust_domain_id

    # The chain verifies: rebuild_projection walks the verified trust-log chain
    # (raising on anything unverified) before it touches the projection.
    from regista._trust_projection import rebuild_projection

    mgr = ConnectionManager(DSN, project_name)
    try:
        mgr.open()
        report = rebuild_projection(
            mgr, project=project_name, genesis_document=fx.document, dry_run=True
        )
    finally:
        mgr.close()
    # A genesis-only log has no key-lifecycle events to project, so rebuild replays
    # none and rebuilds no rows — but returning at all (rather than raising) proves
    # the verified trust-log walk accepted the genesis chain.
    assert report.rows_rebuilt == 0
    assert not report.differences


def test_second_init_log_is_refused(tmp_path, project_name):
    fx = mint_solo()
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.GENESIS_ALREADY_WRITTEN

    # Still exactly one genesis event — the refusal did not double-write or fork.
    rows = _trust_rows(project_name)
    assert [r["transition"] for r in rows] == ["trust_domain_established"]


def test_invalid_genesis_document_is_refused_without_writing(tmp_path, project_name):
    fx = mint_solo()
    bad = copy.deepcopy(fx.document)
    bad["signatures"] = []  # unsigned: threshold cannot be met -> verify raises
    gpath = _write(tmp_path / "genesis.json", bad)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError):
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))

    # Verification precedes any schema work, so nothing was created.
    assert not _schema_exists(project_name)


def test_wrong_root_key_is_refused_without_writing(tmp_path, project_name):
    fx = mint_solo()
    gpath = _write(tmp_path / "genesis.json", fx.document)
    # A key whose fingerprint is not among the genesis signers.
    stranger = bytes(nacl.signing.SigningKey.generate())
    kpath = _seed_file(tmp_path / "stranger.seed", stranger)

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    assert not _schema_exists(project_name)


def test_dry_run_writes_nothing(tmp_path, project_name):
    fx = mint_solo()
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath, dry_run=True)
    )
    # A dry run neither creates the schema nor writes an event.
    assert not _schema_exists(project_name)


def test_co_signed_genesis_refused_from_single_key(tmp_path, project_name):
    """k-of-n genesis cannot be authorized by a single --key: the CLI must refuse
    rather than write a genesis this one seed cannot sign (A-prime is the offline path)."""
    fx = mint_co_signed(threshold=2, signer_count=2)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert not _schema_exists(project_name)
