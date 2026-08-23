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
import threading
import uuid

import nacl.signing
import psycopg
import pytest
from _helpers import DSN
from _trust_fixtures import mint_co_signed, mint_solo, mint_solo_effective

from regista import Regista
from regista._cli import _synthesize_root_keyset_file, cmd_trust_init_log
from regista._connection import ConnectionManager
from regista._errors import ErrorCode, RegistaError
from regista._trust_log import parse_trust_domain_established
from regista._trust_log_writer import chain_order, read_trust_log_rows
from regista.testing import drop_project_schema

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")

# The holder ``_trust_fixtures`` declares in ``initial_custody``. Since WI-320 (a-prime)
# an explicit --root-principal-id is VERIFY-ONLY — it must equal that SIGNED declaration
# — so this is the only explicit value the default fixtures accept.
ROOT_PRINCIPAL = "human:test-owner"


@pytest.fixture(autouse=True)
def _producer_env(monkeypatch):
    """The v6 writer refuses to sign without a real process-level producer identity
    (V6-ENVELOPE.md §1.8 — no invented default). Set it as the other writer suites do."""
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS", "pytest")
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-fixture")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


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


def _genesis_actor(project: str) -> str:
    """The actor_id recorded on the trust_domain_established event."""
    mgr = ConnectionManager(DSN, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            row = conn.execute(
                "SELECT actor_id FROM events WHERE transition = %s",
                ["trust_domain_established"],
            ).fetchone()
        assert row is not None
        return row["actor_id"]
    finally:
        mgr.close()


def _occupy_schema_without_events(project: str) -> None:
    """Create *project* as a schema that is NOT a trust-log store: it exists but has
    no ``events`` table, standing in for a namespace already used by a different
    project. The probe must refuse this cleanly, not raise a raw UndefinedTable."""
    from psycopg.sql import SQL, Identifier

    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SQL("CREATE SCHEMA IF NOT EXISTS {}").format(Identifier(project)))
        conn.execute(
            SQL("CREATE TABLE {}.{} (id int)").format(
                Identifier(project), Identifier("some_other_table")
            )
        )


@pytest.fixture
def project_name():
    project = f"wi319_{uuid.uuid4().hex[:8]}"
    yield project
    drop_project_schema(DSN, project)


def test_init_log_writes_genesis_then_verifies_and_rebuilds(tmp_path, project_name):
    fx = mint_solo(project_name_hint=project_name)
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
    fx = mint_solo(project_name_hint=project_name)
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
    fx = mint_solo(project_name_hint=project_name)
    bad = copy.deepcopy(fx.document)
    bad["signatures"] = []  # unsigned: threshold cannot be met -> verify raises
    gpath = _write(tmp_path / "genesis.json", bad)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError):
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))

    # Verification precedes any schema work, so nothing was created.
    assert not _schema_exists(project_name)


def test_wrong_root_key_is_refused_without_writing(tmp_path, project_name):
    fx = mint_solo(project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    # A key whose fingerprint is not among the genesis signers.
    stranger = bytes(nacl.signing.SigningKey.generate())
    kpath = _seed_file(tmp_path / "stranger.seed", stranger)

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    assert not _schema_exists(project_name)


def test_dry_run_writes_nothing(tmp_path, project_name):
    fx = mint_solo(project_name_hint=project_name)
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
    fx = mint_co_signed(threshold=2, signer_count=2, project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert not _schema_exists(project_name)


# --- WI-319 PR #57 review hardening -------------------------------------------


def test_occupied_namespace_refused_cleanly_not_traceback(tmp_path, project_name):
    """deepseek N5 / Opus NB-2: a schema that exists but is NOT a trust-log store (no
    `events` table) must surface as a named RegistaError, never a raw UndefinedTable."""
    _occupy_schema_without_events(project_name)
    fx = mint_solo(project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    assert exc.value.code is ErrorCode.TRUST_LOG_STORE_UNAVAILABLE
    assert exc.value.detail["reason"] == "schema_not_a_trust_log"
    # The pre-existing foreign table is untouched: nothing was written into it.
    assert not _trust_domain_rows_exist(project_name)


def _trust_domain_rows_exist(project: str) -> bool:
    from psycopg.sql import SQL, Identifier

    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
        row = conn.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name = 'events'",
            [project],
        ).fetchone()
        return row is not None


def test_ambient_project_mismatch_refused(tmp_path, project_name, monkeypatch):
    """deepseek N3: an ambient REGISTA_PROJECT that differs from the document's SIGNED
    project_name_hint must be refused, not silently redirect the genesis to a foreign
    schema (two trust domains for one estate)."""
    # Document names the default hint; the ambient env points somewhere else.
    fx = mint_solo()  # project_name_hint defaults to "regista_trust"
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])
    monkeypatch.setenv("REGISTA_PROJECT", project_name)

    ns = _ns(dsn=DSN, project=None, genesis=gpath, key=kpath)
    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(ns)
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == "project_precedence_conflict"
    # Neither the mismatched ambient schema nor the document's hint was created.
    assert not _schema_exists(project_name)
    assert not _schema_exists("regista_trust")


def test_root_actor_defaults_from_declared_holder(tmp_path, project_name, capsys):
    """Opus NB-1 / deepseek N2 interim: with --root-principal-id omitted, the genesis
    actor defaults from the SIGNED initial_custody declared_holder. WI-320 (a-prime) left
    this path untouched — including its ``declared_holder`` source label."""
    fx = mint_solo(project_name_hint=project_name, declared_holder="human:itadmin")
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id=None, dry_run=True, json_mode=True)
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["root_principal_id"] == "human:itadmin"
    assert plan["root_principal_source"] == "declared_holder"

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id=None)
    )
    assert _genesis_actor(project_name) == "human:itadmin"


def test_explicit_root_principal_matching_declared_holder_is_verified(
    tmp_path, project_name, capsys
):
    """WI-320 (a-prime): an explicit --root-principal-id that AGREES with the signed
    custody declaration is accepted — the explicit-confirmation form — and reports itself as
    ``explicit_verified`` rather than as a free operator override."""
    fx = mint_solo(project_name_hint=project_name, declared_holder="service:root-a")
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id="service:root-a", dry_run=True, json_mode=True)
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["would_write"] is True
    assert plan["root_principal_id"] == "service:root-a"
    assert plan["root_principal_source"] == "explicit_verified"

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id="service:root-a")
    )
    assert _genesis_actor(project_name) == "service:root-a"


def test_explicit_root_principal_contradicting_declared_holder_is_refused(
    tmp_path, project_name
):
    """WI-320 (a-prime) closes this hole: an explicit --root-principal-id used to be
    written into ``actor_id`` verbatim, so a GENUINE root seed could attribute the estate genesis
    to an arbitrary principal the domain never declared. It is now VERIFY-ONLY — a value
    contradicting the signed declaration is refused and NOTHING is written."""
    fx = mint_solo(project_name_hint=project_name, declared_holder="service:root-a")
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(
            _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
                root_principal_id="service:totally-unrelated-attacker")
        )
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    detail = exc.value.detail
    assert detail["reason"] == "root_principal_id_contradicts_declared_holder"
    assert detail["root_principal_id"] == "service:totally-unrelated-attacker"
    assert detail["declared_holder"] == "service:root-a"
    assert detail["fingerprint"] == fx.fingerprints[fx.signer_ids[0]]
    # No schema, therefore no log and no trust_domain_established event.
    assert not _schema_exists(project_name)


def test_explicit_root_principal_is_bound_to_the_selected_root_fingerprint(
    tmp_path, project_name
):
    """The verify-only check is per-SIGNER, not a blind scan of every declared holder.

    WI-292 keys ``initial_custody`` by signer fingerprint, exactly one entry per signer,
    so the entry for the seed actually producing the signature is the only declaration
    that root may claim. root-a therefore cannot assert root-b's declared holder even
    though it sits in the same signed document.
    """
    fx = mint_solo_effective(
        signer_count=2,
        project_name_hint=project_name,
        declared_holders=["service:root-a", "service:root-b"],
    )
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(
            _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
                root_principal_id="service:root-b")
        )
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    assert (
        exc.value.detail["reason"] == "root_principal_id_contradicts_declared_holder"
    )
    assert exc.value.detail["declared_holder"] == "service:root-a"
    assert not _schema_exists(project_name)

    # Its OWN declared holder is accepted, which is also how a multi-custody genesis
    # (where defaulting refuses as ambiguous) gets initialized at all.
    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id="service:root-a")
    )
    assert _genesis_actor(project_name) == "service:root-a"


def test_fingerprint_binding_holds_in_the_reverse_direction(tmp_path, project_name):
    """The same document from root-b's side, so the check cannot be passing by accident.

    A guard that always compared against ``initial_custody[0]`` would accept root-b
    claiming root-a's holder and reject root-b claiming its own — the exact inverse of
    what happens here.
    """
    fx = mint_solo_effective(
        signer_count=2,
        project_name_hint=project_name,
        declared_holders=["service:root-a", "service:root-b"],
    )
    gpath = _write(tmp_path / "genesis.json", fx.document)
    # root-b's seed this time: the SECOND custody entry is the one it may claim.
    kpath = _seed_file(tmp_path / "root-b.seed", fx.seeds[fx.signer_ids[1]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(
            _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
                root_principal_id="service:root-a")
        )
    assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
    detail = exc.value.detail
    assert detail["reason"] == "root_principal_id_contradicts_declared_holder"
    assert detail["root_principal_id"] == "service:root-a"
    assert detail["declared_holder"] == "service:root-b"
    assert detail["fingerprint"] == fx.fingerprints[fx.signer_ids[1]]
    assert not _schema_exists(project_name)

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            root_principal_id="service:root-b")
    )
    assert _genesis_actor(project_name) == "service:root-b"


def test_overridden_non_canonical_root_principal_refused(tmp_path, project_name):
    """An explicit --root-principal-id is still validated: a non-canonical override is
    refused before any write (the actor is recorded permanently)."""
    fx = mint_solo(project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(
            _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
                root_principal_id="not-a-canonical-id")
        )
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == "root_principal_id_not_canonical"
    assert not _schema_exists(project_name)


def test_ambiguous_custody_requires_explicit_root_principal(tmp_path, project_name):
    """When a genesis carries multiple custody entries the actor cannot be inferred; the
    CLI requires an explicit --root-principal-id rather than guessing."""
    # 1-of-n: several signers => several initial_custody entries.
    fx = mint_solo_effective(signer_count=2, project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    with pytest.raises(RegistaError) as exc:
        cmd_trust_init_log(
            _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
                root_principal_id=None)
        )
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == "custody_ambiguous_for_actor_default"
    assert not _schema_exists(project_name)


def test_dry_run_reports_would_write_false_when_already_initialized(
    tmp_path, project_name, capsys
):
    """deepseek N4: --dry-run must reflect the real would-outcome. On an already-
    initialized log a real run refuses, so the dry run reports would_write:false with
    the refusal reason instead of claiming would_write:true (and does NOT raise)."""
    fx = mint_solo(project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    cmd_trust_init_log(_ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath))
    capsys.readouterr()  # discard the write output

    cmd_trust_init_log(
        _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath,
            dry_run=True, json_mode=True)
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["dry_run"] is True
    assert plan["would_write"] is False
    assert plan["would_refuse_reason"] == "genesis_already_written"
    assert plan["already_initialized"] is True
    # Still exactly one genesis — the dry run wrote nothing.
    rows = _trust_rows(project_name)
    assert [r["transition"] for r in rows] == ["trust_domain_established"]


def test_concurrent_init_writes_exactly_one_genesis(tmp_path, project_name):
    """Opus concurrency probe, deterministic form: two threads race to initialize the
    same pre-created trust-log schema. Exactly one writes the genesis; the other is
    refused with GENESIS_ALREADY_WRITTEN. The event_chain_head sentinel (locked FOR
    UPDATE inside write_trust_genesis) serialises even the first append, so the loser
    reliably observes the head already set rather than forking or double-writing."""
    fx = mint_solo(project_name_hint=project_name)
    gpath = _write(tmp_path / "genesis.json", fx.document)
    kpath = _seed_file(tmp_path / "root.seed", fx.seeds[fx.signer_ids[0]])

    # Pre-create the schema (migrations + head sentinel, no genesis) so both threads
    # take the existing-schema path and race only on the genesis insert — removing the
    # schema-creation race, which is the only nondeterministic part.
    prep_key = _synthesize_root_keyset_file(
        seed=fx.seeds[fx.signer_ids[0]],
        public_key=fx.public_keys[fx.signer_ids[0]],
        principal_id="service:prep",
        key_id="k_prep",
    )
    try:
        Regista.create_project(DSN, project_name, prep_key).close()
    finally:
        import os
        os.unlink(prep_key)

    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[RegistaError] = []
    lock = threading.Lock()

    def _run() -> None:
        barrier.wait()
        try:
            cmd_trust_init_log(
                _ns(dsn=DSN, project=project_name, genesis=gpath, key=kpath)
            )
            with lock:
                results.append("ok")
        except RegistaError as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"expected exactly one writer, got {results!r}/{errors!r}"
    assert len(errors) == 1
    assert errors[0].code is ErrorCode.GENESIS_ALREADY_WRITTEN
    # Exactly one genesis event — no fork, no double-write.
    rows = _trust_rows(project_name)
    assert [r["transition"] for r in rows] == ["trust_domain_established"]
