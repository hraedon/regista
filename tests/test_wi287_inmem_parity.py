"""WI-287 / D2 — v6 parity for ``InMemoryRegista`` under the conformance split.

``SUITE-RECONCILIATION.md`` §2.3(a), ratified 2026-08-16, specifies the shape this
module implements:

    a shared semantic conformance suite (envelope validation, signing,
    sequencing, admission-state machine) parametrized over both backends, while
    locking, rollback, persistence, and concurrency/races remain **Postgres-only**
    … **In-memory success never satisfies a Postgres-gated acceptance criterion**;
    the conformance split is what prevents an in-memory placeholder from
    laundering gate claims.

Three things follow, and each has code below rather than prose:

1. **The shared suite is shared by inheritance, not by copy.**
   :class:`TestSemanticConformanceInMemory` subclasses P1.7's
   ``TestSemanticConformance`` and overrides only the ``project`` / ``genesis``
   fixtures. Not one assertion is restated here, and
   ``tests/test_p17_v6_writer.py`` is not modified at all — the seam its author
   designed ("changing nothing in the class body") is honoured literally.
   Subclassing rather than ``params=[...]`` on the shared class also keeps every
   existing Postgres node id byte-identical, which matters because the
   epoch-blocked ratchet and the retirement inventory are keyed by exact node id.

2. **The backend is in the node id.** Every in-memory run of a shared assertion is
   ``…::TestSemanticConformanceInMemory::<name>``, so no report can quote an
   in-memory pass as if it were the Postgres one.

3. **The boundary is enforced, not documented.** :class:`TestParityBoundary`
   asserts the split structurally: the in-memory backend must run the *whole*
   shared suite (no quiet per-test subsetting), must not acquire the
   Postgres-only class, must declare that it provides no transactional isolation,
   must refuse a post-write failure instead of pretending to roll back, and must
   refuse an unmodelled statement by name instead of faking it.

This module is deliberately free of any Postgres dependency — ``conftest``'s
reachability heuristic keys off source tokens, and the in-memory parity suite must
keep running on a machine with no database at all.
"""

from __future__ import annotations

import dataclasses
import inspect
import uuid
from pathlib import Path
from typing import Any

import pytest
import test_p17_v6_writer as _p17
from _v6_fixtures import (
    ACTOR_PRINCIPALS,
    BOOTSTRAP_PRINCIPAL,
    TEST_HARNESS,
    TEST_HARNESS_VERSION,
    TEST_MODEL,
    TEST_MODEL_LINEAGE,
    V6TestKeyset,
    accept_key,
    genesis_envelope,
    make_v6_keyset,
    open_v6_epoch,
    register_test_workflow,
    v6_producer,
)

from regista._errors import ErrorCode, RegistaError
from regista._signing import compute_v6_event_hash
from regista._v6_referents import MappingReferents, MaterialCompleteness
from regista._v6_writer import Producer, append_v6_event, read_project_identity
from regista._verification import (
    Applicability,
    EventRow,
    FailureReason,
    KeySetResolver,
    parse_v6_envelope_strict,
    verify_event_strict,
)
from regista.testing import InMemoryRegista

WORKER = _p17.WORKER
PRODUCER = Producer(
    harness=TEST_HARNESS,
    harness_version=TEST_HARNESS_VERSION,
    model=TEST_MODEL,
    model_lineage=TEST_MODEL_LINEAGE,
)

#: The full row projection ``verify_event_strict`` consumes. Spelled once here so
#: the tamper tests below read a row exactly as the Postgres tests do.
_ROW_COLUMNS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, event_seq, "
    "actor_id, actor_kind, actor_metadata, key_id, workflow_name, "
    "workflow_version, timestamp, transition, payload, payload_canonical_hash, "
    "signature, canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "global_seq, prev_global_event_hash"
)


# ---------------------------------------------------------------------------
# In-memory backend fixtures — the whole of what parametrizing the seam takes
# ---------------------------------------------------------------------------


@pytest.fixture
def keyset(tmp_path: Path) -> V6TestKeyset:
    return make_v6_keyset(tmp_path)


@pytest.fixture
def in_memory_project(keyset: V6TestKeyset):
    """A keyed ``InMemoryRegista`` with NO genesis yet.

    Keyed on purpose: the legacy backend's "no keyset means emit dummy unsigned
    bytes" shortcut cannot open a v6 epoch, and
    ``InMemGenesisMixin._require_keys`` refuses rather than silently degrading.
    """

    instance = InMemoryRegista(project="wi287_parity", hmac_key_path=keyset.path)
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def in_memory_genesis(in_memory_project, keyset: V6TestKeyset):
    return in_memory_project.write_genesis(genesis_envelope(keyset), gate_passed=True)


def _appendable(project, keyset: V6TestKeyset, genesis):
    """Accept ``WORKER``'s key, so it may append ordinary events.

    Uses ``_v6_fixtures.accept_key`` rather than P1.7's private ``_accept``: the
    shared helper is the one the 25-file fixture migration will call, so
    exercising it here is what keeps it honest.
    """

    accept_key(project, keyset, genesis, WORKER)
    return project


def _append(project, *, entity_id: uuid.UUID, transition: str, **kwargs: Any):
    with project._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            project._keys,
            entity_kind="work_item",
            entity_id=entity_id,
            transition=transition,
            actor_id=WORKER,
            actor_kind="agent",
            producer=PRODUCER,
            **kwargs,
        )


def _row(project, event_id) -> dict[str, Any]:
    with project._mgr.transaction() as conn:
        row = conn.execute(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE event_id = %s", [event_id]
        ).fetchone()
    assert row is not None
    return row


def _verify(project, event_id):
    """Verify one stored row against the store's OWN events as presented material.

    The referent resolver is the in-memory store, claiming ``COMPLETE_STORE`` — the
    same claim the Postgres backend's ``store_referents`` makes, which is what keeps a
    v6 verdict identical on the two backends. Passing ``NO_REFERENTS`` here would make
    every v6 verdict ``UNVERIFIABLE`` for want of a key-binding anchor and quietly
    reinstate the situation the P1.7 boundary removed.
    """

    return verify_event_strict(
        EventRow.from_mapping(_row(project, event_id)),
        keys=KeySetResolver(project._keys),
        referents=MappingReferents.from_pairs(
            (
                (event.canonical_envelope, event.signature)
                for event in project._store.all_events()
            ),
            completeness=MaterialCompleteness.COMPLETE_STORE,
            label="in-memory project store",
        ),
    )


def _executable_source(source: str) -> str:
    """``source`` with every docstring removed and every comment dropped.

    ``ast.unparse`` of a docstring-stripped tree yields code only, so a token
    tripwire over the result cannot be tripped (or silenced) by prose.
    """

    import ast
    import textwrap

    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            if len(body) == 1:
                body[0] = ast.Pass()
            else:
                del body[0]
    return ast.unparse(ast.fix_missing_locations(tree))


def _rewrite_row(project, event_id, **replacements: Any) -> None:
    """The in-memory equivalent of an operator ``UPDATE`` on a stored event.

    Rewrites the projection while leaving ``canonical_envelope``/``signature``
    alone unless asked, which is precisely the tamper the row-reconciliation
    check exists to catch.
    """

    store = project._store
    for bucket in store.events.values():
        for index, event in enumerate(bucket):
            if event.event_id == event_id:
                rewritten = dataclasses.replace(event, **replacements)
                bucket[index] = rewritten
                store.event_id_index[event_id] = rewritten
                return
    raise AssertionError(f"no stored event {event_id}")


# ---------------------------------------------------------------------------
# The shared semantic conformance suite, over the in-memory backend
# ---------------------------------------------------------------------------


class TestSemanticConformanceInMemory(_p17.TestSemanticConformance):
    """P1.7's semantic conformance assertions, run against ``InMemoryRegista``.

    The class body is inherited verbatim: envelope member completeness, the JCS
    fixed point, row↔envelope reconciliation, SQL-NULL workflow columns, the
    non-empty-transition refusal, the non-canonical-actor refusal, and the entity
    and project chain links. Only the two fixtures below change, which is exactly
    what ``SUITE-RECONCILIATION.md`` §2.3(a)'s "parametrized over both backends"
    asks for and exactly the seam ``TestSemanticConformance``'s docstring
    promises.

    Nothing is overridden except the fixtures — see
    :meth:`TestParityBoundary.test_the_in_memory_suite_overrides_no_assertion`,
    which fails if a future edit weakens an inherited assertion by shadowing it.
    """

    @pytest.fixture
    def project(self, in_memory_project):
        return in_memory_project

    @pytest.fixture
    def genesis(self, in_memory_genesis):
        return in_memory_genesis


# ---------------------------------------------------------------------------
# The parity boundary, enforced
# ---------------------------------------------------------------------------


class TestParityBoundary:
    """§2.3(a)'s split, asserted structurally rather than trusted.

    Every test here would pass vacuously if it only read documentation, so each
    one reads the actual classes, the actual source, or the actual refusal.
    """

    def test_the_in_memory_suite_runs_every_shared_assertion(self) -> None:
        """The in-memory class exposes exactly the shared suite — no extras.

        Honest about what this can and cannot catch: because the class *inherits*,
        ``dir()`` can never come up short, so this does **not** by itself prevent
        subsetting. It catches an in-memory-only extra test masquerading as shared
        coverage. The two real subsetting routes are closed by
        :meth:`test_the_in_memory_suite_overrides_no_assertion` (a weakened
        redefinition) and
        :meth:`test_no_conformance_assertion_is_skipped_or_xfailed` (a marker that
        silences an inherited method without redefining it).
        """

        shared = {n for n in dir(_p17.TestSemanticConformance) if n.startswith("test_")}
        in_memory = {n for n in dir(TestSemanticConformanceInMemory) if n.startswith("test_")}
        assert shared, "the shared conformance class has no tests to parametrize"
        assert in_memory == shared

    def test_no_conformance_assertion_is_skipped_or_xfailed(self) -> None:
        """The subsetting route that inheritance leaves open, closed.

        ``pytest.mark.skip(...)(inherited_method)`` returns the *same* function
        object with a marker attached, so a subclass can silence an inherited
        assertion while both the set-equality and the function-identity guards
        still pass — and the suite reports SKIPPED, which reads like green. Found
        by attacking my own guard rather than by a failure. Class-level
        ``pytestmark`` is checked too, since one line there silences all nine.

        Only markers attached to the *functions/classes* are inspected. The
        epoch-blocked hook in ``conftest.py`` marks collected **items**, so this
        cannot collide with the manifest machinery.
        """

        silencing = {"skip", "skipif", "xfail"}
        for cls in (_p17.TestSemanticConformance, TestSemanticConformanceInMemory):
            class_marks = {m.name for m in getattr(cls, "pytestmark", [])}
            assert not (class_marks & silencing), (
                f"{cls.__name__} carries a class-level {sorted(class_marks & silencing)} "
                "marker; that silences the whole shared conformance suite"
            )
            for name in (n for n in dir(cls) if n.startswith("test_")):
                marks = {m.name for m in getattr(getattr(cls, name), "pytestmark", [])}
                assert not (marks & silencing), (
                    f"{cls.__name__}.{name} is silenced by "
                    f"{sorted(marks & silencing)}; a shared conformance assertion "
                    "must run on both backends or the split is decorative"
                )

    def test_the_in_memory_suite_overrides_no_assertion(self) -> None:
        """Inheritance must share the assertions, not merely re-declare them.

        A subclass that redefines a test method could weaken it while the set
        equality above still held, so identity of the underlying functions is the
        property that actually needs pinning.
        """

        for name in (n for n in dir(_p17.TestSemanticConformance) if n.startswith("test_")):
            shared = getattr(_p17.TestSemanticConformance, name)
            inherited = getattr(TestSemanticConformanceInMemory, name)
            assert inherited is shared, (
                f"{name} is overridden for the in-memory backend; the conformance "
                "split shares assertions and swaps only fixtures"
            )

    def test_the_postgres_only_class_has_no_in_memory_counterpart(self) -> None:
        """Locking and the transaction boundary stay Postgres-only, by construction.

        A subclass of ``TestPostgresOnly`` in this module would hand the in-memory
        backend a Postgres-gated criterion to "satisfy". The head *does* advance in
        memory, so such a test would pass — and prove nothing about serialisation.
        That is the laundering shape, so the guard is on the class graph.
        """

        for name, obj in list(globals().items()):
            if not (isinstance(obj, type) and name.startswith("Test")):
                continue
            assert not issubclass(obj, _p17.TestPostgresOnly), (
                f"{name} subclasses TestPostgresOnly; SUITE-RECONCILIATION.md "
                "§2.3(a) keeps locking, rollback, persistence and concurrency "
                "Postgres-only"
            )

    def test_the_shared_class_body_asserts_nothing_transactional(self) -> None:
        """A source tripwire on the shared class — the split must stay true upstream.

        The shared suite is only safely parametrizable while it stays free of
        locking/rollback/concurrency assertions. If someone moves such an
        assertion into it, the in-memory backend would start "passing" it, so the
        tripwire lives here rather than in a review checklist.

        Docstrings and comments are stripped before scanning: the shared class's
        own docstring *names* the Postgres-only concerns in order to disclaim
        them, and a tripwire that reddened on prose would have to be deleted the
        first time someone documented the boundary — which is the opposite of the
        intent. Measured: scanning raw source fails on the disclaimer itself.
        """

        source = _executable_source(inspect.getsource(_p17.TestSemanticConformance))
        banned = (
            "FOR UPDATE",
            "event_chain_head",
            "pg_advisory",
            "rollback",
            "isolation_level",
            "threading",
            "Thread(",
            "concurrent.futures",
        )
        found = [token for token in banned if token in source]
        assert not found, (
            f"the shared conformance class now references {found}; those are "
            "Postgres-only concerns and belong in TestPostgresOnly"
        )

    def test_the_in_memory_backend_declares_no_transactional_isolation(
        self, in_memory_project
    ) -> None:
        """The absence of locking is a published fact, not an omission."""

        with in_memory_project._mgr.transaction() as conn:
            assert conn.provides_transactional_isolation is False

    def test_a_failure_after_a_write_refuses_instead_of_faking_rollback(
        self, in_memory_project, keyset, in_memory_genesis
    ) -> None:
        """Rollback is Postgres-only, so a partial write is a refusal, never silence.

        The dangerous alternative is the quiet one: return to the caller with the
        write still applied, exactly as though it had been rolled back. A test
        asserting post-rollback emptiness would then pass in memory while the
        store was dirty.
        """

        with pytest.raises(RegistaError) as exc:
            with in_memory_project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    in_memory_project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                )
                raise RuntimeError("a failure after the write landed")
        assert exc.value.code is ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY
        assert exc.value.detail is not None
        assert exc.value.detail["writes"] >= 1
        assert isinstance(exc.value.__cause__, RuntimeError)

    def test_a_refusal_before_any_write_propagates_unchanged(
        self, in_memory_project, keyset
    ) -> None:
        """The other half of the rule: admission refusals must not be rewrapped.

        Every admission-gate assertion in the shared suite pins a specific
        ``ErrorCode``. If the no-rollback guard wrapped those too, the shared
        suite would go red for the wrong reason and the boundary guard would be
        indistinguishable from a bug.
        """

        with pytest.raises(RegistaError) as exc:
            with in_memory_project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    in_memory_project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.GENESIS_REQUIRED

    def test_an_unmodelled_statement_is_refused_by_name(self, in_memory_project) -> None:
        """The statement grammar is closed: divergence is loud, never permissive.

        A permissive facade is the failure that matters — the Postgres path grows
        a statement, the in-memory path silently answers something plausible, and
        parity becomes a claim nobody can falsify.
        """

        with in_memory_project._mgr.transaction() as conn:
            with pytest.raises(RegistaError) as exc:
                conn.execute("UPDATE events SET actor_id = %s", ["agent:whoever"])
        assert exc.value.code is ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY
        assert "UPDATE events" in exc.value.detail["statement"]

    def test_a_read_only_connection_refuses_writes(self, in_memory_project) -> None:
        """``read_genesis``'s read-only contract is enforced, not annotated.

        Postgres gets this from ``SET TRANSACTION READ ONLY``; the in-memory
        facade cannot execute that statement, so it must enforce the same
        guarantee itself or the recovery path would be write-capable in memory
        and read-only on Postgres.
        """

        with in_memory_project._mgr.read_only_transaction() as conn:
            with pytest.raises(RegistaError) as exc:
                conn.execute(
                    "INSERT INTO event_chain_head (id, head_hash, head_event_id) "
                    "VALUES (TRUE, %s, %s)",
                    [b"\x00" * 32, uuid.uuid4()],
                )
        assert exc.value.code is ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY

    def test_a_v6_append_advances_the_one_chain_head_with_the_v6_formula(
        self, in_memory_project, keyset, in_memory_genesis
    ) -> None:
        """One head, advanced by the writer, under the v6 formula.

        The invariant is about the **formula**, not about a second location:
        ``InMemoryEventStore.append`` advances the head with the v5
        ``sha256(envelope || signature)``, and a v6 append routed through it would
        leave a v5-shaped head behind every v6 event — a mixed-epoch smear with no
        error, which is why the v6 path has its own insert and advances the head with
        ``compute_v6_event_hash``.

        This node used to assert ``store._global_chain_head is None`` after a v6
        append, which *is* the state P1.7 phase 3 escalated as a fail-open gap: the
        head ``_in_memory_replay`` reads is that attribute, so WI-266's "head set, log
        empty" check — the signature of a wholesale-deleted log — could never fire in
        memory while Postgres detected it. Postgres has one ``event_chain_head`` row;
        memory now has one piece of state too (``InMemoryV6Rows.head_hash`` is a view
        of it), so the assertion is the formula and the identity, not an absence.
        """

        import hashlib

        _appendable(in_memory_project, keyset, in_memory_genesis)
        appended = _append(in_memory_project, entity_id=uuid.uuid4(), transition="created")
        store = in_memory_project._store

        assert store._global_chain_head == appended.event_hash, (
            "the v6 writer's head is not the head replay reads"
        )
        assert store.v6_rows.head_hash == store._global_chain_head
        assert store.v6_rows.head_event_id == appended.event_id

        # And it is NOT the v5 formula over the same bytes, which is the mixed-epoch
        # smear this node has always been about.
        event = store.find_by_event_id(appended.event_id)
        assert event is not None
        legacy_shaped = hashlib.sha256(
            bytes(event.canonical_envelope) + bytes(event.signature)
        ).digest()
        assert store._global_chain_head != legacy_shaped, (
            "a v6 append wrote the legacy v5-formula chain head"
        )

    def test_the_legacy_writer_is_refused_on_both_sides_of_in_memory_genesis(
        self, in_memory_project, keyset
    ) -> None:
        """``EPOCH-RESET.md`` §5.1's exclusive doors, on the in-memory backend too.

        Before genesis the refusal keeps the exact code and message the
        epoch-blocked manifest pins for 167 nodes; after genesis it becomes
        ``V6_EPOCH_OPEN``, mirroring ``_genesis.check_legacy_append``. A legacy
        append that started succeeding post-genesis would be a silent v5/v6 mixed
        region, which is the thing the epoch reset exists to prevent.
        """

        store = in_memory_project._store
        with pytest.raises(RegistaError) as before:
            store.check_legacy_append()
        assert before.value.code is ErrorCode.GENESIS_REQUIRED
        assert "the clean v6 epoch is not supported by this backend" in before.value.message

        in_memory_project.write_genesis(genesis_envelope(keyset), gate_passed=True)
        with pytest.raises(RegistaError) as after:
            store.check_legacy_append()
        assert after.value.code is ErrorCode.V6_EPOCH_OPEN


# ---------------------------------------------------------------------------
# In-memory v6 genesis — the equivalence the README pinned as conditional
# ---------------------------------------------------------------------------


class TestInMemoryGenesis:
    """The "equivalent v6 genesis implementation" the README made the condition."""

    def test_genesis_opens_the_epoch_and_records_the_identity(
        self, in_memory_project, keyset, in_memory_genesis
    ) -> None:
        with in_memory_project._mgr.transaction() as conn:
            identity = read_project_identity(conn)
        assert identity is not None
        assert identity.principal_id == BOOTSTRAP_PRINCIPAL
        assert identity.scheme_id == "ed25519"
        assert identity.genesis_event_hash == in_memory_genesis.event_hash
        assert in_memory_project.v6_epoch_open is True

    def test_a_second_genesis_is_refused(self, in_memory_project, keyset, in_memory_genesis):
        """The ``project_identity`` singleton is a real constraint in memory too.

        Without it the in-memory backend would accept two genesis events and two
        project identities — a fork the Postgres primary key makes impossible.

        The refusal is pinned to the *admission* code, not to "any refusal": the
        second write must be rejected by `first_write_admission` **before** it
        writes anything, so the singleton-key refusal in the facade is a
        belt-and-braces backstop that must never be the one that fires. Accepting
        either would let the order silently invert.
        """

        with pytest.raises(RegistaError) as exc:
            in_memory_project.write_genesis(genesis_envelope(keyset), gate_passed=True)
        assert exc.value.code is ErrorCode.GENESIS_ALREADY_WRITTEN
        assert exc.value.detail is not None
        assert exc.value.detail["identity_present"] is True
        assert exc.value.detail["live_event_count"] == 1

    def test_genesis_recovery_verifies_the_stored_bytes(
        self, in_memory_project, keyset, in_memory_genesis
    ) -> None:
        """Recovery runs the shared ``read_genesis_from_connection``, unmodified.

        That function re-parses the stored envelope, re-derives the fingerprint,
        re-verifies the signature and reconciles the row — so a pass here is
        evidence about the stored bytes, not about the writer's return value.
        """

        recovered = in_memory_project.read_genesis()
        assert recovered is not None
        assert recovered.event_hash == in_memory_genesis.event_hash
        assert recovered.principal_id == BOOTSTRAP_PRINCIPAL
        assert recovered.source == "events"
        assert recovered.verified is True

    def test_recovery_before_genesis_is_none_not_an_error(self, in_memory_project) -> None:
        assert in_memory_project.read_genesis() is None

    def test_a_keyless_in_memory_instance_cannot_open_an_epoch(self, keyset) -> None:
        """The legacy "unsigned dummy bytes" shortcut cannot reach the v6 epoch."""

        keyless = InMemoryRegista(project="wi287_keyless")
        with pytest.raises(RegistaError) as exc:
            keyless.write_genesis(genesis_envelope(keyset), gate_passed=True)
        assert exc.value.code is ErrorCode.GENESIS_INVALID
        assert keyless.v6_epoch_open is False


# ---------------------------------------------------------------------------
# The fixture-migration harness the 25-file tranche needs
# ---------------------------------------------------------------------------


class TestMigrationHarness:
    """``_v6_fixtures``' promised sequencing helpers, exercised in memory.

    ``tests/_v6_fixtures.py``'s docstring has always described steps 2 and 3 as
    ``write_test_genesis`` and ``accept_key``, but neither function existed — so
    every caller open-coded them, and each of the 25 epoch-blocked in-memory files
    (plus their Postgres siblings) would have had to copy ~25 lines of ceremony.
    These tests pin the helpers so the migration is one call per fixture.

    The helpers are backend-agnostic by construction: they touch only
    ``write_genesis``, ``_mgr.transaction()`` and ``_keys``, which ``Regista`` and
    ``InMemoryRegista`` both expose. They are exercised here against the in-memory
    backend because this module must stay database-free; nothing about them is
    in-memory-specific.
    """

    def test_store_referents_presents_material_over_the_in_memory_facade(
        self, in_memory_project, keyset, in_memory_genesis
    ) -> None:
        """``_v6_referents.store_referents`` works on BOTH backends, asserted not assumed.

        The P1.7 verifier boundary presents an open store as material by issuing
        ``SELECT canonical_envelope, signature FROM events``. That is a **new statement**
        on a facade whose whole design is a closed set of recognised statements — anything
        outside the grammar is ``PARITY_BOUNDARY_POSTGRES_ONLY`` naming the statement
        (§2 of NOTES-WI287). It happens to be inside the grammar, and
        ``_genesis.read_genesis_from_connection`` now depends on that for the in-memory
        backend, so the dependency is pinned here rather than left to luck: without this
        test, narrowing the facade's column handling would break in-memory genesis
        recovery with no test naming the cause.
        """

        from regista._in_mem_genesis import _as_conn
        from regista._v6_referents import MaterialCompleteness, store_referents

        with in_memory_project._mgr.transaction() as conn:
            referents = store_referents(_as_conn(conn), label="in-memory facade")
            assert referents.completeness is MaterialCompleteness.COMPLETE_STORE
            # An absent hash resolves to None, which is the §5.11 row-1/row-2 input —
            # and it forces the index to be built, which is what exercises the statement.
            assert referents.resolve_referent("sha256:" + "00" * 32) is None
            # The genesis event IS presented, addressed by its own v6 event hash.
            genesis_hash = in_memory_genesis.to_dict()["event_hash"]
            found = referents.resolve_referent(genesis_hash)
        assert found is not None, genesis_hash
        assert found.transition == "project_initialized"
        assert found.event_hash == genesis_hash

    def test_open_v6_epoch_makes_every_actor_principal_appendable(
        self, in_memory_project, keyset
    ) -> None:
        """One call replaces genesis + an acceptance per principal.

        Asserting an actual append per principal (rather than just counting
        acceptance events) is the point: ``resolve_key_binding_anchor`` and
        admission gate 2 both have to be satisfied for each one, and a helper that
        wrote acceptances with the wrong scopes would pass a count assertion.
        """

        open_v6_epoch(in_memory_project, keyset)
        for principal_id in ACTOR_PRINCIPALS:
            with in_memory_project._mgr.transaction() as conn:
                appended = append_v6_event(
                    conn,
                    in_memory_project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=principal_id,
                    actor_kind="agent" if principal_id.startswith("agent:") else "human",
                    producer=v6_producer(),
                )
            assert appended.principal_id == principal_id
            assert appended.key_id == keyset.key_for(principal_id).key_id

    def test_an_unaccepted_principal_is_still_refused_after_open_v6_epoch(
        self, in_memory_project, keyset
    ) -> None:
        """The helper must not become a blanket authorisation.

        A convenience fixture that quietly accepted every key in the file would
        destroy the §5.11 property the writer exists to enforce, and every
        migrated test would then be asserting against a weakened backend.
        """

        outsider = "agent:not-in-the-epoch"
        wider = make_v6_keyset(
            Path(keyset.path).parent,
            principals=(*ACTOR_PRINCIPALS, outsider),
            filename="wider_keys.json",
        )
        instance = InMemoryRegista(project="wi287_outsider", hmac_key_path=wider.path)
        try:
            # Only ACTOR_PRINCIPALS are accepted; the keyset also holds `outsider`.
            open_v6_epoch(instance, wider)
            with pytest.raises(RegistaError) as exc:
                with instance._mgr.transaction() as conn:
                    append_v6_event(
                        conn,
                        instance._keys,
                        entity_kind="work_item",
                        entity_id=uuid.uuid4(),
                        transition="created",
                        actor_id=outsider,
                        actor_kind="agent",
                        producer=v6_producer(),
                    )
            assert exc.value.code is ErrorCode.KEY_BINDING_UNRESOLVED
        finally:
            instance.close()

    def test_register_test_workflow_satisfies_admission_gate_1(
        self, in_memory_project, keyset
    ) -> None:
        """A migrated fixture needs the signed registration, not the registry row.

        This is the step a naive migration will forget: ``register_workflow``
        writes a ``workflow_registry`` row, and admission gate 1 refuses a row
        (``V6-ENVELOPE.md`` §1.9). The refusal is asserted first so the positive
        half cannot pass by accident.
        """

        definition = {
            "states": ["open", "closed"],
            "initial_state": "open",
            "transitions": [{"name": "close", "from": "open", "to": "closed"}],
        }
        open_v6_epoch(in_memory_project, keyset)

        with pytest.raises(RegistaError) as exc:
            _append(
                in_memory_project,
                entity_id=uuid.uuid4(),
                transition="close",
                workflow_name="wf",
                workflow_version=1,
            )
        assert exc.value.code is ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED

        registered = register_test_workflow(in_memory_project, "wf", 1, definition)
        appended = _append(
            in_memory_project,
            entity_id=uuid.uuid4(),
            transition="close",
            workflow_name="wf",
            workflow_version=1,
        )
        assert appended.workflow is not None
        assert appended.workflow.registration_event_hash == registered.event_hash_text


# ---------------------------------------------------------------------------
# WI-289 cluster 6 — the in-memory parity coverage the ledger owes
# ---------------------------------------------------------------------------


class TestWI289Cluster6:
    """v6 counterparts for the six in-memory ``coverage_owed`` ledger entries.

    Each test names the retired node it discharges. The retired originals asserted
    the **v5** ``sha256(envelope || signature)`` formula and the v5 row shape; the
    invariant survives the epoch reset, the formula does not, so these assert the
    v6 domain-tagged ``compute_v6_event_hash`` and the v6 envelope's own
    ``chain`` block.

    **``applicability`` IS asserted, as of P1.7 phase 2.** The instruction this
    docstring used to carry has been carried out rather than deleted, so the history
    is worth keeping: while ``_verification._verify_v6_row`` was clamped it returned
    ``INVALID``/``ENVELOPE_SCHEMA_INCOMPLETE`` for *every* v6 row, clean or tampered,
    so an ``applicability == INVALID`` assertion would have passed on a clean event
    and proved nothing at all. These tests therefore asserted only
    ``row_reconciled``, ``mismatched_field_names`` and the ``FailureReason`` set —
    everything decided *above* the clamp.

    The boundary landed, so each tamper test now additionally asserts that the clean
    event is ``FULLY_AUTHENTICATED`` and the tampered one is ``INVALID``. That pairing
    is the point: an ``INVALID`` assertion is only evidence if the clean case is
    something else.
    """

    @pytest.fixture
    def appendable(self, in_memory_project, keyset, in_memory_genesis):
        return _appendable(in_memory_project, keyset, in_memory_genesis)

    def test_every_cluster_6_ledger_entry_names_a_test_that_exists_here(self) -> None:
        """The node→counterpart mapping is machine-checked, not a closure note.

        ``tests/retired_tests_ledger.json`` records ``covered_by`` for each of the
        six WI-289 cluster-6 entries. A mapping that names a test which does not
        exist — or that stops existing after a rename — is the normal way a
        coverage-owed ledger rots, so the pointer is verified rather than trusted.
        """

        import json
        from pathlib import Path

        ledger = json.loads(
            (Path(__file__).resolve().parents[1] / "tests" / "retired_tests_ledger.json")
            .read_text(encoding="utf-8")
        )
        cluster6 = [
            entry
            for entry in ledger["entries"]
            if entry.get("covered_in", "").startswith("WI-287")
        ]
        assert len(cluster6) == 6, (
            "WI-289 cluster 6 is the six in-memory coverage_owed entries "
            f"(found {len(cluster6)})"
        )
        for entry in cluster6:
            assert entry["work_item"] == "WI-289"
            module, _, rest = entry["covered_by"].partition("::")
            assert module == "tests/test_wi287_inmem_parity.py", entry["covered_by"]
            class_name, _, method = rest.partition("::")
            owner = globals().get(class_name)
            assert owner is not None, f"{class_name} does not exist"
            assert callable(getattr(owner, method, None)), entry["covered_by"]

    def test_the_in_memory_entity_chain_links_every_event_by_v6_event_hash(
        self, appendable
    ) -> None:
        """Discharges ``TestBC233HashChainInMemory::test_multi_event_chain``
        (``tests/test_hash_chain.py``).

        Ledger invariant: "in-memory multi-event chain, v5 formula per link" →
        carried forward as the in-memory v6 entity chain.
        """

        entity_id = uuid.uuid4()
        appended = [
            _append(appendable, entity_id=entity_id, transition="created" if s == 1 else "updated")
            for s in (1, 2, 3)
        ]
        for index, event in enumerate(appended):
            envelope = parse_v6_envelope_strict(
                bytes(_row(appendable, event.event_id)["canonical_envelope"])
            )
            link = envelope["chain"]["previous_entity_event_hash"]
            if index == 0:
                assert link is None
            else:
                assert link == appended[index - 1].event_hash_text
            assert event.entity_seq == index + 1

    def test_the_in_memory_entity_link_uses_the_v6_formula_not_the_v5_one(
        self, appendable
    ) -> None:
        """Discharges ``TestBC233HashChainInMemory::test_second_event_includes_prev_hash``.

        The retired test asserted ``sha256(envelope || signature)``. Asserting the
        v6 formula alone would still pass if the writer had kept the v5 one on a
        different code path, so the v5 value is asserted *absent* — that
        difference is the whole content of the carry-forward.
        """

        import hashlib

        entity_id = uuid.uuid4()
        first = _append(appendable, entity_id=entity_id, transition="created")
        second = _append(appendable, entity_id=entity_id, transition="updated")

        envelope = parse_v6_envelope_strict(
            bytes(_row(appendable, second.event_id)["canonical_envelope"])
        )
        v6 = compute_v6_event_hash(first.canonical_envelope, first.signature)
        v5 = hashlib.sha256(first.canonical_envelope + first.signature).digest()
        assert envelope["chain"]["previous_entity_event_hash"] == "sha256:" + v6.hex()
        assert envelope["chain"]["previous_entity_event_hash"] != "sha256:" + v5.hex()

    def test_an_in_memory_project_chain_rewrite_is_reported_as_a_break(
        self, appendable
    ) -> None:
        """Discharges ``test_bc300_in_memory_replay_detects_global_chain_tamper``
        (``tests/test_global_event_chain.py``).

        Ledger invariant: "in-memory parity: corrupted project-chain link reports a
        chain break". In v6 the link lives inside the signed envelope, so a
        rewritten row column contradicts its own crypto material — the tamper is
        caught by reconciliation, and the field is named.
        """

        entity_id = uuid.uuid4()
        _append(appendable, entity_id=entity_id, transition="created")
        second = _append(appendable, entity_id=entity_id, transition="updated")

        clean = _verify(appendable, second.event_id)
        assert clean.row_reconciled is True
        assert clean.mismatched_field_names == ()
        # Tightened when the v6 verifier boundary landed: the clean case has to be
        # something other than INVALID, or the tamper assertion below proves nothing.
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        _rewrite_row(appendable, second.event_id, prev_global_event_hash=b"\x11" * 32)
        tampered = _verify(appendable, second.event_id)
        assert tampered.signature_valid is True  # the signed bytes were untouched
        assert tampered.row_reconciled is False
        assert tampered.mismatched_field_names == ("prev_global_event_hash",)
        assert FailureReason.ROW_FIELD_MISMATCH in tampered.reasons
        assert tampered.applicability is Applicability.INVALID

    def test_an_in_memory_row_rewrite_halts_verification(self, appendable) -> None:
        """Discharges ``TestInMemoryBackendParity::test_in_memory_row_rewrite_halts_replay``
        (``tests/test_wi267_row_authentication.py``).

        Ledger invariant: "in-memory v6 row-reconciliation halt". ``actor_id`` is
        chosen because it is duplicated between the row and the signed envelope,
        which is the class of column an operator ``UPDATE`` can reach.
        """

        appended = _append(appendable, entity_id=uuid.uuid4(), transition="created")
        clean = _verify(appendable, appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        _rewrite_row(appendable, appended.event_id, actor_id="agent:someone-else")
        result = _verify(appendable, appended.event_id)
        assert result.signature_valid is True
        assert result.row_reconciled is False
        assert result.mismatched_field_names == ("actor_id",)
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons
        assert result.applicability is Applicability.INVALID

    def test_deleting_an_in_memory_envelope_is_unverifiable_not_a_silent_pass(
        self, appendable
    ) -> None:
        """Discharges ``TestBC311ReplayChainFields``
        ``::test_replay_succeeds_with_missing_envelope_in_memory``
        (``tests/test_hash_chain.py``).

        Ledger invariant: "in-memory parity: envelope deletion halts". The stored
        bytes are the artifact (``V6-ENVELOPE.md`` §9.2), so a row whose envelope
        is gone is **unverifiable** — reported, never absent-and-assumed-fine.
        """

        appended = _append(appendable, entity_id=uuid.uuid4(), transition="created")
        clean = _verify(appendable, appended.event_id)
        assert clean.applicability is Applicability.FULLY_AUTHENTICATED, clean.summary()

        _rewrite_row(appendable, appended.event_id, canonical_envelope=None)
        result = _verify(appendable, appended.event_id)
        assert result.envelope_present is False
        assert result.signature_valid is False
        assert result.row_reconciled is False
        assert FailureReason.ENVELOPE_ABSENT in result.reasons

    def test_the_in_memory_envelope_deletion_verdict_matches_the_postgres_one(
        self, appendable
    ) -> None:
        """Discharges ``TestInMemoryBackendParity``
        ``::test_in_memory_envelope_deletion_halts_like_postgres``
        (``tests/test_wi267_row_authentication.py``).

        The retired test's content was *parity*, not detection: the in-memory
        verdict must be the same verdict Postgres reports for the same tamper.
        ``verify_event_strict`` is backend-independent by construction — it is
        handed an ``EventRow``, not a connection — so the parity claim is pinned
        as the exact field values ``tests/test_p17_v6_writer.py``'s Postgres row
        assertions produce, rather than by opening a database this module has no
        business requiring.
        """

        appended = _append(appendable, entity_id=uuid.uuid4(), transition="created")
        _rewrite_row(appendable, appended.event_id, canonical_envelope=None)
        result = _verify(appendable, appended.event_id)
        assert (
            result.envelope_present,
            result.signature_valid,
            result.row_reconciled,
            result.mismatched_field_names,
            FailureReason.ENVELOPE_ABSENT in result.reasons,
        ) == (False, False, False, (), True)
