"""P1.7 — the principal a *system-authored* event is attributed to.

Auto-escalation (``escalated``), claim expiry, hook dead-lettering and recurrence
firing append events no actor asked for. The legacy writers named that non-actor
with a bare literal — ``"system"`` or ``"system:scheduler"`` — and both are
un-appendable in the clean v6 epoch for two independent reasons:

* neither is a canonical ``(human|agent|service):<subject>`` principal
  (``TRUST-DOMAIN.md`` §2.1), which ``validate_v6_envelope`` refuses at ingress; and
* neither can hold a **key-binding anchor**, so ``_v6_writer._writer_key`` refuses
  the signer with ``ACTOR_SIGNER_MISMATCH`` even if the grammar passed.

So those four features were not merely awkward to set up under v6 — they were
impossible. :func:`regista._events.resolve_system_actor_id` closes that by
attributing a system-authored event to the project's own bootstrap principal, the
``service:`` id named by genesis whose anchor is the genesis event itself. The
pattern is not new: ``_workflow_api._append_workflow_registration_event`` has always
done exactly this for ``workflow_registered``.

What this module pins, and why each assertion is here rather than implied by a
migrated node elsewhere:

1. **Both branches, both backends.** Epoch open resolves the genesis principal;
   *no* epoch returns the legacy literal byte for byte. The second half is the one
   that is easy to lose: the epoch-blocked manifest records the exact pre-genesis
   refusal form for every node still inside it, so a legacy path that started
   resolving a different actor would redden those nodes with a **changed** failure
   form — honest red, and not the migration's to spend.
2. **A falsifier, not a tautology.** The resolved id is checked against
   ``regista._principals.validate_principal_id`` — the production grammar — and the
   same check is run against the legacy literals to show it can actually fail. A
   grammar assertion that nothing fails is not a test.
3. **The two backends agree.** Postgres and in-memory resolve through the same
   ``read_project_identity``, and this asserts they land on the same id for the same
   project. Two readers of one row is two chances to disagree about it.
4. **The claim that matters: an escalation really lands.** The unit tests above
   would all pass against a helper that returned a well-formed id nothing had a key
   for. Only the end-to-end nodes prove the ``escalated`` event is admitted, signed
   and readable in a clean epoch.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _helpers import DSN, KEY_PATH
from _v6_fixtures import BOOTSTRAP_PRINCIPAL, make_v6_keyset, open_v6_epoch

from regista._errors import RegistaError
from regista._events import resolve_system_actor_id, resolve_system_actor_id_in_memory
from regista._principals import validate_principal_id
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

WORKER = "agent:worker"

#: The literals the legacy writers used. Held here so the falsifier below can show
#: the grammar check rejects them — which is *why* the helper exists.
LEGACY_LITERALS = ("system", "system:scheduler")


@pytest.fixture
def keyset(tmp_path):
    return make_v6_keyset(tmp_path)


@pytest.fixture
def regista(keyset):
    """A Postgres project on a clean v6 epoch."""
    from regista import Regista

    project = f"test_sysactor_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture
def legacy_regista():
    """A Postgres project that has **never** opened a v6 epoch.

    Not a shortcut and not a fixture bug: the pre-genesis branch of the helper is a
    behaviour under test, and the only way to exercise it is a project with no
    ``project_identity`` row. Uses the committed HMAC ``test_keys.json`` on purpose —
    that is what a legacy project has.
    """
    from regista import Regista

    project = f"test_sysactor_legacy_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _in_memory(keyset):
    """An ``InMemoryRegista`` on a clean v6 epoch, workflow registered."""
    s = InMemoryRegista(project="test", hmac_key_path=keyset.path)
    open_v6_epoch(s, keyset)
    s.register_workflow_file(WORKFLOW_PATH)
    return s


def _resolve_pg(regista, literal):
    with regista._mgr.transaction() as conn:
        return resolve_system_actor_id(conn, legacy_actor_id=literal)


class TestResolveSystemActorIdPostgres:
    def test_open_epoch_resolves_the_genesis_principal(self, regista, keyset):
        from regista._v6_writer import read_project_identity

        with regista._mgr.transaction() as conn:
            identity = read_project_identity(conn)
        assert identity is not None
        for literal in LEGACY_LITERALS:
            resolved = _resolve_pg(regista, literal)
            assert resolved == identity.principal_id
            # Named, not just "whatever genesis said": the bootstrap principal is a
            # `service:` id because the thing that opens an epoch is infrastructure.
            assert resolved == BOOTSTRAP_PRINCIPAL
            assert resolved != literal

    def test_no_epoch_returns_the_literal_byte_for_byte(self, legacy_regista):
        for literal in LEGACY_LITERALS:
            assert _resolve_pg(legacy_regista, literal) == literal

    def test_resolved_id_is_grammatical(self, regista):
        # The production grammar, not a regex restated here.
        for literal in LEGACY_LITERALS:
            validate_principal_id(_resolve_pg(regista, literal))

    def test_the_legacy_literals_are_not_grammatical(self):
        # The falsifier's control. Without this, test_resolved_id_is_grammatical
        # could be passing because validate_principal_id accepts everything.
        for literal in LEGACY_LITERALS:
            with pytest.raises(RegistaError):
                validate_principal_id(literal)


class TestResolveSystemActorIdInMemory:
    def test_open_epoch_resolves_the_genesis_principal(self, keyset):
        s = _in_memory(keyset)
        for literal in LEGACY_LITERALS:
            resolved = resolve_system_actor_id_in_memory(
                s._store, legacy_actor_id=literal
            )
            assert resolved == BOOTSTRAP_PRINCIPAL
            assert resolved != literal

    def test_no_epoch_returns_the_literal_byte_for_byte(self):
        s = InMemoryRegista(project="test")
        s.register_workflow_file(WORKFLOW_PATH)
        for literal in LEGACY_LITERALS:
            assert (
                resolve_system_actor_id_in_memory(s._store, legacy_actor_id=literal)
                == literal
            )

    def test_no_epoch_does_not_materialise_v6_state(self):
        # The pre-check is load-bearing beyond speed: `InMemoryEventStore.v6_rows`
        # documents that a legacy-only store carries no v6 state at all, and a
        # resolver that touched the property on every escalation would break that.
        s = InMemoryRegista(project="test")
        resolve_system_actor_id_in_memory(s._store, legacy_actor_id="system")
        assert s._store._v6_rows is None

    def test_resolved_id_is_grammatical(self, keyset):
        s = _in_memory(keyset)
        for literal in LEGACY_LITERALS:
            validate_principal_id(
                resolve_system_actor_id_in_memory(s._store, legacy_actor_id=literal)
            )


class TestBackendsResolveTheSameId:
    def test_same_project_same_system_actor(self, keyset, tmp_path):
        """One project instance id, two backends, one resolved principal.

        The conformance suite compares the two backends' chains, so a helper that
        resolved differently on each would be caught there — late, and as a chain
        mismatch rather than as this. Asserted directly instead.
        """
        from regista import Regista

        project_instance_id = str(uuid.uuid4())
        project = f"test_sysactor_parity_{uuid.uuid4().hex[:8]}"
        pg = Regista.create_project(DSN, project, keyset.path)
        try:
            open_v6_epoch(pg, keyset, project_instance_id=project_instance_id)
            mem = InMemoryRegista(project="test", hmac_key_path=keyset.path)
            open_v6_epoch(mem, keyset, project_instance_id=project_instance_id)

            for literal in LEGACY_LITERALS:
                assert _resolve_pg(pg, literal) == resolve_system_actor_id_in_memory(
                    mem._store, legacy_actor_id=literal
                )
        finally:
            pg.close()
            drop_project_schema(DSN, project)


class TestEscalationLandsInACleanEpoch:
    """The claim that matters — the feature the bare literal made impossible.

    ``test_workflow.yaml`` carries ``attempt_threshold: 3``, so the third claim
    acquisition is what fires ``_claims.check_escalation``. Before this change that
    third acquisition died with ``ACTOR_SIGNER_MISMATCH`` on a migrated project.
    """

    def _drive_to_escalation(self, handle):
        wi, _ = handle.create_work_item(
            "test_workflow", "feature", WORKER,
            custom_fields={"title": "escalation in a clean epoch"},
        )
        handle.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        handle.release_claim(wi.work_item_id, WORKER)
        handle.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        handle.release_claim(wi.work_item_id, WORKER)
        handle.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        return wi

    def test_postgres_escalation_is_appended_and_signed(self, regista):
        wi = self._drive_to_escalation(regista)

        assert regista.get_work_item(wi.work_item_id).needs_review is True

        escalations = regista.read_events(
            work_item_id=wi.work_item_id, transition="escalated", limit=100
        )
        assert len(escalations) == 1
        event = escalations[0]
        assert event.actor_id == BOOTSTRAP_PRINCIPAL
        assert event.actor_kind == "system"
        validate_principal_id(event.actor_id)
        # A v6 event, not a legacy row: signed under the genesis principal's own
        # Ed25519 key, with a real canonical envelope behind the signature.
        assert event.key_id == regista._keys.resolve_signing_key(event.actor_id).key_id
        assert event.canonical_envelope
        assert event.payload["threshold"] == 3
        assert event.payload["attempt_number"] == 3

        # And the whole chain still verifies — an admitted-but-unverifiable event
        # would satisfy every assertion above.
        report = regista.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0
        assert report.warnings == 0

    def test_in_memory_escalation_is_appended_and_signed(self, keyset):
        s = _in_memory(keyset)
        wi = self._drive_to_escalation(s)

        assert s.get_work_item(wi.work_item_id).needs_review is True

        escalations = [
            e for e in s._store.events[wi.work_item_id] if e.transition == "escalated"
        ]
        assert len(escalations) == 1
        assert escalations[0].actor_id == BOOTSTRAP_PRINCIPAL
        validate_principal_id(escalations[0].actor_id)

        report = s.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0
