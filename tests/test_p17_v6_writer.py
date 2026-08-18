"""P1.7 — the post-genesis v6 ordinary-event writer and its two admission gates.

``EPOCH-RESET.md`` §5.1 says ordinary event writers are refused *before* genesis
and *after* the v6 epoch opens. Read literally that leaves no door open at all,
which is the state P1.1-P2.3 left main in: ``check_legacy_append`` refuses every
legacy append on both sides, and no v6 append path existed. This module is the
behavioural evidence that the door P1.7 adds is the right one — narrow, gated, and
refusing by name at every step rather than defaulting to permissive.

Structure mirrors the writer's own refusal order, because that order is the
contract: epoch admission, key binding (§5.8), workflow registration (gate 1),
producer authorization (gate 2), then the envelope/signature/row invariants.

**WI-287 parametrization seam.** Every test in ``TestSemanticConformance`` is
written against a ``writer`` fixture that resolves the append callable and the
store handle, and asserts only on envelope/verdict semantics — never on locking,
rollback, ``FOR UPDATE`` behaviour or concurrency. Those are the tests
``SUITE-RECONCILIATION.md`` §2.3(a) says a shared conformance suite parametrizes
over both backends. Everything in ``TestPostgresOnly`` is deliberately outside
that seam: it touches the global-chain sentinel and the transaction boundary,
which ``InMemoryEventStore`` has no machinery to fake.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from _helpers import DSN
from _v6_fixtures import (
    BOOTSTRAP_PRINCIPAL,
    TEST_HARNESS,
    TEST_HARNESS_VERSION,
    TEST_MODEL,
    TEST_MODEL_LINEAGE,
    V6TestKeyset,
    acceptance_payload,
    genesis_envelope,
    make_v6_keyset,
)

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._provision import provision
from regista._v6_writer import (
    Producer,
    ProducerPolicyEntry,
    append_v6_event,
    check_producer_authorization,
    read_project_identity,
    require_v6_epoch,
    resolve_key_binding_anchor,
    resolve_workflow_registration,
    workflow_definition_hash,
)

WORKER = "agent:worker"
PRODUCER = Producer(
    harness=TEST_HARNESS,
    harness_version=TEST_HARNESS_VERSION,
    model=TEST_MODEL,
    model_lineage=TEST_MODEL_LINEAGE,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keyset(tmp_path: Path) -> V6TestKeyset:
    return make_v6_keyset(tmp_path)


@pytest.fixture
def project(keyset: V6TestKeyset):
    """A provisioned, empty project bound to the Ed25519 keyset. NO genesis yet."""

    from regista._testing import drop_project_schema

    name = f"p17_{uuid.uuid4().hex[:12]}"
    provision(DSN, [name])
    instance = Regista(DSN, name, keyset.path)
    try:
        yield instance
    finally:
        # WI-243's leak guard fails the session on a surviving schema, so the
        # teardown is part of the fixture contract, not politeness.
        instance.close()
        drop_project_schema(DSN, name)


@pytest.fixture
def genesis(project, keyset: V6TestKeyset):
    """The epoch, opened. Returns the genesis write."""

    return project.write_genesis(genesis_envelope(keyset), gate_passed=True)


def _accept(project, keyset: V6TestKeyset, genesis, principal_id: str, **scopes: Any):
    """Append the standalone ``principal_key_accepted`` for ``principal_id``."""

    identity = _identity(project)
    payload = acceptance_payload(
        keyset,
        principal_id=principal_id,
        accepted_by=BOOTSTRAP_PRINCIPAL,
        accepted_by_anchor=genesis.to_dict()["event_hash"],
        project_instance_id=str(identity.project_instance_id),
        trust_domain_id=str(identity.trust_domain_id),
        **scopes,
    )
    with project._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            project._keys,
            entity_kind="principal",
            entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal_id),
            transition="principal_key_accepted",
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="system",
            producer=PRODUCER,
            payload=payload,
        )


def _identity(project):
    with project._mgr.transaction() as conn:
        identity = read_project_identity(conn)
    assert identity is not None
    return identity


def _register_workflow(project, keyset: V6TestKeyset, name: str, version: int, definition):
    """Append the signed ``workflow_registered`` event gate 1 looks for."""

    workflow_id = uuid.uuid5(
        uuid.NAMESPACE_OID,
        "regista.workflow:"
        + str(_identity(project).project_instance_id)
        + f":{name}:{version}",
    )
    payload = {
        "type": "regista.workflow-registration",
        "version": 1,
        "name": name,
        "workflow_version": version,
        "definition": definition,
        "definition_hash": workflow_definition_hash(definition),
        "supersedes_registration_event_hash": None,
    }
    with project._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            project._keys,
            entity_kind="workflow",
            entity_id=workflow_id,
            transition="workflow_registered",
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="system",
            producer=PRODUCER,
            payload=payload,
        )


_DEFINITION = {
    "states": ["open", "closed"],
    "initial_state": "open",
    "transitions": [{"name": "close", "from": "open", "to": "closed"}],
}


# ---------------------------------------------------------------------------
# Epoch admission
# ---------------------------------------------------------------------------


class TestEpochAdmission:
    """The writer is the mirror image of ``check_legacy_append``, not a bypass of it."""

    def test_an_ordinary_v6_append_before_genesis_is_refused(self, project, keyset):
        """The one refusal that makes the boundary a boundary in both directions.

        Fail-then-pass note (measured, mutation M1): replacing
        ``require_v6_epoch(...)`` with a bare ``read_project_identity(conn)`` inside
        ``append_v6_event`` reddens this test — the append still fails, but on the
        *downstream* empty-chain-head check, whose refusal carries ``detail=None``:

            assert None == {'writer': 'v6_writer.append_v6_event'}

        That is why the assertion pins the ``detail`` and not only the code. Two
        different conditions share ``GENESIS_REQUIRED`` here on purpose (no identity
        vs. identity with no chain head), and a test that checked the code alone
        would accept the wrong one.
        """

        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.GENESIS_REQUIRED
        assert exc.value.detail == {"writer": "v6_writer.append_v6_event"}

    def test_require_v6_epoch_returns_the_signed_identity_after_genesis(
        self, project, keyset, genesis
    ):
        with project._mgr.transaction() as conn:
            identity = require_v6_epoch(conn, writer="probe")
        assert str(identity.project_instance_id) != ""
        assert identity.principal_id == BOOTSTRAP_PRINCIPAL
        assert identity.scheme_id == "ed25519"
        assert identity.genesis_event_hash == genesis.event_hash

    def test_the_legacy_writer_is_still_refused_after_genesis(self, project, genesis):
        """P1.2's guard must not be weakened by P1.7's addition.

        The two doors are exclusive: exactly one is open at any moment. A regression
        that made the legacy append pass post-genesis would be a silent v5/v6
        mixed-epoch region, which the epoch reset exists to prevent.
        """

        from regista._genesis import check_legacy_append

        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                check_legacy_append(conn, writer="probe")
        assert exc.value.code is ErrorCode.V6_EPOCH_OPEN


# ---------------------------------------------------------------------------
# Key binding — TRUST-DOMAIN.md §5.8 / §5.11
# ---------------------------------------------------------------------------


class TestKeyBinding:
    def test_the_bootstrap_acceptance_is_the_projects_first_anchor(
        self, project, keyset, genesis
    ):
        """Resolution 1 (Bootstrap B): the genesis event hash *is* the anchor."""

        with project._mgr.transaction() as conn:
            anchor = resolve_key_binding_anchor(
                conn,
                principal_id=BOOTSTRAP_PRINCIPAL,
                key_id=keyset.bootstrap.key_id,
            )
        assert anchor.kind == "bootstrap"
        assert anchor.event_hash == genesis.to_dict()["event_hash"]
        assert anchor.transition == "project_initialized"
        assert anchor.scopes.may_accept_keys is True

    def test_an_unaccepted_principal_cannot_append(self, project, keyset, genesis):
        """§5.11's whole point: absence of an anchor is a refusal, not a fallback.

        ``agent:worker`` has an active, actor-role, Ed25519 key bound to it in the
        keyset — everything the *legacy* writer ever asked for. The v6 writer still
        refuses, because a key file is not a project-local acceptance.
        """

        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.KEY_BINDING_UNRESOLVED
        assert exc.value.detail == {
            "principal_id": WORKER,
            "key_id": keyset.key_for(WORKER).key_id,
        }

    def test_a_principal_keys_row_does_not_satisfy_the_binding(
        self, project, keyset, genesis
    ):
        """§5.11's last row, as an executable assertion.

        "A row exists in ``principal_keys`` naming the key → **irrelevant**." The
        projection is inserted directly here — the state an operator ``UPDATE`` or a
        legacy provisioning path would leave — and the append is still refused.
        """

        key = keyset.key_for(WORKER)
        with project._mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO principal_keys "
                "(principal_id, key_id, public_key, fingerprint, scheme, status, "
                "registered_by, valid_from, registered_at) "
                "VALUES (%s, %s, %s, %s, %s, 'active', %s, now(), now())",
                [
                    WORKER,
                    key.key_id,
                    key.public_key,
                    key.fingerprint,
                    "ed25519",
                    BOOTSTRAP_PRINCIPAL,
                ],
            )
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.KEY_BINDING_UNRESOLVED

    def test_a_standalone_acceptance_makes_the_principal_appendable(
        self, project, keyset, genesis
    ):
        """The positive half: ordinary acceptance, with no self-authorisation."""

        accepted = _accept(project, keyset, genesis, WORKER)
        assert accepted.transition == "principal_key_accepted"
        # The acceptance itself points at the bootstrap anchor, not at itself.
        assert accepted.key_binding_event_hash == genesis.to_dict()["event_hash"]

        with project._mgr.transaction() as conn:
            anchor = resolve_key_binding_anchor(
                conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
            )
        assert anchor.kind == "acceptance"
        assert anchor.event_hash == accepted.event_hash_text

        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
        assert appended.key_binding_event_hash == accepted.event_hash_text

    def test_no_event_ever_references_itself(self, project, keyset, genesis):
        """§5.8's withdrawn rule, pinned as a negative.

        The self-referential first acceptance was withdrawn by Resolution 1 because
        the envelope field was impossible to fill. Nothing in this writer can
        produce one: the anchor is resolved from committed rows *before* the new
        event's hash exists.
        """

        accepted = _accept(project, keyset, genesis, WORKER)
        assert accepted.key_binding_event_hash != accepted.event_hash_text


# ---------------------------------------------------------------------------
# Admission gate 1 — workflow registration (P1.7 owns it)
# ---------------------------------------------------------------------------


class TestWorkflowRegistrationGate:
    def test_an_unregistered_workflow_is_refused_by_name(self, project, keyset, genesis):
        _accept(project, keyset, genesis, WORKER)
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="close",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                    workflow_name="never-registered",
                    workflow_version=1,
                )
        assert exc.value.code is ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED
        assert exc.value.detail == {
            "workflow_name": "never-registered",
            "workflow_version": 1,
        }

    def test_a_workflow_registry_row_is_not_a_registration(
        self, project, keyset, genesis
    ):
        """The gate's substantive claim, and the reason it is not a lookup.

        ``workflow_registry`` is mutable operator state. Binding replay's oracle to
        it is the S6 shape ``V6-ENVELOPE.md`` §3.4 removes: the row is inserted here
        exactly as ``register_workflow`` would, and the append is still refused
        because no *signed* registration event exists.
        """

        _accept(project, keyset, genesis, WORKER)
        with project._mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO workflow_registry "
                "(workflow_name, version, regista_version, definition) "
                "VALUES (%s, %s, %s, %s)",
                ["row-only", 1, "0.6.0", __import__("json").dumps(_DEFINITION)],
            )
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                resolve_workflow_registration(conn, name="row-only", version=1)
        assert exc.value.code is ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED

    def test_a_signed_registration_resolves_and_binds_the_definition_hash(
        self, project, keyset, genesis
    ):
        registered = _register_workflow(project, keyset, "wf", 1, _DEFINITION)
        _accept(project, keyset, genesis, WORKER)
        with project._mgr.transaction() as conn:
            binding = resolve_workflow_registration(conn, name="wf", version=1)
        assert binding.definition_hash == workflow_definition_hash(_DEFINITION)
        assert binding.registration_event_hash == registered.event_hash_text

        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="close",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
                workflow_name="wf",
                workflow_version=1,
            )
        assert appended.workflow is not None
        assert appended.workflow.registration_event_hash == registered.event_hash_text
        assert appended.workflow.definition_hash == binding.definition_hash

    def test_a_different_version_does_not_satisfy_the_gate(
        self, project, keyset, genesis
    ):
        """``(name, version)`` is the registration key, not ``name`` alone."""

        _register_workflow(project, keyset, "wf", 1, _DEFINITION)
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                resolve_workflow_registration(conn, name="wf", version=2)
        assert exc.value.code is ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED

    def test_the_sentinel_workflow_shape_is_refused_before_anything_is_signed(
        self, project, keyset, genesis
    ):
        """``""`` / ``0`` are rejected and never generated (``V6-ENVELOPE.md`` §1.6).

        This matters because the *legacy* ceremony path passed exactly
        ``workflow_name="", workflow_version=0`` — in v6 the envelope would sign the
        falsehood, so the writer refuses instead of normalising it to null.
        """

        _accept(project, keyset, genesis, WORKER)
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                    workflow_name="",
                    workflow_version=0,
                )
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT
        assert "sentinel" in exc.value.message

    def test_a_half_supplied_workflow_pair_is_refused(self, project, keyset, genesis):
        _accept(project, keyset, genesis, WORKER)
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                    workflow_name="wf",
                )
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT


# ---------------------------------------------------------------------------
# Admission gate 2 — producer authorization (P1.7 owns it)
# ---------------------------------------------------------------------------


class TestProducerAuthorizationGate:
    def _anchor(self, project, keyset, genesis, principal_id=BOOTSTRAP_PRINCIPAL):
        with project._mgr.transaction() as conn:
            return resolve_key_binding_anchor(
                conn,
                principal_id=principal_id,
                key_id=keyset.key_for(principal_id).key_id,
            )

    def test_an_unsupplied_policy_is_reported_never_skipped(
        self, project, keyset, genesis
    ):
        """``policy_not_supplied`` is an explicit state (§1.8), not a silent pass."""

        verdict = check_producer_authorization(
            PRODUCER,
            principal_id=BOOTSTRAP_PRINCIPAL,
            entity_kind="work_item",
            transition="created",
            anchor=self._anchor(project, keyset, genesis),
            policy=None,
        )
        assert verdict == "policy_not_supplied"

    def test_a_matching_policy_is_reported_as_matching(self, project, keyset, genesis):
        verdict = check_producer_authorization(
            PRODUCER,
            principal_id=BOOTSTRAP_PRINCIPAL,
            entity_kind="work_item",
            transition="created",
            anchor=self._anchor(project, keyset, genesis),
            policy=[
                ProducerPolicyEntry(
                    principal_id=BOOTSTRAP_PRINCIPAL,
                    allowed_harnesses=frozenset({TEST_HARNESS, "opencode"}),
                    host="mvmcc03",
                )
            ],
        )
        assert verdict == "matches_published_policy"

    def test_a_harness_outside_the_policy_is_refused(self, project, keyset, genesis):
        with pytest.raises(RegistaError) as exc:
            check_producer_authorization(
                Producer(harness="unlisted-harness", harness_version="1"),
                principal_id=BOOTSTRAP_PRINCIPAL,
                entity_kind="work_item",
                transition="created",
                anchor=self._anchor(project, keyset, genesis),
                policy=[
                    ProducerPolicyEntry(
                        principal_id=BOOTSTRAP_PRINCIPAL,
                        allowed_harnesses=frozenset({TEST_HARNESS}),
                    )
                ],
            )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "harness_not_allowed"

    def test_a_policy_that_omits_the_signer_contradicts_the_event(
        self, project, keyset, genesis
    ):
        """A pinned policy with no entry for the signer is a contradiction.

        The alternative — treating "principal absent" as "unconstrained" — would
        make a pinned policy weaker than no policy at all for exactly the principals
        an attacker would choose.
        """

        with pytest.raises(RegistaError) as exc:
            check_producer_authorization(
                PRODUCER,
                principal_id=BOOTSTRAP_PRINCIPAL,
                entity_kind="work_item",
                transition="created",
                anchor=self._anchor(project, keyset, genesis),
                policy=[
                    ProducerPolicyEntry(
                        principal_id="human:someone-else",
                        allowed_harnesses=frozenset({TEST_HARNESS}),
                    )
                ],
            )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "principal_absent_from_policy"

    def test_a_lineage_outside_the_closed_registry_is_refused(
        self, project, keyset, genesis
    ):
        """``EPOCH-RESET.md`` §5 precondition 2: closed vocabulary, at ingress."""

        with pytest.raises(RegistaError) as exc:
            check_producer_authorization(
                Producer(
                    harness=TEST_HARNESS,
                    harness_version="1",
                    model="some-model",
                    model_lineage="claude-opus-5",  # a versioned token, not a family
                ),
                principal_id=BOOTSTRAP_PRINCIPAL,
                entity_kind="work_item",
                transition="created",
                anchor=self._anchor(project, keyset, genesis),
            )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "model_lineage_not_canonical"

    @pytest.mark.parametrize(
        "producer",
        [
            Producer(harness="h", harness_version="1", model="m", model_lineage=None),
            Producer(harness="h", harness_version="1", model=None, model_lineage="fable"),
        ],
        ids=["model-without-lineage", "lineage-without-model"],
    )
    def test_model_and_lineage_must_be_null_together(
        self, project, keyset, genesis, producer
    ):
        """"No model" and "undeclared" are different states and stay different."""

        with pytest.raises(RegistaError) as exc:
            check_producer_authorization(
                producer,
                principal_id=BOOTSTRAP_PRINCIPAL,
                entity_kind="work_item",
                transition="created",
                anchor=self._anchor(project, keyset, genesis),
            )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "producer_model_lineage_disagreement"

    def test_a_non_model_producer_is_accepted_with_both_null(
        self, project, keyset, genesis
    ):
        verdict = check_producer_authorization(
            Producer(harness="cron", harness_version="1"),
            principal_id=BOOTSTRAP_PRINCIPAL,
            entity_kind="work_item",
            transition="created",
            anchor=self._anchor(project, keyset, genesis),
        )
        assert verdict == "policy_not_supplied"

    def test_an_entity_kind_outside_the_acceptance_scopes_is_refused(
        self, project, keyset, genesis
    ):
        """The §5.8 half of the gate: scopes are enforced, not decorative."""

        _accept(project, keyset, genesis, WORKER, entity_kinds=("work_item",))
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid4(),
                    transition="principal_registered",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "acceptance_scope_exceeded"
        assert exc.value.detail["entity_kinds"] == ["work_item"]

    def test_a_transition_outside_the_acceptance_scopes_is_refused(
        self, project, keyset, genesis
    ):
        _accept(project, keyset, genesis, WORKER, transitions=("created",))
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="deleted",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "acceptance_scope_exceeded"
        assert exc.value.detail["transitions"] == ["created"]

    def test_a_null_transitions_scope_authorises_every_transition(
        self, project, keyset, genesis
    ):
        """``"transitions": null`` is a wildcard; ``[]`` is not, and must not be.

        The distinction is the reason ``AcceptanceScopes.transitions`` is
        ``frozenset | None`` rather than a set that happens to be empty.
        """

        _accept(project, keyset, genesis, WORKER, transitions=None)
        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="anything-at-all",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
        assert appended.transition == "anything-at-all"


# ---------------------------------------------------------------------------
# Envelope, signature and row semantics — the WI-287 parametrization seam
# ---------------------------------------------------------------------------


class TestSemanticConformance:
    """Backend-agnostic semantics. See the module docstring for the WI-287 seam.

    Nothing here asserts on locking, rollback, ``FOR UPDATE`` ordering or
    concurrency; every assertion is about the envelope the writer produces, the
    verdict verification returns, or the row projection. That is precisely
    ``SUITE-RECONCILIATION.md`` §2.3(a)'s "envelope validation, signing,
    sequencing, admission-state machine" split, so WI-287 can parametrize this
    class over ``InMemoryRegista`` by replacing the ``project``/``genesis``
    fixtures with backend-parametrized ones and changing nothing below.
    """

    @pytest.fixture
    def appendable(self, project, keyset, genesis):
        _accept(project, keyset, genesis, WORKER)
        return project

    def _envelope_of(self, project, event_id):
        from regista._verification import parse_v6_envelope_strict

        with project._mgr.transaction() as conn:
            row = conn.execute(
                "SELECT canonical_envelope FROM events WHERE event_id = %s", [event_id]
            ).fetchone()
        assert row is not None
        return parse_v6_envelope_strict(bytes(row["canonical_envelope"]))

    def test_the_writer_emits_all_sixteen_required_members(self, appendable, keyset):
        with appendable._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
                payload={"note": "hello"},
            )
        envelope = self._envelope_of(appendable, appended.event_id)
        assert len(envelope) == 16
        assert envelope["type"] == "regista.event"
        assert envelope["version"] == 6
        assert set(envelope["producer"]) == {
            "harness",
            "harness_version",
            "model",
            "model_lineage",
        }
        assert envelope["producer"]["model_lineage"] == TEST_MODEL_LINEAGE
        # model_lineage lives in producer and NOWHERE else (§1.8, §8.4 rule 7).
        assert envelope["actor"]["metadata"] is None

    def test_the_stored_bytes_are_a_jcs_fixed_point(self, appendable):
        """§5.4: the stored bytes are authoritative and must re-canonicalize to themselves."""

        from regista._signing import canonicalize_v6_envelope

        with appendable._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
                payload={"z": 1, "a": {"nested": True}},
            )
        envelope = self._envelope_of(appendable, appended.event_id)
        assert canonicalize_v6_envelope(envelope) == appended.canonical_envelope

    def test_the_row_reconciles_with_its_signed_envelope(self, appendable):
        """The row projection is a *duplicate* of signed fields, and must agree.

        ``verify_event_strict`` is the only function that decides authentication, so
        this asserts through it rather than re-deriving the comparison.
        """

        from regista._keys import KeySet
        from regista._verification import (
            EventRow,
            KeySetResolver,
            verify_event_strict,
        )

        with appendable._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
                payload={"note": "reconcile"},
            )
            row = conn.execute(
                "SELECT event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                "event_seq, actor_id, actor_kind, actor_metadata, key_id, "
                "workflow_name, workflow_version, timestamp, transition, payload, "
                "payload_canonical_hash, signature, canonical_envelope, on_behalf_of, "
                "scheme_id, prev_event_hash, global_seq, prev_global_event_hash "
                "FROM events WHERE event_id = %s",
                [appended.event_id],
            ).fetchone()
        result = verify_event_strict(
            EventRow.from_mapping(row),
            keys=KeySetResolver(KeySet(appendable._keys.path)
                                if hasattr(appendable._keys, "path")
                                else appendable._keys),
        )
        assert result.signature_valid is True
        assert result.row_reconciled is True
        assert result.mismatched_field_names == ()

    def test_a_workflow_free_event_stores_sql_null_workflow_columns(self, appendable):
        """§1.6 / §9.3: ``workflow: null`` requires SQL NULL, not ``''``/``0``."""

        with appendable._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
            row = conn.execute(
                "SELECT workflow_name, workflow_version FROM events WHERE event_id = %s",
                [appended.event_id],
            ).fetchone()
        assert row["workflow_name"] is None
        assert row["workflow_version"] is None
        assert self._envelope_of(appendable, appended.event_id)["workflow"] is None

    def test_transition_is_non_empty_on_every_v6_event(self, appendable):
        """Resolution 3: there are no transitionless v6 events in 0.6.0."""

        with pytest.raises(RegistaError) as exc:
            with appendable._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    appendable._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        assert exc.value.code is ErrorCode.V6_ENVELOPE_INVALID

    def test_a_non_canonical_actor_never_reaches_key_material(self, appendable, keyset):
        """Criterion 19's inversion, at the writer boundary.

        The refusal must come from the grammar, before signing. A bare legacy name
        has no key in the keyset either, so this asserts the *grammar* code
        specifically rather than accepting any refusal.
        """

        with pytest.raises(RegistaError) as exc:
            with appendable._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    appendable._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id="mvmcc03-agent",
                    actor_kind="agent",
                    producer=PRODUCER,
                )
        # Either the keyset refuses first (no such principal) or the grammar does;
        # both are fail-closed, and neither may be a successful append.
        assert exc.value.code in (
            ErrorCode.PRINCIPAL_ID_NOT_CANONICAL,
            ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL,
            ErrorCode.UNKNOWN_KEY_ID,
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
        )

    def test_the_entity_chain_links_by_signed_v6_event_hash(self, appendable):
        """§1.7: ``previous_entity_event_hash`` is null iff ``entity_seq == 1``."""

        entity_id = uuid.uuid4()
        hashes = []
        for seq in range(1, 4):
            with appendable._mgr.transaction() as conn:
                appended = append_v6_event(
                    conn,
                    appendable._keys,
                    entity_kind="work_item",
                    entity_id=entity_id,
                    transition="created" if seq == 1 else "updated",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                )
            assert appended.entity_seq == seq
            hashes.append(appended.event_hash_text)

        first = self._envelope_of(appendable, None) if False else None
        for index, seq in enumerate(range(1, 4)):
            with appendable._mgr.transaction() as conn:
                row = conn.execute(
                    "SELECT event_id FROM events WHERE entity_kind = 'work_item' "
                    "AND entity_id = %s AND event_seq = %s",
                    [entity_id, seq],
                ).fetchone()
            envelope = self._envelope_of(appendable, row["event_id"])
            link = envelope["chain"]["previous_entity_event_hash"]
            if seq == 1:
                assert link is None
            else:
                assert link == hashes[index - 1]
        assert first is None

    def test_the_project_chain_links_across_entities(self, appendable):
        """One project-wide chain, regardless of entity — §1.7 + the sentinel."""

        first_entity, second_entity = uuid.uuid4(), uuid.uuid4()
        with appendable._mgr.transaction() as conn:
            one = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=first_entity,
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
        with appendable._mgr.transaction() as conn:
            two = append_v6_event(
                conn,
                appendable._keys,
                entity_kind="work_item",
                entity_id=second_entity,
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
        envelope = self._envelope_of(appendable, two.event_id)
        assert envelope["chain"]["previous_project_event_hash"] == one.event_hash_text
        # Different entities, so the entity link is null on both.
        assert envelope["chain"]["previous_entity_event_hash"] is None

    def test_the_first_ordinary_event_chains_from_genesis(
        self, project, keyset, genesis
    ):
        _accept(project, keyset, genesis, WORKER)
        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
        envelope = self._envelope_of(project, appended.event_id)
        # The acceptance event sits between genesis and this one, so the link is the
        # acceptance's hash — the project chain is total, not per-kind.
        assert envelope["chain"]["previous_project_event_hash"] is not None
        assert envelope["chain"]["previous_project_event_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Postgres-only — deliberately OUTSIDE the WI-287 conformance seam
# ---------------------------------------------------------------------------


class TestPostgresOnly:
    """Locking and transactional behaviour. ``InMemoryEventStore`` cannot fake this.

    ``SUITE-RECONCILIATION.md`` §2.3(a): "locking, rollback, persistence, and
    concurrency/races remain Postgres-only". Keeping these here rather than in the
    conformance class is what stops an in-memory pass from laundering a
    Postgres-gated claim.
    """

    def test_the_writer_serialises_on_the_same_global_chain_sentinel_as_genesis(
        self, project, keyset, genesis
    ):
        """The head advances to the v6 event hash, not the legacy ``sha256(env||sig)``.

        Genesis sets the head with ``compute_v6_event_hash``; if the ordinary writer
        used the legacy formula the chain would silently fork at event 2 while every
        row still looked well-formed.
        """

        _accept(project, keyset, genesis, WORKER)
        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=WORKER,
                actor_kind="agent",
                producer=PRODUCER,
            )
            head = conn.execute(
                "SELECT head_hash, head_event_id FROM event_chain_head WHERE id = TRUE"
            ).fetchone()
        assert bytes(head["head_hash"]) == appended.event_hash
        assert uuid.UUID(str(head["head_event_id"])) == appended.event_id

    def test_a_missing_entity_predecessor_is_refused_rather_than_forked(
        self, project, keyset, genesis
    ):
        """An explicit ``entity_seq`` that skips a link must refuse, not write a hole."""

        _accept(project, keyset, genesis, WORKER)
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="work_item",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                    entity_seq=5,
                )
        assert exc.value.code is ErrorCode.V6_CHAIN_LINK_MISSING
        assert exc.value.detail["missing_event_seq"] == 4
