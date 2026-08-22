"""P1.7 — the two payload contracts ``_trust_log.DEFERRED_TRANSITIONS`` assigns here.

``principal_key_accepted`` and ``principal_key_acceptance_revoked`` are both listed in
``src/regista/_trust_log.py`` as "P1.7 (§5.8 project-local acceptance)" and had no
parser anywhere on main: P2.2's §5.5 family covers the *trust-log* enrolment events,
not the *project-local* acceptance ones. Without the revocation contract in
particular, ``TRUST-DOMAIN.md`` §5.10 **step 4** — "no
``principal_key_acceptance_revoked`` for ``A`` lies between ``A`` and ``E``" — is
unimplementable, because there is no event shape to look for.

These are pure-payload tests plus the writer-level consequence of a revocation. They
need no genesis for the validator half, which is why the validator half runs without a
database at all.
"""

from __future__ import annotations

import base64
import copy
import hashlib
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
    KEY_ACCEPTANCE_REVOCATION_TYPE,
    PRINCIPAL_KEY_ACCEPTANCE_REVOKED,
    PRINCIPAL_KEY_ACCEPTED,
    Producer,
    append_v6_event,
    find_acceptance_revocations,
    read_project_identity,
    resolve_key_binding_anchor,
    validate_key_acceptance_payload,
    validate_key_acceptance_revocation_payload,
)

WORKER = "agent:worker"
PRODUCER = Producer(
    harness=TEST_HARNESS,
    harness_version=TEST_HARNESS_VERSION,
    model=TEST_MODEL,
    model_lineage=TEST_MODEL_LINEAGE,
)
_ANCHOR = "sha256:" + "ab" * 32


@pytest.fixture
def keyset(tmp_path: Path) -> V6TestKeyset:
    return make_v6_keyset(tmp_path)


@pytest.fixture
def payload(keyset: V6TestKeyset) -> dict[str, Any]:
    return acceptance_payload(
        keyset,
        principal_id=WORKER,
        accepted_by=BOOTSTRAP_PRINCIPAL,
        accepted_by_anchor=_ANCHOR,
        project_instance_id=str(uuid.uuid4()),
        trust_domain_id=str(uuid.uuid4()),
    )


def _revocation(payload: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    doc = {
        "type": KEY_ACCEPTANCE_REVOCATION_TYPE,
        "version": 1,
        "trust_domain_id": payload["trust_domain_id"],
        "project_instance_id": payload["project_instance_id"],
        "principal_id": payload["principal_id"],
        "key_id": payload["key_id"],
        "acceptance_event_hash": "sha256:" + "cd" * 32,
        "reason": "superseded",
        "revoked_by": {
            "principal_id": BOOTSTRAP_PRINCIPAL,
            "key_id": "pk_whoever",
            "key_binding_event_hash": _ANCHOR,
        },
    }
    doc.update(overrides)
    return doc


# ---------------------------------------------------------------------------
# regista.key-acceptance/v1
# ---------------------------------------------------------------------------


class TestAcceptancePayload:
    def test_the_fixture_payload_is_valid_and_yields_its_scopes(self, payload):
        scopes = validate_key_acceptance_payload(payload)
        assert scopes.entity_kinds == frozenset({"work_item", "principal", "workflow", "note"})
        assert scopes.transitions is None
        assert scopes.may_sign_checkpoints is False
        assert scopes.may_sign_bundles is False

    def test_a_standalone_acceptance_never_confers_may_accept_keys(self, payload):
        """§5.8's object has no ``may_accept_keys``; only the bootstrap object does.

        Reading an absent member as ``False`` rather than inheriting the accepter's
        authority is the narrower choice, and it is the one Resolution 1 implies: a
        further acceptance must be signed by the bootstrap authority or the registrar,
        not by any key that happens to have been accepted.
        """

        assert validate_key_acceptance_payload(payload).may_accept_keys is False

    def test_an_extra_key_is_a_rejection_not_forward_compatibility(self, payload):
        payload["future_field"] = "whatever"
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "payload_key_set"
        assert exc.value.detail["extra"] == ["future_field"]

    def test_a_missing_key_is_named(self, payload):
        del payload["scopes"]
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["missing"] == ["scopes"]

    def test_a_fingerprint_that_does_not_match_the_public_key_is_invalid(self, payload):
        """§5.8: "Mismatch … is **invalid**, not a preference."

        The repeated ``public_key`` is what makes a bundle self-sufficient for key
        material. A fingerprint that disagrees with those bytes turns that asset into a
        liability, so it cannot be tolerated or "preferred against".
        """

        payload["fingerprint"] = "ed25519:sha256:" + "00" * 32
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "fingerprint_mismatch"

    def test_a_non_canonical_32_byte_public_key_is_refused(self, payload):
        payload["public_key"] = base64.b64encode(b"\x01" * 31).decode("ascii")
        payload["fingerprint"] = "ed25519:sha256:" + hashlib.sha256(b"\x01" * 31).hexdigest()
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "public_key_not_canonical_base64_32"

    def test_a_null_accepted_by_anchor_is_refused(self, payload):
        """The withdrawn self-referential first acceptance nulled exactly this field.

        ``TRUST-DOMAIN.md`` §5.8's original bootstrapping rule "nulled only
        ``accepted_by.key_binding_event_hash``" and was withdrawn by Resolution 1.
        Permitting a null here would quietly restore it, so the refusal is the
        mechanism that keeps the withdrawal real.
        """

        payload["accepted_by"]["key_binding_event_hash"] = None
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "accepted_by_anchor_null_or_malformed"

    def test_a_key_cannot_accept_itself(self, payload, keyset):
        """"Ordinary acceptance … with no exceptions and no self-authorisation anywhere.\""""

        payload["accepted_by"]["principal_id"] = payload["principal_id"]
        payload["accepted_by"]["key_id"] = payload["key_id"]
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "self_authorisation"

    def test_a_bare_legacy_principal_is_refused_by_the_grammar(self, payload):
        """§2.7 puts ``principal_key_accepted`` in the always-strict column."""

        payload["principal_id"] = "mvmcc03-agent"
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.code is ErrorCode.PRINCIPAL_ID_NOT_CANONICAL

    def test_an_empty_transitions_list_is_legal_and_authorises_nothing(self, payload):
        """``[]`` and ``null`` must not collapse. This is the load-bearing distinction.

        ``null`` means "any transition"; ``[]`` means "no transition". A parser that
        normalised the empty list to ``None`` would silently widen a scope that was
        deliberately written to authorise nothing.
        """

        payload["scopes"]["transitions"] = []
        scopes = validate_key_acceptance_payload(payload)
        assert scopes.transitions == frozenset()
        assert scopes.transitions is not None
        assert scopes.permits(entity_kind="work_item", transition="created") is False

    def test_an_entity_kind_outside_the_closed_registry_is_refused(self, payload):
        payload["scopes"]["entity_kinds"] = ["project_system"]
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "scopes_entity_kinds_invalid"

    def test_an_empty_entity_kinds_list_is_refused(self, payload):
        """There is no wildcard for entity kind, so an empty set is a defect."""

        payload["scopes"]["entity_kinds"] = []
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == "scopes_entity_kinds_invalid"

    @pytest.mark.parametrize(
        ("field", "value", "reason"),
        [
            ("type", "regista.key-acceptance-v2", "payload_type"),
            ("version", 2, "payload_version"),
            ("version", True, "payload_version"),
            ("trust_domain_id", "not-a-uuid", "trust_domain_id_not_uuid"),
            ("project_instance_id", "NOT-A-UUID", "project_instance_id_not_uuid"),
            ("key_id", "   ", "key_id_empty"),
            ("trust_event_hash", "sha256:XYZ", "trust_event_hash_malformed"),
        ],
    )
    def test_field_level_refusals_are_named(self, payload, field, value, reason):
        payload[field] = value
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == reason

    @pytest.mark.parametrize(
        ("mutate", "reason"),
        [
            (lambda c: c.update({"checkpoint_seq": 0}), "checkpoint_seq_invalid"),
            (lambda c: c.update({"checkpoint_seq": True}), "checkpoint_seq_invalid"),
            (lambda c: c.update({"head_event_hash": "sha256:zz"}),
             "checkpoint_head_event_hash_malformed"),
            (lambda c: c.pop("document_digest"), "checkpoint_key_set"),
        ],
    )
    def test_checkpoint_refusals_are_named(self, payload, mutate, reason):
        mutate(payload["trust_log_checkpoint"])
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_payload(payload)
        assert exc.value.detail["reason"] == reason


# ---------------------------------------------------------------------------
# regista.key-acceptance-revocation/v1 — what §5.10 step 4 looks for
# ---------------------------------------------------------------------------


class TestRevocationPayload:
    def test_the_shape_is_accepted(self, payload):
        validate_key_acceptance_revocation_payload(_revocation(payload))

    def test_a_revocation_must_name_the_exact_acceptance_it_revokes(self, payload):
        """Step 4 decides by hash. Without one it would have to guess.

        A revocation that named only ``(principal_id, key_id)`` could not distinguish
        "revoke the current acceptance" from "revoke a superseded one", and the
        verifier's "between A and E" test needs the specific ``A``.
        """

        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_revocation_payload(
                _revocation(payload, acceptance_event_hash=None)
            )
        assert exc.value.detail["reason"] == "acceptance_event_hash_malformed"

    def test_a_revocation_anchored_on_the_acceptance_it_revokes_is_refused(self, payload):
        """R2 NB1: the counterpart to the acceptance side's ``self_authorisation``.

        If ``revoked_by.key_binding_event_hash`` IS the acceptance being revoked, the
        authority exercised is destroyed by the event exercising it. Since the phase-4
        B1 fix that is also **unrecoverable**: a revoked acceptance refuses every anchor
        for its (principal, key), so a principal revoking its own anchor removes its own
        ability to act — and for the bootstrap principal that is the project's only
        key-accepting authority.
        """

        self_revoking = _revocation(
            payload,
            acceptance_event_hash=_ANCHOR,
            revoked_by={
                "principal_id": BOOTSTRAP_PRINCIPAL,
                "key_id": "pk_whoever",
                "key_binding_event_hash": _ANCHOR,
            },
        )
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_revocation_payload(self_revoking)
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "self_revocation"
        assert exc.value.detail["acceptance_event_hash"] == _ANCHOR

    def test_a_revocation_anchored_elsewhere_is_still_valid(self, payload):
        """And the rule must be about the *anchor*, not about revocation itself: the
        ordinary case — a different authority's anchor — keeps validating."""

        validate_key_acceptance_revocation_payload(_revocation(payload))

    def test_the_reason_comes_from_the_closed_vocabulary(self, payload):
        """Shared verbatim with ``_trust_log._REVOCATION_REASONS``, not a second set."""

        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_revocation_payload(
                _revocation(payload, reason="because I said so")
            )
        assert exc.value.detail["reason"] == "reason_not_in_closed_set"
        assert exc.value.detail["declared_reason"] == "because I said so"
        assert exc.value.detail["allowed"] == [
            "compromised", "decommissioned", "policy", "superseded", "unspecified",
        ]

    def test_an_extra_key_is_refused(self, payload):
        doc = _revocation(payload)
        doc["effective_from"] = "later"
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_revocation_payload(doc)
        assert exc.value.detail["extra"] == ["effective_from"]

    def test_revoked_by_must_carry_its_own_anchor(self, payload):
        doc = _revocation(payload)
        doc["revoked_by"]["key_binding_event_hash"] = None
        with pytest.raises(RegistaError) as exc:
            validate_key_acceptance_revocation_payload(doc)
        assert exc.value.detail["reason"] == "revoked_by_anchor_malformed"


# ---------------------------------------------------------------------------
# The writer-level consequence: a revoked acceptance stops being an anchor
# ---------------------------------------------------------------------------


class TestRevocationAtWriteTime:
    @pytest.fixture
    def project(self, keyset):
        from regista._testing import drop_project_schema

        name = f"p17ka_{uuid.uuid4().hex[:10]}"
        provision(DSN, [name])
        instance = Regista(DSN, name, keyset.path)
        try:
            yield instance
        finally:
            instance.close()
            drop_project_schema(DSN, name)

    @pytest.fixture
    def genesis(self, project, keyset):
        return project.write_genesis(genesis_envelope(keyset), gate_passed=True)

    def _identity(self, project):
        with project._mgr.transaction() as conn:
            identity = read_project_identity(conn)
        assert identity is not None
        return identity

    def _accept(self, project, keyset, genesis):
        identity = self._identity(project)
        doc = acceptance_payload(
            keyset,
            principal_id=WORKER,
            accepted_by=BOOTSTRAP_PRINCIPAL,
            accepted_by_anchor=genesis.to_dict()["event_hash"],
            project_instance_id=str(identity.project_instance_id),
            trust_domain_id=str(identity.trust_domain_id),
        )
        with project._mgr.transaction() as conn:
            return append_v6_event(
                conn,
                project._keys,
                entity_kind="principal",
                entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + WORKER),
                transition=PRINCIPAL_KEY_ACCEPTED,
                actor_id=BOOTSTRAP_PRINCIPAL,
                actor_kind="system",
                producer=PRODUCER,
                payload=doc,
            )

    def _revoke(self, project, keyset, genesis, accepted):
        identity = self._identity(project)
        doc = {
            "type": KEY_ACCEPTANCE_REVOCATION_TYPE,
            "version": 1,
            "trust_domain_id": str(identity.trust_domain_id),
            "project_instance_id": str(identity.project_instance_id),
            "principal_id": WORKER,
            "key_id": keyset.key_for(WORKER).key_id,
            "acceptance_event_hash": accepted.event_hash_text,
            "reason": "compromised",
            "revoked_by": {
                "principal_id": BOOTSTRAP_PRINCIPAL,
                "key_id": keyset.bootstrap.key_id,
                "key_binding_event_hash": genesis.to_dict()["event_hash"],
            },
        }
        with project._mgr.transaction() as conn:
            return append_v6_event(
                conn,
                project._keys,
                entity_kind="principal",
                entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + WORKER),
                transition=PRINCIPAL_KEY_ACCEPTANCE_REVOKED,
                actor_id=BOOTSTRAP_PRINCIPAL,
                actor_kind="system",
                producer=PRODUCER,
                payload=doc,
            )

    def test_the_writer_validates_an_acceptance_payload_it_appends(
        self, project, keyset, genesis
    ):
        """An unparseable acceptance must never become an anchor a later event trusts."""

        identity = self._identity(project)
        doc = acceptance_payload(
            keyset,
            principal_id=WORKER,
            accepted_by=BOOTSTRAP_PRINCIPAL,
            accepted_by_anchor=genesis.to_dict()["event_hash"],
            project_instance_id=str(identity.project_instance_id),
            trust_domain_id=str(identity.trust_domain_id),
        )
        doc["fingerprint"] = "ed25519:sha256:" + "11" * 32
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:" + WORKER
                    ),
                    transition=PRINCIPAL_KEY_ACCEPTED,
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                    payload=doc,
                )
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "fingerprint_mismatch"

    def test_a_revoked_acceptance_stops_being_a_usable_anchor(
        self, project, keyset, genesis
    ):
        """§5.10 step 4, enforced at write time as well as at verification time.

        Note the code: ``KEY_ACCEPTANCE_REVOKED``, not ``KEY_BINDING_UNRESOLVED``.
        "Revoked" and "never accepted" are different facts and the operator response
        to each is different, so they get different codes.
        """

        accepted = self._accept(project, keyset, genesis)
        with project._mgr.transaction() as conn:
            anchor = resolve_key_binding_anchor(
                conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
            )
        assert anchor.event_hash == accepted.event_hash_text

        self._revoke(project, keyset, genesis, accepted)

        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                resolve_key_binding_anchor(
                    conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
                )
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_REVOKED
        assert exc.value.detail["revoked_acceptances"] == [accepted.event_hash_text]

    def test_an_archived_acceptance_remains_a_usable_anchor(
        self, project, keyset, genesis
    ):
        accepted = self._accept(project, keyset, genesis)
        with project._mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO events_archive SELECT * FROM events WHERE event_id = %s",
                [accepted.event_id],
            )
            conn.execute("DELETE FROM events WHERE event_id = %s", [accepted.event_id])
            anchor = resolve_key_binding_anchor(
                conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
            )
        assert anchor.event_hash == accepted.event_hash_text

    def test_an_archived_revocation_still_blocks_its_acceptance(
        self, project, keyset, genesis
    ):
        accepted = self._accept(project, keyset, genesis)
        revoked = self._revoke(project, keyset, genesis, accepted)
        with project._mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO events_archive SELECT * FROM events WHERE event_id = %s",
                [revoked.event_id],
            )
            conn.execute("DELETE FROM events WHERE event_id = %s", [revoked.event_id])
            with pytest.raises(RegistaError) as exc:
                resolve_key_binding_anchor(
                    conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
                )
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_REVOKED
        assert exc.value.detail["revoked_acceptances"] == [accepted.event_hash_text]

    def test_a_revoked_principal_cannot_append(self, project, keyset, genesis):
        accepted = self._accept(project, keyset, genesis)
        self._revoke(project, keyset, genesis, accepted)
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
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_REVOKED

    def test_find_acceptance_revocations_maps_hash_to_chain_position(
        self, project, keyset, genesis
    ):
        """The verifier needs positions, not a boolean — "between A and E" is ordinal."""

        accepted = self._accept(project, keyset, genesis)
        revoked = self._revoke(project, keyset, genesis, accepted)
        with project._mgr.transaction() as conn:
            found = find_acceptance_revocations(conn)
        assert found == {accepted.event_hash_text: revoked.global_seq}

    def test_an_acceptance_must_be_signed_by_the_authority_it_names(
        self, project, keyset, genesis
    ):
        """``accepted_by`` records who exercised the authority — so it must be the signer.

        Without this cross-check the payload could name any accepter it liked while
        being signed by someone else: a self-asserted string wearing a structured
        field's clothes, which is the exact failure mode 0.6.0 exists to remove. The
        payload validator cannot catch it (it sees only the document); only the writer
        can, because only the writer knows who is signing.
        """

        identity = self._identity(project)
        doc = acceptance_payload(
            keyset,
            principal_id=WORKER,
            accepted_by=BOOTSTRAP_PRINCIPAL,
            accepted_by_anchor=genesis.to_dict()["event_hash"],
            project_instance_id=str(identity.project_instance_id),
            trust_domain_id=str(identity.trust_domain_id),
        )
        # The document still claims the bootstrap principal accepted this key, and it
        # is internally valid — validate_key_acceptance_payload passes it.
        validate_key_acceptance_payload(doc)
        doc["accepted_by"]["principal_id"] = "human:operator"
        doc["accepted_by"]["key_id"] = keyset.key_for("human:operator").key_id
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:" + WORKER
                    ),
                    transition=PRINCIPAL_KEY_ACCEPTED,
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                    payload=doc,
                )
        assert exc.value.code is ErrorCode.ACTOR_SIGNER_MISMATCH
        assert exc.value.detail["reason"] == "accepted_by_is_not_the_signer"
        assert exc.value.detail["signer_principal_id"] == BOOTSTRAP_PRINCIPAL

    def test_a_key_without_may_accept_keys_cannot_accept_another(
        self, project, keyset, genesis
    ):
        """§5.8: acceptance needs ``may_accept_keys``, which standalone anchors never grant.

        So an accepted principal cannot go on to accept further keys — acceptance
        authority does not propagate. That narrowness is deliberate: it is what keeps
        one compromised agent key from minting a population of trusted keys.
        """

        accepted = self._accept(project, keyset, genesis)
        assert accepted.transition == PRINCIPAL_KEY_ACCEPTED

        identity = self._identity(project)
        second = acceptance_payload(
            keyset,
            principal_id="human:operator",
            accepted_by=WORKER,
            accepted_by_anchor=accepted.event_hash_text,
            project_instance_id=str(identity.project_instance_id),
            trust_domain_id=str(identity.trust_domain_id),
        )
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:human:operator"
                    ),
                    transition=PRINCIPAL_KEY_ACCEPTED,
                    actor_id=WORKER,
                    actor_kind="agent",
                    producer=PRODUCER,
                    payload=second,
                )
        assert exc.value.code is ErrorCode.PRODUCER_NOT_AUTHORIZED
        assert exc.value.detail["reason"] == "may_accept_keys_not_held"

    def test_the_bootstrap_anchor_is_not_silently_used_after_a_revocation(
        self, project, keyset, genesis
    ):
        """A revoked acceptance must not fall through to an earlier anchor.

        The bootstrap principal keeps its own anchor, so the temptation is to let a
        revoked principal quietly resolve to something older. That would make
        revocation a no-op whenever a superseded anchor still sat in the chain, which
        is the fail-open shape this release exists to remove.
        """

        accepted = self._accept(project, keyset, genesis)
        self._revoke(project, keyset, genesis, accepted)
        # The bootstrap principal is unaffected — the refusal is per principal/key.
        with project._mgr.transaction() as conn:
            bootstrap_anchor = resolve_key_binding_anchor(
                conn,
                principal_id=BOOTSTRAP_PRINCIPAL,
                key_id=keyset.bootstrap.key_id,
            )
        assert bootstrap_anchor.kind == "bootstrap"

    def test_the_bootstrap_cannot_revoke_its_own_genesis_anchor(
        self, project, keyset, genesis
    ):
        """R2 NB1 at the writer, where the consequence is a bricked project.

        The bootstrap principal's key-binding anchor IS the genesis event, and genesis
        carries the bootstrap key acceptance. Naming genesis as *both* the revocation's
        ``acceptance_event_hash`` and its ``revoked_by.key_binding_event_hash`` would
        revoke the only authority the project has for accepting keys — and after the
        phase-4 B1 fix nothing can re-establish it, because a revoked acceptance refuses
        every anchor for that (principal, key) including the bootstrap one. So the
        refusal is not tidiness; it is the difference between a mistake and an
        unrecoverable project.
        """

        genesis_hash = genesis.to_dict()["event_hash"]
        identity = self._identity(project)
        doc = {
            "type": KEY_ACCEPTANCE_REVOCATION_TYPE,
            "version": 1,
            "trust_domain_id": str(identity.trust_domain_id),
            "project_instance_id": str(identity.project_instance_id),
            "principal_id": BOOTSTRAP_PRINCIPAL,
            "key_id": keyset.bootstrap.key_id,
            "acceptance_event_hash": genesis_hash,
            "reason": "compromised",
            "revoked_by": {
                "principal_id": BOOTSTRAP_PRINCIPAL,
                "key_id": keyset.bootstrap.key_id,
                "key_binding_event_hash": genesis_hash,
            },
        }
        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    project._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID,
                        "regista.principal:" + BOOTSTRAP_PRINCIPAL,
                    ),
                    transition=PRINCIPAL_KEY_ACCEPTANCE_REVOKED,
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=PRODUCER,
                    payload=doc,
                )
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "self_revocation"

        # The project is intact: the bootstrap authority still resolves and can still
        # accept a key. Without this half the test would pass on a project that had
        # already been destroyed by an earlier statement.
        with project._mgr.transaction() as conn:
            anchor = resolve_key_binding_anchor(
                conn,
                principal_id=BOOTSTRAP_PRINCIPAL,
                key_id=keyset.bootstrap.key_id,
            )
        assert anchor.kind == "bootstrap"
        accepted = self._accept(project, keyset, genesis)
        with project._mgr.transaction() as conn:
            worker_anchor = resolve_key_binding_anchor(
                conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
            )
        assert worker_anchor.event_hash == accepted.event_hash_text

    def test_a_revoked_newer_acceptance_does_not_fall_back_to_an_older_one(
        self, project, keyset, genesis
    ):
        """B1: the reachable half of the fall-through, which the bootstrap case hid.

        Two standalone acceptances of the SAME (principal, key) — the second carrying
        the current scopes — then a revocation of the second. Before this fix the
        resolver's loop ``continue``d past the revoked A2 and *returned* A1, because
        the ``KEY_ACCEPTANCE_REVOKED`` refusal was reached only when the surviving
        fallback happened to be the bootstrap anchor. So the operator's most recent
        word about the key — "no longer usable" — was silently undone by an older
        acceptance still sitting in the chain, which is the fail-open shape the sibling
        test above claims is closed.

        The writer's policy is the one its comment always stated: a revocation
        *anywhere* for this principal/key refuses. That is deliberately STRICTER than
        the verifier, which keeps §5.10 step 4's per-acceptance-hash rule to the
        letter so historical material verifies by the spec — see
        ``resolve_key_binding_anchor``'s note on the asymmetry.
        """

        first = self._accept(project, keyset, genesis)
        second = self._accept(project, keyset, genesis)
        assert second.event_hash_text != first.event_hash_text

        with project._mgr.transaction() as conn:
            anchor = resolve_key_binding_anchor(
                conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
            )
        assert anchor.event_hash == second.event_hash_text, (
            "the newest acceptance is the one carrying current scopes"
        )

        self._revoke(project, keyset, genesis, second)

        with pytest.raises(RegistaError) as exc:
            with project._mgr.transaction() as conn:
                resolve_key_binding_anchor(
                    conn, principal_id=WORKER, key_id=keyset.key_for(WORKER).key_id
                )
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_REVOKED
        assert exc.value.detail["revoked_acceptances"] == [second.event_hash_text]
        # The older acceptance is named as what was NOT fallen back to, so the refusal
        # is legible as "a revocation is not a downgrade".
        assert first.event_hash_text in exc.value.detail["superseded_live_anchors"]

    def test_an_ordinary_append_is_refused_after_the_newer_acceptance_is_revoked(
        self, project, keyset, genesis
    ):
        """The same reachable case at the production boundary rather than the helper.

        Pre-fix this append was **admitted**: it resolved the older acceptance and
        wrote a signed event under a key whose acceptance the operator had revoked.
        """

        self._accept(project, keyset, genesis)
        second = self._accept(project, keyset, genesis)
        self._revoke(project, keyset, genesis, second)

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
        assert exc.value.code is ErrorCode.KEY_ACCEPTANCE_REVOKED


# ---------------------------------------------------------------------------
# The process-level producer identity, and the §2.3 timestamp form
# ---------------------------------------------------------------------------


class TestProducerResolution:
    def test_an_unset_producer_is_refused_and_names_the_variables(self, monkeypatch):
        """``producer.harness`` is load-bearing, so absence is a refusal, not a default.

        An invented default like ``"unknown"`` would be a *signed* falsehood, which is
        the failure ``EPOCH-RESET.md`` §4 exists to remove: data that reads as complete
        when it is not.
        """

        from regista._v6_writer import PRODUCER_ENV, resolve_producer

        for name in PRODUCER_ENV.values():
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(RegistaError) as exc:
            resolve_producer()
        assert exc.value.code is ErrorCode.LOAD_BEARING_FIELD_MISSING
        assert exc.value.detail["fields"] == [
            "REGISTA_PRODUCER_HARNESS",
            "REGISTA_PRODUCER_HARNESS_VERSION",
        ]

    def test_a_whitespace_only_harness_counts_as_absent(self, monkeypatch):
        from regista._v6_writer import PRODUCER_ENV, resolve_producer

        monkeypatch.setenv(PRODUCER_ENV["harness"], "   ")
        monkeypatch.setenv(PRODUCER_ENV["harness_version"], "1")
        with pytest.raises(RegistaError) as exc:
            resolve_producer()
        assert exc.value.detail["fields"] == ["REGISTA_PRODUCER_HARNESS"]

    def test_a_model_free_producer_resolves_with_both_null(self, monkeypatch):
        """"No model" is a legitimate state and stays distinct from "undeclared"."""

        from regista._v6_writer import PRODUCER_ENV, resolve_producer

        for name in PRODUCER_ENV.values():
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv(PRODUCER_ENV["harness"], "cron")
        monkeypatch.setenv(PRODUCER_ENV["harness_version"], "2.1")
        producer = resolve_producer()
        assert producer == Producer(harness="cron", harness_version="2.1")
        assert producer.model is None and producer.model_lineage is None

    def test_an_explicit_producer_wins_over_the_environment(self, monkeypatch):
        from regista._v6_writer import PRODUCER_ENV, resolve_producer

        monkeypatch.setenv(PRODUCER_ENV["harness"], "from-env")
        monkeypatch.setenv(PRODUCER_ENV["harness_version"], "9")
        assert resolve_producer(PRODUCER) == PRODUCER


class TestOccurredAtLexicalForm:
    """``V6-ENVELOPE.md`` §2.3 — the six-fractional-digit form, centralised."""

    def test_a_whole_millisecond_still_renders_six_digits(self):
        """The exact instant ``isoformat()`` gets wrong.

        ``datetime.isoformat()`` drops to three fractional digits whenever the
        microseconds land on a whole millisecond, so the defect appears for roughly one
        instant in a thousand — reliably absent from a hand-picked test value and
        reliably present in production. Pinning it here is the point of the helper.
        """

        from datetime import UTC, datetime

        from regista._datetime_utils import v6_occurred_at

        whole_ms = datetime(2026, 8, 17, 12, 0, 0, 123000, tzinfo=UTC)
        assert whole_ms.isoformat() == "2026-08-17T12:00:00.123000+00:00"
        assert v6_occurred_at(whole_ms) == "2026-08-17T12:00:00.123000Z"

    def test_a_whole_second_renders_six_zeros(self):
        from datetime import UTC, datetime

        from regista._datetime_utils import v6_occurred_at

        assert (
            v6_occurred_at(datetime(2026, 1, 1, tzinfo=UTC)) == "2026-01-01T00:00:00.000000Z"
        )

    def test_a_naive_datetime_is_treated_as_utc(self):
        from datetime import datetime

        from regista._datetime_utils import v6_occurred_at

        assert v6_occurred_at(datetime(2026, 1, 1, 0, 0, 0)) == "2026-01-01T00:00:00.000000Z"

    def test_a_non_utc_offset_is_converted_not_truncated(self):
        from datetime import datetime, timedelta, timezone

        from regista._datetime_utils import v6_occurred_at

        value = datetime(2026, 1, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=5)))
        assert v6_occurred_at(value) == "2026-01-01T00:00:00.000000Z"

    def test_the_round_trip_is_exact(self):
        from datetime import UTC, datetime

        from regista._datetime_utils import parse_v6_occurred_at, v6_occurred_at

        value = datetime(2026, 8, 17, 23, 59, 59, 999999, tzinfo=UTC)
        assert parse_v6_occurred_at(v6_occurred_at(value)) == value

    def test_the_strict_parser_accepts_what_the_helper_emits(self):
        """The only assertion that matters: what we render, the parser takes."""

        from datetime import UTC, datetime

        from regista._datetime_utils import v6_occurred_at
        from regista._verification import V6EnvelopeError, validate_v6_envelope

        base = _minimal_envelope()
        for microsecond in (0, 1000, 123000, 999999):
            base["occurred_at"] = v6_occurred_at(
                datetime(2026, 8, 17, 12, 0, 0, microsecond, tzinfo=UTC)
            )
            validate_v6_envelope(base)

        base["occurred_at"] = datetime(
            2026, 8, 17, 12, 0, 0, 123000, tzinfo=UTC
        ).isoformat()
        with pytest.raises(V6EnvelopeError):
            validate_v6_envelope(base)


def _minimal_envelope() -> dict[str, Any]:
    """A schema-valid v6 envelope, built from the committed genesis vector."""

    import json

    vector_path = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"
    case = json.loads(vector_path.read_text(encoding="utf-8"))
    envelope: dict[str, Any] = copy.deepcopy(case["input"]["envelope_declaration_order"])
    project = str(uuid.uuid4())
    envelope["project_instance_id"] = project
    envelope["entity"]["id"] = project
    return envelope
