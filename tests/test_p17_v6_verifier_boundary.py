"""The v6 verifier boundary — ``TRUST-DOMAIN.md`` §5.10, §5.11 and §9 criteria 14/15.

What this file is for, stated plainly because the previous state of the tree is the
reason it exists: ``_verification._verify_v6_row`` used to return
``INVALID``/``ENVELOPE_SCHEMA_INCOMPLETE`` for **every** v6 row, clean or tampered.
The bytes and the row projection were checked; nothing that required seeing *another
event* was. So ``applicability`` carried no information about a v6 event at all, and
WI-287's cluster-6 tests had to assert around it (their docstring says so, and this
file is what licenses tightening them).

Almost everything here is **database-free**. The subject is the decision procedure over
presented material, and the honest way to present adversarial material is to build it:
a store fixture can only produce histories the writer is willing to write, and half of
§5.11's table is about histories it would refuse. Real-store coverage lives in
``TestAgainstARealEpoch`` at the end, and in ``tests/test_bundle.py``.

The corpus builder signs real Ed25519 envelopes with ``sign_v6_envelope`` and addresses
them by ``compute_v6_event_hash``, so no assertion here rests on a hand-written hash.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from regista._signing import compute_v6_event_hash, sign_v6_envelope
from regista._v6_referents import (
    NO_REFERENTS,
    MappingReferents,
    MaterialCompleteness,
    ReferentEvent,
    referent_from_bytes,
    resolve_completeness,
)
from regista._verification import (
    Applicability,
    Attribution,
    Backend,
    CheckpointBinding,
    EnvelopeVersion,
    EpochPosition,
    EventRow,
    FailureReason,
    KeyBinding,
    ProducerConsistency,
    RevocationStatus,
    StaticKeyResolver,
    TrustedKeySource,
    TrustRoot,
    VerificationPolicy,
    VerificationResult,
    verify_event_strict,
)

VECTOR = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"

BOOTSTRAP = "service:regista-boundary"
WORKER = "agent:boundary-worker"
OUTSIDER = "agent:boundary-outsider"

_HARNESS = "claude-code"
_HARNESS_VERSION = "test-harness/1"
_MODEL = "claude-fable-5"
_LINEAGE = "fable"

TRUST_DOMAIN_ID = "018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6"

WORKFLOW_NAME = "boundary-flow"
WORKFLOW_VERSION = 1
WORKFLOW_DEFINITION: dict[str, Any] = {"states": ["open", "done"], "initial": "open"}


# ---------------------------------------------------------------------------
# The corpus builder
# ---------------------------------------------------------------------------


class _Key:
    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        self.signing = SigningKey(
            hashlib.sha256(("boundary/" + principal_id).encode()).digest()
        )
        self.public_key = bytes(self.signing.verify_key)
        self.seed = bytes(self.signing._seed)
        self.key_id = "pk_" + hashlib.sha256(principal_id.encode()).hexdigest()[:16]

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")

    @property
    def fingerprint(self) -> str:
        return "ed25519:sha256:" + hashlib.sha256(self.public_key).hexdigest()


class _Signed:
    """One signed v6 event, with its row projection and its addressing hash."""

    def __init__(self, envelope: dict[str, Any], seed: bytes, global_seq: int) -> None:
        signed = sign_v6_envelope(envelope, seed)
        self.envelope = envelope
        self.canonical_envelope = signed.canonical_envelope
        self.signature = signed.signature
        self.payload_canonical_hash = signed.payload_canonical_hash
        self.event_hash = compute_v6_event_hash(
            signed.canonical_envelope, signed.signature
        )
        self.event_hash_text = "sha256:" + self.event_hash.hex()
        self.global_seq = global_seq

    def row(self, **overrides: Any) -> EventRow:
        env = self.envelope
        workflow = env["workflow"]
        mapping: dict[str, Any] = {
            "event_id": env["event_id"],
            "work_item_id": env["entity"]["id"],
            "entity_kind": env["entity"]["kind"],
            "entity_id": env["entity"]["id"],
            "actor_id": env["actor"]["principal_id"],
            "actor_kind": env["actor"]["kind"],
            "actor_metadata": env["actor"]["metadata"],
            "key_id": env["signing"]["key_id"],
            "event_seq": env["entity_seq"],
            "workflow_name": workflow["name"] if workflow is not None else None,
            "workflow_version": workflow["version"] if workflow is not None else None,
            "timestamp": env["occurred_at"].replace("Z", "+00:00"),
            "hash_alg": env["chain"]["hash_algorithm"],
            "on_behalf_of": None,
            "transition": env["transition"],
            "payload": env["payload"],
            "prev_event_hash": _digest(env["chain"]["previous_entity_event_hash"]),
            "prev_global_event_hash": _digest(
                env["chain"]["previous_project_event_hash"]
            ),
            "global_seq": self.global_seq,
            "canonical_envelope": self.canonical_envelope,
            "signature": self.signature,
            "payload_canonical_hash": self.payload_canonical_hash,
            "scheme_id": "ed25519",
        }
        mapping.update(overrides)
        return EventRow.from_mapping(mapping, backend=Backend.POSTGRES)

    def referent(self) -> ReferentEvent:
        built = referent_from_bytes(self.canonical_envelope, self.signature)
        assert built is not None
        return built


def _digest(value: str | None) -> bytes | None:
    return bytes.fromhex(value.removeprefix("sha256:")) if value is not None else None


def _workflow_definition_hash(definition: dict[str, Any]) -> str:
    from regista._v6_writer import workflow_definition_hash

    return workflow_definition_hash(definition)


class Corpus:
    """A signed v6 project chain, built in memory, with adversarial edits allowed.

    ``add`` links each event to the chain head by ``previous_project_event_hash`` and
    per-entity by ``previous_entity_event_hash``, exactly as the writer does — so a
    chain built here is a chain the verifier's traversal accepts, and the tests that
    *break* one break it deliberately and say which link they broke.
    """

    def __init__(self, *, project_instance_id: str | None = None) -> None:
        self.project_instance_id = project_instance_id or str(uuid.uuid4())
        self.trust_domain_id = TRUST_DOMAIN_ID
        self.keys: dict[str, _Key] = {}
        self.events: list[_Signed] = []
        self.head: str | None = None
        self._entity_heads: dict[tuple[str, str], tuple[str, int]] = {}
        self._seq = 0
        self._clock = 0

    def key(self, principal_id: str) -> _Key:
        return self.keys.setdefault(principal_id, _Key(principal_id))

    def _occurred_at(self) -> str:
        self._clock += 1
        return f"2026-08-18T09:{self._clock // 60:02d}:{self._clock % 60:02d}.000001Z"

    def add(
        self,
        *,
        transition: str,
        entity_kind: str,
        entity_id: str,
        principal_id: str,
        payload: Any,
        anchor: str | None,
        actor_kind: str = "agent",
        workflow: dict[str, Any] | None = None,
        authorization: dict[str, Any] | None = None,
        producer: dict[str, Any] | None = None,
        parent: str | None = None,
        fork_from: str | None = None,
        envelope_edit: Any = None,
    ) -> _Signed:
        """Append a signed event.

        ``fork_from`` sets ``previous_project_event_hash`` to a specific ancestor
        instead of the chain head, and does **not** advance the head. That is how the
        unreachability cases are built, and it is the only construction available: the
        v6 *schema* refuses a null ``previous_project_event_hash`` outside genesis
        (``_validate_v6_object``), so "detach the event from the chain" is not a shape
        a valid v6 envelope can take. A fork is, and a fork is what makes an anchor
        genuinely not-an-ancestor.

        ``parent`` is the same thing but advances the head, for building a second
        branch.
        """
        key = self.key(principal_id)
        entity_key = (entity_kind, entity_id)
        prev_entity, entity_seq = self._entity_heads.get(entity_key, (None, 0))
        self._seq += 1
        envelope: dict[str, Any] = {
            "type": "regista.event",
            "version": 6,
            "project_instance_id": self.project_instance_id,
            "trust_domain_id": self.trust_domain_id,
            "event_id": str(uuid.uuid4()),
            "entity": {"kind": entity_kind, "id": entity_id},
            "entity_seq": entity_seq + 1,
            "actor": {"principal_id": principal_id, "kind": actor_kind, "metadata": {}},
            "signing": {
                "scheme_id": "ed25519",
                "key_id": key.key_id,
                "key_binding_event_hash": anchor,
            },
            "authorization": authorization or {"mode": "direct", "credentials": []},
            "workflow": workflow,
            "occurred_at": self._occurred_at(),
            "transition": transition,
            "payload": payload,
            "chain": {
                "hash_algorithm": "sha-256",
                "previous_entity_event_hash": prev_entity,
                "previous_project_event_hash": (
                    fork_from if fork_from is not None
                    else (parent if parent is not None else self.head)
                ),
            },
            "producer": producer
            or {
                "harness": _HARNESS,
                "harness_version": _HARNESS_VERSION,
                "model": _MODEL,
                "model_lineage": _LINEAGE,
            },
        }
        if envelope_edit is not None:
            envelope_edit(envelope)
        signed = _Signed(envelope, key.seed, self._seq)
        self.events.append(signed)
        if fork_from is None:
            self.head = signed.event_hash_text
        self._entity_heads[entity_key] = (signed.event_hash_text, entity_seq + 1)
        return signed

    # -- the three ceremony steps, as the writer performs them --------------

    def genesis(
        self, *, principal_id: str = BOOTSTRAP, entity_kinds: tuple[str, ...] | None = None
    ) -> _Signed:
        case = json.loads(VECTOR.read_text(encoding="utf-8"))
        payload = copy.deepcopy(case["input"]["envelope_declaration_order"]["payload"])
        key = self.key(principal_id)
        acceptance = payload["bootstrap_key_acceptance"]
        acceptance["principal_id"] = principal_id
        acceptance["key_id"] = key.key_id
        acceptance["scheme_id"] = "ed25519"
        acceptance["public_key"] = key.public_key_b64
        acceptance["fingerprint"] = key.fingerprint
        acceptance["trust_event_hash"] = self.trust_enrolment_hash(principal_id)
        acceptance["scopes"] = {
            "entity_kinds": list(
                entity_kinds or ("project", "principal", "workflow", "work_item")
            ),
            "transitions": None,
            "may_accept_keys": True,
            "may_sign_checkpoints": True,
            "may_sign_bundles": False,
        }
        return self.add(
            transition="project_initialized",
            entity_kind="project",
            entity_id=self.project_instance_id,
            principal_id=principal_id,
            actor_kind="system",
            payload=payload,
            anchor=None,
        )

    def trust_enrolment_hash(self, principal_id: str) -> str:
        """A stable stand-in for the trust-log enrolment event's hash.

        Deliberately *not* resolvable unless a test presents the matching trust-log
        event via :meth:`trust_log_enrolment`, because "the trust log is not
        presented" is the normal case for a project-only verification (§5.10 step 5)
        and the default corpus must reproduce it.
        """

        key = self.key(principal_id)
        return "sha256:" + hashlib.sha256(
            b"boundary-trust-enrolment\x00" + key.public_key
        ).hexdigest()

    def accept(
        self,
        principal_id: str,
        *,
        anchor: str,
        accepted_by: str = BOOTSTRAP,
        entity_kinds: tuple[str, ...] = ("work_item", "principal", "workflow"),
        transitions: tuple[str, ...] | None = None,
        payload_edit: Any = None,
        fork_from: str | None = None,
    ) -> _Signed:
        key = self.key(principal_id)
        accepter = self.key(accepted_by)
        payload: dict[str, Any] = {
            "type": "regista.key-acceptance",
            "version": 1,
            "trust_domain_id": self.trust_domain_id,
            "project_instance_id": self.project_instance_id,
            "principal_id": principal_id,
            "key_id": key.key_id,
            "fingerprint": key.fingerprint,
            "public_key": key.public_key_b64,
            "trust_event_hash": self.trust_enrolment_hash(principal_id),
            "trust_log_checkpoint": {
                "checkpoint_seq": 1,
                "head_event_hash": "sha256:" + "0c" * 32,
                "document_digest": "sha256:" + "0d" * 32,
            },
            "scopes": {
                "entity_kinds": list(entity_kinds),
                "transitions": None if transitions is None else list(transitions),
                "may_sign_checkpoints": False,
                "may_sign_bundles": False,
            },
            "accepted_by": {
                "principal_id": accepted_by,
                "key_id": accepter.key_id,
                "key_binding_event_hash": anchor,
            },
        }
        if payload_edit is not None:
            payload_edit(payload)
        return self.add(
            transition="principal_key_accepted",
            entity_kind="principal",
            entity_id=str(uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal_id)),
            principal_id=accepted_by,
            actor_kind="system",
            payload=payload,
            anchor=anchor,
            fork_from=fork_from,
        )

    def revoke_acceptance(
        self, acceptance: _Signed, *, principal_id: str, anchor: str
    ) -> _Signed:
        target_principal = acceptance.envelope["payload"]["principal_id"]
        return self.add(
            transition="principal_key_acceptance_revoked",
            entity_kind="principal",
            entity_id=str(
                uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + target_principal)
            ),
            principal_id=principal_id,
            actor_kind="system",
            payload={
                "type": "regista.key-acceptance-revocation",
                "version": 1,
                "trust_domain_id": self.trust_domain_id,
                "project_instance_id": self.project_instance_id,
                "principal_id": target_principal,
                "key_id": acceptance.envelope["payload"]["key_id"],
                "acceptance_event_hash": acceptance.event_hash_text,
                "reason": "compromised",
                "revoked_by": {
                    "principal_id": principal_id,
                    "key_id": self.key(principal_id).key_id,
                    "key_binding_event_hash": anchor,
                },
            },
            anchor=anchor,
        )

    def register_workflow(
        self,
        *,
        anchor: str,
        principal_id: str = BOOTSTRAP,
        name: str = WORKFLOW_NAME,
        version: int = WORKFLOW_VERSION,
        definition: dict[str, Any] | None = None,
        fork_from: str | None = None,
    ) -> _Signed:
        body = definition if definition is not None else WORKFLOW_DEFINITION
        return self.add(
            transition="workflow_registered",
            entity_kind="workflow",
            entity_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_OID,
                    f"regista.workflow:{self.project_instance_id}:{name}:{version}",
                )
            ),
            principal_id=principal_id,
            actor_kind="system",
            payload={
                "type": "regista.workflow-registration",
                "version": 1,
                "name": name,
                "workflow_version": version,
                "definition": body,
                "definition_hash": _workflow_definition_hash(body),
                "supersedes_registration_event_hash": None,
            },
            anchor=anchor,
            fork_from=fork_from,
        )

    def trust_log_enrolment(self, principal_id: str) -> ReferentEvent:
        """A trust-log ``principal_key_enrolled`` addressed by the hash the acceptance names.

        The trust log is a **separate project chain** (§5.2), so this is presented as
        an extra referent rather than appended to this corpus's chain: the two chains
        have no mutual order except through a checkpoint reference (§6.6), and mixing
        them into one chain is exactly the topology bug NOTES-P17 Finding 4 records.

        The addressing hash is forced to the value the acceptance already committed
        to. That is legitimate here and only here: a real trust-log event's hash is
        what the acceptance is built *from*, and the corpus builds them in the
        opposite order. Nothing else in this file constructs a referent by hand.
        """

        key = self.key(principal_id)
        envelope: dict[str, Any] = {
            "type": "regista.event",
            "version": 6,
            "project_instance_id": str(uuid.uuid5(uuid.NAMESPACE_OID, "trust-log")),
            "trust_domain_id": self.trust_domain_id,
            "event_id": str(uuid.uuid4()),
            "entity": {"kind": "principal", "id": str(uuid.uuid4())},
            "entity_seq": 1,
            "actor": {"principal_id": "human:root", "kind": "human", "metadata": {}},
            "signing": {
                "scheme_id": "ed25519",
                "key_id": self.key("human:root").key_id,
                # The trust-log genesis is the binding anchor for subsequent
                # root-authorised trust-log events (RECONCILIATION.md Resolution 1).
                # Non-null, because only the three bootstrap transitions may be null
                # and an enrolment is not one.
                "key_binding_event_hash": "sha256:" + "0c" * 32,
            },
            "authorization": {"mode": "direct", "credentials": []},
            "workflow": None,
            "occurred_at": "2026-08-18T08:00:00.000001Z",
            "transition": "principal_key_enrolled",
            "payload": {
                "type": "regista.key-enrolment",
                "version": 1,
                "principal_id": principal_id,
                "key_id": key.key_id,
                "fingerprint": key.fingerprint,
                "public_key": key.public_key_b64,
            },
            "chain": {
                "hash_algorithm": "sha-256",
                "previous_entity_event_hash": None,
                # The trust log's own genesis. Non-null because the v6 schema limits a
                # null project-chain predecessor to a genesis transition, and an
                # enrolment is not one — the trust log has a `trust_domain_established`
                # root of its own (§5.2), which this stands in for.
                "previous_project_event_hash": "sha256:" + "0c" * 32,
            },
            "producer": {
                "harness": _HARNESS,
                "harness_version": _HARNESS_VERSION,
                "model": None,
                "model_lineage": None,
            },
        }
        signed = _Signed(envelope, self.key("human:root").seed, 0)
        return ReferentEvent(
            event_hash=self.trust_enrolment_hash(principal_id),
            envelope=signed.envelope,
        )

    # -- presentation ------------------------------------------------------

    def resolver(self, principal_id: str | None = None) -> StaticKeyResolver:
        """A trusted key for one principal, from a keyset file (never the projection)."""

        if principal_id is None:
            keys = {k.key_id: k for k in self.keys.values()}

            class _Multi:
                def resolve(self, key_id: str | None):
                    from regista._verification import TrustedKey

                    entry = keys.get(key_id or "")
                    if entry is None:
                        return None
                    return TrustedKey(
                        key_id=entry.key_id,
                        material=entry.public_key,
                        scheme_id="ed25519",
                        source=TrustedKeySource.KEYSET_FILE,
                        principal_id=entry.principal_id,
                    )

            return _Multi()  # type: ignore[return-value]
        key = self.key(principal_id)
        return StaticKeyResolver(
            material=key.public_key,
            scheme_id="ed25519",
            key_id=key.key_id,
            source=TrustedKeySource.KEYSET_FILE,
            principal_id=key.principal_id,
        )

    def material(
        self,
        *,
        completeness: MaterialCompleteness = MaterialCompleteness.COMPLETE_STORE,
        omit: tuple[_Signed, ...] = (),
        extra: tuple[ReferentEvent, ...] = (),
        label: str = "corpus",
    ) -> MappingReferents:
        omitted = {e.event_hash_text for e in omit}
        events = {
            e.event_hash_text: e.referent()
            for e in self.events
            if e.event_hash_text not in omitted
        }
        for referent in extra:
            events[referent.event_hash] = referent
        return MappingReferents(
            events=events, material_completeness=completeness, label=label
        )


def verify(
    event: _Signed,
    corpus: Corpus,
    *,
    material: Any = None,
    policy: VerificationPolicy | None = None,
    row: EventRow | None = None,
) -> VerificationResult:
    return verify_event_strict(
        row if row is not None else event.row(),
        keys=corpus.resolver(),
        referents=material if material is not None else corpus.material(),
        policy=policy or VerificationPolicy(),
    )


@pytest.fixture
def healthy() -> tuple[Corpus, _Signed, _Signed]:
    """Genesis → workflow registration → acceptance → an ordinary work-item event."""

    corpus = Corpus()
    genesis = corpus.genesis()
    corpus.register_workflow(anchor=genesis.event_hash_text)
    acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
    ordinary = corpus.add(
        transition="created",
        entity_kind="work_item",
        entity_id=str(uuid.uuid4()),
        principal_id=WORKER,
        payload={"initial_state": "open"},
        anchor=acceptance.event_hash_text,
    )
    return corpus, genesis, ordinary


# ---------------------------------------------------------------------------
# The positive case, which is the whole point
# ---------------------------------------------------------------------------


class TestAHealthyChainIsFullyAuthenticated:
    """The clamp's replacement has to *pass* something, or it is a second clamp.

    NOTES-P17 Finding 8 measured the cost of the clamp precisely: ``_replay`` verifies
    every event through ``verify_event_strict``, so a correctly migrated fixture
    reported ``halted=1`` on a perfectly good chain. These assertions are what make
    that stop being true.
    """

    def test_an_ordinary_post_genesis_event_is_fully_authenticated(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert result.ok is True
        assert result.accepted is True
        assert result.reasons == ()
        assert result.key_binding is KeyBinding.ACCEPTED_IN_PROJECT
        assert result.attribution is Attribution.INDIVIDUAL
        assert result.epoch_position is EpochPosition.POST_CUTOVER
        assert result.trust_domain_id == corpus.trust_domain_id
        assert result.envelope_version is EnvelopeVersion.V6

    def test_no_v6_verdict_carries_the_clamp_reason(self, healthy) -> None:
        """``ENVELOPE_SCHEMA_INCOMPLETE`` was the clamp, and it is not a verdict.

        Asserted as a property of the *whole* corpus rather than of one event, because
        the clamp's defining feature was that it applied to every v6 row.
        """

        corpus, _genesis, _ordinary = healthy
        for event in corpus.events:
            result = verify(event, corpus)
            assert FailureReason.ENVELOPE_SCHEMA_INCOMPLETE not in result.reasons, (
                f"{event.envelope['transition']}: {result.summary()}"
            )

    def test_the_trust_root_is_bundled_only_when_no_trust_log_is_presented(
        self, healthy
    ) -> None:
        """§5.10 step 5 / §5.8. The key bytes are here; the authority to believe them
        is not — and ``bundled_only`` is deliberately not ``absent``, because the
        acceptance repeats ``public_key`` on purpose."""

        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus)
        assert result.trust_root is TrustRoot.BUNDLED_ONLY
        assert result.revocation_status is RevocationStatus.UNKNOWN
        # An unchecked revocation state is REPORTED, never assumed (§10.2 inv. 9).
        assert "trust_log_revocation" in result.unbound_properties
        assert "external_trust_pin" in result.unbound_properties

    def test_presenting_the_trust_log_raises_the_trust_root_to_trust_log_only(
        self, healthy
    ) -> None:
        corpus, _genesis, ordinary = healthy
        material = corpus.material(extra=(corpus.trust_log_enrolment(WORKER),))
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert result.trust_root is TrustRoot.TRUST_LOG_ONLY
        assert result.revocation_status is RevocationStatus.NOT_REVOKED
        assert "trust_log_revocation" not in result.unbound_properties

    def test_the_trust_log_plus_a_pinned_domain_is_externally_pinned(self, healthy) -> None:
        """§5.8: "with the trust log **and** the pin it reports ``externally_pinned``."

        Both conditions, not either — a pin over material with no lifecycle evidence
        does not manufacture an external root, which the next test pins.
        """

        corpus, _genesis, ordinary = healthy
        material = corpus.material(extra=(corpus.trust_log_enrolment(WORKER),))
        result = verify(
            ordinary,
            corpus,
            material=material,
            policy=VerificationPolicy(pinned_trust_domain_id=corpus.trust_domain_id),
        )
        assert result.trust_root is TrustRoot.EXTERNALLY_PINNED
        assert result.applicability is Applicability.FULLY_AUTHENTICATED

    def test_a_pin_without_the_trust_log_stays_bundled_only(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(pinned_trust_domain_id=corpus.trust_domain_id),
        )
        assert result.trust_root is TrustRoot.BUNDLED_ONLY

    def test_the_workflow_referent_resolves_for_a_workflow_bearing_event(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        registration = corpus.register_workflow(anchor=genesis.event_hash_text)
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={"initial_state": "open"},
            anchor=acceptance.event_hash_text,
            workflow={
                "name": WORKFLOW_NAME,
                "version": WORKFLOW_VERSION,
                "definition_hash": _workflow_definition_hash(WORKFLOW_DEFINITION),
                "registration_event_hash": registration.event_hash_text,
            },
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()


# ---------------------------------------------------------------------------
# §5.11 — the exhaustive no-fallback verdict table
# ---------------------------------------------------------------------------


class TestSection511VerdictTable:
    """One test per row of §5.11's table, which is "specified exhaustively" because
    "this is the case implementations get wrong by falling back"."""

    def test_row1_absent_anchor_with_no_completeness_claim_is_unverifiable(
        self, healthy
    ) -> None:
        """Row 1: absence of evidence. "The signature may well be fine; the verifier
        cannot say." UNVERIFIABLE, never INVALID."""

        corpus, _genesis, ordinary = healthy
        anchor = corpus.events[2]
        material = corpus.material(
            completeness=MaterialCompleteness.CONTIGUOUS_RANGE, omit=(anchor,)
        )
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        assert FailureReason.KEY_BINDING_UNRESOLVED in result.reasons
        assert result.key_binding is KeyBinding.UNRESOLVED
        assert result.accepted is False

    def test_row2_absent_anchor_in_complete_material_is_invalid(self, healthy) -> None:
        """Row 2: "The completeness claim is false. That is a fact about the artifact,
        not an absence." """

        corpus, _genesis, ordinary = healthy
        anchor = corpus.events[2]
        material = corpus.material(
            completeness=MaterialCompleteness.COMPLETE_STORE, omit=(anchor,)
        )
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE in result.reasons
        assert "completeness claim is false" in (result.detail or "")

    def test_row3_anchor_that_is_not_an_acceptance_is_invalid(self, healthy) -> None:
        """Row 3, first limb: contradicted evidence — the hash resolves to the wrong
        KIND of event."""

        corpus, _genesis, _ordinary = healthy
        registration = corpus.events[1]  # workflow_registered, not an acceptance
        event = corpus.add(
            transition="updated",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=registration.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons
        assert result.key_binding is KeyBinding.MISMATCHED

    def test_row3_anchor_for_a_different_principal_is_invalid(self) -> None:
        """Row 3, second limb: the anchor is a real acceptance, for someone else.

        This is the check that stops "there is an acceptance in this project" from
        being read as "this key was accepted".
        """

        corpus = Corpus()
        genesis = corpus.genesis()
        others_acceptance = corpus.accept(OUTSIDER, anchor=genesis.event_hash_text)
        # WORKER signs, but names the OUTSIDER's acceptance as its authority.
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=others_acceptance.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons

    def test_row3_anchor_from_a_different_project_is_invalid(self, healthy) -> None:
        """Row 3, third limb: ``A.project_instance_id == P`` (§5.10 step 2).

        A validly signed acceptance from another project is presented — cross-project
        anchor reuse — and it is refused on the project binding, not on the signature.
        """

        corpus, _genesis, _ordinary = healthy
        foreign = Corpus()
        foreign.keys = corpus.keys  # same key material, different project
        foreign_genesis = foreign.genesis()
        foreign_acceptance = foreign.accept(WORKER, anchor=foreign_genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=foreign_acceptance.event_hash_text,
        )
        material = corpus.material(extra=(foreign_acceptance.referent(),))
        result = verify(event, corpus, material=material)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons

    def test_row4_an_anchor_that_does_not_precede_the_event_is_invalid(self) -> None:
        """Row 4 / §9 criterion 14 — see :class:`TestCriterion14` for the criterion's
        own statement of it. Kept here too so the table reads as a table."""

        corpus = Corpus()
        genesis = corpus.genesis()
        # The acceptance is on the chain; the event forks from genesis, so the
        # acceptance is a SIBLING and not an ancestor.
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            fork_from=genesis.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.ENROLLMENT_AFTER_USE in result.reasons

    def test_row5_a_pre_cutover_legacy_event_is_untouched_by_this_boundary(self) -> None:
        """Row 5 is *legacy* semantics and is reached only by the v4/v5 path.

        Asserted as an absence: the v6 boundary must not have changed what a v4 or v5
        event reports. The full legacy-epoch reclassification (``RESULT-MODEL.md``
        §10.2 invariants 2, 3 and 7 — the ~334,000-event story) is cutover work and is
        deliberately NOT in this change; this test pins that the v6 work left the
        legacy verdicts where they were.
        """

        from regista._signing import sign_event

        key = b"k" * 32
        event_id, work_item_id = uuid.uuid4(), uuid.uuid4()
        from datetime import UTC, datetime

        signature, payload_canonical_hash, canonical_envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="agent-legacy",
            key_id="legacy-key",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            transition="created",
            payload={"a": 1},
            key=key,
            actor_kind="agent",
            actor_metadata={},
        )
        row = EventRow.from_mapping(
            {
                "event_id": event_id,
                "work_item_id": work_item_id,
                "entity_kind": "work_item",
                "entity_id": work_item_id,
                "actor_id": "agent-legacy",
                "actor_kind": "agent",
                "actor_metadata": {},
                "key_id": "legacy-key",
                "event_seq": 1,
                "workflow_name": "wf",
                "workflow_version": 1,
                "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
                "hash_alg": "sha-256",
                "on_behalf_of": None,
                "transition": "created",
                "payload": {"a": 1},
                "prev_event_hash": None,
                "prev_global_event_hash": None,
                "global_seq": 1,
                "canonical_envelope": canonical_envelope,
                "signature": signature,
                "payload_canonical_hash": payload_canonical_hash,
                "scheme_id": "hmac-sha256",
            }
        )
        result = verify_event_strict(
            row,
            keys=StaticKeyResolver(material=key, scheme_id="hmac-sha256"),
            referents=NO_REFERENTS,
        )
        assert result.envelope_version is EnvelopeVersion.V5
        assert result.applicability is Applicability.FULLY_AUTHENTICATED
        # The v6 vocabulary is present and says "not established", never "checked".
        assert result.key_binding is KeyBinding.UNRESOLVED
        assert result.trust_root is TrustRoot.ABSENT
        assert result.epoch_position is EpochPosition.UNKNOWN

    def test_row7_a_principal_keys_row_is_never_consulted_for_a_v6_event(
        self, healthy
    ) -> None:
        """Row 7, "the one that matters": the projection is **irrelevant**, and §5.9
        rule 1 makes resolving through it "a programming error [that] raises".

        Asserted as a raise rather than as a verdict, because a verdict is something a
        caller can learn to tolerate.
        """

        from regista._errors import RegistaError

        corpus, _genesis, ordinary = healthy
        key = corpus.key(WORKER)
        registry = StaticKeyResolver(
            material=key.public_key,
            scheme_id="ed25519",
            key_id=key.key_id,
            source=TrustedKeySource.PRINCIPAL_REGISTRY,
            principal_id=key.principal_id,
        )
        with pytest.raises(RegistaError, match=re.escape("§5.9 rule 1")):
            verify_event_strict(
                ordinary.row(),
                keys=registry,
                referents=corpus.material(),
            )


# ---------------------------------------------------------------------------
# §5.10 — each of the six steps falsified once
# ---------------------------------------------------------------------------


class TestSection510EachStepFalsified:
    """§5.10 is a six-step decision procedure. A step no test can falsify is a step
    that might not be running."""

    def test_step1_the_anchor_hash_must_resolve_within_the_material(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus, material=NO_REFERENTS)
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.KEY_BINDING_UNRESOLVED in result.reasons

    def test_step1_a_tampered_anchor_stops_resolving_rather_than_resolving_differently(
        self, healthy
    ) -> None:
        """The addressing property, asserted directly: referents are addressed by the
        v6 event hash over ``envelope || signature``, so an edited anchor answers to a
        different name and the referring event's hash no longer finds it."""

        corpus, _genesis, ordinary = healthy
        acceptance = corpus.events[2]
        tampered_envelope = copy.deepcopy(acceptance.envelope)
        tampered_envelope["payload"]["scopes"]["entity_kinds"] = ["project"]
        tampered = _Signed(tampered_envelope, corpus.key(BOOTSTRAP).seed, 99)
        assert tampered.event_hash_text != acceptance.event_hash_text
        material = corpus.material(omit=(acceptance,), extra=(tampered.referent(),))
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE in result.reasons

    def test_step2_the_anchor_must_hold_scope_for_this_entity_kind(self) -> None:
        """§5.8's scopes, from the verifier's side. The writer refuses an out-of-scope
        append; a verifier that did not ask would accept an artifact the writer would
        never have produced."""

        corpus = Corpus()
        genesis = corpus.genesis()
        narrow = corpus.accept(
            WORKER, anchor=genesis.event_hash_text, entity_kinds=("work_item",)
        )
        event = corpus.add(
            transition="principal_registered",
            entity_kind="principal",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=narrow.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons
        assert "entity_kind" in (result.detail or "")

    def test_step2_the_anchor_must_hold_scope_for_this_transition(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        narrow = corpus.accept(
            WORKER, anchor=genesis.event_hash_text, transitions=("created",)
        )
        event = corpus.add(
            transition="claim_acquired",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=narrow.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons
        assert "transition" in (result.detail or "")

    def test_step2_an_unscoped_acceptance_is_refused_not_read_as_unlimited(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()

        def drop_scopes(payload: dict[str, Any]) -> None:
            payload["scopes"] = None

        unscoped = corpus.accept(
            WORKER, anchor=genesis.event_hash_text, payload_edit=drop_scopes
        )
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=unscoped.event_hash_text,
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons
        assert "unscoped acceptance is refused" in (result.detail or "")

    def test_step3_ordering_is_by_chain_traversal_and_not_by_occurred_at(self) -> None:
        """§5.10 step 3 names the two things ordering must NOT come from. This builds a
        history where they disagree with the chain and asserts the chain wins.

        The acceptance is stamped **later** than the event that uses it while being
        **earlier** on the chain. If ``occurred_at`` decided, this would be
        ``ENROLLMENT_AFTER_USE``; it is fully authenticated, because ``occurred_at`` is
        a signed actor claim and not an order.
        """

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        acceptance.envelope["occurred_at"] = "2026-12-31T23:59:59.000001Z"
        # Re-sign so the late timestamp is genuinely signed, then re-point the chain.
        resigned = _Signed(acceptance.envelope, corpus.key(BOOTSTRAP).seed, 2)
        corpus.events[-1] = resigned
        corpus.head = resigned.event_hash_text
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=resigned.event_hash_text,
        )
        assert event.envelope["occurred_at"] < resigned.envelope["occurred_at"]
        result = verify(event, corpus)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()

    def test_step3_ordering_is_not_by_global_seq(self) -> None:
        """The same, for the other forbidden input. ``global_seq`` is unsigned by
        design, so an attacker with row-write access can move an event across any
        watermark — which is exactly why it may not decide this."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        # The row claims a global_seq BELOW its own anchor's. The chain is unchanged.
        row = event.row(global_seq=1)
        result = verify(event, corpus, row=row)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()

    def test_step4_a_revoked_acceptance_between_a_and_e_is_invalid(self) -> None:
        """§5.10 step 4. The revocation lies *between* the acceptance and the use, so
        the use is refused — and the acceptance itself, which precedes the revocation,
        is not."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        corpus.revoke_acceptance(
            acceptance, principal_id=BOOTSTRAP, anchor=genesis.event_hash_text
        )
        after = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        result = verify(after, corpus)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_ACCEPTANCE_REVOKED in result.reasons

    def test_step4_the_reported_revocation_status_matches_what_was_found(self) -> None:
        """A verdict that found a revocation may not report ``revocation_status:
        unknown``. Step 4 and step 6 answer the same question from different material,
        and an internally inconsistent report is worse than a missing one."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        corpus.revoke_acceptance(
            acceptance, principal_id=BOOTSTRAP, anchor=genesis.event_hash_text
        )
        after = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        result = verify(after, corpus)
        assert result.revocation_status is RevocationStatus.REVOKED_BEFORE_USE
        assert result.applicability is Applicability.INVALID
        assert "revocation=revoked_before_use" in result.summary()

    def test_an_event_whose_epoch_root_is_absent_is_unverifiable(self) -> None:
        """``EPOCH-RESET.md`` §5.1: membership of the clean epoch is a fact about the
        chain behind an event. Material that does not present the epoch root cannot
        establish it — and this was found the hard way, as a crash: the class invariant
        forbids ``FULLY_AUTHENTICATED`` with ``epoch_position=unknown``, so without an
        explicit finding here a windowed export raised an ``AssertionError`` from
        ``__post_init__`` instead of returning a verdict."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        window = corpus.material(
            completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
            omit=(genesis,),
            label="contiguous-range window starting after genesis",
        )
        result = verify(event, corpus, material=window)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        assert result.epoch_position is EpochPosition.UNKNOWN
        assert result.checkpoint_binding is CheckpointBinding.UNBOUND
        assert FailureReason.EPOCH_VIOLATION in result.reasons
        assert "cutover_checkpoint" in result.unbound_properties

    def test_step4_an_event_before_the_revocation_is_unaffected(self) -> None:
        """Revocation is **prospective by chain position** (§5.7), so an event that
        precedes it stays valid. A revocation that retroactively invalidated history
        would be a different and much worse contract."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        before = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        corpus.revoke_acceptance(
            acceptance, principal_id=BOOTSTRAP, anchor=genesis.event_hash_text
        )
        result = verify(before, corpus)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()

    def test_step5_a_trust_log_enrolment_for_the_wrong_key_is_invalid(self, healthy) -> None:
        """§5.8: "Mismatch between this ``public_key`` and the enrolment event's is
        **invalid**, not a preference." """

        corpus, _genesis, ordinary = healthy
        enrolment = corpus.trust_log_enrolment(WORKER)
        wrong = copy.deepcopy(dict(enrolment.envelope))
        wrong["payload"] = dict(wrong["payload"])
        wrong["payload"]["public_key"] = base64.b64encode(b"\x01" * 32).decode("ascii")
        material = corpus.material(
            extra=(ReferentEvent(event_hash=enrolment.event_hash, envelope=wrong),)
        )
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons

    def test_step5_a_trust_event_hash_naming_a_non_enrolment_is_invalid(
        self, healthy
    ) -> None:
        corpus, _genesis, ordinary = healthy
        enrolment = corpus.trust_log_enrolment(WORKER)
        # Same addressing hash, but the event is a workflow registration.
        impostor = ReferentEvent(
            event_hash=enrolment.event_hash,
            envelope=corpus.events[1].envelope,
        )
        result = verify(ordinary, corpus, material=corpus.material(extra=(impostor,)))
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_BINDING_MISMATCH in result.reasons

    def test_step6_revocation_status_is_named_not_assumed_when_unchecked(
        self, healthy
    ) -> None:
        """§10.2 invariant 9: "A check is never silently skipped because its input was
        absent." The revocation check's input is the trust log, and when it is absent
        the result says ``unknown`` **and** names the gap."""

        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus)
        assert result.revocation_status is RevocationStatus.UNKNOWN
        assert "trust_log_revocation" in result.unbound_properties
        assert "unbound=" in result.summary()


# ---------------------------------------------------------------------------
# RECONCILIATION.md Resolution 1 — the three permitted nulls
# ---------------------------------------------------------------------------


class TestResolution1PermittedNulls:
    """"No other null is accepted. A null on any other event is
    ``INVALID/KEY_BINDING_BOOTSTRAP_NOT_PERMITTED``." """

    def test_the_genesis_null_is_permitted_and_reports_bootstrap_external(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        result = verify(genesis, corpus)
        assert result.key_binding is KeyBinding.BOOTSTRAP_EXTERNAL
        assert result.epoch_position is EpochPosition.IS_CUTOVER
        assert FailureReason.KEY_BINDING_BOOTSTRAP_NOT_PERMITTED not in result.reasons

    def test_an_unpinned_bootstrap_event_is_unverifiable_not_fully_authenticated(
        self,
    ) -> None:
        """Resolution 1: "Bootstrap without an external pin is not a bootstrap; it is
        an unauthenticated first event."

        The verdict is UNVERIFIABLE, not INVALID: nothing failed and nothing was
        contradicted — the pin was never supplied. The distinction is the operator's
        whole response, and ``unbound_properties`` names what is missing.
        """

        corpus = Corpus()
        genesis = corpus.genesis()
        result = verify(genesis, corpus)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        assert result.signature_valid is True
        assert result.row_reconciled is True
        assert "external_trust_pin" in result.unbound_properties
        assert "unauthenticated first event" in (result.detail or "")

    def test_a_pinned_bootstrap_event_with_the_trust_log_is_fully_authenticated(
        self,
    ) -> None:
        """The other half: supply what Resolution 1 asks for and the bootstrap event
        authenticates. Without this, "bootstrap is never fully authenticated" would be
        a clamp wearing an invariant's clothes."""

        corpus = Corpus()
        genesis = corpus.genesis()
        material = corpus.material(extra=(corpus.trust_log_enrolment(BOOTSTRAP),))
        result = verify(
            genesis,
            corpus,
            material=material,
            policy=VerificationPolicy(
                pinned_trust_domain_id=corpus.trust_domain_id,
                cutover_checkpoint_event_hash=genesis.event_hash_text,
            ),
        )
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert result.key_binding is KeyBinding.BOOTSTRAP_EXTERNAL
        assert result.trust_root is TrustRoot.EXTERNALLY_PINNED
        assert result.checkpoint_binding is CheckpointBinding.EXTERNALLY_PINNED

    def test_a_null_binding_on_an_ordinary_transition_is_refused_at_ingress(self) -> None:
        """"No other null is accepted." Where that is enforced, measured rather than
        assumed.

        The v6 **schema** validator (``_validate_v6_object``) already refuses a null
        ``signing.key_binding_event_hash`` outside the three bootstrap transitions, and
        it runs *before* the boundary. So the reason code Resolution 1 names is not what
        an ordinary null produces through ``verify_event_strict`` — the envelope never
        parses. That is the right architecture (fail at ingress, not at verdict) and it
        is worth pinning, because a reader of the boundary code would otherwise expect
        ``KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`` here and conclude the check is dead.

        Both halves are asserted: the schema's refusal by name, and the verdict a row
        carrying such bytes actually gets.
        """

        from regista._verification import (
            V6EnvelopeError,
            validate_v6_envelope,
        )

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        good = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
        )
        nulled = copy.deepcopy(good.envelope)
        nulled["signing"]["key_binding_event_hash"] = None
        with pytest.raises(
            V6EnvelopeError, match="null key binding is permitted only for a bootstrap"
        ):
            validate_v6_envelope(nulled)

        # And through the primitive: INVALID, on the envelope, above the boundary.
        forged = _Signed.__new__(_Signed)
        from regista._jcs import canonicalize

        forged.envelope = nulled
        forged.canonical_envelope = canonicalize(nulled)
        from regista._signing import v6_signature_input
        from regista._signing_scheme import Ed25519Scheme

        sig, pch = Ed25519Scheme().sign(
            v6_signature_input(forged.canonical_envelope), corpus.key(WORKER).seed
        )
        forged.signature = sig
        forged.payload_canonical_hash = pch
        forged.event_hash = compute_v6_event_hash(forged.canonical_envelope, sig)
        forged.event_hash_text = "sha256:" + forged.event_hash.hex()
        forged.global_seq = 99
        result = verify(forged, corpus)
        assert result.applicability is Applicability.INVALID
        assert result.envelope_schema_valid is False
        assert FailureReason.ENVELOPE_UNKNOWN_SCHEMA in result.reasons

    def test_a_bootstrap_null_with_a_v6_ancestor_is_not_permitted(self) -> None:
        """Resolution 1's table pins **position**, and the position test is "no v6 event
        precedes this one" — not "the predecessor link is null".

        The distinction is load-bearing and getting it wrong would have broken the
        legacy-project path: ``project_cryptographic_epoch_started`` is the "unique
        first v6 event in a legacy project" and its ``previous_project_event_hash``
        names the **legacy** (v5) project head, which is non-null and which never
        resolves as a v6 referent. So a cutover checkpoint whose predecessor *does*
        resolve to a v6 event has borrowed the bootstrap exemption mid-epoch, and that
        is the reachable form of ``KEY_BINDING_BOOTSTRAP_NOT_PERMITTED``.
        """

        # Built as the topology NOTES-P17 Finding 4 records as a real defect: a
        # trust-log genesis event sitting in a PROJECT chain, with a cutover checkpoint
        # chained onto it. The v6 schema permits each event individually (the cutover's
        # predecessor link is non-null, as a real cutover's is, and its entity sequence
        # is 1), so this is the shape the boundary has to catch rather than the parser.
        corpus = Corpus()
        trust_genesis = corpus.add(
            transition="trust_domain_established",
            entity_kind="trust_domain",
            entity_id=corpus.trust_domain_id,
            principal_id="human:root",
            actor_kind="human",
            payload={"trust_domain_core_digest": "sha256:" + "0a" * 32},
            anchor=None,
        )
        second_bootstrap = corpus.add(
            transition="project_cryptographic_epoch_started",
            entity_kind="project",
            entity_id=corpus.project_instance_id,
            principal_id=BOOTSTRAP,
            actor_kind="system",
            payload={"bootstrap_key_acceptance": {"principal_id": BOOTSTRAP}},
            anchor=None,
        )
        genesis = trust_genesis
        result = verify(second_bootstrap, corpus)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.KEY_BINDING_BOOTSTRAP_NOT_PERMITTED in result.reasons
        assert "not the first v6 event" in (result.detail or "")
        assert genesis.event_hash_text in (result.detail or "")

    def test_a_real_cutover_checkpoint_keeps_its_exemption(self) -> None:
        """The other side of the same rule, because a check that refuses the legitimate
        case is worse than no check. A cutover whose predecessor is a v5 head (absent
        from v6 material) is a bootstrap event and reports ``bootstrap_external``."""

        corpus = Corpus()
        cutover = corpus.add(
            transition="project_cryptographic_epoch_started",
            entity_kind="project",
            entity_id=corpus.project_instance_id,
            principal_id=BOOTSTRAP,
            actor_kind="system",
            payload={"bootstrap_key_acceptance": {"principal_id": BOOTSTRAP}},
            anchor=None,
            # The legacy project head: a v5 event hash. Non-null, unresolvable as v6.
            fork_from="sha256:" + "5" * 64,
        )
        result = verify(cutover, corpus)
        assert result.key_binding is KeyBinding.BOOTSTRAP_EXTERNAL, result.summary()
        assert result.epoch_position is EpochPosition.IS_CUTOVER
        assert FailureReason.KEY_BINDING_BOOTSTRAP_NOT_PERMITTED not in result.reasons


# ---------------------------------------------------------------------------
# §9 criteria 14 and 15
# ---------------------------------------------------------------------------


class TestCriterion14:
    """"A v6 event whose ``key_binding_event_hash`` names an acceptance later in the
    chain is ``INVALID`` with ``ENROLLMENT_AFTER_USE``." """

    def test_an_acceptance_later_in_the_chain_is_invalid_with_enrollment_after_use(
        self,
    ) -> None:
        """The construction, and why it is the only one available.

        An event cannot literally *name* an acceptance that comes after it: the anchor
        is a hash of the acceptance's own bytes, and those bytes commit to their chain
        position, so a genuinely-later acceptance has a hash the earlier event could
        not have known. What criterion 14 is therefore about — and what the verifier
        must decide — is **reachability**: the named acceptance is not among the
        event's ancestors.

        Built here as a chain that continues past the event and only then reaches the
        acceptance, which is "later in the chain" in the only sense a hash chain has.
        """

        corpus = Corpus()
        genesis = corpus.genesis()
        early = corpus.accept(
            OUTSIDER, anchor=genesis.event_hash_text
        )  # something to extend the chain with
        # The event forks from genesis. The chain then continues from `early` to
        # WORKER's acceptance, so that acceptance is strictly later in the chain than
        # the event that names it, and is not an ancestor of it.
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor="sha256:" + "00" * 32,  # replaced below
            fork_from=genesis.event_hash_text,
        )
        later = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        assert later.global_seq > event.global_seq
        assert early.event_hash_text in {e.event_hash_text for e in corpus.events}

        # Re-sign the event so it names the real (later) acceptance.
        edited = copy.deepcopy(event.envelope)
        edited["signing"]["key_binding_event_hash"] = later.event_hash_text
        renamed = _Signed(edited, corpus.key(WORKER).seed, event.global_seq)
        corpus.events = [e for e in corpus.events if e is not event] + [renamed]

        result = verify(renamed, corpus)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.ENROLLMENT_AFTER_USE in result.reasons
        assert result.key_binding is KeyBinding.AFTER_USE
        assert "does not precede the use it authorises" in (result.detail or "")

    def test_the_verdict_names_criterion_14s_own_section(self) -> None:
        """The report has to be readable by whoever is holding the spec."""

        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            fork_from=genesis.event_hash_text,
        )
        detail = verify(event, corpus).detail or ""
        assert "§5.10 step 3" in detail
        assert "criterion 14" in detail


class TestCriterion15:
    """"A v6 event whose acceptance is absent from a ``complete-store`` bundle is
    ``INVALID``; the same event absent from a ``contiguous-range`` bundle is
    ``UNVERIFIABLE``, with the missing acceptance named as outside scope." """

    @pytest.fixture
    def missing_acceptance(self, healthy):
        corpus, _genesis, ordinary = healthy
        acceptance = corpus.events[2]
        return corpus, ordinary, acceptance

    def test_absent_from_complete_store_is_invalid(self, missing_acceptance) -> None:
        corpus, ordinary, acceptance = missing_acceptance
        material = corpus.material(
            completeness=MaterialCompleteness.COMPLETE_STORE,
            omit=(acceptance,),
            label="complete-store bundle",
        )
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE in result.reasons

    def test_absent_from_contiguous_range_is_unverifiable_and_names_the_acceptance(
        self, missing_acceptance
    ) -> None:
        corpus, ordinary, acceptance = missing_acceptance
        material = corpus.material(
            completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
            omit=(acceptance,),
            label="contiguous-range bundle",
        )
        result = verify(ordinary, corpus, material=material)
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.KEY_BINDING_UNRESOLVED in result.reasons
        detail = result.detail or ""
        # "with the missing acceptance named as outside scope" — the hash and the
        # scope both, or an auditor cannot act on it.
        assert acceptance.event_hash_text in detail
        assert "outside the scope" in detail
        assert "contiguous-range bundle" in detail
        assert "key_binding" in result.unbound_properties

    def test_the_two_verdicts_differ_only_in_the_completeness_claim(
        self, missing_acceptance
    ) -> None:
        """The criterion is about *the same event*. Asserting both verdicts from one
        row is what makes it a claim about the claim rather than about two artifacts."""

        corpus, ordinary, acceptance = missing_acceptance
        row = ordinary.row()
        verdicts = {
            claim: verify_event_strict(
                row,
                keys=corpus.resolver(),
                referents=corpus.material(completeness=claim, omit=(acceptance,)),
            ).applicability
            for claim in (
                MaterialCompleteness.COMPLETE_STORE,
                MaterialCompleteness.CONTIGUOUS_RANGE,
            )
        }
        assert verdicts == {
            MaterialCompleteness.COMPLETE_STORE: Applicability.INVALID,
            MaterialCompleteness.CONTIGUOUS_RANGE: Applicability.UNVERIFIABLE,
        }


# ---------------------------------------------------------------------------
# The remaining envelope referents
# ---------------------------------------------------------------------------


class TestWorkflowReferent:
    def test_an_unresolvable_registration_in_complete_material_is_invalid(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        registration = corpus.register_workflow(anchor=genesis.event_hash_text)
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            workflow={
                "name": WORKFLOW_NAME,
                "version": WORKFLOW_VERSION,
                "definition_hash": _workflow_definition_hash(WORKFLOW_DEFINITION),
                "registration_event_hash": registration.event_hash_text,
            },
        )
        material = corpus.material(omit=(registration,))
        result = verify(event, corpus, material=material)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED in result.reasons

    def test_a_definition_hash_the_registration_did_not_introduce_is_invalid(self) -> None:
        """The registration resolves, names the right workflow, and commits to a
        DIFFERENT definition. This is the check that makes ``definition_hash`` mean
        something rather than travel alongside."""

        corpus = Corpus()
        genesis = corpus.genesis()
        registration = corpus.register_workflow(anchor=genesis.event_hash_text)
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            workflow={
                "name": WORKFLOW_NAME,
                "version": WORKFLOW_VERSION,
                "definition_hash": _workflow_definition_hash({"states": ["other"]}),
                "registration_event_hash": registration.event_hash_text,
            },
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.WORKFLOW_DEFINITION_MISMATCH in result.reasons

    def test_a_registration_that_does_not_precede_its_use_is_invalid(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        sibling = corpus.register_workflow(
            anchor=genesis.event_hash_text, fork_from=genesis.event_hash_text
        )
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            workflow={
                "name": WORKFLOW_NAME,
                "version": WORKFLOW_VERSION,
                "definition_hash": _workflow_definition_hash(WORKFLOW_DEFINITION),
                "registration_event_hash": sibling.event_hash_text,
            },
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED in result.reasons
        assert "registration that follows its use registers nothing" in (
            result.detail or ""
        )

    def test_a_registration_hash_naming_the_wrong_kind_of_event_is_invalid(self) -> None:
        corpus = Corpus()
        genesis = corpus.genesis()
        acceptance = corpus.accept(WORKER, anchor=genesis.event_hash_text)
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            workflow={
                "name": WORKFLOW_NAME,
                "version": WORKFLOW_VERSION,
                "definition_hash": _workflow_definition_hash(WORKFLOW_DEFINITION),
                # The acceptance event, not a registration.
                "registration_event_hash": acceptance.event_hash_text,
            },
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.INVALID
        assert FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED in result.reasons
        assert "workflow_registry row is not a registration" in (result.detail or "")


class TestDelegation:
    def test_a_delegated_event_is_never_fully_authenticated(self, healthy) -> None:
        """§5.12 requires validating a credential **document** chain, and an
        action-delegation document is not an event: no channel in the presented
        material carries one, and WI-008 has not landed. So the chain is reported
        unestablished. "No documents presented" is never read as "chain fine"."""

        corpus, _genesis, _ordinary = healthy
        acceptance = corpus.events[2]
        event = corpus.add(
            transition="created",
            entity_kind="work_item",
            entity_id=str(uuid.uuid4()),
            principal_id=WORKER,
            payload={},
            anchor=acceptance.event_hash_text,
            authorization={
                "mode": "delegated",
                "credentials": [
                    {
                        "credential_id": str(uuid.uuid4()),
                        "credential_hash": "sha256:" + "ab" * 32,
                    }
                ],
            },
        )
        result = verify(event, corpus)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        assert result.ok is False
        assert FailureReason.DELEGATION_CHAIN_INVALID in result.reasons
        assert "delegation_chain" in result.unbound_properties


class TestProducerPolicy:
    def test_an_unsupplied_policy_reports_policy_not_supplied(self, healthy) -> None:
        """§10.2 invariant 9's model case: an unsupplied pin is an explicit state."""

        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus)
        assert result.producer_consistency is ProducerConsistency.POLICY_NOT_SUPPLIED
        assert "producer_policy" in result.unbound_properties

    def test_a_matching_policy_reports_matches_published_policy(self, healthy) -> None:
        from regista._v6_writer import ProducerPolicyEntry

        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                producer_policy=[
                    ProducerPolicyEntry(
                        principal_id=WORKER, allowed_harnesses=frozenset({_HARNESS})
                    )
                ]
            ),
        )
        assert result.producer_consistency is ProducerConsistency.MATCHES_PUBLISHED_POLICY
        assert result.applicability is Applicability.FULLY_AUTHENTICATED

    def test_a_contradicting_policy_is_invalid(self, healthy) -> None:
        from regista._v6_writer import ProducerPolicyEntry

        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                producer_policy=[
                    ProducerPolicyEntry(
                        principal_id=WORKER, allowed_harnesses=frozenset({"other-harness"})
                    )
                ]
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.PRODUCER_POLICY_MISMATCH in result.reasons
        assert (
            result.producer_consistency is ProducerConsistency.CONTRADICTS_PUBLISHED_POLICY
        )

    def test_a_policy_that_omits_the_signer_contradicts_the_event(self, healthy) -> None:
        from regista._v6_writer import ProducerPolicyEntry

        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                producer_policy=[
                    ProducerPolicyEntry(
                        principal_id="agent:someone-else",
                        allowed_harnesses=frozenset({_HARNESS}),
                    )
                ]
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert "names no entry for principal" in (result.detail or "")


class TestCallerPins:
    def test_a_project_pin_the_envelope_contradicts_is_invalid(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(pinned_project_instance_id=str(uuid.uuid4())),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.PROJECT_BINDING_MISMATCH in result.reasons

    def test_a_trust_domain_pin_the_envelope_contradicts_is_invalid(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(pinned_trust_domain_id=str(uuid.uuid4())),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.TRUST_DOMAIN_MISMATCH in result.reasons

    def test_a_cutover_pin_naming_another_epochs_checkpoint_is_an_epoch_violation(
        self, healthy
    ) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                cutover_checkpoint_event_hash="sha256:" + "ff" * 32
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.EPOCH_VIOLATION in result.reasons
        assert result.checkpoint_binding is CheckpointBinding.UNBOUND

    def test_a_matching_cutover_pin_is_externally_pinned(self, healthy) -> None:
        corpus, genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                cutover_checkpoint_event_hash=genesis.event_hash_text
            ),
        )
        assert result.checkpoint_binding is CheckpointBinding.EXTERNALLY_PINNED
        assert result.applicability is Applicability.FULLY_AUTHENTICATED

    def test_an_excluding_policy_refuses_v6_explicitly_rather_than_downgrading(
        self, healthy
    ) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            policy=VerificationPolicy(
                full_authentication_versions=frozenset({EnvelopeVersion.V5})
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.LEGACY_ENVELOPE_VERSION in result.reasons
        assert "excludes v6" in (result.detail or "")


class TestCompletenessInput:
    """The policy's completeness input: semantics, default, and the refusal."""

    def test_the_default_is_the_materials_own_claim(self) -> None:
        assert VerificationPolicy().material_completeness is None
        for claim in MaterialCompleteness:
            assert resolve_completeness(claim, None) is claim

    def test_a_store_claims_completeness_which_is_the_stricter_reading(self) -> None:
        from regista._v6_referents import StoreReferents

        assert (
            StoreReferents(rows=lambda: []).completeness
            is MaterialCompleteness.COMPLETE_STORE
        )
        assert NO_REFERENTS.completeness is MaterialCompleteness.UNDECLARED

    def test_a_caller_may_tighten_an_undeclared_claim(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(
            ordinary,
            corpus,
            material=corpus.material(
                completeness=MaterialCompleteness.CONTIGUOUS_RANGE,
                omit=(corpus.events[2],),
            ),
            policy=VerificationPolicy(
                material_completeness=MaterialCompleteness.COMPLETE_STORE
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE in result.reasons

    def test_a_caller_may_not_loosen_a_stores_claim(self, healthy) -> None:
        """A softening flag would turn §5.11's INVALID row into its UNVERIFIABLE row on
        request, which is the no-fallback rule with extra steps. It raises."""

        from regista._errors import RegistaError

        corpus, _genesis, ordinary = healthy
        with pytest.raises(RegistaError, match="would loosen"):
            verify(
                ordinary,
                corpus,
                material=corpus.material(
                    completeness=MaterialCompleteness.COMPLETE_STORE
                ),
                policy=VerificationPolicy(
                    material_completeness=MaterialCompleteness.CONTIGUOUS_RANGE
                ),
            )


class TestResultModelInvariants:
    """``RESULT-MODEL.md`` §10.2's asserts, exercised as asserts.

    Each of these constructs a ``VerificationResult`` that claims something the model
    forbids. They are testing the *guard*, which is the thing that will still be there
    when someone adds a twelfth field.
    """

    def _base(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "event_id": uuid.uuid4(),
            "entity_kind": "work_item",
            "entity_id": uuid.uuid4(),
            "global_seq": 1,
            "envelope_version": EnvelopeVersion.V6,
            "envelope_present": True,
            "envelope_schema_valid": True,
            "signature_valid": True,
            "scheme_id": "ed25519",
            "row_scheme_id": "ed25519",
            "hash_alg": "sha-256",
            "trusted_key_source": TrustedKeySource.KEYSET_FILE,
            "trusted_key_id": "pk_x",
            "row_reconciled": True,
            "applicability": Applicability.FULLY_AUTHENTICATED,
            "accepted": True,
            "attribution": Attribution.INDIVIDUAL,
            "epoch_position": EpochPosition.POST_CUTOVER,
            "key_binding": KeyBinding.ACCEPTED_IN_PROJECT,
            "trust_root": TrustRoot.BUNDLED_ONLY,
            "revocation_status": RevocationStatus.NOT_REVOKED,
        }
        base.update(overrides)
        return base

    def test_the_baseline_is_constructible(self) -> None:
        assert VerificationResult(**self._base()).ok is True

    @pytest.mark.parametrize(
        ("overrides", "fragment"),
        [
            (
                {"key_binding": KeyBinding.MISMATCHED},
                "always INVALID",
            ),
            (
                {"key_binding": KeyBinding.AFTER_USE},
                "always INVALID",
            ),
            (
                {
                    "revocation_status": RevocationStatus.REVOKED_BEFORE_USE,
                },
                "revoked_before_use is always INVALID",
            ),
            (
                {"key_binding": KeyBinding.LEGACY_REGISTRY},
                "§5.9 rule 1",
            ),
            (
                {"key_binding": KeyBinding.LEGACY_UNBOUND},
                "never a v6 event's",
            ),
            (
                {"key_binding": KeyBinding.TRUST_LOG_ONLY},
                "only with key_binding=accepted_in_project",
            ),
            (
                {"key_binding": KeyBinding.BOOTSTRAP_EXTERNAL},
                "only with trust_root=externally_pinned",
            ),
            (
                {"trust_root": TrustRoot.ABSENT},
                "must have some trust root",
            ),
            (
                {"attribution": Attribution.SHARED_SECRET},
                "attributes to an individual key holder",
            ),
            (
                {"epoch_position": EpochPosition.UNKNOWN},
                "must report its epoch_position",
            ),
            (
                {"revocation_status": RevocationStatus.UNKNOWN},
                "must name 'trust_log_revocation'",
            ),
            (
                {"revocation_status": RevocationStatus.INDETERMINATE_WINDOW},
                "not silently valid",
            ),
            (
                {"reasons": (FailureReason.ENVELOPE_SCHEMA_INCOMPLETE,)},
                "was the P1.7 phase-2 clamp",
            ),
        ],
    )
    def test_a_forbidden_v6_result_raises(self, overrides, fragment) -> None:
        with pytest.raises(AssertionError, match=fragment.replace("(", r"\(")):
            VerificationResult(**self._base(**overrides))

    def test_unknown_revocation_is_permitted_when_the_gap_is_named(self) -> None:
        result = VerificationResult(
            **self._base(
                revocation_status=RevocationStatus.UNKNOWN,
                unbound_properties=frozenset({"trust_log_revocation"}),
            )
        )
        assert result.ok is True

    def test_the_v6_semantics_reach_to_dict_and_summary(self, healthy) -> None:
        corpus, _genesis, ordinary = healthy
        result = verify(ordinary, corpus)
        d = result.to_dict()
        for field_name in (
            "epoch_position",
            "attribution",
            "checkpoint_binding",
            "unbound_properties",
            "trust_domain_id",
            "trust_root",
            "root_governance",
            "key_binding",
            "key_binding_event_hash",
            "revocation_status",
            "producer_consistency",
        ):
            assert field_name in d, field_name
        assert "key_binding=accepted_in_project" in result.summary()
        assert "trust_root=bundled_only" in result.summary()


# ---------------------------------------------------------------------------
# Against a real epoch
# ---------------------------------------------------------------------------

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)


class TestAgainstARealEpoch:
    """The synthetic corpus proves the decision procedure; this proves the wiring.

    A real Postgres epoch, written by the real writer, verified through the real
    store-backed resolver. If the two disagree, the synthetic corpus is modelling
    something the writer does not produce.
    """

    @pytest.fixture(scope="class")
    def epoch(self, tmp_path_factory):
        from regista import Regista
        from regista._testing import drop_project_schema
        from tests._v6_fixtures import (
            ACTOR_PRINCIPALS,
            make_v6_keyset,
            open_v6_epoch,
        )

        project = "p17_boundary_" + uuid.uuid4().hex[:8]
        keyset = make_v6_keyset(tmp_path_factory.mktemp("boundary_keys"))
        instance = Regista.create_project(DSN, project, keyset.path)
        try:
            genesis = open_v6_epoch(instance, keyset, principals=ACTOR_PRINCIPALS)
            yield instance, keyset, genesis
        finally:
            instance.close()
            drop_project_schema(DSN, project)

    def _verify_row(self, instance, event_id):
        from regista._v6_referents import store_referents
        from regista._verification import KeySetResolver

        columns = (
            "event_id, work_item_id, entity_kind, entity_id, hash_alg, event_seq, "
            "actor_id, actor_kind, actor_metadata, key_id, workflow_name, "
            "workflow_version, timestamp, transition, payload, payload_canonical_hash, "
            "signature, canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
            "global_seq, prev_global_event_hash"
        )
        with instance._mgr.transaction() as conn:
            row = conn.execute(
                f"SELECT {columns} FROM events WHERE event_id = %s", [event_id]
            ).fetchone()
            assert row is not None
            return verify_event_strict(
                EventRow.from_mapping(row),
                keys=KeySetResolver(instance._keys),
                referents=store_referents(conn, label="real epoch"),
            )

    def test_a_real_ordinary_event_is_fully_authenticated(self, epoch) -> None:
        from regista._v6_writer import append_v6_event
        from tests._v6_fixtures import v6_producer

        instance, _keyset, _genesis = epoch
        with instance._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                instance._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id="agent:worker",
                actor_kind="agent",
                producer=v6_producer(),
                payload={"initial_state": "open"},
            )
        result = self._verify_row(instance, appended.event_id)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert result.key_binding is KeyBinding.ACCEPTED_IN_PROJECT
        assert result.key_binding_event_hash == appended.key_binding_event_hash
        assert result.epoch_position is EpochPosition.POST_CUTOVER

    def test_the_real_genesis_event_is_unverifiable_pending_an_external_pin(
        self, epoch
    ) -> None:
        instance, _keyset, genesis = epoch
        result = self._verify_row(instance, genesis.event_id)
        assert result.applicability is Applicability.UNVERIFIABLE, result.summary()
        assert result.key_binding is KeyBinding.BOOTSTRAP_EXTERNAL
        assert result.epoch_position is EpochPosition.IS_CUTOVER
        assert "external_trust_pin" in result.unbound_properties

    def test_a_real_row_rewrite_is_still_caught_by_reconciliation(self, epoch) -> None:
        """The boundary must not have displaced what worked. A row-only rewrite is
        INVALID on the field that was rewritten, above the boundary."""

        from regista._v6_writer import append_v6_event
        from tests._v6_fixtures import v6_producer

        instance, _keyset, _genesis = epoch
        with instance._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                instance._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id="agent:worker",
                actor_kind="agent",
                producer=v6_producer(),
                payload={"initial_state": "open"},
            )
            conn.execute(
                "UPDATE events SET transition = %s WHERE event_id = %s",
                ["not_created", appended.event_id],
            )
        result = self._verify_row(instance, appended.event_id)
        assert result.applicability is Applicability.INVALID
        assert result.mismatched_field_names == ("transition",)
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons

    def test_a_real_replay_does_not_halt_on_a_healthy_v6_chain(self, epoch) -> None:
        """NOTES-P17 Finding 8, inverted. The clamp made ``replay()`` report
        ``halted=1`` on a perfectly good chain, which is what blocked the fixture
        migration. This is the assertion that says it no longer does."""

        instance, _keyset, _genesis = epoch
        instance.register_workflow_file("tests/test_workflow.yaml")
        wi, _event = instance.create_work_item(
            "test_workflow",
            "feature",
            "agent:worker",
            actor_kind="agent",
            custom_fields={"title": "boundary"},
        )
        assert wi is not None
        report = instance.replay()

        assert report.replayed_ok >= 1
        assert report.replayed_drift == 0
        assert report.chain_breaks == 0
        # No halt may be a VERIFICATION halt. That is the precise claim: under the
        # clamp, `_replay` raised `[REPLAY_HALTED] Signature verification failed …
        # applicability=invalid; reasons=envelope_schema_incomplete` for the
        # work-item group of any correctly migrated fixture (NOTES-P17 Finding 8,
        # measured). It no longer does.
        verification_halts = [
            e
            for e in report.entries
            if e.category == "halted" and "verification" in (e.detail or "").lower()
        ]
        assert verification_halts == [], verification_halts

        # The Finding-14 half, which IS assertable here: the `project`, `principal`
        # and `workflow` entity groups a v6 epoch necessarily carries are counted by
        # name and are NOT warnings. (Finding 14's diagnosis — "filed as an orphan
        # halt" — was wrong when re-measured in Phase 3; they were warnings. Its
        # remedy landed regardless: tests/test_p17_replay_entity_kinds.py.)
        assert report.warnings == 0
        assert report.non_work_item_groups_verified >= 3

        # STILL not asserted: `halted == 0` — and the reason is now this class's
        # fixture rather than replay's contract. `epoch` is class-scoped and the
        # sibling tests above append work-item events with `append_v6_event`
        # directly, which writes no `work_items_current` row. Those ARE orphans and
        # halting on them is correct. The clean-epoch `halted == 0` claim lives in
        # test_p17_replay_entity_kinds.py, on a fixture nothing has polluted.
        known_orphan_forms = (
            "Orphaned events with no work_item and no created event",
            "events exist but projection row missing from work_items_current",
        )
        orphan_halts = [
            e
            for e in report.entries
            if e.category == "halted" and (e.detail or "") in known_orphan_forms
        ]
        assert len(orphan_halts) == report.halted, (
            "every remaining halt must be a genuine missing-projection orphan; "
            f"got {[e.detail for e in report.entries if e.category == 'halted']}"
        )
