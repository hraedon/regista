"""Shared Ed25519 actor-role keyset and v6 genesis fixture (P1.7 deliverable).

``SUITE-RECONCILIATION.md`` §2.0 names these as P1.7's own deliverables, and the
reason is mechanical: **the committed ``tests/test_keys.json`` is unusable in the
clean epoch.** It holds one HMAC key, with no ``principal_id``, no ``role`` and no
public key — and a v6 event must be Ed25519, must be signed by a key bound to
``actor.principal_id``, and must name a key-binding anchor that carries that key's
public bytes. Not one of those four properties can be satisfied by that file.

This module consolidates three pieces of prior art rather than adding a fourth:

* ``tests/test_genesis.py``'s ``_envelope`` / ``_key_file`` pair, which builds a
  genesis envelope from the committed ``vectors/v6/bootstrap-project-initialized``
  case and a throwaway Ed25519 key file;
* P1.4's ``genesis_store`` in ``tests/test_bundle.py``, which additionally had to
  register the principal key *before* ``write_genesis`` so the exported bundle had
  key evidence at all (the fact WI-296 records);
* P2.2's ``tests/_trust_log_fixtures.py``, which signs v6 trust-log envelopes.

The shape here is deliberately "one keyset, many roles". A single shared key for
every actor is what the legacy fixture did, and the v6 writer refuses it:
``_v6_writer._writer_key`` requires ``entry.principal_id == actor_id``, so the
suite needs a *per-principal* key or its appends fail with
``ACTOR_SIGNER_MISMATCH``. That refusal is correct and is not worked around here.

Sequencing, which is the part that is easy to get wrong:

1. ``make_v6_keyset`` writes an Ed25519 key file with one actor-role key per
   principal. Nothing is in the store yet.
2. ``write_test_genesis`` opens the epoch with the *bootstrap* principal. Its
   embedded ``bootstrap_key_acceptance`` is the project's first key-binding
   anchor, and it holds ``may_accept_keys: true`` — that is what lets step 3
   happen without self-authorisation.
3. ``accept_key`` appends a standalone ``principal_key_accepted`` for each other
   principal, signed by the bootstrap principal. Only after this may a principal
   append ordinary events; before it, ``resolve_key_binding_anchor`` refuses with
   ``KEY_BINDING_UNRESOLVED``.

That ordering is the contract, not an implementation detail: it is
``RECONCILIATION.md`` Resolution 1's "Bootstrap A establishes external authority;
Bootstrap B imports that authority and creates project-chain order; ordinary
acceptance then operates without exceptions".
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from nacl.signing import SigningKey

VECTOR_PATH = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"

#: The bootstrap principal. It is a ``service:`` id on purpose: the key that opens
#: a project's epoch and accepts other keys is infrastructure, not a person and not
#: an agent. ``RECONCILIATION.md`` Resolution 1's own example spells it
#: ``"principal_id": "service:..."``.
BOOTSTRAP_PRINCIPAL = "service:regista-genesis"

#: The actor roles the suite writes ordinary events as. Canonical per
#: ``TRUST-DOMAIN.md`` §2.1 — ``(human|agent|service):<subject>`` — because
#: ``validate_v6_envelope`` rejects anything else and a bare legacy name is exactly
#: what criterion 19's inversion refuses.
ACTOR_PRINCIPALS: tuple[str, ...] = (
    "human:operator",
    "human:reviewer",
    "agent:worker",
    "agent:reviewer",
    "service:hooks",
)

#: A producer block every fixture-written event can carry. ``model_lineage`` must be
#: a family in ``_lineage.MODEL_LINEAGE_FAMILIES`` or admission gate 2 refuses it,
#: so this is a real family and not a placeholder string.
TEST_HARNESS = "claude-code"
TEST_HARNESS_VERSION = "test-harness/1"
TEST_MODEL = "claude-fable-5"
TEST_MODEL_LINEAGE = "fable"


@dataclass(frozen=True)
class TestKey:
    principal_id: str
    key_id: str
    seed: bytes
    public_key: bytes

    @property
    def fingerprint(self) -> str:
        return "ed25519:sha256:" + hashlib.sha256(self.public_key).hexdigest()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")


@dataclass(frozen=True)
class V6TestKeyset:
    """An Ed25519, actor-role, one-key-per-principal keyset on disk."""

    path: str
    keys: dict[str, TestKey] = field(default_factory=dict)

    @property
    def bootstrap(self) -> TestKey:
        return self.keys[BOOTSTRAP_PRINCIPAL]

    def key_for(self, principal_id: str) -> TestKey:
        try:
            return self.keys[principal_id]
        except KeyError:
            raise AssertionError(
                f"{principal_id!r} is not in this keyset. Pass it to make_v6_keyset "
                "rather than reusing another principal's key — the v6 writer refuses "
                "an actor/signer mismatch by design (ACTOR_SIGNER_MISMATCH)."
            ) from None


def _key_id_for(principal_id: str) -> str:
    """A stable, grammatical key id derived from the principal.

    Derived rather than random so a failure message names which principal's key is
    involved, and so two runs of the same fixture produce comparable ids.
    """

    digest = hashlib.sha256(principal_id.encode("utf-8")).hexdigest()[:16]
    return f"pk_{digest}"


def make_v6_keyset(
    directory: Path | str,
    *,
    principals: tuple[str, ...] = ACTOR_PRINCIPALS,
    include_bootstrap: bool = True,
    filename: str = "v6_keys.json",
) -> V6TestKeyset:
    """Write a fresh Ed25519 keyset covering ``principals`` (+ the bootstrap key).

    Always writes to a caller-owned directory — usually ``tmp_path``. Never point
    this at ``tests/test_keys.json``: mutating a tracked fixture is what made the
    next run fail with ``PRINCIPAL_KEY_ALREADY_EXISTS`` in P2.3's observed case.
    """

    target = Path(directory) / filename
    wanted = list(principals)
    if include_bootstrap and BOOTSTRAP_PRINCIPAL not in wanted:
        wanted.insert(0, BOOTSTRAP_PRINCIPAL)

    keys: dict[str, TestKey] = {}
    entries: list[dict[str, Any]] = []
    for principal_id in wanted:
        signing_key = SigningKey.generate()
        key = TestKey(
            principal_id=principal_id,
            key_id=_key_id_for(principal_id),
            seed=bytes(signing_key),
            public_key=bytes(signing_key.verify_key),
        )
        keys[principal_id] = key
        entries.append(
            {
                "key_id": key.key_id,
                "scheme": "ed25519",
                "alg": "Ed25519",
                "secret": base64.b64encode(key.seed).decode("ascii"),
                "encoding": "base64",
                "public_key": key.public_key_b64,
                "principal_id": principal_id,
                # The v6 writer requires role == "actor"; a signing key with any
                # other role is refused with KEY_ROLE_NOT_PERMITTED.
                "role": "actor",
                "status": "active",
            }
        )
    target.write_text(json.dumps({"keys": entries}, indent=2), encoding="utf-8")
    return V6TestKeyset(path=str(target), keys=keys)


def genesis_envelope(
    keyset: V6TestKeyset,
    *,
    principal_id: str = BOOTSTRAP_PRINCIPAL,
    project_instance_id: str | None = None,
    trust_domain_id: str | None = None,
    entity_kinds: tuple[str, ...] = ("project", "principal", "workflow", "work_item"),
) -> dict[str, Any]:
    """Build a complete ``project_initialized`` envelope from the committed vector.

    Reads ``vectors/v6/bootstrap-project-initialized.json`` rather than hand-rolling
    sixteen members, so the fixture and the frozen conformance vector cannot drift
    apart silently.
    """

    key = keyset.key_for(principal_id)
    case = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    envelope = cast(
        dict[str, Any], copy.deepcopy(case["input"]["envelope_declaration_order"])
    )
    project = project_instance_id or str(uuid.uuid4())
    envelope["project_instance_id"] = project
    envelope["entity"]["id"] = project
    envelope["event_id"] = str(uuid.uuid4())
    envelope["trust_domain_id"] = trust_domain_id or str(uuid.uuid4())
    envelope["actor"]["principal_id"] = principal_id
    envelope["actor"]["kind"] = "system"
    envelope["signing"]["key_id"] = key.key_id
    envelope["producer"] = {
        "harness": TEST_HARNESS,
        "harness_version": TEST_HARNESS_VERSION,
        "model": TEST_MODEL,
        "model_lineage": TEST_MODEL_LINEAGE,
    }
    acceptance = envelope["payload"]["bootstrap_key_acceptance"]
    acceptance["principal_id"] = principal_id
    acceptance["key_id"] = key.key_id
    acceptance["scheme_id"] = "ed25519"
    acceptance["public_key"] = key.public_key_b64
    acceptance["fingerprint"] = key.fingerprint
    acceptance["scopes"] = {
        "entity_kinds": list(entity_kinds),
        "transitions": None,
        # may_accept_keys is what lets the bootstrap principal sign the standalone
        # acceptances in accept_key(). Without it, ordinary acceptance would have
        # nowhere to start — which is the circularity Resolution 1 removed.
        "may_accept_keys": True,
        "may_sign_checkpoints": True,
        "may_sign_bundles": False,
    }
    return envelope


def acceptance_payload(
    keyset: V6TestKeyset,
    *,
    principal_id: str,
    accepted_by: str,
    accepted_by_anchor: str,
    project_instance_id: str,
    trust_domain_id: str,
    entity_kinds: tuple[str, ...] = ("work_item", "principal", "workflow"),
    transitions: tuple[str, ...] | None = None,
    may_sign_checkpoints: bool = False,
    may_sign_bundles: bool = False,
) -> dict[str, Any]:
    """The ``regista.key-acceptance/v1`` payload of ``TRUST-DOMAIN.md`` §5.8.

    ``public_key`` is repeated in the payload **on purpose** (§5.8): it makes a
    project bundle self-sufficient for key *material* without making it
    self-sufficient for *trust*. ``trust_event_hash`` and the checkpoint are the
    external referents; in a test-root context they are fixtures, which is exactly
    what "test roots only" means — no real root material is ever handled here.
    """

    key = keyset.key_for(principal_id)
    accepted_by_key = keyset.key_for(accepted_by)
    return {
        "type": "regista.key-acceptance",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "project_instance_id": project_instance_id,
        "principal_id": principal_id,
        "key_id": key.key_id,
        "fingerprint": key.fingerprint,
        "public_key": key.public_key_b64,
        "trust_event_hash": "sha256:" + hashlib.sha256(
            b"test-root-enrolment\x00" + key.public_key
        ).hexdigest(),
        "trust_log_checkpoint": {
            "checkpoint_seq": 1,
            "head_event_hash": "sha256:" + hashlib.sha256(b"test-root-head").hexdigest(),
            "document_digest": "sha256:" + hashlib.sha256(b"test-root-doc").hexdigest(),
        },
        "scopes": {
            "entity_kinds": list(entity_kinds),
            "transitions": None if transitions is None else list(transitions),
            "may_sign_checkpoints": may_sign_checkpoints,
            "may_sign_bundles": may_sign_bundles,
        },
        "accepted_by": {
            "principal_id": accepted_by,
            "key_id": accepted_by_key.key_id,
            "key_binding_event_hash": accepted_by_anchor,
        },
    }


# ---------------------------------------------------------------------------
# The sequencing helpers this module's docstring has always promised (WI-287)
#
# Steps 2 and 3 of the sequence above named ``write_test_genesis`` and
# ``accept_key``, but neither function existed — every caller open-coded them,
# which is how ``tests/test_p17_v6_writer.py`` ended up with a private ``_accept``
# that the 25 in-memory files would each have had to copy. These are deliberately
# **backend-agnostic**: they take any handle exposing ``write_genesis``,
# ``_mgr.transaction()`` and ``_keys``, which since WI-287 is both ``Regista``
# and ``InMemoryRegista``. Nothing here is in-memory-specific.
# ---------------------------------------------------------------------------


def v6_producer() -> Any:
    """The ``producer`` block fixture-written events carry.

    A function rather than a module constant so importing this module does not
    import ``regista._v6_writer`` — several fixture consumers are pure-logic
    tests with no interest in the writer.
    """

    from regista._v6_writer import Producer

    return Producer(
        harness=TEST_HARNESS,
        harness_version=TEST_HARNESS_VERSION,
        model=TEST_MODEL,
        model_lineage=TEST_MODEL_LINEAGE,
    )


def write_test_genesis(instance: Any, keyset: V6TestKeyset, **kwargs: Any) -> Any:
    """Step 2: open the epoch with the bootstrap principal.

    ``gate_passed=True`` is correct for a test root and is not a shortcut: the
    first-write gate exists to stop an *operator* opening an epoch over legacy
    history, and a fixture-built project has none. The genesis envelope still
    comes from the committed conformance vector.
    """

    return instance.write_genesis(genesis_envelope(keyset, **kwargs), gate_passed=True)


def project_identity_of(instance: Any) -> Any:
    """The ``project_identity`` singleton, through whichever backend ``instance`` is."""

    from regista._v6_writer import read_project_identity

    with instance._mgr.transaction() as conn:
        identity = read_project_identity(conn)
    assert identity is not None, "no v6 epoch is open on this instance"
    return identity


def accept_key(
    instance: Any,
    keyset: V6TestKeyset,
    genesis: Any,
    principal_id: str,
    **scopes: Any,
) -> Any:
    """Step 3: append the standalone ``principal_key_accepted`` for ``principal_id``.

    Signed by the bootstrap principal, anchored on the genesis event — never on
    itself. Until this runs, ``resolve_key_binding_anchor`` refuses
    ``principal_id`` with ``KEY_BINDING_UNRESOLVED``, and that refusal is correct:
    a key file is not a project-local acceptance.
    """

    from regista._v6_writer import PRINCIPAL_KEY_ACCEPTED, append_v6_event

    identity = project_identity_of(instance)
    payload = acceptance_payload(
        keyset,
        principal_id=principal_id,
        accepted_by=BOOTSTRAP_PRINCIPAL,
        accepted_by_anchor=genesis.to_dict()["event_hash"],
        project_instance_id=str(identity.project_instance_id),
        trust_domain_id=str(identity.trust_domain_id),
        **scopes,
    )
    with instance._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            instance._keys,
            entity_kind="principal",
            entity_id=uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal_id),
            transition=PRINCIPAL_KEY_ACCEPTED,
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="system",
            producer=v6_producer(),
            payload=payload,
        )


def register_test_workflow(
    instance: Any,
    name: str,
    version: int,
    definition: dict[str, Any],
) -> Any:
    """Append the signed ``workflow_registered`` event admission gate 1 requires.

    A ``workflow_registry`` row is **not** a registration (``V6-ENVELOPE.md`` §1.9),
    so a migrated fixture that only calls ``register_workflow`` will still be
    refused. This is the missing half.
    """

    from regista._v6_writer import append_v6_event, workflow_definition_hash

    identity = project_identity_of(instance)
    workflow_id = uuid.uuid5(
        uuid.NAMESPACE_OID,
        f"regista.workflow:{identity.project_instance_id}:{name}:{version}",
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
    with instance._mgr.transaction() as conn:
        return append_v6_event(
            conn,
            instance._keys,
            entity_kind="workflow",
            entity_id=workflow_id,
            transition="workflow_registered",
            actor_id=BOOTSTRAP_PRINCIPAL,
            actor_kind="system",
            producer=v6_producer(),
            payload=payload,
        )


def set_v6_producer_env() -> None:
    """Publish the process-level producer identity the writer refuses without.

    ``producer.harness`` is load-bearing (``_genesis._REQUIRED_NONEMPTY_PATHS``), and
    the legacy funnel resolves the producer from the environment rather than from a
    per-append argument — the harness that produces events is a property of the
    running process. ``setdefault`` so a test that has already set its own producer
    (or one asserting ``resolve_producer``'s refusal after ``delenv``) is not
    overridden by a fixture running later.
    """

    import os

    from regista._v6_writer import PRODUCER_ENV

    os.environ.setdefault(PRODUCER_ENV["harness"], TEST_HARNESS)
    os.environ.setdefault(PRODUCER_ENV["harness_version"], TEST_HARNESS_VERSION)
    os.environ.setdefault(PRODUCER_ENV["model"], TEST_MODEL)
    os.environ.setdefault(PRODUCER_ENV["model_lineage"], TEST_MODEL_LINEAGE)


def open_v6_epoch(
    instance: Any,
    keyset: V6TestKeyset,
    *,
    principals: tuple[str, ...] = ACTOR_PRINCIPALS,
    project_instance_id: str | None = None,
    trust_domain_id: str | None = None,
    **scopes: Any,
) -> Any:
    """Steps 2+3 in one call: open the epoch and accept every actor principal.

    This is the shape the epoch-blocked fixture migration needs — one line per
    fixture instead of the ~25 lines each of the 25 in-memory files (and their
    Postgres siblings) would otherwise open-code. Returns the genesis write.

    ``principals`` deliberately defaults to ``ACTOR_PRINCIPALS`` rather than "every
    key in the keyset": a helper that accepted every key on file would be blanket
    authorisation, which is the §5.11 property the writer exists to enforce. WI-287's
    ``test_an_unaccepted_principal_is_still_refused_after_open_v6_epoch`` pins that.

    ``trust_domain_id`` is passed through for the case where the project's chain has
    to agree with an *external* trust-log chain on the domain (``TRUST-DOMAIN.md``
    §5.2 — the trust log is a separate project chain, so the two only agree by
    reference). Also sets the process-level producer environment, because the legacy
    funnel reads it from there.
    """

    set_v6_producer_env()
    genesis = write_test_genesis(
        instance,
        keyset,
        project_instance_id=project_instance_id,
        trust_domain_id=trust_domain_id,
    )
    for principal_id in principals:
        if principal_id == BOOTSTRAP_PRINCIPAL:
            continue
        accept_key(instance, keyset, genesis, principal_id, **scopes)
    return genesis


__all__ = [
    "ACTOR_PRINCIPALS",
    "BOOTSTRAP_PRINCIPAL",
    "TEST_HARNESS",
    "TEST_HARNESS_VERSION",
    "TEST_MODEL",
    "TEST_MODEL_LINEAGE",
    "VECTOR_PATH",
    "TestKey",
    "V6TestKeyset",
    "accept_key",
    "acceptance_payload",
    "genesis_envelope",
    "make_v6_keyset",
    "open_v6_epoch",
    "project_identity_of",
    "register_test_workflow",
    "set_v6_producer_env",
    "v6_producer",
    "write_test_genesis",
]
