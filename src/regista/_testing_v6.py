"""Throwaway v6 fixtures for tests in installed consumer packages.

The helpers in this module are deliberately test-only. They write key material
only to a directory supplied by the caller and use the real genesis and v6
append paths; constructing a production handle never opens an epoch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from nacl.signing import SigningKey

from ._genesis import V6GenesisWrite
from ._v6_writer import (
    PRINCIPAL_KEY_ACCEPTED,
    Producer,
    ProjectIdentity,
    V6Append,
    append_v6_event,
    read_project_identity,
    resolve_producer,
    workflow_definition_hash,
)

BOOTSTRAP_PRINCIPAL = "service:regista-genesis"
ACTOR_PRINCIPALS: tuple[str, ...] = (
    "human:operator",
    "human:reviewer",
    "agent:worker",
    "agent:reviewer",
    "service:hooks",
)

TEST_HARNESS = "claude-code"
TEST_HARNESS_VERSION = "test-harness/1"
TEST_MODEL = "claude-fable-5"
TEST_MODEL_LINEAGE = "fable"

TEST_ENTITY_KINDS: tuple[str, ...] = (
    "work_item",
    "principal",
    "workflow",
    "note",
)
GENESIS_ENTITY_KINDS: tuple[str, ...] = (
    "project",
    "principal",
    "workflow",
    "work_item",
    "note",
)


@dataclass(frozen=True)
class TestKey:
    """One throwaway Ed25519 actor key and its public metadata."""

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
    """An Ed25519 actor-role keyset written to a caller-owned directory."""

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
                f"{principal_id!r} is not in this keyset; add it to make_v6_keyset "
                "rather than reusing another principal's key"
            ) from None


def _key_id_for(principal_id: str) -> str:
    digest = hashlib.sha256(principal_id.encode("utf-8")).hexdigest()[:16]
    return f"pk_{digest}"


def _test_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _occurred_at() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_v6_keyset(
    directory: Path | str,
    *,
    principals: tuple[str, ...] = ACTOR_PRINCIPALS,
    include_bootstrap: bool = True,
    filename: str = "v6_keys.json",
) -> V6TestKeyset:
    """Generate one fresh active actor key for each named principal."""

    wanted = list(principals)
    if include_bootstrap and BOOTSTRAP_PRINCIPAL not in wanted:
        wanted.insert(0, BOOTSTRAP_PRINCIPAL)
    if len(wanted) != len(set(wanted)):
        raise ValueError("principals must not contain duplicates")

    target = Path(directory) / filename
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
                "role": "actor",
                "status": "active",
            }
        )
    target.write_text(json.dumps({"keys": entries}, indent=2), encoding="utf-8")
    target.chmod(0o600)
    return V6TestKeyset(path=str(target), keys=keys)


def _validate_requested_principals(
    keyset: V6TestKeyset,
    principals: tuple[str, ...],
) -> None:
    if len(principals) != len(set(principals)):
        raise ValueError("principals must not contain duplicates")
    for principal_id in principals:
        keyset.key_for(principal_id)


def v6_producer() -> Producer:
    """Return the canonical producer identity used by this test fixture."""

    return Producer(
        harness=TEST_HARNESS,
        harness_version=TEST_HARNESS_VERSION,
        model=TEST_MODEL,
        model_lineage=TEST_MODEL_LINEAGE,
    )


def set_v6_producer_env(
    producer: Producer | None = None,
    *,
    overwrite: bool = False,
) -> Producer:
    """Configure and return the producer identity the v6 writer will resolve."""

    selected = producer or v6_producer()
    from ._v6_writer import PRODUCER_ENV

    values = {
        "harness": selected.harness,
        "harness_version": selected.harness_version,
        "model": selected.model,
        "model_lineage": selected.model_lineage,
    }
    for name, value in values.items():
        variable = PRODUCER_ENV[name]
        if overwrite or variable not in os.environ:
            if value is None:
                os.environ.pop(variable, None)
            else:
                os.environ[variable] = value
    return resolve_producer()


def genesis_envelope(
    keyset: V6TestKeyset,
    *,
    principal_id: str = BOOTSTRAP_PRINCIPAL,
    project_instance_id: str | None = None,
    trust_domain_id: str | None = None,
    entity_kinds: tuple[str, ...] = GENESIS_ENTITY_KINDS,
    producer: Producer | None = None,
) -> dict[str, Any]:
    """Build a self-contained v6 project genesis without repository artifacts."""

    key = keyset.key_for(principal_id)
    project = project_instance_id if project_instance_id is not None else str(uuid.uuid4())
    trust_domain = trust_domain_id if trust_domain_id is not None else str(uuid.uuid4())
    checkpoint = {
        "checkpoint_seq": 1,
        "head_event_hash": _test_digest("regista.testing.v6.test-root-head"),
        "document_digest": _test_digest("regista.testing.v6.test-root-document"),
    }
    acceptance = {
        "principal_id": principal_id,
        "key_id": key.key_id,
        "scheme_id": "ed25519",
        "public_key": key.public_key_b64,
        "fingerprint": key.fingerprint,
        "trust_event_hash": _test_digest(
            "regista.testing.v6.test-root-enrolment:" + principal_id
        ),
        "trust_log_checkpoint": checkpoint,
        "scopes": {
            "entity_kinds": list(entity_kinds),
            "transitions": None,
            "may_accept_keys": True,
            "may_sign_checkpoints": True,
            "may_sign_bundles": False,
        },
    }
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": project,
        "trust_domain_id": trust_domain,
        "event_id": str(uuid.uuid4()),
        "entity": {"kind": "project", "id": project},
        "entity_seq": 1,
        "actor": {"principal_id": principal_id, "kind": "system", "metadata": {}},
        "signing": {
            "scheme_id": "ed25519",
            "key_id": key.key_id,
            "key_binding_event_hash": None,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": _occurred_at(),
        "transition": "project_initialized",
        "payload": {
            "bootstrap_key_acceptance": acceptance,
            "genesis_document_digest": _test_digest("regista.testing.v6.genesis-document"),
            "previous_epoch": {
                "event_count": 0,
                "genesis_event_hash": None,
                "head_event_hash": None,
                "head_hash_construction": "sha256(canonical_envelope||signature)",
                "max_global_seq": None,
                "scheme_counts": {},
            },
            "trust_domain_core_digest": _test_digest("regista.testing.v6.trust-domain-core"),
            "trust_log_checkpoint": checkpoint,
        },
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": (producer or v6_producer()).as_envelope_member(),
    }


def acceptance_payload(
    keyset: V6TestKeyset,
    *,
    principal_id: str,
    accepted_by: str,
    accepted_by_anchor: str,
    project_instance_id: str,
    trust_domain_id: str,
    entity_kinds: tuple[str, ...] = TEST_ENTITY_KINDS,
    transitions: tuple[str, ...] | None = None,
    may_sign_checkpoints: bool = False,
    may_sign_bundles: bool = False,
    trust_event_hash: str | None = None,
) -> dict[str, Any]:
    """Build a project-local key-acceptance payload for a named principal."""

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
        "trust_event_hash": (
            trust_event_hash
            if trust_event_hash is not None
            else _test_digest("regista.testing.v6.test-root-enrolment:" + principal_id)
        ),
        "trust_log_checkpoint": {
            "checkpoint_seq": 1,
            "head_event_hash": _test_digest("regista.testing.v6.test-root-head"),
            "document_digest": _test_digest("regista.testing.v6.test-root-document"),
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


def project_identity_of(instance: Any) -> ProjectIdentity:
    """Return the signed project identity through either supported backend."""

    with instance._mgr.transaction() as conn:
        identity = read_project_identity(conn)
    if identity is None:
        raise AssertionError("no v6 epoch is open on this instance")
    return identity


def write_test_genesis(instance: Any, keyset: V6TestKeyset, **kwargs: Any) -> V6GenesisWrite:
    """Open a clean v6 epoch through the backend's real genesis path."""

    supplied = kwargs.pop("producer", None)
    producer = set_v6_producer_env(
        supplied,
        overwrite=supplied is not None,
    )
    return cast(
        V6GenesisWrite,
        instance.write_genesis(
            genesis_envelope(keyset, producer=producer, **kwargs),
            gate_passed=True,
        ),
    )


def accept_key(
    instance: Any,
    keyset: V6TestKeyset,
    genesis: V6GenesisWrite,
    principal_id: str,
    trust_event_hash: str | None = None,
    **scopes: Any,
) -> V6Append:
    """Accept exactly one named principal with the supplied scopes."""

    identity = project_identity_of(instance)
    payload = acceptance_payload(
        keyset,
        principal_id=principal_id,
        accepted_by=BOOTSTRAP_PRINCIPAL,
        accepted_by_anchor=genesis.to_dict()["event_hash"],
        project_instance_id=str(identity.project_instance_id),
        trust_domain_id=str(identity.trust_domain_id),
        trust_event_hash=trust_event_hash,
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
            producer=set_v6_producer_env(),
            payload=payload,
        )


def register_test_workflow(
    instance: Any,
    name: str,
    version: int,
    definition: dict[str, Any],
) -> V6Append:
    """Append a signed workflow registration for a fixture workflow."""

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
            producer=set_v6_producer_env(),
            payload=payload,
        )


def open_v6_epoch(
    instance: Any,
    keyset: V6TestKeyset,
    *,
    principals: tuple[str, ...] = ACTOR_PRINCIPALS,
    project_instance_id: str | None = None,
    trust_domain_id: str | None = None,
    entity_kinds: tuple[str, ...] = TEST_ENTITY_KINDS,
    transitions: tuple[str, ...] | None = None,
    may_sign_checkpoints: bool = False,
    may_sign_bundles: bool = False,
    trust_event_hash: str | None = None,
) -> V6GenesisWrite:
    """Open v6 and accept only the explicitly listed principals and scopes.

    The helper never derives ordinary acceptances from the keyset contents.
    ``principals`` controls the standalone acceptance events, while the four
    scope arguments are copied into each requested acceptance. The defaults are
    the fixture's test vocabulary, not production configuration.
    """

    _validate_requested_principals(keyset, principals)
    producer = set_v6_producer_env()
    genesis = write_test_genesis(
        instance,
        keyset,
        project_instance_id=project_instance_id,
        trust_domain_id=trust_domain_id,
        producer=producer,
    )
    for principal_id in principals:
        if principal_id == BOOTSTRAP_PRINCIPAL:
            continue
        accept_key(
            instance,
            keyset,
            genesis,
            principal_id,
            trust_event_hash=trust_event_hash,
            entity_kinds=entity_kinds,
            transitions=transitions,
            may_sign_checkpoints=may_sign_checkpoints,
            may_sign_bundles=may_sign_bundles,
        )
    return genesis


__all__ = [
    "ACTOR_PRINCIPALS",
    "BOOTSTRAP_PRINCIPAL",
    "GENESIS_ENTITY_KINDS",
    "TEST_ENTITY_KINDS",
    "TEST_HARNESS",
    "TEST_HARNESS_VERSION",
    "TEST_MODEL",
    "TEST_MODEL_LINEAGE",
    "Producer",
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
