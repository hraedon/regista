"""Authenticated event semantics — the single verification primitive (WI-267).

The defect this module closes
-----------------------------
Signature verification used to authenticate the stored ``canonical_envelope``
bytes and return as soon as they verified. Every consumer then read the
**unsigned row columns**. An attacker with database write access could rewrite
``transition``, ``payload``, ``timestamp``, ``event_seq``, ``prev_event_hash``,
``on_behalf_of``, ``key_id``, ``entity_id`` or ``workflow_name``/``version`` in
the row and everything still reported "verified".

The design rule
---------------
    The stored canonical envelope is the cryptographic artifact; the row is its
    indexed projection. Verify the exact stored bytes, then require every field
    signed by that envelope version to agree with its row representation before
    any consumer uses the row.

Consequences that are load-bearing and must not be relaxed:

* **No fallback.** Once a stored envelope exists it is the *only* envelope. A
  parse, signature or reconciliation failure is ``INVALID``; no candidate is
  rebuilt from the row columns under attack.
* **The scheme comes from trusted key metadata, never from the row.** The row's
  ``scheme_id`` is outside every envelope version and is advisory only.
* **The verification key is resolved from the envelope's ``key_id``**, not the
  row's, so a row-only key_id rewrite surfaces as a reconciliation mismatch
  rather than as an ambiguous "unknown key".
* **``global_seq`` is unsigned by design** (``spec.md`` §17.11) — it is assigned
  after signing. It is validated structurally and may never appear in
  ``authenticated_fields``.
* **A signed-field mismatch can never be turned into a pass.** No policy field,
  environment variable or flag exists that does so; the invariant is asserted in
  ``VerificationResult.__post_init__``.

See ``FIELD-MATRIX.md`` / ``RESULT-MODEL.md`` / ``CUTOVER-POLICY.md`` (S1 design
inputs) for the normative field tables this module implements.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from ._jcs import canonicalize

__all__ = [
    "V6_ACTOR_KEYS",
    "V6_AUTHORIZATION_KEYS",
    "V6_CHAIN_KEYS",
    "V6_CREDENTIAL_KEYS",
    "V6_ENTITY_KEYS",
    "V6_PRODUCER_KEYS",
    "V6_SIGNING_KEYS",
    "V6_TOP_LEVEL_KEYS",
    "V6_WORKFLOW_KEYS",
    "AbsentEnvelopeProbe",
    "Applicability",
    "Backend",
    "BundleKeyResolver",
    "EnvelopeVersion",
    "EventRow",
    "FailureReason",
    "FieldMismatch",
    "KeySetResolver",
    "StaticKeyResolver",
    "TrustedKey",
    "TrustedKeyResolver",
    "TrustedKeySource",
    "V6EnvelopeError",
    "V6EnvelopeUncanonicalError",
    "V6VerificationResult",
    "VerificationPolicy",
    "VerificationResult",
    "classify_envelope",
    "parse_envelope_strict",
    "parse_v6_envelope_strict",
    "probe_absent_envelope",
    "validate_v6_envelope",
    "verify_event_strict",
    "verify_v6_event",
    "verify_v6_signature",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


class EnvelopeVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"  # also chain-less v3 — byte-identical, see FIELD-MATRIX §1
    V3 = "v3"
    V4 = "v4"
    V5 = "v5"
    V6 = "v6"
    ABSENT = "absent"  # canonical_envelope IS NULL (pre-002 rows)
    UNPARSEABLE = "unparseable"
    UNCANONICAL = "uncanonical"
    UNKNOWN_SCHEMA = "unknown_schema"
    KEYLESS_DUMMY = "keyless_dummy"  # InMemory zero-byte material


class Applicability(StrEnum):
    """The single field every caller is allowed to branch on."""

    FULLY_AUTHENTICATED = "fully_authenticated"
    LEGACY_PARTIAL = "legacy_partial"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


class TrustedKeySource(StrEnum):
    PRINCIPAL_REGISTRY = "principal_registry"
    KEYSET_FILE = "keyset_file"
    SUPPLIED_PUBLIC_KEY = "supplied_public_key"
    BUNDLE_EMBEDDED = "bundle_embedded"
    NONE = "none"


class FailureReason(StrEnum):
    # envelope
    ENVELOPE_ABSENT = "envelope_absent"
    ENVELOPE_UNPARSEABLE = "envelope_unparseable"
    ENVELOPE_UNCANONICAL = "envelope_uncanonical"
    ENVELOPE_UNKNOWN_SCHEMA = "envelope_unknown_schema"
    ENVELOPE_SCHEMA_INCOMPLETE = "envelope_schema_incomplete"
    # signature
    SIGNATURE_INVALID = "signature_invalid"
    CANONICAL_HASH_MISMATCH = "canonical_hash_mismatch"
    SCHEME_UNRESOLVABLE = "scheme_unresolvable"
    SCHEME_MISMATCH = "scheme_mismatch"
    # key / principal
    KEY_UNRESOLVABLE = "key_unresolvable"
    KEY_REVOKED = "key_revoked"
    KEY_NOT_VALID_AT_TIME = "key_not_valid_at_time"
    KEY_ID_MISMATCH = "key_id_mismatch"
    UNREGISTERED_SIGNER = "unregistered_signer"
    PRINCIPAL_ACTOR_MISMATCH = "principal_actor_mismatch"
    # reconciliation
    ROW_FIELD_MISMATCH = "row_field_mismatch"
    ENTITY_ALIAS_MISMATCH = "entity_alias_mismatch"
    # chain
    CHAIN_LINK_MISMATCH = "chain_link_mismatch"
    CHAIN_LINK_ABSENT = "chain_link_absent"
    # legacy
    LEGACY_ENVELOPE_VERSION = "legacy_envelope_version"
    UNSIGNED_EVENT = "unsigned_event"


V6_TOP_LEVEL_KEYS = frozenset(
    {
        "type",
        "version",
        "project_instance_id",
        "trust_domain_id",
        "event_id",
        "entity",
        "entity_seq",
        "actor",
        "signing",
        "authorization",
        "workflow",
        "occurred_at",
        "transition",
        "payload",
        "chain",
        "producer",
    }
)
V6_ENTITY_KEYS = frozenset({"kind", "id"})
V6_ACTOR_KEYS = frozenset({"principal_id", "kind", "metadata"})
V6_SIGNING_KEYS = frozenset({"scheme_id", "key_id", "key_binding_event_hash"})
V6_AUTHORIZATION_KEYS = frozenset({"mode", "credentials"})
V6_CREDENTIAL_KEYS = frozenset({"credential_id", "credential_hash"})
V6_WORKFLOW_KEYS = frozenset(
    {"name", "version", "definition_hash", "registration_event_hash"}
)
V6_CHAIN_KEYS = frozenset(
    {
        "hash_algorithm",
        "previous_entity_event_hash",
        "previous_project_event_hash",
    }
)
V6_PRODUCER_KEYS = frozenset(
    {"harness", "harness_version", "model", "model_lineage"}
)

_V6_ENTITY_KINDS = frozenset(
    {
        "work_item",
        "project",
        "principal",
        "trust_domain",
        "project_instance",
        "workflow",
    }
)
_V6_ACTOR_KINDS = frozenset({"agent", "human", "system"})
_V6_AUTHORIZATION_MODES = frozenset({"direct", "delegated"})
_V6_PRODUCER_METADATA_KEYS = frozenset(
    {"harness", "harness_version", "model", "model_lineage"}
)
_V6_BOOTSTRAP_TRANSITIONS = frozenset(
    {
        "trust_domain_established",
        "project_cryptographic_epoch_started",
        "project_initialized",
    }
)
_V6_PRINCIPAL_RE = re.compile(r"^(?:human|agent|service):[A-Za-z0-9._~:/-]+$")
_V6_OCCURRED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_V6_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_V6_MAX_CANONICAL_BYTES = 1_048_576
_V6_MAX_METADATA_BYTES = 65_536
_V6_MAX_DEPTH = 32
_V6_MAX_CREDENTIALS = 8
_V6_MAX_SAFE_NUMBER = 2**53


class V6EnvelopeError(ValueError):
    """Raised when an object or byte string is not a structurally valid v6 envelope."""


class V6EnvelopeUncanonicalError(V6EnvelopeError):
    """Raised when structurally valid v6 bytes are not their RFC 8785 fixed point."""


def _v6_error(message: str) -> V6EnvelopeError:
    return V6EnvelopeError(message)


def _v6_require(condition: bool, message: str) -> None:
    if not condition:
        raise _v6_error(message)


def _v6_require_keys(value: Any, expected: frozenset[str], path: str) -> None:
    _v6_require(isinstance(value, dict), f"{path} must be an object")
    actual = frozenset(value)
    _v6_require(
        actual == expected,
        f"{path} keys must be exactly {sorted(expected)!r}, got {sorted(actual)!r}",
    )


def _v6_require_string(
    value: Any,
    path: str,
    *,
    non_empty: bool = False,
    max_length: int | None = None,
) -> None:
    _v6_require(isinstance(value, str), f"{path} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _v6_error(f"{path} must be valid UTF-8") from exc
    if non_empty:
        _v6_require(bool(value.strip()), f"{path} must be non-empty")
    if max_length is not None:
        _v6_require(len(value) <= max_length, f"{path} exceeds {max_length} characters")


def _v6_require_uuid(value: Any, path: str) -> None:
    _v6_require(isinstance(value, str), f"{path} must be a canonical UUID string")
    try:
        parsed = _uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise _v6_error(f"{path} must be a canonical UUID string") from exc
    _v6_require(str(parsed) == value, f"{path} must use lowercase canonical UUID text")


def _v6_require_digest(value: Any, path: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _v6_require(
        isinstance(value, str) and _V6_DIGEST_RE.fullmatch(value) is not None,
        f"{path} must be sha256:<64 lowercase hex characters>",
    )


def _v6_require_principal_id(value: Any) -> None:
    _v6_require_string(value, "actor.principal_id", non_empty=True, max_length=255)
    _v6_require(
        _V6_PRINCIPAL_RE.fullmatch(value) is not None,
        "actor.principal_id must use the canonical kind:subject grammar",
    )
    subject = value.split(":", 1)[1]
    _v6_require(
        1 <= len(subject) <= 247
        and subject[0] not in ":.-_/"
        and subject[-1] not in ":.-_/",
        "actor.principal_id subject has invalid length or boundary characters",
    )
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _v6_error("actor.principal_id must be ASCII") from exc


def _v6_validate_json_value(value: Any, path: str, depth: int) -> None:
    if isinstance(value, dict):
        _v6_require(depth <= _V6_MAX_DEPTH, f"{path} exceeds nesting depth {_V6_MAX_DEPTH}")
        for key, child in value.items():
            _v6_require(isinstance(key, str), f"{path} contains a non-string object key")
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise _v6_error(f"{path} contains a non-UTF-8 object key") from exc
            _v6_validate_json_value(child, f"{path}.{key}", depth + 1)
        return
    if isinstance(value, list):
        _v6_require(depth <= _V6_MAX_DEPTH, f"{path} exceeds nesting depth {_V6_MAX_DEPTH}")
        for index, child in enumerate(value):
            _v6_validate_json_value(child, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, bool) or value is None or isinstance(value, str):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise _v6_error(f"{path} must be valid UTF-8") from exc
        return
    if isinstance(value, int | float):
        if isinstance(value, float):
            _v6_require(math.isfinite(value), f"{path} must not be NaN or Infinity")
        _v6_require(
            abs(value) < _V6_MAX_SAFE_NUMBER,
            f"{path} must have magnitude below 2**53",
        )
        return
    raise _v6_error(f"{path} contains a value that is not JSON data")


def _v6_canonical_json_size(value: Any, path: str, limit: int) -> None:
    try:
        encoded = canonicalize(value)
    except Exception as exc:
        raise _v6_error(f"{path} cannot be canonicalized") from exc
    _v6_require(len(encoded) <= limit, f"{path} exceeds {limit} canonical bytes")


def _v6_validate_workflow_registration_payload(
    envelope: Mapping[str, Any], payload: Any,
) -> None:
    _v6_require(isinstance(payload, dict), "workflow_registered payload must be an object")
    expected = frozenset(
        {
            "type",
            "version",
            "name",
            "workflow_version",
            "definition",
            "definition_hash",
            "supersedes_registration_event_hash",
        }
    )
    _v6_require_keys(payload, expected, "payload")
    _v6_require(
        payload["type"] == "regista.workflow-registration",
        "invalid workflow registration type",
    )
    _v6_require(
        isinstance(payload["version"], int) and not isinstance(payload["version"], bool)
        and payload["version"] == 1,
        "workflow registration version must be integer 1",
    )
    _v6_require_string(payload["name"], "payload.name", non_empty=True, max_length=255)
    _v6_require(
        isinstance(payload["workflow_version"], int)
        and not isinstance(payload["workflow_version"], bool)
        and payload["workflow_version"] >= 1,
        "payload.workflow_version must be an integer >= 1",
    )
    _v6_require(isinstance(payload["definition"], dict), "payload.definition must be an object")
    _v6_require(
        "raw_yaml" not in payload["definition"],
        "payload.definition must not contain raw_yaml",
    )
    _v6_require_digest(payload["definition_hash"], "payload.definition_hash")
    _v6_require_digest(
        payload["supersedes_registration_event_hash"],
        "payload.supersedes_registration_event_hash",
        nullable=True,
    )
    definition_bytes = canonicalize(payload["definition"])
    expected_hash = "sha256:" + hashlib.sha256(
        b"regista.workflow-definition.v1\x00"
        + struct.pack(">Q", len(definition_bytes))
        + definition_bytes
    ).hexdigest()
    _v6_require(payload["definition_hash"] == expected_hash, "workflow definition hash mismatch")
    project_instance_id = envelope["project_instance_id"]
    workflow_id = str(
        _uuid.uuid5(
            _uuid.NAMESPACE_OID,
            "regista.workflow:" + project_instance_id + ":"
            + payload["name"] + ":" + str(payload["workflow_version"]),
        )
    )
    _v6_require(
        envelope["entity"]["kind"] == "workflow",
        "workflow registration entity kind mismatch",
    )
    _v6_require(
        envelope["entity"]["id"] == workflow_id,
        "workflow registration entity id mismatch",
    )
    _v6_require(
        envelope["workflow"] is None,
        "workflow registration must not carry workflow binding",
    )


def _v6_validate_workflow_retirement_payload(
    envelope: Mapping[str, Any], payload: Any,
) -> None:
    _v6_require(isinstance(payload, dict), "workflow_retired payload must be an object")
    expected = frozenset(
        {"type", "version", "name", "workflow_version", "registration_event_hash", "reason"}
    )
    _v6_require_keys(payload, expected, "payload")
    _v6_require(
        payload["type"] == "regista.workflow-retirement",
        "invalid workflow retirement type",
    )
    _v6_require(
        isinstance(payload["version"], int) and not isinstance(payload["version"], bool)
        and payload["version"] == 1,
        "workflow retirement version must be integer 1",
    )
    _v6_require_string(payload["name"], "payload.name", non_empty=True, max_length=255)
    _v6_require(
        isinstance(payload["workflow_version"], int)
        and not isinstance(payload["workflow_version"], bool)
        and payload["workflow_version"] >= 1,
        "payload.workflow_version must be an integer >= 1",
    )
    _v6_require_digest(payload["registration_event_hash"], "payload.registration_event_hash")
    _v6_require_string(payload["reason"], "payload.reason", non_empty=True, max_length=65_536)
    workflow_id = str(
        _uuid.uuid5(
            _uuid.NAMESPACE_OID,
            "regista.workflow:" + envelope["project_instance_id"] + ":"
            + payload["name"] + ":" + str(payload["workflow_version"]),
        )
    )
    _v6_require(
        envelope["entity"]["kind"] == "workflow",
        "workflow retirement entity kind mismatch",
    )
    _v6_require(envelope["entity"]["id"] == workflow_id, "workflow retirement entity id mismatch")
    _v6_require(
        envelope["workflow"] is None,
        "workflow retirement must not carry workflow binding",
    )


def _validate_v6_object(
    envelope: Mapping[str, Any], *, canonical_bytes: bytes | None = None,
) -> bytes:
    _v6_require(isinstance(envelope, dict), "v6 envelope must be an object")
    _v6_validate_json_value(envelope, "envelope", 1)
    _v6_require_keys(envelope, V6_TOP_LEVEL_KEYS, "envelope")
    _v6_require(envelope["type"] == "regista.event", "v6 type must equal regista.event")
    _v6_require(
        isinstance(envelope["version"], int)
        and not isinstance(envelope["version"], bool)
        and envelope["version"] == 6,
        "v6 version must be integer 6",
    )
    _v6_require_uuid(envelope["project_instance_id"], "project_instance_id")
    _v6_require_uuid(envelope["trust_domain_id"], "trust_domain_id")
    _v6_require_uuid(envelope["event_id"], "event_id")

    entity = envelope["entity"]
    _v6_require_keys(entity, V6_ENTITY_KEYS, "entity")
    _v6_require_string(entity["kind"], "entity.kind", non_empty=True)
    _v6_require(entity["kind"] in _V6_ENTITY_KINDS, "entity.kind is not in the v6 registry")
    _v6_require_uuid(entity["id"], "entity.id")

    _v6_require(
        isinstance(envelope["entity_seq"], int)
        and not isinstance(envelope["entity_seq"], bool)
        and envelope["entity_seq"] >= 1,
        "entity_seq must be an integer >= 1",
    )

    actor = envelope["actor"]
    _v6_require_keys(actor, V6_ACTOR_KEYS, "actor")
    _v6_require_principal_id(actor["principal_id"])
    _v6_require_string(actor["kind"], "actor.kind", non_empty=True)
    _v6_require(actor["kind"] in _V6_ACTOR_KINDS, "actor.kind is not a supported execution kind")
    _v6_require(
        actor["metadata"] is None or isinstance(actor["metadata"], dict),
        "actor.metadata must be an object or null",
    )
    if actor["metadata"] is not None:
        _v6_require(
            not _V6_PRODUCER_METADATA_KEYS.intersection(actor["metadata"]),
            "producer fields must not appear in actor.metadata",
        )
        _v6_canonical_json_size(actor["metadata"], "actor.metadata", _V6_MAX_METADATA_BYTES)

    signing = envelope["signing"]
    _v6_require_keys(signing, V6_SIGNING_KEYS, "signing")
    _v6_require_string(signing["scheme_id"], "signing.scheme_id", non_empty=True)
    _v6_require(signing["scheme_id"] == "ed25519", "production v6 requires ed25519")
    _v6_require_string(signing["key_id"], "signing.key_id", non_empty=True, max_length=255)
    _v6_require_digest(
        signing["key_binding_event_hash"],
        "signing.key_binding_event_hash",
        nullable=True,
    )

    authorization = envelope["authorization"]
    _v6_require_keys(authorization, V6_AUTHORIZATION_KEYS, "authorization")
    _v6_require_string(authorization["mode"], "authorization.mode", non_empty=True)
    _v6_require(
        authorization["mode"] in _V6_AUTHORIZATION_MODES,
        "authorization.mode is not a supported mode",
    )
    credentials = authorization["credentials"]
    _v6_require(isinstance(credentials, list), "authorization.credentials must be an array")
    _v6_require(
        len(credentials) <= _V6_MAX_CREDENTIALS,
        "authorization.credentials exceeds eight entries",
    )
    for index, credential in enumerate(credentials):
        path = f"authorization.credentials[{index}]"
        _v6_require_keys(credential, V6_CREDENTIAL_KEYS, path)
        _v6_require_uuid(credential["credential_id"], f"{path}.credential_id")
        _v6_require_digest(credential["credential_hash"], f"{path}.credential_hash")
    _v6_require(
        (authorization["mode"] == "direct") == (credentials == []),
        "authorization mode and credentials are inconsistent",
    )

    workflow = envelope["workflow"]
    if workflow is None:
        if entity["kind"] != "work_item":
            _v6_require(
                entity["kind"] in {
                    "project",
                    "principal",
                    "trust_domain",
                    "project_instance",
                    "workflow",
                },
                "workflow null is not valid for this entity kind",
            )
    else:
        _v6_require_keys(workflow, V6_WORKFLOW_KEYS, "workflow")
        _v6_require_string(workflow["name"], "workflow.name", non_empty=True, max_length=255)
        _v6_require(
            isinstance(workflow["version"], int)
            and not isinstance(workflow["version"], bool)
            and workflow["version"] >= 1,
            "workflow.version must be an integer >= 1",
        )
        _v6_require_digest(workflow["definition_hash"], "workflow.definition_hash")
        _v6_require_digest(
            workflow["registration_event_hash"], "workflow.registration_event_hash"
        )
        _v6_require(
            entity["kind"] == "work_item",
            "workflow binding is only valid for a workflow-evaluated work item event",
        )

    _v6_require_string(envelope["occurred_at"], "occurred_at")
    _v6_require(
        _V6_OCCURRED_AT_RE.fullmatch(envelope["occurred_at"]) is not None,
        "occurred_at must use YYYY-MM-DDThh:mm:ss.ffffffZ",
    )
    try:
        datetime.strptime(envelope["occurred_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise _v6_error("occurred_at is not a valid UTC calendar time") from exc

    _v6_require_string(envelope["transition"], "transition", non_empty=True, max_length=255)
    _v6_require(
        envelope["payload"] is None or isinstance(envelope["payload"], dict),
        "payload must be an object or null",
    )
    if envelope["payload"] is not None:
        _v6_canonical_json_size(envelope["payload"], "payload", _V6_MAX_CANONICAL_BYTES)

    chain = envelope["chain"]
    _v6_require_keys(chain, V6_CHAIN_KEYS, "chain")
    _v6_require_string(chain["hash_algorithm"], "chain.hash_algorithm", non_empty=True)
    _v6_require(chain["hash_algorithm"] == "sha-256", "v6 hash_algorithm must be sha-256")
    _v6_require_digest(
        chain["previous_entity_event_hash"],
        "chain.previous_entity_event_hash",
        nullable=True,
    )
    _v6_require_digest(
        chain["previous_project_event_hash"],
        "chain.previous_project_event_hash",
        nullable=True,
    )
    if envelope["entity_seq"] == 1:
        _v6_require(
            chain["previous_entity_event_hash"] is None,
            "entity_seq 1 requires a null previous_entity_event_hash",
        )
    else:
        _v6_require(
            chain["previous_entity_event_hash"] is not None,
            "entity_seq greater than 1 requires previous_entity_event_hash",
        )
    if chain["previous_project_event_hash"] is None:
        _v6_require(
            envelope["transition"] in {"trust_domain_established", "project_initialized"},
            "a null previous_project_event_hash is limited to project-chain genesis",
        )

    producer = envelope["producer"]
    _v6_require_keys(producer, V6_PRODUCER_KEYS, "producer")
    _v6_require_string(producer["harness"], "producer.harness", non_empty=True, max_length=255)
    _v6_require_string(
        producer["harness_version"], "producer.harness_version", non_empty=True, max_length=255
    )
    for field in ("model", "model_lineage"):
        value = producer[field]
        _v6_require(
            value is None or isinstance(value, str), f"producer.{field} must be a string or null"
        )
        if value is not None:
            _v6_require_string(value, f"producer.{field}", non_empty=True)
    _v6_require(
        (producer["model"] is None) == (producer["model_lineage"] is None),
        "producer.model and producer.model_lineage must be null together",
    )

    transition = envelope["transition"]
    if signing["key_binding_event_hash"] is None:
        _v6_require(
            transition in _V6_BOOTSTRAP_TRANSITIONS,
            "null key binding is permitted only for a bootstrap transition",
        )
    elif transition in _V6_BOOTSTRAP_TRANSITIONS:
        raise _v6_error("bootstrap transitions require a null key binding")

    if transition == "trust_domain_established":
        _v6_require(entity["kind"] == "trust_domain", "trust genesis entity kind mismatch")
        _v6_require(entity["id"] == envelope["trust_domain_id"], "trust genesis entity id mismatch")
        _v6_require(envelope["entity_seq"] == 1, "trust genesis must be entity sequence 1")
        _v6_require(
            chain["previous_entity_event_hash"] is None
            and chain["previous_project_event_hash"] is None,
            "trust genesis must have null predecessor links",
        )
        _v6_require(workflow is None, "trust genesis must not carry workflow binding")
    elif transition == "project_cryptographic_epoch_started":
        _v6_require(entity["kind"] == "project", "cutover entity kind mismatch")
        _v6_require(
            entity["id"] == envelope["project_instance_id"],
            "cutover entity id must equal project_instance_id",
        )
        _v6_require(envelope["entity_seq"] == 1, "cutover must be entity sequence 1")
        _v6_require(
            chain["previous_entity_event_hash"] is None
            and chain["previous_project_event_hash"] is not None,
            "cutover must start its entity chain and name the legacy project head",
        )
        _v6_require(workflow is None, "cutover must not carry workflow binding")
    elif transition == "project_initialized":
        _v6_require(entity["kind"] == "project", "project initialization entity kind mismatch")
        _v6_require(envelope["entity_seq"] == 1, "project initialization must be entity sequence 1")
        _v6_require(
            chain["previous_entity_event_hash"] is None
            and chain["previous_project_event_hash"] is None,
            "project initialization must have null predecessor links",
        )
        _v6_require(workflow is None, "project initialization must not carry workflow binding")

    if transition == "workflow_registered":
        _v6_validate_workflow_registration_payload(envelope, envelope["payload"])
    elif transition == "workflow_retired":
        _v6_validate_workflow_retirement_payload(envelope, envelope["payload"])

    try:
        canonical = canonicalize(dict(envelope))
    except Exception as exc:
        raise _v6_error("v6 envelope cannot be canonicalized") from exc
    _v6_require(
        len(canonical) <= _V6_MAX_CANONICAL_BYTES,
        f"canonical envelope exceeds {_V6_MAX_CANONICAL_BYTES} bytes",
    )
    if canonical_bytes is not None:
        if canonical != canonical_bytes:
            raise V6EnvelopeUncanonicalError(
                "stored v6 envelope is not a JCS fixed point"
            )
    return canonical


def validate_v6_envelope(envelope: Mapping[str, Any]) -> None:
    """Validate v6 schema and local invariants without resolving external referents."""

    _validate_v6_object(envelope)


def parse_v6_envelope_strict(envelope: bytes) -> dict[str, Any]:
    """Parse exact stored v6 bytes and require the RFC 8785 fixed point."""

    if not isinstance(envelope, bytes):
        raise V6EnvelopeError("stored v6 envelope must be bytes")
    if len(envelope) > _V6_MAX_CANONICAL_BYTES:
        raise V6EnvelopeError("stored v6 envelope exceeds 1048576 bytes")
    try:
        parsed = parse_envelope_strict(envelope)
    except (ValueError, TypeError) as exc:
        raise V6EnvelopeError(str(exc)) from exc
    _validate_v6_object(parsed, canonical_bytes=envelope)
    return parsed


class Backend(StrEnum):
    """Where the row came from.

    Load-bearing for exactly one rule: the keyless-dummy exemption is a property
    of the **backend**, not of the byte pattern. A Postgres row exhibiting the
    InMemory dummy pattern is an attack (or a corrupted import), not an unsigned
    event, and stays ``INVALID``.
    """

    POSTGRES = "postgres"
    IN_MEMORY = "in_memory"
    BUNDLE = "bundle"


# ---------------------------------------------------------------------------
# Strict envelope schemas (RESULT-MODEL §3.1)
# ---------------------------------------------------------------------------

_V1_REQUIRED = frozenset(
    {"event_id", "work_item_id", "actor_id", "on_behalf_of", "transition", "payload"}
)
_V2_REQUIRED = _V1_REQUIRED | {
    "key_id",
    "event_seq",
    "workflow_name",
    "workflow_version",
    "timestamp",
}
_V3_REQUIRED = _V2_REQUIRED
_V4_REQUIRED = frozenset(
    {
        "event_id",
        "entity_kind",
        "entity_id",
        "actor_id",
        "key_id",
        "event_seq",
        "workflow_name",
        "workflow_version",
        "timestamp",
        "hash_alg",
        "on_behalf_of",
        "transition",
        "payload",
    }
)
_V5_REQUIRED = _V4_REQUIRED | {"actor_kind", "actor_metadata"}

#: Presence-significant: emitted only when the signer's argument was not None.
#: Absent and present-with-null are *different signed bytes*, so these are
#: reconciled by presence as well as value (FIELD-MATRIX §5).
_CHAIN_OPTIONAL = frozenset({"prev_event_hash", "global_seq", "prev_global_event_hash"})

_REQUIRED_FIELDS: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V6: V6_TOP_LEVEL_KEYS,
    EnvelopeVersion.V1: _V1_REQUIRED,
    EnvelopeVersion.V2: _V2_REQUIRED,
    EnvelopeVersion.V3: _V3_REQUIRED,
    EnvelopeVersion.V4: _V4_REQUIRED,
    EnvelopeVersion.V5: _V5_REQUIRED,
}

_OPTIONAL_FIELDS: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V6: frozenset(),
    EnvelopeVersion.V1: frozenset(),
    EnvelopeVersion.V2: frozenset(),
    EnvelopeVersion.V3: _CHAIN_OPTIONAL,
    EnvelopeVersion.V4: _CHAIN_OPTIONAL,
    EnvelopeVersion.V5: _CHAIN_OPTIONAL,
}

#: Real envelope versions, newest first — classification tries them in order.
_KNOWN_VERSIONS: tuple[EnvelopeVersion, ...] = (
    EnvelopeVersion.V6,
    EnvelopeVersion.V5,
    EnvelopeVersion.V4,
    EnvelopeVersion.V3,
    EnvelopeVersion.V1,
)

#: Row columns no envelope version has ever signed. Always reported unsigned.
_NEVER_SIGNED = frozenset({"global_seq", "scheme_id"})
#: Every row column a consumer might read. Used to populate ``unsigned_fields``
#: on the outcomes where *nothing* was authenticated, so a consumer that checks
#: membership before trusting a field is correct in those cases too.
_ALL_ROW_FIELDS = frozenset(
    {
        "event_id",
        "work_item_id",
        "entity_kind",
        "entity_id",
        "actor_id",
        "actor_kind",
        "actor_metadata",
        "key_id",
        "event_seq",
        "workflow_name",
        "workflow_version",
        "timestamp",
        "hash_alg",
        "on_behalf_of",
        "transition",
        "payload",
        "prev_event_hash",
        "prev_global_event_hash",
        "global_seq",
        "scheme_id",
    }
)


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number {value!r} in signing envelope")


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r} in signing envelope")
        seen[key] = value
    return seen


def parse_envelope_strict(envelope: bytes) -> dict[str, Any]:
    """Parse stored envelope bytes, refusing everything JCS could not have made.

    Raises ``ValueError`` on: invalid JSON, a non-object top level, duplicate
    keys, or NaN/Infinity. RFC 8785 can emit none of those, so any of them means
    the bytes were not produced by this system's canonicalizer.
    """
    obj = json.loads(
        envelope,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    if not isinstance(obj, dict):
        raise ValueError("signing envelope is not a JSON object")
    return obj


def classify_envelope(obj: Mapping[str, Any]) -> EnvelopeVersion:
    """Strictly classify a parsed envelope.

    Unlike the permissive classifier this replaces, nothing falls through to v1:
    a missing required field or an unrecognised key is ``UNKNOWN_SCHEMA``. The
    old ``issuperset`` classifier let *any subset* of v5's fields — including
    ``{}`` and an attacker-authored object — be treated as a v1 envelope, which
    is the weakest possible claim and therefore the most attractive target.
    """
    if "type" in obj or "version" in obj:
        try:
            _validate_v6_object(obj)
        except (V6EnvelopeError, TypeError, ValueError):
            return EnvelopeVersion.UNKNOWN_SCHEMA
        return EnvelopeVersion.V6

    keys = frozenset(obj.keys())
    for version in _KNOWN_VERSIONS:
        required = _REQUIRED_FIELDS[version]
        optional = _OPTIONAL_FIELDS[version]
        if required <= keys and (keys - required) <= optional:
            if version is EnvelopeVersion.V3 and not (keys & _CHAIN_OPTIONAL):
                # v2 and chain-less v3 are byte-identical; the distinction is
                # not recoverable from the bytes and does not need to be.
                return EnvelopeVersion.V2
            return version
    return EnvelopeVersion.UNKNOWN_SCHEMA


def classify_envelope_bytes(envelope: bytes) -> EnvelopeVersion:
    try:
        obj = parse_envelope_strict(envelope)
    except (ValueError, TypeError):
        return EnvelopeVersion.UNPARSEABLE
    if "type" in obj or "version" in obj:
        try:
            _validate_v6_object(obj, canonical_bytes=envelope)
        except V6EnvelopeUncanonicalError:
            return EnvelopeVersion.UNCANONICAL
        except (V6EnvelopeError, TypeError, ValueError):
            return EnvelopeVersion.UNKNOWN_SCHEMA
        return EnvelopeVersion.V6
    return classify_envelope(obj)


# ---------------------------------------------------------------------------
# The result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldMismatch:
    """One envelope field that disagrees with its row column.

    ``envelope_repr``/``row_repr`` are deliberately short, redacted renderings —
    never a raw payload — so a mismatch can be triaged from a log line without
    leaking event content.
    """

    field: str
    envelope_repr: str
    row_repr: str
    presence_only: bool = False

    def __str__(self) -> str:
        kind = "presence" if self.presence_only else "value"
        return f"{self.field} ({kind}: envelope={self.envelope_repr} row={self.row_repr})"


@dataclass(frozen=True)
class VerificationPolicy:
    """Bounded, explicit, and non-silent. There is no 'lenient' mode.

    **There is no field here that can turn a signed-field mismatch into a
    success.** ``mismatched_fields != ()`` forces ``INVALID`` under every policy;
    that is a class invariant of :class:`VerificationResult`, not a convention.

    ``accept_legacy_before_global_seq`` is an *administrative* bound, not a
    cryptographic one: ``global_seq`` is unsigned by design, so an attacker with
    row-write access can move an event across the watermark. That is acceptable
    only because crossing it can never turn ``INVALID`` into a pass — it can only
    turn ``LEGACY_PARTIAL`` into ``INVALID`` or the reverse, and the reverse still
    requires the signature and every signed field to reconcile.
    """

    #: Envelope versions that may report FULLY_AUTHENTICATED. v5 is the floor:
    #: it is the only version that signs actor_kind/actor_metadata, which is
    #: what the review gate and assurance make decisions from.
    full_authentication_versions: frozenset[EnvelopeVersion] = frozenset(
        {EnvelopeVersion.V5}
    )
    #: Legacy versions that may report LEGACY_PARTIAL instead of INVALID.
    #: Expected to shrink, never grow.
    accept_legacy_versions: frozenset[EnvelopeVersion] = frozenset(
        {EnvelopeVersion.V4}
    )
    #: The cutover watermark. ``None`` means "not yet set for this project".
    accept_legacy_before_global_seq: int | None = None
    #: InMemory keyless events may be *processed*; they are never authenticated.
    accept_unsigned_keyless: bool = False


DEFAULT_POLICY = VerificationPolicy()


@dataclass(frozen=True)
class VerificationResult:
    """The one structured verdict, produced by :func:`verify_event_strict`.

    ``ok`` is the only boolean bridge and means ``fully_authenticated`` and
    nothing else. ``accepted`` additionally admits a legacy version the policy
    explicitly named (and, for the InMemory backend, an explicitly permitted
    unsigned keyless event) — every use of it is therefore a greppable statement
    that legacy is being accepted.
    """

    # --- identity -------------------------------------------------------
    event_id: UUID | None
    entity_kind: str | None
    entity_id: UUID | None
    global_seq: int | None  # structural only; never authenticated

    # --- envelope -------------------------------------------------------
    envelope_version: EnvelopeVersion
    envelope_present: bool
    envelope_schema_valid: bool

    # --- signature ------------------------------------------------------
    signature_valid: bool
    scheme_id: str | None  # DERIVED from key metadata, not the row
    row_scheme_id: str | None  # what the row claimed, for reporting only
    hash_alg: str | None  # taken from the ENVELOPE for v4/v5

    # --- trusted key ----------------------------------------------------
    trusted_key_source: TrustedKeySource
    trusted_key_id: str | None
    principal_id: str | None = None
    principal_binding_verified: bool = False

    # --- reconciliation -------------------------------------------------
    row_reconciled: bool = False
    mismatched_fields: tuple[FieldMismatch, ...] = ()
    authenticated_fields: frozenset[str] = frozenset()
    unsigned_fields: frozenset[str] = frozenset()

    # --- chain ----------------------------------------------------------
    prev_event_hash_ok: bool | None = None
    prev_global_event_hash_ok: bool | None = None

    # --- outcome --------------------------------------------------------
    applicability: Applicability = Applicability.UNVERIFIABLE
    accepted: bool = False
    reasons: tuple[FailureReason, ...] = ()
    legacy_reason: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        # Mechanism 1: legacy_partial is never reachable from a mismatch.
        # Legacy describes fields the version never signed; it can never
        # describe fields that were signed and disagree.
        if self.mismatched_fields and self.applicability is not Applicability.INVALID:
            raise AssertionError(
                "VerificationResult invariant violated: mismatched_fields is "
                f"non-empty but applicability is {self.applicability!r}; a "
                "signed-field mismatch is always INVALID"
            )
        # global_seq is assigned post-signing (spec.md §17.11). Claiming it is
        # authenticated would be a false claim about the 017 backfill.
        if "global_seq" in self.authenticated_fields:
            raise AssertionError(
                "VerificationResult invariant violated: global_seq is unsigned "
                "by design and must never appear in authenticated_fields"
            )
        if self.accepted and self.applicability is Applicability.INVALID:
            raise AssertionError(
                "VerificationResult invariant violated: INVALID is never accepted"
            )
        if self.applicability is Applicability.LEGACY_PARTIAL and not self.unsigned_fields:
            raise AssertionError(
                "VerificationResult invariant violated: LEGACY_PARTIAL must name "
                "the fields it left unauthenticated"
            )

    @property
    def ok(self) -> bool:
        """True iff nothing the consumer may read was left unauthenticated."""
        return self.applicability is Applicability.FULLY_AUTHENTICATED

    @property
    def mismatched_field_names(self) -> tuple[str, ...]:
        return tuple(m.field for m in self.mismatched_fields)

    def summary(self) -> str:
        parts = [f"applicability={self.applicability.value}"]
        parts.append(f"envelope={self.envelope_version.value}")
        if self.reasons:
            parts.append("reasons=" + ",".join(r.value for r in self.reasons))
        if self.mismatched_fields:
            parts.append("mismatched=" + ",".join(self.mismatched_field_names))
        if self.detail:
            parts.append(self.detail)
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id) if self.event_id else None,
            "entity_kind": self.entity_kind,
            "entity_id": str(self.entity_id) if self.entity_id else None,
            "global_seq": self.global_seq,
            "envelope_version": self.envelope_version.value,
            "envelope_present": self.envelope_present,
            "envelope_schema_valid": self.envelope_schema_valid,
            "signature_valid": self.signature_valid,
            "scheme_id": self.scheme_id,
            "row_scheme_id": self.row_scheme_id,
            "hash_alg": self.hash_alg,
            "trusted_key_source": self.trusted_key_source.value,
            "trusted_key_id": self.trusted_key_id,
            "principal_id": self.principal_id,
            "principal_binding_verified": self.principal_binding_verified,
            "row_reconciled": self.row_reconciled,
            "mismatched_fields": [
                {
                    "field": m.field,
                    "envelope": m.envelope_repr,
                    "row": m.row_repr,
                    "presence_only": m.presence_only,
                }
                for m in self.mismatched_fields
            ],
            "authenticated_fields": sorted(self.authenticated_fields),
            "unsigned_fields": sorted(self.unsigned_fields),
            "prev_event_hash_ok": self.prev_event_hash_ok,
            "prev_global_event_hash_ok": self.prev_global_event_hash_ok,
            "applicability": self.applicability.value,
            "accepted": self.accepted,
            "reasons": [r.value for r in self.reasons],
            "legacy_reason": self.legacy_reason,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class V6VerificationResult:
    """Cryptographic v6 verdict before project lifecycle resolution.

    This result deliberately stops at the P1.1 boundary. It verifies the exact
    stored bytes, the v6 signature-input domain, the v6 payload hash and the
    version-aware event hash. Optional project and trust pins are checked when
    supplied. Key-binding anchors, workflow registrations, delegation
    credentials and chain referents remain external checks for P1.2/P1.3.
    """

    envelope_version: EnvelopeVersion
    envelope: dict[str, Any] | None
    schema_valid: bool
    canonical_valid: bool
    signature_valid: bool
    payload_canonical_hash_valid: bool | None
    event_hash: bytes | None
    event_hash_valid: bool | None
    project_binding_valid: bool | None
    trust_domain_binding_valid: bool | None
    scheme_id: str | None
    key_id: str | None
    errors: tuple[str, ...] = ()

    @property
    def cryptographically_valid(self) -> bool:
        checks = [self.schema_valid, self.canonical_valid, self.signature_valid]
        if self.payload_canonical_hash_valid is not None:
            checks.append(self.payload_canonical_hash_valid)
        if self.event_hash_valid is not None:
            checks.append(self.event_hash_valid)
        return all(checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version.value,
            "schema_valid": self.schema_valid,
            "canonical_valid": self.canonical_valid,
            "signature_valid": self.signature_valid,
            "payload_canonical_hash_valid": self.payload_canonical_hash_valid,
            "event_hash": (
                "sha256:" + self.event_hash.hex() if self.event_hash is not None else None
            ),
            "event_hash_valid": self.event_hash_valid,
            "project_binding_valid": self.project_binding_valid,
            "trust_domain_binding_valid": self.trust_domain_binding_valid,
            "scheme_id": self.scheme_id,
            "key_id": self.key_id,
            "cryptographically_valid": self.cryptographically_valid,
            "errors": list(self.errors),
        }


def _v6_hash_bytes(value: bytes | str | None) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str) and _V6_DIGEST_RE.fullmatch(value):
        return bytes.fromhex(value.removeprefix("sha256:"))
    return None


def verify_v6_signature(
    canonical_envelope: bytes,
    signature: bytes,
    public_key: bytes,
    *,
    payload_canonical_hash: bytes | str | None = None,
    expected_event_hash: bytes | str | None = None,
    expected_project_instance_id: UUID | str | None = None,
    expected_trust_domain_id: UUID | str | None = None,
    trusted_scheme_id: str | None = "ed25519",
) -> V6VerificationResult:
    """Verify the production v6 byte and signature contract.

    The parser performs all local schema checks before this function asks
    Ed25519 to verify anything. The optional pins are authoritative inputs for
    project and trust-domain binding; omitted pins are reported as unchecked,
    never as successful external validation.
    """

    try:
        envelope = parse_v6_envelope_strict(canonical_envelope)
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        version = classify_envelope_bytes(canonical_envelope)
        return V6VerificationResult(
            envelope_version=version,
            envelope=None,
            schema_valid=False,
            canonical_valid=False,
            signature_valid=False,
            payload_canonical_hash_valid=None,
            event_hash=None,
            event_hash_valid=None,
            project_binding_valid=None,
            trust_domain_binding_valid=None,
            scheme_id=None,
            key_id=None,
            errors=(str(exc),),
        )

    from ._signing import (
        compute_v6_event_hash,
        compute_v6_payload_canonical_hash,
        v6_signature_input,
    )
    from ._signing_scheme import Ed25519Scheme

    signing = envelope["signing"]
    errors: list[str] = []
    if trusted_scheme_id is not None and trusted_scheme_id != signing["scheme_id"]:
        errors.append("scheme_mismatch")

    project_binding_valid: bool | None = None
    if expected_project_instance_id is not None:
        expected = str(expected_project_instance_id)
        project_binding_valid = envelope["project_instance_id"] == expected
        if not project_binding_valid:
            errors.append("project_binding_mismatch")

    trust_domain_binding_valid: bool | None = None
    if expected_trust_domain_id is not None:
        expected = str(expected_trust_domain_id)
        trust_domain_binding_valid = envelope["trust_domain_id"] == expected
        if not trust_domain_binding_valid:
            errors.append("trust_domain_mismatch")

    signature_input = v6_signature_input(canonical_envelope)
    computed_payload_hash = compute_v6_payload_canonical_hash(canonical_envelope)
    supplied_payload_hash = _v6_hash_bytes(payload_canonical_hash)
    payload_hash_valid: bool | None = None
    if payload_canonical_hash is not None:
        payload_hash_valid = supplied_payload_hash == computed_payload_hash
        if not payload_hash_valid:
            errors.append("payload_canonical_hash_mismatch")

    computed_event_hash = compute_v6_event_hash(canonical_envelope, signature)
    supplied_event_hash = _v6_hash_bytes(expected_event_hash)
    event_hash_valid: bool | None = None
    if expected_event_hash is not None:
        event_hash_valid = supplied_event_hash == computed_event_hash
        if not event_hash_valid:
            errors.append("event_hash_mismatch")

    signature_valid = False
    if trusted_scheme_id in (None, "ed25519"):
        try:
            signature_valid = Ed25519Scheme().verify(
                signature_input,
                signature,
                computed_payload_hash,
                public_key,
            )
        except Exception:
            signature_valid = False
    if not signature_valid:
        errors.append("signature_invalid")

    return V6VerificationResult(
        envelope_version=EnvelopeVersion.V6,
        envelope=envelope,
        schema_valid=True,
        canonical_valid=True,
        signature_valid=signature_valid,
        payload_canonical_hash_valid=payload_hash_valid,
        event_hash=computed_event_hash,
        event_hash_valid=event_hash_valid,
        project_binding_valid=project_binding_valid,
        trust_domain_binding_valid=trust_domain_binding_valid,
        scheme_id=signing["scheme_id"],
        key_id=signing["key_id"],
        errors=tuple(dict.fromkeys(errors)),
    )


verify_v6_event = verify_v6_signature


# ---------------------------------------------------------------------------
# The row view
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRow:
    """A backend-neutral view of the ``events`` row under verification.

    Built from a Postgres row mapping, an :class:`~regista._types.Event`, or a
    bundle event dict, so Postgres and InMemory run *the same* reconciliation
    and cannot drift in what "verified" means.
    """

    event_id: UUID
    work_item_id: UUID | None
    entity_kind: str | None
    entity_id: UUID | None
    actor_id: str
    actor_kind: str | None
    actor_metadata: Any
    key_id: str | None
    event_seq: int | None
    workflow_name: str | None
    workflow_version: int | None
    timestamp: datetime | None
    hash_alg: str | None
    on_behalf_of: Any
    transition: str | None
    payload: Any
    prev_event_hash: bytes | None
    prev_global_event_hash: bytes | None
    global_seq: int | None
    canonical_envelope: bytes | None
    signature: bytes | None
    payload_canonical_hash: bytes | None
    row_scheme_id: str | None
    backend: Backend = Backend.POSTGRES

    @property
    def effective_entity_id(self) -> UUID | None:
        return self.entity_id if self.entity_id is not None else self.work_item_id

    @classmethod
    def from_event(cls, event: Any, *, backend: Backend = Backend.POSTGRES) -> EventRow:
        """Build the row view from an :class:`~regista._types.Event`.

        **Known limitation.** ``Event.__post_init__`` normalises a ``None``
        ``entity_id`` to ``work_item_id``, and ``Event.from_dict`` defaults
        ``entity_kind``/``hash_alg``, so this constructor cannot observe a NULL
        in those columns — the dataclass has already collapsed it. The raw-row
        path (:meth:`from_mapping`), which is what replay uses and therefore
        what applies row values to the projection, does observe it. Verifying
        the raw row is the stronger check; prefer it where the caller has one.
        """
        return cls(
            event_id=event.event_id,
            work_item_id=event.work_item_id,
            entity_kind=getattr(event, "entity_kind", None),
            entity_id=getattr(event, "entity_id", None),
            actor_id=event.actor_id,
            actor_kind=getattr(event, "actor_kind", None),
            actor_metadata=getattr(event, "actor_metadata", None),
            key_id=event.key_id,
            event_seq=event.event_seq,
            workflow_name=event.workflow_name,
            workflow_version=event.workflow_version,
            timestamp=event.timestamp,
            hash_alg=getattr(event, "hash_alg", None),
            on_behalf_of=getattr(event, "on_behalf_of", None),
            transition=event.transition,
            payload=event.payload,
            prev_event_hash=_as_bytes(getattr(event, "prev_event_hash", None)),
            prev_global_event_hash=_as_bytes(
                getattr(event, "prev_global_event_hash", None)
            ),
            global_seq=getattr(event, "global_seq", None),
            canonical_envelope=_as_bytes(getattr(event, "canonical_envelope", None)),
            signature=_as_bytes(event.signature),
            payload_canonical_hash=_as_bytes(event.payload_canonical_hash),
            row_scheme_id=getattr(event, "scheme_id", None),
            backend=backend,
        )

    @classmethod
    def from_mapping(
        cls, row: Mapping[str, Any], *, backend: Backend = Backend.POSTGRES
    ) -> EventRow:
        return cls(
            event_id=_as_uuid(row["event_id"]),  # type: ignore[arg-type]
            work_item_id=_as_uuid(row.get("work_item_id")),
            # No `or` default: a NULL column must reach the comparator as
            # None so it mismatches the signed value, rather than being
            # silently replaced by the value the signer happened to use.
            entity_kind=row.get("entity_kind"),
            entity_id=_as_uuid(row.get("entity_id")),
            actor_id=row["actor_id"],
            actor_kind=row.get("actor_kind"),
            actor_metadata=row.get("actor_metadata"),
            key_id=row.get("key_id"),
            event_seq=row.get("event_seq"),
            workflow_name=row.get("workflow_name"),
            workflow_version=row.get("workflow_version"),
            timestamp=_as_datetime(row.get("timestamp")),
            hash_alg=row.get("hash_alg"),
            on_behalf_of=row.get("on_behalf_of"),
            transition=row.get("transition"),
            payload=row.get("payload"),
            prev_event_hash=_as_bytes(row.get("prev_event_hash")),
            prev_global_event_hash=_as_bytes(row.get("prev_global_event_hash")),
            global_seq=row.get("global_seq"),
            canonical_envelope=_as_bytes(row.get("canonical_envelope")),
            signature=_as_bytes(row.get("signature")),
            payload_canonical_hash=_as_bytes(row.get("payload_canonical_hash")),
            row_scheme_id=row.get("scheme_id"),
            backend=backend,
        )


def _as_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    return bytes(value)


def _as_uuid(value: Any) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    return _uuid.UUID(str(value))


def _as_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Trusted key resolution — the scheme comes from HERE, never from the row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    material: bytes
    #: The authoritative scheme for this key. ``None`` only when the caller
    #: supplied raw key material with no accompanying metadata, in which case
    #: the row's claim is all there is and the result says so.
    scheme_id: str | None
    source: TrustedKeySource
    principal_id: str | None = None
    #: An already-instantiated scheme, used in preference to a registry lookup
    #: so a caller holding a scheme object (including a test-registered one)
    #: does not depend on the mutable global registry.
    scheme_obj: Any = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"TrustedKey(key_id={self.key_id!r}, material=<redacted>, "
            f"scheme_id={self.scheme_id!r}, source={self.source.value!r})"
        )


class TrustedKeyResolver(Protocol):
    """Resolves the ``key_id`` **from the signed envelope** to trusted material."""

    def resolve(self, key_id: str | None) -> TrustedKey | None: ...


@dataclass(frozen=True)
class StaticKeyResolver:
    """A single caller-supplied key.

    ``scheme_id=None`` means the caller supplied bare material with no trusted
    metadata; the row's claim is then used and ``scheme_id`` is reported in
    ``unsigned_fields``. Callers that *can* name the scheme should.
    """

    material: bytes
    scheme_id: str | None = None
    key_id: str | None = None
    source: TrustedKeySource = TrustedKeySource.SUPPLIED_PUBLIC_KEY
    principal_id: str | None = None
    scheme_obj: Any = None

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if self.key_id is not None and key_id is not None and key_id != self.key_id:
            return None
        return TrustedKey(
            key_id=key_id or self.key_id or "",
            material=self.material,
            scheme_id=self.scheme_id,
            source=self.source,
            principal_id=self.principal_id,
            scheme_obj=self.scheme_obj,
        )


@dataclass(frozen=True)
class KeySetResolver:
    """Resolves against a local :class:`~regista._keys.KeySet`.

    ``KeyEntry.scheme`` is the trusted metadata the write path already uses to
    pick the scheme, so it is what the read path must use too.
    """

    key_set: Any
    source: TrustedKeySource = TrustedKeySource.KEYSET_FILE

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if key_id is None or self.key_set is None:
            return None
        try:
            entry = self.key_set.get_key(key_id)
        except Exception:
            return None
        if entry is None:
            return None
        return _trusted_key_from_entry(entry, key_id, self.source)


def _trusted_key_from_entry(
    entry: Any, key_id: str, source: TrustedKeySource
) -> TrustedKey:
    from ._signing_scheme import asymmetric_scheme_ids

    scheme = getattr(entry, "scheme", None)
    public_key = getattr(entry, "public_key", None)
    secret = getattr(entry, "secret", None)
    material = secret
    if scheme in asymmetric_scheme_ids() and public_key:
        material = public_key
    if material is None:
        material = public_key
    return TrustedKey(
        key_id=key_id,
        material=bytes(material) if material is not None else b"",
        scheme_id=scheme,
        source=source,
        principal_id=getattr(entry, "principal_id", None),
    )


@dataclass(frozen=True)
class BundleKeyResolver:
    """Resolves against the public-key registry carried inside a bundle.

    The registry is *inside the artifact under verification* — a circular trust
    root (S5). That is out of scope for WI-267 and is why the source is reported
    as ``BUNDLE_EMBEDDED`` rather than a trusted root: the verdict boundary work
    reads this field.
    """

    keys_by_id: Mapping[str, Mapping[str, Any]]

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if key_id is None:
            return None
        entry = self.keys_by_id.get(key_id)
        if entry is None:
            return None
        return TrustedKey(
            key_id=key_id,
            material=entry["public_key"],
            scheme_id=entry.get("scheme"),
            source=TrustedKeySource.BUNDLE_EMBEDDED,
            principal_id=entry.get("principal_id"),
        )


# ---------------------------------------------------------------------------
# Comparison rules (FIELD-MATRIX §6)
# ---------------------------------------------------------------------------

_MAX_REPR = 48


def _repr_of(value: Any) -> str:
    """Short, redactable rendering — never a raw payload."""
    if value is None:
        return "<null>"
    if isinstance(value, bytes):
        return f"<{len(value)} bytes {value[:6].hex()}…>"
    if isinstance(value, dict | list):
        try:
            import hashlib

            digest = hashlib.sha256(canonicalize(value)).hexdigest()[:12]
        except Exception:
            digest = "?"
        kind = "object" if isinstance(value, dict) else "array"
        return f"<{kind} len={len(value)} jcs:{digest}>"
    text = str(value)
    if len(text) > _MAX_REPR:
        return text[:_MAX_REPR] + "…"
    return text


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "<absent>"


ABSENT = _Absent()


def _cmp_uuid(env_value: Any, row_value: Any) -> bool:
    if row_value is None:
        return False
    try:
        return _uuid.UUID(str(env_value)) == _as_uuid(row_value)
    except (ValueError, TypeError, AttributeError):
        return False


def _cmp_text(env_value: Any, row_value: Any) -> bool:
    if env_value is None or row_value is None:
        return env_value is None and row_value is None
    if not isinstance(env_value, str) or not isinstance(row_value, str):
        return False
    return env_value == row_value


def _cmp_int(env_value: Any, row_value: Any) -> bool:
    # Reject bool (a Python int subclass) and any float, integral or not: the
    # signed bytes for 1, 1.0 and true all differ.
    if isinstance(env_value, bool) or not isinstance(env_value, int):
        return False
    if isinstance(row_value, bool) or not isinstance(row_value, int):
        return False
    return env_value == row_value


def _cmp_nullable_int(env_value: Any, row_value: Any) -> bool:
    if env_value is None or row_value is None:
        return env_value is None and row_value is None
    return _cmp_int(env_value, row_value)


def _cmp_timestamp(env_value: Any, row_value: Any) -> bool:
    """Compare *instants*, not strings.

    The envelope stores a fixed ISO-8601 string; the row stores an instant that
    psycopg renders in the session time zone. The same row therefore yields
    different text under ``TZ=UTC`` and ``TZ=America/Phoenix``. That is a
    rendering artefact, not tamper. A naive/aware mix is refused rather than
    coerced.
    """
    if not isinstance(env_value, str) or not isinstance(row_value, datetime):
        return False
    try:
        parsed = datetime.fromisoformat(env_value)
    except (ValueError, TypeError):
        return False
    if (parsed.tzinfo is None) != (row_value.tzinfo is None):
        return False
    return parsed == row_value


def _cmp_hash_hex(env_value: Any, row_value: Any) -> bool:
    if not isinstance(env_value, str) or row_value is None:
        return False
    try:
        return bytes.fromhex(env_value) == _as_bytes(row_value)
    except (ValueError, TypeError):
        return False


def _cmp_json(env_value: Any, row_value: Any) -> bool:
    """Compare canonical JCS bytes.

    Not raw text (jsonb normalises key order and whitespace) and not Python
    ``==`` (which conflates ``1``/``1.0`` and ``True``/``1`` where the signed
    bytes differ).
    """
    try:
        return canonicalize(env_value) == canonicalize(row_value)
    except Exception:
        return False


# envelope field -> (row attribute, comparator)
_COMPARATORS: dict[str, Any] = {
    "event_id": ("event_id", _cmp_uuid),
    "work_item_id": ("work_item_id", _cmp_uuid),
    "entity_kind": ("entity_kind", _cmp_text),
    # Compared against the REAL column, never `effective_entity_id`. The
    # fallback-to-work_item_id property would let an attacker NULL the signed
    # `entity_id` column and still be told the field was authenticated
    # (`events_set_entity_id`, migration 031, is a BEFORE INSERT trigger — it
    # does not fire on UPDATE). `_cmp_uuid` returns False for a NULL row value,
    # so a NULL is a mismatch.
    "entity_id": ("entity_id", _cmp_uuid),
    "actor_id": ("actor_id", _cmp_text),
    "actor_kind": ("actor_kind", _cmp_text),
    "actor_metadata": ("actor_metadata", _cmp_json),
    "key_id": ("key_id", _cmp_text),
    "event_seq": ("event_seq", _cmp_int),
    "workflow_name": ("workflow_name", _cmp_text),
    "workflow_version": ("workflow_version", _cmp_int),
    "timestamp": ("timestamp", _cmp_timestamp),
    "hash_alg": ("hash_alg", _cmp_text),
    "on_behalf_of": ("on_behalf_of", _cmp_json),
    "transition": ("transition", _cmp_text),
    "payload": ("payload", _cmp_json),
    "prev_event_hash": ("prev_event_hash", _cmp_hash_hex),
    "prev_global_event_hash": ("prev_global_event_hash", _cmp_hash_hex),
    "global_seq": ("global_seq", _cmp_int),
}

#: Fields whose *nullability* is meaningful and which therefore compare
#: null-to-null cleanly rather than through the type comparator.
_NULLABLE_FIELDS = frozenset(
    {"actor_metadata", "on_behalf_of", "transition", "payload"}
)

#: Row columns that no version signs, plus per-version additions, form
#: ``unsigned_fields``. Keyed by envelope version.
_VERSION_UNSIGNED: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V1: frozenset(
        {
            "actor_kind",
            "actor_metadata",
            "entity_kind",
            "entity_id",
            "hash_alg",
            "key_id",
            "event_seq",
            "workflow_name",
            "workflow_version",
            "timestamp",
        }
    ),
    EnvelopeVersion.V2: frozenset(
        {"actor_kind", "actor_metadata", "entity_kind", "entity_id", "hash_alg"}
    ),
    EnvelopeVersion.V3: frozenset(
        {"actor_kind", "actor_metadata", "entity_kind", "entity_id", "hash_alg"}
    ),
    # work_item_id is not itself signed from v4 onward; it is nevertheless
    # *constrained* to equal the signed entity_id by the alias check below, so
    # it is safe to use as an entity identifier — it is listed here because it
    # carries no signature of its own.
    EnvelopeVersion.V4: frozenset({"actor_kind", "actor_metadata", "work_item_id"}),
    EnvelopeVersion.V5: frozenset({"work_item_id"}),
}


def _reconcile(
    envelope: Mapping[str, Any], version: EnvelopeVersion, row: EventRow
) -> tuple[list[FieldMismatch], set[str]]:
    """Total row↔envelope reconciliation for one envelope version.

    Every key the version *may* carry is checked, by presence for the
    presence-significant chain fields and by value for the always-emitted ones.
    """
    mismatches: list[FieldMismatch] = []
    authenticated: set[str] = set()

    checkable = _REQUIRED_FIELDS[version] | _OPTIONAL_FIELDS[version]
    for name in sorted(checkable):
        row_attr, comparator = _COMPARATORS[name]
        row_value = getattr(row, row_attr)
        present = name in envelope
        env_value = envelope.get(name, ABSENT)

        if name in _CHAIN_OPTIONAL:
            # Presence-significant: absent ⇔ row NULL. A row that gains a value
            # where the envelope omitted it is a mismatch, not a benign upgrade.
            if name == "global_seq":
                # UNSIGNED BY DESIGN (spec.md §17.11): assigned post-signing, so
                # absence reconciles against ANY row value. Never authenticated.
                if present and not comparator(env_value, row_value):
                    mismatches.append(
                        FieldMismatch(
                            field=name,
                            envelope_repr=_repr_of(env_value),
                            row_repr=_repr_of(row_value),
                        )
                    )
                continue
            if not present:
                if row_value is not None:
                    mismatches.append(
                        FieldMismatch(
                            field=name,
                            envelope_repr="<absent>",
                            row_repr=_repr_of(row_value),
                            presence_only=True,
                        )
                    )
                else:
                    authenticated.add(name)
                continue
            if row_value is None:
                mismatches.append(
                    FieldMismatch(
                        field=name,
                        envelope_repr=_repr_of(env_value),
                        row_repr="<null>",
                        presence_only=True,
                    )
                )
                continue
            if comparator(env_value, row_value):
                authenticated.add(name)
            else:
                mismatches.append(
                    FieldMismatch(
                        field=name,
                        envelope_repr=_repr_of(env_value),
                        row_repr=_repr_of(row_value),
                    )
                )
            continue

        # Always-emitted key: presence carries no information, the value does.
        if name in _NULLABLE_FIELDS and env_value is None and row_value is None:
            authenticated.add(name)
            continue
        if comparator(env_value, row_value):
            authenticated.add(name)
        else:
            mismatches.append(
                FieldMismatch(
                    field=name,
                    envelope_repr=_repr_of(env_value),
                    row_repr=_repr_of(row_value),
                )
            )

    # The alias check. work_item_id is the ORIGINAL 001 column; entity_id is
    # derived from it by the events_set_entity_id trigger (migration 031). From
    # v4 onward the signature covers entity_id and work_item_id is
    # unauthenticated, so without this check the unsigned column can steer a
    # consumer to a different work item than the one the signature covers.
    if version in (EnvelopeVersion.V4, EnvelopeVersion.V5):
        # A NULL on either side is a mismatch, not an exemption: both columns
        # are NOT NULL in the schema, so a NULL is already evidence that
        # something other than the append path wrote this row.
        if (
            row.work_item_id is None
            or row.entity_id is None
            or row.work_item_id != row.entity_id
        ):
            mismatches.append(
                FieldMismatch(
                    field="work_item_id!=entity_id",
                    envelope_repr=_repr_of(row.entity_id),
                    row_repr=_repr_of(row.work_item_id),
                )
            )

    authenticated.discard("global_seq")
    return mismatches, authenticated


def _cmp_v6_digest(env_value: Any, row_value: Any) -> bool:
    if env_value is None:
        return row_value is None
    if not isinstance(env_value, str) or not _V6_DIGEST_RE.fullmatch(env_value):
        return False
    try:
        return bytes.fromhex(env_value.removeprefix("sha256:")) == _as_bytes(row_value)
    except (TypeError, ValueError):
        return False


def _reconcile_v6(
    envelope: Mapping[str, Any], row: EventRow,
) -> tuple[list[FieldMismatch], set[str]]:
    entity = envelope["entity"]
    actor = envelope["actor"]
    signing = envelope["signing"]
    workflow = envelope["workflow"]
    chain = envelope["chain"]
    checks: tuple[tuple[str, str, Any, Any], ...] = (
        ("event_id", "event_id", envelope["event_id"], _cmp_uuid),
        ("entity_kind", "entity_kind", entity["kind"], _cmp_text),
        ("entity_id", "entity_id", entity["id"], _cmp_uuid),
        ("entity_seq", "event_seq", envelope["entity_seq"], _cmp_int),
        ("actor_id", "actor_id", actor["principal_id"], _cmp_text),
        ("actor_kind", "actor_kind", actor["kind"], _cmp_text),
        ("actor_metadata", "actor_metadata", actor["metadata"], _cmp_json),
        ("scheme_id", "row_scheme_id", signing["scheme_id"], _cmp_text),
        ("key_id", "key_id", signing["key_id"], _cmp_text),
        ("timestamp", "timestamp", envelope["occurred_at"], _cmp_timestamp),
        ("transition", "transition", envelope["transition"], _cmp_text),
        ("payload", "payload", envelope["payload"], _cmp_json),
        ("hash_alg", "hash_alg", chain["hash_algorithm"], _cmp_text),
        (
            "prev_event_hash",
            "prev_event_hash",
            chain["previous_entity_event_hash"],
            _cmp_v6_digest,
        ),
        (
            "prev_global_event_hash",
            "prev_global_event_hash",
            chain["previous_project_event_hash"],
            _cmp_v6_digest,
        ),
    )
    mismatches: list[FieldMismatch] = []
    authenticated: set[str] = set()
    for field, row_attr, env_value, comparator in checks:
        row_value = getattr(row, row_attr)
        if comparator(env_value, row_value):
            authenticated.add(field)
        else:
            mismatches.append(
                FieldMismatch(
                    field=field,
                    envelope_repr=_repr_of(env_value),
                    row_repr=_repr_of(row_value),
                )
            )

    workflow_checks = (
        ("workflow_name", workflow["name"] if workflow is not None else None, _cmp_text),
        (
            "workflow_version",
            workflow["version"] if workflow is not None else None,
            _cmp_nullable_int,
        ),
    )
    for field, env_value, comparator in workflow_checks:
        row_value = getattr(row, field)
        if comparator(env_value, row_value):
            authenticated.add(field)
        else:
            mismatches.append(
                FieldMismatch(
                    field=field,
                    envelope_repr=_repr_of(env_value),
                    row_repr=_repr_of(row_value),
                )
            )

    if row.work_item_id is None or row.entity_id is None or row.work_item_id != row.entity_id:
        mismatches.append(
            FieldMismatch(
                field="work_item_id!=entity_id",
                envelope_repr=_repr_of(row.entity_id),
                row_repr=_repr_of(row.work_item_id),
            )
        )
    return mismatches, authenticated


# ---------------------------------------------------------------------------
# The primitive
# ---------------------------------------------------------------------------

_KEYLESS_KEY_ID = "in-memory"
_KEYLESS_BYTES = b"\x00" * 32


def _is_keyless_dummy(row: EventRow) -> bool:
    """InMemory keyless material — an event that was never signed.

    All criteria must hold, and the last one is the point: a Postgres row
    exhibiting this byte pattern is an attack or a corrupted import, not an
    unsigned event, and must stay INVALID. The exemption is a property of the
    backend, not of the bytes.
    """
    return (
        row.backend is Backend.IN_MEMORY
        and row.key_id == _KEYLESS_KEY_ID
        and row.signature == _KEYLESS_BYTES
        and row.canonical_envelope == _KEYLESS_BYTES
        and row.payload_canonical_hash == _KEYLESS_BYTES
    )


class AbsentEnvelopeProbe(StrEnum):
    """Whether a row with NO stored envelope still agrees with its own crypto.

    ``canonical_envelope`` was added nullable and never backfilled (migration
    002), so a NULL is normally an evidentiary gap: nothing failed, there is
    nothing to check, and the verdict is ``UNVERIFIABLE``. But a NULL is also
    what an attacker gets by running ``UPDATE events SET canonical_envelope =
    NULL`` before rewriting the row — and the row still carries the
    ``signature`` and ``payload_canonical_hash`` the original envelope
    produced. Those two retained values can still contradict the row.

    This probe answers only that question. **It can never grant acceptance.**
    Its single actionable outcome is ``INCONSISTENT``, which makes a verdict
    *stricter* (``UNVERIFIABLE`` -> halt); ``CONSISTENT`` and ``UNKNOWN`` change
    nothing. :func:`verify_event_strict` does not call it, and no code path
    turns any of its outcomes into a pass. That asymmetry is what keeps it from
    being the rebuild-from-row escape hatch WI-267 deleted: the candidates are
    built from the columns under attack, so they may only ever be used to
    convict, never to acquit.

    The candidate shapes are the ones CUTOVER-POLICY §4.1 enumerates as
    plausible for a genuinely pre-002 row: v1, v1 with ``on_behalf_of``
    dropped, and v2.
    """

    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    UNKNOWN = "unknown"


def probe_absent_envelope(
    row: EventRow, *, keys: TrustedKeyResolver,
) -> AbsentEnvelopeProbe:
    """See :class:`AbsentEnvelopeProbe`. Convicts only; never acquits."""
    from ._signing import build_signing_envelope, build_signing_envelope_v2
    from ._signing_scheme import get_scheme, resolve_hash_function

    if row.canonical_envelope:
        return AbsentEnvelopeProbe.UNKNOWN
    signature = row.signature
    canonical_hash = row.payload_canonical_hash
    if not signature or not canonical_hash:
        return AbsentEnvelopeProbe.UNKNOWN
    if row.event_id is None or row.work_item_id is None or row.actor_id is None:
        return AbsentEnvelopeProbe.UNKNOWN

    trusted = keys.resolve(row.key_id)
    if trusted is None:
        return AbsentEnvelopeProbe.UNKNOWN
    scheme_id = trusted.scheme_id or row.row_scheme_id or "hmac-sha256"
    try:
        scheme = trusted.scheme_obj or get_scheme(scheme_id)
        # v1/v2 predate hash agility; sha-256 by construction.
        hash_fn = resolve_hash_function("sha-256")
    except Exception:
        return AbsentEnvelopeProbe.UNKNOWN

    candidates: list[bytes] = []
    try:
        candidates.append(
            build_signing_envelope(
                row.event_id, row.work_item_id, row.actor_id,
                row.transition, row.payload, row.on_behalf_of,
            )
        )
        if row.on_behalf_of is not None:
            candidates.append(
                build_signing_envelope(
                    row.event_id, row.work_item_id, row.actor_id,
                    row.transition, row.payload, None,
                )
            )
        if (
            row.key_id is not None
            and row.event_seq is not None
            and row.workflow_name is not None
            and row.workflow_version is not None
            and row.timestamp is not None
        ):
            candidates.append(
                build_signing_envelope_v2(
                    event_id=row.event_id,
                    work_item_id=row.work_item_id,
                    actor_id=row.actor_id,
                    key_id=row.key_id,
                    event_seq=row.event_seq,
                    workflow_name=row.workflow_name,
                    workflow_version=row.workflow_version,
                    timestamp=row.timestamp,
                    transition=row.transition,
                    payload=row.payload,
                    on_behalf_of=row.on_behalf_of,
                )
            )
    except Exception:
        return AbsentEnvelopeProbe.UNKNOWN

    for candidate in candidates:
        try:
            if hash_fn(candidate).digest() != canonical_hash:
                continue
            if scheme.verify(
                candidate, signature, canonical_hash, trusted.material,
                hash_alg="sha-256",
            ):
                return AbsentEnvelopeProbe.CONSISTENT
        except Exception:
            continue

    # No shape a pre-002 row could have carried reproduces the retained
    # signature over these column values. The envelope did not merely predate
    # the column; the row and its own crypto disagree.
    return AbsentEnvelopeProbe.INCONSISTENT


def _base_kwargs(row: EventRow) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "entity_kind": row.entity_kind,
        "entity_id": row.effective_entity_id,
        "global_seq": row.global_seq,
        "row_scheme_id": row.row_scheme_id,
    }


def _verify_v6_row(
    row: EventRow,
    envelope: Mapping[str, Any],
    *,
    keys: TrustedKeyResolver,
) -> VerificationResult:
    base = _base_kwargs(row)
    signing = envelope["signing"]
    chain = envelope["chain"]
    unsigned = frozenset({"global_seq", "on_behalf_of", "work_item_id"})
    trusted = keys.resolve(signing["key_id"])
    if trusted is None:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.V6,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=None,
            hash_alg=chain["hash_algorithm"],
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=signing["key_id"],
            unsigned_fields=frozenset(_ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            reasons=(FailureReason.KEY_UNRESOLVABLE,),
            detail=f"no trusted key for v6 key_id={signing['key_id']!r}",
        )

    trusted_scheme_id = trusted.scheme_id or signing["scheme_id"]
    if trusted_scheme_id != signing["scheme_id"]:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.V6,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=trusted_scheme_id,
            hash_alg=chain["hash_algorithm"],
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(_ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SCHEME_MISMATCH,),
            detail=(
                f"v6 envelope claims scheme={signing['scheme_id']!r} but the trusted key "
                f"claims {trusted.scheme_id!r}"
            ),
        )

    cryptographic = verify_v6_signature(
        row.canonical_envelope or b"",
        row.signature or b"",
        trusted.material,
        payload_canonical_hash=row.payload_canonical_hash,
        trusted_scheme_id=trusted_scheme_id,
    )
    common = {
        **base,
        "envelope_version": EnvelopeVersion.V6,
        "envelope_present": True,
        "envelope_schema_valid": True,
        "signature_valid": cryptographic.signature_valid,
        "scheme_id": trusted_scheme_id,
        "hash_alg": chain["hash_algorithm"],
        "trusted_key_source": trusted.source,
        "trusted_key_id": trusted.key_id,
        "principal_id": trusted.principal_id,
    }
    if (
        not cryptographic.signature_valid
        or cryptographic.payload_canonical_hash_valid is not True
    ):
        reason = (
            FailureReason.CANONICAL_HASH_MISMATCH
            if cryptographic.payload_canonical_hash_valid is not True
            else FailureReason.SIGNATURE_INVALID
        )
        detail = "; ".join(cryptographic.errors)
        if not detail and cryptographic.payload_canonical_hash_valid is None:
            detail = "payload_canonical_hash is required for a stored v6 row"
        return VerificationResult(
            **common,
            unsigned_fields=frozenset(_ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(reason,),
            detail=detail,
        )

    mismatches, authenticated = _reconcile_v6(envelope, row)
    prev_ok = "prev_event_hash" in authenticated
    prev_global_ok = "prev_global_event_hash" in authenticated
    if mismatches:
        reasons: list[FailureReason] = [FailureReason.ROW_FIELD_MISMATCH]
        if any(m.field == "work_item_id!=entity_id" for m in mismatches):
            reasons.append(FailureReason.ENTITY_ALIAS_MISMATCH)
        if any(m.field == "key_id" for m in mismatches):
            reasons.append(FailureReason.KEY_ID_MISMATCH)
        if any(m.field == "scheme_id" for m in mismatches):
            reasons.append(FailureReason.SCHEME_MISMATCH)
        return VerificationResult(
            **common,
            row_reconciled=False,
            mismatched_fields=tuple(mismatches),
            authenticated_fields=frozenset(authenticated),
            unsigned_fields=unsigned,
            prev_event_hash_ok=prev_ok,
            prev_global_event_hash_ok=prev_global_ok,
            applicability=Applicability.INVALID,
            reasons=tuple(reasons),
            detail=(
                "row disagrees with the v6 signed envelope on: "
                + ", ".join(str(m) for m in mismatches)
            ),
        )

    return VerificationResult(
        **common,
        row_reconciled=True,
        authenticated_fields=frozenset(authenticated),
        unsigned_fields=unsigned,
        prev_event_hash_ok=prev_ok,
        prev_global_event_hash_ok=prev_global_ok,
        applicability=Applicability.INVALID,
        reasons=(FailureReason.ENVELOPE_SCHEMA_INCOMPLETE,),
        detail=(
            "v6 bytes and duplicated row fields verify; project, trust, key-binding, "
            "workflow and delegation referents require the v6 verifier boundary"
        ),
    )


def verify_event_strict(
    row: EventRow,
    *,
    keys: TrustedKeyResolver,
    policy: VerificationPolicy = DEFAULT_POLICY,
) -> VerificationResult:
    """Verify the stored envelope bytes, then reconcile the row against them.

    This is the only function in the tree that decides whether an event is
    authenticated. Any path that reimplements part of it is a bug.
    """
    from ._signing_scheme import get_scheme, resolve_hash_function

    base = _base_kwargs(row)

    # (1) Never-signed row columns are reported unsigned in every outcome.
    unsigned: set[str] = set(_NEVER_SIGNED)

    # (2) An event that was never signed is UNVERIFIABLE, not INVALID. Detected
    #     before parsing: the dummy envelope is not JSON and would otherwise be
    #     reported as "tampered with", which it was not.
    if _is_keyless_dummy(row):
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.KEYLESS_DUMMY,
            envelope_present=False,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            accepted=policy.accept_unsigned_keyless,
            reasons=(FailureReason.UNSIGNED_EVENT,),
            detail="keyless InMemory event: never signed, nothing to verify",
        )

    # (3) No stored envelope at all (pre-002 rows). Nothing failed; there is
    #     nothing to check. UNVERIFIABLE, never INVALID — the operator response
    #     is completely different.
    if not row.canonical_envelope:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.ABSENT,
            envelope_present=False,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            reasons=(FailureReason.ENVELOPE_ABSENT,),
            detail="no stored canonical_envelope; offline reconstruction is an "
            "explicit operator action, never a verify-path fallback",
        )

    stored = row.canonical_envelope

    # (4) Strict parse. No fallback to a rebuilt candidate from here on.
    try:
        envelope = parse_envelope_strict(stored)
    except (ValueError, TypeError) as exc:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.UNPARSEABLE,
            envelope_present=True,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.ENVELOPE_UNPARSEABLE,),
            detail=f"stored envelope is not canonical JSON: {exc}",
        )

    if "type" in envelope or "version" in envelope:
        try:
            envelope = parse_v6_envelope_strict(stored)
            version = EnvelopeVersion.V6
        except (V6EnvelopeError, TypeError, ValueError) as exc:
            version = classify_envelope_bytes(stored)
            if version is EnvelopeVersion.UNPARSEABLE:
                reason = FailureReason.ENVELOPE_UNPARSEABLE
            elif version is EnvelopeVersion.UNCANONICAL:
                reason = FailureReason.ENVELOPE_UNCANONICAL
            else:
                reason = FailureReason.ENVELOPE_UNKNOWN_SCHEMA
            return VerificationResult(
                **base,
                envelope_version=version,
                envelope_present=True,
                envelope_schema_valid=False,
                signature_valid=False,
                scheme_id=None,
                hash_alg=None,
                trusted_key_source=TrustedKeySource.NONE,
                trusted_key_id=None,
                unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
                applicability=Applicability.INVALID,
                reasons=(reason,),
                detail=f"stored v6 envelope failed strict validation: {exc}",
            )
    else:
        version = classify_envelope(envelope)
    if version is EnvelopeVersion.UNKNOWN_SCHEMA:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.ENVELOPE_UNKNOWN_SCHEMA,),
            detail=(
                "stored envelope matches no known schema strictly "
                f"(keys={sorted(envelope)[:12]}); the permissive classifier "
                "this replaced would have called it v1"
            ),
        )

    if version is EnvelopeVersion.V6:
        return _verify_v6_row(row, envelope, keys=keys)

    version_unsigned = unsigned | _VERSION_UNSIGNED[version]

    # (5) The verification key is resolved from the ENVELOPE's key_id, never the
    #     row's. A row-only key_id rewrite therefore surfaces as a
    #     reconciliation mismatch, not as an ambiguous "unknown key".
    envelope_key_id = envelope.get("key_id")
    if version is EnvelopeVersion.V1:
        # v1 signs no key_id at all: key selection for a v1 event is itself
        # unauthenticated, and the result must carry that.
        envelope_key_id = row.key_id
    lookup_key_id = envelope_key_id if isinstance(envelope_key_id, str) else None

    trusted = keys.resolve(lookup_key_id)
    if trusted is None:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=lookup_key_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            reasons=(FailureReason.KEY_UNRESOLVABLE,),
            detail=f"no trusted key for key_id={lookup_key_id!r}",
        )

    # (6) S2-interim: the scheme comes from trusted key metadata. Where the
    #     registry names a scheme, it wins, and disagreement with the row's
    #     self-declared scheme_id is an error — relabelling an ed25519 event as
    #     hmac-sha256 must not exempt it from asymmetric verification.
    derived_scheme_id = trusted.scheme_id
    if derived_scheme_id is None:
        derived_scheme_id = row.row_scheme_id or "hmac-sha256"
    elif row.row_scheme_id is not None and row.row_scheme_id != derived_scheme_id:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=None,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SCHEME_MISMATCH,),
            detail=(
                f"row claims scheme_id={row.row_scheme_id!r} but the trusted key "
                f"{trusted.key_id!r} is {derived_scheme_id!r}; the key's scheme wins"
            ),
        )

    try:
        scheme = trusted.scheme_obj or get_scheme(derived_scheme_id)
    except Exception as exc:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=None,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SCHEME_UNRESOLVABLE,),
            detail=f"cannot resolve signing scheme {derived_scheme_id!r}: {exc}",
        )

    # (7) The hash algorithm comes from the ENVELOPE for v4/v5, so a row-only
    #     hash_alg rewrite is a reconciliation failure rather than an ambiguous
    #     signature failure. v1-v3 never signed it and are sha-256 by
    #     construction.
    if version in (EnvelopeVersion.V4, EnvelopeVersion.V5):
        env_hash_alg = envelope.get("hash_alg")
        effective_hash_alg = env_hash_alg if isinstance(env_hash_alg, str) else "sha-256"
    else:
        effective_hash_alg = "sha-256"

    signature = row.signature or b""
    canonical_hash = row.payload_canonical_hash or b""

    # (8) Defence in depth: the SigningScheme protocol does not *require* an
    #     implementation to check envelope_hash, so check it here rather than
    #     trusting every scheme to.
    try:
        hash_fn = resolve_hash_function(effective_hash_alg)
        computed = hash_fn(stored).digest()
    except Exception as exc:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.CANONICAL_HASH_MISMATCH,),
            detail=f"cannot resolve hash algorithm {effective_hash_alg!r}: {exc}",
        )

    import hmac as _hmac

    if not _hmac.compare_digest(computed, canonical_hash):
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.CANONICAL_HASH_MISMATCH,),
            detail="payload_canonical_hash does not match the stored envelope",
        )

    try:
        signature_valid = bool(
            scheme.verify(
                stored,
                signature,
                canonical_hash,
                trusted.material,
                hash_alg=effective_hash_alg,
            )
        )
    except Exception:
        signature_valid = False

    if not signature_valid:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SIGNATURE_INVALID,),
            detail=(
                f"signature invalid over the stored envelope under trusted key "
                f"{trusted.key_id!r} ({derived_scheme_id})"
            ),
        )

    # (9) Total reconciliation. The signature proves what the signer committed
    #     to; a row that disagrees was written by something other than the
    #     append path.
    mismatches, authenticated = _reconcile(envelope, version, row)

    prev_ok: bool | None = None
    if "prev_event_hash" in authenticated or any(
        m.field == "prev_event_hash" for m in mismatches
    ):
        prev_ok = "prev_event_hash" in authenticated
    prev_global_ok: bool | None = None
    if "prev_global_event_hash" in authenticated or any(
        m.field == "prev_global_event_hash" for m in mismatches
    ):
        prev_global_ok = "prev_global_event_hash" in authenticated

    if mismatches:
        reasons: list[FailureReason] = [FailureReason.ROW_FIELD_MISMATCH]
        if any(m.field == "work_item_id!=entity_id" for m in mismatches):
            reasons.append(FailureReason.ENTITY_ALIAS_MISMATCH)
        if any(m.field == "key_id" for m in mismatches):
            reasons.append(FailureReason.KEY_ID_MISMATCH)
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=True,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            row_reconciled=False,
            mismatched_fields=tuple(mismatches),
            authenticated_fields=frozenset(authenticated),
            unsigned_fields=frozenset(version_unsigned),
            prev_event_hash_ok=prev_ok,
            prev_global_event_hash_ok=prev_global_ok,
            applicability=Applicability.INVALID,
            reasons=tuple(reasons),
            detail=(
                "row disagrees with the signed envelope on: "
                + ", ".join(str(m) for m in mismatches)
            ),
        )

    # (10) The signature is valid over the stored bytes and the row agrees on
    #      every field this version signs. What remains is a policy question
    #      about the version itself.
    common = {
        **base,
        "envelope_version": version,
        "envelope_present": True,
        "envelope_schema_valid": True,
        "signature_valid": True,
        "scheme_id": derived_scheme_id,
        "hash_alg": effective_hash_alg,
        "trusted_key_source": trusted.source,
        "trusted_key_id": trusted.key_id,
        "principal_id": trusted.principal_id,
        "row_reconciled": True,
        "authenticated_fields": frozenset(authenticated),
        "unsigned_fields": frozenset(version_unsigned),
        "prev_event_hash_ok": prev_ok,
        "prev_global_event_hash_ok": prev_global_ok,
    }

    if version in policy.full_authentication_versions:
        return VerificationResult(
            **common,
            applicability=Applicability.FULLY_AUTHENTICATED,
            accepted=True,
        )

    watermark = policy.accept_legacy_before_global_seq
    over_watermark = (
        watermark is not None
        and row.global_seq is not None
        and row.global_seq >= watermark
    )
    if version in policy.accept_legacy_versions and not over_watermark:
        return VerificationResult(
            **common,
            applicability=Applicability.LEGACY_PARTIAL,
            accepted=True,
            reasons=(FailureReason.LEGACY_ENVELOPE_VERSION,),
            legacy_reason=(
                f"envelope {version.value} does not sign "
                + ", ".join(sorted(version_unsigned))
                + "; those fields are unauthenticated for this event"
            ),
        )

    detail = (
        f"envelope {version.value} is not accepted by policy "
        f"(accept_legacy_versions={sorted(v.value for v in policy.accept_legacy_versions)})"
    )
    if over_watermark:
        detail = (
            f"envelope {version.value} at global_seq={row.global_seq} is at or "
            f"above the cutover watermark {watermark}: a legacy envelope written "
            "after the cutover is a regression, not history"
        )
    return VerificationResult(
        **common,
        applicability=Applicability.INVALID,
        reasons=(FailureReason.LEGACY_ENVELOPE_VERSION,),
        detail=detail,
    )
