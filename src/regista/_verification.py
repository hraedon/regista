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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as _dc_field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Protocol
from uuid import UUID

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._lineage import MODEL_LINEAGE_FAMILIES

# TRUST-DOMAIN.md §2.6 reporting vocabulary and the single canonical-grammar
# implementation. `_principals` is pure (hashlib/re/unicodedata) and imports nothing from
# regista but `_errors`, so this is safe at module scope. Note what is *absent*:
# `_principal_alias` is never imported here or anywhere a binding check can reach — §2.5
# requires that "no verifier code path may load aliases before the binding check", and
# criterion 21 is proven structurally by that absence
# (`tests/test_p23_principal_binding_isolation.py`).
from ._principals import (
    IdentityConsistency,
    MappingStatus,
    classify_principal_id,
    identity_consistency,
    mapping_status,
    principal_id_kind,
)

# The presented material (TRUST-DOMAIN.md §5.10, §8.4). `_v6_referents` imports
# nothing from regista at module scope but `_errors`, so this is not a cycle; the two
# functions it needs from here and from `_signing` are imported lazily inside it.
from ._v6_referents import (
    NO_REFERENTS,
    MaterialCompleteness,
    ReferentEvent,
    ReferentResolver,
    resolve_completeness,
    walk_project_chain,
)

__all__ = [
    "NO_REFERENTS",
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
    "Attribution",
    "Backend",
    "BundleKeyResolver",
    "CheckpointBinding",
    "EnvelopeVersion",
    "EpochPosition",
    "EventRow",
    "FailureReason",
    "FieldMismatch",
    "KeyBinding",
    "KeySetResolver",
    "MaterialCompleteness",
    "ProducerConsistency",
    "ReferentEvent",
    "ReferentResolver",
    "RevocationStatus",
    "RootGovernance",
    "StaticKeyResolver",
    "TrustRoot",
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
    #: Resolved by replaying signed trust-log lifecycle events (§8.1). Never from
    #: ``principal_keys`` — that is the S6 defect (§5.9 rule 1).
    TRUST_DOMAIN_LOG = "trust_domain_log"
    #: Chains to a genesis root the *caller* pinned out of band (§4.6, §8.4).
    EXTERNALLY_PINNED = "externally_pinned"
    NONE = "none"


# --- RESULT-MODEL.md §10.1's v6 vocabulary ---------------------------------
#
# Every one of these is reported on *every* result, with an explicit "not
# established" member rather than an absence, because §10.2 invariant 9 is
# "missing pins produce explicit unbound / not-checked states. A check is never
# silently skipped because its input was absent."


class EpochPosition(StrEnum):
    PRE_CUTOVER = "pre_cutover"
    IS_CUTOVER = "is_cutover"
    POST_CUTOVER = "post_cutover"
    NO_CUTOVER = "no_cutover"
    UNKNOWN = "unknown"


class Attribution(StrEnum):
    """Whether the signature attributes the event to *someone*.

    ``SHARED_SECRET`` is the HMAC epoch's honest label: possession of the secret is
    not identity (WI-278), so an HMAC event may never imply origin authentication.
    """

    INDIVIDUAL = "individual"
    SHARED_SECRET = "shared_secret"
    NONE = "none"


class CheckpointBinding(StrEnum):
    EXTERNALLY_PINNED = "externally_pinned"
    CHECKPOINT_BOUND = "checkpoint_bound"
    UNBOUND = "unbound"
    NOT_APPLICABLE = "not_applicable"


class TrustRoot(StrEnum):
    """Where the authority to believe the signing key comes from (§8.3).

    ``TRUST_LOG_ONLY`` is "the honest middle state and the one most online
    verifications will report": the log is present and internally consistent, but no
    caller-supplied policy pins the genesis. ``BUNDLED_ONLY`` is weaker still — the
    key evidence is inside the material under verification (§8.2, S5) — and is
    deliberately *not* ``ABSENT``, because the bytes really are there.
    """

    EXTERNALLY_PINNED = "externally_pinned"
    TRUST_LOG_ONLY = "trust_log_only"
    BUNDLED_ONLY = "bundled_only"
    ABSENT = "absent"


class RootGovernance(StrEnum):
    CO_SIGNED = "co_signed"
    SOLO = "solo"
    SOLO_EFFECTIVE = "solo_effective"
    UNKNOWN = "unknown"


class KeyBinding(StrEnum):
    """§5.10's outcome for "was this key accepted in this project before use"."""

    ACCEPTED_IN_PROJECT = "accepted_in_project"
    BOOTSTRAP_EXTERNAL = "bootstrap_external"
    TRUST_LOG_ONLY = "trust_log_only"
    RETROSPECTIVE = "retrospective"
    LEGACY_REGISTRY = "legacy_registry"
    LEGACY_UNBOUND = "legacy_unbound"
    UNRESOLVED = "unresolved"
    MISMATCHED = "mismatched"
    AFTER_USE = "after_use"
    RECOVERY_ROTATED = "recovery_rotated"


class RevocationStatus(StrEnum):
    NOT_REVOKED = "not_revoked"
    REVOKED_BEFORE_USE = "revoked_before_use"
    INDETERMINATE_WINDOW = "indeterminate_window"
    SUSPECT_DECLARED = "suspect_declared"
    UNKNOWN = "unknown"


class ProducerConsistency(StrEnum):
    MATCHES_PUBLISHED_POLICY = "matches_published_policy"
    CONTRADICTS_PUBLISHED_POLICY = "contradicts_published_policy"
    POLICY_NOT_SUPPLIED = "policy_not_supplied"
    NOT_APPLICABLE = "not_applicable"


#: ``unbound_properties`` vocabulary — **semantic** names, deliberately disjoint from
#: ``unsigned_fields``' row-column names (§10.2 invariant 8: "one answers 'which
#: column was not covered by a signature', the other 'which property is not
#: established at all'"). Spelled as constants so a report and a test cannot drift.
UNBOUND_EXTERNAL_TRUST_PIN: Final[str] = "external_trust_pin"
#: Distinct from the above on purpose. ``external_trust_pin`` means "the caller
#: supplied no trust policy"; this means "this bootstrap event's authority is external
#: by construction and the presented material does not establish it" — which stays true
#: *with* a pin, because §5.8 requires the trust log as well. Collapsing the two would
#: make a report say "no pin supplied" to a caller who supplied one.
UNBOUND_BOOTSTRAP_AUTHORITY: Final[str] = "bootstrap_external_authority"
UNBOUND_TRUST_LOG_REVOCATION: Final[str] = "trust_log_revocation"
UNBOUND_ROOT_GOVERNANCE: Final[str] = "root_governance"
UNBOUND_DELEGATION_CHAIN: Final[str] = "delegation_chain"
UNBOUND_PRODUCER_POLICY: Final[str] = "producer_policy"
UNBOUND_KEY_BINDING: Final[str] = "key_binding"


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
    # --- v6 referents (RESULT-MODEL.md §10.1, TRUST-DOMAIN.md §5.10/§5.11) ----
    #: The envelope binds a project/trust-domain the caller's pin contradicts.
    PROJECT_BINDING_MISMATCH = "project_binding_mismatch"
    TRUST_DOMAIN_MISMATCH = "trust_domain_mismatch"
    #: §5.11 row 1 — ``h_A`` is not in the material and the material claims nothing.
    #: Absence of evidence: ``UNVERIFIABLE``, never ``INVALID``.
    KEY_BINDING_UNRESOLVED = "key_binding_unresolved"
    #: §5.11 row 2 — ``h_A`` is not in material that *claims completeness*. The
    #: claim is false, which is a fact about the artifact: ``INVALID``.
    KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE = "key_binding_missing_from_complete_scope"
    #: §5.11 row 3 — the anchor resolves to something that is not an acceptance for
    #: this principal/key/project.
    KEY_BINDING_MISMATCH = "key_binding_mismatch"
    #: §5.11 row 4 / §9 criterion 14. ``ENROLLMENT_AFTER_USE`` is §5.11's spelling
    #: and ``KEY_BINDING_NOT_BEFORE_USE`` is ``RESULT-MODEL.md`` §10.1's; they name
    #: the same step-3 failure. Both exist because both documents are normative for
    #: their own vocabulary, and a report that used one name would be unsearchable
    #: from the other. ``ENROLLMENT_AFTER_USE`` is the one emitted.
    ENROLLMENT_AFTER_USE = "enrollment_after_use"
    KEY_BINDING_NOT_BEFORE_USE = "key_binding_not_before_use"
    #: ``RECONCILIATION.md`` Resolution 1 — a null ``key_binding_event_hash`` outside
    #: the three permitted bootstrap positions.
    KEY_BINDING_BOOTSTRAP_NOT_PERMITTED = "key_binding_bootstrap_not_permitted"
    #: §5.10 step 4 — a ``principal_key_acceptance_revoked`` lies between A and E.
    KEY_ACCEPTANCE_REVOKED = "key_acceptance_revoked"
    WORKFLOW_DEFINITION_MISMATCH = "workflow_definition_mismatch"
    WORKFLOW_REGISTRATION_UNRESOLVED = "workflow_registration_unresolved"
    DELEGATION_CHAIN_INVALID = "delegation_chain_invalid"
    EPOCH_VIOLATION = "epoch_violation"
    PRODUCER_POLICY_MISMATCH = "producer_policy_mismatch"


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

#: The CLOSED v6 entity-kind registry (``V6-ENVELOPE.md`` §1.2). Exactly six
#: values, and "closed" is the load-bearing word: a kind outside this set is not
#: an unrecognised extension to be tolerated, it is a refusal. This is the single
#: definition — ``_genesis``, ``_v6_writer`` and ``_replay`` all import it rather
#: than restating it, because three hand-copied frozensets are three chances for
#: the registry to stop being one registry.
V6_ENTITY_KINDS: frozenset[str] = frozenset(
    {
        "work_item",
        "project",
        "principal",
        "trust_domain",
        "project_instance",
        "workflow",
    }
)
_V6_ENTITY_KINDS = V6_ENTITY_KINDS
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
# The canonical principal grammar formerly had a second copy here. It now lives in
# `regista._principals` (TRUST-DOMAIN.md §2.1) and `_v6_require_principal_id` delegates —
# two implementations of a grammar are two grammars.
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
    """Enforce the §2.1 canonical grammar on a v6 envelope's ``actor.principal_id``.

    P2.3 replaced a second, hand-rolled copy of the grammar here with a delegation to
    ``regista._principals``, which is now the single implementation. The rules checked are
    identical (closed lowercase kinds, subject = everything after the first colon, 1..247
    subject chars from the §2.1 class, no ``:.-_/`` at either edge, ASCII, ≤ 256 bytes) plus
    two the local copy omitted: the NFC assertion, and the named ``key:*`` refusal.

    This is *not* a §2.7 "Verification … Never" violation. It is v6 **schema** validation:
    a v6 envelope exists only post-cutover, so its actor is held to the post-cutover
    standard. Legacy (v1-v5) rows never reach this function — they are reconciled through
    ``_reconcile``, which compares strings and validates no grammar.
    """
    _v6_require_string(value, "actor.principal_id", non_empty=True, max_length=255)
    classification = classify_principal_id(value)
    _v6_require(
        classification.canonical,
        f"actor.principal_id must use the canonical kind:subject grammar "
        f"(TRUST-DOMAIN.md §2.1): {classification.reason}",
    )


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
    if producer["model_lineage"] is not None:
        _v6_require(
            producer["model_lineage"] in MODEL_LINEAGE_FAMILIES,
            "producer.model_lineage must name a registered model family",
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

    #: Envelope versions that may report FULLY_AUTHENTICATED. v5 was the floor:
    #: it is the only *legacy* version that signs actor_kind/actor_metadata, which
    #: is what the review gate and assurance make decisions from. **v6 is here
    #: too**, and it has to be: without it no v6 event could ever be
    #: ``FULLY_AUTHENTICATED`` no matter how completely §5.10 succeeded, which is
    #: the easiest possible way to ship a verifier boundary that does nothing.
    full_authentication_versions: frozenset[EnvelopeVersion] = frozenset(
        {EnvelopeVersion.V5, EnvelopeVersion.V6}
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

    # --- v6 pins (RESULT-MODEL.md §10.1, TRUST-DOMAIN.md §8.4) ---------------
    #
    # All four are things the verifier is **given** by the caller, out of band. None
    # of them is ever read from the store, the bundle, or the network: "a verifier
    # that silently fetches its own trust material has no trust root at all; it has
    # whatever the network gave it" (§8.4). Every one defaults to "not supplied",
    # and an unsupplied pin produces an explicit unbound state — never a skipped
    # check (§10.2 invariant 9).

    #: The project this material is expected to be. A v6 envelope binding a
    #: different ``project_instance_id`` is ``INVALID``/``PROJECT_BINDING_MISMATCH``
    #: — cross-project replay of a validly signed event is the attack this closes.
    pinned_project_instance_id: str | None = None
    #: The trust domain the caller pinned (§4.6 trust policy). Supplying it is one
    #: of the two conditions for ``trust_root: externally_pinned``; the other is the
    #: trust log actually being presented (§5.8: "with the trust log and the pin it
    #: reports ``externally_pinned``"). A pin alone cannot manufacture an external
    #: root out of material that carries no lifecycle evidence.
    pinned_trust_domain_id: str | None = None
    #: The event hash of the project's cutover checkpoint / genesis, pinned out of
    #: band. Turns ``checkpoint_binding`` from ``checkpoint_bound`` (the material
    #: contains *a* bootstrap event) into ``externally_pinned`` (it contains *the*
    #: one the caller named), which is what ``RECONCILIATION.md`` Resolution 1's
    #: Bootstrap-B position requires before a bootstrap event may be fully
    #: authenticated.
    cutover_checkpoint_event_hash: str | None = None
    #: The published producer policy (``TRUST-DOMAIN.md`` §4.3), as a sequence of
    #: ``regista._v6_writer.ProducerPolicyEntry``. ``None`` reports
    #: ``producer_consistency: policy_not_supplied``, which is an explicit state.
    #: Typed loosely to keep ``_verification`` free of a ``_v6_writer`` import (the
    #: dependency runs the other way).
    producer_policy: Sequence[Any] | None = None
    #: An **explicit tightening** of the presented material's own completeness claim
    #: (§5.11). ``None`` — the default — means "the material's claim governs", and
    #: the material's claim is where completeness structurally belongs: a store
    #: connection knows it is complete, a windowed bundle knows it is not. This
    #: field exists for the caller who knows *more* than the material does. It is
    #: tighten-only: an attempt to soften ``complete_store`` into
    #: ``contiguous_range`` raises, because that would convert §5.11's ``INVALID``
    #: row into its ``UNVERIFIABLE`` row by flag, which is the no-fallback rule with
    #: extra steps.
    material_completeness: MaterialCompleteness | None = None


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

    # --- identity consistency (TRUST-DOMAIN.md §2.6) ---------------------
    # Reporting only. §2.6 requires the conflict state be *computed and surfaced*, and
    # §2.7's last row forbids verification from refusing on grammar, so none of these four
    # fields participates in any verdict. `actor_kind` is in `unsigned_fields` for every
    # envelope below v5 (see `_VERSION_UNSIGNED`), which is what makes it a reporting label
    # there and never security-relevant evidence; a consumer reading `actor_kind` for a
    # security decision must assert `"actor_kind" in result.authenticated_fields`.
    #: The canonical kind prefix, or ``None`` for a bare legacy id (§2.6).
    actor_id_kind: str | None = None
    #: The row/envelope ``actor_kind`` field, echoed for the comparison's sake (§2.6).
    actor_kind: str | None = None
    identity_consistency: IdentityConsistency = IdentityConsistency.CONSISTENT
    #: Whether a deliberate ``actor_id → principal_id`` assignment exists for this writer.
    #: ``not_evaluated`` unless the caller supplied a mapping population.
    actor_principal_mapping: MappingStatus = MappingStatus.NOT_EVALUATED

    @property
    def actor_kind_authenticated(self) -> bool:
        """§2.6 ``actor_kind_authenticated``: ``False`` for every pre-v5 envelope.

        Derived from the authoritative source — ``unsigned_fields`` — rather than stored,
        so the two can never disagree.
        """
        return "actor_kind" in self.authenticated_fields

    # --- reconciliation -------------------------------------------------
    row_reconciled: bool = False
    mismatched_fields: tuple[FieldMismatch, ...] = ()
    authenticated_fields: frozenset[str] = frozenset()
    unsigned_fields: frozenset[str] = frozenset()

    # --- chain ----------------------------------------------------------
    prev_event_hash_ok: bool | None = None
    prev_global_event_hash_ok: bool | None = None

    # --- v6 semantics (RESULT-MODEL.md §10.1) ---------------------------
    #
    # These eleven are "non-optional" in §10.1's sense: every result reports every
    # one of them, with an explicit not-established member instead of an absence.
    # They carry dataclass defaults naming that state so the ~30 legacy construction
    # sites are not made to restate "unknown" eleven times — and a v6 result that
    # *left* them at the default would be claiming nothing while the boundary
    # believes it checked something, so `__post_init__` refuses exactly that. The
    # default is therefore the honest legacy answer and a mechanical error for v6,
    # which is stricter than either "all defaults" or "39 explicit call sites".
    epoch_position: EpochPosition = EpochPosition.UNKNOWN
    attribution: Attribution = Attribution.NONE
    checkpoint_binding: CheckpointBinding = CheckpointBinding.NOT_APPLICABLE
    #: Semantic vocabulary: properties not established *at all*. Deliberately
    #: disjoint from ``unsigned_fields``, which is row-column vocabulary (§10.2
    #: invariant 8).
    unbound_properties: frozenset[str] = frozenset()
    trust_domain_id: str | None = None
    trust_root: TrustRoot = TrustRoot.ABSENT
    root_governance: RootGovernance = RootGovernance.UNKNOWN
    key_binding: KeyBinding = KeyBinding.UNRESOLVED
    revocation_status: RevocationStatus = RevocationStatus.UNKNOWN
    producer_consistency: ProducerConsistency = ProducerConsistency.NOT_APPLICABLE
    #: The resolved key-binding anchor's event hash, for reports and for a caller
    #: that wants to fetch the anchor. ``None`` when no anchor was resolved.
    key_binding_event_hash: str | None = None

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
        self._check_v6_invariants()

    # -- RESULT-MODEL.md §10.2 / TRUST-DOMAIN.md §8.3 -----------------------
    #
    # Asserts, not conventions, for the same reason the four above are: a
    # convention is a thing a later change can forget.
    def _check_v6_invariants(self) -> None:
        def fail(text: str) -> None:
            raise AssertionError(f"VerificationResult invariant violated: {text}")

        # §10.2 invariant 10 (retained from §8.3), applies to every version.
        if self.key_binding in (KeyBinding.MISMATCHED, KeyBinding.AFTER_USE) and (
            self.applicability is not Applicability.INVALID
        ):
            fail(
                f"key_binding={self.key_binding.value!r} is a contradiction and is "
                f"always INVALID, not {self.applicability.value!r}"
            )
        if self.revocation_status is RevocationStatus.REVOKED_BEFORE_USE and (
            self.applicability is not Applicability.INVALID
        ):
            fail("revocation_status=revoked_before_use is always INVALID")
        if self.key_binding is KeyBinding.RETROSPECTIVE:
            if self.applicability is Applicability.FULLY_AUTHENTICATED:
                fail("a retrospective key binding is never FULLY_AUTHENTICATED (§6.4)")
            if self.legacy_reason != "retrospective_key_binding":
                fail(
                    "key_binding=retrospective must carry "
                    "legacy_reason='retrospective_key_binding'"
                )
        if self.key_binding is KeyBinding.LEGACY_REGISTRY:
            if self.envelope_version is EnvelopeVersion.V6:
                # §5.9 rule 1: "resolving via PRINCIPAL_REGISTRY is a programming
                # error and raises". This is the raise.
                fail(
                    "a v6 event resolved its key from the principal_keys projection; "
                    "TRUST-DOMAIN.md §5.9 rule 1 makes that a programming error, not "
                    "a degraded result"
                )
            if self.applicability is Applicability.FULLY_AUTHENTICATED:
                fail("key_binding=legacy_registry is never FULLY_AUTHENTICATED")
            if "key_binding" not in self.unsigned_fields:
                fail(
                    "key_binding=legacy_registry must report 'key_binding' in "
                    "unsigned_fields"
                )

        if self.envelope_version is not EnvelopeVersion.V6:
            return

        if self.key_binding is KeyBinding.LEGACY_UNBOUND:
            fail("legacy_unbound is the HMAC epoch's binding and never a v6 event's")
        # The clamp this boundary replaced returned ENVELOPE_SCHEMA_INCOMPLETE for
        # every v6 row, which is why the reason is refused by name here as well as
        # being deleted from the code: a future partial rollback would otherwise
        # reintroduce a clamp that the type system was happy with.
        if FailureReason.ENVELOPE_SCHEMA_INCOMPLETE in self.reasons:
            fail(
                "a v6 result may not report envelope_schema_incomplete: the strict "
                "parser either accepted the envelope or the version is not V6. That "
                "reason was the P1.7 phase-2 clamp and it is not a verdict."
            )

        if self.applicability is not Applicability.FULLY_AUTHENTICATED:
            return

        # A v6 result that claims full authentication must have *decided* every
        # semantic field. Leaving one at its constructor default would report
        # "nothing established" from a path claiming it established everything —
        # the silent-skip failure §10.2 invariant 9 forbids.
        if self.epoch_position is EpochPosition.UNKNOWN:
            fail(
                "a FULLY_AUTHENTICATED v6 result must report its epoch_position; "
                "'unknown' means the boundary did not run"
            )

        # §10.2 invariants 4 and 5, and §8.3's "load-bearing invariant of this whole
        # document": a v6 event cannot be reported as fully authenticated without a
        # project-local acceptance and some trust root.
        if self.key_binding is KeyBinding.BOOTSTRAP_EXTERNAL:
            if self.trust_root is not TrustRoot.EXTERNALLY_PINNED or (
                self.checkpoint_binding is not CheckpointBinding.EXTERNALLY_PINNED
            ):
                fail(
                    "a bootstrap v6 event is FULLY_AUTHENTICATED only with "
                    "trust_root=externally_pinned AND "
                    "checkpoint_binding=externally_pinned; RECONCILIATION.md "
                    "Resolution 1: 'bootstrap without an external pin is not a "
                    "bootstrap; it is an unauthenticated first event' (got "
                    f"trust_root={self.trust_root.value!r}, "
                    f"checkpoint_binding={self.checkpoint_binding.value!r})"
                )
        elif self.key_binding is not KeyBinding.ACCEPTED_IN_PROJECT:
            fail(
                "a normal v6 event is FULLY_AUTHENTICATED only with "
                f"key_binding=accepted_in_project (got {self.key_binding.value!r})"
            )
        if self.trust_root is TrustRoot.ABSENT:
            fail("a FULLY_AUTHENTICATED v6 event must have some trust root")
        if self.attribution is not Attribution.INDIVIDUAL:
            fail(
                "a FULLY_AUTHENTICATED v6 event is Ed25519 and therefore attributes "
                f"to an individual key holder (got {self.attribution.value!r})"
            )
        # A revocation status of "unknown" is compatible with full authentication
        # ONLY when the material presented no trust log to check it against, and
        # then the gap must be *named* (§10.2 invariant 9). Silence is the failure.
        if self.revocation_status is RevocationStatus.UNKNOWN and (
            UNBOUND_TRUST_LOG_REVOCATION not in self.unbound_properties
        ):
            fail(
                "revocation_status=unknown on a FULLY_AUTHENTICATED v6 event must "
                f"name {UNBOUND_TRUST_LOG_REVOCATION!r} in unbound_properties: an "
                "unchecked revocation state is reported, never assumed"
            )
        if self.revocation_status is RevocationStatus.INDETERMINATE_WINDOW:
            fail(
                "revocation_status=indeterminate_window is not silently valid "
                "(TRUST-DOMAIN.md §6.6); it may not be FULLY_AUTHENTICATED"
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
        if self.envelope_version is EnvelopeVersion.V6:
            # The v6 semantics belong in the one-line form: a v6 verdict that says
            # only "invalid" sends an operator back to the structured result to find
            # out *which* referent failed, which is the failure mode `summary()`
            # exists to avoid.
            parts.append(f"key_binding={self.key_binding.value}")
            parts.append(f"trust_root={self.trust_root.value}")
            if self.revocation_status is not RevocationStatus.NOT_REVOKED:
                parts.append(f"revocation={self.revocation_status.value}")
            if self.unbound_properties:
                parts.append("unbound=" + ",".join(sorted(self.unbound_properties)))
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
            # TRUST-DOMAIN.md §2.6 — computed, not merely defined.
            "actor_id_kind": self.actor_id_kind,
            "actor_kind": self.actor_kind,
            "identity_consistency": str(self.identity_consistency),
            "actor_kind_authenticated": self.actor_kind_authenticated,
            "actor_principal_mapping": str(self.actor_principal_mapping),
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
            # RESULT-MODEL.md §10.1 — reported on every result, never omitted.
            "epoch_position": self.epoch_position.value,
            "attribution": self.attribution.value,
            "checkpoint_binding": self.checkpoint_binding.value,
            "unbound_properties": sorted(self.unbound_properties),
            "trust_domain_id": self.trust_domain_id,
            "trust_root": self.trust_root.value,
            "root_governance": self.root_governance.value,
            "key_binding": self.key_binding.value,
            "key_binding_event_hash": self.key_binding_event_hash,
            "revocation_status": self.revocation_status.value,
            "producer_consistency": self.producer_consistency.value,
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
    def signature_and_hashes_valid(self) -> bool:
        checks = [self.schema_valid, self.canonical_valid, self.signature_valid]
        if self.payload_canonical_hash_valid is not None:
            checks.append(self.payload_canonical_hash_valid)
        if self.event_hash_valid is not None:
            checks.append(self.event_hash_valid)
        return all(checks)

    @property
    def unchecked(self) -> tuple[str, ...]:
        checks = (
            ("payload_canonical_hash", self.payload_canonical_hash_valid),
            ("event_hash", self.event_hash_valid),
            ("project_binding", self.project_binding_valid),
            ("trust_domain_binding", self.trust_domain_binding_valid),
        )
        return tuple(name for name, result in checks if result is None)

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
            "signature_and_hashes_valid": self.signature_and_hashes_valid,
            "unchecked": list(self.unchecked),
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
    # --- §8.1 additions ---------------------------------------------------
    #: The trust domain this key was enrolled in, when the resolver knows it.
    #: ``None`` for a keyset file or bare caller-supplied material, which carry no
    #: domain — and the result then reports the domain from the *envelope*, which is
    #: signed, rather than inventing agreement between the two.
    trust_domain_id: str | None = None
    #: The trust-log lifecycle event this key resolved from, for a
    #: ``TRUST_DOMAIN_LOG``/``EXTERNALLY_PINNED`` resolver. Never a project
    #: acceptance hash: that is ``VerificationResult.key_binding_event_hash``, which
    #: the *verifier* resolves, because binding is not resolution (§8.1).
    key_binding_event_hash: str | None = None
    #: ``accepted`` | ``retrospective`` | ``legacy_registry``, per §8.1. ``None``
    #: means the resolver makes no claim about how the key was bound, which is the
    #: honest answer for a keyset file.
    binding_kind: str | None = None

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


def _base_kwargs(
    row: EventRow, *, mapped_actor_ids: Iterable[str] | None = None
) -> dict[str, Any]:
    """Fields present in *every* outcome, including the ones that authenticate nothing.

    The §2.6 identity trio is computed here rather than at each construction site so no
    outcome can be missing it — an ``UNVERIFIABLE`` keyless row still reports its actor's
    grammar, which is exactly the case an operator most needs the label for.
    """
    return {
        "event_id": row.event_id,
        "entity_kind": row.entity_kind,
        "entity_id": row.effective_entity_id,
        "global_seq": row.global_seq,
        "row_scheme_id": row.row_scheme_id,
        "actor_id_kind": principal_id_kind(row.actor_id),
        "actor_kind": row.actor_kind,
        "identity_consistency": identity_consistency(
            row.actor_id, row.actor_kind, mapped_actor_ids=mapped_actor_ids
        ),
        "actor_principal_mapping": mapping_status(
            row.actor_id, mapped_actor_ids=mapped_actor_ids
        ),
    }


# ---------------------------------------------------------------------------
# The v6 verifier boundary (TRUST-DOMAIN.md §5.10 / §5.11)
# ---------------------------------------------------------------------------
#
# What replaced what, because the diff is easy to misread: everything above this
# comment already worked before P1.7 phase 2 — the signature over the exact stored
# bytes, scheme equality with the trusted key, and total row reconciliation via
# `_reconcile_v6`. The clamp that stood here returned
# INVALID/ENVELOPE_SCHEMA_INCOMPLETE for *every* v6 row, clean or tampered, which
# made `applicability` useless as a tamper signal (WI-287 measured that and wrote it
# down). What is new below is only the part that needs to see OTHER EVENTS.
#
# The one structural rule: the material is **presented**, never fetched (§8.4), and
# it is addressed by v6 event hash, so a presented anchor whose bytes were altered
# does not resolve at all rather than resolving to something else. There is no
# fallback anywhere in here — not to `principal_keys` (§5.9 rule 1, §5.11's last
# row), not to `occurred_at`, not to `global_seq`. `_v6_writer._anchor_candidate_rows`
# is allowed to order by `global_seq` because at write time everything committed is
# behind the head; that argument does not transfer to a verifier holding possibly
# adversarial material, and this module does not borrow it.

_TRUST_LOG_CHECKPOINT_OBSERVED: Final[str] = "trust_log_checkpoint_observed"
_PRINCIPAL_KEY_ACCEPTED: Final[str] = "principal_key_accepted"
_PRINCIPAL_KEY_ACCEPTANCE_REVOKED: Final[str] = "principal_key_acceptance_revoked"
_PRINCIPAL_KEY_ENROLLED: Final[str] = "principal_key_enrolled"
_PRINCIPAL_KEY_ROTATED: Final[str] = "principal_key_rotated"
_PRINCIPAL_KEY_REVOKED: Final[str] = "principal_key_revoked"
_WORKFLOW_REGISTERED: Final[str] = "workflow_registered"
_WORKFLOW_RETIRED: Final[str] = "workflow_retired"
#: ``V6-ENVELOPE.md`` §1.4(b)'s closed set of project key-binding anchor kinds.
_V6_ANCHOR_TRANSITIONS: Final[frozenset[str]] = frozenset(
    {"project_initialized", "project_cryptographic_epoch_started", _PRINCIPAL_KEY_ACCEPTED}
)


@dataclass(frozen=True)
class _ChainContext:
    """Everything one backwards walk of the presented project chain establishes.

    One walk, several questions — deliberately, because each question is "what lies
    between A and E in P's chain" and answering them separately would mean several
    traversals that could disagree about what the chain *is*.
    """

    #: Hashes reachable from ``E`` by ``chain.previous_project_event_hash``, in walk
    #: order (nearest ancestor first). Membership is §5.10 step 3's whole answer.
    reachable: tuple[str, ...]
    #: ``acceptance_event_hash`` values revoked by a ``principal_key_acceptance_revoked``
    #: that is itself reachable from ``E`` — i.e. that lies *between* the acceptance
    #: and ``E``, which is exactly §5.10 step 4's window.
    revoked_acceptances: frozenset[str]
    #: The nearest reachable bootstrap event (``project_initialized`` /
    #: ``project_cryptographic_epoch_started``), or ``None``.
    bootstrap: ReferentEvent | None
    #: The most recent reachable ``trust_log_checkpoint_observed`` (§6.6's import
    #: point), or ``None`` if the chain carries none at or before ``E``.
    latest_checkpoint_observation: ReferentEvent | None
    #: ``True`` when the walk stopped because the material does not present a
    #: predecessor. For ``COMPLETE_STORE`` material that is a contradiction of the
    #: completeness claim; for a windowed export it is the legitimate bridge point.
    truncated: bool

    def reaches(self, event_hash: str) -> bool:
        return event_hash in self.reachable


def _walk_chain_context(
    envelope: Mapping[str, Any], referents: ReferentResolver
) -> _ChainContext:
    reachable: list[str] = []
    revoked: set[str] = set()
    bootstrap: ReferentEvent | None = None
    observation: ReferentEvent | None = None
    cursor = envelope["chain"]["previous_project_event_hash"]
    truncated = cursor is not None
    for event in walk_project_chain(cursor, referents):
        reachable.append(event.event_hash)
        transition = event.transition
        if transition == _PRINCIPAL_KEY_ACCEPTANCE_REVOKED:
            target = event.payload.get("acceptance_event_hash")
            if isinstance(target, str):
                revoked.add(target)
        elif transition == _TRUST_LOG_CHECKPOINT_OBSERVED and observation is None:
            observation = event
        elif transition in _V6_BOOTSTRAP_TRANSITIONS and bootstrap is None:
            bootstrap = event
        if event.previous_project_event_hash is None:
            truncated = False
    return _ChainContext(
        reachable=tuple(reachable),
        revoked_acceptances=frozenset(revoked),
        bootstrap=bootstrap,
        latest_checkpoint_observation=observation,
        truncated=truncated,
    )


@dataclass
class _Findings:
    """Accumulated verdict material. Contradiction outranks absence, always."""

    reasons: list[FailureReason] = _dc_field(default_factory=list)
    details: list[str] = _dc_field(default_factory=list)
    unbound: set[str] = _dc_field(default_factory=set)
    invalid: bool = False
    unverifiable: bool = False

    def contradicts(self, reason: FailureReason, detail: str) -> None:
        self.invalid = True
        self.reasons.append(reason)
        self.details.append(detail)

    def cannot_say(self, reason: FailureReason, detail: str, *, unbound: str | None = None) -> None:
        self.unverifiable = True
        self.reasons.append(reason)
        self.details.append(detail)
        if unbound is not None:
            self.unbound.add(unbound)

    def note_unbound(self, name: str, detail: str | None = None) -> None:
        self.unbound.add(name)
        if detail is not None:
            self.details.append(detail)

    @property
    def applicability(self) -> Applicability:
        if self.invalid:
            return Applicability.INVALID
        if self.unverifiable:
            return Applicability.UNVERIFIABLE
        return Applicability.FULLY_AUTHENTICATED


def _absent_referent_verdict(
    findings: _Findings,
    completeness: MaterialCompleteness,
    *,
    what: str,
    referent_hash: str,
    scope: str,
    unresolved_reason: FailureReason,
    missing_reason: FailureReason,
) -> None:
    """§5.11 rows 1 and 2, which differ *only* in the completeness claim.

    "Absence of evidence" and "the completeness claim is false" are different facts
    and get different verdicts. Criterion 15 is exactly this distinction, and the
    ``CONTIGUOUS_RANGE`` branch must **name** the missing referent as out of scope
    rather than merely declining.
    """

    if completeness is MaterialCompleteness.COMPLETE_STORE:
        findings.contradicts(
            missing_reason,
            f"{what} {referent_hash} is absent from material that claims "
            f"completeness ({scope}); the completeness claim is false, which is a "
            "fact about the artifact and not an absence (TRUST-DOMAIN.md §5.11)",
        )
        return
    findings.cannot_say(
        unresolved_reason,
        f"{what} {referent_hash} is outside the scope of the presented material "
        f"({scope}); absence of evidence, so no verdict is possible on it "
        "(TRUST-DOMAIN.md §5.11 row 1)",
        unbound=UNBOUND_KEY_BINDING if unresolved_reason is (
            FailureReason.KEY_BINDING_UNRESOLVED
        ) else None,
    )


def _resolve_v6_key_binding(
    envelope: Mapping[str, Any],
    *,
    chain: _ChainContext,
    referents: ReferentResolver,
    completeness: MaterialCompleteness,
    findings: _Findings,
) -> tuple[KeyBinding, ReferentEvent | None]:
    """``TRUST-DOMAIN.md`` §5.10 steps 1-4, plus Resolution 1's three permitted nulls."""

    signing = envelope["signing"]
    anchor_hash = signing["key_binding_event_hash"]
    transition = str(envelope["transition"])

    # --- Resolution 1: the three permitted nulls, and nothing else -----------
    if anchor_hash is None:
        if transition not in _V6_BOOTSTRAP_TRANSITIONS:
            findings.contradicts(
                FailureReason.KEY_BINDING_BOOTSTRAP_NOT_PERMITTED,
                f"signing.key_binding_event_hash is null on transition "
                f"{transition!r}; RECONCILIATION.md Resolution 1 permits null only "
                f"at {sorted(_V6_BOOTSTRAP_TRANSITIONS)}, and 'no other null is "
                "accepted'",
            )
            return KeyBinding.UNRESOLVED, None
        # Resolution 1's table pins **position** as tightly as it pins transition:
        # "trust-log genesis, first v6 event"; "unique first v6 event in a legacy
        # project". The position test is "no v6 ancestor is reachable", not "the
        # predecessor link is null" — because the cutover checkpoint legitimately
        # names the *legacy* project head, which is a v5 event and therefore never
        # resolves as a v6 referent. Testing the link for null would have refused
        # every real `project_cryptographic_epoch_started`.
        if chain.reachable:
            findings.contradicts(
                FailureReason.KEY_BINDING_BOOTSTRAP_NOT_PERMITTED,
                f"{transition!r} carries a null key binding but {len(chain.reachable)} "
                "v6 event(s) precede it on the project chain, so it is not the first "
                "v6 event; Resolution 1 permits the null by position as well as by "
                f"transition (nearest ancestor {chain.reachable[0]})",
            )
            return KeyBinding.UNRESOLVED, None
        return KeyBinding.BOOTSTRAP_EXTERNAL, None

    # --- Step 1: resolve h_A within the PRESENTED material -------------------
    anchor = referents.resolve_referent(anchor_hash)
    if anchor is None:
        _absent_referent_verdict(
            findings,
            completeness,
            what="the key-binding anchor",
            referent_hash=anchor_hash,
            scope=referents.describe(),
            unresolved_reason=FailureReason.KEY_BINDING_UNRESOLVED,
            missing_reason=FailureReason.KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE,
        )
        return KeyBinding.UNRESOLVED, None

    # --- Step 2: it must BE an acceptance, for THIS principal/key/project ----
    if anchor.transition not in _V6_ANCHOR_TRANSITIONS:
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the key-binding anchor {anchor_hash} is a {anchor.transition!r} event, "
            f"which is not one of {sorted(_V6_ANCHOR_TRANSITIONS)} "
            "(V6-ENVELOPE.md §1.4b)",
        )
        return KeyBinding.MISMATCHED, anchor
    if anchor.transition == _PRINCIPAL_KEY_ACCEPTED:
        accepted = anchor.payload
        anchor_kind = KeyBinding.ACCEPTED_IN_PROJECT
    else:
        embedded = anchor.payload.get("bootstrap_key_acceptance")
        if not isinstance(embedded, Mapping):
            findings.contradicts(
                FailureReason.KEY_BINDING_MISMATCH,
                f"the bootstrap anchor {anchor_hash} carries no "
                "bootstrap_key_acceptance object to bind against "
                "(RECONCILIATION.md Resolution 1 Bootstrap B)",
            )
            return KeyBinding.MISMATCHED, anchor
        accepted = embedded
        anchor_kind = KeyBinding.ACCEPTED_IN_PROJECT
    expected = {
        "principal_id": envelope["actor"]["principal_id"],
        "key_id": signing["key_id"],
        "project_instance_id": envelope["project_instance_id"],
    }
    mismatched = {
        name: (accepted.get(name) if name != "project_instance_id" else anchor.project_instance_id)
        for name, value in expected.items()
        if (accepted.get(name) if name != "project_instance_id" else anchor.project_instance_id)
        != value
    }
    if mismatched:
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the key-binding anchor {anchor_hash} does not accept this event's "
            f"principal/key/project: expected {expected!r}, anchor names "
            f"{mismatched!r} (TRUST-DOMAIN.md §5.10 step 2)",
        )
        return KeyBinding.MISMATCHED, anchor

    # §5.8's acceptance SCOPES. The writer refuses an out-of-scope append (admission
    # gate 2, `check_producer_authorization`); a verifier that did not ask the same
    # question would accept an artifact the writer would never have produced, which
    # is the gap between "our writer is careful" and "this event is authorised". A
    # key accepted for `work_item` may not sign a `principal` event just because it
    # is the only key present.
    scopes = accepted.get("scopes")
    if not isinstance(scopes, Mapping):
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the key-binding anchor {anchor_hash} carries no scopes object, so the "
            "authority it confers is unstated; §5.8's acceptance always names its "
            "scope and an unscoped acceptance is refused rather than read as "
            "unlimited",
        )
        return KeyBinding.MISMATCHED, anchor
    entity_kinds = scopes.get("entity_kinds")
    transitions = scopes.get("transitions")
    entity_kind = str(envelope["entity"]["kind"])
    if not isinstance(entity_kinds, list) or entity_kind not in entity_kinds:
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the acceptance at {anchor_hash} does not hold scope for "
            f"entity_kind={entity_kind!r} (scopes.entity_kinds={entity_kinds!r}); "
            "there is no wildcard for entity kind (TRUST-DOMAIN.md §5.8)",
        )
        return KeyBinding.MISMATCHED, anchor
    # `transitions: null` is the spec's own spelling for "any transition" and is NOT
    # the same as an empty list, which authorises nothing.
    if transitions is not None and (
        not isinstance(transitions, list) or transition not in transitions
    ):
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the acceptance at {anchor_hash} does not hold scope for transition "
            f"{transition!r} (scopes.transitions={transitions!r})",
        )
        return KeyBinding.MISMATCHED, anchor

    # --- Step 3: A must PRECEDE E by chain traversal -------------------------
    # There is deliberately no special case for "the event names its own hash". §5.8's
    # self-referential first acceptance was withdrawn because the envelope field was
    # "impossible to fill — the event would have had to reference itself", and that is
    # a statement about hash preimages, not about policy: an event whose signed bytes
    # contain their own v6 hash cannot be constructed. A branch for it would be
    # unreachable, and the general test below already returns the right verdict
    # (a self-named anchor is not among the event's ancestors).
    if not chain.reaches(anchor_hash):
        if chain.truncated and completeness is not MaterialCompleteness.COMPLETE_STORE:
            # The walk ran off the end of a window. The anchor may well precede E;
            # this material cannot show it. Naming the bridge point is the point.
            findings.cannot_say(
                FailureReason.KEY_BINDING_UNRESOLVED,
                f"the key-binding anchor {anchor_hash} is present but its position "
                "relative to this event cannot be established: the presented chain "
                f"is truncated ({referents.describe()}), so reachability by "
                "chain.previous_project_event_hash is undecidable here. Ordering is "
                "never taken from occurred_at or global_seq (§5.10 step 3).",
                unbound=UNBOUND_KEY_BINDING,
            )
            return KeyBinding.UNRESOLVED, anchor
        findings.contradicts(
            FailureReason.ENROLLMENT_AFTER_USE,
            f"the key-binding anchor {anchor_hash} is not reachable from this event "
            "by following chain.previous_project_event_hash, so the acceptance does "
            "not precede the use it authorises (TRUST-DOMAIN.md §5.10 step 3, §9 "
            "criterion 14)",
        )
        return KeyBinding.AFTER_USE, anchor

    # --- Step 4: no acceptance revocation lies between A and E --------------
    if anchor_hash in chain.revoked_acceptances:
        findings.contradicts(
            FailureReason.KEY_ACCEPTANCE_REVOKED,
            f"a principal_key_acceptance_revoked for anchor {anchor_hash} lies "
            "between that acceptance and this event on the project chain "
            "(TRUST-DOMAIN.md §5.10 step 4)",
        )
        return anchor_kind, anchor
    return anchor_kind, anchor


def _resolve_v6_trust_root(
    envelope: Mapping[str, Any],
    *,
    anchor: ReferentEvent | None,
    key_binding: KeyBinding,
    referents: ReferentResolver,
    policy: VerificationPolicy,
    findings: _Findings,
) -> tuple[TrustRoot, RevocationStatus]:
    """§5.10 steps 5-6: the cross-chain import point, and revocation.

    Two facts decide ``trust_root``, and §5.8 states them together: "A verifier that
    has the bundle but not the trust log can check signatures and must report
    ``trust_root: bundled_only``; **with the trust log and the pin** it reports
    ``externally_pinned``." So a pin alone never manufactures an external root out of
    material carrying no lifecycle evidence, and a presented log without a pin is the
    honest middle state ``trust_log_only``.
    """

    acceptance: Any = None
    if anchor is not None:
        acceptance = (
            anchor.payload
            if anchor.transition == _PRINCIPAL_KEY_ACCEPTED
            else anchor.payload.get("bootstrap_key_acceptance")
        )
    elif key_binding is KeyBinding.BOOTSTRAP_EXTERNAL:
        # A bootstrap event has no *referenced* anchor: it carries its own acceptance
        # object, and Resolution 1's Bootstrap-B row is explicit about what that object
        # is for — "the payload's `bootstrap_key_acceptance` resolves through the pinned
        # genesis and a verified trust-log checkpoint". So the cross-chain import point
        # for a bootstrap event is its own payload, and reading it from anywhere else
        # would mean a bootstrap event could never reach an external root at all.
        payload = envelope["payload"]
        if isinstance(payload, Mapping):
            acceptance = payload.get("bootstrap_key_acceptance")
    trust_event_hash = (
        acceptance.get("trust_event_hash") if isinstance(acceptance, Mapping) else None
    )

    enrolment: ReferentEvent | None = None
    if isinstance(trust_event_hash, str):
        enrolment = referents.resolve_referent(trust_event_hash)

    if enrolment is None:
        # §5.10 step 5: "If the trust log is not presented → key_binding:
        # trust_log_only is unavailable, so trust_root: bundled_only at best."
        # The key bytes ARE here — the acceptance repeats `public_key` on purpose
        # (§5.8) — so this is `bundled_only`, deliberately not `absent`.
        root = (
            TrustRoot.ABSENT
            if key_binding in (KeyBinding.UNRESOLVED, KeyBinding.MISMATCHED)
            else TrustRoot.BUNDLED_ONLY
        )
        findings.note_unbound(UNBOUND_TRUST_LOG_REVOCATION)
        if policy.pinned_trust_domain_id is None:
            findings.note_unbound(UNBOUND_EXTERNAL_TRUST_PIN)
        findings.note_unbound(UNBOUND_ROOT_GOVERNANCE)
        return root, RevocationStatus.UNKNOWN

    if enrolment.transition not in (_PRINCIPAL_KEY_ENROLLED, _PRINCIPAL_KEY_ROTATED):
        findings.contradicts(
            FailureReason.KEY_BINDING_MISMATCH,
            f"the acceptance's trust_event_hash {trust_event_hash} resolves to a "
            f"{enrolment.transition!r} event rather than a principal_key_enrolled or "
            "principal_key_rotated (TRUST-DOMAIN.md §5.10 step 5)",
        )
        return TrustRoot.TRUST_LOG_ONLY, RevocationStatus.UNKNOWN

    # §5.8: "Mismatch between this public_key and the enrolment event's is
    # **invalid**, not a preference."
    enrolled = enrolment.payload
    assert isinstance(acceptance, Mapping)  # implied by trust_event_hash being present
    for member in ("principal_id", "key_id", "fingerprint", "public_key"):
        claimed = acceptance.get(member)
        enrolled_value = enrolled.get(member)
        if claimed is not None and enrolled_value is not None and claimed != enrolled_value:
            findings.contradicts(
                FailureReason.KEY_BINDING_MISMATCH,
                f"the project acceptance and the trust-log enrolment disagree on "
                f"{member!r}; §5.8 makes that invalid, not a preference",
            )
            return TrustRoot.TRUST_LOG_ONLY, RevocationStatus.UNKNOWN

    pinned = policy.pinned_trust_domain_id
    if pinned is None:
        findings.note_unbound(UNBOUND_EXTERNAL_TRUST_PIN)
        findings.note_unbound(UNBOUND_ROOT_GOVERNANCE)
        root = TrustRoot.TRUST_LOG_ONLY
    elif pinned != str(envelope["trust_domain_id"]):
        findings.contradicts(
            FailureReason.TRUST_DOMAIN_MISMATCH,
            f"the envelope binds trust_domain_id={envelope['trust_domain_id']!r} but "
            f"the caller pinned {pinned!r}; a pinned policy rejects the result as a "
            "different domain (§9 criterion 4(i))",
        )
        root = TrustRoot.TRUST_LOG_ONLY
    else:
        root = TrustRoot.EXTERNALLY_PINNED

    return root, RevocationStatus.NOT_REVOKED


def _check_v6_workflow_referent(
    envelope: Mapping[str, Any],
    *,
    chain: _ChainContext,
    referents: ReferentResolver,
    completeness: MaterialCompleteness,
    findings: _Findings,
) -> None:
    """``V6-ENVELOPE.md`` §1.9 / Resolution 2, from the verifier's side.

    The writer's admission gate 1 refuses an unregistered workflow at append time.
    That protects the store it writes; it says nothing about an artifact handed to a
    verifier, which is why the same question is asked again here — over presented
    material, by hash, with the *definition* hash reconciled rather than assumed.
    """

    workflow = envelope["workflow"]
    if workflow is None:
        return
    registration_hash = workflow["registration_event_hash"]
    registration = referents.resolve_referent(registration_hash)
    if registration is None:
        _absent_referent_verdict(
            findings,
            completeness,
            what="the workflow registration",
            referent_hash=registration_hash,
            scope=referents.describe(),
            unresolved_reason=FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
            missing_reason=FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
        )
        return
    if registration.transition != _WORKFLOW_REGISTERED:
        findings.contradicts(
            FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
            f"workflow.registration_event_hash {registration_hash} resolves to a "
            f"{registration.transition!r} event, not a workflow_registered one; a "
            "workflow_registry row is not a registration (V6-ENVELOPE.md §1.9)",
        )
        return
    payload = registration.payload
    if payload.get("name") != workflow["name"] or (
        payload.get("workflow_version") != workflow["version"]
    ):
        findings.contradicts(
            FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
            f"the registration at {registration_hash} introduces "
            f"{payload.get('name')!r} v{payload.get('workflow_version')!r}, not the "
            f"{workflow['name']!r} v{workflow['version']!r} this event names",
        )
        return
    if payload.get("definition_hash") != workflow["definition_hash"]:
        findings.contradicts(
            FailureReason.WORKFLOW_DEFINITION_MISMATCH,
            "the workflow definition this event signs is not the one its "
            f"registration introduced: event says {workflow['definition_hash']!r}, "
            f"registration says {payload.get('definition_hash')!r}",
        )
        return
    if not chain.reaches(registration_hash):
        if chain.truncated and completeness is not MaterialCompleteness.COMPLETE_STORE:
            findings.cannot_say(
                FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
                f"the workflow registration {registration_hash} is present but the "
                "presented chain is truncated, so it cannot be shown to precede this "
                f"event ({referents.describe()})",
            )
            return
        findings.contradicts(
            FailureReason.WORKFLOW_REGISTRATION_UNRESOLVED,
            f"the workflow registration {registration_hash} does not precede this "
            "event on the project chain; a registration that follows its use "
            "registers nothing (RECONCILIATION.md Resolution 2)",
        )


def _check_v6_delegation(
    envelope: Mapping[str, Any], *, findings: _Findings
) -> None:
    """``TRUST-DOMAIN.md`` §5.12, to exactly the extent 0.6.0 can check it.

    ``authorization.mode == "delegated"`` requires a full credential-chain validation
    over the **documents**, and an action-delegation document is not an event: there
    is no channel in the presented material that carries one, and WI-008 has not
    landed. So a delegated v6 event is reported ``UNVERIFIABLE`` with the chain named
    as unbound, and can never be ``FULLY_AUTHENTICATED``. Inventing a credential
    channel here, or treating "no documents presented" as "chain fine", are the two
    wrong answers; ``DELEGATION_CHAIN_INVALID`` stays defined for the presented
    contradiction that becomes reachable when WI-008 lands.
    """

    authorization = envelope["authorization"]
    if authorization["mode"] != "delegated":
        return
    credentials = authorization["credentials"] or []
    findings.cannot_say(
        FailureReason.DELEGATION_CHAIN_INVALID,
        f"authorization.mode is 'delegated' with {len(credentials)} credential "
        "reference(s), and action-delegation credential documents are not part of "
        "the presented material in this release (TRUST-DOMAIN.md §5.12 / WI-008). "
        "The chain is therefore unestablished, which is reported rather than "
        "assumed.",
        unbound=UNBOUND_DELEGATION_CHAIN,
    )


def _check_v6_producer(
    envelope: Mapping[str, Any], *, policy: VerificationPolicy, findings: _Findings
) -> ProducerConsistency:
    """§1.8 / §4.3 producer policy, when the caller supplied one.

    The writer *raises* on a policy contradiction (admission gate 2); the verifier
    *reports* it, because a verifier that raised would be unable to describe the
    artifact it was handed. The two read the same ``ProducerPolicyEntry`` shape so
    they cannot drift on what the policy means.
    """

    producer = envelope["producer"]
    entries = policy.producer_policy
    if entries is None:
        findings.note_unbound(UNBOUND_PRODUCER_POLICY)
        return ProducerConsistency.POLICY_NOT_SUPPLIED
    principal_id = str(envelope["actor"]["principal_id"])
    harness = producer["harness"]
    candidates = [e for e in entries if getattr(e, "principal_id", None) == principal_id]
    if not candidates:
        findings.contradicts(
            FailureReason.PRODUCER_POLICY_MISMATCH,
            f"the supplied producer policy names no entry for principal "
            f"{principal_id!r}; a pinned policy that omits the signer contradicts the "
            "event rather than being silent about it (V6-ENVELOPE.md §1.8)",
        )
        return ProducerConsistency.CONTRADICTS_PUBLISHED_POLICY
    for entry in candidates:
        if harness in getattr(entry, "allowed_harnesses", frozenset()):
            return ProducerConsistency.MATCHES_PUBLISHED_POLICY
    findings.contradicts(
        FailureReason.PRODUCER_POLICY_MISMATCH,
        f"producer.harness {harness!r} is not an allowed harness for principal "
        f"{principal_id!r} under the supplied producer policy",
    )
    return ProducerConsistency.CONTRADICTS_PUBLISHED_POLICY


def _verify_v6_row(
    row: EventRow,
    envelope: Mapping[str, Any],
    *,
    keys: TrustedKeyResolver,
    referents: ReferentResolver,
    policy: VerificationPolicy,
    mapped_actor_ids: Iterable[str] | None = None,
) -> VerificationResult:
    base = _base_kwargs(row, mapped_actor_ids=mapped_actor_ids)
    signing = envelope["signing"]
    chain = envelope["chain"]
    unsigned = frozenset({"global_seq", "on_behalf_of", "work_item_id"})
    # Every v6 result carries these two regardless of outcome. `attribution` is
    # `individual` by *schema*: a v6 envelope's `signing.scheme_id` is ed25519, so
    # possession of the key is possession by one holder — the property the HMAC epoch
    # never had (§10.2 invariant 7). `trust_domain_id` comes from the signed
    # envelope, never from a row column or a resolver's claim.
    v6_semantics: dict[str, Any] = {
        "attribution": Attribution.INDIVIDUAL,
        "trust_domain_id": str(envelope["trust_domain_id"]),
    }
    trusted = keys.resolve(signing["key_id"])
    if trusted is None:
        return VerificationResult(
            **base,
            **v6_semantics,
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

    # TRUST-DOMAIN.md §5.9 rule 1, enforced where it can be enforced: "For a v6
    # event, resolving via PRINCIPAL_REGISTRY is a programming error and raises."
    # A degraded result would be a fallback the caller could learn to tolerate; a
    # raise cannot be tolerated, which is the whole point of the rule. Callers that
    # legitimately try several registry entries (`_signing`'s principal-binding
    # probe) already treat an exception as "this entry does not bind".
    if trusted.source is TrustedKeySource.PRINCIPAL_REGISTRY:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "a v6 event's key was resolved from the principal_keys projection "
            "(TrustedKeySource.PRINCIPAL_REGISTRY). TRUST-DOMAIN.md §5.9 rule 1: 'No "
            "verifier resolves a key from this table for a v6 event' — the table is a "
            "projection and consulting it is the S6 defect. Resolve from the keyset "
            "file, the trust log, or the presented material instead.",
            detail={"key_id": trusted.key_id, "event_id": str(row.event_id)},
        )

    trusted_scheme_id = trusted.scheme_id or signing["scheme_id"]
    if trusted_scheme_id != signing["scheme_id"]:
        return VerificationResult(
            **base,
            **v6_semantics,
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
        **v6_semantics,
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

    # ------------------------------------------------------------------
    # The boundary. The bytes verify and the row agrees with them; what is left is
    # everything that requires seeing ANOTHER EVENT.
    # ------------------------------------------------------------------
    from ._signing import compute_v6_event_hash

    event_hash_text = "sha256:" + compute_v6_event_hash(
        bytes(row.canonical_envelope or b""), bytes(row.signature or b"")
    ).hex()
    completeness = resolve_completeness(referents.completeness, policy.material_completeness)
    findings = _Findings()

    # (a) Caller pins. A contradiction of something the caller pinned out of band
    #     outranks everything else: it means this material is not the material the
    #     caller asked about, and no later check can make that acceptable.
    if policy.pinned_project_instance_id is not None and (
        policy.pinned_project_instance_id != str(envelope["project_instance_id"])
    ):
        findings.contradicts(
            FailureReason.PROJECT_BINDING_MISMATCH,
            f"the envelope binds project_instance_id="
            f"{envelope['project_instance_id']!r} but the caller pinned "
            f"{policy.pinned_project_instance_id!r}; a validly signed event from "
            "another project is still the wrong project",
        )
    if policy.pinned_trust_domain_id is not None and (
        policy.pinned_trust_domain_id != str(envelope["trust_domain_id"])
    ):
        findings.contradicts(
            FailureReason.TRUST_DOMAIN_MISMATCH,
            f"the envelope binds trust_domain_id={envelope['trust_domain_id']!r} but "
            f"the caller pinned {policy.pinned_trust_domain_id!r}",
        )

    # (b) One walk of the presented project chain answers §5.10 step 3, step 4,
    #     epoch position and the §6.6 import point.
    chain_context = _walk_chain_context(envelope, referents)

    # (c) §5.10 steps 1-4 + Resolution 1's three permitted nulls.
    key_binding, anchor = _resolve_v6_key_binding(
        envelope,
        chain=chain_context,
        referents=referents,
        completeness=completeness,
        findings=findings,
    )

    # (d) §5.10 steps 5-6.
    trust_root, revocation_status = _resolve_v6_trust_root(
        envelope,
        anchor=anchor,
        key_binding=key_binding,
        referents=referents,
        policy=policy,
        findings=findings,
    )

    # (e) The remaining envelope referents.
    _check_v6_workflow_referent(
        envelope,
        chain=chain_context,
        referents=referents,
        completeness=completeness,
        findings=findings,
    )
    _check_v6_delegation(envelope, findings=findings)
    producer_consistency = _check_v6_producer(envelope, policy=policy, findings=findings)

    # (f) Epoch position and checkpoint binding. Both are derived from the material
    #     rather than declared: `is_cutover` when this event IS a bootstrap event,
    #     `post_cutover` when one is reachable behind it. `unknown` survives only
    #     when the presented chain shows neither, which a windowed export legitimately
    #     does — and then `checkpoint_binding` says `unbound` rather than pretending.
    is_bootstrap = str(envelope["transition"]) in _V6_BOOTSTRAP_TRANSITIONS
    if is_bootstrap:
        epoch_position = EpochPosition.IS_CUTOVER
        checkpoint_hash: str | None = event_hash_text
    elif chain_context.bootstrap is not None:
        epoch_position = EpochPosition.POST_CUTOVER
        checkpoint_hash = chain_context.bootstrap.event_hash
    else:
        epoch_position = EpochPosition.UNKNOWN
        checkpoint_hash = None
    pinned_checkpoint = policy.cutover_checkpoint_event_hash
    if checkpoint_hash is None:
        checkpoint_binding = CheckpointBinding.UNBOUND
        # Not merely reported: an event whose epoch root the material does not show
        # cannot be shown to belong to the clean epoch at all, and "fully
        # authenticated" would be claiming that it does. A windowed export that starts
        # after the checkpoint legitimately lands here, which is why the message names
        # what to present rather than implying the artifact is defective.
        findings.cannot_say(
            FailureReason.EPOCH_VIOLATION,
            "no cutover checkpoint or project genesis is reachable from this event in "
            f"the presented material ({referents.describe()}), so its epoch position "
            "is unestablished; a v6 event's membership of the clean epoch is a fact "
            "about the chain behind it (EPOCH-RESET.md §5.1)",
            unbound="cutover_checkpoint",
        )
    elif pinned_checkpoint is None:
        checkpoint_binding = CheckpointBinding.CHECKPOINT_BOUND
        findings.note_unbound("cutover_checkpoint_pin")
    elif pinned_checkpoint == checkpoint_hash:
        checkpoint_binding = CheckpointBinding.EXTERNALLY_PINNED
    else:
        findings.contradicts(
            FailureReason.EPOCH_VIOLATION,
            f"the cutover checkpoint reachable from this event is {checkpoint_hash} "
            f"but the caller pinned {pinned_checkpoint}; this event belongs to a "
            "different epoch than the one under audit",
        )
        checkpoint_binding = CheckpointBinding.UNBOUND

    # (g) A bootstrap event's binding is `bootstrap_external`, and §10.2 invariant 5
    #     makes that fully authenticated ONLY under an external pin. Recording the
    #     absent pin as a *finding* rather than letting the invariant assert is what
    #     turns "bootstrap without an external pin is an unauthenticated first event"
    #     into a reported verdict instead of a crash.
    if key_binding is KeyBinding.BOOTSTRAP_EXTERNAL and not findings.invalid:
        if trust_root is not TrustRoot.EXTERNALLY_PINNED or (
            checkpoint_binding is not CheckpointBinding.EXTERNALLY_PINNED
        ):
            findings.cannot_say(
                FailureReason.KEY_BINDING_UNRESOLVED,
                "this is a bootstrap event whose authority is external by "
                "construction, and the presented material does not establish it: "
                f"trust_root={trust_root.value}, "
                f"checkpoint_binding={checkpoint_binding.value}. RECONCILIATION.md "
                "Resolution 1: 'Bootstrap without an external pin is not a bootstrap; "
                "it is an unauthenticated first event.' Supply a trust policy pinning "
                "the domain and the checkpoint hash, and present the trust log.",
                unbound=UNBOUND_BOOTSTRAP_AUTHORITY,
            )

    # (h) A revocation found in §5.10 step 4's window IS the revocation status. Leaving
    #     it at whatever step 6 concluded would report `unknown` about a revocation the
    #     verifier had just read, which is the kind of internally inconsistent report
    #     the result model exists to make impossible.
    if FailureReason.KEY_ACCEPTANCE_REVOKED in findings.reasons:
        revocation_status = RevocationStatus.REVOKED_BEFORE_USE

    applicability = findings.applicability
    if (
        applicability is Applicability.FULLY_AUTHENTICATED
        and EnvelopeVersion.V6 not in policy.full_authentication_versions
    ):
        # An explicit policy that excludes v6 gets an explicit refusal, not a silent
        # downgrade: the caller asked for something and this says what happened.
        applicability = Applicability.INVALID
        findings.reasons.append(FailureReason.LEGACY_ENVELOPE_VERSION)
        findings.details.append(
            "every v6 referent resolved, but this policy's "
            "full_authentication_versions excludes v6"
        )

    detail = "; ".join(findings.details) or (
        "every v6 referent resolved against the presented material: "
        f"{referents.describe()}"
    )
    return VerificationResult(
        **common,
        row_reconciled=True,
        authenticated_fields=frozenset(authenticated),
        unsigned_fields=unsigned,
        prev_event_hash_ok=prev_ok,
        prev_global_event_hash_ok=prev_global_ok,
        epoch_position=epoch_position,
        checkpoint_binding=checkpoint_binding,
        unbound_properties=frozenset(findings.unbound),
        trust_root=trust_root,
        key_binding=key_binding,
        key_binding_event_hash=(None if anchor is None else anchor.event_hash),
        revocation_status=revocation_status,
        producer_consistency=producer_consistency,
        applicability=applicability,
        accepted=applicability is Applicability.FULLY_AUTHENTICATED,
        reasons=tuple(dict.fromkeys(findings.reasons)),
        detail=detail,
    )


def verify_event_strict(
    row: EventRow,
    *,
    keys: TrustedKeyResolver,
    referents: ReferentResolver,
    policy: VerificationPolicy = DEFAULT_POLICY,
    mapped_actor_ids: Iterable[str] | None = None,
) -> VerificationResult:
    """Verify the stored envelope bytes, then reconcile the row against them.

    This is the only function in the tree that decides whether an event is
    authenticated. Any path that reimplements part of it is a bug.

    ``referents`` is the **presented material** (``TRUST-DOMAIN.md`` §8.4) and has no
    default on purpose. A v6 event's key binding, workflow registration and chain
    position are facts about *other events*, so a call site that cannot say what
    material it is presenting cannot get a v6 verdict — and the honest way to say
    "one row, no chain" is to pass :data:`NO_REFERENTS` by name, which is greppable,
    rather than to omit an argument, which is not. The verifier never fetches: this
    object is a lookup over what the caller already handed over.

    ``mapped_actor_ids`` is the deliberate ``actor_id -> principal_id`` assignment
    population (TRUST-DOMAIN.md §2 consequence 2), supplied by a caller that holds a
    validated ``regista.actor-principal-mapping/v1`` document. It affects **reporting
    only** — ``identity_consistency`` / ``actor_principal_mapping`` — and never a verdict.
    Omit it and those fields say ``not_evaluated`` rather than claiming a mapping is
    missing.
    """
    from ._signing_scheme import get_scheme, resolve_hash_function

    base = _base_kwargs(row, mapped_actor_ids=mapped_actor_ids)

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
        return _verify_v6_row(
            row,
            envelope,
            keys=keys,
            referents=referents,
            policy=policy,
            mapped_actor_ids=mapped_actor_ids,
        )

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
