"""Strict v6 action-delegation credentials and chain verification.

Credential documents are signed evidence, not trust roots. Project-local key
acceptance anchors the issuer key; an optional trust-log referent corroborates
the external lifecycle event, and all action ordering remains on the project
chain.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, cast

from ._datetime_utils import parse_v6_occurred_at
from ._jcs import canonicalize
from ._signing_scheme import get_scheme

ACTION_DELEGATION_TYPE: Final = "regista.action-delegation"
ACTION_DELEGATION_VERSION: Final = 1
ACTION_DELEGATION_SIGNING_DOMAIN: Final = b"regista.action-delegation.v1\x00"
ACTION_DELEGATION_HASH_DOMAIN: Final = b"regista.action-delegation.hash.v1\x00"
ACTION_DELEGATION_REVOKED: Final = "action_delegation_revoked"
MAX_ACTION_DELEGATION_DEPTH: Final = 8

_DIGEST_PREFIX: Final = "sha256:"
_DOCUMENT_KEYS: Final = frozenset(
    {
        "type",
        "version",
        "credential_id",
        "trust_domain_id",
        "issuer_principal_id",
        "subject_principal_id",
        "issuer_key_id",
        "issuer_key_binding_event_hash",
        "parent_credential_hash",
        "scope",
        "not_before",
        "not_after",
        "max_uses",
        "delegation_allowed",
        "signature",
    }
)
_SCOPE_KEYS: Final = frozenset(
    {"project_instance_ids", "entity_kinds", "workflow_names", "transitions"}
)
_SIGNATURE_KEYS: Final = frozenset({"scheme_id", "value"})
_REFERENCE_KEYS: Final = frozenset({"credential_id", "credential_hash"})
_REVOCATION_KEYS: Final = frozenset(
    {"type", "version", "credential_id", "credential_hash", "reason"}
)
_ADMINISTRATIVE_TRANSITIONS: Final = frozenset(
    {
        "action_delegation_revoked",
        "principal_registered",
        "principal_key_accepted",
        "principal_key_acceptance_revoked",
        "principal_key_enrolled",
        "principal_key_rotated",
        "principal_key_revoked",
        "trust_root_rotated",
        "trust_domain_custody_declared",
        "registrar_revoked",
        "trust_log_checkpoint_published",
        "project_instance_registered",
        "principal_alias_bound",
        "legacy_key_binding_attested",
        "registrar_delegated",
        "registrar_delegation_revoked",
        "trust_domain_established",
        "trust_governance_changed",
        "trust_log_checkpoint_observed",
        "workflow_registered",
        "workflow_retired",
        "project_initialized",
        "project_cryptographic_epoch_started",
    }
)


class ActionDelegationError(ValueError):
    pass


class DelegationVerificationStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    VERIFIED = "verified"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True, slots=True)
class ActionDelegationScope:
    project_instance_ids: frozenset[str]
    entity_kinds: frozenset[str]
    workflow_names: frozenset[str]
    transitions: frozenset[str]

    def contains(self, child: ActionDelegationScope) -> bool:
        return (
            child.project_instance_ids <= self.project_instance_ids
            and child.entity_kinds <= self.entity_kinds
            and child.workflow_names <= self.workflow_names
            and child.transitions <= self.transitions
        )

    def permits(
        self,
        *,
        project_instance_id: str,
        entity_kind: str,
        workflow_name: str,
        transition: str,
    ) -> bool:
        return (
            project_instance_id in self.project_instance_ids
            and entity_kind in self.entity_kinds
            and workflow_name in self.workflow_names
            and transition in self.transitions
        )


@dataclass(frozen=True, slots=True)
class ActionDelegationCredential:
    credential_id: uuid.UUID
    trust_domain_id: uuid.UUID
    issuer_principal_id: str
    subject_principal_id: str
    issuer_key_id: str
    issuer_key_binding_event_hash: str
    parent_credential_hash: str | None
    scope: ActionDelegationScope
    not_before: datetime
    not_after: datetime
    max_uses: int | None
    delegation_allowed: bool
    signature: bytes
    canonical_document: bytes
    canonical_unsigned: bytes
    credential_hash: str


@dataclass(frozen=True, slots=True)
class VerifiedActionDelegation:
    status: DelegationVerificationStatus
    credential_hashes: tuple[str, ...] = ()
    participating_principals: frozenset[str] = frozenset()
    reason: str | None = None

    @property
    def verified(self) -> bool:
        return self.status is DelegationVerificationStatus.VERIFIED


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ActionDelegationError(message)


def _canonical_uuid(value: Any, path: str) -> uuid.UUID:
    _require(isinstance(value, str), f"{path} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ActionDelegationError(f"{path} must be a canonical UUID string") from exc
    _require(str(parsed) == value, f"{path} must be lowercase canonical UUID text")
    return parsed


def _digest(value: Any, path: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    _require(
        isinstance(value, str)
        and value.startswith(_DIGEST_PREFIX)
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:]),
        f"{path} must be sha256:<64 lowercase hex characters>",
    )
    return str(value)


def _nonempty_string(value: Any, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be non-empty")
    return str(value)


def _scope_axis(value: Any, path: str, *, uuids: bool = False) -> frozenset[str]:
    _require(isinstance(value, list) and bool(value), f"{path} must be a non-empty array")
    result: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if uuids:
            item = str(_canonical_uuid(item, item_path))
        else:
            item = _nonempty_string(item, item_path)
        result.append(item)
    _require(len(result) == len(set(result)), f"{path} must not contain duplicates")
    return frozenset(result)


def _parse_scope(value: Any) -> ActionDelegationScope:
    _require(isinstance(value, dict), "scope must be an object")
    _require(frozenset(value) == _SCOPE_KEYS, "scope has unknown or missing members")
    return ActionDelegationScope(
        project_instance_ids=_scope_axis(
            value["project_instance_ids"], "scope.project_instance_ids", uuids=True
        ),
        entity_kinds=_scope_axis(value["entity_kinds"], "scope.entity_kinds"),
        workflow_names=_scope_axis(value["workflow_names"], "scope.workflow_names"),
        transitions=_scope_axis(value["transitions"], "scope.transitions"),
    )


def action_delegation_unsigned_bytes(document: Mapping[str, Any]) -> bytes:
    _require(frozenset(document) == _DOCUMENT_KEYS, "credential has unknown or missing members")
    unsigned = dict(document)
    del unsigned["signature"]
    return canonicalize(unsigned)


def action_delegation_signature_input(document: Mapping[str, Any]) -> bytes:
    unsigned = action_delegation_unsigned_bytes(document)
    return ACTION_DELEGATION_SIGNING_DOMAIN + struct.pack(">Q", len(unsigned)) + unsigned


def action_delegation_hash(document: Mapping[str, Any]) -> str:
    unsigned = action_delegation_unsigned_bytes(document)
    framed = ACTION_DELEGATION_HASH_DOMAIN + struct.pack(">Q", len(unsigned)) + unsigned
    return _DIGEST_PREFIX + hashlib.sha256(framed).hexdigest()


def parse_action_delegation(document: Mapping[str, Any] | bytes) -> ActionDelegationCredential:
    if isinstance(document, bytes):
        import json

        try:
            raw = json.loads(document)
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise ActionDelegationError("credential document must be UTF-8 JSON") from exc
        _require(isinstance(raw, dict), "credential document must be an object")
        try:
            canonical = canonicalize(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ActionDelegationError("credential document is not canonical JSON") from exc
        _require(canonical == document, "credential document must be canonical JCS bytes")
    else:
        if not isinstance(document, Mapping):
            raise ActionDelegationError("credential document must be an object")
        try:
            raw = dict(document)
        except (TypeError, ValueError) as exc:
            raise ActionDelegationError("credential document must be an object") from exc
    _require(frozenset(raw) == _DOCUMENT_KEYS, "credential has unknown or missing members")
    _require(raw["type"] == ACTION_DELEGATION_TYPE, "credential type is not action delegation")
    _require(raw["version"] == ACTION_DELEGATION_VERSION, "credential version must be 1")
    signature = raw["signature"]
    _require(isinstance(signature, dict), "signature must be an object")
    _require(frozenset(signature) == _SIGNATURE_KEYS, "signature has unknown or missing members")
    _require(signature["scheme_id"] == "ed25519", "signature.scheme_id must be ed25519")
    try:
        signature_bytes = base64.b64decode(signature["value"], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ActionDelegationError("signature.value must be canonical base64") from exc
    _require(len(signature_bytes) == 64, "signature.value must decode to 64 bytes")
    _require(
        base64.b64encode(signature_bytes).decode("ascii") == signature["value"],
        "signature.value must use canonical base64",
    )
    not_before = parse_v6_occurred_at(_nonempty_string(raw["not_before"], "not_before"))
    not_after = parse_v6_occurred_at(_nonempty_string(raw["not_after"], "not_after"))
    _require(not_before < not_after, "not_before must precede not_after")
    max_uses = raw["max_uses"]
    _require(
        max_uses is None
        or (
            isinstance(max_uses, int)
            and not isinstance(max_uses, bool)
            and max_uses > 0
        ),
        "max_uses must be null or a positive integer",
    )
    _require(isinstance(raw["delegation_allowed"], bool), "delegation_allowed must be boolean")
    issuer_principal_id = _nonempty_string(
        raw["issuer_principal_id"], "issuer_principal_id"
    )
    subject_principal_id = _nonempty_string(
        raw["subject_principal_id"], "subject_principal_id"
    )
    from ._principals import classify_principal_id

    _require(
        classify_principal_id(issuer_principal_id).canonical,
        "issuer_principal_id must use canonical kind:subject grammar",
    )
    _require(
        classify_principal_id(subject_principal_id).canonical,
        "subject_principal_id must use canonical kind:subject grammar",
    )
    unsigned = action_delegation_unsigned_bytes(raw)
    canonical = canonicalize(raw)
    return ActionDelegationCredential(
        credential_id=_canonical_uuid(raw["credential_id"], "credential_id"),
        trust_domain_id=_canonical_uuid(raw["trust_domain_id"], "trust_domain_id"),
        issuer_principal_id=issuer_principal_id,
        subject_principal_id=subject_principal_id,
        issuer_key_id=_nonempty_string(raw["issuer_key_id"], "issuer_key_id"),
        issuer_key_binding_event_hash=str(
            _digest(raw["issuer_key_binding_event_hash"], "issuer_key_binding_event_hash")
        ),
        parent_credential_hash=_digest(
            raw["parent_credential_hash"], "parent_credential_hash", nullable=True
        ),
        scope=_parse_scope(raw["scope"]),
        not_before=not_before,
        not_after=not_after,
        max_uses=max_uses,
        delegation_allowed=raw["delegation_allowed"],
        signature=signature_bytes,
        canonical_document=canonical,
        canonical_unsigned=unsigned,
        credential_hash=action_delegation_hash(raw),
    )


def verify_action_delegation_signature(
    credential: ActionDelegationCredential, public_key: bytes
) -> bool:
    framed = (
        ACTION_DELEGATION_SIGNING_DOMAIN
        + struct.pack(">Q", len(credential.canonical_unsigned))
        + credential.canonical_unsigned
    )
    try:
        return get_scheme("ed25519").verify(
            framed,
            credential.signature,
            hashlib.sha256(framed).digest(),
            public_key,
        )
    except (TypeError, ValueError, OverflowError):
        return False


def parse_action_delegation_revocation(payload: Mapping[str, Any]) -> tuple[str, str]:
    _require(frozenset(payload) == _REVOCATION_KEYS, "revocation has unknown or missing members")
    _require(
        payload["type"] == "regista.action-delegation-revocation",
        "revocation type is invalid",
    )
    _require(payload["version"] == 1, "revocation version must be 1")
    credential_id = str(_canonical_uuid(payload["credential_id"], "credential_id"))
    credential_hash = str(_digest(payload["credential_hash"], "credential_hash"))
    _nonempty_string(payload["reason"], "reason")
    return credential_id, credential_hash


def credential_public_key(binding: Any) -> bytes | None:
    acceptance = credential_acceptance(binding)
    if acceptance is None:
        return None
    value = acceptance.get("public_key")
    if not isinstance(value, str):
        return None
    try:
        public_key = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(public_key) != 32 or base64.b64encode(public_key).decode("ascii") != value:
        return None
    fingerprint = acceptance.get("fingerprint")
    if fingerprint != "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest():
        return None
    return public_key


def credential_binding_identity(binding: Any) -> tuple[str, str] | None:
    acceptance = credential_acceptance(binding)
    if acceptance is None:
        return None
    principal_id = acceptance.get("principal_id")
    key_id = acceptance.get("key_id")
    if not isinstance(principal_id, str) or not isinstance(key_id, str):
        return None
    return principal_id, key_id


def credential_acceptance(binding: Any) -> Mapping[str, Any] | None:
    payload = getattr(binding, "payload", None)
    if not isinstance(payload, Mapping):
        return None
    acceptance: Any
    transition = getattr(binding, "transition", None)
    if transition == "principal_key_accepted":
        acceptance = payload
    elif transition in {
        "project_initialized",
        "project_cryptographic_epoch_started",
    }:
        acceptance = payload.get("bootstrap_key_acceptance")
    else:
        return None
    return acceptance if isinstance(acceptance, Mapping) else None


def _missing_evidence(
    reason: str, *, complete: bool
) -> VerifiedActionDelegation:
    return VerifiedActionDelegation(
        status=(
            DelegationVerificationStatus.INVALID
            if complete
            else DelegationVerificationStatus.UNVERIFIABLE
        ),
        reason=reason,
    )


def _issuer_trust_evidence(
    credential: ActionDelegationCredential,
    binding: Any,
    referents: Any,
    *,
    root: bool,
    project_instance_id: str,
    material_complete: bool,
) -> VerifiedActionDelegation | bytes:
    acceptance = credential_acceptance(binding)
    if acceptance is None:
        return VerifiedActionDelegation(
            DelegationVerificationStatus.INVALID,
            reason="issuer project acceptance payload is malformed",
        )
    trust_event_hash = acceptance.get("trust_event_hash")
    try:
        _digest(trust_event_hash, "issuer project acceptance.trust_event_hash")
    except ActionDelegationError:
        return VerifiedActionDelegation(
            DelegationVerificationStatus.INVALID,
            reason="issuer project acceptance has no trust_event_hash",
        )
    acceptance_project = acceptance.get("project_instance_id")
    if acceptance_project != project_instance_id:
        return VerifiedActionDelegation(
            DelegationVerificationStatus.INVALID,
            reason="issuer project acceptance belongs to a different project",
        )

    trust_event = referents.resolve_referent(str(trust_event_hash))
    if trust_event is not None:
        trust_project = getattr(trust_event, "project_instance_id", None)
        if not isinstance(trust_project, str):
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="issuer trust event has no project-chain identity",
            )
        if trust_project == project_instance_id:
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="trust-log evidence must come from the separate trust-log chain",
            )
        if trust_event.trust_domain_id != str(credential.trust_domain_id):
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="issuer trust event belongs to a different trust domain",
            )
        if trust_event.transition not in {
            "principal_key_enrolled",
            "principal_key_rotated",
        }:
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="issuer trust_event_hash does not resolve to key lifecycle evidence",
            )
        trust_payload = trust_event.payload
        if not isinstance(trust_payload, Mapping):
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="issuer trust event payload is malformed",
            )
        for field, expected in (
            ("trust_domain_id", str(credential.trust_domain_id)),
            ("principal_id", credential.issuer_principal_id),
            ("key_id", credential.issuer_key_id),
            ("public_key", acceptance.get("public_key")),
            ("fingerprint", acceptance.get("fingerprint")),
        ):
            if trust_payload.get(field) != expected:
                return VerifiedActionDelegation(
                    DelegationVerificationStatus.INVALID,
                    reason=f"issuer trust event disagrees with project acceptance on {field}",
                )
        if root:
            from ._errors import RegistaError
            from ._trust_log import parse_principal_key_enrolled, parse_principal_key_rotated

            try:
                lifecycle = (
                    parse_principal_key_enrolled(trust_payload)
                    if trust_event.transition == "principal_key_enrolled"
                    else parse_principal_key_rotated(trust_payload)
                )
            except (RegistaError, TypeError, ValueError):
                return VerifiedActionDelegation(
                    DelegationVerificationStatus.INVALID,
                    reason="issuer trust event is not a valid trust-log key lifecycle event",
                )
            if lifecycle.authorized_by.authority not in {"root", "registrar"}:
                return VerifiedActionDelegation(
                    DelegationVerificationStatus.INVALID,
                    reason="delegation issuer is not root- or registrar-authorized",
                )

        trust_envelope = trust_event.envelope
        trust_signing = (
            trust_envelope.get("signing") if isinstance(trust_envelope, Mapping) else None
        )
        if not isinstance(trust_signing, Mapping):
            return VerifiedActionDelegation(
                DelegationVerificationStatus.INVALID,
                reason="issuer trust event has no signing block",
            )

    # The project acceptance is the project-side import proof. The optional trust-log
    # referent above is corroborating material only; an absent trust-log referent is
    # the documented bundled-only state. This verifier does not promote a
    # structurally parsed external event to a cryptographic trust root. The ordinary
    # v6 verifier reports the existing bundled_only/trust_log_only/external pin grade
    # independently, and P2.4/P3.x own full external publication verification.
    public_key = credential_public_key(binding)
    if public_key is None:
        return VerifiedActionDelegation(
            DelegationVerificationStatus.INVALID,
            reason="issuer public key is absent from project acceptance",
        )
    return public_key


def action_delegation_revocation_authorized(
    event: Any,
    credential: ActionDelegationCredential,
    referents: Any,
) -> bool:
    actor_principal_id = getattr(event, "actor_principal_id", None)
    if actor_principal_id == credential.issuer_principal_id:
        return True
    envelope = getattr(event, "envelope", None)
    if not isinstance(envelope, Mapping):
        return False
    signing = envelope.get("signing")
    if not isinstance(signing, Mapping):
        return False
    binding_hash = signing.get("key_binding_event_hash")
    if not isinstance(binding_hash, str):
        return False
    binding = referents.resolve_referent(binding_hash)
    if binding is None or getattr(binding, "transition", None) not in {
        "project_initialized",
        "project_cryptographic_epoch_started",
        "principal_key_accepted",
    }:
        return False
    event_project = envelope.get("project_instance_id")
    binding_project = getattr(binding, "project_instance_id", None)
    if not isinstance(event_project, str) or binding_project != event_project:
        return False
    acceptance = credential_acceptance(binding)
    if (
        acceptance is None
        or acceptance.get("principal_id") != actor_principal_id
        or acceptance.get("project_instance_id") != event_project
    ):
        return False
    scopes = acceptance.get("scopes")
    return (
        isinstance(scopes, Mapping)
        and scopes.get("may_accept_keys") is True
        and acceptance.get("key_id") == signing.get("key_id")
    )


def verify_action_delegation_chain(
    *,
    envelope: Mapping[str, Any],
    references: Sequence[Mapping[str, Any]],
    credentials: Sequence[ActionDelegationCredential],
    ancestors: Sequence[Any],
    referents: Any | None = None,
    material_complete: bool = True,
) -> VerifiedActionDelegation:
    try:
        _require(0 < len(credentials) <= MAX_ACTION_DELEGATION_DEPTH, "delegation depth is invalid")
        _require(len(references) == len(credentials), "credential reference count differs")
        transition = str(envelope["transition"])
        workflow = envelope["workflow"]
        _require(
            transition not in _ADMINISTRATIVE_TRANSITIONS
            and isinstance(workflow, Mapping)
            and envelope["entity"]["kind"] == "work_item",
            "action delegation cannot authorize lifecycle administration",
        )
        occurred_at = parse_v6_occurred_at(str(envelope["occurred_at"]))
        ancestor_hashes = {
            event.event_hash for event in ancestors if isinstance(event.event_hash, str)
        }
        seen: set[str] = set()
        principals: set[str] = set()
        previous: ActionDelegationCredential | None = None
        _require(referents is not None, "delegation verification requires presented referents")
        for index, (reference, credential) in enumerate(zip(references, credentials, strict=True)):
            _require(
                isinstance(reference, Mapping)
                and frozenset(reference) == _REFERENCE_KEYS,
                "credential reference has unknown or missing members",
            )
            _require(credential.credential_hash not in seen, "delegation cycle detected")
            seen.add(credential.credential_hash)
            _require(
                str(credential.credential_id) == reference["credential_id"],
                "credential_id mismatch",
            )
            _require(
                credential.credential_hash == reference["credential_hash"],
                "credential_hash mismatch",
            )
            _require(
                str(credential.trust_domain_id) == envelope["trust_domain_id"],
                "credential trust domain mismatch",
            )
            if credential.issuer_key_binding_event_hash not in ancestor_hashes:
                return _missing_evidence(
                    "issuer key binding does not precede candidate event",
                    complete=material_complete,
                )
            _require(
                not any(
                    getattr(event, "transition", None) == "principal_key_acceptance_revoked"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("acceptance_event_hash")
                    == credential.issuer_key_binding_event_hash
                    for event in ancestors
                ),
                "issuer key binding was revoked before credential use",
            )
            binding = next(
                event
                for event in ancestors
                if event.event_hash == credential.issuer_key_binding_event_hash
            )
            binding_identity = credential_binding_identity(binding)
            _require(
                binding_identity
                == (credential.issuer_principal_id, credential.issuer_key_id),
                "issuer binding principal or key mismatch",
            )
            trust_evidence = _issuer_trust_evidence(
                credential,
                binding,
                referents,
                root=index == 0,
                project_instance_id=str(envelope["project_instance_id"]),
                material_complete=material_complete,
            )
            if isinstance(trust_evidence, VerifiedActionDelegation):
                return trust_evidence
            public_key = trust_evidence
            _require(
                verify_action_delegation_signature(credential, public_key),
                "credential signature is invalid",
            )
            _require(
                credential.not_before <= occurred_at < credential.not_after,
                "credential is outside validity interval",
            )
            if previous is None:
                _require(credential.parent_credential_hash is None, "root credential has a parent")
            else:
                _require(previous.delegation_allowed, "parent forbids further delegation")
                _require(
                    credential.parent_credential_hash == previous.credential_hash,
                    "parent credential hash continuity failed",
                )
                _require(
                    credential.issuer_principal_id == previous.subject_principal_id,
                    "child issuer is not parent subject",
                )
                _require(previous.scope.contains(credential.scope), "child credential widens scope")
            revoked = False
            uses = 1
            for event in ancestors:
                if getattr(event, "transition", None) == ACTION_DELEGATION_REVOKED:
                    try:
                        revocation_payload = getattr(event, "payload", None)
                        _require(
                            isinstance(revocation_payload, Mapping),
                            "malformed action delegation revocation",
                        )
                        revocation_payload = cast(Mapping[str, Any], revocation_payload)
                        revoked_id, revoked_hash = parse_action_delegation_revocation(
                            revocation_payload
                        )
                    except (ActionDelegationError, TypeError, ValueError):
                        raise ActionDelegationError(
                            "malformed action delegation revocation"
                        ) from None
                    if (
                        revoked_id == str(credential.credential_id)
                        and revoked_hash == credential.credential_hash
                    ):
                        _require(
                            action_delegation_revocation_authorized(
                                event, credential, referents
                            ),
                            "action delegation revocation signer is not authorized",
                        )
                        revoked = True
                event_envelope = getattr(event, "envelope", None)
                authorization = (
                    event_envelope.get("authorization")
                    if isinstance(event_envelope, Mapping)
                    else None
                )
                if isinstance(authorization, Mapping):
                    event_refs = authorization.get("credentials")
                    if isinstance(event_refs, list) and any(
                        isinstance(item, Mapping)
                        and item.get("credential_hash") == credential.credential_hash
                        for item in event_refs
                    ):
                        uses += 1
            _require(not revoked, "credential was revoked before use")
            _require(
                credential.max_uses is None or uses <= credential.max_uses,
                "credential max_uses exceeded",
            )
            principals.add(credential.issuer_principal_id)
            principals.add(credential.subject_principal_id)
            previous = credential
        terminal = credentials[-1]
        _require(
            terminal.subject_principal_id == envelope["actor"]["principal_id"],
            "terminal credential subject differs from actor",
        )
        _require(
            terminal.scope.permits(
                project_instance_id=str(envelope["project_instance_id"]),
                entity_kind=str(envelope["entity"]["kind"]),
                workflow_name=str(workflow["name"]),
                transition=transition,
            ),
            "delegation scope does not authorize candidate action",
        )
        return VerifiedActionDelegation(
            status=DelegationVerificationStatus.VERIFIED,
            credential_hashes=tuple(item.credential_hash for item in credentials),
            participating_principals=frozenset(principals),
        )
    except (
        ActionDelegationError,
        AttributeError,
        IndexError,
        KeyError,
        OverflowError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        return VerifiedActionDelegation(
            status=DelegationVerificationStatus.INVALID,
            reason=str(exc),
        )


__all__ = [
    "ACTION_DELEGATION_HASH_DOMAIN",
    "ACTION_DELEGATION_REVOKED",
    "ACTION_DELEGATION_SIGNING_DOMAIN",
    "ACTION_DELEGATION_TYPE",
    "ACTION_DELEGATION_VERSION",
    "ActionDelegationCredential",
    "ActionDelegationError",
    "ActionDelegationScope",
    "DelegationVerificationStatus",
    "VerifiedActionDelegation",
    "action_delegation_hash",
    "action_delegation_revocation_authorized",
    "action_delegation_signature_input",
    "action_delegation_unsigned_bytes",
    "parse_action_delegation",
    "parse_action_delegation_revocation",
    "verify_action_delegation_chain",
    "verify_action_delegation_signature",
]
