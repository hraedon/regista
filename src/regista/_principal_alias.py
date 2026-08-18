"""Identity-migration payload contracts: ``regista.principal-alias/v1`` and the
deliberate ``actor_id → principal_id`` mapping document (P2.3).

Normative source: ``docs/0.6.0/TRUST-DOMAIN.md`` §2.5 and §2 CONFIRMED consequence 2,
with §10 D-4 (the separately-proposed ``identity_cutover_attested`` record is folded into
one event kind with a **mandatory** ``scope``).

**This module is the payload CONTRACT only.** It parses and validates; it writes nothing.
Turning a validated payload into a signed ``principal_alias_bound`` trust-log event is
P2.2/P1.7 machinery (``_trust_log.py``), and this module deliberately does not import it.

.. warning::

   **SEAM FOR P2.2 / P1.7 — READ THIS BEFORE WRITING AN ALIAS EVENT.**
   The trust-log writer must call :func:`parse_principal_alias` on the payload *before*
   signing it, and :func:`parse_actor_principal_mapping` on a mapping document. Nothing in
   this module is wired into a write path, because no write path exists on this branch.
   If an alias event is ever written without passing through this validator, the mandatory
   ``scope`` object stops being an enforcement and becomes a comment — which is precisely
   the failure §2.5 and §10 D-4 were designed to prevent.

**Why this lives in its own module.** Conformance criterion 21: "an alias never affects
``key.principal_id == actor_id`` binding". §2.5 makes that structural — "no verifier code
path may load aliases before the binding check". The two live binding checks
(``_bundle._verify_event_signatures`` and ``_principal_keys.verify_principal_binding``)
compare *exact* strings, and keeping the alias contract out of ``_principals`` (which the
verifier *does* import for §2.6 reporting) means the import graph itself witnesses the
invariant: neither binding path can reach this module, transitively or otherwise. There is
a test that asserts exactly that.

Alias payload shape (§2.5)::

    {
      "type": "regista.principal-alias",
      "version": 1,
      "alias_id": "uuid",
      "trust_domain_id": "uuid",
      "from_principal_id": "human:itadmin",     # may be legacy/bare
      "to_principal_id": "agent:0f6c...",       # MUST be canonical
      "relation": "same_subject | legacy_conflated_execution | renamed",
      "scope": {
        "kind": "unscoped | project | event-set",
        "project_instance_id": "uuid | null",
        "event_hash_set_root": "sha256:... | null",
        "event_count": 230976,
        "first_event_hash": "sha256:... | null",
        "last_event_hash": "sha256:... | null"
      },
      "asserted_by": {"principal_id": "human:...", "method": "...", "evidence": "..."},
      "asserted_at": "2026-08-08T00:00:00.000000Z",
      "binding_effect": "reporting_join_only"
    }

``binding_effect`` is the literal ``"reporting_join_only"`` and there is no other permitted
value in v1. **An alias never satisfies signature binding.**
"""

from __future__ import annotations

import re
import uuid as _uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn

from ._errors import ErrorCode, RegistaError
from ._principals import PrincipalForm, classify_principal_id

# ---------------------------------------------------------------------------
# Wire constants (§2.5). Changing any literal is a spec change, not a patch.
# ---------------------------------------------------------------------------

PRINCIPAL_ALIAS_TYPE = "regista.principal-alias"
PRINCIPAL_ALIAS_VERSION = 1

#: §2.5 — the *only* permitted value in v1. An alias joins records for reporting and never
#: satisfies signature binding.
BINDING_EFFECT_REPORTING_JOIN_ONLY = "reporting_join_only"

ACTOR_PRINCIPAL_MAPPING_TYPE = "regista.actor-principal-mapping"
ACTOR_PRINCIPAL_MAPPING_VERSION = 1

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")

_ALIAS_KEYS = frozenset(
    {
        "type",
        "version",
        "alias_id",
        "trust_domain_id",
        "from_principal_id",
        "to_principal_id",
        "relation",
        "scope",
        "asserted_by",
        "asserted_at",
        "binding_effect",
    }
)
_SCOPE_KEYS = frozenset(
    {
        "kind",
        "project_instance_id",
        "event_hash_set_root",
        "event_count",
        "first_event_hash",
        "last_event_hash",
    }
)
_ASSERTED_BY_KEYS = frozenset({"principal_id", "method", "evidence"})

_MAPPING_KEYS = frozenset(
    {
        "type",
        "version",
        "mapping_id",
        "trust_domain_id",
        "scope",
        "entries",
        "asserted_by",
        "asserted_at",
        "binding_effect",
    }
)
_MAPPING_ENTRY_KEYS = frozenset({"actor_id", "principal_id", "basis", "evidence"})


class AliasRelation(StrEnum):
    """§2.5 ``relation`` — a closed enum."""

    SAME_SUBJECT = "same_subject"
    #: The ~231k ``human:itadmin`` / ``actor_kind=agent`` corpus. Always event-set scoped;
    #: see :func:`parse_principal_alias`.
    LEGACY_CONFLATED_EXECUTION = "legacy_conflated_execution"
    RENAMED = "renamed"


class AliasScopeKind(StrEnum):
    """§2.5 ``scope.kind`` — a closed enum. The object is **mandatory**, which is how
    WI-055's "never a global alias from ``human:itadmin``" prohibition becomes structural
    rather than procedural (§10 D-4)."""

    UNSCOPED = "unscoped"
    PROJECT = "project"
    EVENT_SET = "event-set"


class MappingBasis(StrEnum):
    """How an ``actor_id → principal_id`` assignment was determined.

    §2 CONFIRMED consequence 2: the mapping "is **never** inferred from string
    similarity". There is deliberately no ``string_similarity`` member, and
    :func:`parse_actor_principal_mapping` names that value in its refusal so an attempt to
    smuggle one in is loud rather than silently coerced.
    """

    OPERATOR_INSPECTION = "operator-inspection"
    CONFIGURATION_RECORD = "configuration-record"
    IDP_RECORD = "idp-record"


#: Substrings that make a basis a *similarity* claim however it is spelled. Matched
#: case-insensitively against the whole basis string, so ``string-similarity``,
#: ``fuzzy_match``, ``looks-like-the-host`` and ``nameSimilarityScore`` all land on the same
#: named refusal. An enumerated denylist could always be spelled around, and "not in enum"
#: would not tell an operator *why* — §2 consequence 2's rule is specifically that the
#: mapping "is **never** inferred from string similarity", so the refusal says that.
#: None of :class:`MappingBasis`'s members contain any of these, so there are no false
#: positives on a legal value; ``test_the_similarity_denylist_never_catches_a_legal_basis``
#: keeps that true if the enum grows.
_SIMILARITY_MARKERS: tuple[str, ...] = ("similar", "fuzzy", "match", "looks")
#: Bases that are not similarity claims but are still inference rather than assignment.
_INFERENCE_BASES: frozenset[str] = frozenset({"inferred", "inference", "guess", "guessed"})

_SIMILARITY_REASON = "string_similarity_is_never_a_basis"
_INFERENCE_REASON = "inference_is_never_a_basis"


def _forbidden_basis_reason(basis: str) -> str | None:
    """The named reason ``basis`` is refused outright, or ``None`` to fall through to the
    enum check."""
    lowered = basis.strip().lower()
    if any(marker in lowered for marker in _SIMILARITY_MARKERS):
        return _SIMILARITY_REASON
    if lowered in _INFERENCE_BASES:
        return _INFERENCE_REASON
    return None


# ---------------------------------------------------------------------------
# Failure helpers — mirror _trust_domain.py: every rejection is a RegistaError with a
# machine-readable `reason`, so a test asserts the *named* rule, not message text.
# ---------------------------------------------------------------------------


def _fail(code: ErrorCode, message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(code, message, {"reason": reason, **detail})


def _require(
    condition: bool, code: ErrorCode, message: str, reason: str, **detail: Any
) -> None:
    if not condition:
        _fail(code, message, reason, **detail)


def _require_keys(value: Any, expected: frozenset[str], path: str, code: ErrorCode) -> None:
    _require(isinstance(value, dict), code, f"{path} must be an object", "not_an_object", path=path)
    actual = frozenset(value)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    _require(
        not unknown and not missing,
        code,
        f"{path} keys must be exactly {sorted(expected)!r}; "
        f"unknown={unknown!r} missing={missing!r}",
        "unknown_or_missing_field",
        path=path,
        unknown=unknown,
        missing=missing,
    )


def _require_string(value: Any, path: str, code: ErrorCode) -> str:
    _require(isinstance(value, str), code, f"{path} must be a string", "not_a_string", path=path)
    _require(bool(str(value).strip()), code, f"{path} must be non-empty", "empty_string", path=path)
    return str(value)


def _require_uuid(value: Any, path: str, code: ErrorCode) -> str:
    text = _require_string(value, path, code)
    try:
        parsed = _uuid.UUID(text)
    except (ValueError, TypeError) as exc:
        raise RegistaError(
            code,
            f"{path} must be a canonical UUID string",
            {"reason": "malformed_uuid", "path": path},
        ) from exc
    _require(
        str(parsed) == text,
        code,
        f"{path} must use lowercase canonical UUID text",
        "non_canonical_uuid",
        path=path,
    )
    return text


def _require_digest(value: Any, path: str, code: ErrorCode) -> str:
    text = _require_string(value, path, code)
    _require(
        _DIGEST_RE.fullmatch(text) is not None,
        code,
        f"{path} must be sha256:<64 lowercase hex characters>",
        "malformed_digest",
        path=path,
    )
    return text


def _require_timestamp(value: Any, path: str, code: ErrorCode) -> str:
    text = _require_string(value, path, code)
    _require(
        _TIMESTAMP_RE.fullmatch(text) is not None,
        code,
        f"{path} must be microsecond-precision UTC 'Z' text",
        "malformed_timestamp",
        path=path,
    )
    return text


def _require_null(value: Any, path: str, code: ErrorCode, reason: str) -> None:
    _require(value is None, code, f"{path} must be null for this scope kind", reason, path=path)


def _require_canonical(value: Any, path: str, code: ErrorCode) -> str:
    text = _require_string(value, path, code)
    classification = classify_principal_id(text)
    _require(
        classification.canonical,
        code,
        f"{path} {text!r} must be a canonical principal id (TRUST-DOMAIN.md §2.1): "
        f"{classification.reason}",
        "not_canonical",
        path=path,
        form=str(classification.form),
        grammar_reason=classification.reason,
    )
    return text


def _require_aliasable(value: Any, path: str, code: ErrorCode) -> str:
    """A ``from`` side may be legacy/bare (§2.5) but never unparseable junk.

    Aliasing junk would let an arbitrary string be joined into a canonical principal's
    reporting identity, which is the one thing the mandatory scope is meant to bound.
    """
    text = _require_string(value, path, code)
    classification = classify_principal_id(text)
    _require(
        classification.form in (PrincipalForm.CANONICAL, PrincipalForm.BARE_NAME),
        code,
        f"{path} {text!r} is neither canonical nor a legacy bare name "
        f"(TRUST-DOMAIN.md §2.4 convention 2): {classification.reason}",
        "from_principal_not_aliasable",
        path=path,
        form=str(classification.form),
        grammar_reason=classification.reason,
    )
    return text


# ---------------------------------------------------------------------------
# Scope — shared by the alias payload and the mapping document
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AliasScope:
    """§2.5 ``scope``. Mandatory, and the enforcement of the no-global-alias prohibition."""

    kind: AliasScopeKind
    project_instance_id: str | None
    event_hash_set_root: str | None
    event_count: int | None
    first_event_hash: str | None
    last_event_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "project_instance_id": self.project_instance_id,
            "event_hash_set_root": self.event_hash_set_root,
            "event_count": self.event_count,
            "first_event_hash": self.first_event_hash,
            "last_event_hash": self.last_event_hash,
        }


def parse_alias_scope(value: Any, *, path: str = "scope", code: ErrorCode) -> AliasScope:
    """Parse and validate the §2.5 scope object.

    Per-kind field discipline is exact, not "at least": an ``unscoped`` alias that carries
    an ``event_count`` is refused rather than silently ignored, because a scope that can
    carry inert fields is a scope a reader cannot trust.
    """
    _require_keys(value, _SCOPE_KEYS, path, code)
    obj: Mapping[str, Any] = value
    kind_text = _require_string(obj["kind"], f"{path}.kind", code)
    _require(
        kind_text in tuple(AliasScopeKind),
        code,
        f"{path}.kind must be one of {[str(k) for k in AliasScopeKind]}, got {kind_text!r}",
        "unknown_scope_kind",
        path=f"{path}.kind",
    )
    kind = AliasScopeKind(kind_text)

    project_instance_id: str | None = None
    event_hash_set_root: str | None = None
    event_count: int | None = None
    first_event_hash: str | None = None
    last_event_hash: str | None = None

    if kind is AliasScopeKind.UNSCOPED:
        for field_name in (
            "project_instance_id",
            "event_hash_set_root",
            "event_count",
            "first_event_hash",
            "last_event_hash",
        ):
            _require_null(
                obj[field_name], f"{path}.{field_name}", code, "unscoped_field_must_be_null"
            )
    elif kind is AliasScopeKind.PROJECT:
        project_instance_id = _require_uuid(
            obj["project_instance_id"], f"{path}.project_instance_id", code
        )
        for field_name in (
            "event_hash_set_root",
            "event_count",
            "first_event_hash",
            "last_event_hash",
        ):
            _require_null(
                obj[field_name],
                f"{path}.{field_name}",
                code,
                "project_scope_event_field_must_be_null",
            )
    else:  # EVENT_SET
        _require_null(
            obj["project_instance_id"],
            f"{path}.project_instance_id",
            code,
            "event_set_project_instance_id_must_be_null",
        )
        event_hash_set_root = _require_digest(
            obj["event_hash_set_root"], f"{path}.event_hash_set_root", code
        )
        raw_count = obj["event_count"]
        _require(
            isinstance(raw_count, int) and not isinstance(raw_count, bool) and raw_count > 0,
            code,
            f"{path}.event_count must be a positive integer for an event-set scope",
            "event_count_not_positive",
            path=f"{path}.event_count",
        )
        event_count = int(raw_count)
        first_event_hash = _require_digest(
            obj["first_event_hash"], f"{path}.first_event_hash", code
        )
        last_event_hash = _require_digest(obj["last_event_hash"], f"{path}.last_event_hash", code)

    return AliasScope(
        kind=kind,
        project_instance_id=project_instance_id,
        event_hash_set_root=event_hash_set_root,
        event_count=event_count,
        first_event_hash=first_event_hash,
        last_event_hash=last_event_hash,
    )


@dataclass(frozen=True, slots=True)
class AssertedBy:
    """Who asserted the alias/mapping, by what method, on what evidence (§2.5).

    ``method`` and ``evidence`` are **unverified operator claims**, like
    ``custody.declared_mode`` (§11 obligation 2 pattern). Nothing here proves the
    inspection happened.
    """

    principal_id: str
    method: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "method": self.method,
            "evidence": self.evidence,
        }


def parse_asserted_by(value: Any, *, path: str = "asserted_by", code: ErrorCode) -> AssertedBy:
    _require_keys(value, _ASSERTED_BY_KEYS, path, code)
    obj: Mapping[str, Any] = value
    return AssertedBy(
        # The asserter signs post-cutover, so its own id is held to the §2.7 always-strict
        # standard: a legacy bare name cannot be the authority that retires legacy names.
        principal_id=_require_canonical(obj["principal_id"], f"{path}.principal_id", code),
        method=_require_string(obj["method"], f"{path}.method", code),
        evidence=_require_string(obj["evidence"], f"{path}.evidence", code),
    )


# ---------------------------------------------------------------------------
# regista.principal-alias/v1
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrincipalAlias:
    """A validated ``regista.principal-alias/v1`` payload.

    Holding one of these proves the §2.5 rules were checked. It proves **nothing** about
    signature binding: ``binding_effect`` is invariably ``reporting_join_only``.
    """

    alias_id: str
    trust_domain_id: str
    from_principal_id: str
    to_principal_id: str
    relation: AliasRelation
    scope: AliasScope
    asserted_by: AssertedBy
    asserted_at: str
    binding_effect: str = BINDING_EFFECT_REPORTING_JOIN_ONLY

    @property
    def satisfies_signature_binding(self) -> bool:
        """Always ``False``. Present so a caller that wonders gets a definitive answer
        instead of reasoning about ``binding_effect`` strings (§2.5, criterion 21)."""
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": PRINCIPAL_ALIAS_TYPE,
            "version": PRINCIPAL_ALIAS_VERSION,
            "alias_id": self.alias_id,
            "trust_domain_id": self.trust_domain_id,
            "from_principal_id": self.from_principal_id,
            "to_principal_id": self.to_principal_id,
            "relation": str(self.relation),
            "scope": self.scope.to_dict(),
            "asserted_by": self.asserted_by.to_dict(),
            "asserted_at": self.asserted_at,
            "binding_effect": self.binding_effect,
        }


def parse_principal_alias(payload: Any) -> PrincipalAlias:
    """Strictly validate a ``regista.principal-alias/v1`` payload (§2.5).

    Rules enforced beyond the field shapes:

    * ``binding_effect`` is the literal ``"reporting_join_only"``; there is no other
      permitted value in v1.
    * ``to_principal_id`` must be canonical; ``from_principal_id`` may be canonical or a
      legacy bare name, but never junk.
    * ``from`` and ``to`` must differ — a self-alias joins nothing and would let a reader
      believe a migration happened.
    * **relation=legacy_conflated_execution requires scope.kind="event-set".** §2.5 pairs
      them explicitly, and states the reason: WI-055 forbids a *global* alias from
      ``human:itadmin`` "because that id also names genuine human activity elsewhere". A
      project-wide conflation alias has the same defect at project granularity — it
      re-attributes every human write in that project. Requiring the event-set scope makes
      the population enumerable and hash-bounded. This is **stricter** than merely banning
      ``unscoped``; see the module note in the P2.3 handoff. Loosening it later is a
      one-line change; tightening it after aliases are signed is not.
    """
    code = ErrorCode.PRINCIPAL_ALIAS_INVALID
    _require_keys(payload, _ALIAS_KEYS, "alias", code)
    obj: Mapping[str, Any] = payload

    _require(
        obj["type"] == PRINCIPAL_ALIAS_TYPE,
        code,
        f"alias.type must be {PRINCIPAL_ALIAS_TYPE!r}, got {obj['type']!r}",
        "wrong_type",
        path="alias.type",
    )
    _require(
        obj["version"] == PRINCIPAL_ALIAS_VERSION,
        code,
        f"alias.version must be {PRINCIPAL_ALIAS_VERSION}, got {obj['version']!r}",
        "wrong_version",
        path="alias.version",
    )
    _require(
        obj["binding_effect"] == BINDING_EFFECT_REPORTING_JOIN_ONLY,
        code,
        f"alias.binding_effect must be the literal "
        f"{BINDING_EFFECT_REPORTING_JOIN_ONLY!r} — v1 permits no other value, because an "
        f"alias never satisfies signature binding (TRUST-DOMAIN.md §2.5)",
        "binding_effect_not_reporting_join_only",
        path="alias.binding_effect",
    )

    alias_id = _require_uuid(obj["alias_id"], "alias.alias_id", code)
    trust_domain_id = _require_uuid(obj["trust_domain_id"], "alias.trust_domain_id", code)
    from_principal_id = _require_aliasable(
        obj["from_principal_id"], "alias.from_principal_id", code
    )
    to_principal_id = _require_canonical(obj["to_principal_id"], "alias.to_principal_id", code)
    _require(
        from_principal_id != to_principal_id,
        code,
        f"alias.from_principal_id and alias.to_principal_id are both "
        f"{from_principal_id!r}; a self-alias joins nothing",
        "self_alias",
        path="alias.from_principal_id",
    )

    relation_text = _require_string(obj["relation"], "alias.relation", code)
    _require(
        relation_text in tuple(AliasRelation),
        code,
        f"alias.relation must be one of {[str(r) for r in AliasRelation]}, "
        f"got {relation_text!r}",
        "unknown_relation",
        path="alias.relation",
    )
    relation = AliasRelation(relation_text)

    scope = parse_alias_scope(obj["scope"], path="alias.scope", code=code)

    if relation is AliasRelation.LEGACY_CONFLATED_EXECUTION:
        _require(
            scope.kind is AliasScopeKind.EVENT_SET,
            code,
            f"alias.relation={AliasRelation.LEGACY_CONFLATED_EXECUTION!s} requires "
            f"scope.kind={AliasScopeKind.EVENT_SET!s}, got {scope.kind!s}. WI-055 forbids "
            f"a global alias from a human principal to an agent id because that id also "
            f"names genuine human activity elsewhere (TRUST-DOMAIN.md §2.5); the "
            f"enumerable, hash-bounded event set is how the prohibition is enforced "
            f"rather than merely stated.",
            "conflated_execution_requires_event_set_scope",
            path="alias.scope.kind",
            relation=str(relation),
            scope_kind=str(scope.kind),
        )

    return PrincipalAlias(
        alias_id=alias_id,
        trust_domain_id=trust_domain_id,
        from_principal_id=from_principal_id,
        to_principal_id=to_principal_id,
        relation=relation,
        scope=scope,
        asserted_by=parse_asserted_by(obj["asserted_by"], path="alias.asserted_by", code=code),
        asserted_at=_require_timestamp(obj["asserted_at"], "alias.asserted_at", code),
        binding_effect=BINDING_EFFECT_REPORTING_JOIN_ONLY,
    )


# ---------------------------------------------------------------------------
# regista.actor-principal-mapping/v1 — the deliberate-assignment artifact
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ActorPrincipalMappingEntry:
    """One deliberate ``actor_id → principal_id`` assignment."""

    actor_id: str
    principal_id: str
    basis: MappingBasis
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "principal_id": self.principal_id,
            "basis": str(self.basis),
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class ActorPrincipalMapping:
    """A validated ``regista.actor-principal-mapping/v1`` document.

    §2 CONFIRMED consequence 2: the ``actor_id → principal_id`` mapping "does not exist in
    the store and must be assigned deliberately … never inferred from string similarity,
    and the result is recorded as signed scoped mappings (Gate 1)". This is that artifact's
    contract: scoped like an alias, asserted by a canonical principal, one canonical
    principal per writing actor, and every entry carrying the basis on which a human
    decided it.

    ``binding_effect`` is ``reporting_join_only`` here too. A mapping tells a *reporter*
    which principal a legacy writer's records belong to. It authorises nothing.
    """

    mapping_id: str
    trust_domain_id: str
    scope: AliasScope
    entries: tuple[ActorPrincipalMappingEntry, ...]
    asserted_by: AssertedBy
    asserted_at: str
    binding_effect: str = BINDING_EFFECT_REPORTING_JOIN_ONLY

    @property
    def mapped_actor_ids(self) -> frozenset[str]:
        """The actor ids this document assigns — the verifier's ``mapping_absent``
        population (see ``regista._principals.identity_consistency``)."""
        return frozenset(e.actor_id for e in self.entries)

    def principal_for(self, actor_id: str) -> str | None:
        """The assigned canonical principal, or ``None``. Never a guess."""
        for entry in self.entries:
            if entry.actor_id == actor_id:
                return entry.principal_id
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": ACTOR_PRINCIPAL_MAPPING_TYPE,
            "version": ACTOR_PRINCIPAL_MAPPING_VERSION,
            "mapping_id": self.mapping_id,
            "trust_domain_id": self.trust_domain_id,
            "scope": self.scope.to_dict(),
            "entries": [e.to_dict() for e in self.entries],
            "asserted_by": self.asserted_by.to_dict(),
            "asserted_at": self.asserted_at,
            "binding_effect": self.binding_effect,
        }


def _parse_mapping_entry(
    value: Any, index: int, code: ErrorCode
) -> ActorPrincipalMappingEntry:
    path = f"mapping.entries[{index}]"
    _require_keys(value, _MAPPING_ENTRY_KEYS, path, code)
    obj: Mapping[str, Any] = value
    # The actor id is whatever the store actually holds — bare legacy names are the whole
    # point of the exercise — but never junk, for the same reason as an alias `from`.
    actor_id = _require_aliasable(obj["actor_id"], f"{path}.actor_id", code)
    principal_id = _require_canonical(obj["principal_id"], f"{path}.principal_id", code)
    basis_text = _require_string(obj["basis"], f"{path}.basis", code)
    forbidden_reason = _forbidden_basis_reason(basis_text)
    _require(
        forbidden_reason is None,
        code,
        f"{path}.basis {basis_text!r} is explicitly forbidden: the actor_id → "
        f"principal_id mapping is never inferred from string similarity "
        f"(TRUST-DOMAIN.md §2 consequence 2). Assign it deliberately and record the "
        f"basis on which a human decided.",
        forbidden_reason or "forbidden_basis",
        path=f"{path}.basis",
        basis=basis_text,
    )
    _require(
        basis_text in tuple(MappingBasis),
        code,
        f"{path}.basis must be one of {[str(b) for b in MappingBasis]}, got {basis_text!r}",
        "unknown_basis",
        path=f"{path}.basis",
    )
    return ActorPrincipalMappingEntry(
        actor_id=actor_id,
        principal_id=principal_id,
        basis=MappingBasis(basis_text),
        evidence=_require_string(obj["evidence"], f"{path}.evidence", code),
    )


def parse_actor_principal_mapping(payload: Any) -> ActorPrincipalMapping:
    """Strictly validate a ``regista.actor-principal-mapping/v1`` document.

    The load-bearing rule is P2.3's acceptance criterion: **every writing actor resolves to
    exactly one canonical principal.** A document that names the same ``actor_id`` twice is
    refused even when both entries agree, because a reader that has to reconcile duplicates
    is a reader who will eventually pick the wrong one.

    An entry may not map an actor id to itself-as-a-principal via a non-canonical
    ``principal_id``; the target is always canonical. Nothing here derives the target from
    the actor id.
    """
    code = ErrorCode.PRINCIPAL_MAPPING_INVALID
    _require_keys(payload, _MAPPING_KEYS, "mapping", code)
    obj: Mapping[str, Any] = payload

    _require(
        obj["type"] == ACTOR_PRINCIPAL_MAPPING_TYPE,
        code,
        f"mapping.type must be {ACTOR_PRINCIPAL_MAPPING_TYPE!r}, got {obj['type']!r}",
        "wrong_type",
        path="mapping.type",
    )
    _require(
        obj["version"] == ACTOR_PRINCIPAL_MAPPING_VERSION,
        code,
        f"mapping.version must be {ACTOR_PRINCIPAL_MAPPING_VERSION}, got {obj['version']!r}",
        "wrong_version",
        path="mapping.version",
    )
    _require(
        obj["binding_effect"] == BINDING_EFFECT_REPORTING_JOIN_ONLY,
        code,
        f"mapping.binding_effect must be the literal "
        f"{BINDING_EFFECT_REPORTING_JOIN_ONLY!r}: a mapping joins records for reporting "
        f"and authorises nothing (TRUST-DOMAIN.md §2.5)",
        "binding_effect_not_reporting_join_only",
        path="mapping.binding_effect",
    )

    raw_entries = obj["entries"]
    _require(
        isinstance(raw_entries, list) and bool(raw_entries),
        code,
        "mapping.entries must be a non-empty array",
        "entries_empty",
        path="mapping.entries",
    )
    entries = tuple(
        _parse_mapping_entry(entry, index, code) for index, entry in enumerate(raw_entries)
    )
    seen: dict[str, str] = {}
    for entry in entries:
        previous = seen.get(entry.actor_id)
        _require(
            previous is None,
            code,
            f"mapping.entries assigns actor_id {entry.actor_id!r} twice "
            f"({previous!r} and {entry.principal_id!r}); every writing actor must resolve "
            f"to exactly one canonical principal",
            "duplicate_actor_id",
            path="mapping.entries",
            actor_id=entry.actor_id,
        )
        seen[entry.actor_id] = entry.principal_id

    return ActorPrincipalMapping(
        mapping_id=_require_uuid(obj["mapping_id"], "mapping.mapping_id", code),
        trust_domain_id=_require_uuid(obj["trust_domain_id"], "mapping.trust_domain_id", code),
        scope=parse_alias_scope(obj["scope"], path="mapping.scope", code=code),
        entries=entries,
        asserted_by=parse_asserted_by(
            obj["asserted_by"], path="mapping.asserted_by", code=code
        ),
        asserted_at=_require_timestamp(obj["asserted_at"], "mapping.asserted_at", code),
        binding_effect=BINDING_EFFECT_REPORTING_JOIN_ONLY,
    )


def alias_covers_actor_id(alias: PrincipalAlias, actor_id: str) -> bool:
    """Whether ``alias`` names ``actor_id`` on its ``from`` side.

    A *reporting* helper for the §2.7 estate sweep and for report renderers. It is
    deliberately not consulted by any binding check, and lives in this module (which no
    binding path imports) so that stays true.
    """
    return alias.from_principal_id == actor_id


__all__ = [
    "ACTOR_PRINCIPAL_MAPPING_TYPE",
    "ACTOR_PRINCIPAL_MAPPING_VERSION",
    "BINDING_EFFECT_REPORTING_JOIN_ONLY",
    "PRINCIPAL_ALIAS_TYPE",
    "PRINCIPAL_ALIAS_VERSION",
    "ActorPrincipalMapping",
    "ActorPrincipalMappingEntry",
    "AliasRelation",
    "AliasScope",
    "AliasScopeKind",
    "AssertedBy",
    "MappingBasis",
    "PrincipalAlias",
    "alias_covers_actor_id",
    "parse_actor_principal_mapping",
    "parse_alias_scope",
    "parse_asserted_by",
    "parse_principal_alias",
]
