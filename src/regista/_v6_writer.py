"""The post-genesis v6 ordinary-event append path (P1.7).

``_genesis.py`` opens the epoch: it writes exactly one ``project_initialized``
event, records ``project_identity``, and then refuses every further legacy
append on both sides of that boundary (``check_legacy_append`` →
``GENESIS_REQUIRED`` before genesis, ``V6_EPOCH_OPEN`` after it). This module is
the sanctioned path *after* the boundary — ``EPOCH-RESET.md`` §5.1's "ordinary
event and segment writers are refused before genesis and after the v6 epoch
opens" names the hole this fills.

Three things make an ordinary v6 append different from the genesis one, and all
three are gates rather than defaults:

**Key binding.** Genesis carries ``signing.key_binding_event_hash = null`` — the
one Bootstrap-B position ``RECONCILIATION.md`` Resolution 1 permits — and embeds
``bootstrap_key_acceptance`` as the project's *first* key-binding anchor. Every
ordinary event must name a **preceding** anchor: that bootstrap anchor (the
genesis event hash) or a standalone ``principal_key_accepted`` for the same
principal and key (``TRUST-DOMAIN.md`` §5.8). There is no self-authorisation and
no fallback to the ``principal_keys`` projection (§5.11's last row).

**Workflow registration** (admission gate 1, owned by P1.7). An event naming a
workflow must reference a signed ``workflow_registered`` event that strictly
precedes it on the project chain, and the ``workflow.definition_hash`` it signs
must equal that registration's. A workflow-registry *row* is not evidence.

**Producer authorization** (admission gate 2, owned by P1.7). The ``producer``
block (``V6-ENVELOPE.md`` §1.8) must reconcile with the closed lineage registry
and with the scopes the accepted key actually holds (§5.8) — entity kind,
transition, and, where a producer policy is supplied, the harness allowed for
that host principal.

Both gates fail closed with named error codes. Neither has a permissive default:
an unsupplied producer policy is reported ``policy_not_supplied`` and never
silently skipped, but an unresolvable *registration* or a lineage outside the
registry is a refusal.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

import psycopg.types.json
from psycopg.sql import SQL

from ._connection import DictConn
from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._keys import KeyEntry, KeySet
from ._lineage import MODEL_LINEAGE_FAMILIES
from ._signing import sign_v6_envelope
from ._verification import (
    V6EnvelopeError,
    parse_v6_envelope_strict,
    validate_v6_envelope,
    verify_v6_signature,
)

#: ``TRUST-DOMAIN.md`` §5.8 project-local acceptance, and its revocation. Both are
#: listed in ``_trust_log.DEFERRED_TRANSITIONS`` as "P1.7 (§5.8 project-local
#: acceptance)" — this module is that owner.
PRINCIPAL_KEY_ACCEPTED: Final[str] = "principal_key_accepted"
PRINCIPAL_KEY_ACCEPTANCE_REVOKED: Final[str] = "principal_key_acceptance_revoked"

#: ``V6-ENVELOPE.md`` §1.9 / ``RECONCILIATION.md`` Resolution 2.
WORKFLOW_REGISTERED: Final[str] = "workflow_registered"
WORKFLOW_RETIRED: Final[str] = "workflow_retired"

#: The closed set of project key-binding anchor kinds (``V6-ENVELOPE.md`` §1.4(b)).
#: ``project_cryptographic_epoch_started`` is the legacy-project spelling and never
#: occurs in the clean epoch, but naming it keeps the closed set honest rather than
#: silently two-valued.
_ANCHOR_TRANSITIONS: Final[frozenset[str]] = frozenset(
    {"project_initialized", "project_cryptographic_epoch_started", PRINCIPAL_KEY_ACCEPTED}
)

_V6_ENTITY_KINDS: Final[frozenset[str]] = frozenset(
    {"work_item", "project", "principal", "trust_domain", "project_instance", "workflow"}
)

_OCCURRED_AT_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"

_EVENT_COLUMNS: Final[str] = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, event_seq, actor_id, "
    "actor_kind, actor_metadata, key_id, workflow_name, workflow_version, timestamp, "
    "transition, payload, payload_canonical_hash, signature, canonical_envelope, "
    "on_behalf_of, scheme_id, prev_event_hash, prev_global_event_hash"
)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectIdentity:
    """The single ``project_identity`` row ``append_v6_genesis`` wrote."""

    project_instance_id: UUID
    trust_domain_id: UUID
    genesis_event_id: UUID
    genesis_event_hash: bytes
    principal_id: str
    key_id: str
    scheme_id: str
    key_fingerprint: str

    @property
    def genesis_event_hash_text(self) -> str:
        return "sha256:" + self.genesis_event_hash.hex()


@dataclass(frozen=True)
class AcceptanceScopes:
    """``TRUST-DOMAIN.md`` §5.8 ``scopes``, as the writer consumes them.

    ``transitions is None`` means "any transition", which is the spec's own
    spelling (``"transitions": null``) and is *not* the same as an empty list —
    an empty list authorises nothing. ``entity_kinds`` is always a concrete,
    non-empty set: there is no wildcard for entity kind.
    """

    entity_kinds: frozenset[str]
    transitions: frozenset[str] | None
    may_accept_keys: bool
    may_sign_checkpoints: bool
    may_sign_bundles: bool

    def permits(self, *, entity_kind: str, transition: str) -> bool:
        if entity_kind not in self.entity_kinds:
            return False
        return self.transitions is None or transition in self.transitions


@dataclass(frozen=True)
class KeyBindingAnchor:
    """A resolved *preceding* project key-binding anchor (``V6-ENVELOPE.md`` §1.4b)."""

    event_hash: str
    event_id: UUID
    transition: str
    principal_id: str
    key_id: str
    scopes: AcceptanceScopes
    #: ``bootstrap`` for the genesis/checkpoint embedded acceptance, ``acceptance``
    #: for a standalone ``principal_key_accepted``. The distinction is what
    #: ``VerificationResultV6.key_binding`` reports as ``bootstrap_external`` vs
    #: ``accepted_in_project`` (``RECONCILIATION.md`` Resolution 2).
    kind: str


@dataclass(frozen=True)
class WorkflowBinding:
    """The resolved ``workflow`` block, with its registration proven."""

    name: str
    version: int
    definition_hash: str
    registration_event_hash: str

    def as_envelope_member(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "definition_hash": self.definition_hash,
            "registration_event_hash": self.registration_event_hash,
        }


@dataclass(frozen=True)
class Producer:
    """``V6-ENVELOPE.md`` §1.8. Exactly four members; ``producer`` is never null."""

    harness: str
    harness_version: str
    model: str | None = None
    model_lineage: str | None = None

    def as_envelope_member(self) -> dict[str, Any]:
        return {
            "harness": self.harness,
            "harness_version": self.harness_version,
            "model": self.model,
            "model_lineage": self.model_lineage,
        }


@dataclass(frozen=True)
class ProducerPolicyEntry:
    """One entry of the published ``producer-policy.json`` (``TRUST-DOMAIN.md`` §4.3)."""

    principal_id: str
    allowed_harnesses: frozenset[str]
    host: str | None = None
    key_fingerprints: frozenset[str] = frozenset()


@dataclass(frozen=True)
class V6Append:
    """Everything the caller and the projection appliers need after an append."""

    event_id: UUID
    entity_kind: str
    entity_id: UUID
    entity_seq: int
    global_seq: int
    transition: str
    occurred_at: datetime
    canonical_envelope: bytes
    signature: bytes
    payload_canonical_hash: bytes
    event_hash: bytes
    key_id: str
    principal_id: str
    key_binding_event_hash: str
    workflow: WorkflowBinding | None
    producer_consistency: str

    @property
    def event_hash_text(self) -> str:
        return "sha256:" + self.event_hash.hex()


# ---------------------------------------------------------------------------
# Epoch admission — the mirror image of _genesis.check_legacy_append
# ---------------------------------------------------------------------------


def _relation_exists(conn: DictConn, relation: str) -> bool:
    row = conn.execute(SQL("SELECT to_regclass(%s) AS relation"), [relation]).fetchone()
    return row is not None and row["relation"] is not None


def read_project_identity(conn: DictConn) -> ProjectIdentity | None:
    """Read the ``project_identity`` singleton, or ``None`` before genesis."""

    if not _relation_exists(conn, "project_identity"):
        raise RegistaError(
            ErrorCode.MIGRATION_REQUIRED,
            "the v6 writer requires the clean-epoch project_identity baseline",
        )
    row = conn.execute(
        SQL(
            "SELECT project_instance_id, trust_domain_id, genesis_event_id, "
            "genesis_event_hash, principal_id, key_id, scheme_id, key_fingerprint "
            "FROM project_identity WHERE id = TRUE"
        )
    ).fetchone()
    if row is None:
        return None
    return ProjectIdentity(
        project_instance_id=UUID(str(row["project_instance_id"])),
        trust_domain_id=UUID(str(row["trust_domain_id"])),
        genesis_event_id=UUID(str(row["genesis_event_id"])),
        genesis_event_hash=bytes(row["genesis_event_hash"]),
        principal_id=row["principal_id"],
        key_id=row["key_id"],
        scheme_id=row["scheme_id"],
        key_fingerprint=row["key_fingerprint"],
    )


def require_v6_epoch(conn: DictConn, *, writer: str) -> ProjectIdentity:
    """Refuse an ordinary v6 append until genesis has opened the epoch.

    The inverse of ``_genesis.check_legacy_append``: that function refuses the
    *legacy* writer on both sides of genesis, this one refuses the *v6* writer
    before it. The two together leave exactly one door open at any moment, which
    is the property ``EPOCH-RESET.md`` §5.1 asserts.
    """

    identity = read_project_identity(conn)
    if identity is None:
        raise RegistaError(
            ErrorCode.GENESIS_REQUIRED,
            f"{writer} refused: project genesis must be written before ordinary events",
            detail={"writer": writer},
        )
    return identity


# ---------------------------------------------------------------------------
# Key binding (§5.8) — resolve a PRECEDING anchor, never the projection table
# ---------------------------------------------------------------------------


def _parse_scopes(raw: object, *, source: str) -> AcceptanceScopes:
    if not isinstance(raw, Mapping):
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            f"{source} carries no usable scopes object",
        )
    entity_kinds = raw.get("entity_kinds")
    if (
        not isinstance(entity_kinds, list)
        or not entity_kinds
        or not all(isinstance(kind, str) and kind in _V6_ENTITY_KINDS for kind in entity_kinds)
    ):
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            f"{source} scopes.entity_kinds is not a non-empty set of v6 entity kinds",
        )
    transitions = raw.get("transitions")
    if transitions is not None and (
        not isinstance(transitions, list)
        or not all(isinstance(t, str) and t.strip() for t in transitions)
    ):
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            f"{source} scopes.transitions must be a list of names or null",
        )
    return AcceptanceScopes(
        entity_kinds=frozenset(entity_kinds),
        transitions=None if transitions is None else frozenset(transitions),
        may_accept_keys=bool(raw.get("may_accept_keys", False)),
        may_sign_checkpoints=bool(raw.get("may_sign_checkpoints", False)),
        may_sign_bundles=bool(raw.get("may_sign_bundles", False)),
    )


def _anchor_from_row(row: Mapping[str, Any]) -> KeyBindingAnchor:
    """Build an anchor from a stored anchor event, reading the SIGNED envelope.

    Deliberately parses ``canonical_envelope`` rather than trusting the row's
    ``payload`` column: the envelope bytes are the artifact (``V6-ENVELOPE.md``
    §5.4), and an anchor read out of a rewritable column would make the whole
    binding check theatre.
    """

    envelope_bytes = row["canonical_envelope"]
    if not envelope_bytes:
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            "the resolved key-binding anchor has no stored canonical envelope",
        )
    try:
        envelope = parse_v6_envelope_strict(bytes(envelope_bytes))
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            f"the resolved key-binding anchor is not a valid v6 envelope: {exc}",
        ) from exc

    transition = envelope["transition"]
    payload = envelope["payload"] if isinstance(envelope["payload"], Mapping) else {}
    if transition == PRINCIPAL_KEY_ACCEPTED:
        principal_id = payload.get("principal_id")
        key_id = payload.get("key_id")
        scopes = _parse_scopes(payload.get("scopes"), source="principal_key_accepted")
        kind = "acceptance"
    else:
        acceptance = payload.get("bootstrap_key_acceptance")
        if not isinstance(acceptance, Mapping):
            raise RegistaError(
                ErrorCode.KEY_BINDING_UNRESOLVED,
                f"{transition!r} carries no bootstrap_key_acceptance to anchor on",
            )
        principal_id = acceptance.get("principal_id")
        key_id = acceptance.get("key_id")
        scopes = _parse_scopes(acceptance.get("scopes"), source="bootstrap_key_acceptance")
        kind = "bootstrap"

    if not isinstance(principal_id, str) or not isinstance(key_id, str):
        raise RegistaError(
            ErrorCode.KEY_BINDING_UNRESOLVED,
            "the resolved key-binding anchor names no principal/key pair",
        )
    return KeyBindingAnchor(
        event_hash="sha256:" + bytes(row["event_hash"]).hex(),
        event_id=UUID(str(row["event_id"])),
        transition=transition,
        principal_id=principal_id,
        key_id=key_id,
        scopes=scopes,
        kind=kind,
    )


def _anchor_candidate_rows(conn: DictConn) -> list[dict[str, Any]]:
    """Every stored anchor event, newest first on the project chain.

    ``global_seq`` orders the query only; it never *decides* anything — the
    caller's correctness comes from "this row exists and precedes the append we
    are about to make", and every existing row precedes it by construction
    because the append has not happened yet. ``TRUST-DOMAIN.md`` §5.10 step 3's
    chain-traversal requirement is a *verifier* obligation over material that
    may be adversarial; at write time the writer is appending to the head, so
    every committed anchor is behind it.
    """

    rows = conn.execute(
        SQL(
            "SELECT event_id, transition, canonical_envelope, signature, global_seq "
            "FROM events WHERE transition = ANY(%s) ORDER BY global_seq DESC"
        ),
        [sorted(_ANCHOR_TRANSITIONS)],
    ).fetchall()
    from ._signing import compute_v6_event_hash

    out: list[dict[str, Any]] = []
    for row in rows:
        if not row["canonical_envelope"] or not row["signature"]:
            continue
        enriched = dict(row)
        enriched["event_hash"] = compute_v6_event_hash(
            bytes(row["canonical_envelope"]), bytes(row["signature"])
        )
        out.append(enriched)
    return out


def resolve_key_binding_anchor(
    conn: DictConn,
    *,
    principal_id: str,
    key_id: str,
) -> KeyBindingAnchor:
    """Find the preceding anchor that authorises ``key_id`` for ``principal_id``.

    Preference order is "most recent standalone acceptance, else the bootstrap
    anchor" — the later acceptance is the one carrying current scopes. Nothing
    consults ``principal_keys``: §5.11's last row makes that the S6 defect, and
    the discipline is "no fallback", so an unresolvable binding is a refusal with
    ``KEY_BINDING_UNRESOLVED`` rather than a guess.
    """

    candidates = _anchor_candidate_rows(conn)
    bootstrap: KeyBindingAnchor | None = None
    for row in candidates:
        anchor = _anchor_from_row(row)
        if anchor.principal_id != principal_id or anchor.key_id != key_id:
            continue
        if anchor.kind == "acceptance":
            return anchor
        if bootstrap is None:
            bootstrap = anchor
    if bootstrap is not None:
        return bootstrap
    raise RegistaError(
        ErrorCode.KEY_BINDING_UNRESOLVED,
        f"no preceding project key-binding anchor accepts key {key_id!r} for "
        f"principal {principal_id!r}; append a principal_key_accepted event first "
        "(TRUST-DOMAIN.md §5.8). The principal_keys projection is never consulted "
        "for a v6 event (§5.11).",
        detail={"principal_id": principal_id, "key_id": key_id},
    )


# ---------------------------------------------------------------------------
# Admission gate 1: workflow registration (owned by P1.7)
# ---------------------------------------------------------------------------


def workflow_definition_hash(definition: Mapping[str, Any]) -> str:
    """``RECONCILIATION.md`` Resolution 2's workflow-definition hash domain."""

    body = canonicalize(definition)
    return "sha256:" + hashlib.sha256(
        b"regista.workflow-definition.v1\x00" + struct.pack(">Q", len(body)) + body
    ).hexdigest()


def resolve_workflow_registration(
    conn: DictConn,
    *,
    name: str,
    version: int,
) -> WorkflowBinding:
    """Admission gate 1 — an event naming a workflow must name a *registered* one.

    "Registered" means a signed ``workflow_registered`` event exists on this
    project's chain for ``(name, version)``, was not superseded by a
    ``workflow_retired`` at a later chain position, and its
    ``payload.definition_hash`` is what the appending event will sign. A
    ``workflow_registry`` row is emphatically *not* sufficient: the row is
    mutable operator state, and binding replay's oracle to it is exactly the S6
    shape ``V6-ENVELOPE.md`` §3.4 removes.

    Fails closed with ``WORKFLOW_REGISTRATION_UNRESOLVED``.
    """

    from ._signing import compute_v6_event_hash

    rows = conn.execute(
        SQL(
            "SELECT event_id, transition, canonical_envelope, signature, global_seq "
            "FROM events WHERE transition = ANY(%s) ORDER BY global_seq ASC"
        ),
        [[WORKFLOW_REGISTERED, WORKFLOW_RETIRED]],
    ).fetchall()

    registration: WorkflowBinding | None = None
    retired_at: int | None = None
    registered_at: int | None = None
    for row in rows:
        if not row["canonical_envelope"] or not row["signature"]:
            continue
        try:
            envelope = parse_v6_envelope_strict(bytes(row["canonical_envelope"]))
        except (V6EnvelopeError, TypeError, ValueError):
            continue
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            continue
        if payload.get("name") != name or payload.get("workflow_version") != version:
            continue
        if envelope["transition"] == WORKFLOW_REGISTERED:
            event_hash = compute_v6_event_hash(
                bytes(row["canonical_envelope"]), bytes(row["signature"])
            )
            registration = WorkflowBinding(
                name=name,
                version=version,
                definition_hash=str(payload["definition_hash"]),
                registration_event_hash="sha256:" + event_hash.hex(),
            )
            registered_at = int(row["global_seq"])
            retired_at = None
        else:
            retired_at = int(row["global_seq"])

    if registration is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED,
            f"no signed workflow_registered event introduces workflow {name!r} "
            f"version {version}; a workflow_registry row is not a registration "
            "(V6-ENVELOPE.md §1.9, RECONCILIATION.md Resolution 2)",
            detail={"workflow_name": name, "workflow_version": version},
        )
    if retired_at is not None and registered_at is not None and retired_at > registered_at:
        raise RegistaError(
            ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED,
            f"workflow {name!r} version {version} was retired; no later event may "
            "reference that registration (RECONCILIATION.md Resolution 2)",
            detail={"workflow_name": name, "workflow_version": version, "retired": True},
        )
    return registration


# ---------------------------------------------------------------------------
# Admission gate 2: producer authorization (owned by P1.7)
# ---------------------------------------------------------------------------


def check_producer_authorization(
    producer: Producer,
    *,
    principal_id: str,
    entity_kind: str,
    transition: str,
    anchor: KeyBindingAnchor,
    policy: Sequence[ProducerPolicyEntry] | None = None,
    key_fingerprint: str | None = None,
) -> str:
    """Admission gate 2 — reconcile ``producer`` against scopes, lineage, policy.

    Three independent checks, in the order that gives the most useful refusal:

    1. **Scopes** (``TRUST-DOMAIN.md`` §5.8). The accepted key must actually hold
       this ``entity.kind`` and this ``transition``. A key accepted for
       ``work_item`` may not sign a ``principal`` event just because it is the
       only key present.
    2. **Closed lineage vocabulary** (``EPOCH-RESET.md`` §6 rule 2,
       ``V6-ENVELOPE.md`` §1.8). ``model_lineage`` must be a family in
       ``_lineage.MODEL_LINEAGE_FAMILIES``, and ``model``/``model_lineage`` must
       be null together — "no model" and "undeclared" are different states and
       are not re-collapsed.
    3. **Published policy** (§1.8, ``TRUST-DOMAIN.md`` §4.3), *when supplied*. A
       contradiction is a refusal; an unsupplied policy returns
       ``policy_not_supplied``, which is an explicit reported state and never a
       silent skip.

    Returns the ``producer_consistency`` verdict for the result model.
    """

    if not anchor.scopes.permits(entity_kind=entity_kind, transition=transition):
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            f"the accepted key {anchor.key_id!r} does not hold scope for "
            f"entity_kind={entity_kind!r} transition={transition!r} "
            "(TRUST-DOMAIN.md §5.8 acceptance scopes)",
            detail={
                "reason": "acceptance_scope_exceeded",
                "entity_kind": entity_kind,
                "transition": transition,
                "entity_kinds": sorted(anchor.scopes.entity_kinds),
                "transitions": (
                    None if anchor.scopes.transitions is None
                    else sorted(anchor.scopes.transitions)
                ),
            },
        )

    if (producer.model is None) != (producer.model_lineage is None):
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            "producer.model and producer.model_lineage must be null together: a "
            "non-model producer declares both null, and a model producer declares "
            "both (V6-ENVELOPE.md §1.8)",
            detail={
                "reason": "producer_model_lineage_disagreement",
                "model": producer.model,
                "model_lineage": producer.model_lineage,
            },
        )
    if producer.model_lineage is not None and producer.model_lineage not in (
        MODEL_LINEAGE_FAMILIES
    ):
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            f"producer.model_lineage {producer.model_lineage!r} is not a canonical "
            "family; lineage is a closed vocabulary rejected at ingress "
            "(EPOCH-RESET.md §5 precondition 2)",
            detail={
                "reason": "model_lineage_not_canonical",
                "model_lineage": producer.model_lineage,
                "allowed": sorted(MODEL_LINEAGE_FAMILIES),
            },
        )

    if policy is None:
        return "policy_not_supplied"

    entries = [entry for entry in policy if entry.principal_id == principal_id]
    if not entries:
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            f"the supplied producer policy names no entry for principal "
            f"{principal_id!r}; a pinned policy that omits the signer contradicts "
            "the event rather than being silent about it (V6-ENVELOPE.md §1.8)",
            detail={"reason": "principal_absent_from_policy", "principal_id": principal_id},
        )
    for entry in entries:
        if producer.harness not in entry.allowed_harnesses:
            continue
        if entry.key_fingerprints and key_fingerprint is not None and (
            key_fingerprint not in entry.key_fingerprints
        ):
            continue
        return "matches_published_policy"
    raise RegistaError(
        ErrorCode.PRODUCER_NOT_AUTHORIZED,
        f"producer.harness {producer.harness!r} is not an allowed harness for "
        f"principal {principal_id!r} under the supplied producer policy",
        detail={
            "reason": "harness_not_allowed",
            "harness": producer.harness,
            "principal_id": principal_id,
            "allowed_harnesses": sorted(
                {h for entry in entries for h in entry.allowed_harnesses}
            ),
        },
    )


# ---------------------------------------------------------------------------
# Chain linkage
# ---------------------------------------------------------------------------


def _previous_entity_event_hash(
    conn: DictConn, *, entity_kind: str, entity_id: UUID, entity_seq: int
) -> str | None:
    """``chain.previous_entity_event_hash`` — null iff ``entity_seq == 1``."""

    if entity_seq <= 1:
        return None
    from ._signing import compute_v6_event_hash

    row = conn.execute(
        SQL(
            "SELECT canonical_envelope, signature FROM events "
            "WHERE entity_kind = %s AND entity_id = %s AND event_seq = %s"
        ),
        [entity_kind, entity_id, entity_seq - 1],
    ).fetchone()
    if row is None or not row["canonical_envelope"] or not row["signature"]:
        raise RegistaError(
            ErrorCode.V6_CHAIN_LINK_MISSING,
            f"entity {entity_kind}:{entity_id} has no signed predecessor at "
            f"event_seq {entity_seq - 1}; a v6 entity chain may not skip a link",
            detail={
                "entity_kind": entity_kind,
                "entity_id": str(entity_id),
                "missing_event_seq": entity_seq - 1,
            },
        )
    return "sha256:" + compute_v6_event_hash(
        bytes(row["canonical_envelope"]), bytes(row["signature"])
    ).hex()


def _allocate_entity_seq(conn: DictConn, *, entity_kind: str, entity_id: UUID) -> int:
    row = conn.execute(
        SQL(
            "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq FROM events "
            "WHERE entity_kind = %s AND entity_id = %s"
        ),
        [entity_kind, entity_id],
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.GENESIS_INVALID, "could not allocate an entity sequence number"
        )
    return int(row["next_seq"])


# ---------------------------------------------------------------------------
# The writer
# ---------------------------------------------------------------------------


def _format_occurred_at(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    # §2.3 is a SINGLE lexical form: exactly six fractional digits and a literal Z.
    # `%f` already renders six, so no truncation or padding is correct here — a
    # three-digit rendering (isoformat's default for whole milliseconds) is refused
    # by the strict parser, which is how this was caught.
    return value.astimezone(UTC).strftime(_OCCURRED_AT_FORMAT)


def _writer_key(key_set: KeySet, *, principal_id: str, key_id: str | None) -> KeyEntry:
    entry = key_set.resolve_signing_key(principal_id, key_id=key_id)
    if entry.scheme != "ed25519":
        raise RegistaError(
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
            f"the v6 writer requires an Ed25519 key; {entry.key_id!r} uses "
            f"{entry.scheme!r}. HMAC is read-only history in the clean epoch.",
            detail={"key_id": entry.key_id, "scheme": entry.scheme},
        )
    if entry.status != "active":
        raise RegistaError(
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
            f"the v6 writer requires an active key; {entry.key_id!r} is {entry.status!r}",
        )
    if entry.role != "actor":
        raise RegistaError(
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
            f"the v6 writer requires an actor key; {entry.key_id!r} has role "
            f"{entry.role!r}",
        )
    if entry.principal_id != principal_id:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"key {entry.key_id!r} is not bound to actor {principal_id!r}; the "
            "v6 epoch has no shared signing key",
        )
    if entry.public_key is None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "the v6 writer key has no public key")
    return entry


def build_v6_envelope(
    *,
    identity: ProjectIdentity,
    event_id: UUID,
    entity_kind: str,
    entity_id: UUID,
    entity_seq: int,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Mapping[str, Any] | None,
    key_id: str,
    key_binding_event_hash: str,
    transition: str,
    payload: Mapping[str, Any] | None,
    workflow: WorkflowBinding | None,
    producer: Producer,
    occurred_at: datetime,
    previous_entity_event_hash: str | None,
    previous_project_event_hash: str | None,
) -> dict[str, Any]:
    """Assemble all sixteen required members in one place (``V6-ENVELOPE.md`` §1.1)."""

    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": str(identity.project_instance_id),
        "trust_domain_id": str(identity.trust_domain_id),
        "event_id": str(event_id),
        "entity": {"kind": entity_kind, "id": str(entity_id)},
        "entity_seq": entity_seq,
        "actor": {
            "principal_id": actor_id,
            "kind": actor_kind,
            "metadata": dict(actor_metadata) if actor_metadata is not None else None,
        },
        "signing": {
            "scheme_id": "ed25519",
            "key_id": key_id,
            "key_binding_event_hash": key_binding_event_hash,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None if workflow is None else workflow.as_envelope_member(),
        "occurred_at": _format_occurred_at(occurred_at),
        "transition": transition,
        "payload": dict(payload) if payload is not None else None,
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": previous_entity_event_hash,
            "previous_project_event_hash": previous_project_event_hash,
        },
        "producer": producer.as_envelope_member(),
    }


def append_v6_event(
    conn: DictConn,
    key_set: KeySet,
    *,
    entity_kind: str,
    entity_id: UUID,
    transition: str,
    actor_id: str,
    actor_kind: str,
    producer: Producer,
    payload: Mapping[str, Any] | None = None,
    actor_metadata: Mapping[str, Any] | None = None,
    event_id: UUID | None = None,
    key_id: str | None = None,
    workflow_name: str | None = None,
    workflow_version: int | None = None,
    entity_seq: int | None = None,
    occurred_at: datetime | None = None,
    producer_policy: Sequence[ProducerPolicyEntry] | None = None,
) -> V6Append:
    """Append one ordinary v6 event behind both admission gates.

    The order is deliberate and every step can refuse:

    1. ``require_v6_epoch`` — before genesis this is ``GENESIS_REQUIRED``, the
       exact mirror of the legacy writer's refusal after genesis.
    2. Global-chain sentinel lock — the same ``event_chain_head`` ``FOR UPDATE``
       row ``append_v6_genesis`` serialises on, so the project chain cannot fork.
    3. Key resolution, then **key binding**: a preceding anchor must accept this
       key for this principal.
    4. **Admission gate 1** — workflow registration, when the event names one.
    5. **Admission gate 2** — producer authorization against scopes, lineage and
       (optionally) the published policy.
    6. Envelope construction, ``validate_v6_envelope`` — the named
       grammar-enforcement mechanism ``TRUST-DOMAIN.md`` §2.7 row 4 requires and
       the P2.3 AST tripwire looks for — then sign, then verify what was signed,
       then insert, then advance the chain head.
    """

    import uuid as _uuid

    from ._events import _advance_global_chain_head, _lock_global_chain_head
    from ._signing import compute_v6_event_hash

    if entity_kind not in _V6_ENTITY_KINDS:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"entity_kind {entity_kind!r} is not in the closed v6 registry",
            detail={"allowed": sorted(_V6_ENTITY_KINDS)},
        )
    if (workflow_name is None) != (workflow_version is None):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "workflow_name and workflow_version must be supplied together or not "
            "at all; '' / 0 sentinels are rejected and never generated "
            "(V6-ENVELOPE.md §1.6)",
        )
    if workflow_name is not None and (not workflow_name or workflow_version == 0):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "'' / 0 workflow sentinels are refused: v6 would sign the falsehood "
            "(V6-ENVELOPE.md §1.6)",
        )

    identity = require_v6_epoch(conn, writer="v6_writer.append_v6_event")
    head_hash = _lock_global_chain_head(conn)
    if head_hash is None:
        raise RegistaError(
            ErrorCode.GENESIS_REQUIRED,
            "v6_writer.append_v6_event refused: project_identity exists but the "
            "global chain head is empty, so there is no genesis event to chain from",
        )

    key_entry = _writer_key(key_set, principal_id=actor_id, key_id=key_id)
    anchor = resolve_key_binding_anchor(
        conn, principal_id=actor_id, key_id=key_entry.key_id
    )

    workflow: WorkflowBinding | None = None
    if workflow_name is not None and workflow_version is not None:
        workflow = resolve_workflow_registration(
            conn, name=workflow_name, version=workflow_version
        )

    producer_consistency = check_producer_authorization(
        producer,
        principal_id=actor_id,
        entity_kind=entity_kind,
        transition=transition,
        anchor=anchor,
        policy=producer_policy,
        key_fingerprint=key_entry.fingerprint(),
    )

    resolved_seq = (
        entity_seq
        if entity_seq is not None
        else _allocate_entity_seq(conn, entity_kind=entity_kind, entity_id=entity_id)
    )
    previous_entity = _previous_entity_event_hash(
        conn, entity_kind=entity_kind, entity_id=entity_id, entity_seq=resolved_seq
    )
    resolved_event_id = event_id if event_id is not None else _uuid.uuid4()
    resolved_time = occurred_at if occurred_at is not None else datetime.now(UTC)

    envelope = build_v6_envelope(
        identity=identity,
        event_id=resolved_event_id,
        entity_kind=entity_kind,
        entity_id=entity_id,
        entity_seq=resolved_seq,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_id=key_entry.key_id,
        key_binding_event_hash=anchor.event_hash,
        transition=transition,
        payload=payload,
        workflow=workflow,
        producer=producer,
        occurred_at=resolved_time,
        previous_entity_event_hash=previous_entity,
        previous_project_event_hash="sha256:" + head_hash.hex(),
    )
    # The named grammar-enforcement mechanism (TRUST-DOMAIN.md §2.7 row 4). It
    # runs BEFORE signing so a non-canonical actor id never reaches key material,
    # and it is what the P2.3 AST tripwire in
    # tests/test_p23_enrolment_inversion.py identifies as this writer's gate.
    try:
        validate_v6_envelope(envelope)
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.V6_ENVELOPE_INVALID,
            f"the v6 writer refused to sign an invalid envelope: {exc}",
        ) from exc

    signed = sign_v6_envelope(envelope, key_entry.secret)
    assert key_entry.public_key is not None
    verification = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        key_entry.public_key,
        payload_canonical_hash=signed.payload_canonical_hash,
        expected_event_hash=signed.event_hash,
        expected_project_instance_id=str(identity.project_instance_id),
        expected_trust_domain_id=str(identity.trust_domain_id),
        trusted_scheme_id="ed25519",
    )
    if not (
        verification.signature_and_hashes_valid
        and verification.project_binding_valid is True
        and verification.trust_domain_binding_valid is True
    ):
        raise RegistaError(
            ErrorCode.V6_ENVELOPE_INVALID,
            "the v6 writer produced bytes that do not verify under its own key",
            detail={"errors": list(verification.errors)},
        )

    stored_time = datetime.strptime(envelope["occurred_at"], _OCCURRED_AT_FORMAT).replace(
        tzinfo=UTC
    )
    inserted = conn.execute(
        SQL(
            f"INSERT INTO events ({_EVENT_COLUMNS}) VALUES "
            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s) RETURNING global_seq"
        ),
        [
            resolved_event_id,
            entity_id,
            entity_kind,
            entity_id,
            "sha-256",
            resolved_seq,
            actor_id,
            actor_kind,
            psycopg.types.json.Jsonb(dict(actor_metadata))
            if actor_metadata is not None
            else None,
            key_entry.key_id,
            None if workflow is None else workflow.name,
            None if workflow is None else workflow.version,
            stored_time,
            transition,
            psycopg.types.json.Jsonb(dict(payload)) if payload is not None else None,
            signed.payload_canonical_hash,
            signed.signature,
            signed.canonical_envelope,
            None,
            "ed25519",
            None if previous_entity is None else bytes.fromhex(previous_entity[7:]),
            head_hash,
        ],
    )
    row = inserted.fetchone()
    if row is None:
        raise RegistaError(ErrorCode.GENESIS_INVALID, "the v6 append returned no global_seq")
    event_hash = compute_v6_event_hash(signed.canonical_envelope, signed.signature)
    _advance_global_chain_head(conn, resolved_event_id, event_hash)

    return V6Append(
        event_id=resolved_event_id,
        entity_kind=entity_kind,
        entity_id=entity_id,
        entity_seq=resolved_seq,
        global_seq=int(row["global_seq"]),
        transition=transition,
        occurred_at=stored_time,
        canonical_envelope=signed.canonical_envelope,
        signature=signed.signature,
        payload_canonical_hash=signed.payload_canonical_hash,
        event_hash=event_hash,
        key_id=key_entry.key_id,
        principal_id=actor_id,
        key_binding_event_hash=anchor.event_hash,
        workflow=workflow,
        producer_consistency=producer_consistency,
    )


__all__ = [
    "PRINCIPAL_KEY_ACCEPTANCE_REVOKED",
    "PRINCIPAL_KEY_ACCEPTED",
    "WORKFLOW_REGISTERED",
    "WORKFLOW_RETIRED",
    "AcceptanceScopes",
    "KeyBindingAnchor",
    "Producer",
    "ProducerPolicyEntry",
    "ProjectIdentity",
    "V6Append",
    "WorkflowBinding",
    "append_v6_event",
    "build_v6_envelope",
    "check_producer_authorization",
    "read_project_identity",
    "require_v6_epoch",
    "resolve_key_binding_anchor",
    "resolve_workflow_registration",
    "workflow_definition_hash",
]
