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

import base64
import binascii
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
from ._datetime_utils import parse_v6_occurred_at, v6_occurred_at
from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._keys import KeyEntry, KeySet
from ._lineage import MODEL_LINEAGE_FAMILIES
from ._signing import sign_v6_envelope
from ._verification import (
    V6_ENTITY_KINDS,
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

#: The closed six-value registry, imported rather than restated — see
#: ``_verification.V6_ENTITY_KINDS``.
_V6_ENTITY_KINDS: Final[frozenset[str]] = V6_ENTITY_KINDS

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


#: Environment names the process-level producer identity resolves from.
PRODUCER_ENV: Final[dict[str, str]] = {
    "harness": "REGISTA_PRODUCER_HARNESS",
    "harness_version": "REGISTA_PRODUCER_HARNESS_VERSION",
    "model": "REGISTA_PRODUCER_MODEL",
    "model_lineage": "REGISTA_PRODUCER_MODEL_LINEAGE",
}


def resolve_producer(explicit: Producer | None = None) -> Producer:
    """Resolve the producer identity for this *process*, or refuse.

    The producer is deliberately **not** a per-append argument. ``V6-ENVELOPE.md``
    §1.8's whole argument is that a model holds nothing and signs nothing, while a
    harness/host does — so "which harness and model produced this event" is a
    property of the running process, resolved once, not something a business call
    site is asked to assert each time. Making it a parameter would invite exactly the
    self-asserted-string pattern §1.8 exists to remove.

    ``producer.harness`` and ``producer.harness_version`` are load-bearing
    (``_genesis._REQUIRED_NONEMPTY_PATHS``), so an unset environment is a refusal with
    ``LOAD_BEARING_FIELD_MISSING`` naming the variables — never a default like
    ``"unknown"``, which would sign a falsehood.

    ``model``/``model_lineage`` may legitimately both be absent: that is the "no model
    producer" case, and it is distinct from "undeclared". Setting exactly one is a
    refusal, caught downstream by admission gate 2.
    """

    import os

    if explicit is not None:
        return explicit
    harness = os.environ.get(PRODUCER_ENV["harness"], "").strip()
    harness_version = os.environ.get(PRODUCER_ENV["harness_version"], "").strip()
    missing = [
        PRODUCER_ENV[name]
        for name, value in (("harness", harness), ("harness_version", harness_version))
        if not value
    ]
    if missing:
        raise RegistaError(
            ErrorCode.LOAD_BEARING_FIELD_MISSING,
            "the v6 writer needs a process-level producer identity: set "
            + ", ".join(missing)
            + " (V6-ENVELOPE.md §1.8). There is no default — an invented harness name "
            "would be a signed falsehood.",
            detail={"fields": missing},
        )
    model = os.environ.get(PRODUCER_ENV["model"], "").strip() or None
    lineage = os.environ.get(PRODUCER_ENV["model_lineage"], "").strip() or None
    return Producer(
        harness=harness, harness_version=harness_version, model=model, model_lineage=lineage
    )


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

    A revocation of **any** acceptance of this principal/key refuses the whole
    resolution with ``KEY_ACCEPTANCE_REVOKED`` — it is not superseded by an older
    surviving anchor, and it is stricter than what the verifier decides. Both halves
    of that are explained at the refusal itself.
    """

    candidates = _anchor_candidate_rows(conn)
    revoked = find_acceptance_revocations(conn)
    acceptance: KeyBindingAnchor | None = None
    bootstrap: KeyBindingAnchor | None = None
    revoked_matches: list[str] = []
    live_matches: list[str] = []
    # Candidates arrive newest-first, so the FIRST live acceptance seen is the newest
    # one — the one carrying current scopes. Nothing returns from inside this loop:
    # the revocation question is about the whole set for this principal/key, and
    # answering it early is precisely the bug B1 named (see below).
    for row in candidates:
        anchor = _anchor_from_row(row)
        if anchor.principal_id != principal_id or anchor.key_id != key_id:
            continue
        if anchor.event_hash in revoked:
            revoked_matches.append(anchor.event_hash)
            continue
        live_matches.append(anchor.event_hash)
        if anchor.kind == "acceptance":
            if acceptance is None:
                acceptance = anchor
        elif bootstrap is None:
            bootstrap = anchor

    # A revocation ANYWHERE for this principal/key refuses, whatever else survives.
    # Falling back turns a revocation into a *privilege escalation*: the operator's
    # most recent word about this key was "no longer usable", and what remains is
    # either an older acceptance (whose scopes the newer one superseded) or the
    # bootstrap anchor (typically the BROADER scope — it carries may_accept_keys).
    #
    # B1 (cross-lineage ceremony, phase 4): this policy is what the comment here has
    # always said, and until now the code delivered it only for the bootstrap case.
    # The loop above used to `continue` past a revoked candidate and RETURN an older
    # live acceptance, so the refusal fired only when the surviving fallback happened
    # to be a bootstrap anchor. The reachable case: the bootstrap principal signs
    # A1(P,K), signs A2(P,K), then revokes A2 — and an ordinary event by P/K resolved
    # A1 and was admitted, silently undoing the latest revocation. Measured as
    # admitted before the fix; pinned by
    # `test_a_revoked_newer_acceptance_does_not_fall_back_to_an_older_one`.
    #
    # THE WRITER IS DELIBERATELY STRICTER THAN THE VERIFIER HERE, and the asymmetry is
    # the point rather than an oversight. `TRUST-DOMAIN.md` §5.10 step 4 is a rule
    # about ONE acceptance hash — "no `principal_key_acceptance_revoked` for `A` lies
    # between `A` and `E`" — and `_verification` implements exactly that, because a
    # verifier must be able to reproduce a verdict over material written years ago by
    # the spec's letter. The writer is deciding something else: whether to *create*
    # new evidence under a key an operator has revoked. Refusing more than the
    # verifier costs a caller nothing but a new `key_id`, and it is the direction that
    # cannot be wrong. One consequence, stated: re-accepting the SAME `key_id` after a
    # revocation no longer restores appendability. A revoked key stays revoked; a
    # replacement key is a new key.
    if revoked_matches:
        raise RegistaError(
            ErrorCode.KEY_ACCEPTANCE_REVOKED,
            f"key {key_id!r} for principal {principal_id!r} has a revoked "
            f"project-local acceptance, so no anchor for it may be used — a "
            f"revocation is not superseded by an older acceptance "
            f"(TRUST-DOMAIN.md §5.8/§5.10 step 4)",
            detail={
                "principal_id": principal_id,
                "key_id": key_id,
                "revoked_acceptances": revoked_matches,
                # What was NOT fallen back to, so the refusal reads as a decision
                # rather than as "nothing was found".
                "superseded_live_anchors": live_matches,
            },
        )
    if acceptance is not None:
        return acceptance
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
# The two payload contracts _trust_log.DEFERRED_TRANSITIONS assigns to P1.7
# ---------------------------------------------------------------------------
#
# `principal_key_accepted` and `principal_key_acceptance_revoked` are listed in
# `_trust_log.DEFERRED_TRANSITIONS` as "P1.7 (§5.8 project-local acceptance)", and
# until now had no parser anywhere — the §5.5 family in `_trust_log.py` covers the
# *trust-log* enrolment events, not the *project-local* acceptance ones. These two
# validators close that gap. They follow the §5.5 parsers' shape deliberately: a
# closed key set (extra keys are a rejection, not forward compatibility), a
# machine-readable `reason` in `detail` so callers assert the named rule rather than
# message text, and no coercion anywhere.

#: ``TRUST-DOMAIN.md`` §5.8's ``regista.key-acceptance/v1``.
KEY_ACCEPTANCE_TYPE: Final[str] = "regista.key-acceptance"
_ACCEPTANCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "project_instance_id",
        "principal_id",
        "key_id",
        "fingerprint",
        "public_key",
        "trust_event_hash",
        "trust_log_checkpoint",
        "scopes",
        "accepted_by",
    }
)
_ACCEPTANCE_SCOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"entity_kinds", "transitions", "may_sign_checkpoints", "may_sign_bundles"}
)
_ACCEPTED_BY_KEYS: Final[frozenset[str]] = frozenset(
    {"principal_id", "key_id", "key_binding_event_hash"}
)
_CHECKPOINT_KEYS: Final[frozenset[str]] = frozenset(
    {"checkpoint_seq", "head_event_hash", "document_digest"}
)

#: The project-local counterpart to a trust-log revocation. §5.10 step 4 requires it
#: — "no ``principal_key_acceptance_revoked`` for ``A`` lies between ``A`` and ``E``"
#: is unimplementable without a contract for the event it looks for.
KEY_ACCEPTANCE_REVOCATION_TYPE: Final[str] = "regista.key-acceptance-revocation"
_REVOCATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "project_instance_id",
        "principal_id",
        "key_id",
        "acceptance_event_hash",
        "reason",
        "revoked_by",
    }
)
#: Reused verbatim from ``_trust_log._REVOCATION_REASONS``: a project-local
#: revocation and a trust-log revocation answer the same question ("why is this key
#: no longer usable") and must not drift into two vocabularies.
_ACCEPTANCE_REVOCATION_REASONS: Final[frozenset[str]] = frozenset(
    {"compromised", "superseded", "decommissioned", "policy", "unspecified"}
)

_DIGEST_LEN: Final[int] = 71


def _acceptance_fail(rule: str, message: str, **detail: Any) -> Any:
    # The parameter is `rule`, not `reason`, precisely so a payload field *named*
    # `reason` can be reported in `detail` without colliding with it. mypy caught
    # the collision; the rename is the fix, not a `# type: ignore`.
    raise RegistaError(
        ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID,
        message,
        detail={"reason": rule, **detail},
    )


def _acceptance_require(condition: bool, rule: str, message: str, **detail: Any) -> None:
    if not condition:
        _acceptance_fail(rule, message, **detail)


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_LEN
        and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def _is_uuid_text(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def validate_key_acceptance_payload(payload: object) -> AcceptanceScopes:
    """Validate a ``regista.key-acceptance/v1`` payload; return its scopes.

    Enforces §5.8's object exactly, plus the two cross-field facts that make the
    payload evidence rather than decoration:

    * ``fingerprint`` must be the SHA-256 of the ``public_key`` bytes it ships beside.
      §5.8 repeats ``public_key`` on purpose so a bundle is self-sufficient for key
      material; a fingerprint that does not match those bytes makes the repetition a
      liability instead of an asset, and §5.8 calls that case "**invalid**, not a
      preference".
    * ``accepted_by.key_binding_event_hash`` must be non-null. This is where Bootstrap
      B's replacement of the self-referential first acceptance actually bites: the
      withdrawn rule nulled exactly this field, so permitting a null here would
      quietly restore it.
    """

    _acceptance_require(
        isinstance(payload, Mapping), "payload_not_object",
        "a key-acceptance payload must be a JSON object",
    )
    assert isinstance(payload, Mapping)
    extra = sorted(set(payload) - _ACCEPTANCE_KEYS)
    missing = sorted(_ACCEPTANCE_KEYS - set(payload))
    _acceptance_require(
        not extra and not missing, "payload_key_set",
        f"a key-acceptance payload has exactly {sorted(_ACCEPTANCE_KEYS)}",
        extra=extra, missing=missing,
    )
    _acceptance_require(
        payload["type"] == KEY_ACCEPTANCE_TYPE, "payload_type",
        f"payload.type must equal {KEY_ACCEPTANCE_TYPE!r}", type=payload["type"],
    )
    _acceptance_require(
        payload["version"] == 1 and isinstance(payload["version"], int)
        and not isinstance(payload["version"], bool),
        "payload_version", "payload.version must be integer 1",
    )
    for field in ("trust_domain_id", "project_instance_id"):
        _acceptance_require(
            _is_uuid_text(payload[field]), f"{field}_not_uuid",
            f"payload.{field} must be lowercase canonical UUID text",
        )
    from ._principals import validate_principal_id

    # §2.7 puts principal_key_accepted in the always-strict column, so the subject
    # goes through the canonical grammar rather than a local string check.
    validate_principal_id(payload["principal_id"], path="payload.principal_id")
    _acceptance_require(
        isinstance(payload["key_id"], str) and bool(payload["key_id"].strip()),
        "key_id_empty", "payload.key_id must be a non-empty string",
    )

    public_key = payload["public_key"]
    _acceptance_require(
        isinstance(public_key, str), "public_key_not_text",
        "payload.public_key must be base64 text for 32 raw bytes",
    )
    assert isinstance(public_key, str)
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    _acceptance_require(
        len(raw) == 32 and base64.b64encode(raw).decode("ascii") == public_key,
        "public_key_not_canonical_base64_32",
        "payload.public_key must be canonical base64 for exactly 32 raw bytes",
    )
    expected_fingerprint = "ed25519:sha256:" + hashlib.sha256(raw).hexdigest()
    _acceptance_require(
        payload["fingerprint"] == expected_fingerprint, "fingerprint_mismatch",
        "payload.fingerprint does not match payload.public_key; §5.8 makes a "
        "disagreement between the repeated key material and its fingerprint invalid, "
        "not a preference",
        fingerprint=payload["fingerprint"], expected=expected_fingerprint,
    )
    _acceptance_require(
        _is_digest(payload["trust_event_hash"]), "trust_event_hash_malformed",
        "payload.trust_event_hash must be sha256:<64 lowercase hex>",
    )

    checkpoint = payload["trust_log_checkpoint"]
    _acceptance_require(
        isinstance(checkpoint, Mapping) and set(checkpoint) == _CHECKPOINT_KEYS,
        "checkpoint_key_set",
        f"payload.trust_log_checkpoint has exactly {sorted(_CHECKPOINT_KEYS)}",
    )
    assert isinstance(checkpoint, Mapping)
    _acceptance_require(
        isinstance(checkpoint["checkpoint_seq"], int)
        and not isinstance(checkpoint["checkpoint_seq"], bool)
        and checkpoint["checkpoint_seq"] >= 1,
        "checkpoint_seq_invalid",
        "payload.trust_log_checkpoint.checkpoint_seq must be an integer >= 1",
    )
    for field in ("head_event_hash", "document_digest"):
        _acceptance_require(
            _is_digest(checkpoint[field]), f"checkpoint_{field}_malformed",
            f"payload.trust_log_checkpoint.{field} must be sha256:<64 lowercase hex>",
        )

    scopes_raw = payload["scopes"]
    _acceptance_require(
        isinstance(scopes_raw, Mapping) and set(scopes_raw) == _ACCEPTANCE_SCOPE_KEYS,
        "scopes_key_set",
        f"payload.scopes has exactly {sorted(_ACCEPTANCE_SCOPE_KEYS)}",
    )
    assert isinstance(scopes_raw, Mapping)
    entity_kinds = scopes_raw["entity_kinds"]
    _acceptance_require(
        isinstance(entity_kinds, list) and bool(entity_kinds)
        and all(isinstance(k, str) and k in _V6_ENTITY_KINDS for k in entity_kinds)
        and len(entity_kinds) == len(set(entity_kinds)),
        "scopes_entity_kinds_invalid",
        "payload.scopes.entity_kinds must be a unique, non-empty set of v6 entity "
        "kinds; there is no wildcard for entity kind",
    )
    transitions = scopes_raw["transitions"]
    _acceptance_require(
        transitions is None or (
            isinstance(transitions, list)
            and all(isinstance(t, str) and t.strip() for t in transitions)
            and len(transitions) == len(set(transitions))
        ),
        "scopes_transitions_invalid",
        'payload.scopes.transitions must be null (meaning "any") or a unique list of '
        "non-empty names. An empty list is legal and authorises nothing — it is NOT "
        "a spelling of null.",
    )
    for flag in ("may_sign_checkpoints", "may_sign_bundles"):
        _acceptance_require(
            isinstance(scopes_raw[flag], bool), f"scopes_{flag}_not_bool",
            f"payload.scopes.{flag} must be a boolean",
        )

    accepted_by = payload["accepted_by"]
    _acceptance_require(
        isinstance(accepted_by, Mapping) and set(accepted_by) == _ACCEPTED_BY_KEYS,
        "accepted_by_key_set",
        f"payload.accepted_by has exactly {sorted(_ACCEPTED_BY_KEYS)}",
    )
    assert isinstance(accepted_by, Mapping)
    validate_principal_id(
        accepted_by["principal_id"], path="payload.accepted_by.principal_id"
    )
    _acceptance_require(
        isinstance(accepted_by["key_id"], str) and bool(accepted_by["key_id"].strip()),
        "accepted_by_key_id_empty",
        "payload.accepted_by.key_id must be a non-empty string",
    )
    _acceptance_require(
        _is_digest(accepted_by["key_binding_event_hash"]),
        "accepted_by_anchor_null_or_malformed",
        "payload.accepted_by.key_binding_event_hash must be sha256:<64 lowercase "
        "hex> and may NOT be null: the withdrawn self-referential first acceptance "
        "(TRUST-DOMAIN.md §5.8, superseded by RECONCILIATION.md Resolution 1) is "
        "exactly the case that nulled this field",
    )
    _acceptance_require(
        accepted_by["principal_id"] != payload["principal_id"]
        or accepted_by["key_id"] != payload["key_id"],
        "self_authorisation",
        "a key may not accept itself: ordinary acceptance runs with no exceptions and "
        "no self-authorisation anywhere (RECONCILIATION.md Resolution 1)",
        principal_id=payload["principal_id"], key_id=payload["key_id"],
    )

    return AcceptanceScopes(
        entity_kinds=frozenset(entity_kinds),
        transitions=None if transitions is None else frozenset(transitions),
        # §5.8's standalone acceptance object has no `may_accept_keys` member — only
        # the bootstrap object does (Resolution 1). An accepted key therefore cannot
        # accept further keys unless the bootstrap authority or the registrar does it,
        # which is the narrower reading and the correct one.
        may_accept_keys=False,
        may_sign_checkpoints=bool(scopes_raw["may_sign_checkpoints"]),
        may_sign_bundles=bool(scopes_raw["may_sign_bundles"]),
    )


def validate_key_acceptance_revocation_payload(payload: object) -> None:
    """Validate a ``regista.key-acceptance-revocation/v1`` payload.

    §5.10 step 4 says "no ``principal_key_acceptance_revoked`` for ``A`` lies between
    ``A`` and ``E`` in ``P``'s chain. Otherwise **INVALID**, reason
    ``KEY_ACCEPTANCE_REVOKED``." That step cannot be implemented against an event
    with no contract, which is why this lands with the writer rather than with the
    verifier that consumes it.
    """

    _acceptance_require(
        isinstance(payload, Mapping), "payload_not_object",
        "a key-acceptance-revocation payload must be a JSON object",
    )
    assert isinstance(payload, Mapping)
    extra = sorted(set(payload) - _REVOCATION_KEYS)
    missing = sorted(_REVOCATION_KEYS - set(payload))
    _acceptance_require(
        not extra and not missing, "payload_key_set",
        f"a key-acceptance-revocation payload has exactly {sorted(_REVOCATION_KEYS)}",
        extra=extra, missing=missing,
    )
    _acceptance_require(
        payload["type"] == KEY_ACCEPTANCE_REVOCATION_TYPE, "payload_type",
        f"payload.type must equal {KEY_ACCEPTANCE_REVOCATION_TYPE!r}",
        type=payload["type"],
    )
    _acceptance_require(
        payload["version"] == 1 and isinstance(payload["version"], int)
        and not isinstance(payload["version"], bool),
        "payload_version", "payload.version must be integer 1",
    )
    for field in ("trust_domain_id", "project_instance_id"):
        _acceptance_require(
            _is_uuid_text(payload[field]), f"{field}_not_uuid",
            f"payload.{field} must be lowercase canonical UUID text",
        )
    from ._principals import validate_principal_id

    validate_principal_id(payload["principal_id"], path="payload.principal_id")
    _acceptance_require(
        isinstance(payload["key_id"], str) and bool(payload["key_id"].strip()),
        "key_id_empty", "payload.key_id must be a non-empty string",
    )
    _acceptance_require(
        _is_digest(payload["acceptance_event_hash"]), "acceptance_event_hash_malformed",
        "payload.acceptance_event_hash must be sha256:<64 lowercase hex>: a revocation "
        "names the exact acceptance it revokes, so §5.10 step 4 can decide by hash "
        "rather than by guessing which acceptance was meant",
    )
    _acceptance_require(
        payload["reason"] in _ACCEPTANCE_REVOCATION_REASONS, "reason_not_in_closed_set",
        "payload.reason must come from the closed §5.7 revocation vocabulary",
        declared_reason=payload["reason"],
        allowed=sorted(_ACCEPTANCE_REVOCATION_REASONS),
    )
    revoked_by = payload["revoked_by"]
    _acceptance_require(
        isinstance(revoked_by, Mapping) and set(revoked_by) == _ACCEPTED_BY_KEYS,
        "revoked_by_key_set",
        f"payload.revoked_by has exactly {sorted(_ACCEPTED_BY_KEYS)}",
    )
    assert isinstance(revoked_by, Mapping)
    validate_principal_id(
        revoked_by["principal_id"], path="payload.revoked_by.principal_id"
    )
    _acceptance_require(
        isinstance(revoked_by["key_id"], str) and bool(revoked_by["key_id"].strip()),
        "revoked_by_key_id_empty",
        "payload.revoked_by.key_id must be a non-empty string",
    )
    _acceptance_require(
        _is_digest(revoked_by["key_binding_event_hash"]),
        "revoked_by_anchor_malformed",
        "payload.revoked_by.key_binding_event_hash must be sha256:<64 lowercase hex>",
    )


def _require_authority_matches_signer(
    payload: object, *, field: str, actor_id: str, key_id: str
) -> None:
    """The ``accepted_by`` / ``revoked_by`` block must BE the signer.

    A document is evidence only where its claims are constrained by something the
    claimant cannot forge. ``accepted_by`` names who exercised the authority; the
    envelope's ``actor.principal_id`` / ``signing.key_id`` name who actually signed.
    If those may differ, the payload asserts an authority that never touched the
    event — a free-text claim wearing a structured field's clothes.
    """

    assert isinstance(payload, Mapping)
    block = payload[field]
    assert isinstance(block, Mapping)
    if block["principal_id"] != actor_id or block["key_id"] != key_id:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"payload.{field} names {block['principal_id']!r}/{block['key_id']!r} but "
            f"the event is signed by {actor_id!r}/{key_id!r}; the block records who "
            "exercised the authority and must be the signer",
            detail={
                "reason": f"{field}_is_not_the_signer",
                "declared_principal_id": block["principal_id"],
                "declared_key_id": block["key_id"],
                "signer_principal_id": actor_id,
                "signer_key_id": key_id,
            },
        )


def _require_authority_may_accept(anchor: KeyBindingAnchor, *, actor_id: str) -> None:
    """Only a key whose anchor grants ``may_accept_keys`` may accept or revoke.

    §5.8: "Subsequent acceptances are still signed by an already-accepted key holding
    ``scopes.may_accept_keys``, or by the registrar." Standalone acceptances never
    grant it (their §5.8 object has no such member), so in practice this is the
    bootstrap authority until the registrar path lands — which is the intended
    narrowness, not an accident.
    """

    if not anchor.scopes.may_accept_keys:
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            f"{actor_id!r} signs with a key whose acceptance does not grant "
            "may_accept_keys, so it may not accept or revoke another key "
            "(TRUST-DOMAIN.md §5.8)",
            detail={
                "reason": "may_accept_keys_not_held",
                "principal_id": actor_id,
                "anchor_kind": anchor.kind,
            },
        )


def find_acceptance_revocations(conn: DictConn) -> dict[str, int]:
    """Map ``acceptance_event_hash`` -> the ``global_seq`` that revoked it.

    Read by :func:`resolve_key_binding_anchor` so a revoked acceptance stops being a
    usable anchor at write time, and available to the verifier for §5.10 step 4's
    "between ``A`` and ``E``" question, which needs positions rather than a boolean.
    """

    rows = conn.execute(
        SQL(
            "SELECT canonical_envelope, global_seq FROM events WHERE transition = %s "
            "ORDER BY global_seq ASC"
        ),
        [PRINCIPAL_KEY_ACCEPTANCE_REVOKED],
    ).fetchall()
    revoked: dict[str, int] = {}
    for row in rows:
        if not row["canonical_envelope"]:
            continue
        try:
            envelope = parse_v6_envelope_strict(bytes(row["canonical_envelope"]))
        except (V6EnvelopeError, TypeError, ValueError):
            continue
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            continue
        target = payload.get("acceptance_event_hash")
        if isinstance(target, str) and target not in revoked:
            revoked[target] = int(row["global_seq"])
    return revoked


def find_previous_workflow_registration(
    conn: DictConn, *, name: str, workflow_version: int
) -> str | None:
    """The registration this one replaces, as a v6 event hash, or ``None``.

    ``V6-ENVELOPE.md`` §1.9 / ``RECONCILIATION.md`` Resolution 2: "Exactly one
    registration may introduce ``(name, workflow_version)`` in a project … A
    replacement uses a new version and **may** name
    ``supersedes_registration_event_hash``." The writer used to hardcode ``None``
    there, so the field was a signed constant: every replacement claimed to replace
    nothing, and the provenance chain between versions of a workflow did not exist in
    the signed record at all (phase-4 ceremony NB6).

    "The registration this one replaces" is the **highest prior version of the same
    name**, tie-broken on chain position. Two properties make that the right answer
    rather than a convenient one:

    * A *lower* version registered later is not a replacement of a higher one, so
      registering v1 after v3 correctly supersedes nothing. Only versions below this
      one are candidates.
    * The answer is a function of signed events, not of the ``workflow_registry`` row,
      which is mutable and is precisely what §1.9 exists to stop being the referent.

    Retirement is deliberately not consulted: ``workflow_retired`` has no writer in
    this release, and §1.9's rule about retirement constrains events that *refer to* a
    registration through ``workflow.registration_event_hash``, not a later registration
    recording what it replaced.
    """

    from ._signing import compute_v6_event_hash

    rows = conn.execute(
        SQL(
            "SELECT canonical_envelope, signature, global_seq FROM events "
            "WHERE transition = %s ORDER BY global_seq ASC"
        ),
        [WORKFLOW_REGISTERED],
    ).fetchall()

    best: tuple[int, int] | None = None
    best_hash: str | None = None
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
        if payload.get("name") != name:
            continue
        prior_version = payload.get("workflow_version")
        if not isinstance(prior_version, int) or isinstance(prior_version, bool):
            continue
        if prior_version >= workflow_version:
            continue
        position = (prior_version, int(row["global_seq"]))
        if best is None or position > best:
            best = position
            best_hash = "sha256:" + compute_v6_event_hash(
                bytes(row["canonical_envelope"]), bytes(row["signature"])
            ).hex()
    return best_hash


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
    # A pinned `key_fingerprints` set is a *restriction*, so an unknown fingerprint is
    # a NON-MATCH — including the "no fingerprint presented" case. The old condition
    # was `entry.key_fingerprints and key_fingerprint is not None and ...`, which
    # skipped the pin entirely when the caller passed nothing: an entry pinned to one
    # key matched an event whose key was never named. That is fail-open by omission,
    # and it was latent rather than exploited only because the one production caller
    # (`append_v6_event`) always passes `key_entry.fingerprint()`. A gate whose
    # strictness depends on a caller remembering an optional argument is not a gate
    # (phase-4 ceremony NB2).
    fingerprint_rejected = False
    for entry in entries:
        if producer.harness not in entry.allowed_harnesses:
            continue
        if entry.key_fingerprints and (
            key_fingerprint is None or key_fingerprint not in entry.key_fingerprints
        ):
            fingerprint_rejected = True
            continue
        return "matches_published_policy"
    if fingerprint_rejected:
        # Named separately from the harness refusal because the operator response is
        # different: one is "this harness may not sign for this principal", the other
        # is "this KEY may not", and reporting the first for the second sends the
        # reader to the wrong half of the policy.
        raise RegistaError(
            ErrorCode.PRODUCER_NOT_AUTHORIZED,
            f"key fingerprint {key_fingerprint!r} is not pinned for principal "
            f"{principal_id!r} under the supplied producer policy; a pinned "
            "key_fingerprints set is a restriction, and an unnamed key does not "
            "satisfy it (V6-ENVELOPE.md §1.8, TRUST-DOMAIN.md §4.3)",
            detail={
                "reason": "key_fingerprint_not_pinned",
                "key_fingerprint": key_fingerprint,
                "principal_id": principal_id,
                "harness": producer.harness,
                "pinned_fingerprints": sorted(
                    {f for entry in entries for f in entry.key_fingerprints}
                ),
            },
        )
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
        "occurred_at": v6_occurred_at(occurred_at),
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

    # The two transitions this module owns get their payloads validated here, so an
    # unparseable acceptance can never become an anchor a later event depends on.
    #
    # The payload validators check the DOCUMENT; only the writer can check the
    # document against the ENVELOPE, so the accepter/revoker cross-check lives here.
    # Without it an acceptance could name any `accepted_by` it liked while being
    # signed by someone else entirely — the document would claim an authority that
    # never touched it, which is the self-asserted-string failure the whole release
    # exists to remove. Found by mutation M14's survival prompting a re-read.
    if transition == PRINCIPAL_KEY_ACCEPTED:
        validate_key_acceptance_payload(payload)
        _require_authority_matches_signer(
            payload, field="accepted_by", actor_id=actor_id, key_id=key_entry.key_id
        )
        _require_authority_may_accept(anchor, actor_id=actor_id)
    elif transition == PRINCIPAL_KEY_ACCEPTANCE_REVOKED:
        validate_key_acceptance_revocation_payload(payload)
        _require_authority_matches_signer(
            payload, field="revoked_by", actor_id=actor_id, key_id=key_entry.key_id
        )
        _require_authority_may_accept(anchor, actor_id=actor_id)

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

    stored_time = parse_v6_occurred_at(envelope["occurred_at"])
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
    "KEY_ACCEPTANCE_REVOCATION_TYPE",
    "KEY_ACCEPTANCE_TYPE",
    "PRINCIPAL_KEY_ACCEPTANCE_REVOKED",
    "PRINCIPAL_KEY_ACCEPTED",
    "PRODUCER_ENV",
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
    "find_acceptance_revocations",
    "read_project_identity",
    "require_v6_epoch",
    "resolve_key_binding_anchor",
    "resolve_producer",
    "resolve_workflow_registration",
    "validate_key_acceptance_payload",
    "validate_key_acceptance_revocation_payload",
    "workflow_definition_hash",
]
