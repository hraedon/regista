"""WI-325: assemble a per-project v6 genesis from LIVE trust-log facts.

``_genesis.append_v6_genesis`` is the writer. It takes a finished, ready-to-sign
``project_initialized`` envelope and it is *strict about shape*: every load-bearing
field, the closed ``bootstrap_key_acceptance`` key set, the digest grammar of
``trust_event_hash`` and of the three ``trust_log_checkpoint`` members. What it
cannot do — because it never opens the trust log — is decide whether any of those
well-formed values are **true**. ``_genesis.py`` never queries ``regista_trust``, so
before this module a project could be opened with a self-consistent but entirely
fabricated trust reference: an unenrolled principal, a revoked key, a
``trust_event_hash`` naming nothing, a checkpoint naming a head that never existed.

This module is where those values come from, and it resolves every one of them from
the verified trust-log chain walk rather than from a projection row or an operator
flag:

* :func:`resolve_enrolled_key` — the principal's ``principal_key_enrolled`` event,
  found in :func:`~regista._trust_log_writer.verify_trust_log_chain`'s output, with
  its key ACTIVE in the replayed state, its public key byte-equal to the material the
  event enrolled, its fingerprint recomputed from those bytes, and its validity window
  containing the genesis instant. ``principal_keys`` is consulted only as a
  cross-check: a row that disagrees with the chain is a refusal, and an absent row is
  not (§5.9 rule 1 — the projection is never the authority).
* :func:`derive_trust_log_checkpoint` — the ``{checkpoint_seq, head_event_hash,
  document_digest}`` triplet, from the head the same verified walk reached.
* :func:`load_gate_evidence` — the EPOCH-RESET §5 first-write verdict, as the
  ``agent-suite genesis-gate --json`` report, bound to this store fingerprint and this
  project. ``initialize_epoch(..., gate_passed=True)`` is never asserted without it.
* :func:`build_project_initialized_envelope` — the envelope itself, which until now
  existed only in ``tests/_v6_fixtures.py``.

**Where each guarantee lives.** Everything here is CLI-side by nature: it is the
*assembly* of the inputs, and assembly cannot be writer-side because the writer's
argument is the finished envelope. What the writer re-verifies independently, on the
signed bytes, in the same transaction as the insert: the empty-store precondition
(``first_write_admission``), the complete envelope shape, the acceptance's internal
consistency against the resolved signing key, and the signature under the bound
Ed25519 public key. What ONLY this module establishes: that the trust reference in
those signed bytes corresponds to the live trust log. A caller that builds an envelope
by hand and calls ``initialize_epoch`` directly still gets the writer's guarantees and
does NOT get these — which is why ``regista genesis init`` is the supported path.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from ._connection import DictConn
from ._errors import ErrorCode, RegistaError

#: The default project-local scopes granted to the bootstrap key by its own
#: acceptance. ``project`` is mandatory (``_genesis._validate_bootstrap_acceptance``
#: refuses an acceptance that does not authorise project genesis) and the other three
#: are what a freshly opened project needs in order to be usable at all: accept a
#: second writer's key, register a workflow, create a work item. Narrower is
#: expressible with ``--scope-entity-kind``; wider is the operator's explicit choice,
#: never a default.
DEFAULT_SCOPE_ENTITY_KINDS: Final[tuple[str, ...]] = (
    "project",
    "principal",
    "workflow",
    "work_item",
)

#: The ``agent-suite genesis-gate --json`` report versions this code understands. An
#: unrecognised version is a refusal, not a best-effort parse: a v2 report could move
#: ``epoch_may_open``'s meaning, and reading it as v1 would turn a BLOCKED gate into a
#: PASS. Fail closed on the version, always.
SUPPORTED_GATE_REPORT_VERSIONS: Final[frozenset[int]] = frozenset({1})

#: The type tag on the locally derived, unsigned trust-log observation whose digest
#: fills ``trust_log_checkpoint.document_digest`` when no PUBLISHED checkpoint document
#: is supplied. Deliberately NOT ``regista.trust-checkpoint``: a §4.3 checkpoint is a
#: signed, published, sequence-numbered document, and minting one of those here — with
#: no signer and no publication — would be exactly the "unobserved claim in a field
#: that reads as observed" EPOCH-RESET §6 rule 3 forbids. This document says only what
#: it is: one process's verified observation of the trust log at one instant.
TRUST_LOG_OBSERVATION_TYPE: Final[str] = "regista.trust-log-observation"

_ENROLLED = "principal_key_enrolled"
_ROTATED = "principal_key_rotated"


def _refuse(code: ErrorCode, message: str, reason: str, **detail: Any) -> Any:
    raise RegistaError(code, message, {"reason": reason, **detail})


def _unverified(message: str, reason: str, **detail: Any) -> Any:
    return _refuse(
        ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED, message, reason, **detail
    )


def _fingerprint_of(public_key: bytes) -> str:
    return "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# The trust-log checkpoint triplet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustLogCheckpoint:
    """The ``{checkpoint_seq, head_event_hash, document_digest}`` acceptance member.

    ``source`` records HOW the triplet was obtained, and it is reported everywhere the
    checkpoint is: ``"published"`` when an operator supplied a signed §4.3 checkpoint
    document that was then reconciled against the live log, ``"derived"`` when this
    process observed the log itself. The two are not equivalent evidence and the
    difference is never left implicit.
    """

    checkpoint_seq: int
    head_event_hash: str
    document_digest: str
    source: str
    document: Mapping[str, Any] = field(default_factory=dict)

    def as_payload_member(self) -> dict[str, Any]:
        """Exactly the three keys ``_genesis._validate_bootstrap_acceptance`` allows."""
        return {
            "checkpoint_seq": self.checkpoint_seq,
            "head_event_hash": self.head_event_hash,
            "document_digest": self.document_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.as_payload_member(), "source": self.source}


def _max_global_seq(conn: DictConn) -> int | None:
    """The trust log's highest ``global_seq``, informational only.

    ``TRUST-DOMAIN.md`` §4.3: "``max_global_seq`` is informational and is never the
    binding". It is reported because a checkpoint document declares it, and it is
    never compared for equality by anything here.
    """
    row = conn.execute("SELECT MAX(global_seq) AS max_seq FROM events").fetchone()
    if row is None or row["max_seq"] is None:
        return None
    return int(row["max_seq"])


def derive_trust_log_checkpoint(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    checkpoint_seq: int = 1,
    observed_at: datetime | None = None,
    verified: Any | None = None,
) -> TrustLogCheckpoint:
    """Observe the live trust log and mint the checkpoint triplet from that observation.

    The head is taken from :func:`verify_trust_log_chain`'s own return value, so the
    hash that lands in signed genesis bytes is one an authority-verified walk arrived
    at — not one read back off an unverified row. ``document_digest`` is the JCS digest
    of the observation document this function builds, which is emitted alongside the
    triplet so the operator can publish or archive the exact bytes the digest covers.
    """
    from ._jcs import canonicalize
    from ._trust_domain import parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    if not isinstance(checkpoint_seq, int) or isinstance(checkpoint_seq, bool):
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "checkpoint_seq must be an integer",
            "checkpoint_seq_not_integer",
        )
    if checkpoint_seq < 1:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            f"checkpoint_seq must be >= 1 (§5.8 requires it); got {checkpoint_seq}",
            "checkpoint_seq_below_one",
            checkpoint_seq=checkpoint_seq,
        )

    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)
    document = {
        "type": TRUST_LOG_OBSERVATION_TYPE,
        "version": 1,
        "trust_domain_id": str(doc.trust_domain_id),
        "trust_domain_core_digest": doc.trust_domain_core_digest,
        "checkpoint_seq": checkpoint_seq,
        "trust_log": {
            "project_instance_id": str(doc.trust_log.project_instance_id),
            "event_count": chain.event_count,
            "genesis_event_hash": chain.state.genesis_event_hash,
            "head_event_hash": chain.head_event_hash,
            "max_global_seq": _max_global_seq(conn),
        },
        "root_governance": {
            "threshold": chain.state.governance.threshold,
            "signer_count": len(chain.state.governance.signer_fingerprints),
        },
        "active_root_fingerprints": sorted(chain.state.governance.signer_fingerprints),
        "prev_checkpoint_digest": None,
        "observed_at": _iso_micro_z(observed_at or datetime.now(UTC)),
    }
    return TrustLogCheckpoint(
        checkpoint_seq=checkpoint_seq,
        head_event_hash=chain.head_event_hash,
        document_digest="sha256:" + hashlib.sha256(canonicalize(document)).hexdigest(),
        source="derived",
        document=document,
    )


def load_published_checkpoint(
    path: str,
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    verified: Any | None = None,
) -> TrustLogCheckpoint:
    """Read a published §4.3 checkpoint document and reconcile it with the live log.

    A published checkpoint is stronger evidence than a local observation only if it is
    actually checked against the log it claims to describe. Every field that can be
    contradicted is contradicted here: the trust domain, the trust-log project
    instance, the genesis event hash, the head, and the event count. A checkpoint that
    describes a different log, or a stale state of this one, is refused rather than
    signed into a project's first event.
    """
    from ._jcs import canonicalize
    from ._trust_domain import parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        _unverified(
            f"cannot read --trust-checkpoint {path!r}: {exc}",
            "checkpoint_file_unreadable",
            path=path,
        )
    except (ValueError, UnicodeError) as exc:
        _unverified(
            f"--trust-checkpoint {path!r} is not valid JSON: {exc}",
            "checkpoint_file_invalid_json",
            path=path,
        )
    if not isinstance(raw, Mapping):
        _unverified(
            f"--trust-checkpoint {path!r} must contain a JSON object",
            "checkpoint_document_not_object",
            path=path,
        )
    assert isinstance(raw, Mapping)

    seq = raw.get("checkpoint_seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        _unverified(
            "the checkpoint document's checkpoint_seq must be an integer >= 1",
            "checkpoint_seq_invalid",
            checkpoint_seq=seq,
        )
    assert isinstance(seq, int)

    log = raw.get("trust_log")
    if not isinstance(log, Mapping):
        _unverified(
            "the checkpoint document has no trust_log object",
            "checkpoint_trust_log_absent",
        )
    assert isinstance(log, Mapping)

    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)

    for field_name, stated, actual in (
        ("trust_domain_id", raw.get("trust_domain_id"), str(doc.trust_domain_id)),
        (
            "trust_domain_core_digest",
            raw.get("trust_domain_core_digest"),
            doc.trust_domain_core_digest,
        ),
        (
            "trust_log.project_instance_id",
            log.get("project_instance_id"),
            str(doc.trust_log.project_instance_id),
        ),
        (
            "trust_log.genesis_event_hash",
            log.get("genesis_event_hash"),
            chain.state.genesis_event_hash,
        ),
        ("trust_log.head_event_hash", log.get("head_event_hash"), chain.head_event_hash),
    ):
        if stated != actual:
            _unverified(
                f"the supplied checkpoint's {field_name} is {stated!r}, but the live "
                f"trust log's is {actual!r}; a checkpoint that does not describe this "
                "log's current state is not evidence about it",
                "checkpoint_disagrees_with_live_log",
                field=field_name,
                stated=stated,
                actual=actual,
            )
    stated_count = log.get("event_count")
    if stated_count != chain.event_count:
        _unverified(
            f"the supplied checkpoint states event_count {stated_count!r}, but the "
            f"verified walk reached {chain.event_count} event(s)",
            "checkpoint_event_count_mismatch",
            stated=stated_count,
            actual=chain.event_count,
        )
    return TrustLogCheckpoint(
        checkpoint_seq=seq,
        head_event_hash=chain.head_event_hash,
        document_digest="sha256:" + hashlib.sha256(canonicalize(raw)).hexdigest(),
        source="published",
        document=dict(raw),
    )


# ---------------------------------------------------------------------------
# The enrolled key, resolved from the verified chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrolledKey:
    """One principal's live, ACTIVE, chain-verified enrolment."""

    principal_id: str
    principal_kind: str
    key_id: str
    public_key: bytes
    fingerprint: str
    #: The ``principal_key_enrolled`` event's own hash — what
    #: ``bootstrap_key_acceptance.trust_event_hash`` must name.
    trust_event_hash: str
    not_before: datetime
    not_after: datetime | None
    #: ``"agree"`` when a ``principal_keys`` row was found and matched the chain,
    #: ``"absent"`` when the projection has no row for this key. Never ``"disagree"``:
    #: a disagreeing row is a refusal, not a report.
    projection: str

    @property
    def public_key_b64(self) -> str:
        return _b64(self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "public_key": self.public_key_b64,
            "trust_event_hash": self.trust_event_hash,
            "not_before": _iso_micro_z(self.not_before),
            "not_after": None if self.not_after is None else _iso_micro_z(self.not_after),
            "projection": self.projection,
        }


def _iso_micro_z(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _projection_cross_check(
    conn: DictConn, principal_id: str, key_id: str, public_key: bytes, source_hash: str
) -> str:
    """Compare the ``principal_keys`` row against the chain, or report its absence.

    §5.9 rule 1: no verifier resolves a key FROM this table. So an absent row is not an
    error — the projection may simply not have been rebuilt. A row that CONTRADICTS the
    verified chain is a different matter: it means the table and the log disagree about
    the key a project is about to bind its whole history to, and the honest response is
    to stop and make the operator rebuild.
    """
    present = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE "
        "table_schema = current_schema() AND table_name = 'principal_keys') AS present"
    ).fetchone()
    if present is None or not present["present"]:
        # A trust-log schema without the projection table cannot contradict anything.
        # Reported, not raised: §5.9 rule 1 means the table's absence is never grounds
        # to refuse, and a raw UndefinedTable here would be an unnamed failure.
        return "absent"
    row = conn.execute(
        "SELECT principal_id, key_id, public_key, fingerprint, status, source_event_hash "
        "FROM principal_keys WHERE principal_id = %s AND key_id = %s",
        [principal_id, key_id],
    ).fetchone()
    if row is None:
        return "absent"
    mismatches: list[str] = []
    if bytes(row["public_key"]) != public_key:
        mismatches.append("public_key")
    if row["fingerprint"] != _fingerprint_of(public_key):
        mismatches.append("fingerprint")
    if row["status"] != "active":
        mismatches.append("status")
    if row["source_event_hash"] != source_hash:
        mismatches.append("source_event_hash")
    if mismatches:
        _unverified(
            f"the principal_keys projection row for {principal_id}/{key_id} "
            f"contradicts the verified trust-log chain on: {', '.join(mismatches)}. "
            "The projection is not the authority (§5.9 rule 1), but a projection that "
            "disagrees with the log is not evidence of anything either — run "
            "`regista trust rebuild-projection` and re-check before opening an epoch.",
            "projection_disagrees_with_chain",
            principal_id=principal_id,
            key_id=key_id,
            fields=mismatches,
        )
    return "agree"


def resolve_enrolled_key(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    principal_id: str,
    key_id: str | None = None,
    expected_trust_event_hash: str | None = None,
    at: datetime | None = None,
    verified: Any | None = None,
) -> EnrolledKey:
    """Resolve one principal's live enrolled key from the VERIFIED trust-log chain.

    ``at`` is the instant the enrolment must be valid at — the genesis's own
    ``occurred_at`` — and it defaults to now. Every refusal names a distinct reason
    because the operator's next action differs for each: enrol the principal, rotate a
    revoked key, wait for a not-yet-valid window, re-enrol an expired one, or pass
    ``--key-id`` to disambiguate.
    """
    from ._trust_log import parse_principal_key_enrolled
    from ._trust_log_writer import verify_trust_log_chain

    moment = at or datetime.now(UTC)
    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)

    # Every principal_key_enrolled the verified walk accepted, for this principal.
    candidates: list[tuple[Any, Any]] = []
    for record in chain.verified:
        if record.transition != _ENROLLED:
            continue
        parsed = parse_principal_key_enrolled(record.payload)
        if parsed.principal_id != principal_id:
            continue
        candidates.append((record, parsed))

    # This principal's rotations, and the key_ids they SUPERSEDE. This matters more than
    # it looks: `_trust_log_writer._classify_rotation` does NOT flip the superseded key's
    # entry in `principal_key_status` — a rotation only records the incoming key as
    # "active" (`_remember_principal_key`). So after a rotation the outgoing key is
    # STILL "active" in the replayed status map, and an "is it active?" test alone would
    # happily resolve a superseded key and sign a project's genesis with it. Supersession
    # has to be read off the rotation events themselves.
    rotations = [
        r
        for r in chain.verified
        if r.transition == _ROTATED
        and isinstance(r.payload, Mapping)
        and r.payload.get("principal_id") == principal_id
    ]
    superseded_key_ids = {
        r.payload["supersedes_key_id"]
        for r in rotations
        if isinstance(r.payload.get("supersedes_key_id"), str)
    }

    def _rotation_refusal() -> None:
        # `bootstrap_key_acceptance.trust_event_hash` names an ENROLMENT event. A
        # rotation-sourced key has no such event, and quietly pointing the field at a
        # principal_key_rotated hash would make the acceptance say something untrue about
        # which event introduced the key.
        _unverified(
            f"{principal_id!r} has trust-log key history, but its current key came from "
            "principal_key_rotated, not principal_key_enrolled. "
            "bootstrap_key_acceptance.trust_event_hash names an ENROLMENT event, so "
            "there is nothing honest to put in it for a rotation-sourced key. Opening a "
            "project genesis under a rotated key is not supported by this command.",
            "key_source_is_rotation_not_enrollment",
            principal_id=principal_id,
            rotation_events=len(rotations),
            superseded_key_ids=sorted(superseded_key_ids),
        )

    if not candidates:
        if rotations:
            _rotation_refusal()
        _unverified(
            f"{principal_id!r} has no principal_key_enrolled event in the verified "
            "trust log; enrol the principal with `regista trust enroll` before opening "
            "a project epoch as it",
            "principal_not_enrolled",
            principal_id=principal_id,
        )

    if key_id is not None:
        narrowed = [(r, p) for r, p in candidates if p.key.key_id == key_id]
        if not narrowed:
            _unverified(
                f"{principal_id!r} has no principal_key_enrolled event for key_id "
                f"{key_id!r}; enrolled key ids are: "
                + ", ".join(sorted(p.key.key_id for _r, p in candidates)),
                "key_id_not_enrolled",
                principal_id=principal_id,
                key_id=key_id,
                enrolled_key_ids=sorted(p.key.key_id for _r, p in candidates),
            )
        candidates = narrowed

    # Drop superseded enrolments BEFORE the active test, so the more specific reason
    # wins: "your enrolled key was rotated away" is actionable, "it is not active" would
    # be both vaguer and — given the status map above — wrong.
    unsuperseded = [(r, p) for r, p in candidates if p.key.key_id not in superseded_key_ids]
    if not unsuperseded:
        _rotation_refusal()
    candidates = unsuperseded

    status = chain.state.principal_key_status
    live = [
        (r, p) for r, p in candidates if status.get((principal_id, p.key.key_id)) == "active"
    ]
    if not live:
        _unverified(
            f"every enrolled key for {principal_id!r} is revoked in the verified trust "
            "log; a revoked key may not sign a project's genesis",
            "enrolled_key_not_active",
            principal_id=principal_id,
            key_ids=sorted(p.key.key_id for _r, p in candidates),
            statuses={
                p.key.key_id: status.get((principal_id, p.key.key_id))
                for _r, p in candidates
            },
        )
    if len(live) > 1:
        _unverified(
            f"{principal_id!r} has {len(live)} active enrolled keys "
            f"({', '.join(sorted(p.key.key_id for _r, p in live))}); pass --key-id to "
            "name the one that signs this genesis rather than letting the tool choose "
            "which key a project's whole history is bound to",
            "enrolled_key_ambiguous",
            principal_id=principal_id,
            key_ids=sorted(p.key.key_id for _r, p in live),
        )

    record, parsed = live[0]
    resolved_key_id = parsed.key.key_id

    # The validity window is the enrolment's own claim about when the key is usable.
    # verify_trust_log_chain evaluates registrar liveness at each event's occurred_at;
    # nothing there checks the ENROLLED key against the instant it is about to sign.
    if moment < parsed.not_before:
        _unverified(
            f"the enrolment of {principal_id}/{resolved_key_id} is not valid until "
            f"{_iso_micro_z(parsed.not_before)}, which is after the genesis instant "
            f"{_iso_micro_z(moment)}",
            "enrollment_not_yet_valid",
            principal_id=principal_id,
            key_id=resolved_key_id,
            not_before=_iso_micro_z(parsed.not_before),
            at=_iso_micro_z(moment),
        )
    if parsed.not_after is not None and moment >= parsed.not_after:
        _unverified(
            f"the enrolment of {principal_id}/{resolved_key_id} expired at "
            f"{_iso_micro_z(parsed.not_after)}, before the genesis instant "
            f"{_iso_micro_z(moment)}",
            "enrollment_expired",
            principal_id=principal_id,
            key_id=resolved_key_id,
            not_after=_iso_micro_z(parsed.not_after),
            at=_iso_micro_z(moment),
        )

    # The replayed state's key bytes and the enrolment payload's must agree, and the
    # fingerprint must be recomputed from the bytes rather than trusted as stated.
    replayed = chain.state.principal_public_keys.get((principal_id, resolved_key_id))
    if replayed is None or replayed != parsed.key.public_key:
        _unverified(
            f"the replayed public key for {principal_id}/{resolved_key_id} does not "
            "match the key material its enrolment event carries",
            "replayed_public_key_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
        )
    recomputed = _fingerprint_of(parsed.key.public_key)
    if parsed.key.fingerprint != recomputed:
        _unverified(
            f"the enrolment of {principal_id}/{resolved_key_id} states fingerprint "
            f"{parsed.key.fingerprint!r}, which is not the digest of the public key it "
            "carries",
            "enrollment_fingerprint_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
        )
    if parsed.key.scheme_id != "ed25519":
        _unverified(
            f"the enrolment of {principal_id}/{resolved_key_id} declares scheme "
            f"{parsed.key.scheme_id!r}; a v6 project genesis is Ed25519-only",
            "enrollment_scheme_not_ed25519",
            principal_id=principal_id,
            key_id=resolved_key_id,
            scheme_id=parsed.key.scheme_id,
        )

    # An operator-claimed trust_event_hash is checked, never taken. This is the
    # concrete hole `_genesis.py:396` leaves open: there, the value only has to LOOK
    # like a digest.
    if expected_trust_event_hash is not None and expected_trust_event_hash != record.event_hash:
        _unverified(
            f"--trust-event-hash {expected_trust_event_hash!r} is not the "
            f"principal_key_enrolled event for {principal_id}/{resolved_key_id}; that "
            f"event's hash is {record.event_hash!r}",
            "trust_event_hash_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
            claimed=expected_trust_event_hash,
            actual=record.event_hash,
        )

    projection = _projection_cross_check(
        conn, principal_id, resolved_key_id, parsed.key.public_key, record.event_hash
    )
    return EnrolledKey(
        principal_id=principal_id,
        principal_kind=parsed.principal_kind,
        key_id=resolved_key_id,
        public_key=parsed.key.public_key,
        fingerprint=recomputed,
        trust_event_hash=record.event_hash,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        projection=projection,
    )


# ---------------------------------------------------------------------------
# The whole verified reference
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustReference:
    """Everything a ``project_initialized`` envelope needs, all of it verified."""

    trust_domain_id: str
    trust_domain_core_digest: str
    genesis_document_digest: str
    trust_log_project_instance_id: str
    key: EnrolledKey
    checkpoint: TrustLogCheckpoint

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "genesis_document_digest": self.genesis_document_digest,
            "trust_log_project_instance_id": self.trust_log_project_instance_id,
            "key": self.key.to_dict(),
            "checkpoint": self.checkpoint.to_dict(),
        }


def resolve_trust_reference(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    principal_id: str,
    key_id: str | None = None,
    expected_trust_event_hash: str | None = None,
    expected_trust_domain_id: str | None = None,
    at: datetime | None = None,
    checkpoint_seq: int = 1,
    published_checkpoint_path: str | None = None,
) -> TrustReference:
    """One verified walk; every genesis input derived from it.

    ``verify_trust_log_chain`` is run ONCE and its result threaded through the key
    resolution and the checkpoint derivation, so the enrolment and the head cannot be
    read from two different views of the log.
    """
    from ._trust_domain import genesis_document_digest, parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    chain = verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)
    trust_domain_id = str(doc.trust_domain_id)

    # verify_trust_log_chain already refuses a stored genesis whose trust_domain_id
    # differs from the pinned document, and every lifecycle event that names another
    # domain. This is the operator's own expectation, checked against the same
    # verified document: `--trust-domain-id` is how a ceremony script asserts "the
    # domain I think I am joining" and gets told if it is wrong.
    if expected_trust_domain_id is not None and expected_trust_domain_id != trust_domain_id:
        _unverified(
            f"the verified trust log's domain is {trust_domain_id!r}, not the expected "
            f"{expected_trust_domain_id!r}",
            "trust_domain_id_mismatch",
            expected=expected_trust_domain_id,
            actual=trust_domain_id,
        )

    key = resolve_enrolled_key(
        conn,
        genesis_document,
        principal_id=principal_id,
        key_id=key_id,
        expected_trust_event_hash=expected_trust_event_hash,
        at=at,
        verified=chain,
    )
    if published_checkpoint_path is not None:
        checkpoint = load_published_checkpoint(
            published_checkpoint_path, conn, genesis_document, verified=chain
        )
    else:
        checkpoint = derive_trust_log_checkpoint(
            conn,
            genesis_document,
            checkpoint_seq=checkpoint_seq,
            observed_at=at,
            verified=chain,
        )
    return TrustReference(
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=doc.trust_domain_core_digest,
        genesis_document_digest=genesis_document_digest(genesis_document),
        trust_log_project_instance_id=str(doc.trust_log.project_instance_id),
        key=key,
        checkpoint=checkpoint,
    )


# ---------------------------------------------------------------------------
# EPOCH-RESET §5: the first-write verdict, as evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateEvidence:
    """A validated ``agent-suite genesis-gate --json`` report for THIS target."""

    path: str
    report_version: int
    store_fingerprint: str
    project: str
    observation_snapshot: str | None
    finding_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "report_version": self.report_version,
            "store_fingerprint": self.store_fingerprint,
            "project": self.project,
            "observation_snapshot": self.observation_snapshot,
            "findings": self.finding_count,
            "epoch_may_open": True,
        }


def _gate_refuse(message: str, reason: str, **detail: Any) -> Any:
    return _refuse(ErrorCode.GENESIS_GATE_EVIDENCE_INVALID, message, reason, **detail)


def load_gate_evidence(path: str | None, *, dsn: str, project: str) -> GateEvidence:
    """Validate the §5 gate report, or refuse. There is no default-true.

    ``initialize_epoch``'s ``gate_passed`` is a bare boolean, and a CLI that defaulted
    it to ``True`` would make EPOCH-RESET §5 ("the store conformance check gates the
    epoch; if it does not pass, the epoch does not open") a comment. So the flag is
    only ever set from a report that: is the version this code understands, says
    ``ok`` AND ``epoch_may_open`` are both exactly ``True``, carries no non-passing
    finding, has healthy probes, and is BOUND to the store fingerprint and project
    about to be written. The binding is the part that matters most: a PASS report for
    a throwaway fixture store is a real report about the wrong store, and without the
    fingerprint check it would open an epoch anywhere.

    There is deliberately no override. A gate that cannot pass is a gate telling the
    truth about a store that is not ready.
    """
    from ._invariant_probe import postgres_database_fingerprint

    if path is None:
        _gate_refuse(
            "no genesis-gate evidence: pass --gate-report PATH pointing at the output "
            "of `agent-suite genesis-gate --json --exit-code`. EPOCH-RESET §5 makes the "
            "gate a precondition on the FIRST WRITE, so there is no default and no "
            "override — an epoch does not open on an unevidenced assertion that it may.",
            "gate_report_absent",
        )
    assert path is not None
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        _gate_refuse(
            f"cannot read --gate-report {path!r}: {exc}",
            "gate_report_unreadable",
            path=path,
        )
    except (ValueError, UnicodeError) as exc:
        _gate_refuse(
            f"--gate-report {path!r} is not valid JSON: {exc}",
            "gate_report_invalid_json",
            path=path,
        )
    if not isinstance(raw, Mapping):
        _gate_refuse(
            f"--gate-report {path!r} must contain a JSON object",
            "gate_report_not_object",
            path=path,
        )
    assert isinstance(raw, Mapping)

    if raw.get("kind") != "genesis_gate":
        _gate_refuse(
            f"--gate-report {path!r} has kind {raw.get('kind')!r}; this must be the "
            "`agent-suite genesis-gate --json` report (kind 'genesis_gate'), not the "
            "`invariant-probes` report, which carries no first-write verdict",
            "gate_report_wrong_kind",
            kind=raw.get("kind"),
        )
    version = raw.get("report_version")
    if not isinstance(version, int) or isinstance(version, bool):
        _gate_refuse(
            "the gate report has no integer report_version",
            "gate_report_version_absent",
            report_version=version,
        )
    assert isinstance(version, int)
    if version not in SUPPORTED_GATE_REPORT_VERSIONS:
        _gate_refuse(
            f"the gate report declares report_version {version}, which this regista "
            f"does not understand (supported: {sorted(SUPPORTED_GATE_REPORT_VERSIONS)}). "
            "Refusing to interpret an unknown report version — a later version could "
            "change what epoch_may_open means.",
            "gate_report_version_unsupported",
            report_version=version,
        )

    if raw.get("epoch_may_open") is not True or raw.get("ok") is not True:
        _gate_refuse(
            "the gate report does not say the epoch may open "
            f"(ok={raw.get('ok')!r}, epoch_may_open={raw.get('epoch_may_open')!r}). "
            "Resolve the blocking findings and re-run the gate; the epoch does not "
            "open on a BLOCKED verdict.",
            "gate_did_not_pass",
            ok=raw.get("ok"),
            epoch_may_open=raw.get("epoch_may_open"),
        )

    findings = raw.get("findings")
    if not isinstance(findings, Sequence) or isinstance(findings, str | bytes):
        _gate_refuse(
            "the gate report has no findings list",
            "gate_report_findings_absent",
        )
    assert isinstance(findings, Sequence)
    if not findings:
        _gate_refuse(
            "the gate report carries zero findings; a gate that checked nothing is not "
            "a PASS, whatever its ok flag says",
            "gate_report_findings_empty",
        )
    # `ok` is not taken on trust: a report whose top-level flag disagrees with its own
    # findings is self-contradictory, and the safe reading of a contradiction is the
    # pessimistic one.
    failed = [
        str(f.get("check_id"))
        for f in findings
        if isinstance(f, Mapping) and f.get("status") != "pass"
    ]
    if failed:
        _gate_refuse(
            f"the gate report says ok=true but {len(failed)} finding(s) do not pass: "
            + ", ".join(sorted(failed)[:8]),
            "gate_report_self_contradictory",
            failed_checks=sorted(failed),
        )
    probes = raw.get("probes")
    if not isinstance(probes, Mapping) or probes.get("ok") is not True:
        _gate_refuse(
            "the gate report's probe health is not ok; the required behavioral probes "
            "did not all answer cleanly",
            "gate_probe_health_not_ok",
        )

    binding = raw.get("binding")
    if not isinstance(binding, Mapping):
        _gate_refuse(
            "the gate report has no binding object, so it cannot be shown to be about "
            "this store and project",
            "gate_report_binding_absent",
        )
    assert isinstance(binding, Mapping)
    expected_fp = postgres_database_fingerprint(dsn)
    if expected_fp is None:
        _gate_refuse(
            "could not compute the credential-free store fingerprint for the target "
            "DSN, so the gate report cannot be bound to it",
            "target_store_fingerprint_unavailable",
        )
    assert expected_fp is not None
    reported = binding.get("reported_store_fingerprint")
    declared = binding.get("expected_store_fingerprint")
    if reported != expected_fp or declared != expected_fp:
        _gate_refuse(
            "the gate report is bound to a different store than the one about to be "
            f"written: it reports {reported!r} (expected {declared!r}) but the target "
            f"DSN fingerprints as {expected_fp!r}. A PASS about another store is a real "
            "report about the wrong thing.",
            "gate_report_store_mismatch",
            reported_store_fingerprint=reported,
            expected_store_fingerprint=declared,
            target_store_fingerprint=expected_fp,
        )
    if binding.get("project") != project:
        _gate_refuse(
            f"the gate report is bound to project {binding.get('project')!r}, not the "
            f"target project {project!r}",
            "gate_report_project_mismatch",
            report_project=binding.get("project"),
            target_project=project,
        )

    snapshot = binding.get("observation_snapshot")
    return GateEvidence(
        path=path,
        report_version=version,
        store_fingerprint=expected_fp,
        project=project,
        observation_snapshot=snapshot if isinstance(snapshot, str) else None,
        finding_count=len(findings),
    )


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


def _actor_kind_for(principal_id: str) -> str:
    """The v6 ``actor.kind`` implied by a canonical principal's kind (§2.6).

    ``service`` is spelled ``system`` on the row, so the mapping is not the identity.
    Derived rather than asked for: an operator-supplied actor kind that contradicts the
    principal id is a fact the envelope would sign.
    """
    from ._principals import classify_principal_id

    classification = classify_principal_id(principal_id)
    if not classification.canonical or classification.kind is None:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            f"{principal_id!r} is not a canonical kind:subject principal id "
            "(TRUST-DOMAIN.md §2.1)",
            "principal_id_not_canonical",
            principal_id=principal_id,
        )
    return {"agent": "agent", "human": "human", "service": "system"}[
        str(classification.kind)
    ]


def validate_scope_entity_kinds(kinds: Sequence[str]) -> tuple[str, ...]:
    """Normalise and check the acceptance's ``entity_kinds``, refusing early.

    ``_genesis._validate_bootstrap_acceptance`` enforces the same rules on the finished
    envelope; doing it here means an operator typo is a clear CLI refusal naming the
    closed registry rather than a GENESIS_INVALID from deep inside the writer.
    """
    from ._verification import V6_ENTITY_KINDS

    ordered: list[str] = []
    for raw in kinds:
        for piece in str(raw).split(","):
            kind = piece.strip()
            if not kind:
                continue
            if kind not in V6_ENTITY_KINDS:
                _refuse(
                    ErrorCode.INVALID_ARGUMENT,
                    f"{kind!r} is not a v6 entity kind; the registry is closed: "
                    + ", ".join(sorted(V6_ENTITY_KINDS)),
                    "entity_kind_not_in_registry",
                    entity_kind=kind,
                )
            if kind not in ordered:
                ordered.append(kind)
    if not ordered:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "the bootstrap acceptance needs at least one entity kind",
            "entity_kinds_empty",
        )
    if "project" not in ordered:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "the bootstrap acceptance must include the 'project' entity kind, or it "
            "does not authorise the very genesis event it travels in",
            "entity_kinds_missing_project",
            entity_kinds=ordered,
        )
    return tuple(ordered)


@dataclass(frozen=True)
class PreviousEpoch:
    """The measured state of whatever the target store held before genesis.

    Under EPOCH-RESET there is no seam and no legacy prefix, so for a legitimate
    genesis every number here is zero or null — but they are MEASURED from the target
    store, not asserted. An honest zero and an assumed zero look identical in the
    signed bytes and are not the same claim (EPOCH-RESET §6 rule 3).
    """

    event_count: int
    archived_event_count: int
    head_event_hash: str | None
    genesis_event_hash: str | None
    max_global_seq: int | None
    scheme_counts: Mapping[str, int]

    @property
    def empty(self) -> bool:
        return (
            self.event_count == 0
            and self.archived_event_count == 0
            and self.head_event_hash is None
        )

    def as_payload_member(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "genesis_event_hash": self.genesis_event_hash,
            "head_event_hash": self.head_event_hash,
            "head_hash_construction": "sha256(canonical_envelope||signature)",
            "max_global_seq": self.max_global_seq,
            "scheme_counts": dict(self.scheme_counts),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.as_payload_member(),
            "archived_event_count": self.archived_event_count,
        }


def measure_previous_epoch(conn: DictConn) -> PreviousEpoch:
    """Measure the target store's pre-genesis state on a read-only connection."""
    from ._genesis import _archived_count, _count_rows

    live = _count_rows(conn, "events")
    archived = _archived_count(conn)
    head_row = conn.execute(
        "SELECT head_hash FROM event_chain_head WHERE id = TRUE"
    ).fetchone()
    head = (
        None
        if head_row is None or head_row["head_hash"] is None
        else "sha256:" + bytes(head_row["head_hash"]).hex()
    )
    seq_row = conn.execute("SELECT MAX(global_seq) AS max_seq FROM events").fetchone()
    max_seq = None if seq_row is None or seq_row["max_seq"] is None else int(seq_row["max_seq"])
    scheme_rows = conn.execute(
        "SELECT scheme_id, COUNT(*) AS n FROM events GROUP BY scheme_id"
    ).fetchall()
    counts = {
        (row["scheme_id"] or "unset"): int(row["n"]) for row in scheme_rows
    }
    # Read rather than hardcode null. On the only store state that can legitimately
    # reach signed bytes this IS null (an empty store has no identity row), but a
    # hardcoded null would report a falsehood in the --dry-run plan for a store that
    # has already opened an epoch — and "measured null" and "assumed null" are not the
    # same claim even when they print identically.
    identity = conn.execute(
        "SELECT genesis_event_hash FROM project_identity WHERE id = TRUE"
    ).fetchone()
    genesis_hash = (
        None
        if identity is None or identity["genesis_event_hash"] is None
        else "sha256:" + bytes(identity["genesis_event_hash"]).hex()
    )
    return PreviousEpoch(
        event_count=live,
        archived_event_count=archived,
        head_event_hash=head,
        genesis_event_hash=genesis_hash,
        max_global_seq=max_seq,
        scheme_counts=counts,
    )


def build_project_initialized_envelope(
    *,
    project_instance_id: str,
    reference: TrustReference,
    producer: Mapping[str, Any],
    previous_epoch: PreviousEpoch,
    occurred_at: datetime,
    event_id: str | None = None,
    scope_entity_kinds: Sequence[str] = DEFAULT_SCOPE_ENTITY_KINDS,
    may_sign_bundles: bool = False,
) -> dict[str, Any]:
    """Build the ``project_initialized`` envelope from verified inputs.

    Every field that could be invented is instead taken from ``reference`` (verified
    against the live trust log) or ``previous_epoch`` (measured on the target store).
    The only free choices are the project instance id, the event id, the acceptance's
    project-local scopes — which have no trust-log counterpart, because §5.8 acceptance
    scopes ARE project-local — and the instant.

    ``may_accept_keys`` and ``may_sign_checkpoints`` are not parameters: the writer
    requires both to be exactly ``True`` (``_genesis.py:468``), because a bootstrap key
    that cannot accept another key leaves the project with no way to admit a second
    writer, which is the circularity RECONCILIATION Resolution 1 removed.
    """
    entity_kinds = validate_scope_entity_kinds(scope_entity_kinds)
    key = reference.key
    acceptance = {
        "principal_id": key.principal_id,
        "key_id": key.key_id,
        "scheme_id": "ed25519",
        "public_key": key.public_key_b64,
        "fingerprint": key.fingerprint,
        "trust_event_hash": key.trust_event_hash,
        "trust_log_checkpoint": reference.checkpoint.as_payload_member(),
        "scopes": {
            "entity_kinds": list(entity_kinds),
            # None means "no transition restriction". A list here would have to include
            # project_initialized or the acceptance would refuse the event carrying it.
            "transitions": None,
            "may_accept_keys": True,
            "may_sign_checkpoints": True,
            "may_sign_bundles": bool(may_sign_bundles),
        },
    }
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": project_instance_id,
        "trust_domain_id": reference.trust_domain_id,
        "event_id": event_id or str(_uuid.uuid4()),
        "entity": {"kind": "project", "id": project_instance_id},
        "entity_seq": 1,
        "actor": {
            "principal_id": key.principal_id,
            "kind": _actor_kind_for(key.principal_id),
            "metadata": {},
        },
        "signing": {
            "scheme_id": "ed25519",
            "key_id": key.key_id,
            # The genesis key's binding is EXTERNAL — the trust log — so there is no
            # preceding project event to point at. The writer refuses a non-null value.
            "key_binding_event_hash": None,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": _iso_micro_z(occurred_at),
        "transition": "project_initialized",
        "payload": {
            "bootstrap_key_acceptance": acceptance,
            "genesis_document_digest": reference.genesis_document_digest,
            "previous_epoch": previous_epoch.as_payload_member(),
            "trust_domain_core_digest": reference.trust_domain_core_digest,
            "trust_log_checkpoint": reference.checkpoint.as_payload_member(),
        },
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": dict(producer),
    }


__all__ = [
    "DEFAULT_SCOPE_ENTITY_KINDS",
    "SUPPORTED_GATE_REPORT_VERSIONS",
    "TRUST_LOG_OBSERVATION_TYPE",
    "EnrolledKey",
    "GateEvidence",
    "PreviousEpoch",
    "TrustLogCheckpoint",
    "TrustReference",
    "build_project_initialized_envelope",
    "derive_trust_log_checkpoint",
    "load_gate_evidence",
    "load_published_checkpoint",
    "measure_previous_epoch",
    "resolve_enrolled_key",
    "resolve_trust_reference",
    "validate_scope_entity_kinds",
]
