"""Audit bundle export and offline verification — bundle v3 only.

``BUNDLE-V3.md`` is the contract. This module is the store-facing half of it: it reads a
project's events, hands them to :mod:`regista._bundle_v3` to become a signed statement, and
reads an artifact back to recompute what that statement commits to. The format itself — the
statement schema, the membership tree, the section digests, the signature — lives in
``_bundle_v3`` and is deliberately not restated here.

**Bundle v2 is gone from this module, not deprecated in it.** ``BUNDLE-V3.md`` §2:
"``format_version`` 1 is deleted, and so is 2. Bundle v3 is the only accepted format; a
bundle declaring 1 or 2 is rejected with a named error, not downgraded." What that deleted
here, and why each deletion is safe:

``manifest`` / ``bundle_hash`` / ``_canonical_bundle_bytes``
    The v2 bundle hash was an **unkeyed** SHA-256 that anyone could recompute after editing
    anything, so it detected accidental corruption and nothing else (§1). Every claim it
    guarded — event count, key count, the export window — is now inside the statement
    signature. There is no replacement field: a second, unkeyed digest alongside a real
    signature is a field an operator could mistake for evidence.

``signature_check`` and its three magic strings
    ``"enforced"`` / ``"skipped_v1_bundle"`` / ``"enforced_none_verified"`` (§6). The first
    is unconditional now, the second described a format that no longer exists, and the
    third is exactly A4 ``none_verifiable`` in the §5.1 axis model — a correct signal
    invented under duress because the boolean could not carry it.

``_row_to_event_dict``
    §3.6: a v3 event record is ``{canonical_envelope, signature}`` and **nothing else**.
    The twenty row columns v2 exported alongside the envelope were a second copy of signed
    data for a consumer to read instead of the signed one. The projection now runs the
    other way — :func:`_event_from_member` recomputes the row view *from* the envelope —
    which is the same discipline ``verify_event_strict`` applies to a live row.

``_verify_global_chain``
    Replaced by ``_bundle_v3.derive_chain_order``, which is strictly stronger and for a
    reason found the hard way. The old walk treated an event whose predecessor was not in
    the set as a legitimate *bridge point*, so when every link failed to resolve, every
    event became an entry point, every entry point was immediately its own tail, all events
    were visited, and it returned ``ok=True`` **vacuously** — the chain was not verified and
    the report said it was. ``derive_chain_order`` admits exactly one entry point, the one
    the signed scope declares, and refuses anything it cannot totally order.

What is **retained**, per §8 "Retained from ``_bundle.py``": ``_reject_archive_output_name``
(WI-210), :data:`MAX_BUNDLE_BYTES` (WI-240), the empty-bundle refusals — now doubled,
because an empty bundle also has no membership root to sign — the write-then-rename
discipline, and the delegation to ``verify_event_strict``, which §8 calls "the keystone".

**Phase boundaries.** This is WI-289 Phase B. Two things a reader might look for here and
should not:

* ``TrustPolicy`` / ``AcceptBundledKeys`` and the §4.1 required-trust-argument signature,
  and the §5 axis model and verdict lattice, are **Phase C**. :func:`verify_audit_bundle_offline`
  therefore still takes an optional ``statement_public_key`` rather than a required trust
  object, and still emits a ``verified`` boolean §5.2 deletes. Both are documented at their
  definitions as the seam C replaces.
* The §9 export ceremony — write to ``.partial``, self-verify the ``.partial``, ``os.replace``
  only on success; the preflight comparison; the dependency-closure walk; the CLI flags and
  exit codes — is **Phase D**. The write order here is still v2's (write, rename, verify),
  which §9 rule 5 and D11 name as wrong; it is left wrong on purpose so the fix lands as
  one reviewable change with the tests that pin it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as _hmac
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from ._bundle_v3 import (
    BUNDLE_V3_FORMAT_VERSION,
    SUPPORTED_FORMAT_VERSIONS,
    BundleV3CoreReport,
    BundleV3Document,
    BundleV3Signer,
    BundleV3TrustRoot,
    OrderedMember,
    build_bundle_v3_document,
    canonical_bundle_bytes,
    parse_bundle_v3_document,
    parse_event_member,
    verify_bundle_v3_core,
)
from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._signing_scheme import get_scheme
from ._types import Event
from ._v6_referents import BundleReferents, MaterialCompleteness, referent_from_bytes
from ._verification import (
    DEFAULT_POLICY,
    Applicability,
    Backend,
    BundleKeyResolver,
    EventRow,
    VerificationPolicy,
    verify_event_strict,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle only at type-check time
    from ._keys import KeySet

log = structlog.get_logger()

#: Re-exported so §2's two citations resolve to one object. Widening either is a spec
#: change; they are asserted equal in ``tests/test_bundle_v3.py``.
_BUNDLE_FORMAT_VERSION = BUNDLE_V3_FORMAT_VERSION
_SUPPORTED_FORMAT_VERSIONS = SUPPORTED_FORMAT_VERSIONS

# One cap, shared by export and verify (WI-240). An export larger than what
# the offline verifier accepts is unverifiable by the tool that exists to
# verify it, so export refuses to write past this size rather than exit 0.
MAX_BUNDLE_BYTES = 512 * 1024 * 1024

# Output names that imply a compressed/archive container. An audit bundle is a
# canonical JSON document; writing plain JSON under one of these names hands an
# auditor a file that `tar -xzf` / `unzip` rejects as corrupt (WI-210).
_ARCHIVE_OUTPUT_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tgz",
    ".tbz2",
    ".txz",
    ".tar",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".7z",
    ".rar",
)


def _reject_archive_output_name(output_path: str | Path) -> None:
    name = Path(output_path).name.lower()
    for suffix in _ARCHIVE_OUTPUT_SUFFIXES:
        if name.endswith(suffix):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Output name {Path(output_path).name!r} implies a compressed "
                f"archive ({suffix}), but an audit bundle is a canonical JSON "
                f"document; use a .json name (e.g. 'bundle.json').",
            )


@dataclass(frozen=True)
class BundleVerificationReport:
    """The offline verification report, Phase B shape.

    Every field below is either a fact about a check that ran or a count. There is no
    ``bundle_hash_ok`` (the unkeyed hash is deleted) and no ``signature_check`` (its three
    magic strings are §5.1's axes A2/A4/A5).

    ``verified`` **survives Phase B and is deleted by Phase C.** ``BUNDLE-V3.md`` §5.2 is
    explicit — "There is no ``verified: bool``. Not deprecated — absent" — and replaces it
    with the ordered ``applicability`` summary over the §5.1 axes. That replacement is the
    verdict lattice, which is Phase C's work, so the boolean is kept here as the one thing
    the current CLI can read. Its Phase B definition is deliberately narrow and stricter
    than v2's: it requires the statement signature to have been **checked and valid**, so a
    caller who supplies no key gets ``False`` rather than a pass. What it still does not
    say, and what makes it inadequate, is *whose* key — that is §4 and the reason the field
    goes.
    """

    verified: bool
    event_count: int
    format_version: int
    #: The chain-derived ordering (§3.3). Named ``global_chain_*`` because it answers the
    #: same question v2's global-chain walk did — do the project-chain links resolve into
    #: one sequence — by a construction that cannot pass vacuously.
    global_chain_ok: bool
    global_chain_error: str | None = None
    work_item_chain_ok: bool = True
    work_item_chain_error: str | None = None
    statement_signature_checked: bool = False
    statement_signature_valid: bool = False
    membership_root_ok: bool = True
    section_digests_ok: bool = True
    reference_sections_ok: bool = True
    scope_consistent: bool = True
    signer_authority_checked: bool = False
    signer_may_sign_bundles: bool = False
    signatures_verified: int = 0
    signatures_unverifiable: int = 0
    errors: list[str] = field(default_factory=list)
    #: Why each unverifiable signature was unverifiable. A count with no reason is
    #: how "nothing was checked" gets read as "everything checks out"; the two v6
    #: cases that land here (an unpinned bootstrap event, a referent outside a
    #: windowed scope) are both things an auditor must be able to read off the
    #: report rather than reproduce.
    unverifiable_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "event_count": self.event_count,
            "format_version": self.format_version,
            "global_chain_ok": self.global_chain_ok,
            "global_chain_error": self.global_chain_error,
            "work_item_chain_ok": self.work_item_chain_ok,
            "work_item_chain_error": self.work_item_chain_error,
            "statement_signature_checked": self.statement_signature_checked,
            "statement_signature_valid": self.statement_signature_valid,
            "membership_root_ok": self.membership_root_ok,
            "section_digests_ok": self.section_digests_ok,
            "reference_sections_ok": self.reference_sections_ok,
            "scope_consistent": self.scope_consistent,
            "signer_authority_checked": self.signer_authority_checked,
            "signer_may_sign_bundles": self.signer_may_sign_bundles,
            "signatures_verified": self.signatures_verified,
            "signatures_unverifiable": self.signatures_unverifiable,
            "errors": self.errors,
            "unverifiable_details": self.unverifiable_details,
        }


# ---------------------------------------------------------------------------
# §3.6 — the row projection, recomputed from the envelope
# ---------------------------------------------------------------------------


def _event_from_member(member: OrderedMember) -> Event:
    """Project a v3 event record into the :class:`~regista._types.Event` view.

    This is ``_row_to_event_dict`` reversed, and the reversal is the point of §3.6. v2
    exported twenty row columns beside the envelope and the verifier reconciled them; v3
    exports the envelope and the verifier *derives* the columns, so there is nothing left
    to disagree. Reconciliation over a derived row is vacuous by construction — what
    remains, and what still matters, is the signature check, the key binding and the
    referent resolution, all of which ``verify_event_strict`` performs.

    The mapping is ``_verification._reconcile_v6``'s check table read in the other
    direction, so the two cannot drift without a test noticing.
    """

    from ._signing import compute_v6_payload_canonical_hash

    envelope = member.envelope
    entity = envelope["entity"]
    actor = envelope["actor"]
    signing = envelope["signing"]
    workflow = envelope["workflow"]
    chain = envelope["chain"]
    entity_id = uuid.UUID(str(entity["id"]))

    def _digest_or_none(value: object) -> bytes | None:
        if not isinstance(value, str):
            return None
        return bytes.fromhex(value.removeprefix("sha256:"))

    return Event(
        event_id=uuid.UUID(str(envelope["event_id"])),
        # v6 requires work_item_id == entity_id (`_reconcile_v6`'s last check), so the
        # projection sets both from the one signed identifier rather than inventing a
        # distinction the envelope does not carry.
        work_item_id=entity_id,
        event_seq=int(envelope["entity_seq"]),
        actor_id=str(actor["principal_id"]),
        actor_kind=str(actor["kind"]),
        actor_metadata=actor["metadata"],
        key_id=str(signing["key_id"]),
        workflow_name=None if workflow is None else str(workflow["name"]),
        workflow_version=None if workflow is None else int(workflow["version"]),
        timestamp=datetime.fromisoformat(str(envelope["occurred_at"]).replace("Z", "+00:00")),
        transition=str(envelope["transition"]),
        payload=envelope["payload"],
        payload_canonical_hash=compute_v6_payload_canonical_hash(member.canonical_envelope),
        signature=member.signature,
        canonical_envelope=member.canonical_envelope,
        scheme_id=str(signing["scheme_id"]),
        prev_event_hash=_digest_or_none(chain["previous_entity_event_hash"]),
        # §3.6: `global_seq` is not a member of a v3 event record at all. It is unsigned by
        # construction, so a bundle that carried it would carry a field no signature
        # covers — and §3.3 already refuses to order on it.
        global_seq=None,
        prev_global_event_hash=_digest_or_none(chain["previous_project_event_hash"]),
        entity_kind=str(entity["kind"]),
        entity_id=entity_id,
        hash_alg=str(chain["hash_algorithm"]),
    )


def _bundled_key_registry(section: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Adapt ``sections.bundled_key_evidence`` to the registry shape the verifier reads.

    The section is base64 (§3.6's encoding decision applies to the whole document);
    ``_verify_event_signatures`` reads hex, because that is the shape a ``principal_keys``
    row projection has and the function is shared with the live-store path. One conversion
    here beats two spellings of "public key material" inside the verifier.

    The entries carry **no validity window and no revocation state**, because the section
    declares none — see :func:`_key_evidence_from_v6_payloads` for the same limitation and
    the same consequence.
    """

    registry: list[dict[str, Any]] = []
    for record in section:
        try:
            material = base64.b64decode(str(record["public_key"]), validate=True)
        except (ValueError, binascii.Error, KeyError):
            continue
        registry.append(
            {
                "key_id": record["key_id"],
                "principal_id": record["principal_id"],
                "scheme": record["scheme_id"],
                "public_key": material.hex(),
                "status": "active",
            }
        )
    return registry


def _bundle_referents_v3(
    scope_kind: str, events: Sequence[Event]
) -> BundleReferents:
    """Present a v3 bundle's events as verifier material, with the scope it declares.

    ``BundleReferents.from_bundle`` derives its completeness claim from the v2 manifest's
    ``since_seq``/``until_seq``, which a v3 bundle does not have — it has a signed
    ``scope.kind``, which is the same statement said properly. So the claim is constructed
    from the signed field directly rather than by synthesising the manifest keys the
    derivation used to read.

    ``action_credentials`` is left ``UNDECLARED``: §9 rule 6's
    ``sections.action_delegation_credentials`` is deferred post-cutover by owner ruling O1,
    and this format has no section for a credential to be absent *from*. Passing an empty
    section instead would be a false completeness claim — it would say "this credential is
    absent from a complete section" about a section that does not exist.
    """

    indexed = {}
    counted = 0
    for event in events:
        counted += 1
        referent = referent_from_bytes(event.canonical_envelope, event.signature)
        if referent is not None:
            indexed[referent.event_hash] = referent
    return BundleReferents(
        events=indexed,
        material_completeness=(
            MaterialCompleteness.COMPLETE_STORE
            if scope_kind == "complete-store"
            else MaterialCompleteness.CONTIGUOUS_RANGE
        ),
        event_count=counted,
        action_credentials={},
        credential_material_completeness=MaterialCompleteness.UNDECLARED,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

_EVENT_COLUMNS = "global_seq, canonical_envelope, signature"


def _read_export_rows(
    conn: DictConn, *, since_seq: int | None, until_seq: int | None
) -> list[tuple[bytes, bytes]]:
    clauses: list[str] = []
    params: list[int] = []
    if since_seq is not None:
        clauses.append("global_seq > %s")
        params.append(since_seq)
    if until_seq is not None:
        clauses.append("global_seq <= %s")
        params.append(until_seq)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    # ORDER BY global_seq is a *selection* convenience, not the bundle's order: the
    # membership tree's order is derived by walking `previous_project_event_hash`
    # (§3.3), and `build_bundle_v3_document` re-derives it whatever order arrives.
    rows = conn.execute(
        f"SELECT {_EVENT_COLUMNS} FROM events{where} ORDER BY global_seq", params
    ).fetchall()

    records: list[tuple[bytes, bytes]] = []
    for row in rows:
        envelope = row["canonical_envelope"]
        signature = row["signature"]
        if envelope is None or signature is None:
            # §3.6's consequence for the S1 corpus, stated as a refusal rather than a
            # record with a null envelope: an event with no signed bytes cannot be
            # represented in a v3 bundle at all.
            raise RegistaError(
                ErrorCode.BUNDLE_UNVERIFIABLE,
                f"event at global_seq={row['global_seq']} has no canonical_envelope or "
                "signature, so it cannot be represented in a bundle v3 event record "
                "(BUNDLE-V3.md §3.6). Nothing was written.",
            )
        records.append((bytes(envelope), bytes(signature)))
    return records


def _resolve_bundle_signer(
    conn: DictConn,
    keys: KeySet,
    *,
    principal_id: str,
    key_id: str | None,
) -> BundleV3Signer:
    """Resolve the statement signer and its ``may_sign_bundles`` scope (owner ruling O3).

    The scope comes from ``resolve_key_binding_anchor`` — the *signed* project-local
    acceptance — and never from the key file, a ``principal_keys`` row or a configuration
    flag. That is the whole content of O3: "the authority to sign bundles is an explicit,
    signed property of a key — not an implication of holding the writer key". The anchor's
    own event hash becomes ``statement.signer.authority_event_hash``, so a verifier holding
    the bundle can re-derive the same grant from the same signed event.
    """

    from ._v6_writer import resolve_key_binding_anchor

    entry = keys.resolve_signing_key(principal_id, key_id)
    if entry.public_key is None:
        raise RegistaError(
            ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED,
            f"key {entry.key_id!r} carries no public key, so it cannot be named as a "
            "bundle statement signer (BUNDLE-V3.md §3.2 requires signer.fingerprint).",
        )
    anchor = resolve_key_binding_anchor(conn, principal_id=principal_id, key_id=entry.key_id)
    return BundleV3Signer(
        principal_id=principal_id,
        key_id=entry.key_id,
        fingerprint="ed25519:sha256:" + hashlib.sha256(entry.public_key).hexdigest(),
        # `scoped` is the honest value for a project-local acceptance: the authority came
        # from an acceptance event inside this project, not from the trust root or a
        # registrar delegation.
        authority_kind="scoped",
        authority_event_hash=anchor.event_hash,
        may_sign_bundles=anchor.scopes.may_sign_bundles,
        private_key=entry.secret,
    )


def _trust_root_from_store(
    conn: DictConn,
    *,
    genesis_event_id: uuid.UUID,
    trust_domain_id: str,
    root_governance: Mapping[str, Any],
) -> BundleV3TrustRoot:
    """Assemble the signed ``trust_root`` block (§3.2, ``TRUST-DOMAIN.md`` §3.6).

    Two of the four members are restatements of what the project's own genesis event
    already signed — ``append_v6_genesis`` puts ``trust_domain_core_digest`` and
    ``genesis_document_digest`` in the ``project_initialized`` payload — so they are read
    from that event's **signed envelope**, never from a row column or a projection.

    The genesis event is read from the **store**, not from the export window. That
    distinction matters for a ``contiguous-range`` export: the statement is the exporter's
    signed restatement of the trust root it observed, and the exporter observes the whole
    store, so a window that happens to exclude genesis does not stop it stating what its
    own trust root is. When genesis *is* in scope a verifier cross-checks the restatement
    against it (:func:`_check_trust_root_against_genesis`); when it is not, the auditor's
    pinned policy is what checks it, which is §4 and Phase C's.

    ``root_governance`` is **not** derived and cannot be. §3.2: it "MUST be the current
    governance state obtained by replaying the signed trust-domain governance log through
    the authenticated trust-log checkpoint. It is not copied from genesis, configuration or
    a mutable projection." A project store holds no governance state at all, so a caller
    that cannot supply the replayed state has nothing to attest, and export refuses rather
    than inventing the one field WI-272 requires to be true.
    """

    from ._verification import V6EnvelopeError, parse_v6_envelope_strict

    row = conn.execute(
        "SELECT canonical_envelope FROM events WHERE event_id = %s", [genesis_event_id]
    ).fetchone()
    core_digest: object = None
    document_digest: object = None
    if row is not None and row["canonical_envelope"] is not None:
        try:
            envelope = parse_v6_envelope_strict(bytes(row["canonical_envelope"]))
        except (V6EnvelopeError, TypeError, ValueError) as exc:
            raise RegistaError(
                ErrorCode.BUNDLE_STATEMENT_INVALID,
                f"the project's genesis event does not parse as a v6 envelope, so its "
                f"trust-root restatement cannot be read: {exc}. Nothing was written.",
            ) from exc
        payload = envelope["payload"]
        if isinstance(payload, Mapping):
            core_digest = payload.get("trust_domain_core_digest")
            document_digest = payload.get("genesis_document_digest")
    if not isinstance(core_digest, str) or not isinstance(document_digest, str):
        raise RegistaError(
            ErrorCode.BUNDLE_STATEMENT_INVALID,
            "cannot assemble statement.trust_root: this project's genesis event does not "
            "carry trust_domain_core_digest and genesis_document_digest in its signed "
            "payload, so there is nothing to restate. An estate whose genesis predates "
            "those members cannot produce a conforming v3 statement; re-open the epoch "
            "through `write_genesis`. Nothing was written.",
        )
    for member in ("mode", "threshold", "signer_count"):
        if member not in root_governance:
            raise RegistaError(
                ErrorCode.BUNDLE_STATEMENT_INVALID,
                f"root_governance is missing {member!r}: the three-member replayed "
                "governance state is required (TRUST-DOMAIN.md §3.6).",
            )
    return BundleV3TrustRoot(
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=core_digest,
        genesis_document_digest=document_digest,
        governance_mode=str(root_governance["mode"]),
        governance_threshold=int(root_governance["threshold"]),
        governance_signer_count=int(root_governance["signer_count"]),
    )


def export_audit_bundle(
    mgr: ConnectionManager,
    project_name: str,
    output_path: str | Path,
    *,
    keys: KeySet | None = None,
    root_governance: Mapping[str, Any] | None = None,
    signing_principal_id: str | None = None,
    signing_key_id: str | None = None,
    external_evidence: Sequence[Mapping[str, Any]] = (),
    since_seq: int | None = None,
    until_seq: int | None = None,
) -> dict[str, Any]:
    """Export a signed bundle v3 artifact.

    Two inputs have no default and no fallback, and both refusals are the point:

    ``keys``
        The signing material. A v3 bundle *is* a signed statement; there is no unsigned
        v3 artifact, so an export with nothing to sign with produces nothing.

    ``root_governance``
        The replayed current governance state (§3.2). See
        :func:`_trust_root_from_genesis` for why it cannot be derived from a project
        store. Resolving it is trust-root resolution — ``BUNDLE-V3.md`` §4, WI-289 Phase C
        — so until that lands a caller must pass the state it replayed, and the CLI cannot
        yet do so. That is a scheduling consequence of the ratified phasing and it fails
        closed: the command errors by name rather than exporting a bundle whose governance
        restatement was made up.

    ``since_seq``/``until_seq`` select rows; they do **not** order them. A windowed export
    is a ``contiguous-range`` scope (§3.5) and its ``preceding_event_hash`` is derived from
    the chain, not from the window bounds.
    """

    _reject_archive_output_name(output_path)
    if until_seq is not None and since_seq is not None and until_seq <= since_seq:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Empty export range: until_seq ({until_seq}) must be greater "
            f"than since_seq ({since_seq}).",
        )
    if keys is None:
        raise RegistaError(
            ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED,
            "bundle v3 export requires signing material: the statement signature IS the "
            "artifact's integrity (BUNDLE-V3.md §3.4), so there is no unsigned v3 bundle "
            "to write. Nothing was written.",
        )
    if root_governance is None:
        raise RegistaError(
            ErrorCode.BUNDLE_STATEMENT_INVALID,
            "bundle v3 export requires the replayed root governance state "
            "({mode, threshold, signer_count}) for statement.trust_root. It cannot be "
            "derived from a project store: BUNDLE-V3.md §3.2 requires the state obtained "
            "by replaying the signed trust-domain governance log through the authenticated "
            "trust-log checkpoint, and forbids copying it from genesis, configuration or a "
            "mutable projection. Trust-root resolution is BUNDLE-V3.md §4 (WI-289 Phase C); "
            "until it lands, supply the replayed state explicitly. Nothing was written.",
        )

    with mgr.transaction() as conn:
        records = _read_export_rows(conn, since_seq=since_seq, until_seq=until_seq)
        if not records:
            detail = (
                "the store has no events"
                if since_seq is None and until_seq is None
                else f"window since_seq={since_seq} until_seq={until_seq} "
                "selected no events"
            )
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Refusing to export an empty bundle: {detail}. Nothing was written.",
            )

        from ._v6_writer import read_project_identity

        identity = read_project_identity(conn)
        if identity is None:
            raise RegistaError(
                ErrorCode.BUNDLE_STATEMENT_INVALID,
                "this store has no v6 project identity, so it cannot state a "
                "project_instance_id or trust_domain_id in a signed statement "
                "(BUNDLE-V3.md §3.2). Nothing was written.",
            )
        signer = _resolve_bundle_signer(
            conn,
            keys,
            principal_id=signing_principal_id or identity.principal_id,
            key_id=signing_key_id,
        )
        trust_root = _trust_root_from_store(
            conn,
            genesis_event_id=identity.genesis_event_id,
            trust_domain_id=str(identity.trust_domain_id),
            root_governance=root_governance,
        )

    members = [parse_event_member(env, sig) for env, sig in records]
    # A windowed export starts mid-chain, and its anchor is the event immediately before
    # it — read off the chain, never off the window bounds. A window that happens to start
    # at genesis is a complete prefix and declares `preceding_event_hash: null`.
    #
    # Owner ruling O4 is enforced twice on purpose, and the two refusals say different
    # things. Here: the selected set has more than one way in, so it is not a *range* at
    # all and the scope cannot be stated. In `derive_chain_order`: the set has one entry
    # point but does not link all the way through. Both refuse; neither degrades.
    entry_prevs = {m.previous_project_event_hash for m in members}
    presented = {m.event_hash_text for m in members}
    external_prevs = sorted(p for p in entry_prevs if p is not None and p not in presented)
    entry_count = len(external_prevs) + (1 if None in entry_prevs else 0)
    if entry_count != 1:
        raise RegistaError(
            ErrorCode.BUNDLE_CHAIN_UNORDERABLE,
            f"the selected events have {entry_count} distinct entry point(s) into the "
            "chain, so they are not one contiguous range and no scope describes them. "
            "Owner ruling O4: export refuses rather than producing a partial or "
            "diagnostic artifact. Nothing was written.",
            detail={
                "external_entry_points": external_prevs[:10],
                "contains_chain_genesis": None in entry_prevs,
            },
        )
    preceding_event_hash = None if None in entry_prevs else external_prevs[0]
    # A *windowed* export is `contiguous-range` even when the window happens to select the
    # whole chain, and this is the strict direction rather than a convenience. §3.5's
    # `complete-store` claim is "the signer attested this is the whole chain as it stood at
    # `created_at`"; an export that was given bounds cannot attest that, because the bounds
    # are what it looked at. A prefix window anchored at genesis is a legitimate
    # `contiguous-range` with `preceding_event_hash: null` — §3.5 says so in as many words
    # ("or the range starts at genesis") — so nothing is lost by refusing to promote it.
    scope_kind = (
        "complete-store"
        if preceding_event_hash is None and since_seq is None and until_seq is None
        else "contiguous-range"
    )

    from ._integrity import REGISTA_VERSION

    document = build_bundle_v3_document(
        event_records=records,
        project_instance_id=str(identity.project_instance_id),
        trust_root=trust_root,
        signer=signer,
        scope_kind=scope_kind,
        preceding_event_hash=preceding_event_hash,
        bundled_key_evidence=_key_evidence_section(members),
        external_evidence=external_evidence,
        regista_version=REGISTA_VERSION,
    )

    serialized = canonical_bundle_bytes(document)
    if len(serialized) > MAX_BUNDLE_BYTES:
        raise RegistaError(
            ErrorCode.BUNDLE_UNVERIFIABLE,
            f"Refusing to write an unverifiable bundle: {len(serialized)} bytes "
            f"exceeds the offline verifier's {MAX_BUNDLE_BYTES}-byte cap "
            f"({len(records)} events). Chunk the export with "
            "--since-seq/--until-seq; nothing was written.",
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so a killed process cannot leave a plausible-looking
    # partial bundle at the destination (review F8). If write_bytes itself
    # dies mid-write, unlink the .partial temp file — only the partial, never
    # the real destination (WI-249).
    #
    # §9 rule 5 / D11 require self-verification of the `.partial` BEFORE the replace, so a
    # failed self-verification never leaves the bad artifact at the destination. That
    # reorder is WI-289 Phase D's, deliberately not smuggled in here.
    tmp_output = output.with_name(output.name + ".partial")
    try:
        tmp_output.write_bytes(serialized)
    except BaseException:
        if tmp_output.exists():
            tmp_output.unlink()
        raise
    os.replace(tmp_output, output)

    # An export is done when the artifact it wrote is verifiable, not when the write
    # returns (WI-240). The public key is the one this export just signed with, so this
    # self-verification proves the artifact verifies against ITS OWN signer — not that the
    # signer is trusted, which is §4 and an auditor's pin.
    report = verify_audit_bundle_offline(
        output, statement_public_key=keys.get_key(signer.key_id).public_key
    )
    if not report.statement_signature_valid:
        raise RegistaError(
            ErrorCode.BUNDLE_WRITE_CORRUPT,
            f"Exported artifact does not match what was serialized "
            f"(the statement signature does not verify against the key that signed it); "
            f"artifact left at {output} for inspection: {report.errors[:3]}",
        )
    if not report.verified:
        log.warning(
            "bundle.exported_with_verification_errors",
            output_path=str(output),
            errors=report.errors[:5],
        )

    statement = document["statement"]
    log.info(
        "bundle.exported",
        project=project_name,
        event_count=len(records),
        bundle_bytes=len(serialized),
        self_verified=report.verified,
        output_path=str(output),
    )

    return {
        "output_path": str(output),
        "event_count": len(records),
        "public_key_count": len(document["sections"]["bundled_key_evidence"]),
        "bundle_id": statement["bundle_id"],
        "format_version": statement["version"],
        "scope_kind": scope_kind,
        "event_membership_root": statement["event_membership_root"],
        "statement_signer_key_id": signer.key_id,
        "bundle_bytes": len(serialized),
        "since_seq": since_seq,
        "until_seq": until_seq,
        "self_verification": {
            "verified": report.verified,
            "statement_signature_valid": report.statement_signature_valid,
            "signatures_verified": report.signatures_verified,
            "signatures_unverifiable": report.signatures_unverifiable,
            "errors": report.errors[:5],
            "unverifiable_details": report.unverifiable_details[:5],
        },
    }


def _key_evidence_section(members: Sequence[OrderedMember]) -> list[dict[str, Any]]:
    """Build ``sections.bundled_key_evidence`` from the acceptance payloads in scope.

    §4.3's naming rule made load-bearing: the section is ``bundled_key_evidence``, not
    ``public_keys``, and what it carries is exactly the key material the bundle's own
    **signed** acceptance objects already repeat. ``TRUST-DOMAIN.md`` §5.8 repeats
    ``public_key`` inside every acceptance on purpose — "it makes a project bundle
    self-sufficient for key material without making it self-sufficient for *trust*" — so
    reading it from there is not a fallback; it is the signed artifact.

    Notably this does **not** read ``principal_keys``. A projection row that exists
    *because* a verifier needs it is §5.9 rule 1's forbidden coupling, and it is why v2's
    ``public_keys`` section could quietly become a trust root.
    """

    evidence: dict[str, dict[str, Any]] = {}
    for member in members:
        payload = member.envelope.get("payload")
        if not isinstance(payload, Mapping):
            continue
        candidates: list[Mapping[str, Any]] = []
        if payload.get("type") == "regista.key-acceptance":
            candidates.append(payload)
        embedded = payload.get("bootstrap_key_acceptance")
        if isinstance(embedded, Mapping):
            candidates.append(embedded)
        for acceptance in candidates:
            key_id = acceptance.get("key_id")
            principal_id = acceptance.get("principal_id")
            public_key = acceptance.get("public_key")
            if not (
                isinstance(key_id, str)
                and isinstance(principal_id, str)
                and isinstance(public_key, str)
            ):
                continue
            try:
                material = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error):
                continue
            if len(material) != 32:
                continue
            evidence.setdefault(
                key_id,
                {
                    "key_id": key_id,
                    "principal_id": principal_id,
                    # ed25519 by construction: a v6 envelope's `signing.scheme_id` is
                    # validated to it, and the acceptance's own `scheme_id` is
                    # cross-checked at write time.
                    "scheme_id": "ed25519",
                    "public_key": public_key,
                    "fingerprint": "ed25519:sha256:" + hashlib.sha256(material).hexdigest(),
                },
            )
    return [evidence[key_id] for key_id in sorted(evidence)]


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _check_trust_root_against_genesis(
    document: BundleV3Document, members: Sequence[OrderedMember]
) -> list[str]:
    """Cross-check the signed ``trust_root`` restatement against the genesis event.

    Two of ``trust_root``'s four members — ``trust_domain_core_digest`` and
    ``genesis_document_digest`` — are also inside the ``project_initialized`` payload the
    genesis event signed. When that event is in scope, the two must agree: a statement that
    restates its own genesis event incorrectly is contradicted by the bundle it describes.

    ``root_governance`` is deliberately **not** checked here. It is not derivable from
    genesis (that is precisely §3.2's rule) and checking it requires the replayed
    governance log — §4, Phase C. A verifier that cannot replay reports
    ``unverified_restatement`` (§4.5), which is an axis value, not a finding.
    """

    trust_root = document.statement["trust_root"]
    assert isinstance(trust_root, Mapping)
    genesis = next((m for m in members if m.previous_project_event_hash is None), None)
    if genesis is None:
        return []
    payload = genesis.envelope.get("payload")
    if not isinstance(payload, Mapping):
        return []
    findings: list[str] = []
    for statement_member, payload_member in (
        ("trust_domain_core_digest", "trust_domain_core_digest"),
        ("genesis_document_digest", "genesis_document_digest"),
    ):
        signed = payload.get(payload_member)
        if not isinstance(signed, str):
            continue
        if trust_root[statement_member] != signed:
            findings.append(
                f"trust_root_contradicts_genesis: statement.trust_root."
                f"{statement_member} is {trust_root[statement_member]!r} but the bundle's "
                f"own genesis event signed {signed!r}"
            )
    return findings


def _verify_entity_chains(members: Sequence[OrderedMember]) -> tuple[bool, str]:
    """Verify each entity's own hash chain, reading the signed envelope.

    The project-chain traversal (§3.3) proves the events form one sequence; it says nothing
    about the per-entity links, which are a separate signed field
    (``chain.previous_entity_event_hash``) and a separate invariant. The distinction is not
    academic: mutation M20 reverted the event-hash formula and survived a fixture whose
    every entity had exactly one event, because a per-entity chain with nothing to check
    passes.
    """

    from collections import defaultdict

    by_entity: dict[tuple[str, str], list[OrderedMember]] = defaultdict(list)
    for member in members:
        entity = member.envelope["entity"]
        by_entity[(str(entity["kind"]), str(entity["id"]))].append(member)

    for (kind, entity_id), entity_events in by_entity.items():
        entity_events.sort(key=lambda m: int(m.envelope["entity_seq"]))
        present = {m.event_hash_text for m in entity_events}
        previous: str | None = None
        for i, member in enumerate(entity_events):
            declared = member.envelope["chain"]["previous_entity_event_hash"]
            if i == 0:
                if isinstance(declared, str) and declared in present:
                    return False, (
                        f"first event for {kind}/{entity_id} references an event within "
                        "the slice — the slice is incomplete"
                    )
            else:
                if declared is None:
                    return False, (
                        f"event {member.event_hash_text} for {kind}/{entity_id} at "
                        f"entity_seq={member.envelope['entity_seq']} has a null "
                        "previous_entity_event_hash but is not the entity's first event"
                    )
                if previous is not None and declared != previous:
                    return False, (
                        f"entity chain mismatch for {kind}/{entity_id} at entity_seq="
                        f"{member.envelope['entity_seq']}: declares {declared}, the "
                        f"preceding event hashes to {previous}"
                    )
            previous = member.event_hash_text
    return True, ""


def verify_audit_bundle_offline(
    bundle_path: str | Path,
    *,
    policy: VerificationPolicy | None = None,
    statement_public_key: bytes | None = None,
) -> BundleVerificationReport:
    """Verify a bundle v3 artifact offline. No network, no store, no fetch (§8.4).

    A v1 or v2 artifact is refused by name (``BUNDLE_FORMAT_UNSUPPORTED``) before any other
    check runs. It is **not** verified with reduced expectations and not reported as
    malformed v3: §2 deleted those formats, and the whole of S3 was "signature enforcement
    is optional under format 1".

    ``statement_public_key`` is the key the statement signature is checked against, and it
    must come from the **caller**. This module never resolves it from the artifact — not
    from ``sections.bundled_key_evidence``, not from an acceptance payload — because a key
    harvested from the artifact it authenticates is §5.2 rule C's clamp, and a verifier
    that quietly harvested it would make the clamp unreachable. ``None`` is a legitimate
    call and is reported as ``statement_signature_checked=False``.

    **This is the Phase C seam, and the signature is Phase C's to change.** §4.1's fix is
    ``verify_audit_bundle_v3(path, trust: TrustPolicy | AcceptBundledKeys)`` — one required
    argument, no default, no ``None`` — because "every 'remember to pass the trust file'
    discipline fails eventually". This function's optional keyword is the honest interim: it
    plumbs the input end to end and reports its absence, but it does not yet make the input
    un-forgettable. Phase C replaces it, and until then the reported ``verified`` is False
    whenever no key was supplied.

    ``policy`` carries the caller's out-of-band per-event pins (trust domain, cutover
    checkpoint, project instance) and is threaded to ``verify_event_strict`` unchanged.
    """

    path = Path(bundle_path)
    if not path.is_file():
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file not found: {bundle_path}",
        )

    raw = path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file too large ({len(raw)} bytes, max {MAX_BUNDLE_BYTES})",
        )

    document = parse_bundle_v3_document(raw)
    core = verify_bundle_v3_core(document, statement_public_key=statement_public_key)

    errors: list[str] = list(core.findings)
    members: list[OrderedMember] = []
    if core.chain_ordered:
        members = [
            parse_event_member(
                base64.b64decode(record["canonical_envelope"], validate=True),
                base64.b64decode(record["signature"], validate=True),
            )
            for record in document.events
        ]
        # Re-derive rather than reuse: `verify_bundle_v3_core` returns hashes, not members,
        # so that its report stays a report. The order below is the signed one because the
        # core already proved the traversal agrees with `scope`.
        from ._bundle_v3 import derive_chain_order

        members = derive_chain_order(
            members, preceding_event_hash=document.scope["preceding_event_hash"]
        )
        errors.extend(_check_trust_root_against_genesis(document, members))

    ok_entity, err_entity = (
        _verify_entity_chains(members) if members else (True, "")
    )
    if not ok_entity:
        errors.append(f"Entity chain error: {err_entity}")

    events = [_event_from_member(m) for m in members]
    sigs_verified, sigs_unverifiable, sig_errors, sigs_unverifiable_details = (
        _verify_event_signatures(
            events,
            _bundled_key_registry(document.sections["bundled_key_evidence"]),
            policy=policy or DEFAULT_POLICY,
            referents=_bundle_referents_v3(str(document.scope["kind"]), events),
        )
    )
    errors.extend(sig_errors)

    # WI-267 survives verbatim: `signatures_verified > 0` is part of the verdict, because
    # "nothing was checked" must never read as "everything checks out". Bundle v3 adds the
    # statement signature to the same rule — an artifact whose membership statement nobody
    # could check is not verified either, and §4.1 is why the key is a caller input.
    verified = (
        core.structural_checks_ok
        and core.statement_signature_checked
        and core.statement_signature_valid
        and ok_entity
        and len(errors) == 0
        and sigs_verified > 0
    )

    return BundleVerificationReport(
        verified=verified,
        event_count=core.event_count,
        format_version=core.format_version,
        global_chain_ok=core.chain_ordered,
        global_chain_error=(
            None
            if core.chain_ordered
            else next(
                (f for f in core.findings if f.startswith("BUNDLE_CHAIN_UNORDERABLE")),
                "the presented events do not form one contiguous chain segment",
            )
        ),
        work_item_chain_ok=ok_entity,
        work_item_chain_error=err_entity or None,
        statement_signature_checked=core.statement_signature_checked,
        statement_signature_valid=core.statement_signature_valid,
        membership_root_ok=core.membership_root_ok,
        section_digests_ok=core.section_digests_ok,
        reference_sections_ok=core.reference_sections_ok,
        scope_consistent=core.scope_consistent,
        signer_authority_checked=core.signer_authority_checked,
        signer_may_sign_bundles=core.signer_may_sign_bundles,
        signatures_verified=sigs_verified,
        signatures_unverifiable=sigs_unverifiable,
        errors=errors,
        unverifiable_details=sigs_unverifiable_details,
    )


def verify_bundle_v3_report(
    bundle_path: str | Path, *, statement_public_key: bytes | None = None
) -> BundleV3CoreReport:
    """Return the raw §3 core report for an artifact on disk.

    The Phase C/D seam in its narrowest form: no event authentication, no chain walk beyond
    the traversal §3.3 needs, no boolean summary. A caller building the §5.1 axes wants
    this, not :func:`verify_audit_bundle_offline`'s report.
    """

    return verify_bundle_v3_core(
        parse_bundle_v3_document(Path(bundle_path).read_bytes()),
        statement_public_key=statement_public_key,
    )


def _key_evidence_from_v6_payloads(events: list[Event]) -> dict[str, dict[str, Any]]:
    """Key material carried by the bundle's own v6 acceptance payloads (WI-296).

    ``TRUST-DOMAIN.md`` §5.8 repeats ``public_key`` inside every
    ``regista.key-acceptance`` object, and ``RECONCILIATION.md`` Resolution 1 repeats
    it inside every ``bootstrap_key_acceptance``, and both say why: "It makes a
    project bundle self-sufficient for key material without making it self-sufficient
    for *trust*: the bytes are present, the authority to believe them comes from the
    externally pinned root via ``trust_event_hash``."

    So this is not a fallback and not a second key resolver — it reads the **signed
    envelope** of an event the bundle already carries. The alternative WI-296 offered
    (``write_genesis`` seeding a ``principal_keys`` row from the same object) was
    rejected on the item: a projection row that exists *because* a verifier needs it
    is precisely §5.9 rule 1's forbidden coupling.

    The entries produced carry no validity window and no revocation state, because
    the acceptance payload declares none. That is why an operator-registered entry
    wins where both exist: it knows strictly more.
    """

    from ._verification import (
        V6EnvelopeError,
        parse_v6_envelope_strict,
    )

    evidence: dict[str, dict[str, Any]] = {}
    for evt in events:
        if evt.canonical_envelope is None:
            continue
        try:
            envelope = parse_v6_envelope_strict(bytes(evt.canonical_envelope))
        except (V6EnvelopeError, TypeError, ValueError):
            continue
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            continue
        candidates: list[Mapping[str, Any]] = []
        if payload.get("type") == "regista.key-acceptance":
            candidates.append(payload)
        embedded = payload.get("bootstrap_key_acceptance")
        if isinstance(embedded, Mapping):
            candidates.append(embedded)
        for acceptance in candidates:
            key_id = acceptance.get("key_id")
            principal_id = acceptance.get("principal_id")
            public_key = acceptance.get("public_key")
            if not (
                isinstance(key_id, str)
                and isinstance(principal_id, str)
                and isinstance(public_key, str)
            ):
                continue
            try:
                material = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error):
                continue
            if len(material) != 32:
                continue
            evidence.setdefault(
                key_id,
                {
                    "key_id": key_id,
                    "principal_id": principal_id,
                    # The scheme is ed25519 by construction: a v6 envelope's
                    # `signing.scheme_id` is validated to it, and the acceptance's
                    # own `scheme_id` is cross-checked at write time
                    # (`_genesis._require_bootstrap_acceptance`).
                    "scheme": "ed25519",
                    "public_key": material,
                    "status": "active",
                    "valid_from": None,
                    "valid_to": None,
                    "revoked_at": None,
                },
            )
    return evidence


def _verify_event_signatures(
    events: list[Event],
    public_keys_data: list[dict[str, Any]],
    *,
    manifest: Mapping[str, Any] | None = None,
    policy: VerificationPolicy | None = None,
    referents: BundleReferents | None = None,
) -> tuple[int, int, list[str], list[str]]:
    """Verify event signatures offline against the bundled key registry.

    Asymmetric-scheme events (e.g. ed25519) are verified against the
    principal public-key registry exported in the bundle, including the
    principal↔signer binding (key.principal_id must equal event.actor_id,
    mirroring ``verify_principal_binding``) and the key's validity window.

    Symmetric-scheme events (hmac-*) are counted as unverifiable: verifying
    an HMAC requires the secret, which is deliberately never exported. An
    unknown scheme fails closed.

    ``referents`` is the presented material and its completeness claim. Bundle v3 builds it
    from the signed ``scope.kind`` (:func:`_bundle_referents_v3`); the ``manifest``
    fallback derives the same claim from the v2 window keys and survives for callers that
    still hold a v2-shaped mapping — tests of this function's principal-binding rule among
    them.

    Returns ``(verified_count, unverifiable_count, errors, unverifiable_details)``.
    """
    keys_by_id: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    for kd in public_keys_data:
        try:
            entry = {
                "key_id": kd["key_id"],
                "principal_id": kd["principal_id"],
                "scheme": kd["scheme"],
                "public_key": bytes.fromhex(kd["public_key"]),
                "status": kd.get("status", "active"),
                "valid_from": (
                    datetime.fromisoformat(kd["valid_from"])
                    if kd.get("valid_from")
                    else None
                ),
                "valid_to": (
                    datetime.fromisoformat(kd["valid_to"])
                    if kd.get("valid_to")
                    else None
                ),
                "revoked_at": (
                    datetime.fromisoformat(kd["revoked_at"])
                    if kd.get("revoked_at")
                    else None
                ),
            }
        except (KeyError, ValueError, TypeError) as exc:
            errors.append(f"Malformed public-key entry in bundle: {exc}")
            continue
        keys_by_id[entry["key_id"]] = entry

    # WI-296's genesis key-evidence half, taking the BUNDLE route rather than
    # seeding `principal_keys` from the genesis payload. §5.8 repeats `public_key`
    # inside the acceptance object **on purpose** — "it makes a project bundle
    # self-sufficient for key material without making it self-sufficient for
    # trust" — so a bundle that carries a v6 acceptance already carries the bytes,
    # and reading them from there is not a fallback: it is the signed artifact.
    # Seeding the projection instead would put a row in `principal_keys`
    # specifically so a verifier could find it, which §5.9 rule 1 forbids and
    # §5.11's last row calls the S6 defect.
    #
    # The registry still wins where both exist: an operator-registered entry
    # carries a validity window and a status that the payload does not.
    for key_id, entry in _key_evidence_from_v6_payloads(events).items():
        keys_by_id.setdefault(key_id, entry)

    verified_count = 0
    unverifiable_count = 0
    errors_unverifiable: list[str] = []
    resolver = BundleKeyResolver(keys_by_id)
    effective_referents = (
        referents
        if referents is not None
        else BundleReferents.from_bundle(manifest or {}, events)
    )
    effective_policy = policy or DEFAULT_POLICY

    for evt in events:
        label = f"event {evt.event_id} (global_seq={evt.global_seq})"

        key = keys_by_id.get(evt.key_id)
        if key is None:
            # WI-267 / S2-interim: whether this event needs an asymmetric check
            # is decided from key metadata, not from the row's self-declared
            # scheme_id. With no registry entry there is no metadata, so a row
            # claiming a symmetric scheme can no longer excuse itself — an
            # event whose key the bundle does not carry is unverifiable.
            try:
                claimed = get_scheme(evt.scheme_id)
            except RegistaError:
                errors.append(
                    f"Unknown signing scheme {evt.scheme_id!r} at {label} (fail closed)"
                )
                continue
            if getattr(claimed, "is_asymmetric", False):
                errors.append(
                    f"No public key for key_id {evt.key_id!r} in bundle registry at {label}"
                )
            else:
                unverifiable_count += 1
            continue

        key_scheme = key["scheme"]
        try:
            scheme = get_scheme(key_scheme)
        except RegistaError:
            errors.append(
                f"Unknown signing scheme {key_scheme!r} for key {evt.key_id!r} "
                f"at {label} (fail closed)"
            )
            continue

        if not getattr(scheme, "is_asymmetric", False):
            # Verifying an HMAC requires the secret, which is deliberately never
            # exported. Unverifiable, and it must not count towards `verified`.
            unverifiable_count += 1
            continue

        if key["principal_id"] != evt.actor_id:
            errors.append(
                f"Actor-signer mismatch at {label}: actor_id={evt.actor_id!r} "
                f"but key {evt.key_id!r} is bound to {key['principal_id']!r}"
            )
            continue

        try:
            if key["valid_from"] is not None and evt.timestamp < key["valid_from"]:
                errors.append(
                    f"Event signed before key validity at {label}: "
                    f"timestamp={evt.timestamp.isoformat()}, "
                    f"valid_from={key['valid_from'].isoformat()}"
                )
                continue
            boundary = key["revoked_at"] or key["valid_to"]
            if boundary is not None and evt.timestamp > boundary:
                errors.append(
                    f"Event signed after key revocation/expiry at {label}: "
                    f"timestamp={evt.timestamp.isoformat()}, "
                    f"boundary={boundary.isoformat()}"
                )
                continue
        except TypeError as exc:
            errors.append(f"Key validity comparison failed at {label}: {exc}")
            continue

        # WI-267: this used to be a second, independent verifier that called
        # scheme.verify() on the stored envelope and never reconciled the row —
        # the audit's defect in its purest form. It now delegates to the one
        # primitive, so a bundle whose event records were rewritten under intact
        # envelopes no longer verifies.
        result = verify_event_strict(
            EventRow.from_event(evt, backend=Backend.BUNDLE),
            keys=resolver,
            referents=effective_referents,
            policy=effective_policy,
        )
        if result.applicability is Applicability.INVALID:
            errors.append(f"Signature verification failed at {label}: {result.summary()}")
            continue
        if not result.accepted:
            # UNVERIFIABLE is an evidentiary gap, not a defect of the artifact, and
            # the two must not be collapsed — the operator response is completely
            # different. Two cases reach here on a healthy v6 bundle and both are
            # honest: a bootstrap event whose authority is external and unpinned
            # (RECONCILIATION.md Resolution 1), and a referent outside a
            # `contiguous-range` window (§9 criterion 15). Both are counted, and the
            # reason travels with the count instead of being dropped.
            unverifiable_count += 1
            errors_unverifiable.append(f"{label}: {result.summary()}")
            continue

        verified_count += 1

    return verified_count, unverifiable_count, errors, errors_unverifiable


def _hash_event(event: Event) -> bytes | None:
    """The chain head hash this event contributes, in ITS OWN version's formula.

    Delegates to :func:`regista._signing.compute_chain_head_hash`, which is where the
    formula lives for the whole tree. This function used to hand-copy the version
    dispatch, which made it the **fifth** copy — and the copies have a history:
    mutation M20 reverted this one to the legacy formula and the suite stayed green
    (NOTES-P17 finding 15), and ``_in_memory_replay`` carried the legacy formula in
    both its chain walks, which made a healthy in-memory v6 epoch report five chain
    breaks (finding 16). Finding 16 centralised the formula; this is that
    centralisation finishing the job it started, found by the phase-4 ceremony.

    ``None`` when the event carries no bytes to chain on. Under bundle v3 that case is
    unreachable from an artifact — §3.6 refuses to represent an event without an
    envelope — but the helper is also called on live-store events, where a pre-002 row
    can still turn up, and "no envelope" is not "a zero hash".
    """

    if event.canonical_envelope is None or event.signature is None:
        return None
    from ._signing import compute_chain_head_hash

    return compute_chain_head_hash(
        bytes(event.canonical_envelope), bytes(event.signature)
    )


def _verify_work_item_chains(events: list[Event]) -> tuple[bool, str]:
    """Per-entity chain walk over :class:`~regista._types.Event` values.

    Retained for callers holding row-shaped events (replay, the live-store paths). The
    bundle-v3 verifier uses :func:`_verify_entity_chains`, which reads the signed envelope
    instead of a projected row — the same invariant, one fewer copy of the data.
    """
    from collections import defaultdict

    by_entity: dict[tuple[str, uuid.UUID], list[Event]] = defaultdict(list)
    for evt in events:
        entity_key = (evt.entity_kind, evt.effective_entity_id)
        by_entity[entity_key].append(evt)

    for (ek, eid), entity_events in by_entity.items():
        entity_events.sort(key=lambda e: e.event_seq)

        entity_event_hashes: set[bytes] = set()
        for evt in entity_events:
            head = _hash_event(evt)
            if head is not None:
                entity_event_hashes.add(head)

        prev_hash: bytes | None = None
        for i, evt in enumerate(entity_events):
            if i == 0:
                if evt.prev_event_hash is not None:
                    if bytes(evt.prev_event_hash) in entity_event_hashes:
                        return False, (
                            f"first event for {ek}/{eid} references an event "
                            f"within the slice — slice is incomplete"
                        )
            else:
                if evt.prev_event_hash is None:
                    return False, (
                        f"event {evt.event_id} (seq {evt.event_seq}) "
                        f"for {ek}/{eid} has null prev_event_hash"
                    )
                if prev_hash is not None:
                    if not _hmac.compare_digest(prev_hash, bytes(evt.prev_event_hash)):
                        return False, (
                            f"hash chain mismatch for {ek}/{eid} at seq {evt.event_seq}"
                        )
            head = _hash_event(evt)
            prev_hash = head

    return True, ""


__all__ = [
    "MAX_BUNDLE_BYTES",
    "BundleVerificationReport",
    "export_audit_bundle",
    "verify_audit_bundle_offline",
    "verify_bundle_v3_report",
]
