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
    The three values §6 names are gone with the field. One was unconditional, one described
    a format that no longer exists, and the third was exactly A4 ``none_verifiable`` in the
    §5.1 axis model — a correct signal invented under duress because the boolean could not
    carry it. The strings are not repeated here: a deleted magic string that survives in a
    docstring is the next reader's grep hit.

``_row_to_event_dict``
    §3.6: a v3 event record is ``{canonical_envelope, signature}`` and **nothing else**.
    The twenty row columns v2 exported alongside the envelope were a second copy of signed
    data for a consumer to read instead of the signed one. The projection now runs the
    other way — :func:`_event_from_member` recomputes the row view *from* the envelope —
    which is the same discipline ``verify_event_strict`` applies to a live row.

``_hash_event`` / ``_verify_work_item_chains``
    Both walked chains over *row-shaped* :class:`~regista._types.Event` values. A v3 event
    record has no row, so the per-entity walk became :func:`_verify_entity_chains`, which
    reads ``chain.previous_entity_event_hash`` out of the signed envelope — the same
    invariant with one fewer copy of the data. Keeping the row-shaped pair beside it would
    have been the fifth and sixth copies of the chain-hash formula, and the copies have a
    history: mutation M20 reverted ``_hash_event`` to the legacy formula and the suite
    stayed green.

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
import json
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

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
    ed25519_fingerprint,
    parse_bundle_v3_document,
    parse_event_member,
    statement_signing_input,
    verify_bundle_v3_core,
)
from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._signing_scheme import get_scheme
from ._types import Event
from ._v6_referents import (
    BundleReferents,
    MaterialCompleteness,
    ReferentEvent,
    referent_from_bytes,
)
from ._verification import (
    DEFAULT_POLICY,
    Applicability,
    Backend,
    BundledKeyEvidenceResolver,
    EventRow,
    TrustedKey,
    TrustedKeySource,
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

    ``verified`` is **deleted** (Phase C). ``BUNDLE-V3.md`` §5.2 is explicit — "There is no
    ``verified: bool``. Not deprecated — absent" — because a single boolean cannot say *whose*
    key signed, which is the whole of §4. The verdict now lives in :class:`BundleReport`'s
    ordered ``applicability`` over the §5.1 axes, produced by :func:`verify_audit_bundle_v3`.

    This report survives only as the **export self-check** vehicle: export (Phase D) still
    signs with its own key and asks "does the artifact I just wrote verify against that key",
    which is an integrity question, not a trust one. That question's answer is
    :attr:`self_verification_ok` — named for what it checks, never ``verified``, so an export
    log line can never be mistaken for an authentication verdict (WI-272).
    """

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
    #: ``None`` means the check did not run, because the chain could not be ordered and
    #: there was nothing to root, compare or classify. Mirrors
    #: :class:`~regista._bundle_v3.BundleV3CoreReport`'s contract: an unrun check must never
    #: be emitted as a passing fact.
    membership_root_ok: bool | None = True
    section_digests_ok: bool = True
    reference_sections_ok: bool | None = True
    scope_consistent: bool | None = True
    signer_authority_checked: bool = False
    signer_may_sign_bundles: bool = False
    signatures_verified: int = 0
    signatures_unverifiable: int = 0
    errors: list[str] = field(default_factory=list)
    #: Named facts that are not failures and must not be read as satisfaction either —
    #: ``RECONCILIATION.md`` Resolution 4's "reports the named dependency as outside scope,
    #: never silently valid". A ``contiguous-range`` bundle whose signing-authority event
    #: lies outside its window lands here.
    notes: list[str] = field(default_factory=list)
    #: Why each unverifiable signature was unverifiable. A count with no reason is
    #: how "nothing was checked" gets read as "everything checks out"; the two v6
    #: cases that land here (an unpinned bootstrap event, a referent outside a
    #: windowed scope) are both things an auditor must be able to read off the
    #: report rather than reproduce.
    unverifiable_details: list[str] = field(default_factory=list)

    @property
    def self_verification_ok(self) -> bool:
        """The export integrity self-check: the artifact verifies against its own signer.

        Deliberately not ``verified`` (§5.2, WI-272): it says nothing about *whose* key,
        only that the bytes on disk match the statement the exporter signed and every
        structural recomputation agrees. A caller wanting a trust verdict uses
        :func:`verify_audit_bundle_v3`, which resolves the key against auditor-supplied
        material and reports the §5.1 axes.
        """

        return (
            self.membership_root_ok is True
            and self.section_digests_ok is True
            and self.reference_sections_ok is True
            and self.scope_consistent is True
            and self.global_chain_ok
            and self.work_item_chain_ok
            and self.statement_signature_checked
            and self.statement_signature_valid
            and self.signer_authority_checked
            and self.signer_may_sign_bundles
            and not self.errors
            and self.signatures_verified > 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
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
            "notes": self.notes,
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
    """Resolve the statement signer's identity, and refuse early if the store denies it.

    Two independent gates guard owner ruling O3, and both run. This one asks the STORE:
    ``resolve_key_binding_anchor`` sees the whole chain including ``events_archive`` and
    every revocation, and it refuses with the store's own named errors
    (``KEY_ACCEPTANCE_REVOKED``, ``KEY_BINDING_UNRESOLVED``). The second is
    ``build_bundle_v3_document``'s offline derivation over the event bytes it is about to
    sign — the same rules read from the artifact rather than from the store.

    Keeping both is deliberate rather than redundant. They can only disagree if the offline
    material misrepresents the store, which is the exact condition the artifact exists to
    make detectable; and the store-side check gives a fast, precise refusal before any
    signing work happens. The offline one is what an auditor can reproduce.
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
    if not anchor.scopes.may_sign_bundles:
        raise RegistaError(
            ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED,
            f"key {entry.key_id!r} for principal {principal_id!r} does not bear "
            "may_sign_bundles in the anchor currently in force for it "
            f"({anchor.event_hash}, kind {anchor.kind}). Owner ruling O3: the statement "
            "signer MAY be the project writer key, but the authority is an explicit, "
            "signed property of the key (TRUST-DOMAIN.md §5.8 scopes) and never an "
            "implication of holding it. Grant the scope in a key-acceptance event, or "
            "sign with a key that has it. Nothing was written.",
            detail={
                "principal_id": principal_id,
                "key_id": entry.key_id,
                "anchor_event_hash": anchor.event_hash,
            },
        )
    return BundleV3Signer(
        principal_id=principal_id,
        key_id=entry.key_id,
        fingerprint=ed25519_fingerprint(entry.public_key),
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
        :func:`_trust_root_from_store` for why it cannot be derived from a project
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

    # A windowed export legitimately excludes the signer's own acceptance event, so the
    # builder resolves O3 over the WHOLE chain (what the exporter observes) and emits over
    # the window. Reading the full chain a second time is the honest cost of that: the
    # alternative is resolving authority from the window and refusing every chunk that
    # happens not to contain the acceptance, which would break §9's chunking workflow.
    authority_records = records
    if since_seq is not None or until_seq is not None:
        with mgr.transaction() as conn:
            authority_records = _read_export_rows(conn, since_seq=None, until_seq=None)

    document = build_bundle_v3_document(
        event_records=records,
        authority_records=authority_records,
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
    if not report.self_verification_ok:
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
        self_verified=report.self_verification_ok,
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
            "verified": report.self_verification_ok,
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

    # The report exposes the export integrity self-check as `self_verification_ok`
    # (computed from the fields below), not a stored `verified` boolean — §5.2 deletes that
    # boolean because it cannot say *whose* key. WI-267's rule survives inside that property:
    # `signatures_verified > 0`, the statement signature checked-and-valid, and the signer's
    # `may_sign_bundles` re-derived from its signed acceptance (O3) are all required, so
    # "nothing was checked" never reads as "everything checks out".
    return BundleVerificationReport(
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
        notes=list(core.notes),
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
    resolver = BundledKeyEvidenceResolver(keys_by_id)
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


# ===========================================================================
# Bundle v3 Phase C — the trust root, the axis model, the verdict lattice
# (BUNDLE-V3.md §4, §5, §10; WI-289 Phase C)
#
# S1's whole reason for existing is that "we did not check" and "the check failed" are
# different facts, and a single boolean conflates them. Phase C keeps them apart with an
# axis per question (§5.1), each reporting `not_checkable` when the supplied trust material
# cannot answer it — never a silent `false`. The summary `applicability` is the WEAKEST of
# the axes (§5.2), and the two required-argument types below make it impossible to reach a
# verdict without the caller stating, on the record, where trust comes from (§4.1).
# ===========================================================================


class BundleStructure(StrEnum):
    """A1 — did the document parse at all."""

    PARSED = "parsed"
    MALFORMED = "malformed"


class MembershipSignature(StrEnum):
    """A2 — the statement signature, and against whose key."""

    VALID_EXTERNAL_ROOT = "valid_external_root"
    VALID_BUNDLED_KEY = "valid_bundled_key"
    INVALID = "invalid"
    ABSENT = "absent"


class MembershipConsistency(StrEnum):
    """A3 — do the presented events match the signed scope and root."""

    COMPLETE_FOR_CLAIMED_SCOPE = "complete_for_claimed_scope"
    MISMATCH = "mismatch"
    NOT_CHECKABLE = "not_checkable"


class EventAuthentication(StrEnum):
    """A4 — aggregated over per-event ``Applicability``."""

    FULL = "full"
    LEGACY_PARTIAL = "legacy_partial"
    NONE_VERIFIABLE = "none_verifiable"
    INVALID = "invalid"
    NOT_CHECKABLE = "not_checkable"


class EventTrustRootAxis(StrEnum):
    """A5 — aggregated over per-event ``TrustedKeySource`` (the WEAKEST)."""

    EXTERNALLY_PINNED = "externally_pinned"
    TRUST_LOG_ONLY = "trust_log_only"
    BUNDLED_ONLY = "bundled_only"
    ABSENT = "absent"
    NOT_CHECKABLE = "not_checkable"


class ScopeCorroboration(StrEnum):
    """A7 — does an independently pinned head agree with the signed scope."""

    MATCHES_PINNED_HEAD = "matches_pinned_head"
    NO_PIN_SUPPLIED = "no_pin_supplied"
    CONTRADICTS_PINNED_HEAD = "contradicts_pinned_head"
    NOT_CHECKABLE = "not_checkable"


class RegistryChainConsistency(StrEnum):
    """A8 — does bundled key evidence agree with the signed acceptances (§4.3)."""

    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    NOT_APPLICABLE = "not_applicable"


class Governance(StrEnum):
    """A9 — the replayed/restated governance state against the policy (§4.5)."""

    MATCHES_POLICY = "matches_policy"
    UNVERIFIED_RESTATEMENT = "unverified_restatement"
    CONTRADICTS_POLICY = "contradicts_policy"
    NOT_CHECKABLE = "not_checkable"


class BundleApplicability(StrEnum):
    """The §5.2 summary — the WEAKEST over the axes and the clamps."""

    INVALID = "invalid"
    UNAUTHENTICATED = "unauthenticated"
    BUNDLE_ROOTED = "bundle_rooted"
    EXTERNALLY_AUTHENTICATED = "externally_authenticated"


#: The ordered lattice (§5.2): ``invalid < unauthenticated < bundle_rooted <
#: externally_authenticated``. ``legacy_checkpoint_bound`` is DROPPED (decision E3), and Rule
#: S is WITHDRAWN with ``declared-selection``. Rank is used only for the two clamps and the
#: minimum; the string enum is what a report carries.
_APPLICABILITY_RANK: Final[dict[BundleApplicability, int]] = {
    BundleApplicability.INVALID: 0,
    BundleApplicability.UNAUTHENTICATED: 1,
    BundleApplicability.BUNDLE_ROOTED: 2,
    BundleApplicability.EXTERNALLY_AUTHENTICATED: 3,
}

#: A5 aggregated over events is the WEAKEST source any event's key came from. absent is the
#: floor: a single event whose key resolved to nothing drops the whole axis to it.
_TRUST_ROOT_RANK: Final[dict[EventTrustRootAxis, int]] = {
    EventTrustRootAxis.ABSENT: 0,
    EventTrustRootAxis.BUNDLED_ONLY: 1,
    EventTrustRootAxis.TRUST_LOG_ONLY: 2,
    EventTrustRootAxis.EXTERNALLY_PINNED: 3,
}

_TRUSTED_KEY_SOURCE_TO_AXIS: Final[dict[TrustedKeySource, EventTrustRootAxis]] = {
    TrustedKeySource.EXTERNALLY_PINNED: EventTrustRootAxis.EXTERNALLY_PINNED,
    TrustedKeySource.TRUST_DOMAIN_LOG: EventTrustRootAxis.TRUST_LOG_ONLY,
    TrustedKeySource.BUNDLE_EMBEDDED: EventTrustRootAxis.BUNDLED_ONLY,
    TrustedKeySource.NONE: EventTrustRootAxis.ABSENT,
}

_TRUST_POLICY_SCHEMA_TYPE: Final[str] = "regista.trust-policy"

#: The §4.6 fields a FULL policy file must carry. ``required_root_governance`` and
#: ``known_project_checkpoints`` are deliberately NOT here: the former defaults to the strict
#: ``["co_signed"]`` when absent (§4.6), the latter is optional and its presence is what
#: upgrades ``complete-store`` from an attestation to a checked claim (§4.2).
_REQUIRED_TRUST_POLICY_FIELDS: Final[tuple[str, ...]] = (
    "trust_domain_id",
    "trust_domain_core_digest",
    "genesis_document_digest",
    "root_signer_fingerprints",
    "min_root_signatures",
    "publication",
    "accepted_project_instance_ids",
    "min_trust_log_checkpoint",
    "bundle_signing",
    "legacy_epoch_policy",
)


@dataclass(frozen=True)
class TrustPolicy:
    """The auditor's out-of-band trust material (``TRUST-DOMAIN.md`` §4.6, consumed by §4.2).

    Constructed ONLY from an auditor-supplied file (:meth:`from_file`) or explicit
    fingerprints (:meth:`from_fingerprints`). It is never built from a bundle — that is the
    S5 circularity, and the type has no constructor that takes one. Every policy-dependent
    axis it cannot answer (the ad-hoc fingerprint form answers few) reports ``not_checkable``
    or the axis's honest "no pin" value, never a pass (§4.2).
    """

    trust_domain_id: str | None = None
    trust_domain_core_digest: str | None = None
    genesis_document_digest: str | None = None
    required_root_governance: tuple[str, ...] = ("co_signed",)
    root_signer_fingerprints: frozenset[str] = frozenset()
    min_root_signatures: int | None = None
    accepted_project_instance_ids: frozenset[str] | None = None
    min_trust_log_checkpoint: Mapping[str, Any] | None = None
    known_project_checkpoints: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    bundle_signing: Mapping[str, Any] | None = None
    legacy_epoch_policy: Mapping[str, Any] | None = None
    #: ``"trust_policy"`` for the full §4.6 form, ``"ad_hoc_fingerprints"`` for the minimal
    #: ``--trusted-fingerprint`` form. The distinction is not cosmetic: the ad-hoc form has no
    #: governance expectation, no accepted-project set and no head pin, so the axes those
    #: fields drive report their not-checkable value under it.
    source: str = "trust_policy"

    @property
    def is_ad_hoc(self) -> bool:
        return self.source == "ad_hoc_fingerprints"

    @property
    def pinned_fingerprints(self) -> frozenset[str]:
        return self.root_signer_fingerprints

    @classmethod
    def from_fingerprints(cls, fingerprints: Sequence[str]) -> TrustPolicy:
        """The minimal ad-hoc form (§4.2): repeated ``--trusted-fingerprint``.

        Subsumes WI-209's ``--trusted-fingerprints <file>``. It supplies pinned root
        fingerprints and nothing else, so governance (A9), the accepted-project check and the
        head pin (A7) all report their not-checkable value — never a pass.
        """

        cleaned: list[str] = []
        for raw in fingerprints:
            fp = raw.strip()
            if not (fp.startswith("ed25519:sha256:") and len(fp) == len("ed25519:sha256:") + 64):
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"--trusted-fingerprint must be ed25519:sha256:<64 lowercase hex>, got "
                    f"{raw!r} (TRUST-DOMAIN.md §3.5's one fingerprint function)",
                )
            cleaned.append(fp)
        if not cleaned:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "at least one --trusted-fingerprint is required for the ad-hoc trust form",
            )
        return cls(
            root_signer_fingerprints=frozenset(cleaned),
            min_root_signatures=1,
            source="ad_hoc_fingerprints",
        )

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> TrustPolicy:
        """Consume the ONE §4.6 schema, rejecting a policy missing a required field.

        Defines no competing shape (§4.2, collision 11): the field names are exactly
        ``TRUST-DOMAIN.md`` §4.6's. A missing required field is a refusal, not a default —
        the one deliberate default is ``required_root_governance`` → ``["co_signed"]``, the
        strict direction, so a policy written without thought rejects a solo root.
        """

        if not isinstance(document, Mapping):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT, "trust policy must be a JSON object"
            )
        declared_type = document.get("type")
        if declared_type != _TRUST_POLICY_SCHEMA_TYPE:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"trust policy.type must be {_TRUST_POLICY_SCHEMA_TYPE!r}, got "
                f"{declared_type!r}",
            )
        missing = [f for f in _REQUIRED_TRUST_POLICY_FIELDS if f not in document]
        if missing:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"trust policy is missing required §4.6 field(s): {sorted(missing)}. This "
                "verifier consumes TRUST-DOMAIN.md §4.6's schema and defines no fallback; a "
                "policy that omits a field it requires is refused, not defaulted",
            )
        fingerprints = document["root_signer_fingerprints"]
        if not isinstance(fingerprints, Sequence) or isinstance(fingerprints, str | bytes):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "trust policy.root_signer_fingerprints must be a list of fingerprints",
            )
        accepted = document["accepted_project_instance_ids"]
        if not isinstance(accepted, Sequence) or isinstance(accepted, str | bytes):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "trust policy.accepted_project_instance_ids must be a list",
            )
        governance = document.get("required_root_governance", ["co_signed"])
        if not isinstance(governance, Sequence) or isinstance(governance, str | bytes):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "trust policy.required_root_governance must be a list of mode names",
            )
        checkpoints = document.get("known_project_checkpoints", {})
        if not isinstance(checkpoints, Mapping):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "trust policy.known_project_checkpoints must be an object keyed by "
                "project_instance_id",
            )
        return cls(
            trust_domain_id=str(document["trust_domain_id"]),
            trust_domain_core_digest=str(document["trust_domain_core_digest"]),
            genesis_document_digest=str(document["genesis_document_digest"]),
            required_root_governance=tuple(str(m) for m in governance),
            root_signer_fingerprints=frozenset(str(fp) for fp in fingerprints),
            min_root_signatures=int(document["min_root_signatures"]),
            accepted_project_instance_ids=frozenset(str(p) for p in accepted),
            min_trust_log_checkpoint=document["min_trust_log_checkpoint"],
            known_project_checkpoints=dict(checkpoints),
            bundle_signing=document["bundle_signing"],
            legacy_epoch_policy=document["legacy_epoch_policy"],
            source="trust_policy",
        )

    @classmethod
    def from_file(cls, path: str | Path) -> TrustPolicy:
        """Load and parse a §4.6 policy file. Never read from the store or a bundle."""

        raw = Path(path).read_text(encoding="utf-8")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT, f"trust policy is not valid JSON: {exc}"
            ) from exc
        return cls.from_mapping(document)


@dataclass(frozen=True)
class AcceptBundledKeys:
    """The operator's explicit, deliberately awkward acceptance of bundled-key checking.

    §4.1: this is a DISTINCT type carrying explicit operator acceptance. It is **not** a
    :class:`TrustPolicy`, does not subclass one, and carries no pin, so there is no implicit
    conversion and no ``isinstance(x, TrustPolicy)`` branch can ever mistake it for external
    trust. Constructing it requires typing the acknowledgement out in full — the awkwardness
    is the point (§4.1): an operator who reaches for this is stating that the bundle will be
    checked against keys carried *inside itself*, and the verdict is clamped to
    ``bundle_rooted`` by Rule C no matter what else holds.
    """

    operator_acknowledges_no_external_trust: bool

    def __post_init__(self) -> None:
        if self.operator_acknowledges_no_external_trust is not True:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "AcceptBundledKeys must be constructed as "
                "AcceptBundledKeys(operator_acknowledges_no_external_trust=True): it is a "
                "deliberate, un-defaultable acceptance that the bundle is authenticated "
                "against keys carried inside it, and the result is clamped to bundle_rooted "
                "(BUNDLE-V3.md §4.1, §5.2 rule C)",
            )


@dataclass(frozen=True)
class PolicyKeyResolver:
    """The default-path resolver, built ONLY from a :class:`TrustPolicy` (§4.3 mechanism 2).

    Key *material* (bytes) travels in the bundle's ``bundled_key_evidence``; *trust* comes
    only from the auditor's pin (§4.2). This resolver reads the bytes from the evidence and
    tags a key ``EXTERNALLY_PINNED`` **only in the base case**: its recomputed fingerprint is
    itself a policy-pinned ROOT fingerprint — i.e. a root key signing directly, a chain-to-root
    of length zero.

    **This is the operative reading of §5.1 amendment 4, reconciled with §10 and §4.4
    criterion 2 (see the Phase-C clarifies marker in BUNDLE-V3.md).** Amendment 4's literal
    "externally_pinned iff the fingerprint matches a pin" is the base case only. The §10
    auditor workflow pins the ROOT and lets the acceptance/enrolment chain authenticate the
    keys beneath it (worker → project acceptance → project genesis bootstrap → trust-log
    enrolment → pinned root, with enrolment-before-use and rotation/revocation windowing).
    That chain-to-root walk crosses into the trust log, and every trust-log verifier
    (``verify_trust_log_chain``, ``resolve_enrolled_key``) is store-backed — there is no
    offline, signature-verified trust-log artifact yet (WI-337). So a **non-root** project key
    resolves to ``BUNDLE_EMBEDDED`` here: its authority to a pinned root is real but not
    establishable offline, and reporting it as externally pinned would be the F1 false
    assurance. A key with no matching pin is likewise ``BUNDLE_EMBEDDED``, which clamps the
    verdict (Rule C). It is a different type from
    :class:`~regista._verification.BundledKeyEvidenceResolver` on purpose, so the default path
    can never resolve a bundled key as trusted by habit.
    """

    material_by_key_id: Mapping[str, bytes]
    principal_by_key_id: Mapping[str, str]
    pinned_fingerprints: frozenset[str]

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if key_id is None:
            return None
        material = self.material_by_key_id.get(key_id)
        if material is None:
            return None
        fingerprint = ed25519_fingerprint(material)
        source = (
            TrustedKeySource.EXTERNALLY_PINNED
            if fingerprint in self.pinned_fingerprints
            else TrustedKeySource.BUNDLE_EMBEDDED
        )
        return TrustedKey(
            key_id=key_id,
            material=material,
            scheme_id="ed25519",
            source=source,
            principal_id=self.principal_by_key_id.get(key_id),
        )


@dataclass(frozen=True)
class BundleReport:
    """The §5.1 axis report and the §5.2 verdict, produced by :func:`verify_audit_bundle_v3`.

    Each axis is reported independently. ``not_checkable`` and ``false`` are DIFFERENT and
    are never conflated — that split is the whole reason this phase exists (WI-269/S1). There
    is no ``verified: bool`` (§5.2). ``policy_satisfied`` is emitted ONLY when a full
    :class:`TrustPolicy` was supplied and every named requirement is met.
    """

    structure: BundleStructure  # A1
    membership_signature: MembershipSignature  # A2
    membership_consistency: MembershipConsistency  # A3
    event_authentication: EventAuthentication  # A4
    event_trust_root: EventTrustRootAxis  # A5
    # A6 (`epoch_binding`) DROPPED by decision E3; the number is not reused.
    scope_corroboration: ScopeCorroboration  # A7
    registry_chain_consistency: RegistryChainConsistency  # A8
    governance: Governance  # A9
    #: A10/A11/A12 are per-event *factual* counts. When event verification did not run — the
    #: bundle was malformed or its chain could not be ordered — they are NOT a claim: a
    #: reported ``identity_conflict_count: 0`` on unparseable input would be an unearned "no
    #: conflicts". This flag is ``False`` in exactly that case, and a consumer must read the
    #: counts as ``not_checkable`` (§5.1 not_checkable ≠ false, F5).
    event_verification_ran: bool  # gates A10/A11/A12
    identity_conflict_count: int  # A10
    identity_conflicts: tuple[str, ...]  # A10 list
    event_attribution_counts: Mapping[str, int]  # A11
    key_binding_counts: Mapping[str, int]  # A12
    applicability: BundleApplicability  # §5.2 summary
    tail_truncation_undetectable: bool  # Rule H
    policy_satisfied: bool | None  # only when a full policy was supplied
    event_count: int
    findings: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicability": self.applicability.value,
            "structure": self.structure.value,
            "membership_signature": self.membership_signature.value,
            "membership_consistency": self.membership_consistency.value,
            "event_authentication": self.event_authentication.value,
            "event_trust_root": self.event_trust_root.value,
            "scope_corroboration": self.scope_corroboration.value,
            "registry_chain_consistency": self.registry_chain_consistency.value,
            "governance": self.governance.value,
            "event_verification_ran": self.event_verification_ran,
            # A10/A11/A12 are meaningful only when event_verification_ran is True; a consumer
            # reads them as not_checkable otherwise (F5). Emitted as null in that case so a JSON
            # consumer cannot mistake an unrun check for a factual zero.
            "identity_conflict_count": (
                self.identity_conflict_count if self.event_verification_ran else None
            ),
            "identity_conflicts": list(self.identity_conflicts),
            "event_attribution_counts": (
                dict(self.event_attribution_counts) if self.event_verification_ran else None
            ),
            "key_binding_counts": (
                dict(self.key_binding_counts) if self.event_verification_ran else None
            ),
            "tail_truncation_undetectable": self.tail_truncation_undetectable,
            "policy_satisfied": self.policy_satisfied,
            "event_count": self.event_count,
            "findings": list(self.findings),
            "notes": list(self.notes),
        }


def _bundled_evidence_material(
    section: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, bytes], dict[str, str]]:
    """``key_id -> public-key bytes`` and ``key_id -> principal_id`` from the evidence section."""

    material: dict[str, bytes] = {}
    principals: dict[str, str] = {}
    for record in section:
        try:
            raw = base64.b64decode(str(record["public_key"]), validate=True)
        except (ValueError, binascii.Error, KeyError):
            continue
        if len(raw) != 32:
            continue
        key_id = str(record["key_id"])
        material[key_id] = raw
        principal = record.get("principal_id")
        if isinstance(principal, str):
            principals[key_id] = principal
    return material, principals


def _verify_root_signatures(
    statement: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    *,
    pinned_fingerprints: frozenset[str],
    min_root_signatures: int | None,
) -> tuple[int, list[str]]:
    """Verify each ``root_signatures[]`` entry (§3.2 item 2), now that Phase C holds the pin.

    Phase B refused this member; Phase C verifies it against the auditor's pinned root signer
    set and threshold (§4.4 criterion 4). Each entry's signature is checked over the same
    domain-prefixed JCS bytes the single-signer path signs (§3.4), the entry's fingerprint
    must be pinned, and at least ``min_root_signatures`` distinct pinned signers must verify.
    Returns ``(verified_count, findings)``.
    """

    from ._signing_scheme import Ed25519Scheme

    # The signatures cannot cover themselves, so the signing input is the statement with its
    # own `root_signatures` member removed — the same relationship the single-signer path has
    # to its sibling `statement_signature` block (§3.4).
    signed_statement = {k: v for k, v in statement.items() if k != "root_signatures"}
    signing_input = statement_signing_input(signed_statement)
    digest = hashlib.sha256(signing_input).digest()
    findings: list[str] = []
    verified: set[str] = set()
    for index, entry in enumerate(entries):
        fingerprint = str(entry["fingerprint"])
        try:
            public_key = base64.b64decode(str(entry["public_key"]), validate=True)
            signature = base64.b64decode(str(entry["signature"]), validate=True)
        except (ValueError, binascii.Error):
            findings.append(f"root_signatures[{index}]: undecodable key or signature")
            continue
        if fingerprint not in pinned_fingerprints:
            findings.append(
                f"root_signatures[{index}] ({fingerprint}) is not among the auditor's "
                "pinned root_signer_fingerprints — trust comes from the pin, not the entry"
            )
            continue
        if ed25519_fingerprint(public_key) != fingerprint:
            findings.append(
                f"root_signatures[{index}] carries a public_key whose fingerprint is not "
                f"the declared {fingerprint} (§4.4 criterion 4: invalid, not merely reported)"
            )
            continue
        if not Ed25519Scheme().verify(signing_input, signature, digest, public_key):
            findings.append(
                f"root_signatures[{index}] ({fingerprint}) does not verify over the "
                "statement signing input"
            )
            continue
        verified.add(fingerprint)
    threshold = min_root_signatures if min_root_signatures is not None else 1
    if len(verified) < threshold:
        findings.append(
            f"root_signatures reached {len(verified)} verified pinned signer(s), below the "
            f"required threshold of {threshold} (min_root_signatures)"
        )
    return len(verified), findings


def _build_referents(
    events: Sequence[Event],
    scope_kind: str,
) -> BundleReferents:
    """The presented material: the bundle's own events, and nothing else.

    A previous cut accepted a caller-supplied ``presented_trust_log`` of trust-domain
    lifecycle referents, indexed by the hash an acceptance names, and let
    ``verify_event_strict`` resolve a key's ``trust_event_hash`` against it. That was the F1
    defect both reviewers caught: those referents were **never signature-verified or
    chain-checked** — ``_resolve_v6_trust_root`` cross-checks their payload *fields*, not
    their signatures or ancestry — so ``event_authentication: full`` and
    ``event_trust_root: externally_pinned`` could rest on blindly-trusted caller material.
    That is the exact false-external-authentication class this phase exists to remove, so the
    parameter is gone.

    Authenticating a project key's chain to a policy-pinned ROOT requires the trust log
    (worker → project acceptance → project genesis bootstrap → trust-log enrolment → root),
    and every trust-log verifier — ``verify_trust_log_chain``, ``resolve_enrolled_key`` — is
    store-backed: there is no offline, signature-verified trust-log artifact yet (that is
    WI-337). So a self-contained project bundle's events resolve to ``bundled_only`` here, the
    honest weaker state, and ``externally_authenticated`` is WI-337-blocked for such a bundle.
    """

    indexed: dict[str, ReferentEvent] = {}
    for event in events:
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
        event_count=len(events),
        action_credentials={},
        credential_material_completeness=MaterialCompleteness.UNDECLARED,
    )


def _malformed_report(message: str) -> BundleReport:
    """A1 = malformed; every other axis not_checkable. Nothing parsed, nothing to check."""

    return BundleReport(
        structure=BundleStructure.MALFORMED,
        membership_signature=MembershipSignature.ABSENT,
        membership_consistency=MembershipConsistency.NOT_CHECKABLE,
        event_authentication=EventAuthentication.NOT_CHECKABLE,
        event_trust_root=EventTrustRootAxis.NOT_CHECKABLE,
        scope_corroboration=ScopeCorroboration.NOT_CHECKABLE,
        registry_chain_consistency=RegistryChainConsistency.NOT_APPLICABLE,
        governance=Governance.NOT_CHECKABLE,
        event_verification_ran=False,
        identity_conflict_count=0,
        identity_conflicts=(),
        event_attribution_counts={},
        key_binding_counts={},
        applicability=BundleApplicability.INVALID,
        tail_truncation_undetectable=False,
        policy_satisfied=None,
        event_count=0,
        findings=(message,),
    )


def verify_audit_bundle_v3(
    bundle_path: str | Path,
    trust: TrustPolicy | AcceptBundledKeys,
    *,
    known_head: tuple[str, int] | None = None,
) -> BundleReport:
    """Verify a bundle v3 artifact against auditor-supplied trust material (§4.1, §5, §10).

    ``trust`` is REQUIRED and has no default and admits no ``None``: §4.1's structural fix is
    that trust material is un-forgettable because it is un-omittable. A caller with nothing
    must choose :class:`TrustPolicy` (external) or :class:`AcceptBundledKeys` (bundle-rooted,
    clamped) and live with the ceiling that choice imposes (§5.2). There is no third state.

    ``known_head`` is the ``(head_event_hash, event_count)`` the auditor pinned from a channel
    the operator does not solely control (§10); it drives A7 and Rule H.

    **externally_authenticated is WI-337-blocked for a project bundle.** Reaching it requires
    every event key to be authenticated by a signature chain to a policy-pinned root, and that
    chain crosses into the trust log, whose only verifiers are store-backed (§8.4 forbids the
    offline verifier from fetching, and there is no offline signature-verified trust-log
    artifact yet — WI-337). So a self-contained project bundle verified here reports
    ``bundle_rooted``/``unauthenticated`` honestly; it does not, and must not, reach
    ``externally_authenticated`` off bundle-only material. See the Phase-C status note in
    BUNDLE-V3.md.
    """

    if not isinstance(trust, TrustPolicy | AcceptBundledKeys):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "verify_audit_bundle_v3 requires a TrustPolicy or an AcceptBundledKeys as its "
            "second argument (BUNDLE-V3.md §4.1): there is no default and no None, because "
            "'every remember-to-pass-the-trust-file discipline fails eventually'",
        )

    path = Path(bundle_path)
    if not path.is_file():
        raise RegistaError(ErrorCode.INVALID_ARGUMENT, f"Bundle file not found: {bundle_path}")
    raw = path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file too large ({len(raw)} bytes, max {MAX_BUNDLE_BYTES})",
        )

    try:
        document = parse_bundle_v3_document(raw)
    except RegistaError as exc:
        # A1 = malformed: a v1/v2 artifact, a forbidden member, a broken shape. Every other
        # axis is not_checkable, because nothing parsed to check.
        return _malformed_report(f"{exc.code.value}: {exc.message}")

    return _assess_bundle_v3(document, trust, known_head=known_head)


def _assess_bundle_v3(
    document: BundleV3Document,
    trust: TrustPolicy | AcceptBundledKeys,
    *,
    known_head: tuple[str, int] | None,
) -> BundleReport:
    statement = document.statement
    scope = document.scope
    accept_bundled = isinstance(trust, AcceptBundledKeys)
    policy = trust if isinstance(trust, TrustPolicy) else None
    pinned_fingerprints = policy.pinned_fingerprints if policy is not None else frozenset()

    findings: list[str] = []
    notes: list[str] = []

    evidence_material, evidence_principals = _bundled_evidence_material(
        document.sections["bundled_key_evidence"]
    )

    # --- statement signature material -----------------------------------------------------
    # The signer's key BYTES come from the evidence (transport); the core checks them against
    # the signed fingerprint. Trust in that key is a §4 decision made below, never here.
    signer = statement.get("signer")
    has_named_signer = isinstance(signer, Mapping)
    signer_public_key: bytes | None = None
    if has_named_signer:
        assert isinstance(signer, Mapping)
        signer_public_key = evidence_material.get(str(signer["key_id"]))

    core = verify_bundle_v3_core(document, statement_public_key=signer_public_key)
    findings.extend(core.findings)
    notes.extend(core.notes)

    # --- chain-ordered members (for A4/A5/A8, and the genesis root cross-check) ------------
    members: list[OrderedMember] = []
    if core.chain_ordered:
        from ._bundle_v3 import derive_chain_order

        members = derive_chain_order(
            [
                parse_event_member(
                    base64.b64decode(record["canonical_envelope"], validate=True),
                    base64.b64decode(record["signature"], validate=True),
                )
                for record in document.events
            ],
            preceding_event_hash=scope["preceding_event_hash"],
        )
        # The signed trust_root MUST agree with the bundle's own genesis event where it is in
        # scope: a statement that restates its own genesis incorrectly is contradicted by the
        # bundle it describes. Phase B reported this only as a finding; Phase C makes it a hard
        # invalid (F2), independent of any policy.
        genesis_contradiction = _check_trust_root_against_genesis(document, members)
        findings.extend(genesis_contradiction)
        trust_root_contradicts_genesis = bool(genesis_contradiction)
    else:
        trust_root_contradicts_genesis = False

    # --- A1 structure ---------------------------------------------------------------------
    structure = BundleStructure.PARSED

    # --- A3 membership_consistency --------------------------------------------------------
    if not core.chain_ordered:
        membership_consistency = MembershipConsistency.MISMATCH
    elif (
        core.membership_root_ok is True
        and core.section_digests_ok is True
        and core.reference_sections_ok is True
        and core.scope_consistent is True
    ):
        membership_consistency = MembershipConsistency.COMPLETE_FOR_CLAIMED_SCOPE
    else:
        membership_consistency = MembershipConsistency.MISMATCH

    # --- Per-event authentication (A4/A5/A10/A11/A12) -------------------------------------
    events = [_event_from_member(m) for m in members]
    resolver: Any
    if policy is not None:
        resolver = PolicyKeyResolver(
            material_by_key_id=evidence_material,
            principal_by_key_id=evidence_principals,
            pinned_fingerprints=pinned_fingerprints,
        )
    else:
        # AcceptBundledKeys: every key is BUNDLE_EMBEDDED, so Rule C clamps unconditionally.
        resolver = BundledKeyEvidenceResolver(
            {
                key_id: {
                    "public_key": material,
                    "scheme": "ed25519",
                    "principal_id": evidence_principals.get(key_id),
                }
                for key_id, material in evidence_material.items()
            }
        )

    event_policy = _event_verification_policy(document, policy, members)
    referents = _build_referents(events, str(scope["kind"]))

    per_event_applicability: list[Applicability] = []
    per_event_trust_axis: list[EventTrustRootAxis] = []
    attribution_counts: dict[str, int] = {}
    key_binding_counts: dict[str, int] = {}
    identity_conflicts: list[str] = []
    any_bundle_embedded_used = False

    for event, member in zip(events, members, strict=True):
        result = verify_event_strict(
            EventRow.from_event(event, backend=Backend.BUNDLE),
            keys=resolver,
            referents=referents,
            policy=event_policy,
        )
        per_event_applicability.append(result.applicability)
        axis = _TRUSTED_KEY_SOURCE_TO_AXIS.get(
            result.trusted_key_source, EventTrustRootAxis.ABSENT
        )
        per_event_trust_axis.append(axis)
        if result.trusted_key_source is TrustedKeySource.BUNDLE_EMBEDDED:
            any_bundle_embedded_used = True
        attribution_counts[result.attribution.value] = (
            attribution_counts.get(result.attribution.value, 0) + 1
        )
        key_binding_counts[result.key_binding.value] = (
            key_binding_counts.get(result.key_binding.value, 0) + 1
        )
        if result.identity_consistency.value != "consistent":
            identity_conflicts.append(
                f"{member.event_hash_text}: {result.identity_consistency.value}"
            )

    # --- A4 event_authentication ----------------------------------------------------------
    if not core.chain_ordered:
        event_authentication = EventAuthentication.NOT_CHECKABLE
    elif any(a is Applicability.INVALID for a in per_event_applicability):
        event_authentication = EventAuthentication.INVALID
    elif per_event_applicability and all(
        a is Applicability.FULLY_AUTHENTICATED for a in per_event_applicability
    ):
        event_authentication = EventAuthentication.FULL
    elif not any(a is Applicability.FULLY_AUTHENTICATED for a in per_event_applicability) and (
        not any(a is Applicability.LEGACY_PARTIAL for a in per_event_applicability)
    ):
        event_authentication = EventAuthentication.NONE_VERIFIABLE
    else:
        # Some authenticated, some not (an unpinned genesis bootstrap is the canonical case),
        # or a legacy_partial event. Partial authentication — never reported as `full`.
        event_authentication = EventAuthentication.LEGACY_PARTIAL

    # --- A5 event_trust_root (the WEAKEST source any event's key came from) ----------------
    if not core.chain_ordered or not per_event_trust_axis:
        event_trust_root = EventTrustRootAxis.NOT_CHECKABLE
    else:
        event_trust_root = min(
            per_event_trust_axis, key=lambda ax: _TRUST_ROOT_RANK[ax]
        )

    # --- A2 membership_signature ----------------------------------------------------------
    membership_signature = _membership_signature_axis(
        statement=statement,
        core=core,
        accept_bundled=accept_bundled,
        policy=policy,
        pinned_fingerprints=pinned_fingerprints,
        signer_public_key=signer_public_key,
        scope_kind=str(scope["kind"]),
        findings=findings,
    )

    # --- A7 scope_corroboration -----------------------------------------------------------
    scope_corroboration = _scope_corroboration_axis(
        scope=scope,
        statement=statement,
        known_head=known_head,
        policy=policy,
        findings=findings,
    )

    # --- A8 registry_chain_consistency ----------------------------------------------------
    registry_chain_consistency = _registry_chain_consistency_axis(
        document, members, str(scope["kind"]), findings, notes
    )

    # --- A9 governance --------------------------------------------------------------------
    governance = _governance_axis(statement, policy, findings)

    # --- F2 policy conformance: every named full-policy requirement is EVALUATED, and a
    #     contradiction of any of them (or of the bundle's own signed genesis) is a hard
    #     `invalid`, not a finding a caller might skim past (a name must not promise more than
    #     the check — WI-272). An ad-hoc fingerprint policy carries none of these fields, so it
    #     evaluates none of them.
    policy_conformant = _policy_conformance(document, policy, findings)

    # --- summary + clamps (§5.2) ----------------------------------------------------------
    applicability, tail_flag = _summarize(
        membership_signature=membership_signature,
        membership_consistency=membership_consistency,
        event_authentication=event_authentication,
        event_trust_root=event_trust_root,
        scope_corroboration=scope_corroboration,
        governance=governance,
        accept_bundled=accept_bundled,
        any_bundle_embedded_used=any_bundle_embedded_used,
        scope_kind=str(scope["kind"]),
        policy_conformant=policy_conformant,
        trust_root_contradicts_genesis=trust_root_contradicts_genesis,
    )

    policy_satisfied: bool | None = None
    if policy is not None and not policy.is_ad_hoc:
        # True ONLY after every named requirement was actually checked and met (F2): the full
        # policy conformance held, the verdict is externally authenticated, and no axis
        # contradicts. Because externally_authenticated is WI-337-blocked for a project bundle,
        # this is honestly False today for such a bundle — it never claims a satisfaction the
        # checks did not establish.
        policy_satisfied = (
            policy_conformant
            and applicability is BundleApplicability.EXTERNALLY_AUTHENTICATED
            and governance is not Governance.CONTRADICTS_POLICY
            and scope_corroboration is not ScopeCorroboration.CONTRADICTS_PINNED_HEAD
        )

    return BundleReport(
        structure=structure,
        membership_signature=membership_signature,
        membership_consistency=membership_consistency,
        event_authentication=event_authentication,
        event_trust_root=event_trust_root,
        scope_corroboration=scope_corroboration,
        registry_chain_consistency=registry_chain_consistency,
        governance=governance,
        event_verification_ran=bool(members),
        identity_conflict_count=len(identity_conflicts),
        identity_conflicts=tuple(identity_conflicts),
        event_attribution_counts=attribution_counts,
        key_binding_counts=key_binding_counts,
        applicability=applicability,
        tail_truncation_undetectable=tail_flag,
        policy_satisfied=policy_satisfied,
        event_count=core.event_count,
        findings=tuple(findings),
        notes=tuple(notes),
    )


def _policy_conformance(
    document: BundleV3Document,
    policy: TrustPolicy | None,
    findings: list[str],
) -> bool:
    """F2 — evaluate every named full-policy requirement; any contradiction → not conformant.

    Returns ``True`` when there is nothing to check (no policy, or the ad-hoc fingerprint form
    which carries none of these fields) OR when every named requirement is present and matches.
    A ``False`` here is fed to :func:`_summarize` as a hard ``invalid``: a bundle whose trust
    domain, genesis digest, accepted-project set or signed genesis contradicts the auditor's
    pinned policy is not "unauthenticated", it is a bundle the auditor's own policy rejects.
    """

    if policy is None or policy.is_ad_hoc:
        return True

    statement = document.statement
    trust_root = statement.get("trust_root")
    trust_root = trust_root if isinstance(trust_root, Mapping) else {}
    ok = True

    if policy.trust_domain_id is not None and (
        str(statement.get("trust_domain_id")) != policy.trust_domain_id
    ):
        findings.append(
            f"policy_conformance: the bundle binds trust_domain_id "
            f"{statement.get('trust_domain_id')!r} but the policy pins "
            f"{policy.trust_domain_id!r} (§4.6)"
        )
        ok = False
    if policy.trust_domain_core_digest is not None and (
        str(trust_root.get("trust_domain_core_digest")) != policy.trust_domain_core_digest
    ):
        findings.append(
            "policy_conformance: the bundle's trust_root.trust_domain_core_digest "
            f"{trust_root.get('trust_domain_core_digest')!r} does not match the policy's "
            f"pinned {policy.trust_domain_core_digest!r} (§4.6)"
        )
        ok = False
    if policy.genesis_document_digest is not None and (
        str(trust_root.get("genesis_document_digest")) != policy.genesis_document_digest
    ):
        findings.append(
            "policy_conformance: the bundle's trust_root.genesis_document_digest "
            f"{trust_root.get('genesis_document_digest')!r} does not match the policy's "
            f"pinned {policy.genesis_document_digest!r} (§4.6)"
        )
        ok = False
    if policy.accepted_project_instance_ids is not None and (
        str(statement.get("project_instance_id")) not in policy.accepted_project_instance_ids
    ):
        findings.append(
            f"policy_conformance: the bundle project {statement.get('project_instance_id')!r} "
            "is not among the policy's accepted_project_instance_ids — the auditor's policy "
            "does not cover this project (§4.6). An excluded project is a rejection, not a "
            "silently disabled check"
        )
        ok = False
    return ok


def _event_verification_policy(
    document: BundleV3Document,
    policy: TrustPolicy | None,
    members: Sequence[OrderedMember],
) -> VerificationPolicy:
    """The per-event pins threaded into ``verify_event_strict`` (reuse, not reimplementation).

    Under a :class:`TrustPolicy` the domain and project pins come straight from it, and the
    cutover-checkpoint pin is the recomputed genesis hash (the clean epoch's bootstrap
    checkpoint) — the Merkle-committed first event, not an attacker-writable field. Under
    ``AcceptBundledKeys`` nothing is pinned, so every per-event trust decision reports its
    unbound state (§10.2 invariant 9).
    """

    if policy is None:
        return DEFAULT_POLICY
    statement = document.statement
    project_instance_id = str(statement["project_instance_id"])
    pinned_project = (
        project_instance_id
        if (
            policy.accepted_project_instance_ids is None
            or project_instance_id in policy.accepted_project_instance_ids
        )
        else None
    )
    cutover = (
        members[0].event_hash_text
        if members and str(document.scope["kind"]) == "complete-store"
        else None
    )
    return VerificationPolicy(
        pinned_trust_domain_id=policy.trust_domain_id,
        pinned_project_instance_id=pinned_project,
        cutover_checkpoint_event_hash=cutover,
    )


def _membership_signature_axis(
    *,
    statement: Mapping[str, Any],
    core: BundleV3CoreReport,
    accept_bundled: bool,
    policy: TrustPolicy | None,
    pinned_fingerprints: frozenset[str],
    signer_public_key: bytes | None,
    scope_kind: str,
    findings: list[str],
) -> MembershipSignature:
    """A2 — the statement signature, and against whose key (§5.1, §3.4, O3).

    §3.4 makes ``may_sign_bundles`` MANDATORY: a signature is a valid *membership* signature
    only if the signer was authorised to sign bundles. So a cryptographically valid signature
    from a signer the policy forbids, or whose in-scope acceptance does not grant the scope, is
    ``invalid`` — NOT a ``valid_bundled_key`` success (F3). "Valid" must never promise more
    than the authority check performed (WI-272).
    """

    root_signatures = statement.get("root_signatures")
    if isinstance(root_signatures, list):
        # Direct root-threshold statement (§3.2 item 2), verified now that the pin is held.
        if policy is None:
            findings.append(
                "root_signatures present but no TrustPolicy supplied: a direct "
                "root-threshold statement can only be authenticated against the auditor's "
                "pinned root signer set (AcceptBundledKeys cannot check it)"
            )
            return MembershipSignature.ABSENT
        verified_count, root_findings = _verify_root_signatures(
            statement,
            root_signatures,
            pinned_fingerprints=pinned_fingerprints,
            min_root_signatures=policy.min_root_signatures,
        )
        findings.extend(root_findings)
        threshold = policy.min_root_signatures if policy.min_root_signatures is not None else 1
        if verified_count >= threshold and not root_findings:
            return MembershipSignature.VALID_EXTERNAL_ROOT
        return MembershipSignature.INVALID

    # Single named signer (the common case).
    if signer_public_key is None:
        # No key material for the signer reached the verifier — the signature was not checked.
        return MembershipSignature.ABSENT
    if not core.statement_signature_valid:
        return MembershipSignature.INVALID

    assert isinstance(statement.get("signer"), Mapping)
    signer = statement["signer"]

    # F3 — policy bundle-signing authority. A signer the policy does not permit is a signature
    # from a forbidden authority: invalid, not a pass, under either trust form.
    if policy is not None and policy.bundle_signing is not None:
        permitted_principals = policy.bundle_signing.get("permitted_principal_ids")
        permitted_schemes = policy.bundle_signing.get("permitted_schemes")
        if (
            isinstance(permitted_principals, Sequence)
            and not isinstance(permitted_principals, str | bytes)
            and str(signer["principal_id"]) not in permitted_principals
        ):
            findings.append(
                f"membership_signature: the statement signer {signer['principal_id']!r} is "
                "not among the policy's bundle_signing.permitted_principal_ids — a valid "
                "signature from a signer the policy forbids is not a valid membership "
                "signature (§3.4). Invalid, not merely reported"
            )
            return MembershipSignature.INVALID
        if (
            isinstance(permitted_schemes, Sequence)
            and not isinstance(permitted_schemes, str | bytes)
            and str(signer["scheme_id"]) not in permitted_schemes
        ):
            findings.append(
                f"membership_signature: the statement signer's scheme {signer['scheme_id']!r} "
                "is not permitted by the policy's bundle_signing.permitted_schemes (§3.4)"
            )
            return MembershipSignature.INVALID

    # F3 — O3 may_sign_bundles authority, re-derived by the core from the signed acceptance.
    # An in-scope acceptance that does NOT grant may_sign_bundles (checked and false), or a
    # complete-store bundle that must contain the authority but does not (a finding), is an
    # authority FAILURE → invalid. A `contiguous-range` whose authority event lies legitimately
    # OUTSIDE the window (a note, not a finding) is not a failure — it simply cannot be shown
    # external, so it caps at `valid_bundled_key` (→ unauthenticated), never invalid (F4-safe).
    authority_established = core.signer_authority_checked and core.signer_may_sign_bundles
    if not authority_established:
        if core.signer_authority_checked and not core.signer_may_sign_bundles:
            return MembershipSignature.INVALID  # in-scope anchor exists but lacks the scope
        if scope_kind == "complete-store":
            # A complete-store bundle MUST contain the authority; its absence or a stale/
            # wrong-anchor reference is a hard failure, not a mere scope limitation.
            return MembershipSignature.INVALID
        # contiguous-range, authority outside the window: cannot be shown external.
        return MembershipSignature.VALID_BUNDLED_KEY

    if accept_bundled:
        return MembershipSignature.VALID_BUNDLED_KEY
    # Authority established. External iff the signer's fingerprint is a pinned root (base case
    # of chain-to-root; the chain extension for a non-root signer is WI-337-blocked).
    if str(signer["fingerprint"]) in pinned_fingerprints:
        return MembershipSignature.VALID_EXTERNAL_ROOT
    return MembershipSignature.VALID_BUNDLED_KEY


def _scope_corroboration_axis(
    *,
    scope: Mapping[str, Any],
    statement: Mapping[str, Any],
    known_head: tuple[str, int] | None,
    policy: TrustPolicy | None,
    findings: list[str],
) -> ScopeCorroboration:
    """A7 — an independently pinned head against the signed scope (§5.1, §3.5)."""

    head = known_head
    if head is None and policy is not None:
        project_instance_id = str(statement["project_instance_id"])
        checkpoint = policy.known_project_checkpoints.get(project_instance_id)
        if isinstance(checkpoint, Mapping):
            head_hash = checkpoint.get("head_event_hash")
            count = checkpoint.get("event_count")
            if isinstance(head_hash, str) and isinstance(count, int):
                head = (head_hash, count)
    if head is None:
        return ScopeCorroboration.NO_PIN_SUPPLIED
    head_hash, head_count = head
    if head_hash == str(scope["last_event_hash"]) and head_count == int(scope["event_count"]):
        return ScopeCorroboration.MATCHES_PINNED_HEAD
    # F4 — a whole-project head pin corroborates only a WHOLE-project (complete-store) claim.
    # A bounded `contiguous-range` is a subset by construction, so a project head that does not
    # equal the range's own last event is EXPECTED, not a contradiction: it simply does not
    # corroborate the range (no range-specific pin/ancestry proof is defined). Reporting it as
    # `contradicts_pinned_head` would falsely invalidate every valid range bundle.
    if str(scope["kind"]) != "complete-store":
        return ScopeCorroboration.NO_PIN_SUPPLIED
    findings.append(
        f"scope_corroboration: the pinned head ({head_hash}, {head_count} events) "
        f"contradicts the signed complete-store scope (last_event_hash="
        f"{scope['last_event_hash']}, event_count={scope['event_count']})"
    )
    return ScopeCorroboration.CONTRADICTS_PINNED_HEAD


def _registry_chain_consistency_axis(
    document: BundleV3Document,
    members: Sequence[OrderedMember],
    scope_kind: str,
    findings: list[str],
    notes: list[str],
) -> RegistryChainConsistency:
    """A8 — bundled key evidence corroborated against the signed acceptances (§4.3).

    A **disagreement** — a bundled key whose fingerprint or public_key (or principal_id, G3)
    contradicts the signed acceptance that names the same key_id — is ``inconsistent``. A
    bundled key with NO in-scope acceptance is treated differently by scope (F4): for a
    ``complete-store`` bundle, which must contain every dependency, a missing acceptance is
    ``inconsistent``; for a bounded ``contiguous-range``, whose acceptance may legitimately lie
    outside the window, it is reported as an outside-scope *note* — Phase B's "never silently
    valid" third state — not a false ``inconsistent``.
    """

    presented = document.sections["bundled_key_evidence"]
    if not presented:
        return RegistryChainConsistency.NOT_APPLICABLE
    if not members:
        # No ordered events to corroborate against — the structural failure is reported by A3;
        # this axis cannot corroborate, so it says so rather than claiming consistency.
        return RegistryChainConsistency.NOT_APPLICABLE
    recomputed = {rec["key_id"]: rec for rec in _key_evidence_section(members)}
    inconsistent = False
    corroborated_any = False
    for record in presented:
        key_id = record.get("key_id")
        signed = recomputed.get(key_id)
        if signed is None:
            if scope_kind == "complete-store":
                findings.append(
                    f"registry_chain_consistency: bundled_key_evidence names key {key_id!r} "
                    "with no matching signed acceptance/enrolment event inside a complete-store "
                    "bundle, which must contain it (§4.3)"
                )
                inconsistent = True
            else:
                notes.append(
                    f"registry_chain_consistency: bundled_key_evidence key {key_id!r} has no "
                    "acceptance inside this contiguous-range scope, so it cannot be "
                    "corroborated here — outside scope, not inconsistent (§4.3, Resolution 4)"
                )
            continue
        corroborated_any = True
        # G3 — principal_id is part of the binding: a relabelled evidence principal is a
        # disagreement with the signed acceptance, not a silent pass.
        if (
            signed.get("fingerprint") != record.get("fingerprint")
            or signed.get("public_key") != record.get("public_key")
            or signed.get("principal_id") != record.get("principal_id")
        ):
            findings.append(
                f"registry_chain_consistency: bundled_key_evidence for {key_id!r} disagrees "
                "with the principal_id/fingerprint/public_key its signed acceptance carries "
                "(§4.3: disagreement is a finding)"
            )
            inconsistent = True
    if inconsistent:
        return RegistryChainConsistency.INCONSISTENT
    if not corroborated_any:
        # Nothing in the evidence had an in-scope acceptance to check against (a bounded range
        # whose acceptances are all outside the window): not_applicable, never a bare
        # "consistent" that would overclaim a corroboration that did not happen.
        return RegistryChainConsistency.NOT_APPLICABLE
    return RegistryChainConsistency.CONSISTENT


def _governance_axis(
    statement: Mapping[str, Any],
    policy: TrustPolicy | None,
    findings: list[str],
) -> Governance:
    """A9 — the restated governance against the policy expectation (§4.5).

    The verifier holds no authenticated trust log to replay here (§10 hands it the policy and
    the head pin, not the log), so it can never confirm the restatement is TRUE — it reports
    ``unverified_restatement`` (§4.5: "A verifier that cannot replay reports … never a
    genesis-derived value"). What it CAN check without a replay is whether the operator's own
    signed restatement contradicts what the auditor requires: a solo restatement under a
    ``["co_signed"]`` policy is ``contradicts_policy``, a finding.
    """

    trust_root = statement.get("trust_root")
    if not isinstance(trust_root, Mapping):
        return Governance.NOT_CHECKABLE
    root_governance = trust_root.get("root_governance")
    restated_mode = (
        root_governance.get("mode") if isinstance(root_governance, Mapping) else None
    )
    if policy is None or policy.is_ad_hoc:
        # No governance expectation supplied — the restatement is present but unconfirmed.
        return Governance.UNVERIFIED_RESTATEMENT
    if restated_mode is not None and restated_mode not in policy.required_root_governance:
        findings.append(
            f"governance: the bundle restates root governance mode {restated_mode!r}, which "
            f"is not among the policy's required_root_governance "
            f"{sorted(policy.required_root_governance)} (§4.5)"
        )
        return Governance.CONTRADICTS_POLICY
    # The restatement is consistent with the requirement, but was NOT confirmed against a
    # replayed, authenticated trust log — so it is a restatement, not a checked match.
    return Governance.UNVERIFIED_RESTATEMENT


def _summarize(
    *,
    membership_signature: MembershipSignature,
    membership_consistency: MembershipConsistency,
    event_authentication: EventAuthentication,
    event_trust_root: EventTrustRootAxis,
    scope_corroboration: ScopeCorroboration,
    governance: Governance,
    accept_bundled: bool,
    any_bundle_embedded_used: bool,
    scope_kind: str,
    policy_conformant: bool,
    trust_root_contradicts_genesis: bool,
) -> tuple[BundleApplicability, bool]:
    """The §5.2 summary: a base verdict from A2 + A4, then the live Rule C ceiling and Rule H.

    Structure is handled by the caller (a malformed bundle never reaches here). The base
    deliberately does NOT gate on A5: the trust-root requirement of ``externally_authenticated``
    is enforced by **Rule C**, so Rule C is the sole trust-source ceiling and is demonstrably
    load-bearing (G2) — remove it and a root-signed statement over bundle-keyed events reads as
    ``externally_authenticated``, the F1 false assurance.
    """

    invalid = (
        membership_signature is MembershipSignature.INVALID
        or membership_consistency is MembershipConsistency.MISMATCH
        or event_authentication is EventAuthentication.INVALID
        or governance is Governance.CONTRADICTS_POLICY
        or scope_corroboration is ScopeCorroboration.CONTRADICTS_PINNED_HEAD
        # F2: a full policy the bundle contradicts, or a trust_root that disagrees with the
        # bundle's own signed genesis, is a rejection — not merely a finding.
        or not policy_conformant
        or trust_root_contradicts_genesis
    )
    if invalid:
        return BundleApplicability.INVALID, _rule_h(scope_kind, scope_corroboration)

    # Base — from A2 (statement authority) and A4 (event authentication). A5 is NOT gated here.
    if (
        membership_signature is MembershipSignature.VALID_EXTERNAL_ROOT
        and event_authentication is EventAuthentication.FULL
    ):
        applicability = BundleApplicability.EXTERNALLY_AUTHENTICATED
    elif accept_bundled and membership_signature is MembershipSignature.VALID_BUNDLED_KEY:
        applicability = BundleApplicability.BUNDLE_ROOTED
    elif event_trust_root is EventTrustRootAxis.BUNDLED_ONLY:
        # G1 — §5.2: "…and/or A5 = bundled_only" → bundle_rooted, reachable under a TrustPolicy
        # too, not only under an explicit AcceptBundledKeys.
        applicability = BundleApplicability.BUNDLE_ROOTED
    else:
        applicability = BundleApplicability.UNAUTHENTICATED

    # A cap for the honest "nothing external authenticated the statement" state (§5.2
    # unauthenticated row): A2 absent, or a valid bundled key without explicit acceptance.
    if membership_signature is MembershipSignature.ABSENT or (
        membership_signature is MembershipSignature.VALID_BUNDLED_KEY and not accept_bundled
    ):
        applicability = _min_verdict(applicability, BundleApplicability.UNAUTHENTICATED)

    # Rule C (circularity ceiling, §5.2) — THE trust-source ceiling, and load-bearing because
    # the base above did not gate on A5. ``externally_authenticated`` is reachable ONLY when
    # every event's key is externally pinned to the auditor's root (A5 externally_pinned) AND no
    # bundle-embedded key was used. Either shortfall caps the verdict at ``bundle_rooted``.
    # (The two conditions coincide by construction — a bundle-embedded key caps A5 below
    # externally_pinned — but both are named so the ceiling is explicit.)
    if any_bundle_embedded_used or event_trust_root is not EventTrustRootAxis.EXTERNALLY_PINNED:
        applicability = _min_verdict(applicability, BundleApplicability.BUNDLE_ROOTED)

    return applicability, _rule_h(scope_kind, scope_corroboration)


def _min_verdict(a: BundleApplicability, b: BundleApplicability) -> BundleApplicability:
    """The weaker (lower-rank) of two verdicts — a ceiling never raises a floor."""

    return a if _APPLICABILITY_RANK[a] <= _APPLICABILITY_RANK[b] else b


def _rule_h(scope_kind: str, scope_corroboration: ScopeCorroboration) -> bool:
    """Rule H — complete-store with no pinned head sets ``tail_truncation_undetectable`` and
    does NOT clamp, so the auditor's pin date bounds the claim (§5.2, residual 6)."""

    return (
        scope_kind == "complete-store"
        and scope_corroboration is ScopeCorroboration.NO_PIN_SUPPLIED
    )


__all__ = [
    "MAX_BUNDLE_BYTES",
    "AcceptBundledKeys",
    "BundleApplicability",
    "BundleReport",
    "BundleStructure",
    "BundleVerificationReport",
    "EventAuthentication",
    "EventTrustRootAxis",
    "Governance",
    "MembershipConsistency",
    "MembershipSignature",
    "PolicyKeyResolver",
    "RegistryChainConsistency",
    "ScopeCorroboration",
    "TrustPolicy",
    "export_audit_bundle",
    "verify_audit_bundle_offline",
    "verify_audit_bundle_v3",
    "verify_bundle_v3_report",
]
