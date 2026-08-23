"""Bundle v3 core — the signed statement, its membership tree, and their verification.

``BUNDLE-V3.md`` is the frozen contract; this module is §2, §3 and §6 of it. It is
deliberately the whole of what those sections specify and **nothing** of §4 or §5.

What is here (WI-289 Phase B, "verification-complete bundle v3 core"):

* §2/§6 — the format decision and the anti-downgrade refusal. :data:`SUPPORTED_FORMAT_VERSIONS`
  is ``{3}``; a document declaring 1 or 2 is refused by name, never read as v3.
* §3.1 — the document shape, with a closed top-level key set and an advisory ``index``
  that no code path in this module reads.
* §3.2 as amended — the statement schema: ``trust_root`` (not ``governance``), one
  ``signer`` shape, a closed section set, ``complete-store``/``contiguous-range`` only, and
  **no** ``epoch`` block (decision E2, forbidden rather than merely unemitted).
* §3.3 — the RFC 6962 membership tree over chain-derived ordinals.
* §3.4 — the ed25519 statement signature over ``b"regista.audit-bundle.v3\\x00" || JCS(statement)``.
* §3.6/§3.7 — base64 event records and the domain-separated section digests.

**What is NOT here, and where it goes.** This module resolves no trust and reaches no
verdict. Those are the two seams it exists to present:

``Phase C (§4 trust-root resolution, §5 verdict lattice)``
    consumes :func:`verify_bundle_v3_core`. Everything C needs is either a field of
    :class:`BundleV3CoreReport` or a primitive it can call directly
    (:func:`membership_root`, :func:`section_digest`, :func:`statement_signing_input`,
    :func:`verify_statement_signature`). The one input C must supply is
    ``statement_public_key`` — the bytes of the key the *auditor's policy* pins. This
    module never resolves that key, and in particular never reads it out of
    ``sections.bundled_key_evidence``: a key harvested from the artifact it authenticates
    is §5.2 rule C's clamp, and a core that quietly did the harvesting would make the
    clamp unreachable. With no key supplied the report says
    ``statement_signature_checked=False`` and ``core_ok`` is False — "not checked" is
    never "checked out".

``Phase D (§9 export contract discipline)``
    consumes :func:`build_bundle_v3_document`. D owns the ceremony around it — ``.partial``
    write then self-verify then ``os.replace``, preflight comparison, the dependency-closure
    walk, exit codes and the CLI flags. This module owns only the document: given ordered
    event bytes, a trust root, a signer and its private key, it produces the exact bytes
    §3 specifies, or it refuses.

``Phase E (§9 rule 6 credential transport)``
    is deferred post-cutover by owner ruling O1. There is no
    ``action_delegation_credentials`` section here, and :data:`SECTION_NAMES` is closed, so
    a bundle carrying one is refused rather than silently accepted with an unread section.

Two owner rulings from the 2026-08-23 amendment are enforced here rather than documented:

O3
    The statement signer MAY be the project writer key **provided that key bears
    ``may_sign_bundles``**. :func:`build_bundle_v3_document` takes the resolved scope as a
    required flag on :class:`BundleV3Signer` and refuses to sign without it, and
    :func:`verify_bundle_v3_core` re-derives it from the signer's own authority event when
    that event is inside the bundle (which a ``complete-store`` bundle guarantees).

O4
    A broken chain means no bundle. :func:`derive_chain_order` refuses — one named error,
    no diagnostic flag, no partial document. §12 L2's ``--diagnostic`` escape hatch is
    explicitly not built.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._signing import compute_v6_event_hash

# ---------------------------------------------------------------------------
# §2 / §6 — the format decision
# ---------------------------------------------------------------------------

#: ``BUNDLE-V3.md`` §2: "``format_version`` **1 is deleted, and so is 2.** Bundle v3 is the
#: only accepted format." The set is a frozenset of one rather than an ``== 3`` comparison
#: so that widening it is a visible, greppable diff rather than a changed operator.
SUPPORTED_FORMAT_VERSIONS: Final[frozenset[int]] = frozenset({3})

#: The version a fresh export declares. Equal to the sole supported version by
#: construction, and asserted as such in the tests: an exporter that writes a version its
#: own verifier rejects is the WI-240 defect class.
BUNDLE_V3_FORMAT_VERSION: Final[int] = 3

BUNDLE_V3_STATEMENT_TYPE: Final[str] = "regista.audit-bundle"
BUNDLE_V3_STATEMENT_SCHEMA: Final[str] = "regista.audit-bundle/3"

# ---------------------------------------------------------------------------
# Domain tags. Every one of these is frozen; none is derived from a constant
# elsewhere in the tree, because a shared constant is how two documents end up
# agreeing by accident and disagreeing after a rename.
# ---------------------------------------------------------------------------

#: §3.4 — the statement signature input prefix. Mandatory: it is what stops a v3
#: statement being replayed as some other JCS-signed regista object under the same key.
STATEMENT_SIGNING_DOMAIN: Final[bytes] = b"regista.audit-bundle.v3\x00"

#: §3.3 — membership leaf. Frozen by ``tests/vectors/v6/bundle-merkle-*.json``.
MEMBER_LEAF_DOMAIN: Final[bytes] = b"regista.bundle.member.v1\x00"

#: §3.3 — membership interior node. No bare ``0x01``: the tag *is* the separation.
MEMBER_NODE_DOMAIN: Final[bytes] = b"regista.bundle.node.v1\x00"

#: §3.7 — section digest. NOTE: unlike the two above, this tag has **no frozen P0.3
#: vector**; the vector set covers the leaf, node and tree only. The construction is
#: pinned by this module's own tests instead, and that difference is stated rather than
#: left for an implementer of a second verifier to discover.
SECTION_DIGEST_DOMAIN: Final[bytes] = b"regista.bundle.section.v1\x00"

# ---------------------------------------------------------------------------
# §3.1 — document shape
# ---------------------------------------------------------------------------

#: §3.1 rule 3: "Unknown top-level keys are a rejection, not an ignore."
TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {"statement", "statement_signature", "sections", "index"}
)
REQUIRED_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {"statement", "statement_signature", "sections"}
)

#: §3.1 / §3.2 amendment item 4 — the closed section set, in emission order.
SECTION_NAMES: Final[tuple[str, ...]] = (
    "events",
    "key_lifecycle",
    "project_key_acceptance",
    "workflows",
    "review_verdicts",
    "checkpoints",
    "bundled_key_evidence",
    "external_evidence",
)

#: The five sections that carry "sorted event-hash references into ``events``" rather than
#: records of their own (§3.2 amendment item 4).
REFERENCE_SECTIONS: Final[tuple[str, ...]] = (
    "key_lifecycle",
    "project_key_acceptance",
    "workflows",
    "review_verdicts",
    "checkpoints",
)

#: Which project-chain transition puts an event in which reference section.
#:
#: This map is the whole of Phase B's section classification, and it is deliberately
#: *recomputed at verify* rather than trusted from the artifact — see
#: :func:`recompute_reference_sections`. A section a verifier recomputes cannot be edited;
#: a section it merely reads is a manifest count with better manners.
#:
#: ``review_verdicts`` is keyed on the signed **payload type**, not on a transition name,
#: because ``REVIEW-VERDICTS.md`` §4.1 rule 3 is explicit that transition names are not
#: consulted at all: "a forged ``adversarial_pass`` string with no verdict payload
#: contributes nothing". Keying this section on the transition would reintroduce exactly
#: the inference that document exists to delete.
#:
#: Phase D's dependency-closure walk (§9 rule 6, ``RECONCILIATION.md`` Resolution 4) will
#: extend this map — delegation and verdict supersession are not here. Extending it is a
#: one-place diff, and until it happens a bundle whose events do not classify simply has
#: empty sections, which is a true statement rather than a silent one.
SECTION_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = {
    # Trust-log lifecycle (`_trust_log`'s vocabulary). Empty on a project bundle: a
    # project chain carries acceptances, not enrolments. Present so a bundle over the
    # trust-log project classifies without a second map.
    "key_lifecycle": frozenset(
        {
            "trust_domain_established",
            "trust_root_rotated",
            "trust_domain_custody_declared",
            "registrar_delegated",
            "registrar_revoked",
            "principal_registered",
            "principal_key_enrolled",
            "principal_key_rotated",
            "principal_key_revoked",
        }
    ),
    # TRUST-DOMAIN.md §5.8 project-local acceptance and its revocation.
    "project_key_acceptance": frozenset(
        {"principal_key_accepted", "principal_key_acceptance_revoked"}
    ),
    # V6-ENVELOPE.md §1.9 / RECONCILIATION.md Resolution 2.
    "workflows": frozenset({"workflow_registered", "workflow_retired"}),
    # The epoch-opening events. `project_cryptographic_epoch_started` is the legacy-project
    # spelling and cannot occur in a clean epoch; naming it keeps the set honest rather
    # than silently one-valued (the same reasoning as `_v6_writer._ANCHOR_TRANSITIONS`).
    "checkpoints": frozenset({"project_initialized", "project_cryptographic_epoch_started"}),
    "review_verdicts": frozenset(),
}

#: Signed payload ``type`` values that place an event in a reference section.
SECTION_PAYLOAD_TYPES: Final[Mapping[str, frozenset[str]]] = {
    "review_verdicts": frozenset({"regista.review-verdict"}),
}

# ---------------------------------------------------------------------------
# §3.2 — statement schema, as amended
# ---------------------------------------------------------------------------

#: Every statement member except the mutually exclusive signer/root_signatures pair.
STATEMENT_BASE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "version",
        "bundle_id",
        "project_instance_id",
        "trust_domain_id",
        "created_at",
        "scope",
        "event_membership_root",
        "section_digests",
        "trust_root",
        "exporter",
    }
)

#: §3.2 amendment item 2 (``RECONCILIATION.md`` collision 21): "A **direct root-threshold**
#: signature does not invent a principal id: it uses ``root_signatures[]`` and omits
#: ``signer``." Exactly one of the two is present.
STATEMENT_AUTHORITY_KEYS: Final[frozenset[str]] = frozenset({"signer", "root_signatures"})

#: Members that were specified once and are now refused by name, with the decision that
#: retired each. Refusing by name rather than as "unknown key" is the difference between a
#: diagnosis and a shrug for an operator holding a pre-decision artifact.
FORBIDDEN_STATEMENT_KEYS: Final[Mapping[str, str]] = {
    "epoch": (
        "decision E2 (BUNDLE-V3.md §3.2, EPOCH-RESET.md:69): the epoch block is dropped "
        "as vacuous — one epoch means cutover_event_hash is always null and "
        "legacy_event_count always 0 — and it is FORBIDDEN rather than merely unemitted, "
        "because a tolerated member of the SIGNED statement is attacker-chosen content "
        "under a valid signature that no verifier checks. Re-export the bundle"
    ),
    "governance": (
        "RECONCILIATION.md collision 12: replaced by the four-field trust_root block "
        "(TRUST-DOMAIN.md §3.6). The old block could not carry the core digest an auditor "
        "pins, so a verifier holding a policy had nothing to compare against"
    ),
    "selection": (
        "RECONCILIATION.md Resolution 4: the declared-selection scope kind is CUT from "
        "0.6.0 (BUNDLE-V3.md §3.5), and scope.selection went with it"
    ),
}

SCOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"kind", "event_count", "first_event_hash", "last_event_hash", "preceding_event_hash"}
)

#: §3.5 as amended: ``declared-selection`` is CUT. Two kinds, no third mode.
SCOPE_KINDS: Final[frozenset[str]] = frozenset({"complete-store", "contiguous-range"})

TRUST_ROOT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "trust_domain_id",
        "trust_domain_core_digest",
        "root_governance",
        "genesis_document_digest",
    }
)
ROOT_GOVERNANCE_KEYS: Final[frozenset[str]] = frozenset({"mode", "threshold", "signer_count"})

#: Underscored spellings — ``RECONCILIATION.md`` Resolution 4. ``single_signer_lab`` is
#: retired and ``unknown`` is a *verifier output* (§4.5), never a signed restatement: a
#: signer that cannot state its own governance has nothing to attest.
ROOT_GOVERNANCE_MODES: Final[frozenset[str]] = frozenset({"co_signed", "solo", "solo_effective"})

SIGNER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "principal_id",
        "key_id",
        "scheme_id",
        "fingerprint",
        "authority_kind",
        "authority_event_hash",
    }
)
AUTHORITY_KINDS: Final[frozenset[str]] = frozenset({"root", "registrar", "scoped"})

STATEMENT_SIGNATURE_KEYS: Final[frozenset[str]] = frozenset({"scheme_id", "key_id", "signature"})

EXPORTER_KEYS: Final[frozenset[str]] = frozenset({"regista_version", "statement_schema"})

#: §3.6: "**Nothing else.** Not ``transition``, not ``payload``, not ``actor_id``, not
#: ``global_seq``." Base64 per decision E1.
EVENT_RECORD_KEYS: Final[frozenset[str]] = frozenset({"canonical_envelope", "signature"})

#: §4.3 — "exact public-key material records". Deliberately the same five members
#: ``TRUST-DOMAIN.md`` §5.8's acceptance object repeats, so a reader comparing the section
#: against the signed acceptance it corroborates is comparing like with like.
BUNDLED_KEY_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {"key_id", "principal_id", "scheme_id", "fingerprint", "public_key"}
)

EXTERNAL_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {"class", "source", "obtained_at", "content"}
)
EXTERNAL_EVIDENCE_CLASSES: Final[frozenset[str]] = frozenset(
    {"operator_asserted", "independently_pinned_copy", "third_party_signed"}
)

#: §3.4: "Scheme MUST be ``ed25519``. There is no HMAC bundle signature — an HMAC statement
#: signature would be verifiable only by the operator, which is the S5 circularity wearing
#: a different hat."
STATEMENT_SIGNATURE_SCHEME: Final[str] = "ed25519"

_DIGEST_PREFIX: Final[str] = "sha256:"
_DIGEST_HEX_LEN: Final[int] = 64
_LOWER_HEX: Final[frozenset[str]] = frozenset("0123456789abcdef")


# ---------------------------------------------------------------------------
# Refusals. One helper per error class so every refusal carries the same
# structured detail and no call site invents its own spelling.
# ---------------------------------------------------------------------------


def _format_refusal(message: str, **detail: Any) -> RegistaError:
    return RegistaError(ErrorCode.BUNDLE_FORMAT_UNSUPPORTED, message, detail=detail or None)


def _statement_refusal(message: str, **detail: Any) -> RegistaError:
    return RegistaError(ErrorCode.BUNDLE_STATEMENT_INVALID, message, detail=detail or None)


def _chain_refusal(message: str, **detail: Any) -> RegistaError:
    return RegistaError(ErrorCode.BUNDLE_CHAIN_UNORDERABLE, message, detail=detail or None)


def _signer_refusal(message: str, **detail: Any) -> RegistaError:
    return RegistaError(ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED, message, detail=detail or None)


def _signature_refusal(message: str, **detail: Any) -> RegistaError:
    return RegistaError(
        ErrorCode.BUNDLE_STATEMENT_SIGNATURE_INVALID, message, detail=detail or None
    )


def _require_statement(condition: bool, message: str, **detail: Any) -> None:
    if not condition:
        raise _statement_refusal(message, **detail)


# ---------------------------------------------------------------------------
# Small typed readers. Every one of these fails closed: there is no
# "read it as a string if it happens to be one" path.
# ---------------------------------------------------------------------------


def is_digest_text(value: object) -> bool:
    """True for exactly ``sha256:<64 lowercase hex>``.

    Case-sensitive on purpose: two spellings of one digest are two strings, and a
    verifier that accepts both has to normalise before every comparison. One spelling
    means ``hmac.compare_digest`` on the text is a correct comparison.
    """

    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    hex_part = value[len(_DIGEST_PREFIX) :]
    return len(hex_part) == _DIGEST_HEX_LEN and all(c in _LOWER_HEX for c in hex_part)


def digest_text(raw: bytes) -> str:
    return _DIGEST_PREFIX + raw.hex()


def digest_bytes(value: str) -> bytes:
    if not is_digest_text(value):
        raise _statement_refusal(
            f"expected a sha256:<64 lowercase hex> digest, got {value!r}",
            value=value,
        )
    return bytes.fromhex(value[len(_DIGEST_PREFIX) :])


def _require_uuid_text(value: object, path: str) -> str:
    _require_statement(isinstance(value, str), f"{path} must be a string", path=path)
    assert isinstance(value, str)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise _statement_refusal(f"{path} is not a UUID: {value!r}", path=path) from exc
    _require_statement(
        str(parsed) == value,
        f"{path} must be the canonical lowercase hyphenated UUID spelling, not {value!r}",
        path=path,
    )
    return value


def _require_nonempty_text(value: object, path: str) -> str:
    _require_statement(
        isinstance(value, str) and bool(value.strip()),
        f"{path} must be a non-empty string",
        path=path,
    )
    assert isinstance(value, str)
    return value


def _require_closed_mapping(
    value: object, expected: frozenset[str], path: str
) -> Mapping[str, Any]:
    _require_statement(isinstance(value, Mapping), f"{path} must be an object", path=path)
    assert isinstance(value, Mapping)
    present = set(value)
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    _require_statement(
        not unknown,
        f"{path} carries unknown member(s) {unknown} — the object is closed "
        f"(BUNDLE-V3.md §3.1 rule 3 applied at every level, not only the top)",
        path=path,
        unknown=unknown,
    )
    _require_statement(
        not missing,
        f"{path} is missing required member(s) {missing}",
        path=path,
        missing=missing,
    )
    return value


def _require_list(value: object, path: str) -> list[Any]:
    _require_statement(isinstance(value, list), f"{path} must be an array", path=path)
    assert isinstance(value, list)
    return value


def _decode_base64(value: object, path: str) -> bytes:
    _require_statement(isinstance(value, str), f"{path} must be a base64 string", path=path)
    assert isinstance(value, str)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _statement_refusal(
            f"{path} is not strict base64 (decision E1, BUNDLE-V3.md §3.6): {exc}",
            path=path,
        ) from exc


def _encode_base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# §3.3 — the membership tree
# ---------------------------------------------------------------------------


def merkle_leaf(scope_ordinal: int, event_hash: bytes) -> bytes:
    """``SHA256(b"regista.bundle.member.v1\\x00" || uint64be(i) || event_hash)``.

    ``event_hash`` is taken as opaque bytes and its length is NOT checked, because the
    frozen vectors exercise 16-byte inputs alongside 32-byte ones
    (``tests/vectors/v6/bundle-merkle-three.json``). Length validation belongs where the
    hash is produced, not where the tree consumes it; putting it here would make this
    function disagree with the vectors that freeze it.
    """

    if scope_ordinal < 0:
        raise _statement_refusal(
            f"scope_ordinal must be non-negative, got {scope_ordinal}",
            scope_ordinal=scope_ordinal,
        )
    return hashlib.sha256(
        MEMBER_LEAF_DOMAIN + struct.pack(">Q", scope_ordinal) + event_hash
    ).digest()


def merkle_node(left: bytes, right: bytes) -> bytes:
    """``SHA256(b"regista.bundle.node.v1\\x00" || left || right)``."""

    return hashlib.sha256(MEMBER_NODE_DOMAIN + left + right).digest()


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 Merkle tree head over already-domain-tagged leaves.

    ``MTH({}) = SHA256()`` — the empty root is specified (§3.3, frozen in
    ``bundle-merkle-empty.json``) and unreachable in practice, because an empty bundle is
    refused before a root is computed. It is implemented anyway: returning ``None`` here
    instead would be a silent disagreement between two conforming implementations at the
    one input neither can test against real data.

    The split is at the largest power of two strictly less than ``n`` — never the
    Bitcoin-style "duplicate the last node", which admits two distinct leaf sequences with
    the same root.
    """

    if not leaves:
        return hashlib.sha256(b"").digest()

    def mth(nodes: Sequence[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        split = 1
        while split * 2 < len(nodes):
            split *= 2
        return merkle_node(mth(nodes[:split]), mth(nodes[split:]))

    return mth(list(leaves))


def membership_root(event_hashes: Sequence[bytes]) -> bytes:
    """The signed ``event_membership_root``, from event hashes in scope order.

    The ordinal is the *position in this sequence* — ``scope_ordinal``, local to the signed
    scope. It is never ``global_seq``: ``global_seq`` is unsigned by construction
    (``_verification.py`` asserts it can never appear in ``authenticated_fields``), so
    ordering the tree on it would let a row-write attacker permute the tree without
    touching a signed byte.
    """

    return merkle_root([merkle_leaf(i, h) for i, h in enumerate(event_hashes)])


def membership_root_text(event_hashes: Sequence[bytes]) -> str:
    return digest_text(membership_root(event_hashes))


# ---------------------------------------------------------------------------
# §3.7 — section digests
# ---------------------------------------------------------------------------


def section_digest(name: str, section: Sequence[Any]) -> bytes:
    """``SHA256(domain || section_name || 0x00 || JCS(section_array))``.

    The name is inside the hash input, so two sections cannot be swapped even when their
    contents are structurally compatible.
    """

    if "\x00" in name:
        # Otherwise the NUL separator is ambiguous and two (name, contents) pairs could
        # produce one digest. Unreachable through SECTION_NAMES; checked because the
        # function is public and the failure would be silent.
        raise _statement_refusal(f"section name may not contain NUL: {name!r}", section=name)
    return hashlib.sha256(
        SECTION_DIGEST_DOMAIN + name.encode("utf-8") + b"\x00" + canonicalize(list(section))
    ).digest()


def section_digest_text(name: str, section: Sequence[Any]) -> str:
    return digest_text(section_digest(name, section))


# ---------------------------------------------------------------------------
# §3.4 — the statement signature
# ---------------------------------------------------------------------------


def statement_signing_input(statement: Mapping[str, Any]) -> bytes:
    """``b"regista.audit-bundle.v3\\x00" || JCS(statement)``.

    The domain prefix is mandatory and MUST NOT be omitted "because JCS output is
    unambiguous" — it is what stops a v3 statement being replayed as some other
    JCS-signed regista object under the same key.
    """

    return STATEMENT_SIGNING_DOMAIN + canonicalize(dict(statement))


def sign_statement(
    statement: Mapping[str, Any], *, private_key: bytes, key_id: str
) -> dict[str, Any]:
    """Produce the §3.1 ``statement_signature`` block over *statement*."""

    from ._signing_scheme import Ed25519Scheme

    signature, _payload_hash = Ed25519Scheme().sign(statement_signing_input(statement), private_key)
    return {
        "scheme_id": STATEMENT_SIGNATURE_SCHEME,
        "key_id": key_id,
        "signature": _encode_base64(signature),
    }


def verify_statement_signature(
    statement: Mapping[str, Any],
    signature_block: Mapping[str, Any],
    *,
    public_key: bytes,
) -> None:
    """Raise unless *signature_block* is a valid ed25519 signature over *statement*.

    Returns ``None`` on success. A boolean return would invite ``if verify(...)`` written
    without the ``not``, which is the one typo class this must not have.
    """

    block = _require_closed_mapping(
        signature_block, STATEMENT_SIGNATURE_KEYS, "statement_signature"
    )
    scheme_id = block["scheme_id"]
    if scheme_id != STATEMENT_SIGNATURE_SCHEME:
        raise _signature_refusal(
            f"statement_signature.scheme_id must be {STATEMENT_SIGNATURE_SCHEME!r}, got "
            f"{scheme_id!r} — BUNDLE-V3.md §3.4 admits no HMAC statement signature, "
            "because one would be verifiable only by the operator",
            scheme_id=scheme_id,
        )
    _require_nonempty_text(block["key_id"], "statement_signature.key_id")
    signature = _decode_base64(block["signature"], "statement_signature.signature")

    from ._signing_scheme import Ed25519Scheme

    signing_input = statement_signing_input(statement)
    # `Ed25519Scheme.verify` also compares a caller-supplied digest of the signing input.
    # That third factor is for the event path, where the digest is a stored row column
    # worth reconciling; here there is no stored digest to reconcile against, so it is
    # recomputed from the same bytes and carries no information. Recomputing it rather
    # than reaching past the scheme keeps one ed25519 call site in the tree.
    if not Ed25519Scheme().verify(
        signing_input, signature, hashlib.sha256(signing_input).digest(), public_key
    ):
        raise _signature_refusal(
            "statement signature does not verify against the supplied public key: the "
            "statement's bytes, the signature, or the key is not the one that signed it",
            key_id=block["key_id"],
        )


# ---------------------------------------------------------------------------
# §3.3 — chain-derived ordering
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrderedMember:
    """One event, at its position in the chain-derived order."""

    scope_ordinal: int
    canonical_envelope: bytes
    signature: bytes
    event_hash: bytes
    envelope: Mapping[str, Any]

    @property
    def event_hash_text(self) -> str:
        return digest_text(self.event_hash)

    @property
    def previous_project_event_hash(self) -> str | None:
        chain = self.envelope.get("chain")
        if not isinstance(chain, Mapping):
            return None
        value = chain.get("previous_project_event_hash")
        return value if isinstance(value, str) else None

    @property
    def transition(self) -> str | None:
        value = self.envelope.get("transition")
        return value if isinstance(value, str) else None

    @property
    def payload_type(self) -> str | None:
        payload = self.envelope.get("payload")
        if not isinstance(payload, Mapping):
            return None
        value = payload.get("type")
        return value if isinstance(value, str) else None

    def as_event_record(self) -> dict[str, str]:
        """The §3.6 record: envelope and signature, base64, nothing else."""

        return {
            "canonical_envelope": _encode_base64(self.canonical_envelope),
            "signature": _encode_base64(self.signature),
        }


def parse_event_member(canonical_envelope: bytes, signature: bytes) -> OrderedMember:
    """Parse one event's stored bytes into an unordered member.

    ``scope_ordinal`` is ``-1`` until :func:`derive_chain_order` assigns it. Using a
    sentinel rather than ``None`` keeps the field an ``int`` for the tree, and ``-1`` is
    refused by :func:`merkle_leaf`, so a member that escaped ordering cannot be hashed.
    """

    from ._verification import V6EnvelopeError, parse_v6_envelope_strict

    try:
        envelope = parse_v6_envelope_strict(canonical_envelope)
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        raise _statement_refusal(
            "an event record's canonical_envelope is not a strictly canonical v6 "
            f"envelope: {exc}. BUNDLE-V3.md §3.6 as amended by EPOCH-RESET.md:69 admits "
            "one construction, so a v1-v5 envelope cannot be represented in a v3 bundle "
            "at all"
        ) from exc
    return OrderedMember(
        scope_ordinal=-1,
        canonical_envelope=canonical_envelope,
        signature=signature,
        event_hash=compute_v6_event_hash(canonical_envelope, signature),
        envelope=envelope,
    )


def derive_chain_order(
    members: Sequence[OrderedMember],
    *,
    preceding_event_hash: str | None,
) -> list[OrderedMember]:
    """Order *members* by walking ``previous_project_event_hash`` forward from the entry.

    §3.3: "Ordering is by project-chain traversal, never by ``global_seq`` and never by
    event UUID." The entry point is the member whose ``previous_project_event_hash``
    equals *preceding_event_hash* — ``None`` for a chain that starts at genesis, a digest
    for a ``contiguous-range`` bundle anchored to the event immediately before it.

    **Owner ruling O4 (2026-08-23): a broken chain is a refusal, fail-closed.** One
    missing or duplicated link means there is no total order and therefore no membership
    tree, so there is no bundle — including the diagnostic bundle an operator most wants
    at that moment. §12 L2 offered ``--diagnostic`` and O4 rejected it: "Any forensic
    capability must be a separately named command that is unmistakably non-evidentiary:
    not a flag on ``export``, not a mode of it." So this function has no partial-order
    mode and no leniency argument, and every failure below names the specific break.
    """

    if not members:
        raise _chain_refusal(
            "refusing to order an empty event set: an empty bundle has no membership root "
            "to sign and is rejected twice (BUNDLE-V3.md §8 'Retained')"
        )

    by_hash: dict[str, OrderedMember] = {}
    for member in members:
        text = member.event_hash_text
        if text in by_hash:
            raise _chain_refusal(
                f"two event records share the event hash {text} — a duplicated event has "
                "no unique scope_ordinal, so the membership tree is undefined",
                event_hash=text,
            )
        by_hash[text] = member

    successors: dict[str | None, list[OrderedMember]] = {}
    for member in members:
        successors.setdefault(member.previous_project_event_hash, []).append(member)

    entries = successors.get(preceding_event_hash, [])
    if not entries:
        raise _chain_refusal(
            "no event in the set links from the declared scope entry point "
            f"({preceding_event_hash!r}). A complete-store scope must contain the chain "
            "genesis (previous_project_event_hash null); a contiguous-range scope must "
            "contain the event that links from scope.preceding_event_hash",
            preceding_event_hash=preceding_event_hash,
        )
    if len(entries) > 1:
        raise _chain_refusal(
            f"{len(entries)} events link from the declared scope entry point "
            f"({preceding_event_hash!r}) — the chain forks at its head",
            preceding_event_hash=preceding_event_hash,
            forked=sorted(m.event_hash_text for m in entries),
        )

    ordered: list[OrderedMember] = []
    current: OrderedMember | None = entries[0]
    while current is not None:
        ordered.append(
            OrderedMember(
                scope_ordinal=len(ordered),
                canonical_envelope=current.canonical_envelope,
                signature=current.signature,
                event_hash=current.event_hash,
                envelope=current.envelope,
            )
        )
        nexts = successors.get(current.event_hash_text, [])
        if len(nexts) > 1:
            raise _chain_refusal(
                f"the chain forks after {current.event_hash_text}: "
                f"{len(nexts)} events declare it as their predecessor",
                at=current.event_hash_text,
                forked=sorted(m.event_hash_text for m in nexts),
            )
        current = nexts[0] if nexts else None

    if len(ordered) != len(members):
        unreachable = sorted(
            set(by_hash) - {m.event_hash_text for m in ordered}
        )
        raise _chain_refusal(
            f"{len(unreachable)} of {len(members)} event(s) are not reachable by walking "
            "previous_project_event_hash from the scope entry point. A v3 bundle is a "
            "contiguous chain segment; an unreachable event means a broken link, a "
            "relocated chunk, or an injected event",
            unreachable=unreachable[:10],
            unreachable_count=len(unreachable),
        )
    return ordered


# ---------------------------------------------------------------------------
# §3.1 — parsing a document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleV3Document:
    """A parsed v3 bundle: shape-valid, format-accepted, nothing yet verified.

    ``index`` is carried so a caller can hand the document back out unchanged. **No code
    path in this module reads it** (§3.1 rule 2: "Emitting it is optional; consuming it in
    the verification path is forbidden"), and ``tests/test_bundle_v3.py`` pins that by
    filling it with contradictory values and asserting the verdict does not move.
    """

    statement: Mapping[str, Any]
    statement_signature: Mapping[str, Any]
    sections: Mapping[str, list[Any]]
    index: Mapping[str, Any] | None

    @property
    def format_version(self) -> int:
        version = self.statement["version"]
        assert isinstance(version, int)
        return version

    @property
    def scope(self) -> Mapping[str, Any]:
        scope = self.statement["scope"]
        assert isinstance(scope, Mapping)
        return scope

    @property
    def events(self) -> list[Any]:
        return self.sections["events"]


def require_supported_format_version(document: Mapping[str, Any]) -> int:
    """Accept only ``statement.version`` in :data:`SUPPORTED_FORMAT_VERSIONS`.

    This is §2 and §6 in one function, and it is the first thing
    :func:`parse_bundle_v3_document` calls, before any other structural check — so a v1 or
    v2 artifact is refused as a *format* decision rather than falling through to a pile of
    shape errors that read as corruption.

    The v1/v2 document shape had no ``statement`` at all; it had a ``manifest`` carrying
    ``format_version``. Both spellings are recognised so the refusal can say which
    artifact the operator is holding.
    """

    manifest = document.get("manifest")
    if isinstance(manifest, Mapping):
        declared = manifest.get("format_version")
        raise _format_refusal(
            f"this is a bundle v{declared} artifact (it carries a `manifest`, not a signed "
            "`statement`). Bundle v3 is the only accepted format: format_version 1 and 2 "
            "are DELETED, not deprecated, and are never read as v3 "
            "(BUNDLE-V3.md §2, §6). Re-export the bundle from the store; a v1/v2 bundle "
            "was never authenticated to anything, so nothing is lost by regenerating it",
            declared_format_version=declared,
            supported=sorted(SUPPORTED_FORMAT_VERSIONS),
        )

    statement = document.get("statement")
    if not isinstance(statement, Mapping):
        raise _format_refusal(
            "the document carries no `statement` object, so it declares no bundle format. "
            "A v3 bundle's statement is the only signed object (BUNDLE-V3.md §3.1 rule 1)",
            supported=sorted(SUPPORTED_FORMAT_VERSIONS),
        )

    declared = statement.get("version")
    # `bool` is an `int` subclass; `True` must not read as version 1.
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise _format_refusal(
            f"statement.version must be an integer, got {declared!r}",
            declared_format_version=declared,
            supported=sorted(SUPPORTED_FORMAT_VERSIONS),
        )
    if declared not in SUPPORTED_FORMAT_VERSIONS:
        raise _format_refusal(
            f"unsupported bundle format_version {declared}; this verifier accepts only "
            f"{sorted(SUPPORTED_FORMAT_VERSIONS)}. A lower version is REFUSED rather than "
            "downgraded to: S3 was 'signature enforcement is optional under format 1', "
            "and bundle v3 removes the configuration rather than hardening it "
            "(BUNDLE-V3.md §6)",
            declared_format_version=declared,
            supported=sorted(SUPPORTED_FORMAT_VERSIONS),
        )
    return declared


def _validate_scope(scope: object) -> Mapping[str, Any]:
    block = _require_closed_mapping(scope, SCOPE_KEYS, "statement.scope")
    kind = block["kind"]
    _require_statement(
        kind in SCOPE_KINDS,
        f"statement.scope.kind must be one of {sorted(SCOPE_KINDS)}, got {kind!r}. "
        "`declared-selection` is CUT from 0.6.0 (BUNDLE-V3.md §3.5): a bundle declaring it "
        "is rejected, not attested",
        kind=kind,
    )
    count = block["event_count"]
    _require_statement(
        isinstance(count, int) and not isinstance(count, bool) and count > 0,
        "statement.scope.event_count must be a positive integer — an empty bundle proves "
        "nothing and has no membership root to sign",
        event_count=count,
    )
    for member in ("first_event_hash", "last_event_hash"):
        _require_statement(
            is_digest_text(block[member]),
            f"statement.scope.{member} must be sha256:<64 lowercase hex>",
            member=member,
        )
    preceding = block["preceding_event_hash"]
    _require_statement(
        preceding is None or is_digest_text(preceding),
        "statement.scope.preceding_event_hash must be null or sha256:<64 lowercase hex>",
        preceding_event_hash=preceding,
    )
    if kind == "complete-store":
        _require_statement(
            preceding is None,
            "a complete-store scope MUST carry preceding_event_hash: null — it claims the "
            "whole chain, so there is nothing before it (BUNDLE-V3.md §3.5)",
        )
    if count == 1:
        _require_statement(
            block["first_event_hash"] == block["last_event_hash"],
            "a single-event scope must name the same hash as first and last",
        )
    return block


def _validate_trust_root(trust_root: object, *, trust_domain_id: str) -> Mapping[str, Any]:
    block = _require_closed_mapping(trust_root, TRUST_ROOT_KEYS, "statement.trust_root")
    inner = _require_uuid_text(block["trust_domain_id"], "statement.trust_root.trust_domain_id")
    _require_statement(
        inner == trust_domain_id,
        "statement.trust_root.trust_domain_id must equal statement.trust_domain_id: one "
        "artifact naming two domains is a contradiction, not a choice",
        trust_root=inner,
        statement=trust_domain_id,
    )
    for member in ("trust_domain_core_digest", "genesis_document_digest"):
        _require_statement(
            is_digest_text(block[member]),
            f"statement.trust_root.{member} must be sha256:<64 lowercase hex>",
            member=member,
        )
    governance = _require_closed_mapping(
        block["root_governance"], ROOT_GOVERNANCE_KEYS, "statement.trust_root.root_governance"
    )
    mode = governance["mode"]
    _require_statement(
        mode in ROOT_GOVERNANCE_MODES,
        f"statement.trust_root.root_governance.mode must be one of "
        f"{sorted(ROOT_GOVERNANCE_MODES)}, got {mode!r} — underscored spellings, and "
        "`single_signer_lab` is retired (RECONCILIATION.md Resolution 4). `unknown` is a "
        "verifier output (BUNDLE-V3.md §4.5), never a signed restatement",
        mode=mode,
    )
    for member in ("threshold", "signer_count"):
        value = governance[member]
        _require_statement(
            isinstance(value, int) and not isinstance(value, bool) and value >= 1,
            f"statement.trust_root.root_governance.{member} must be an integer >= 1",
            member=member,
            value=value,
        )
    threshold = governance["threshold"]
    signer_count = governance["signer_count"]
    assert isinstance(threshold, int) and isinstance(signer_count, int)
    _require_statement(
        threshold <= signer_count,
        "statement.trust_root.root_governance.threshold may not exceed signer_count: a "
        "threshold no signer set can meet is not a governance state",
        threshold=threshold,
        signer_count=signer_count,
    )
    # TRUST-DOMAIN.md §3.4: the mode is DERIVED from threshold/signer_count, so a signed
    # restatement that contradicts its own numbers is invalid rather than merely odd.
    # `solo_effective` exists precisely to stop an estate listing several fingerprints at
    # threshold 1 and calling itself co_signed (§10 "What you pin").
    if threshold >= 2:
        expected = "co_signed"
    elif signer_count == 1:
        expected = "solo"
    else:
        expected = "solo_effective"
    _require_statement(
        mode == expected,
        f"statement.trust_root.root_governance says mode={mode!r} at threshold="
        f"{threshold}, signer_count={signer_count}, but that state derives "
        f"{expected!r} (TRUST-DOMAIN.md §3.4). A signed restatement that contradicts its "
        "own numbers is invalid",
        mode=mode,
        derived=expected,
        threshold=threshold,
        signer_count=signer_count,
    )
    return block


def _validate_signer(signer: object) -> Mapping[str, Any]:
    block = _require_closed_mapping(signer, SIGNER_KEYS, "statement.signer")
    _require_nonempty_text(block["principal_id"], "statement.signer.principal_id")
    _require_nonempty_text(block["key_id"], "statement.signer.key_id")
    scheme_id = block["scheme_id"]
    _require_statement(
        scheme_id == STATEMENT_SIGNATURE_SCHEME,
        f"statement.signer.scheme_id must be {STATEMENT_SIGNATURE_SCHEME!r}, got "
        f"{scheme_id!r} (BUNDLE-V3.md §3.4)",
        scheme_id=scheme_id,
    )
    fingerprint = block["fingerprint"]
    _require_statement(
        isinstance(fingerprint, str)
        and fingerprint.startswith("ed25519:sha256:")
        and is_digest_text(fingerprint[len("ed25519:") :]),
        "statement.signer.fingerprint must be ed25519:sha256:<64 lowercase hex> "
        "(TRUST-DOMAIN.md §3.5's one fingerprint function)",
        fingerprint=fingerprint,
    )
    authority_kind = block["authority_kind"]
    _require_statement(
        authority_kind in AUTHORITY_KINDS,
        f"statement.signer.authority_kind must be one of {sorted(AUTHORITY_KINDS)}, got "
        f"{authority_kind!r}",
        authority_kind=authority_kind,
    )
    _require_statement(
        is_digest_text(block["authority_event_hash"]),
        "statement.signer.authority_event_hash must be sha256:<64 lowercase hex> and may "
        "NOT be null: it is the signed event that granted this key the authority to sign "
        "bundles (owner ruling O3), and a null there is a self-authorising signer",
        authority_event_hash=block["authority_event_hash"],
    )
    return block


def _validate_statement(statement: object) -> Mapping[str, Any]:
    _require_statement(isinstance(statement, Mapping), "statement must be an object")
    assert isinstance(statement, Mapping)

    for forbidden, why in FORBIDDEN_STATEMENT_KEYS.items():
        if forbidden in statement:
            raise _statement_refusal(
                f"statement carries the retired member {forbidden!r}, which is FORBIDDEN "
                f"rather than ignored: {why}",
                forbidden_key=forbidden,
            )

    authority_present = sorted(STATEMENT_AUTHORITY_KEYS & set(statement))
    _require_statement(
        len(authority_present) == 1,
        "exactly one of statement.signer and statement.root_signatures is present; found "
        f"{authority_present or 'neither'} (BUNDLE-V3.md §3.2, RECONCILIATION.md "
        "collision 21)",
        present=authority_present,
    )
    authority_key = authority_present[0]
    if authority_key == "root_signatures":
        # Recognised, and refused rather than tolerated. A direct root-threshold statement
        # needs the root signer set and the current threshold, both of which come from
        # trust-root resolution (§4) — Phase C's work. Accepting the shape and not checking
        # the signatures would be a signed object with no verifier, which is the exact
        # failure this document exists to remove.
        raise _statement_refusal(
            "a direct root-threshold statement (statement.root_signatures) is not accepted "
            "by this verifier: checking it requires the current root signer set and "
            "threshold from trust-root resolution (BUNDLE-V3.md §4), which is not "
            "implemented here. Refused rather than accepted-and-unchecked",
            authority="root_signatures",
        )

    _require_closed_mapping(statement, STATEMENT_BASE_KEYS | {authority_key}, "statement")

    _require_statement(
        statement["type"] == BUNDLE_V3_STATEMENT_TYPE,
        f"statement.type must be {BUNDLE_V3_STATEMENT_TYPE!r}, got {statement['type']!r}",
        type=statement["type"],
    )
    _require_uuid_text(statement["bundle_id"], "statement.bundle_id")
    project_instance_id = _require_uuid_text(
        statement["project_instance_id"], "statement.project_instance_id"
    )
    trust_domain_id = _require_uuid_text(statement["trust_domain_id"], "statement.trust_domain_id")
    _require_statement(
        project_instance_id != trust_domain_id,
        "statement.project_instance_id and statement.trust_domain_id must differ: one "
        "identifier serving as both is a store that is its own trust domain",
    )
    created_at = _require_nonempty_text(statement["created_at"], "statement.created_at")
    try:
        parsed_created = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise _statement_refusal(
            f"statement.created_at is not an ISO-8601 instant: {created_at!r}",
            created_at=created_at,
        ) from exc
    _require_statement(
        parsed_created.tzinfo is not None,
        "statement.created_at must carry an explicit offset — a naive instant is a claim "
        "about an unstated timezone",
        created_at=created_at,
    )

    _validate_scope(statement["scope"])
    _require_statement(
        is_digest_text(statement["event_membership_root"]),
        "statement.event_membership_root must be sha256:<64 lowercase hex>",
    )
    digests = _require_closed_mapping(
        statement["section_digests"], frozenset(SECTION_NAMES), "statement.section_digests"
    )
    for name in SECTION_NAMES:
        _require_statement(
            is_digest_text(digests[name]),
            f"statement.section_digests.{name} must be sha256:<64 lowercase hex>",
            section=name,
        )
    _validate_trust_root(statement["trust_root"], trust_domain_id=trust_domain_id)
    _validate_signer(statement["signer"])

    exporter = _require_closed_mapping(statement["exporter"], EXPORTER_KEYS, "statement.exporter")
    _require_nonempty_text(exporter["regista_version"], "statement.exporter.regista_version")
    _require_statement(
        exporter["statement_schema"] == BUNDLE_V3_STATEMENT_SCHEMA,
        f"statement.exporter.statement_schema must be {BUNDLE_V3_STATEMENT_SCHEMA!r}, got "
        f"{exporter['statement_schema']!r}",
        statement_schema=exporter["statement_schema"],
    )
    return statement


def _validate_sections(sections: object) -> Mapping[str, list[Any]]:
    block = _require_closed_mapping(sections, frozenset(SECTION_NAMES), "sections")
    validated: dict[str, list[Any]] = {}
    for name in SECTION_NAMES:
        validated[name] = _require_list(block[name], f"sections.{name}")

    for i, record in enumerate(validated["events"]):
        _require_closed_mapping(record, EVENT_RECORD_KEYS, f"sections.events[{i}]")
        assert isinstance(record, Mapping)
        _decode_base64(record["canonical_envelope"], f"sections.events[{i}].canonical_envelope")
        _decode_base64(record["signature"], f"sections.events[{i}].signature")

    for name in REFERENCE_SECTIONS:
        seen: set[str] = set()
        previous: str | None = None
        for i, ref in enumerate(validated[name]):
            _require_statement(
                is_digest_text(ref),
                f"sections.{name}[{i}] must be a sha256:<64 lowercase hex> event-hash "
                "reference into sections.events — these sections carry references, never "
                "extracted payload duplicates (BUNDLE-V3.md §3.2 as amended)",
                section=name,
            )
            assert isinstance(ref, str)
            _require_statement(
                ref not in seen,
                f"sections.{name}[{i}] repeats {ref}",
                section=name,
            )
            _require_statement(
                previous is None or previous < ref,
                f"sections.{name} must be sorted ascending; {ref} follows {previous}",
                section=name,
            )
            seen.add(ref)
            previous = ref

    for i, record in enumerate(validated["bundled_key_evidence"]):
        path = f"sections.bundled_key_evidence[{i}]"
        _require_closed_mapping(record, BUNDLED_KEY_EVIDENCE_KEYS, path)
        assert isinstance(record, Mapping)
        _require_nonempty_text(record["key_id"], f"{path}.key_id")
        _require_nonempty_text(record["principal_id"], f"{path}.principal_id")
        _require_statement(
            record["scheme_id"] == STATEMENT_SIGNATURE_SCHEME,
            f"{path}.scheme_id must be {STATEMENT_SIGNATURE_SCHEME!r} — the one epoch has "
            "one asymmetric scheme",
            scheme_id=record["scheme_id"],
        )
        material = _decode_base64(record["public_key"], f"{path}.public_key")
        _require_statement(
            len(material) == 32,
            f"{path}.public_key must be 32 bytes of raw ed25519 public key, got "
            f"{len(material)}",
        )
        expected = "ed25519:sha256:" + hashlib.sha256(material).hexdigest()
        _require_statement(
            record["fingerprint"] == expected,
            f"{path}.fingerprint does not match sha256 of the public_key it accompanies. "
            "This is a self-consistency check on evidence, NOT a trust decision: "
            "authority comes only from the auditor's pin (BUNDLE-V3.md §4.3)",
            fingerprint=record["fingerprint"],
        )

    for i, record in enumerate(validated["external_evidence"]):
        path = f"sections.external_evidence[{i}]"
        _require_closed_mapping(record, EXTERNAL_EVIDENCE_KEYS, path)
        assert isinstance(record, Mapping)
        _require_statement(
            record["class"] in EXTERNAL_EVIDENCE_CLASSES,
            f"{path}.class must be one of {sorted(EXTERNAL_EVIDENCE_CLASSES)}, got "
            f"{record['class']!r}. The classification is what stops a bundled copy of a "
            "checkpoint counting as external evidence (BUNDLE-V3.md §4.6, D9)",
            klass=record["class"],
        )
        _require_nonempty_text(record["source"], f"{path}.source")
        _require_nonempty_text(record["obtained_at"], f"{path}.obtained_at")

    return validated


def parse_bundle_v3_document(raw: bytes | str) -> BundleV3Document:
    """Parse and shape-validate a v3 bundle. Nothing cryptographic happens here.

    Order matters: the format decision is first, so a v1/v2 artifact is refused as a
    format decision rather than reported as malformed v3.
    """

    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT, f"Bundle is not valid JSON: {exc}"
        ) from exc
    if not isinstance(loaded, Mapping):
        raise _format_refusal("a bundle document must be a JSON object")

    require_supported_format_version(loaded)

    unknown = sorted(set(loaded) - TOP_LEVEL_KEYS)
    if unknown:
        raise _statement_refusal(
            f"unknown top-level key(s) {unknown}: a v3 bundle carries exactly "
            f"{sorted(TOP_LEVEL_KEYS)}. Unknown keys are a REJECTION, not an ignore — a "
            "v2 verifier's tolerance of extra keys is how `public_keys` quietly became a "
            "trust root (BUNDLE-V3.md §3.1 rule 3)",
            unknown=unknown,
        )
    missing = sorted(REQUIRED_TOP_LEVEL_KEYS - set(loaded))
    if missing:
        raise _statement_refusal(f"missing required top-level key(s) {missing}", missing=missing)

    statement = _validate_statement(loaded["statement"])
    sections = _validate_sections(loaded["sections"])
    signature_block = _require_closed_mapping(
        loaded["statement_signature"], STATEMENT_SIGNATURE_KEYS, "statement_signature"
    )
    index = loaded.get("index")
    if index is not None and not isinstance(index, Mapping):
        raise _statement_refusal("index, when present, must be an object")

    return BundleV3Document(
        statement=statement,
        statement_signature=signature_block,
        sections=sections,
        index=index,
    )


# ---------------------------------------------------------------------------
# Verification primitives — the Phase C / Phase D seam
# ---------------------------------------------------------------------------


def recompute_reference_sections(ordered: Sequence[OrderedMember]) -> dict[str, list[str]]:
    """Derive the five reference sections from the events themselves.

    Recomputed, never read: a section a verifier derives cannot be edited, and the whole
    of §1's argument is that a check reading an attacker-writable field can only argue
    about plausibility. :data:`SECTION_TRANSITIONS` and :data:`SECTION_PAYLOAD_TYPES` are
    the classification, and their docstrings name what Phase D still owes.
    """

    derived: dict[str, list[str]] = {name: [] for name in REFERENCE_SECTIONS}
    for member in ordered:
        transition = member.transition
        payload_type = member.payload_type
        for name in REFERENCE_SECTIONS:
            if transition is not None and transition in SECTION_TRANSITIONS.get(
                name, frozenset()
            ):
                derived[name].append(member.event_hash_text)
            elif payload_type is not None and payload_type in SECTION_PAYLOAD_TYPES.get(
                name, frozenset()
            ):
                derived[name].append(member.event_hash_text)
    return {name: sorted(set(refs)) for name, refs in derived.items()}


@dataclass(frozen=True)
class BundleV3CoreReport:
    """What Phase B establishes about a v3 bundle, and nothing more.

    Every field is a *fact about a check that ran*, never a verdict. There is no
    ``applicability`` here and no axis: §5's lattice reads these and decides, which is
    why "the signature was not checked" and "the signature failed" are two fields rather
    than one boolean (the exact conflation S1 exists to eliminate).
    """

    format_version: int
    event_count: int
    #: True when a public key was supplied and the signature verified against it. False
    #: when the signature failed AND when no key was supplied — read it with
    #: ``statement_signature_checked``, never alone.
    statement_signature_valid: bool
    #: False means no caller-supplied key reached this verifier. Phase C's
    #: ``TrustPolicy``/``AcceptBundledKeys`` is what makes it True; this module refuses to
    #: resolve a key from the artifact, because that is §5.2 rule C's clamp and a core that
    #: quietly harvested the key would make the clamp unreachable.
    statement_signature_checked: bool
    membership_root_ok: bool
    section_digests_ok: bool
    reference_sections_ok: bool
    scope_consistent: bool
    chain_ordered: bool
    #: O3: True when the signer's authority event was found inside the bundle and its
    #: acceptance object grants ``may_sign_bundles``.
    signer_may_sign_bundles: bool
    #: False when the authority event is outside the presented scope — a fact for §5's
    #: ``not_checkable``, not a pass.
    signer_authority_checked: bool
    recomputed_membership_root: str
    section_digest_mismatches: tuple[str, ...] = ()
    ordered_event_hashes: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()

    @property
    def structural_checks_ok(self) -> bool:
        """Every check that runs without caller-supplied trust material passed.

        Deliberately NOT named ``verified``: it says nothing about *whose* key signed the
        statement, which is the whole of §4. A caller reading only this and reporting
        "verified" would be committing S5 again.
        """

        return (
            self.membership_root_ok
            and self.section_digests_ok
            and self.reference_sections_ok
            and self.scope_consistent
            and self.chain_ordered
            and not self.findings
        )

    @property
    def core_ok(self) -> bool:
        """Structural checks passed AND the statement signature was checked and valid."""

        return (
            self.structural_checks_ok
            and self.statement_signature_checked
            and self.statement_signature_valid
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "event_count": self.event_count,
            "statement_signature_checked": self.statement_signature_checked,
            "statement_signature_valid": self.statement_signature_valid,
            "membership_root_ok": self.membership_root_ok,
            "section_digests_ok": self.section_digests_ok,
            "reference_sections_ok": self.reference_sections_ok,
            "scope_consistent": self.scope_consistent,
            "chain_ordered": self.chain_ordered,
            "signer_may_sign_bundles": self.signer_may_sign_bundles,
            "signer_authority_checked": self.signer_authority_checked,
            "recomputed_membership_root": self.recomputed_membership_root,
            "section_digest_mismatches": list(self.section_digest_mismatches),
            "findings": list(self.findings),
        }


@dataclass
class _CoreAccumulator:
    findings: list[str] = field(default_factory=list)

    def check(self, condition: bool, finding: str) -> bool:
        if not condition:
            self.findings.append(finding)
        return condition


def _acceptance_scopes_for(member: OrderedMember, *, key_id: str) -> Mapping[str, Any] | None:
    """The signed acceptance ``scopes`` block *member* grants to *key_id*, if any.

    Reads the parsed **envelope**, never a row column: the envelope bytes are the
    artifact, and an authority read out of a rewritable projection is the S6 defect.
    """

    payload = member.envelope.get("payload")
    if not isinstance(payload, Mapping):
        return None
    candidates: list[Mapping[str, Any]] = []
    if payload.get("type") == "regista.key-acceptance":
        candidates.append(payload)
    embedded = payload.get("bootstrap_key_acceptance")
    if isinstance(embedded, Mapping):
        candidates.append(embedded)
    for acceptance in candidates:
        if acceptance.get("key_id") != key_id:
            continue
        scopes = acceptance.get("scopes")
        if isinstance(scopes, Mapping):
            return scopes
    return None


def verify_bundle_v3_core(
    document: BundleV3Document,
    *,
    statement_public_key: bytes | None,
) -> BundleV3CoreReport:
    """Recompute everything the signed statement commits to.

    Five checks, each fail-closed and each reported separately:

    1. **Format acceptance** — already done by :func:`parse_bundle_v3_document`; the
       accepted version is carried through so a report cannot omit it.
    2. **Chain-derived ordering** — the events form one contiguous chain segment entered
       at ``scope.preceding_event_hash``.
    3. **Membership root** — the RFC 6962 root over those ordinals equals the signed
       ``event_membership_root``.
    4. **Section digests and derived sections** — every section's digest matches, and the
       five reference sections match what the events themselves classify to.
    5. **Statement signature** — ed25519 over the domain-prefixed JCS bytes, against a key
       the *caller* supplied.

    ``statement_public_key=None`` is a legitimate call and is reported as
    ``statement_signature_checked=False``. It is not an error, because "the auditor
    supplied no key" is a different fact from "the signature is wrong", and Phase C's §5.1
    axes need to tell them apart.
    """

    acc = _CoreAccumulator()
    statement = document.statement
    scope = document.scope

    ordered: list[OrderedMember] = []
    chain_ordered = True
    try:
        members = [
            parse_event_member(
                base64.b64decode(record["canonical_envelope"], validate=True),
                base64.b64decode(record["signature"], validate=True),
            )
            for record in document.events
        ]
        ordered = derive_chain_order(
            members, preceding_event_hash=scope["preceding_event_hash"]
        )
    except RegistaError as exc:
        chain_ordered = False
        acc.findings.append(f"{exc.code.value}: {exc.message}")

    recomputed_root = digest_text(membership_root([m.event_hash for m in ordered]))
    membership_root_ok = chain_ordered and acc.check(
        hmac.compare_digest(recomputed_root, str(statement["event_membership_root"])),
        "membership_root_mismatch: the recomputed RFC 6962 root over the presented events "
        f"is {recomputed_root}, but the signed statement commits to "
        f"{statement['event_membership_root']}",
    )

    declared_digests = statement["section_digests"]
    assert isinstance(declared_digests, Mapping)
    mismatches: list[str] = []
    for name in SECTION_NAMES:
        recomputed = section_digest_text(name, document.sections[name])
        if not hmac.compare_digest(recomputed, str(declared_digests[name])):
            mismatches.append(name)
    section_digests_ok = acc.check(
        not mismatches,
        f"section_digest_mismatch: {sorted(mismatches)} do not match the signed digests",
    )

    reference_sections_ok = True
    if chain_ordered:
        derived = recompute_reference_sections(ordered)
        for name in REFERENCE_SECTIONS:
            presented = list(document.sections[name])
            if presented != derived[name]:
                reference_sections_ok = False
                acc.findings.append(
                    f"reference_section_mismatch: sections.{name} carries "
                    f"{len(presented)} reference(s) but the events themselves classify to "
                    f"{len(derived[name])}. These sections are recomputed, never read "
                    "(BUNDLE-V3.md §3.2 as amended)"
                )

    scope_consistent = True
    if chain_ordered:
        scope_consistent &= acc.check(
            len(ordered) == scope["event_count"],
            f"scope_event_count_mismatch: the signed scope claims "
            f"{scope['event_count']} event(s), the bundle presents {len(ordered)}",
        )
        scope_consistent &= acc.check(
            ordered[0].event_hash_text == scope["first_event_hash"],
            "scope_first_event_mismatch: the chain-ordered first event is "
            f"{ordered[0].event_hash_text}, the signed scope names "
            f"{scope['first_event_hash']}",
        )
        scope_consistent &= acc.check(
            ordered[-1].event_hash_text == scope["last_event_hash"],
            "scope_last_event_mismatch: the chain-ordered last event is "
            f"{ordered[-1].event_hash_text}, the signed scope names "
            f"{scope['last_event_hash']}",
        )
        scope_consistent &= acc.check(
            len(ordered) == len(document.events),
            "scope_event_record_count_mismatch: sections.events and the membership tree "
            "must have the same length (BUNDLE-V3.md §3.2: two independent equalities, "
            "one signature)",
        )
        project_instance_id = str(statement["project_instance_id"])
        trust_domain_id = str(statement["trust_domain_id"])
        for member in ordered:
            if str(member.envelope.get("project_instance_id")) != project_instance_id:
                scope_consistent = False
                acc.findings.append(
                    "event_project_instance_mismatch: "
                    f"{member.event_hash_text} names project_instance_id "
                    f"{member.envelope.get('project_instance_id')!r}, the statement names "
                    f"{project_instance_id!r}"
                )
                break
        for member in ordered:
            if str(member.envelope.get("trust_domain_id")) != trust_domain_id:
                scope_consistent = False
                acc.findings.append(
                    "event_trust_domain_mismatch: "
                    f"{member.event_hash_text} names trust_domain_id "
                    f"{member.envelope.get('trust_domain_id')!r}, the statement names "
                    f"{trust_domain_id!r}"
                )
                break
        if scope["kind"] == "complete-store":
            scope_consistent &= acc.check(
                ordered[0].previous_project_event_hash is None,
                "complete_store_not_at_genesis: a complete-store scope claims the whole "
                "chain, so its first event must be the chain genesis "
                "(previous_project_event_hash null)",
            )

    # O3 — the signer's authority, checked from the signed acceptance rather than assumed.
    signer = statement["signer"]
    assert isinstance(signer, Mapping)
    authority_hash = str(signer["authority_event_hash"])
    signer_key_id = str(signer["key_id"])
    authority_member = next(
        (m for m in ordered if m.event_hash_text == authority_hash), None
    )
    signer_authority_checked = authority_member is not None
    signer_may_sign_bundles = False
    if authority_member is not None:
        scopes = _acceptance_scopes_for(authority_member, key_id=signer_key_id)
        if scopes is None:
            acc.findings.append(
                "signer_authority_not_an_acceptance: "
                f"statement.signer.authority_event_hash names {authority_hash}, which is "
                f"in the bundle but grants no acceptance to key {signer_key_id!r}"
            )
        else:
            signer_may_sign_bundles = scopes.get("may_sign_bundles") is True
            if not signer_may_sign_bundles:
                acc.findings.append(
                    "signer_may_not_sign_bundles: the signed acceptance at "
                    f"{authority_hash} does not grant may_sign_bundles to key "
                    f"{signer_key_id!r}. Owner ruling O3: the bundle signer MAY be the "
                    "project writer key, but only if that key explicitly bears the scope "
                    "— holding the writer key is not an implication of the authority"
                )
    elif scope["kind"] == "complete-store":
        # RECONCILIATION.md Resolution 4: "Missing closure in `complete-store` is invalid."
        # The signing-authority closure is the one dependency Phase B needs to enforce O3
        # at verify; the rest of the closure walk is Phase D's.
        acc.findings.append(
            "signer_authority_outside_complete_store: "
            f"statement.signer.authority_event_hash names {authority_hash}, which is not "
            "in a bundle claiming the whole chain. A complete-store scope missing a "
            "dependency it must contain is invalid, not unverifiable"
        )

    statement_signature_checked = statement_public_key is not None
    statement_signature_valid = False
    if statement_public_key is not None:
        try:
            verify_statement_signature(
                statement, document.statement_signature, public_key=statement_public_key
            )
            statement_signature_valid = True
        except RegistaError as exc:
            acc.findings.append(f"{exc.code.value}: {exc.message}")

    return BundleV3CoreReport(
        format_version=document.format_version,
        event_count=len(document.events),
        statement_signature_valid=statement_signature_valid,
        statement_signature_checked=statement_signature_checked,
        membership_root_ok=membership_root_ok,
        section_digests_ok=section_digests_ok,
        reference_sections_ok=reference_sections_ok,
        scope_consistent=scope_consistent,
        chain_ordered=chain_ordered,
        signer_may_sign_bundles=signer_may_sign_bundles,
        signer_authority_checked=signer_authority_checked,
        recomputed_membership_root=recomputed_root,
        section_digest_mismatches=tuple(sorted(mismatches)),
        ordered_event_hashes=tuple(m.event_hash_text for m in ordered),
        findings=tuple(acc.findings),
    )


# ---------------------------------------------------------------------------
# Building a document — the Phase D seam
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleV3TrustRoot:
    """The four-field signed ``trust_root`` block (``TRUST-DOMAIN.md`` §3.6).

    Supplied by the caller, never derived here. ``root_governance`` in particular MUST be
    the state obtained by *replaying the signed governance log* through the authenticated
    trust-log checkpoint (§3.2): it is not copied from genesis, configuration or a mutable
    projection. That replay is trust-domain machinery outside a project store — the
    project chain carries ``trust_domain_core_digest`` and ``genesis_document_digest`` in
    its genesis payload but carries no governance state at all — so a builder that
    "derived" it would be inventing the one field WI-272 requires to be true.
    """

    trust_domain_id: str
    trust_domain_core_digest: str
    genesis_document_digest: str
    governance_mode: str
    governance_threshold: int
    governance_signer_count: int

    def as_statement_member(self) -> dict[str, Any]:
        return {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "root_governance": {
                "mode": self.governance_mode,
                "threshold": self.governance_threshold,
                "signer_count": self.governance_signer_count,
            },
            "genesis_document_digest": self.genesis_document_digest,
        }


@dataclass(frozen=True)
class BundleV3Signer:
    """The bundle-signing authority, with the O3 scope as a required input.

    ``may_sign_bundles`` is a constructor argument rather than something this module reads,
    for the same reason ``trust_root`` is: resolving it means walking the project's
    acceptance anchors, which is the caller's transaction. What this module guarantees is
    that a ``False`` never signs — see :func:`build_bundle_v3_document`.
    """

    principal_id: str
    key_id: str
    fingerprint: str
    authority_kind: str
    authority_event_hash: str
    may_sign_bundles: bool
    private_key: bytes

    def as_statement_member(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "scheme_id": STATEMENT_SIGNATURE_SCHEME,
            "fingerprint": self.fingerprint,
            "authority_kind": self.authority_kind,
            "authority_event_hash": self.authority_event_hash,
        }


def build_bundle_v3_document(
    *,
    event_records: Sequence[tuple[bytes, bytes]],
    project_instance_id: str,
    trust_root: BundleV3TrustRoot,
    signer: BundleV3Signer,
    scope_kind: str,
    preceding_event_hash: str | None = None,
    bundled_key_evidence: Sequence[Mapping[str, Any]] = (),
    external_evidence: Sequence[Mapping[str, Any]] = (),
    regista_version: str,
    bundle_id: str | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build and sign a complete v3 bundle document.

    *event_records* are ``(canonical_envelope, signature)`` pairs in any order: the order
    that ends up in the artifact is derived by chain traversal, not taken from the caller.
    That is deliberate — a builder that trusted a caller's ordering would let a query's
    ``ORDER BY`` decide a signed field.

    Refuses, by name, on: a signer without ``may_sign_bundles`` (O3), a chain that cannot
    be totally ordered (O4), an empty event set, and any statement this module's own
    verifier would reject (the document is round-tripped through
    :func:`parse_bundle_v3_document` before it is returned, so an exporter cannot write a
    document its verifier refuses).
    """

    if not signer.may_sign_bundles:
        raise _signer_refusal(
            f"key {signer.key_id!r} for principal {signer.principal_id!r} does not bear "
            "may_sign_bundles, so it may not sign a bundle statement. Owner ruling O3 "
            "(2026-08-23): the statement signer MAY be the project writer key, but the "
            "authority is an explicit, signed property of the key "
            "(TRUST-DOMAIN.md §5.8 scopes) and never an implication of holding it. Grant "
            "the scope in a key-acceptance event, or sign with a key that has it",
            key_id=signer.key_id,
            principal_id=signer.principal_id,
        )
    if scope_kind not in SCOPE_KINDS:
        raise _statement_refusal(
            f"scope_kind must be one of {sorted(SCOPE_KINDS)}, got {scope_kind!r}",
            scope_kind=scope_kind,
        )
    if scope_kind == "complete-store" and preceding_event_hash is not None:
        raise _statement_refusal(
            "a complete-store scope cannot have a preceding_event_hash: it claims the "
            "whole chain (BUNDLE-V3.md §3.5)",
            preceding_event_hash=preceding_event_hash,
        )

    members = [parse_event_member(env, sig) for env, sig in event_records]
    ordered = derive_chain_order(members, preceding_event_hash=preceding_event_hash)

    sections: dict[str, list[Any]] = {name: [] for name in SECTION_NAMES}
    sections["events"] = [m.as_event_record() for m in ordered]
    sections.update(recompute_reference_sections(ordered))
    sections["bundled_key_evidence"] = sorted(
        (dict(record) for record in bundled_key_evidence),
        key=lambda r: str(r.get("key_id", "")),
    )
    sections["external_evidence"] = [dict(record) for record in external_evidence]

    trust_domain_id = trust_root.trust_domain_id
    statement: dict[str, Any] = {
        "type": BUNDLE_V3_STATEMENT_TYPE,
        "version": BUNDLE_V3_FORMAT_VERSION,
        "bundle_id": bundle_id if bundle_id is not None else str(uuid.uuid4()),
        "project_instance_id": project_instance_id,
        "trust_domain_id": trust_domain_id,
        "created_at": (created_at or datetime.now(UTC)).isoformat(),
        "scope": {
            "kind": scope_kind,
            "event_count": len(ordered),
            "first_event_hash": ordered[0].event_hash_text,
            "last_event_hash": ordered[-1].event_hash_text,
            "preceding_event_hash": preceding_event_hash,
        },
        "event_membership_root": digest_text(membership_root([m.event_hash for m in ordered])),
        "section_digests": {
            name: section_digest_text(name, sections[name]) for name in SECTION_NAMES
        },
        "trust_root": trust_root.as_statement_member(),
        "signer": signer.as_statement_member(),
        "exporter": {
            "regista_version": regista_version,
            "statement_schema": BUNDLE_V3_STATEMENT_SCHEMA,
        },
    }

    # Validate before signing. Signing an invalid statement would produce an artifact
    # whose signature is real and whose contents this verifier refuses — a signature over
    # bytes nobody will read is worse than no artifact.
    _validate_statement(statement)

    document = {
        "statement": statement,
        "statement_signature": sign_statement(
            statement, private_key=signer.private_key, key_id=signer.key_id
        ),
        "sections": sections,
    }

    # The exporter's own parse. `MAX_BUNDLE_BYTES` and the write ceremony belong to the
    # caller (§9); what belongs here is the guarantee that the bytes are acceptable to the
    # verifier that will read them.
    parse_bundle_v3_document(canonical_bundle_bytes(document))
    return document


def canonical_bundle_bytes(document: Mapping[str, Any]) -> bytes:
    """The artifact's bytes: RFC 8785 canonical JSON over the whole document.

    Replaces bundle v2's ``_canonical_bundle_bytes``, whose output fed an **unkeyed**
    SHA-256 that anyone could recompute after editing anything (§1). There is no bundle
    hash in v3: the statement signature is what makes an edit detectable, and a second,
    unkeyed digest alongside it would be a field an operator could mistake for evidence.
    """

    return canonicalize(dict(document))


__all__ = [
    "AUTHORITY_KINDS",
    "BUNDLED_KEY_EVIDENCE_KEYS",
    "BUNDLE_V3_FORMAT_VERSION",
    "BUNDLE_V3_STATEMENT_SCHEMA",
    "BUNDLE_V3_STATEMENT_TYPE",
    "EVENT_RECORD_KEYS",
    "EXTERNAL_EVIDENCE_CLASSES",
    "EXTERNAL_EVIDENCE_KEYS",
    "FORBIDDEN_STATEMENT_KEYS",
    "MEMBER_LEAF_DOMAIN",
    "MEMBER_NODE_DOMAIN",
    "REFERENCE_SECTIONS",
    "ROOT_GOVERNANCE_MODES",
    "SCOPE_KINDS",
    "SECTION_DIGEST_DOMAIN",
    "SECTION_NAMES",
    "SECTION_PAYLOAD_TYPES",
    "SECTION_TRANSITIONS",
    "SIGNER_KEYS",
    "STATEMENT_BASE_KEYS",
    "STATEMENT_SIGNATURE_SCHEME",
    "STATEMENT_SIGNING_DOMAIN",
    "SUPPORTED_FORMAT_VERSIONS",
    "TOP_LEVEL_KEYS",
    "TRUST_ROOT_KEYS",
    "BundleV3CoreReport",
    "BundleV3Document",
    "BundleV3Signer",
    "BundleV3TrustRoot",
    "OrderedMember",
    "build_bundle_v3_document",
    "canonical_bundle_bytes",
    "derive_chain_order",
    "digest_bytes",
    "digest_text",
    "is_digest_text",
    "membership_root",
    "membership_root_text",
    "merkle_leaf",
    "merkle_node",
    "merkle_root",
    "parse_bundle_v3_document",
    "parse_event_member",
    "recompute_reference_sections",
    "require_supported_format_version",
    "section_digest",
    "section_digest_text",
    "sign_statement",
    "statement_signing_input",
    "verify_bundle_v3_core",
    "verify_statement_signature",
]
