"""Trust-domain log event contracts (P2.2, ``docs/0.6.0/TRUST-DOMAIN.md`` §5).

The trust-domain log is **one estate-wide project** whose first event is a v6 Ed25519
event: no HMAC prefix, no ``project_cryptographic_epoch_started``, no cutover
checkpoint (§5.2). A trust log with a legacy prefix would root the estate in exactly
the semantics the epoch exists to leave behind, so this module refuses every legacy
shape rather than tolerating one.

What this module owns
---------------------

Typed payload models and strict validation for the §5.3 catalogue rows that the key
lifecycle needs:

===============================  ==========================================
``trust_domain_established``     §5.2 Bootstrap A; restates ``binding_core``
``trust_root_rotated``           §5.4 + WI-280 monotone governance
``registrar_delegated``          §5.4 scoped, expiring online credential
``registrar_revoked``            §5.4
``principal_registered``         §5.3 declares canonical id and kind
``principal_key_enrolled``       §5.5 — ``public_key`` MANDATORY (WI-273)
``principal_key_rotated``        §5.6 — ``supersedes_key_id`` + dual auth
``principal_key_revoked``        §5.7 — prospective by chain position
``trust_domain_custody_declared``  WI-292 custody correction (see below)
===============================  ==========================================

Deliberately **not** here:

* Witness lifecycle (``witness_registered`` and friends) is **CUT from 0.6.0**
  (§7 CUT marker, D-7). The §5.3 rows are struck. Nothing here implements it, and
  ``_witness.py``'s key-lifecycle write paths refuse by name.
* ``bundle_signing_authority_granted`` / ``_revoked`` — sibling C owns which
  principal may sign bundle v3 statements. **Seam for P3.3.**
* ``trust_log_checkpoint_published`` / ``trust_log_checkpoint_observed`` — the
  checkpoint document and its cross-chain import are §4.3/§6.6 publication
  concerns. **Seam for P2.4.**
* ``project_instance_registered``, ``principal_alias_bound``,
  ``legacy_key_binding_attested`` — §2.5/§6 identity and legacy-attestation
  contracts; ``principal_alias_bound`` grammar belongs to P2.3.
* The §5.10/§5.11 verifier decision procedure and chain-order verification of key
  binding (§9 criteria 14/15). This module supplies the payload half those
  criteria stand on; the traversal half is the v6 verifier's (P1.7-adjacent).

Fail-closed posture, inherited from the P2.1 genesis contracts: unknown fields are
rejected at every level, a stated fingerprint that disagrees with the recomputation
is invalid rather than corrected, and every rejection is a :class:`RegistaError`
carrying a machine-readable ``reason`` so tests assert the *named* failure.

Byte-level framings
-------------------

Possession proof v2 (§5.5, verbatim)::

    p                = JCS(challenge_object_including_domain_field)
    possession_input = b"regista.principal-possession.v2\\x00" || uint64be(len(p)) || p

Root-threshold and outgoing-key authorisation over a trust-log payload
(**JUDGMENT CALL — see the module note below**)::

    core                = payload minus {"root_signatures"},
                          with dual_authorization.old_key_signature nulled
    c                   = JCS(core)
    root_sig_input      = b"regista.trust-log.root.v1\\x00"    || uint64be(len(c)) || c
    old_key_sig_input   = b"regista.trust-log.old-key.v1\\x00" || uint64be(len(c)) || c

.. note::

   **Judgment calls this module makes, because the frozen contract does not fix
   them.** Flagged here rather than chosen silently:

   1. §5.4 says a ``trust_root_rotated`` event carries "≥ threshold detached root
      signatures over its own canonical bytes", and `RECONCILIATION.md` Resolution 1
      points at `TRUST-DOMAIN.md`:795-818 for the shape — which is §4.3's
      *document* rule (``root_signatures: []``, an array of
      ``{signer_id, fingerprint, signature}``, with ``signer`` absent for a direct
      root-threshold authorisation). Signatures cannot be inside the bytes they
      sign, so this module excludes ``root_signatures`` from the signed core, the
      way the genesis document excludes ``signatures``/``countersignatures``/
      ``anchors`` (§3.5). The two domain separators above are new and are **not**
      frozen anywhere.
   2. §5.6's ``mode: "dual"`` signature is "by the superseded key over the same
      canonical rotation bytes". Taken literally, ``old_key_signature`` would have
      to sign bytes containing itself, so it is nulled in the core rather than
      removed — the field's presence stays visible in the signed bytes.
   3. §5.5's ``possession_proof`` block carries only ``domain``, ``challenge_id``,
      ``verifier_nonce``, ``enrollment_request_digest`` and ``signature``, but the
      signed object is the *whole* challenge. **The event payload alone is therefore
      insufficient to verify possession** — a verifier must be presented the
      challenge object too. :func:`verify_possession_proof_v2` takes it explicitly
      rather than reconstructing a guess.
   4. §5.3 describes ``trust_domain_established``'s payload only as "restates
      ``binding_core`` and ``trust_domain_core_digest``"; the exact key set is not
      frozen. This module validates the restatement by *canonical-byte equality*
      against the presented genesis document and by recomputing the derivation
      through :mod:`regista._trust_domain`, so it never enumerates signer fields —
      which is what lets WI-292 (custody moving out of ``binding_core`` into a
      top-level ``initial_custody`` block) compose without touching this file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, NoReturn

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._principal_keys import _compute_fingerprint
from ._trust_domain import (
    GovernanceState,
    derive_core_digest,
    derive_governance_mode,
    validate_governance_transition,
)

# ---------------------------------------------------------------------------
# Frozen constants
# ---------------------------------------------------------------------------

#: §5.5 possession proof v2 domain, as it appears in the challenge object's
#: ``domain`` field *and* (with a NUL) as the byte prefix.
POSSESSION_DOMAIN_V2: Final[str] = "regista.principal-possession.v2"
POSSESSION_PREFIX_V2: Final[bytes] = POSSESSION_DOMAIN_V2.encode("ascii") + b"\x00"

#: Judgment call 1/2 (see module docstring): not frozen by the contract.
TRUST_LOG_ROOT_SIG_DOMAIN: Final[bytes] = b"regista.trust-log.root.v1\x00"
TRUST_LOG_OLD_KEY_SIG_DOMAIN: Final[bytes] = b"regista.trust-log.old-key.v1\x00"

#: §5.4: ``not_after`` is mandatory and bounded. The contract says "≤ 400 days".
REGISTRAR_MAX_VALIDITY: Final[timedelta] = timedelta(days=400)

# Transitions this module validates. Closed: an unknown transition is refused,
# never waved through as "some other package's event".
TRUST_DOMAIN_ESTABLISHED: Final[str] = "trust_domain_established"
TRUST_ROOT_ROTATED: Final[str] = "trust_root_rotated"
TRUST_DOMAIN_CUSTODY_DECLARED: Final[str] = "trust_domain_custody_declared"
REGISTRAR_DELEGATED: Final[str] = "registrar_delegated"
REGISTRAR_REVOKED: Final[str] = "registrar_revoked"
PRINCIPAL_REGISTERED: Final[str] = "principal_registered"
PRINCIPAL_KEY_ENROLLED: Final[str] = "principal_key_enrolled"
PRINCIPAL_KEY_ROTATED: Final[str] = "principal_key_rotated"
PRINCIPAL_KEY_REVOKED: Final[str] = "principal_key_revoked"

#: The subset of §5.3 whose payloads this module validates.
TRUST_LOG_TRANSITIONS: Final[frozenset[str]] = frozenset(
    {
        TRUST_DOMAIN_ESTABLISHED,
        TRUST_ROOT_ROTATED,
        TRUST_DOMAIN_CUSTODY_DECLARED,
        REGISTRAR_DELEGATED,
        REGISTRAR_REVOKED,
        PRINCIPAL_REGISTERED,
        PRINCIPAL_KEY_ENROLLED,
        PRINCIPAL_KEY_ROTATED,
        PRINCIPAL_KEY_REVOKED,
    }
)

#: The three transitions that mutate the ``principal_keys`` projection (§5.9).
PROJECTION_DRIVING_TRANSITIONS: Final[frozenset[str]] = frozenset(
    {PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED, PRINCIPAL_KEY_REVOKED}
)

#: §5.2 as AMENDED by Resolution 1: the entity-kind registry is shared and CLOSED
#: at six values (``V6-ENVELOPE.md`` §1.2). ``project_system`` is prose, never a
#: wire value. This module only maps the kinds its own transitions use.
TRUST_LOG_ENTITY_KIND: Final[dict[str, str]] = {
    TRUST_DOMAIN_ESTABLISHED: "trust_domain",
    TRUST_ROOT_ROTATED: "trust_domain",
    TRUST_DOMAIN_CUSTODY_DECLARED: "trust_domain",
    REGISTRAR_DELEGATED: "trust_domain",
    REGISTRAR_REVOKED: "trust_domain",
    PRINCIPAL_REGISTERED: "principal",
    PRINCIPAL_KEY_ENROLLED: "principal",
    PRINCIPAL_KEY_ROTATED: "principal",
    PRINCIPAL_KEY_REVOKED: "principal",
}

# Witness lifecycle transitions, retained ONLY so a payload naming one is refused
# with the CUT reason rather than an anonymous "unknown transition" (§7, D-7).
WITNESS_LIFECYCLE_TRANSITIONS_CUT: Final[frozenset[str]] = frozenset(
    {
        "witness_registered",
        "witness_key_rotated",
        "witness_paused",
        "witness_resumed",
        "witness_revoked",
    }
)

#: Seams named explicitly so a caller gets a pointer, not a generic refusal.
DEFERRED_TRANSITIONS: Final[dict[str, str]] = {
    "bundle_signing_authority_granted": "sibling C / P3.3 (bundle v3 signing authority)",
    "bundle_signing_authority_revoked": "sibling C / P3.3 (bundle v3 signing authority)",
    "trust_log_checkpoint_published": "P2.4 (§4.3 publication)",
    "trust_log_checkpoint_observed": "P2.4 / §6.6 (cross-chain checkpoint import)",
    "project_instance_registered": "P2.4 (§4.3 publication catalogue)",
    "principal_alias_bound": "P2.3 (§2.5 identity grammar and alias scope)",
    "legacy_key_binding_attested": "§6 retrospective attestation (not P2.2)",
    "principal_key_accepted": "P1.7 (§5.8 project-local acceptance)",
    "principal_key_acceptance_revoked": "P1.7 (§5.8 project-local acceptance)",
}

# Closed value sets. Widening any of these is a spec change, not a patch.
_SCHEME_IDS: Final[frozenset[str]] = frozenset({"ed25519"})
_AUTHORITIES: Final[frozenset[str]] = frozenset({"root", "registrar"})
_PRINCIPAL_KINDS: Final[frozenset[str]] = frozenset({"human", "agent", "service"})
_CUSTODY_BACKENDS: Final[frozenset[str]] = frozenset(
    {"vault", "azure", "windows", "file", "operator"}
)
_REVOCATION_REASONS: Final[frozenset[str]] = frozenset(
    {"compromised", "superseded", "decommissioned", "policy", "unspecified"}
)
_ROTATION_MODES: Final[frozenset[str]] = frozenset({"dual", "recovery"})
_RECOVERY_REASONS: Final[frozenset[str]] = frozenset(
    {"key-lost", "key-compromised", "custody-migration"}
)
#: §5.4: a registrar's scopes are lifecycle administration only. Action delegation
#: is a *different* credential (§5.12) and the two are never interchangeable — a
#: credential minted for key administration must not be able to sign business
#: events, which is the "scope creep by field reuse" shape 0.6.0 exists to remove.
_REGISTRAR_SCOPES: Final[frozenset[str]] = frozenset(
    {PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED, PRINCIPAL_KEY_REVOKED,
     PRINCIPAL_REGISTERED}
)
_EFFECTIVE_FROM_KINDS: Final[frozenset[str]] = frozenset({"on_chain_position"})

_PAYLOAD_TYPES: Final[dict[str, tuple[str, int]]] = {
    TRUST_DOMAIN_ESTABLISHED: ("regista.trust-domain-established", 1),
    TRUST_ROOT_ROTATED: ("regista.trust-root-rotation", 1),
    TRUST_DOMAIN_CUSTODY_DECLARED: ("regista.trust-domain-custody", 1),
    REGISTRAR_DELEGATED: ("regista.registrar-delegation", 1),
    REGISTRAR_REVOKED: ("regista.registrar-revocation", 1),
    PRINCIPAL_REGISTERED: ("regista.principal-registration", 1),
    PRINCIPAL_KEY_ENROLLED: ("regista.key-enrollment", 1),
    PRINCIPAL_KEY_ROTATED: ("regista.key-rotation", 1),
    PRINCIPAL_KEY_REVOKED: ("regista.key-revocation", 1),
}

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_FINGERPRINT_RE = re.compile(r"[a-z0-9-]+:sha256:[0-9a-f]{64}")
_KEY_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_NONCE_RE = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")

_ED25519_PUBLIC_KEY_LEN: Final[int] = 32
_ED25519_SIGNATURE_LEN: Final[int] = 64


# ---------------------------------------------------------------------------
# Failure helpers — the reason string is the assertion surface
# ---------------------------------------------------------------------------


def _fail(code: ErrorCode, message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(code, message, {"reason": reason, **detail})


def _require(condition: bool, message: str, reason: str, **detail: Any) -> None:
    if not condition:
        _fail(ErrorCode.TRUST_LOG_PAYLOAD_INVALID, message, reason, **detail)


def _require_authority(condition: bool, message: str, reason: str, **detail: Any) -> None:
    if not condition:
        _fail(ErrorCode.TRUST_LOG_AUTHORITY_INVALID, message, reason, **detail)


def _require_keys(value: Any, expected: frozenset[str], path: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{path} must be an object", "not_an_object", path=path)
    assert isinstance(value, Mapping)
    actual = frozenset(value)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    _require(
        not unknown and not missing,
        f"{path} keys must be exactly {sorted(expected)!r}; "
        f"unknown={unknown!r} missing={missing!r}",
        "unknown_or_missing_field",
        path=path,
        unknown=unknown,
        missing=missing,
    )
    return value


def _require_string(value: Any, path: str) -> str:
    _require(isinstance(value, str), f"{path} must be a string", "not_a_string", path=path)
    _require(bool(str(value).strip()), f"{path} must be non-empty", "empty_string", path=path)
    return str(value)


def _require_pattern(value: Any, pattern: re.Pattern[str], path: str, what: str) -> str:
    text = _require_string(value, path)
    _require(
        pattern.fullmatch(text) is not None,
        f"{path} must be {what}",
        "malformed_value",
        path=path,
    )
    return text


def _require_int(value: Any, path: str) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{path} must be an integer",
        "not_an_integer",
        path=path,
    )
    return int(value)


def _require_bool(value: Any, path: str) -> bool:
    _require(isinstance(value, bool), f"{path} must be a boolean", "not_a_boolean", path=path)
    return bool(value)


def _require_uuid(value: Any, path: str) -> str:
    text = _require_string(value, path)
    try:
        parsed = _uuid.UUID(text)
    except (ValueError, TypeError) as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"{path} must be a canonical UUID string",
            {"reason": "malformed_uuid", "path": path},
        ) from exc
    _require(
        str(parsed) == text,
        f"{path} must use lowercase canonical UUID text",
        "non_canonical_uuid",
        path=path,
    )
    return text


def _require_base64(value: Any, path: str, *, expected_len: int) -> bytes:
    text = _require_string(value, path)
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"{path} must be standard base64",
            {"reason": "malformed_base64", "path": path},
        ) from exc
    _require(
        len(raw) == expected_len,
        f"{path} must decode to exactly {expected_len} bytes, got {len(raw)}",
        "wrong_key_length" if expected_len == _ED25519_PUBLIC_KEY_LEN
        else "wrong_signature_length",
        path=path,
    )
    # One base64 spelling per byte string, so the signed bytes admit no aliasing.
    _require(
        base64.b64encode(raw).decode("ascii") == text,
        f"{path} must be canonical (padded, no alternate alphabet) base64",
        "non_canonical_base64",
        path=path,
    )
    return raw


def _require_timestamp(value: Any, path: str) -> datetime:
    text = _require_pattern(
        value, _TIMESTAMP_RE, path, "a microsecond-precision UTC Z timestamp"
    )
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(UTC)


def _require_scheme(value: Any, path: str) -> str:
    scheme = _require_string(value, path)
    _require(
        scheme in _SCHEME_IDS,
        f"{path} must be one of {sorted(_SCHEME_IDS)!r}: the trust log is Ed25519 "
        "from its genesis event and has no legacy epoch (§5.2)",
        "unsupported_scheme",
        path=path,
        scheme_id=scheme,
    )
    return scheme


def _require_string_list(value: Any, path: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    _require(isinstance(value, list), f"{path} must be an array", "not_an_array", path=path)
    assert isinstance(value, list)
    _require(
        allow_empty or bool(value),
        f"{path} must be a non-empty array",
        "empty_array",
        path=path,
    )
    return tuple(_require_string(v, f"{path}[{i}]") for i, v in enumerate(value))


# ---------------------------------------------------------------------------
# Signed-core framing (judgment calls 1 and 2)
# ---------------------------------------------------------------------------


def trust_log_authorization_core(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The payload as the detached authorisation signatures see it.

    ``root_signatures`` is removed and ``dual_authorization.old_key_signature`` is
    nulled: a signature cannot be inside the bytes it signs, and the genesis
    document already establishes the "exclude the signature sections" pattern
    (§3.5). Nulling rather than deleting keeps the field's *presence* — the
    difference between "recovery, no outgoing-key signature" and "dual" — inside
    the signed bytes.
    """
    core = {k: v for k, v in payload.items() if k != "root_signatures"}
    dual = core.get("dual_authorization")
    if isinstance(dual, Mapping):
        core["dual_authorization"] = {
            **{k: v for k, v in dual.items() if k != "old_key_signature"},
            "old_key_signature": None,
        }
    return core


def _framed(domain: bytes, core: Mapping[str, Any]) -> bytes:
    body = canonicalize(dict(core))
    return domain + struct.pack(">Q", len(body)) + body


def root_signature_input(payload: Mapping[str, Any]) -> bytes:
    """Bytes each detached root signature covers (§5.4; judgment call 1)."""
    return _framed(TRUST_LOG_ROOT_SIG_DOMAIN, trust_log_authorization_core(payload))


def old_key_signature_input(payload: Mapping[str, Any]) -> bytes:
    """Bytes the superseded key signs for ``mode: dual`` (§5.6; judgment call 2)."""
    return _framed(TRUST_LOG_OLD_KEY_SIG_DOMAIN, trust_log_authorization_core(payload))


# ---------------------------------------------------------------------------
# Ed25519 verification
# ---------------------------------------------------------------------------


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        import nacl.exceptions
        import nacl.signing
    except ImportError as exc:  # pragma: no cover - extras always present in CI
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "trust-log verification requires PyNaCl: pip install regista[ed25519]",
        ) from exc
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False
    return True


# ---------------------------------------------------------------------------
# Possession proof v2 (§5.5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PossessionChallengeV2:
    """The v2 possession challenge object.

    v2 keeps v1's object shape (``principal_lifecycle.PossessionChallenge``,
    including the in-object ``domain`` field) and adds ``trust_domain_id`` and
    ``enrollment_request_digest``, then changes the framing to the byte-prefix form
    used everywhere else in v6 (§5.5, D-9: belt-and-braces, deliberately).
    """

    challenge_id: str
    operation_id: str
    operation_digest: str
    project: str
    trust_domain_id: str
    principal_id: str
    fingerprint: str
    scheme: str
    verifier_nonce: str
    enrollment_request_digest: str
    issued_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": POSSESSION_DOMAIN_V2,
            "challenge_id": self.challenge_id,
            "operation_id": self.operation_id,
            "operation_digest": self.operation_digest,
            "project": self.project,
            "trust_domain_id": self.trust_domain_id,
            "principal_id": self.principal_id,
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "verifier_nonce": self.verifier_nonce,
            "enrollment_request_digest": self.enrollment_request_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def signing_input(self) -> bytes:
        """``b"regista.principal-possession.v2\\x00" || uint64be(len(p)) || p``."""
        return _framed(POSSESSION_PREFIX_V2, self.to_dict())


@dataclass(frozen=True)
class PossessionProofV2:
    """The ``possession_proof`` block as it appears in a §5.5 payload."""

    domain: str
    challenge_id: str
    verifier_nonce: str
    enrollment_request_digest: str
    signature: bytes


_POSSESSION_PROOF_KEYS = frozenset(
    {"domain", "challenge_id", "verifier_nonce", "enrollment_request_digest", "signature"}
)


def _parse_possession_proof(value: Any, path: str) -> PossessionProofV2:
    raw = _require_keys(value, _POSSESSION_PROOF_KEYS, path)
    domain = _require_string(raw["domain"], f"{path}.domain")
    _require(
        domain == POSSESSION_DOMAIN_V2,
        f'{path}.domain must be "{POSSESSION_DOMAIN_V2}"; v1 framing put the domain '
        "inside the object only, and enrolment through this contract requires v2",
        "possession_domain_not_v2",
        path=f"{path}.domain",
        stated=domain,
    )
    return PossessionProofV2(
        domain=domain,
        challenge_id=_require_uuid(raw["challenge_id"], f"{path}.challenge_id"),
        verifier_nonce=_require_pattern(
            raw["verifier_nonce"],
            _NONCE_RE,
            f"{path}.verifier_nonce",
            "64 lowercase hex characters",
        ),
        enrollment_request_digest=_require_pattern(
            raw["enrollment_request_digest"],
            _DIGEST_RE,
            f"{path}.enrollment_request_digest",
            "sha256:<64 lowercase hex characters>",
        ),
        signature=_require_base64(
            raw["signature"], f"{path}.signature", expected_len=_ED25519_SIGNATURE_LEN
        ),
    )


def verify_possession_proof_v2(
    payload: Mapping[str, Any],
    challenge: PossessionChallengeV2,
) -> None:
    """Verify a §5.5 possession proof against the challenge it answers.

    The challenge is a **required argument**: the payload's ``possession_proof``
    block carries only an identifying subset, so the event alone cannot determine
    the signed bytes (judgment call 3). Raises with a named reason on any
    disagreement; returns ``None`` on success.

    Proves the enroller holds the private half of the key **in this payload**. It
    proves nothing about who the enroller *is* — that comes from ``authorized_by``.
    Both are required; neither substitutes for the other (§5.5).
    """
    _require(
        isinstance(payload, Mapping),
        "payload must be an object",
        "not_an_object",
        path="payload",
    )
    for required in ("possession_proof", "public_key", "trust_domain_id",
                     "principal_id", "fingerprint"):
        _require(
            required in payload,
            f"payload.{required} is required to verify a possession proof",
            "unknown_or_missing_field",
            path=required,
        )
    proof = _parse_possession_proof(payload["possession_proof"], "possession_proof")
    public_key = _require_base64(
        payload["public_key"], "public_key", expected_len=_ED25519_PUBLIC_KEY_LEN
    )
    trust_domain_id = _require_uuid(payload["trust_domain_id"], "trust_domain_id")
    principal_id = _require_string(payload["principal_id"], "principal_id")
    fingerprint = _require_string(payload["fingerprint"], "fingerprint")

    for field_name, expected, actual in (
        ("challenge_id", challenge.challenge_id, proof.challenge_id),
        ("verifier_nonce", challenge.verifier_nonce, proof.verifier_nonce),
        (
            "enrollment_request_digest",
            challenge.enrollment_request_digest,
            proof.enrollment_request_digest,
        ),
        ("trust_domain_id", challenge.trust_domain_id, trust_domain_id),
        ("principal_id", challenge.principal_id, principal_id),
        ("fingerprint", challenge.fingerprint, fingerprint),
    ):
        _require_authority(
            expected == actual,
            f"possession proof {field_name} does not match the challenge it answers",
            "possession_challenge_binding_mismatch",
            field=field_name,
            challenge=expected,
            payload=actual,
        )

    _require_authority(
        _verify_ed25519(public_key, challenge.signing_input(), proof.signature),
        "possession proof does not verify under the public_key being enrolled",
        "possession_proof_verification_failed",
        challenge_id=proof.challenge_id,
    )


# ---------------------------------------------------------------------------
# Root-threshold authorisation (§5.4, Resolution 1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RootSignature:
    signer_id: str
    fingerprint: str
    signature: bytes


_ROOT_SIGNATURE_KEYS = frozenset({"signer_id", "fingerprint", "signature"})


def _parse_root_signatures(value: Any, path: str) -> tuple[RootSignature, ...]:
    _require(isinstance(value, list), f"{path} must be an array", "not_an_array", path=path)
    assert isinstance(value, list)
    out: list[RootSignature] = []
    for i, entry in enumerate(value):
        item_path = f"{path}[{i}]"
        raw = _require_keys(entry, _ROOT_SIGNATURE_KEYS, item_path)
        out.append(
            RootSignature(
                signer_id=_require_string(raw["signer_id"], f"{item_path}.signer_id"),
                fingerprint=_require_pattern(
                    raw["fingerprint"],
                    _FINGERPRINT_RE,
                    f"{item_path}.fingerprint",
                    "<scheme_id>:sha256:<64 lowercase hex>",
                ),
                signature=_require_base64(
                    raw["signature"], f"{item_path}.signature",
                    expected_len=_ED25519_SIGNATURE_LEN,
                ),
            )
        )
    fingerprints = [s.fingerprint for s in out]
    _require(
        len(set(fingerprints)) == len(fingerprints),
        f"{path} entries must have pairwise-distinct fingerprints: two entries by "
        "the same signer cannot raise the distinct-signer count",
        "duplicate_root_signature",
        path=path,
    )
    return tuple(out)


def verify_root_threshold(
    payload: Mapping[str, Any],
    governance: GovernanceState,
    public_keys: Mapping[str, bytes],
    *,
    required_threshold: int | None = None,
) -> tuple[str, ...]:
    """Verify ≥ threshold detached root signatures by keys in the *current* set.

    ``public_keys`` maps fingerprint -> raw 32-byte Ed25519 public key. Returns the
    verified fingerprints. A signature that does not verify, or whose fingerprint is
    not in the current signer set, makes the event INVALID — never "bad signature
    ignored", because silently dropping one turns a k-of-n check into a 1-of-n check
    (§3.4, applied to the log).
    """
    threshold = governance.threshold if required_threshold is None else required_threshold
    signatures = _parse_root_signatures(payload.get("root_signatures"), "root_signatures")
    message = root_signature_input(payload)
    current = set(governance.signer_fingerprints)
    verified: list[str] = []
    for i, entry in enumerate(signatures):
        path = f"root_signatures[{i}]"
        _require_authority(
            entry.fingerprint in current,
            f"{path}.fingerprint is not in the current root signer set",
            "root_signer_not_current",
            path=path,
            fingerprint=entry.fingerprint,
        )
        key = public_keys.get(entry.fingerprint)
        _require_authority(
            key is not None,
            f"{path}.fingerprint has no public key in the presented trust material",
            "root_public_key_unavailable",
            path=path,
            fingerprint=entry.fingerprint,
        )
        assert key is not None
        _require_authority(
            _verify_ed25519(key, message, entry.signature),
            f"{path} does not verify over the trust-log root signature input",
            "root_signature_invalid",
            path=path,
            fingerprint=entry.fingerprint,
        )
        verified.append(entry.fingerprint)
    _require_authority(
        len(verified) >= threshold,
        f"{len(verified)} verified root signature(s); threshold is {threshold}",
        "root_threshold_not_met",
        verified=len(verified),
        threshold=threshold,
    )
    return tuple(verified)


# ---------------------------------------------------------------------------
# Bootstrap A (§5.2 AMENDED, RECONCILIATION.md Resolution 1)
# ---------------------------------------------------------------------------


def validate_key_binding_bootstrap(
    transition: str,
    key_binding_event_hash: str | None,
    *,
    event_seq: int | None = None,
    payload: Mapping[str, Any] | None = None,
    genesis_document: Mapping[str, Any] | None = None,
    root_public_keys: Mapping[str, bytes] | None = None,
    signer_fingerprint: str | None = None,
) -> None:
    """A-prime Bootstrap A: which trust-log event may carry a null key binding.

    ``trust_domain_established`` is the first v6 event in the log and the only one
    with a null ``signing.key_binding_event_hash`` (Resolution 1). Its authorisation
    is **external** and is proven here, on presented evidence, with no absent-
    evidence pass:

    * the event is chain position 1;
    * the pinned genesis document fully threshold-verifies and carries a **null**
      ``trust_log.initial_head_event_hash`` (the genesis event hash is pinned later
      by the checkpoint, not by the document);
    * the event payload is a strict ``trust_domain_established`` restatement whose
      ``genesis_document_digest`` equals the recomputed digest over the exact
      published document bytes (A-prime);
    * the envelope signer's fingerprint is a genesis root (transport attribution);
    * the payload's detached ``root_signatures`` meet the initial root threshold over
      ``root_signature_input(payload)`` — the authority proof; and no earlier event
      precedes it.

    None of these is waved through: absent evidence is a named refusal.
    """
    if key_binding_event_hash is not None:
        _require_pattern(
            key_binding_event_hash,
            _DIGEST_RE,
            "signing.key_binding_event_hash",
            "sha256:<64 lowercase hex characters> or null",
        )
        _require(
            transition != TRUST_DOMAIN_ESTABLISHED,
            "trust_domain_established must carry "
            "signing.key_binding_event_hash = null: it is the first v6 event in the "
            "log and has no predecessor acceptance to name (§5.2 Bootstrap A)",
            "bootstrap_hash_must_be_null",
            transition=transition,
        )
        return

    if transition != TRUST_DOMAIN_ESTABLISHED:
        _fail(
            ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED,
            f"signing.key_binding_event_hash = null is not permitted on "
            f"{transition!r}: Bootstrap A admits exactly one null in the trust log, "
            "on trust_domain_established (RECONCILIATION.md Resolution 1)",
            "KEY_BINDING_BOOTSTRAP_NOT_PERMITTED",
            transition=transition,
        )

    _require_authority(
        genesis_document is not None and payload is not None,
        "Bootstrap A requires the pinned genesis document and the "
        "trust_domain_established payload; absent evidence is refused",
        "bootstrap_evidence_not_presented",
        genesis_document_present=genesis_document is not None,
        payload_present=payload is not None,
    )
    assert genesis_document is not None and payload is not None

    from ._trust_domain import (
        GovernanceState,
        genesis_document_digest,
        parse_trust_genesis,
        verify_trust_genesis,
    )

    doc = parse_trust_genesis(genesis_document)
    report = verify_trust_genesis(genesis_document)
    _require_authority(
        report.signatures_verified >= report.root_governance.threshold,
        f"{report.signatures_verified} verified genesis document signature(s); "
        f"threshold is {report.root_governance.threshold}",
        "genesis_document_threshold_not_met",
        verified=report.signatures_verified,
        threshold=report.root_governance.threshold,
    )
    _require_authority(
        genesis_document.get("trust_log", {}).get("initial_head_event_hash") is None,
        "a v1 trust genesis must carry trust_log.initial_head_event_hash = null; "
        "the genesis event hash is pinned by the checkpoint, not the document",
        "genesis_head_must_be_null",
    )
    _require_authority(
        event_seq is not None,
        "Bootstrap A requires the event's chain position",
        "bootstrap_event_seq_not_presented",
    )
    _require_authority(
        event_seq == 1,
        "trust_domain_established must be the first event in the log (chain "
        "position 1)",
        "bootstrap_event_not_position_one",
        event_seq=event_seq,
    )
    established = parse_trust_domain_established(payload)
    recomputed_digest = genesis_document_digest(genesis_document)
    _require_authority(
        established.genesis_document_digest == recomputed_digest,
        "the event payload's genesis_document_digest disagrees with the recomputed "
        "digest over the published genesis document bytes",
        "genesis_document_digest_mismatch",
        stated=established.genesis_document_digest,
        recomputed=recomputed_digest,
    )
    document_roots = {s.fingerprint for s in doc.signers}
    _require_authority(
        signer_fingerprint is not None and signer_fingerprint in document_roots,
        "trust_domain_established is not signed by a genesis root key",
        "bootstrap_signer_not_a_root_key",
        signer_fingerprint=signer_fingerprint,
    )
    _require_authority(
        root_public_keys is not None,
        "Bootstrap A requires the genesis root public keys to verify the detached "
        "payload signatures",
        "bootstrap_root_keys_not_presented",
    )
    assert root_public_keys is not None
    governance = GovernanceState(
        threshold=doc.initial_governance.threshold,
        signer_fingerprints=tuple(s.fingerprint for s in doc.signers),
    )
    verified = verify_root_threshold(
        payload, governance, root_public_keys
    )
    _require_authority(
        len(verified) >= doc.initial_governance.threshold,
        f"{len(verified)} verified root signature(s); initial threshold is "
        f"{doc.initial_governance.threshold}",
        "root_threshold_not_met",
        verified=len(verified),
        threshold=doc.initial_governance.threshold,
    )


# ---------------------------------------------------------------------------
# Typed payload models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyMaterial:
    """The key-material fields shared by enrolment and rotation (§5.5)."""

    key_id: str
    scheme_id: str
    public_key: bytes
    fingerprint: str


@dataclass(frozen=True)
class AuthorizedBy:
    authority: str
    principal_id: str
    key_id: str
    delegation_event_hash: str | None


@dataclass(frozen=True)
class CustodyDeclaration:
    """Unverified operator claims (§11 obligation 2, OPERATOR-FORGERY R1)."""

    declared_backend: str
    declared_policy_ref: str


@dataclass(frozen=True)
class DualAuthorization:
    old_key_signature: bytes | None
    mode: str
    recovery_reason: str | None


@dataclass(frozen=True)
class RetroactiveSuspicion:
    """§5.7. Never turns a valid signature invalid or an invalid one valid."""

    declared: bool
    suspect_from_event_hash: str | None
    note: str | None


@dataclass(frozen=True)
class TrustDomainEstablished:
    trust_domain_id: str
    trust_domain_core_digest: str
    binding_core: Mapping[str, Any]
    initial_governance: Mapping[str, Any]
    genesis_document_digest: str
    trust_log_project_instance_id: str
    root_signatures: tuple[RootSignature, ...]

    @property
    def governance_state(self) -> GovernanceState:
        """The genesis governance, as the starting point for §5.4 replay.

        Signer fingerprints are read out of the restated ``binding_core`` without
        assuming anything else about a signer entry (WI-292-safe).
        """
        signers = self.binding_core["signers"]
        return GovernanceState(
            threshold=int(self.initial_governance["threshold"]),
            signer_fingerprints=tuple(str(s["fingerprint"]) for s in signers),
        )


@dataclass(frozen=True)
class TrustRootRotated:
    trust_domain_id: str
    added: tuple[Mapping[str, Any], ...]
    removed: tuple[str, ...]
    reason: str
    effective_from_checkpoint_seq: int
    new_threshold: int
    root_signatures: tuple[RootSignature, ...]


@dataclass(frozen=True)
class TrustDomainCustodyDeclared:
    """WI-292: custody declarations live outside ``binding_core``.

    Custody moved out of the signed identity core into a mandatory top-level
    ``initial_custody`` block, with post-genesis corrections as threshold-authorised
    trust-log events. This is that event.

    Two rules make it a *correction* rather than a rewrite:

    * ``supersedes_declaration_digest`` names the declaration being replaced, so the
      superseded declaration is preserved by reference and the chain of who claimed
      what, when, stays reconstructible. Deleting the prior claim is not a
      correction, it is a rewrite.
    * ``declaration_seq`` is strictly monotone per trust domain, so two concurrent
      corrections cannot silently interleave into an ambiguous "current" custody.
      Enforced across a sequence by :func:`replay_custody_declarations`, which is
      where "monotone" can actually be checked — a single payload can only assert
      its own seq and the digest it supersedes.

    Custody remains an **unverified operator claim** at every version
    (OPERATOR-FORGERY R1); correcting it changes what is claimed, never what is
    proven. ``trust_domain_id`` does not move and no epoch changes.

    Entry shape and invariants deliberately mirror the genesis document's mandatory
    top-level ``initial_custody`` block (WI-292): ``{fingerprint, declared_mode,
    declared_holder, attestation}``, keyed by signer fingerprint, pairwise distinct,
    sorted ascending. A correction that did not satisfy the declaration's own rules
    would not be comparable to the thing it replaces. The named reasons
    (``custody_not_a_list``, ``duplicate_custody_fingerprint``,
    ``custody_not_sorted``) match the genesis block's spellings for the same faults.
    """

    trust_domain_id: str
    declaration_seq: int
    supersedes_declaration_digest: str | None
    custody: tuple[Mapping[str, Any], ...]
    reason: str
    root_signatures: tuple[RootSignature, ...]


@dataclass(frozen=True)
class RegistrarDelegated:
    trust_domain_id: str
    registrar_principal_id: str
    key: KeyMaterial
    scopes: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    max_operations: int | None
    root_signatures: tuple[RootSignature, ...]


@dataclass(frozen=True)
class RegistrarRevoked:
    trust_domain_id: str
    registrar_principal_id: str
    key_id: str
    delegation_event_hash: str
    reason: str
    root_signatures: tuple[RootSignature, ...]


@dataclass(frozen=True)
class PrincipalRegistered:
    trust_domain_id: str
    principal_id: str
    principal_kind: str
    authorized_by: AuthorizedBy


@dataclass(frozen=True)
class PrincipalKeyEnrolled:
    trust_domain_id: str
    principal_id: str
    principal_kind: str
    key: KeyMaterial
    not_before: datetime
    not_after: datetime | None
    possession_proof: PossessionProofV2
    authorized_by: AuthorizedBy
    custody: CustodyDeclaration
    supersedes_key_id: str | None


@dataclass(frozen=True)
class PrincipalKeyRotated:
    trust_domain_id: str
    principal_id: str
    principal_kind: str
    key: KeyMaterial
    not_before: datetime
    not_after: datetime | None
    possession_proof: PossessionProofV2
    authorized_by: AuthorizedBy
    custody: CustodyDeclaration
    supersedes_key_id: str
    dual_authorization: DualAuthorization
    root_signatures: tuple[RootSignature, ...]

    @property
    def is_recovery(self) -> bool:
        return self.dual_authorization.mode == "recovery"


@dataclass(frozen=True)
class PrincipalKeyRevoked:
    trust_domain_id: str
    principal_id: str
    key_id: str
    reason: str
    revoked_at: datetime
    effective_from_kind: str
    effective_from_event_hash: str
    retroactive_suspicion: RetroactiveSuspicion
    authorized_by: AuthorizedBy


TrustLogPayload = (
    TrustDomainEstablished
    | TrustRootRotated
    | TrustDomainCustodyDeclared
    | RegistrarDelegated
    | RegistrarRevoked
    | PrincipalRegistered
    | PrincipalKeyEnrolled
    | PrincipalKeyRotated
    | PrincipalKeyRevoked
)


# ---------------------------------------------------------------------------
# Shared sub-object parsers
# ---------------------------------------------------------------------------

_AUTHORIZED_BY_KEYS = frozenset(
    {"authority", "principal_id", "key_id", "delegation_event_hash"}
)
_CUSTODY_KEYS = frozenset({"declared_backend", "declared_policy_ref"})
_DUAL_AUTH_KEYS = frozenset({"old_key_signature", "mode", "recovery_reason"})
_RETRO_KEYS = frozenset({"declared", "suspect_from_event_hash", "note"})
_EFFECTIVE_FROM_KEYS = frozenset({"kind", "trust_log_event_hash"})


def _parse_key_material(raw: Mapping[str, Any], path: str = "") -> KeyMaterial:
    """Parse and cross-check the key-material fields.

    ``public_key`` is **mandatory and is the fix for Defect A** (§5.1/§5.5, WI-273):
    a verifier replaying enrolment events must be able to *obtain* the key, not
    merely check a candidate against a fingerprint. ``fingerprint`` must equal the
    recomputation from the bytes; disagreement is invalid, because the fingerprint
    is a convenience and the bytes are the artifact.
    """
    prefix = f"{path}." if path else ""
    scheme_id = _require_scheme(raw["scheme_id"], f"{prefix}scheme_id")
    public_key = _require_base64(
        raw["public_key"], f"{prefix}public_key", expected_len=_ED25519_PUBLIC_KEY_LEN
    )
    fingerprint = _require_pattern(
        raw["fingerprint"],
        _FINGERPRINT_RE,
        f"{prefix}fingerprint",
        "<scheme_id>:sha256:<64 lowercase hex>",
    )
    recomputed = _compute_fingerprint(public_key, scheme_id)
    _require(
        fingerprint == recomputed,
        f"{prefix}fingerprint does not match the fingerprint recomputed from "
        f"{prefix}public_key",
        "fingerprint_mismatch",
        path=f"{prefix}fingerprint",
        stated=fingerprint,
        recomputed=recomputed,
    )
    return KeyMaterial(
        key_id=_require_pattern(
            raw["key_id"], _KEY_ID_RE, f"{prefix}key_id", "1-128 chars of [A-Za-z0-9._:-]"
        ),
        scheme_id=scheme_id,
        public_key=public_key,
        fingerprint=fingerprint,
    )


def _parse_authorized_by(value: Any, path: str) -> AuthorizedBy:
    raw = _require_keys(value, _AUTHORIZED_BY_KEYS, path)
    authority = _require_string(raw["authority"], f"{path}.authority")
    _require(
        authority in _AUTHORITIES,
        f"{path}.authority must be one of {sorted(_AUTHORITIES)!r}",
        "unknown_authority",
        path=f"{path}.authority",
        stated=authority,
    )
    delegation = raw["delegation_event_hash"]
    if delegation is not None:
        delegation = _require_pattern(
            delegation,
            _DIGEST_RE,
            f"{path}.delegation_event_hash",
            "sha256:<64 lowercase hex characters> or null",
        )
    # A registrar authorisation MUST name the delegation event that created it:
    # without it there is nothing to check the scope and expiry against, and an
    # unbounded "registrar says so" is the online-takeover path Resolution 5 closes.
    _require(
        authority != "registrar" or delegation is not None,
        f"{path}.delegation_event_hash is required when authority is 'registrar': "
        "the delegation event is what bounds the credential's scope and expiry (§5.4)",
        "registrar_delegation_hash_missing",
        path=f"{path}.delegation_event_hash",
    )
    _require(
        authority != "root" or delegation is None,
        f"{path}.delegation_event_hash must be null when authority is 'root': the "
        "root is not delegated to",
        "root_authority_has_delegation_hash",
        path=f"{path}.delegation_event_hash",
    )
    return AuthorizedBy(
        authority=authority,
        principal_id=_require_string(raw["principal_id"], f"{path}.principal_id"),
        key_id=_require_pattern(
            raw["key_id"], _KEY_ID_RE, f"{path}.key_id", "1-128 chars of [A-Za-z0-9._:-]"
        ),
        delegation_event_hash=delegation,
    )


def _parse_custody(value: Any, path: str) -> CustodyDeclaration:
    raw = _require_keys(value, _CUSTODY_KEYS, path)
    backend = _require_string(raw["declared_backend"], f"{path}.declared_backend")
    _require(
        backend in _CUSTODY_BACKENDS,
        f"{path}.declared_backend must be one of {sorted(_CUSTODY_BACKENDS)!r}",
        "unknown_custody_backend",
        path=f"{path}.declared_backend",
        stated=backend,
    )
    return CustodyDeclaration(
        declared_backend=backend,
        declared_policy_ref=_require_string(
            raw["declared_policy_ref"], f"{path}.declared_policy_ref"
        ),
    )


def _parse_dual_authorization(value: Any, path: str) -> DualAuthorization:
    raw = _require_keys(value, _DUAL_AUTH_KEYS, path)
    mode = _require_string(raw["mode"], f"{path}.mode")
    _require(
        mode in _ROTATION_MODES,
        f"{path}.mode must be one of {sorted(_ROTATION_MODES)!r}",
        "unknown_rotation_mode",
        path=f"{path}.mode",
        stated=mode,
    )
    old_sig = raw["old_key_signature"]
    if old_sig is not None:
        old_sig = _require_base64(
            old_sig, f"{path}.old_key_signature", expected_len=_ED25519_SIGNATURE_LEN
        )
    recovery_reason = raw["recovery_reason"]
    if recovery_reason is not None:
        recovery_reason = _require_string(recovery_reason, f"{path}.recovery_reason")
        _require(
            recovery_reason in _RECOVERY_REASONS,
            f"{path}.recovery_reason must be one of {sorted(_RECOVERY_REASONS)!r} or null",
            "unknown_recovery_reason",
            path=f"{path}.recovery_reason",
            stated=recovery_reason,
        )
    if mode == "dual":
        # The outgoing-key signature is what proves the rotation was requested by
        # the holder of the key being replaced, not merely by the registrar (§5.6).
        _require(
            old_sig is not None,
            f"{path}.old_key_signature is required when mode is 'dual'",
            "dual_mode_missing_old_key_signature",
            path=f"{path}.old_key_signature",
        )
        _require(
            recovery_reason is None,
            f"{path}.recovery_reason must be null when mode is 'dual'",
            "dual_mode_has_recovery_reason",
            path=f"{path}.recovery_reason",
        )
    else:
        _require(
            recovery_reason is not None,
            f"{path}.recovery_reason is required when mode is 'recovery': every "
            "recovery carries a reason and stays visibly classified (§5.6, D-8)",
            "recovery_mode_missing_reason",
            path=f"{path}.recovery_reason",
        )
    return DualAuthorization(
        old_key_signature=old_sig, mode=mode, recovery_reason=recovery_reason
    )


def _parse_retroactive_suspicion(value: Any, path: str) -> RetroactiveSuspicion:
    raw = _require_keys(value, _RETRO_KEYS, path)
    declared = _require_bool(raw["declared"], f"{path}.declared")
    suspect_from = raw["suspect_from_event_hash"]
    if suspect_from is not None:
        suspect_from = _require_pattern(
            suspect_from,
            _DIGEST_RE,
            f"{path}.suspect_from_event_hash",
            "sha256:<64 lowercase hex characters> or null",
        )
    note = raw["note"]
    if note is not None:
        note = _require_string(note, f"{path}.note")
    _require(
        declared or (suspect_from is None and note is None),
        f"{path} must not carry a suspect range or note unless declared is true",
        "undeclared_suspicion_has_detail",
        path=path,
    )
    _require(
        not declared or suspect_from is not None,
        f"{path}.suspect_from_event_hash is required when declared is true: a "
        "suspicion without a range is not a disclosure",
        "declared_suspicion_missing_range",
        path=f"{path}.suspect_from_event_hash",
    )
    return RetroactiveSuspicion(
        declared=declared, suspect_from_event_hash=suspect_from, note=note
    )


def _require_payload_type(raw: Mapping[str, Any], transition: str) -> None:
    expected_type, expected_version = _PAYLOAD_TYPES[transition]
    _require(
        raw["type"] == expected_type,
        f'payload.type must be "{expected_type}" for {transition}',
        "wrong_payload_type",
        path="type",
        stated=raw["type"],
        expected=expected_type,
    )
    _require(
        _require_int(raw["version"], "version") == expected_version,
        f"payload.version must be integer {expected_version} for {transition}",
        "wrong_payload_version",
        path="version",
    )


# ---------------------------------------------------------------------------
# Per-transition parsers
# ---------------------------------------------------------------------------

_ESTABLISHED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "trust_domain_core_digest",
        "binding_core",
        "initial_governance",
        "genesis_document_digest",
        "trust_log_project_instance_id",
        "root_signatures",
    }
)


def parse_trust_domain_established(payload: Mapping[str, Any]) -> TrustDomainEstablished:
    """§5.2/§5.3: the log's first event, restating the signed genesis identity.

    The restatement is validated by recomputing the §3.3 derivation through
    :mod:`regista._trust_domain` — never by enumerating the fields of a signer — so
    WI-292's move of custody out of ``binding_core`` composes here untouched.
    """
    raw = _require_keys(payload, _ESTABLISHED_KEYS, "payload")
    _require_payload_type(raw, TRUST_DOMAIN_ESTABLISHED)
    binding_core = raw["binding_core"]
    _require(
        isinstance(binding_core, Mapping),
        "payload.binding_core must be an object",
        "not_an_object",
        path="binding_core",
    )
    assert isinstance(binding_core, Mapping)
    signers = binding_core.get("signers")
    _require(
        isinstance(signers, list) and bool(signers),
        "payload.binding_core.signers must be a non-empty array",
        "signers_not_a_list",
        path="binding_core.signers",
    )
    assert isinstance(signers, list)
    for i, signer in enumerate(signers):
        _require(
            isinstance(signer, Mapping) and "fingerprint" in signer,
            f"payload.binding_core.signers[{i}] must be an object carrying a "
            "fingerprint",
            "signer_missing_fingerprint",
            path=f"binding_core.signers[{i}]",
        )
        assert isinstance(signer, Mapping)
        _require_pattern(
            signer["fingerprint"],
            _FINGERPRINT_RE,
            f"binding_core.signers[{i}].fingerprint",
            "<scheme_id>:sha256:<64 lowercase hex>",
        )

    stated_digest = _require_pattern(
        raw["trust_domain_core_digest"],
        _DIGEST_RE,
        "trust_domain_core_digest",
        "sha256:<64 lowercase hex characters>",
    )
    recomputed = derive_core_digest(binding_core)
    _require(
        stated_digest == recomputed,
        "payload.trust_domain_core_digest disagrees with the digest recomputed from "
        "the restated binding_core",
        "core_digest_mismatch",
        stated=stated_digest,
        recomputed=recomputed,
    )

    governance = _require_keys(
        raw["initial_governance"],
        frozenset({"mode", "threshold", "signer_count"}),
        "initial_governance",
    )
    threshold = _require_int(governance["threshold"], "initial_governance.threshold")
    signer_count = _require_int(governance["signer_count"], "initial_governance.signer_count")
    _require(
        signer_count == len(signers),
        f"initial_governance.signer_count {signer_count} != len(binding_core.signers) "
        f"{len(signers)}",
        "signer_count_mismatch",
        signer_count=signer_count,
        signers=len(signers),
    )
    derived_mode = derive_governance_mode(threshold, signer_count)
    _require(
        governance["mode"] == derived_mode,
        f"initial_governance.mode {governance['mode']!r} disagrees with the mode "
        f"derived from threshold={threshold}, signer_count={signer_count}: "
        f"{derived_mode!r}",
        "mode_threshold_disagreement",
        stated=governance["mode"],
        derived=derived_mode,
    )

    return TrustDomainEstablished(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        trust_domain_core_digest=stated_digest,
        binding_core=binding_core,
        initial_governance=governance,
        genesis_document_digest=_require_pattern(
            raw["genesis_document_digest"],
            _DIGEST_RE,
            "genesis_document_digest",
            "sha256:<64 lowercase hex characters>",
        ),
        trust_log_project_instance_id=_require_uuid(
            raw["trust_log_project_instance_id"], "trust_log_project_instance_id"
        ),
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


def validate_established_against_genesis(
    established: TrustDomainEstablished,
    genesis_document: Mapping[str, Any],
) -> None:
    """Cross-check the restatement against the genesis document itself.

    Canonical-byte equality on ``binding_core``, plus the derived identifiers and the
    trust-log project id. Deliberately structure-agnostic: it compares JCS bytes and
    asks :mod:`regista._trust_domain` for the derivation, so it keeps working when
    WI-292 changes what a signer entry contains.
    """
    from ._trust_domain import parse_trust_genesis

    parsed = parse_trust_genesis(genesis_document)
    _require(
        canonicalize(dict(established.binding_core))
        == canonicalize(dict(genesis_document["binding_core"])),
        "payload.binding_core is not a byte-exact restatement of the genesis "
        "document's binding_core",
        "binding_core_restatement_mismatch",
    )
    _require(
        established.trust_domain_id == parsed.trust_domain_id,
        "payload.trust_domain_id disagrees with the genesis document",
        "trust_domain_id_mismatch",
        payload=established.trust_domain_id,
        genesis=parsed.trust_domain_id,
    )
    _require(
        established.trust_domain_core_digest == parsed.trust_domain_core_digest,
        "payload.trust_domain_core_digest disagrees with the genesis document",
        "core_digest_mismatch",
        payload=established.trust_domain_core_digest,
        genesis=parsed.trust_domain_core_digest,
    )
    _require(
        established.trust_log_project_instance_id == parsed.trust_log.project_instance_id,
        "payload.trust_log_project_instance_id disagrees with the genesis document's "
        "trust_log.project_instance_id",
        "trust_log_project_mismatch",
        payload=established.trust_log_project_instance_id,
        genesis=parsed.trust_log.project_instance_id,
    )
    _require(
        established.initial_governance["threshold"] == parsed.initial_governance.threshold
        and established.initial_governance["signer_count"]
        == parsed.initial_governance.signer_count
        and established.initial_governance["mode"] == parsed.initial_governance.mode,
        "payload.initial_governance disagrees with the genesis document",
        "initial_governance_mismatch",
    )


_ROOT_ROTATED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "added",
        "removed",
        "reason",
        "effective_from_checkpoint_seq",
        "new_threshold",
        "root_signatures",
    }
)


def parse_trust_root_rotated(payload: Mapping[str, Any]) -> TrustRootRotated:
    """§5.4: replace/add/remove a root signer, or raise the threshold."""
    raw = _require_keys(payload, _ROOT_ROTATED_KEYS, "payload")
    _require_payload_type(raw, TRUST_ROOT_ROTATED)
    added_raw = raw["added"]
    _require(isinstance(added_raw, list), "payload.added must be an array", "not_an_array",
             path="added")
    assert isinstance(added_raw, list)
    for i, entry in enumerate(added_raw):
        _require(
            isinstance(entry, Mapping) and "fingerprint" in entry and "public_key" in entry,
            f"payload.added[{i}] must be a signer object carrying fingerprint and "
            "public_key: a rotation that names a key it does not carry leaves the "
            "resulting signer set unusable",
            "added_signer_incomplete",
            path=f"added[{i}]",
        )
        assert isinstance(entry, Mapping)
        scheme = _require_scheme(entry.get("scheme_id"), f"added[{i}].scheme_id")
        public_key = _require_base64(
            entry["public_key"], f"added[{i}].public_key",
            expected_len=_ED25519_PUBLIC_KEY_LEN,
        )
        stated = _require_pattern(
            entry["fingerprint"], _FINGERPRINT_RE, f"added[{i}].fingerprint",
            "<scheme_id>:sha256:<64 lowercase hex>",
        )
        recomputed = _compute_fingerprint(public_key, scheme)
        _require(
            stated == recomputed,
            f"payload.added[{i}].fingerprint does not match the recomputation from "
            "its public_key",
            "fingerprint_mismatch",
            path=f"added[{i}].fingerprint",
            stated=stated,
            recomputed=recomputed,
        )
    removed = _require_string_list(raw["removed"], "removed", allow_empty=True)
    for i, fp in enumerate(removed):
        _require_pattern(
            fp, _FINGERPRINT_RE, f"removed[{i}]", "<scheme_id>:sha256:<64 lowercase hex>"
        )
    new_threshold = _require_int(raw["new_threshold"], "new_threshold")
    _require(
        new_threshold >= 1,
        "payload.new_threshold must be >= 1",
        "threshold_below_one",
        new_threshold=new_threshold,
    )
    # Whether the event actually *changes* anything can only be decided against the
    # current signer set, so that check lives in apply_root_rotation.
    return TrustRootRotated(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        added=tuple(added_raw),
        removed=removed,
        reason=_require_string(raw["reason"], "reason"),
        effective_from_checkpoint_seq=_require_int(
            raw["effective_from_checkpoint_seq"], "effective_from_checkpoint_seq"
        ),
        new_threshold=new_threshold,
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


def apply_root_rotation(
    current: GovernanceState, rotation: TrustRootRotated
) -> GovernanceState:
    """Compute the post-rotation governance under the WI-280 monotone rules.

    Delegates the monotonicity decision to
    :func:`regista._trust_domain.validate_governance_transition` — the P2.1
    primitive — so "the threshold may never decrease" is enforced in exactly one
    place and takes no signer identity at all. A lowering event is rejected no
    matter who signed it.
    """
    removed = set(rotation.removed)
    unknown = sorted(removed - set(current.signer_fingerprints))
    _require(
        not unknown,
        f"payload.removed names fingerprints that are not in the current signer set: "
        f"{unknown!r}",
        "removed_signer_not_current",
        unknown=unknown,
    )
    added_fps = [str(s["fingerprint"]) for s in rotation.added]
    kept = [fp for fp in current.signer_fingerprints if fp not in removed]
    collisions = sorted(set(added_fps) & set(kept))
    _require(
        not collisions,
        f"payload.added re-adds fingerprints already in the signer set: {collisions!r}",
        "added_signer_already_present",
        collisions=collisions,
    )
    _require(
        len(set(added_fps)) == len(added_fps),
        "payload.added contains duplicate fingerprints",
        "duplicate_added_fingerprint",
    )
    proposed = GovernanceState(
        threshold=rotation.new_threshold,
        signer_fingerprints=tuple(sorted(kept + added_fps)),
    )
    # A root-threshold-signed no-op is not a governance transition. Refusing it keeps
    # the monotone log free of padding that would otherwise be indistinguishable
    # from real rotations when auditing who held the root and when.
    _require(
        proposed != current,
        "payload changes neither the signer set nor the threshold: a rotation that "
        "changes nothing is not a governance transition (§5.4)",
        "rotation_changes_nothing",
        threshold=current.threshold,
        signer_count=current.signer_count,
    )
    validate_governance_transition(current, proposed)
    return proposed


_CUSTODY_DECLARED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "declaration_seq",
        "supersedes_declaration_digest",
        "custody",
        "reason",
        "root_signatures",
    }
)


def parse_trust_domain_custody_declared(
    payload: Mapping[str, Any],
) -> TrustDomainCustodyDeclared:
    """WI-292: a threshold-authorised custody correction.

    Shape plus the two monotone rules (see :class:`TrustDomainCustodyDeclared`).
    ``declaration_seq >= 1``; ``seq == 1`` is the only declaration permitted to have
    no predecessor, so a correction can never orphan the declaration it replaces.
    """
    raw = _require_keys(payload, _CUSTODY_DECLARED_KEYS, "payload")
    _require_payload_type(raw, TRUST_DOMAIN_CUSTODY_DECLARED)
    seq = _require_int(raw["declaration_seq"], "declaration_seq")
    _require(
        seq >= 1,
        "payload.declaration_seq must be >= 1",
        "declaration_seq_below_one",
        declaration_seq=seq,
    )
    supersedes = raw["supersedes_declaration_digest"]
    if supersedes is not None:
        supersedes = _require_pattern(
            supersedes,
            _DIGEST_RE,
            "supersedes_declaration_digest",
            "sha256:<64 lowercase hex characters> or null",
        )
    _require(
        (seq == 1) == (supersedes is None),
        "payload.supersedes_declaration_digest must be null exactly when "
        "declaration_seq is 1: a correction preserves the declaration it replaces "
        "by naming it, and only the first declaration has no predecessor (WI-292)",
        "custody_supersession_broken",
        declaration_seq=seq,
        supersedes_present=supersedes is not None,
    )
    custody_raw = raw["custody"]
    _require(
        isinstance(custody_raw, list) and bool(custody_raw),
        "payload.custody must be a non-empty array of per-signer declarations",
        "custody_not_a_list",
        path="custody",
    )
    assert isinstance(custody_raw, list)
    seen: set[str] = set()
    fingerprints: list[str] = []
    for i, entry in enumerate(custody_raw):
        _require(
            isinstance(entry, Mapping) and "fingerprint" in entry,
            f"payload.custody[{i}] must be an object naming the signer fingerprint "
            "its declaration is about",
            "custody_entry_missing_fingerprint",
            path=f"custody[{i}]",
        )
        assert isinstance(entry, Mapping)
        fp = _require_pattern(
            entry["fingerprint"], _FINGERPRINT_RE, f"custody[{i}].fingerprint",
            "<scheme_id>:sha256:<64 lowercase hex>",
        )
        _require(
            fp not in seen,
            f"payload.custody[{i}] duplicates an earlier declaration for the same "
            "signer fingerprint",
            "duplicate_custody_fingerprint",
            path=f"custody[{i}].fingerprint",
            fingerprint=fp,
        )
        seen.add(fp)
        fingerprints.append(fp)
    # Same ordering rule the genesis document's `initial_custody` block carries
    # (WI-292): sorted ascending by fingerprint, enforced rather than silently
    # sorted, so the signed bytes are independent of authoring order. A correction
    # must satisfy the same invariants as the declaration it replaces, or the two are
    # not comparable.
    _require(
        fingerprints == sorted(fingerprints),
        "payload.custody must be sorted by fingerprint ascending",
        "custody_not_sorted",
        path="custody",
    )
    return TrustDomainCustodyDeclared(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        declaration_seq=seq,
        supersedes_declaration_digest=supersedes,
        custody=tuple(custody_raw),
        reason=_require_string(raw["reason"], "reason"),
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


_REGISTRAR_DELEGATED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "registrar_principal_id",
        "key_id",
        "fingerprint",
        "public_key",
        "scheme_id",
        "scopes",
        "not_before",
        "not_after",
        "max_operations",
        "root_signatures",
    }
)


def replay_custody_declarations(
    declarations: Sequence[tuple[TrustDomainCustodyDeclared, str]],
) -> TrustDomainCustodyDeclared | None:
    """Replay custody corrections in order, enforcing the WI-292 monotone rules.

    Takes ``(declaration, its_own_digest)`` pairs in chain order and returns the
    current declaration, or ``None`` for an empty sequence. Two rules the individual
    payload cannot check:

    * ``declaration_seq`` must increase by exactly one, starting at 1. A gap would
      mean a correction is missing from the presented material; a repeat or a
      decrease would make "current custody" ambiguous.
    * ``supersedes_declaration_digest`` must name the **immediately preceding**
      declaration. Naming an older one would silently discard the corrections
      between, which is a rewrite wearing a correction's clothes.
    """
    previous: TrustDomainCustodyDeclared | None = None
    previous_digest: str | None = None
    for index, (declaration, digest) in enumerate(declarations):
        expected_seq = index + 1
        _require(
            declaration.declaration_seq == expected_seq,
            f"custody declaration_seq must increase by one from 1; expected "
            f"{expected_seq}, got {declaration.declaration_seq}",
            "custody_seq_not_contiguous",
            expected=expected_seq,
            stated=declaration.declaration_seq,
        )
        _require(
            declaration.supersedes_declaration_digest == previous_digest,
            "custody supersedes_declaration_digest must name the immediately "
            "preceding declaration",
            "custody_supersedes_wrong_predecessor",
            expected=previous_digest,
            stated=declaration.supersedes_declaration_digest,
        )
        previous, previous_digest = declaration, digest
    return previous


def parse_registrar_delegated(payload: Mapping[str, Any]) -> RegistrarDelegated:
    """§5.4: a scoped, expiring online credential, signed at root threshold.

    ``not_after`` is mandatory and bounded at 400 days. The registrar's scopes are
    lifecycle administration only — never work-item writing, which is §5.12's
    separate action-delegation credential.
    """
    raw = _require_keys(payload, _REGISTRAR_DELEGATED_KEYS, "payload")
    _require_payload_type(raw, REGISTRAR_DELEGATED)
    key = _parse_key_material(raw)
    scopes = _require_string_list(raw["scopes"], "scopes")
    unknown = sorted(set(scopes) - _REGISTRAR_SCOPES)
    _require(
        not unknown,
        f"payload.scopes contains values outside the registrar's lifecycle-"
        f"administration scope set {sorted(_REGISTRAR_SCOPES)!r}: {unknown!r}. "
        "Registrar delegation never authorises writing work-item events; that is "
        "the separate action-delegation credential (§5.12)",
        "scope_outside_registrar_authority",
        unknown=unknown,
    )
    _require(
        len(set(scopes)) == len(scopes),
        "payload.scopes contains duplicates",
        "duplicate_scope",
    )
    not_before = _require_timestamp(raw["not_before"], "not_before")
    _require(
        raw["not_after"] is not None,
        "payload.not_after is mandatory for a registrar delegation: an online "
        "credential that never expires is not a delegation (§5.4)",
        "registrar_not_after_missing",
        path="not_after",
    )
    not_after = _require_timestamp(raw["not_after"], "not_after")
    _require(
        not_after > not_before,
        "payload.not_after must be strictly after not_before",
        "registrar_validity_window_inverted",
        not_before=raw["not_before"],
        not_after=raw["not_after"],
    )
    _require(
        not_after - not_before <= REGISTRAR_MAX_VALIDITY,
        f"registrar validity window {not_after - not_before} exceeds the contract "
        f"bound of {REGISTRAR_MAX_VALIDITY.days} days (§5.4)",
        "registrar_validity_too_long",
        days=(not_after - not_before).days,
        max_days=REGISTRAR_MAX_VALIDITY.days,
    )
    max_operations = raw["max_operations"]
    if max_operations is not None:
        max_operations = _require_int(max_operations, "max_operations")
        _require(
            max_operations >= 1,
            "payload.max_operations must be >= 1 or null",
            "max_operations_below_one",
            max_operations=max_operations,
        )
    return RegistrarDelegated(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        registrar_principal_id=_require_string(
            raw["registrar_principal_id"], "registrar_principal_id"
        ),
        key=key,
        scopes=scopes,
        not_before=not_before,
        not_after=not_after,
        max_operations=max_operations,
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


_REGISTRAR_REVOKED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "registrar_principal_id",
        "key_id",
        "delegation_event_hash",
        "reason",
        "root_signatures",
    }
)


def parse_registrar_revoked(payload: Mapping[str, Any]) -> RegistrarRevoked:
    """§5.4: revoke a registrar delegation, at root threshold."""
    raw = _require_keys(payload, _REGISTRAR_REVOKED_KEYS, "payload")
    _require_payload_type(raw, REGISTRAR_REVOKED)
    return RegistrarRevoked(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        registrar_principal_id=_require_string(
            raw["registrar_principal_id"], "registrar_principal_id"
        ),
        key_id=_require_pattern(
            raw["key_id"], _KEY_ID_RE, "key_id", "1-128 chars of [A-Za-z0-9._:-]"
        ),
        delegation_event_hash=_require_pattern(
            raw["delegation_event_hash"],
            _DIGEST_RE,
            "delegation_event_hash",
            "sha256:<64 lowercase hex characters>",
        ),
        reason=_require_string(raw["reason"], "reason"),
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


_PRINCIPAL_REGISTERED_KEYS = frozenset(
    {"type", "version", "trust_domain_id", "principal_id", "principal_kind", "authorized_by"}
)


def parse_principal_registered(payload: Mapping[str, Any]) -> PrincipalRegistered:
    """§5.3: creates the principal; declares canonical id and kind.

    ``principal_kind`` comes from a root/registrar-authorised ``principal_registered``
    and **from nowhere else** (§5.12): an action-delegation document asserting
    "human" never manufactures human identity.

    Grammar note: the canonical ``kind:subject`` grammar is **P2.3's** contract
    (§2.1, §9 criterion 19). This parser checks the closed kind set and that the id
    is non-empty, and calls the grammar seam below — it deliberately does not
    reimplement the grammar.
    """
    raw = _require_keys(payload, _PRINCIPAL_REGISTERED_KEYS, "payload")
    _require_payload_type(raw, PRINCIPAL_REGISTERED)
    principal_id = _require_string(raw["principal_id"], "principal_id")
    kind = _require_string(raw["principal_kind"], "principal_kind")
    _require(
        kind in _PRINCIPAL_KINDS,
        f"payload.principal_kind must be one of {sorted(_PRINCIPAL_KINDS)!r} "
        "(kinds are closed; witness lifecycle is cut from 0.6.0)",
        "unknown_principal_kind",
        path="principal_kind",
        stated=kind,
    )
    check_principal_grammar(principal_id, path="principal_id")
    return PrincipalRegistered(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        principal_id=principal_id,
        principal_kind=kind,
        authorized_by=_parse_authorized_by(raw["authorized_by"], "authorized_by"),
    )


def check_principal_grammar(principal_id: str, *, path: str = "principal_id") -> None:
    """Enforce P2.3's canonical ``kind:subject`` grammar (§2.1, §2.7).

    §2.7 puts key enrolment and project acceptance in the **always-strict** column,
    so every §5.5/§5.6/§5.7 payload's ``principal_id`` goes through P2.3's
    :func:`regista._principals.validate_principal_id` — the single definition of what
    a canonical principal id is. This was a deliberate no-op seam while P2.3 was in
    flight; it is now filled rather than duplicated, so there is exactly one grammar.
    """
    from ._principals import validate_principal_id

    _require(bool(principal_id.strip()), f"{path} must be non-empty", "empty_string", path=path)
    validate_principal_id(principal_id, path=path)


_ENROLLED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "principal_id",
        "principal_kind",
        "key_id",
        "scheme_id",
        "public_key",
        "fingerprint",
        "not_before",
        "not_after",
        "possession_proof",
        "authorized_by",
        "custody",
        "supersedes_key_id",
    }
)

_ROTATED_KEYS = _ENROLLED_KEYS | frozenset({"dual_authorization", "root_signatures"})


def _parse_validity(raw: Mapping[str, Any]) -> tuple[datetime, datetime | None]:
    not_before = _require_timestamp(raw["not_before"], "not_before")
    not_after = raw["not_after"]
    if not_after is not None:
        not_after = _require_timestamp(not_after, "not_after")
        _require(
            not_after > not_before,
            "payload.not_after must be strictly after not_before",
            "validity_window_inverted",
        )
    return not_before, not_after


def parse_principal_key_enrolled(payload: Mapping[str, Any]) -> PrincipalKeyEnrolled:
    """§5.5. ``public_key`` mandatory (WI-273); fingerprint recomputed and compared.

    A payload lacking ``public_key`` is rejected here, at validation/write time —
    that is §9 criterion 16, and it is what makes the projection rebuildable at all.
    """
    raw = _require_keys(payload, _ENROLLED_KEYS, "payload")
    _require_payload_type(raw, PRINCIPAL_KEY_ENROLLED)
    kind = _require_string(raw["principal_kind"], "principal_kind")
    _require(
        kind in _PRINCIPAL_KINDS,
        f"payload.principal_kind must be one of {sorted(_PRINCIPAL_KINDS)!r}",
        "unknown_principal_kind",
        path="principal_kind",
        stated=kind,
    )
    not_before, not_after = _parse_validity(raw)
    supersedes = raw["supersedes_key_id"]
    _require(
        supersedes is None,
        "payload.supersedes_key_id must be null on an enrolment: a rotation is "
        "principal_key_rotated, which additionally carries dual_authorization (§5.6)",
        "enrolment_supersedes_key_id",
        path="supersedes_key_id",
    )
    principal_id = _require_string(raw["principal_id"], "principal_id")
    check_principal_grammar(principal_id)
    return PrincipalKeyEnrolled(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        principal_id=principal_id,
        principal_kind=kind,
        key=_parse_key_material(raw),
        not_before=not_before,
        not_after=not_after,
        possession_proof=_parse_possession_proof(raw["possession_proof"], "possession_proof"),
        authorized_by=_parse_authorized_by(raw["authorized_by"], "authorized_by"),
        custody=_parse_custody(raw["custody"], "custody"),
        supersedes_key_id=None,
    )


def parse_principal_key_rotated(payload: Mapping[str, Any]) -> PrincipalKeyRotated:
    """§5.6: enrolment plus a non-null ``supersedes_key_id`` and dual authorisation."""
    raw = _require_keys(payload, _ROTATED_KEYS, "payload")
    _require_payload_type(raw, PRINCIPAL_KEY_ROTATED)
    kind = _require_string(raw["principal_kind"], "principal_kind")
    _require(
        kind in _PRINCIPAL_KINDS,
        f"payload.principal_kind must be one of {sorted(_PRINCIPAL_KINDS)!r}",
        "unknown_principal_kind",
        path="principal_kind",
        stated=kind,
    )
    not_before, not_after = _parse_validity(raw)
    key = _parse_key_material(raw)
    supersedes = raw["supersedes_key_id"]
    _require(
        supersedes is not None,
        "payload.supersedes_key_id is required and non-null on a rotation (§5.6)",
        "rotation_supersedes_key_id_missing",
        path="supersedes_key_id",
    )
    supersedes_key_id = _require_pattern(
        supersedes, _KEY_ID_RE, "supersedes_key_id", "1-128 chars of [A-Za-z0-9._:-]"
    )
    _require(
        supersedes_key_id != key.key_id,
        "payload.supersedes_key_id must differ from key_id: a key cannot supersede "
        "itself",
        "rotation_supersedes_self",
        key_id=key.key_id,
    )
    principal_id = _require_string(raw["principal_id"], "principal_id")
    check_principal_grammar(principal_id)
    return PrincipalKeyRotated(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        principal_id=principal_id,
        principal_kind=kind,
        key=key,
        not_before=not_before,
        not_after=not_after,
        possession_proof=_parse_possession_proof(raw["possession_proof"], "possession_proof"),
        authorized_by=_parse_authorized_by(raw["authorized_by"], "authorized_by"),
        custody=_parse_custody(raw["custody"], "custody"),
        supersedes_key_id=supersedes_key_id,
        dual_authorization=_parse_dual_authorization(
            raw["dual_authorization"], "dual_authorization"
        ),
        root_signatures=_parse_root_signatures(raw["root_signatures"], "root_signatures"),
    )


_REVOKED_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "principal_id",
        "key_id",
        "reason",
        "revoked_at",
        "effective_from",
        "retroactive_suspicion",
        "authorized_by",
    }
)


def parse_principal_key_revoked(payload: Mapping[str, Any]) -> PrincipalKeyRevoked:
    """§5.7. Revocation is prospective by chain position, never by wall-clock.

    ``revoked_at`` is a claim; the binding fact is the event's position in the
    trust-log chain, imported into a project chain by §6.6. This parser therefore
    requires ``effective_from.kind == "on_chain_position"`` and refuses any other
    spelling rather than accepting a timestamp as the effective point.
    """
    raw = _require_keys(payload, _REVOKED_KEYS, "payload")
    _require_payload_type(raw, PRINCIPAL_KEY_REVOKED)
    reason = _require_string(raw["reason"], "reason")
    _require(
        reason in _REVOCATION_REASONS,
        f"payload.reason must be one of {sorted(_REVOCATION_REASONS)!r}",
        "unknown_revocation_reason",
        path="reason",
        stated=reason,
    )
    effective = _require_keys(raw["effective_from"], _EFFECTIVE_FROM_KEYS, "effective_from")
    kind = _require_string(effective["kind"], "effective_from.kind")
    _require(
        kind in _EFFECTIVE_FROM_KINDS,
        f"payload.effective_from.kind must be one of "
        f"{sorted(_EFFECTIVE_FROM_KINDS)!r}: revocation is prospective by chain "
        "position, never by wall-clock (§5.7)",
        "effective_from_kind_not_chain_position",
        path="effective_from.kind",
        stated=kind,
    )
    event_hash = _require_string(
        effective["trust_log_event_hash"], "effective_from.trust_log_event_hash"
    )
    _require(
        event_hash == "self" or _DIGEST_RE.fullmatch(event_hash) is not None,
        'payload.effective_from.trust_log_event_hash must be "self" or '
        "sha256:<64 lowercase hex characters>",
        "malformed_value",
        path="effective_from.trust_log_event_hash",
    )
    return PrincipalKeyRevoked(
        trust_domain_id=_require_uuid(raw["trust_domain_id"], "trust_domain_id"),
        principal_id=_require_string(raw["principal_id"], "principal_id"),
        key_id=_require_pattern(
            raw["key_id"], _KEY_ID_RE, "key_id", "1-128 chars of [A-Za-z0-9._:-]"
        ),
        reason=reason,
        revoked_at=_require_timestamp(raw["revoked_at"], "revoked_at"),
        effective_from_kind=kind,
        effective_from_event_hash=event_hash,
        retroactive_suspicion=_parse_retroactive_suspicion(
            raw["retroactive_suspicion"], "retroactive_suspicion"
        ),
        authorized_by=_parse_authorized_by(raw["authorized_by"], "authorized_by"),
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PARSERS: Final[dict[str, Any]] = {
    TRUST_DOMAIN_ESTABLISHED: parse_trust_domain_established,
    TRUST_ROOT_ROTATED: parse_trust_root_rotated,
    TRUST_DOMAIN_CUSTODY_DECLARED: parse_trust_domain_custody_declared,
    REGISTRAR_DELEGATED: parse_registrar_delegated,
    REGISTRAR_REVOKED: parse_registrar_revoked,
    PRINCIPAL_REGISTERED: parse_principal_registered,
    PRINCIPAL_KEY_ENROLLED: parse_principal_key_enrolled,
    PRINCIPAL_KEY_ROTATED: parse_principal_key_rotated,
    PRINCIPAL_KEY_REVOKED: parse_principal_key_revoked,
}


def parse_trust_log_payload(transition: str, payload: Any) -> TrustLogPayload:
    """Strictly parse a trust-domain-log payload for ``transition``.

    Unknown transitions fail closed with a reason that says *why* the transition is
    not here: cut from 0.6.0, deferred to a named package, or simply unknown.
    """
    if transition in WITNESS_LIFECYCLE_TRANSITIONS_CUT:
        _fail(
            ErrorCode.WITNESS_LIFECYCLE_CUT,
            f"{transition!r} is cut from 0.6.0: witness lifecycle and positive "
            "witness-independence work do not ship in this release "
            "(TRUST-DOMAIN.md §7 CUT marker, D-7). There are zero witness "
            "registrations and zero receipts estate-wide, so there is nothing to "
            "migrate and no deployed evidence to preserve.",
            "witness_lifecycle_cut_from_0_6_0",
            transition=transition,
        )
    if transition in DEFERRED_TRANSITIONS:
        _fail(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"{transition!r} payload validation is not owned by P2.2: "
            f"{DEFERRED_TRANSITIONS[transition]}",
            "transition_owned_by_another_package",
            transition=transition,
            owner=DEFERRED_TRANSITIONS[transition],
        )
    parser = _PARSERS.get(transition)
    if parser is None:
        _fail(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"{transition!r} is not a trust-domain-log transition this contract "
            f"knows; known: {sorted(TRUST_LOG_TRANSITIONS)!r}",
            "unknown_transition",
            transition=transition,
        )
    _require(
        isinstance(payload, Mapping),
        "payload must be an object",
        "not_an_object",
        path="payload",
    )
    return parser(payload)  # type: ignore[no-any-return]


def expected_entity_kind(transition: str) -> str:
    """The v6 envelope ``entity.kind`` for a trust-log transition (§5.2 AMENDED).

    The registry is shared and closed at six values; ``project_system`` is prose and
    never a wire value.
    """
    kind = TRUST_LOG_ENTITY_KIND.get(transition)
    if kind is None:
        _fail(
            ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
            f"no entity kind is defined for {transition!r}",
            "unknown_transition",
            transition=transition,
        )
    return kind


# ---------------------------------------------------------------------------
# Registrar authority resolution (§5.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistrarCredential:
    """A replayed, currently-effective registrar delegation."""

    delegation_event_hash: str
    registrar_principal_id: str
    key_id: str
    fingerprint: str
    scopes: frozenset[str]
    not_before: datetime
    not_after: datetime
    max_operations: int | None
    revoked: bool = False


def authorize_lifecycle_operation(
    transition: str,
    authorized_by: AuthorizedBy,
    *,
    registrars: Mapping[str, RegistrarCredential],
    at: datetime,
    operations_used: int = 0,
) -> str:
    """Check a lifecycle event's ``authorized_by`` against §5.4.

    Returns the effective authority (``"root"`` or ``"registrar"``). Root authority
    is checked by the caller with :func:`verify_root_threshold` — the root is never
    a stored credential. Registrar authority is checked here: the delegation must
    exist, not be revoked, cover ``transition`` in its scopes, be inside its
    validity window, and be within ``max_operations``.

    ``a registrar cannot delegate`` (§5.4) is enforced structurally at delegation
    time by :func:`refuse_registrar_delegating_registrar`; there are no chains, so
    no depth question and no cycle check.
    """
    if authorized_by.authority == "root":
        return "root"
    hash_ = authorized_by.delegation_event_hash
    assert hash_ is not None  # _parse_authorized_by requires it for registrars
    credential = registrars.get(hash_)
    _require_authority(
        credential is not None,
        "authorized_by.delegation_event_hash does not resolve to a registrar "
        "delegation in the presented trust material",
        "registrar_delegation_unresolved",
        delegation_event_hash=hash_,
    )
    assert credential is not None
    _require_authority(
        not credential.revoked,
        "the registrar delegation is revoked; a revoked credential is invalid, not "
        "degraded",
        "registrar_delegation_revoked",
        delegation_event_hash=hash_,
    )
    _require_authority(
        credential.registrar_principal_id == authorized_by.principal_id,
        "authorized_by.principal_id does not match the delegated registrar principal",
        "registrar_principal_mismatch",
        stated=authorized_by.principal_id,
        delegated=credential.registrar_principal_id,
    )
    _require_authority(
        credential.key_id == authorized_by.key_id,
        "authorized_by.key_id does not match the delegated registrar key",
        "registrar_key_mismatch",
        stated=authorized_by.key_id,
        delegated=credential.key_id,
    )
    _require_authority(
        transition in credential.scopes,
        f"the registrar delegation does not cover {transition!r}; scopes are "
        f"{sorted(credential.scopes)!r}",
        "registrar_scope_exceeded",
        transition=transition,
        scopes=sorted(credential.scopes),
    )
    _require_authority(
        credential.not_before <= at < credential.not_after,
        "the registrar delegation is outside its validity window; an expired "
        "credential is invalid, not degraded",
        "registrar_delegation_expired",
        at=at.isoformat(),
        not_before=credential.not_before.isoformat(),
        not_after=credential.not_after.isoformat(),
    )
    if credential.max_operations is not None:
        _require_authority(
            operations_used < credential.max_operations,
            "the registrar delegation has exhausted max_operations",
            "registrar_max_operations_exhausted",
            used=operations_used,
            max_operations=credential.max_operations,
        )
    return "registrar"


def refuse_registrar_delegating_registrar(
    delegation: RegistrarDelegated,
    *,
    existing_registrar_principal_ids: Sequence[str],
) -> None:
    """§5.4: ``registrar_delegated`` naming a principal that is itself a registrar
    is **invalid**. A registrar cannot delegate — no chains, no depth question, no
    cycle check needed."""
    _require_authority(
        delegation.registrar_principal_id not in set(existing_registrar_principal_ids),
        f"registrar_delegated names {delegation.registrar_principal_id!r}, which is "
        "already a registrar: a registrar cannot delegate (§5.4)",
        "registrar_cannot_delegate",
        registrar_principal_id=delegation.registrar_principal_id,
    )


# ---------------------------------------------------------------------------
# Rotation authority classification (§5.6, Resolution 5 / D-8)
# ---------------------------------------------------------------------------

#: The value a verifier reports for a recovery rotation, and which propagates into
#: VerificationResult (§8.3) and bundle verdicts. Visible classification is
#: retained; it is never a substitute for prevention.
KEY_BINDING_RECOVERY_ROTATED: Final[str] = "recovery_rotated"
KEY_BINDING_DUAL_ROTATED: Final[str] = "dual_rotated"


def classify_rotation_authority(
    rotation: PrincipalKeyRotated,
    *,
    governance: GovernanceState,
    root_public_keys: Mapping[str, bytes],
    payload: Mapping[str, Any],
    superseded_public_key: bytes | None = None,
) -> str:
    """Authorise a rotation and return its reported ``key_binding`` classification.

    * ``mode: "dual"`` — the **superseded key** must have signed the same canonical
      rotation bytes, in addition to the registrar authorisation. Returns
      ``"dual_rotated"``.
    * ``mode: "recovery"`` — requires the **current root threshold**. The online
      registrar may prepare and submit the request but cannot authorise it
      (Resolution 5, D-8): leaving recovery at registrar authority left it as the
      only residual takeover path not requiring host root. Returns
      ``"recovery_rotated"``.

    Raises on any failure. There is no path that accepts a recovery rotation below
    the current root threshold, and none that accepts a dual rotation without the
    outgoing-key signature.

    **Caller obligation.** This function checks the rotation-specific authority
    only. The registrar half of a ``mode: "dual"`` rotation — that
    ``authorized_by`` resolves to a live, in-scope, unexpired delegation — is
    :func:`authorize_lifecycle_operation`'s, and the caller must run both. They are
    deliberately separate because the root-threshold path takes no registrar at all
    (Resolution 5), so composing them here would mean passing a registrar registry
    to a check that must not consult one.
    """
    if rotation.dual_authorization.mode == "recovery":
        verify_root_threshold(
            payload, governance, root_public_keys, required_threshold=governance.threshold
        )
        return KEY_BINDING_RECOVERY_ROTATED

    signature = rotation.dual_authorization.old_key_signature
    _require_authority(
        signature is not None,
        "a dual rotation requires dual_authorization.old_key_signature",
        "dual_mode_missing_old_key_signature",
    )
    assert signature is not None
    _require_authority(
        superseded_public_key is not None,
        "the superseded key's public bytes must be presented to verify a dual "
        "rotation; they come from the enrolment/rotation event that introduced it",
        "superseded_public_key_unavailable",
        supersedes_key_id=rotation.supersedes_key_id,
    )
    assert superseded_public_key is not None
    _require_authority(
        _verify_ed25519(
            superseded_public_key, old_key_signature_input(payload), signature
        ),
        "dual_authorization.old_key_signature does not verify under the superseded "
        "key: the rotation is not proven to have been requested by the holder of the "
        "outgoing key",
        "old_key_signature_invalid",
        supersedes_key_id=rotation.supersedes_key_id,
    )
    return KEY_BINDING_DUAL_ROTATED


# ---------------------------------------------------------------------------
# Enrolment request digest (§5.5 possession binding)
# ---------------------------------------------------------------------------


def enrollment_request_digest(request: Mapping[str, Any]) -> str:
    """``"sha256:" + hex(SHA256(JCS(request)))`` — what the challenge binds to.

    Kept separate from the event payload so the challenge can be issued (and the
    possession proof produced) before the event exists.
    """
    return "sha256:" + hashlib.sha256(canonicalize(dict(request))).hexdigest()


__all__: Sequence[str] = [
    "KEY_BINDING_DUAL_ROTATED",
    "KEY_BINDING_RECOVERY_ROTATED",
    "POSSESSION_DOMAIN_V2",
    "POSSESSION_PREFIX_V2",
    "PRINCIPAL_KEY_ENROLLED",
    "PRINCIPAL_KEY_REVOKED",
    "PRINCIPAL_KEY_ROTATED",
    "PRINCIPAL_REGISTERED",
    "PROJECTION_DRIVING_TRANSITIONS",
    "REGISTRAR_DELEGATED",
    "REGISTRAR_MAX_VALIDITY",
    "REGISTRAR_REVOKED",
    "TRUST_DOMAIN_CUSTODY_DECLARED",
    "TRUST_DOMAIN_ESTABLISHED",
    "TRUST_LOG_OLD_KEY_SIG_DOMAIN",
    "TRUST_LOG_ROOT_SIG_DOMAIN",
    "TRUST_LOG_TRANSITIONS",
    "TRUST_ROOT_ROTATED",
    "AuthorizedBy",
    "CustodyDeclaration",
    "DualAuthorization",
    "KeyMaterial",
    "PossessionChallengeV2",
    "PossessionProofV2",
    "PrincipalKeyEnrolled",
    "PrincipalKeyRevoked",
    "PrincipalKeyRotated",
    "PrincipalRegistered",
    "RegistrarCredential",
    "RegistrarDelegated",
    "RegistrarRevoked",
    "RetroactiveSuspicion",
    "RootSignature",
    "TrustDomainCustodyDeclared",
    "TrustDomainEstablished",
    "TrustRootRotated",
    "apply_root_rotation",
    "authorize_lifecycle_operation",
    "check_principal_grammar",
    "classify_rotation_authority",
    "enrollment_request_digest",
    "expected_entity_kind",
    "old_key_signature_input",
    "parse_principal_key_enrolled",
    "parse_principal_key_revoked",
    "parse_principal_key_rotated",
    "parse_principal_registered",
    "parse_registrar_delegated",
    "parse_registrar_revoked",
    "parse_trust_domain_custody_declared",
    "parse_trust_domain_established",
    "parse_trust_log_payload",
    "parse_trust_root_rotated",
    "refuse_registrar_delegating_registrar",
    "replay_custody_declarations",
    "root_signature_input",
    "trust_log_authorization_core",
    "validate_established_against_genesis",
    "validate_key_binding_bootstrap",
    "verify_possession_proof_v2",
    "verify_root_threshold",
]
