"""Canonical principal identity: grammar, classification, backend-safe naming (P2.3).

Normative source: ``docs/0.6.0/TRUST-DOMAIN.md`` §2 (WI-055 as ratified 2026-08-01),
overlay-corrected by ``RECONCILIATION.md`` overlay change 13 and
``ARCHITECTURE-FINAL.md`` §3 decision 5. This module is the **single**
implementation of that grammar in regista; every other site delegates here.

§2.1 grammar::

    principal-id = kind ":" subject
    kind         = "human" / "agent" / "service"
    subject      = 1*247 subject-char
    subject-char = ALPHA / DIGIT / "." / "_" / "-" / "~" / ":" / "/"

Additional rules, all enforced (§2.1):

* total length ≤ 256 bytes UTF-8, ASCII only, NFC asserted (a no-op under ASCII, asserted
  anyway so a future relaxation cannot silently change bytes that were already signed);
* ``kind`` matched case-sensitively against the closed lowercase set — no ``unknown`` kind
  and no extension mechanism in 0.6.0;
* ``subject`` must not begin or end with ``:``, ``.``, ``-``, ``_`` or ``/``;
* ``subject`` is *everything after the first colon*, so ``service:idp:tenant-a/svc-7`` is
  legal and unambiguous;
* ``key:*`` is never a principal — rejected as a kind at every creation path, and no
  principal id is ever minted from a key id.

Principals are **hosts and services, never models** (§2 CONFIRMED consequence 1). Models,
harnesses and roles are ``producer.*`` fields on an event signed by the host principal
(``V6-ENVELOPE.md`` §1.8). Nothing here mints a principal id from a model name.

**No inference from string similarity, anywhere** (§2 CONFIRMED consequence 2). This module
classifies and validates; it never guesses which canonical principal a legacy bare name
"means". That assignment is a deliberate, signed, scoped artifact —
``regista._principal_alias`` owns its payload contract.

Enforcement boundaries (§2.7) — stated here because the table is the contract:

===============================================  ==========================================
Path                                             Enforce canonical grammar?
===============================================  ==========================================
``principal_registered`` / key enrolment          **Yes, always** — :func:`validate_principal_id`
``principal_key_accepted`` (project)              **Yes, always** — :func:`validate_principal_id`
delegation credential issue/subject               **Yes, always** — :func:`validate_principal_id`
``append_event`` actor_id                         **Yes, per project, from its cutover event
                                                  onward** — the ``require_canonical`` gate on
                                                  ``_contract.validate_actor_id``
witness registration                              **No in 0.6.0** — cut (§7 is future design)
verification / replay / bundle import /           **Never** — :func:`classify_principal_id`
historical key lookup                             reports, and reporting is not refusal
===============================================  ==========================================

The last row is why :func:`classify_principal_id` exists and never raises: a verifier must
be able to *say* an id is non-canonical without refusing to verify a historical event.

§2.2 backend-safe naming. Secret backends (Azure Key Vault, the Windows credential store)
forbid ``:``. The ratified decision is a collision-resistant derived name, **not** a
``:``→``-`` substitution::

    backend_name = "rp-" || lowercase_hex(
        SHA256("regista.principal-name.v1\\x00" || utf8(principal_id))[0:16]
    )
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn

from ._errors import ErrorCode, RegistaError

# ---------------------------------------------------------------------------
# Frozen constants (§2.1, §2.2). Widening any of these is a spec change.
# ---------------------------------------------------------------------------

#: §2.1 — the closed set, case-sensitive and lowercase. No `unknown`, no extension.
PRINCIPAL_KINDS: frozenset[str] = frozenset({"human", "agent", "service"})

#: §2.1 — `key:*` is never a principal. Kept as its own set (not merely "absent from
#: PRINCIPAL_KINDS") so the refusal carries a *named* reason a grep can find.
FORBIDDEN_KINDS: frozenset[str] = frozenset({"key"})

#: §2.1 — total length ceiling in UTF-8 bytes.
MAX_PRINCIPAL_ID_BYTES = 256
#: §2.1 — `subject = 1*247 subject-char`.
MAX_SUBJECT_LENGTH = 247
MIN_SUBJECT_LENGTH = 1

#: §2.1 subject-char = ALPHA / DIGIT / "." / "_" / "-" / "~" / ":" / "/"
_SUBJECT_RE = re.compile(r"[A-Za-z0-9._~:/-]+")
#: §2.1 — a subject may neither begin nor end with any of these.
SUBJECT_EDGE_FORBIDDEN = ":.-_/"

#: §2.4 convention 2, the rejected "bare enrolled name" shape — regista's *old* validator
#: (`_provision.py:234-247` pre-inversion). Matched here only to tell a legacy name apart
#: from unparseable junk, so the refusal can point at the alias path instead of just
#: saying "invalid".
_LEGACY_BARE_RE = re.compile(r"[A-Za-z0-9._-]{1,256}")

#: §2.2 — byte-level derivation constants. These are wire constants: changing either one
#: renames every secret in every backend.
BACKEND_NAME_DOMAIN = b"regista.principal-name.v1\x00"
BACKEND_NAME_PREFIX = "rp-"
_BACKEND_NAME_DIGEST_BYTES = 16
BACKEND_NAME_RE = re.compile(r"rp-[0-9a-f]{32}")

#: §2.6 — regista's `actor_kind` vocabulary (`_contract.py:19`) is
#: {agent, human, system}; the principal `kind` vocabulary is {human, agent, service}.
#: `service` is spelled `system` on the row. Anything else is a conflict.
ACTOR_KIND_BY_PRINCIPAL_KIND: Mapping[str, frozenset[str]] = {
    "human": frozenset({"human"}),
    "agent": frozenset({"agent"}),
    "service": frozenset({"system", "service"}),
}


class PrincipalForm(StrEnum):
    """What :func:`classify_principal_id` found. Reporting vocabulary, never a verdict."""

    #: Satisfies §2.1 in full.
    CANONICAL = "canonical"
    #: §2.4 convention 2: a legacy bare enrolled name, `[A-Za-z0-9._-]{1,256}`, no colon.
    #: Aliasable (§2.5); refused at creation post-cutover.
    BARE_NAME = "bare_name"
    #: Neither. Includes a non-canonical kind, `key:*`, a bad subject, non-ASCII, and
    #: anything over the length ceiling.
    UNGRAMMATICAL = "ungrammatical"


class IdentityConsistency(StrEnum):
    """§2.6 — the computed conflict state, surfaced per event by the verifier.

    The first three values are §2.6's closed list verbatim. Two more are added because
    §2.6's list is not total over the data the verifier actually holds, and reporting
    ``consistent`` for a case it did not check would be a false claim:

    * :attr:`ACTOR_KIND_ABSENT` — the row's ``actor_kind`` is NULL, so there is nothing to
      compare the canonical kind against. ``EventRow.actor_kind`` is ``str | None``.
    * :attr:`MAPPING_ABSENT` — §2 CONFIRMED consequence 2 verbatim: a non-canonical writer
      with no deliberate ``actor_id → principal_id`` assignment "is
      ``identity_consistency: mapping_absent``, not a guess". Reported only when a mapping
      population was actually supplied; see :func:`identity_consistency`.
    """

    CONSISTENT = "consistent"
    PRINCIPAL_KIND_CONFLICT = "principal_kind_conflict"
    ACTOR_ID_UNGRAMMATICAL = "actor_id_ungrammatical"
    ACTOR_KIND_ABSENT = "actor_kind_absent"
    MAPPING_ABSENT = "mapping_absent"


class MappingStatus(StrEnum):
    """Whether a writing actor has a deliberately assigned canonical principal.

    A separate axis from :class:`IdentityConsistency` so neither masks the other: the
    ~231k ``human:itadmin`` / ``actor_kind=agent`` corpus is *both*
    ``principal_kind_conflict`` and ``mapping_absent``, and collapsing that into one field
    would lose one of the two facts.
    """

    #: A mapping population was supplied and names this actor.
    MAPPED = "mapped"
    #: A mapping population was supplied and does not name this actor.
    MAPPING_ABSENT = "mapping_absent"
    #: No mapping population was supplied. Not a claim that a mapping is missing.
    NOT_EVALUATED = "not_evaluated"
    #: The actor id is already canonical; it *is* its own principal, no mapping needed.
    SELF_CANONICAL = "self_canonical"


@dataclass(frozen=True, slots=True)
class PrincipalId:
    """A parsed canonical principal id. Existence of this value proves §2.1 was satisfied."""

    kind: str
    subject: str
    text: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.text

    @property
    def backend_name(self) -> str:
        """The §2.2 derived, backend-safe name for this principal."""
        return backend_name(self.text)


@dataclass(frozen=True, slots=True)
class PrincipalClassification:
    """The non-raising classification result (§2.6, and the §2.7 "never validate" rows)."""

    form: PrincipalForm
    #: The canonical kind, or ``None`` for a bare legacy id and for junk (§2.6:
    #: "``actor_id_kind`` — the prefix, or ``null`` for a bare legacy id").
    kind: str | None
    #: Machine-readable reason a non-canonical value was rejected; ``None`` when canonical.
    reason: str | None

    @property
    def canonical(self) -> bool:
        return self.form is PrincipalForm.CANONICAL


# ---------------------------------------------------------------------------
# Classification — never raises. This is the verifier's and the sweep's entry point.
# ---------------------------------------------------------------------------


def _classify(value: Any) -> tuple[PrincipalForm, str | None, str | None]:
    if not isinstance(value, str):
        return PrincipalForm.UNGRAMMATICAL, None, "not_a_string"
    if not value:
        return PrincipalForm.UNGRAMMATICAL, None, "empty"

    # ASCII first: everything downstream (byte length, NFC, the char classes) is stated in
    # §2.1 over ASCII, and a non-ASCII value has no canonical spelling to check.
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return PrincipalForm.UNGRAMMATICAL, None, "non_ascii"
    # §2.1: "NFC is therefore a no-op but is still asserted so a future relaxation cannot
    # silently change bytes that were already signed."
    if unicodedata.normalize("NFC", value) != value:
        return PrincipalForm.UNGRAMMATICAL, None, "not_nfc"
    if len(value.encode("utf-8")) > MAX_PRINCIPAL_ID_BYTES:
        return PrincipalForm.UNGRAMMATICAL, None, "too_long"

    if ":" not in value:
        # §2.4 convention 2 vs. junk. A legacy bare name is aliasable and gets a refusal
        # that points at §2.5; junk does not.
        if _LEGACY_BARE_RE.fullmatch(value) is not None:
            return PrincipalForm.BARE_NAME, None, "bare_name_not_canonical"
        return PrincipalForm.UNGRAMMATICAL, None, "not_kind_colon_subject"

    # §2.1: subject is everything after the FIRST colon.
    kind, subject = value.split(":", 1)
    if kind in FORBIDDEN_KINDS:
        return PrincipalForm.UNGRAMMATICAL, None, "key_is_never_a_principal"
    if kind not in PRINCIPAL_KINDS:
        return PrincipalForm.UNGRAMMATICAL, None, "kind_not_canonical"
    if len(subject) < MIN_SUBJECT_LENGTH:
        return PrincipalForm.UNGRAMMATICAL, None, "subject_empty"
    if len(subject) > MAX_SUBJECT_LENGTH:
        return PrincipalForm.UNGRAMMATICAL, None, "subject_too_long"
    if _SUBJECT_RE.fullmatch(subject) is None:
        return PrincipalForm.UNGRAMMATICAL, None, "subject_char_not_allowed"
    if subject[0] in SUBJECT_EDGE_FORBIDDEN or subject[-1] in SUBJECT_EDGE_FORBIDDEN:
        return PrincipalForm.UNGRAMMATICAL, None, "subject_edge_char"
    return PrincipalForm.CANONICAL, kind, None


def classify_principal_id(value: Any) -> PrincipalClassification:
    """Classify ``value`` against §2.1 **without raising**.

    This is the only entry point the §2.7 "Never" rows may use: verification, replay,
    bundle import and historical key lookup must be able to *report* that an id is
    non-canonical without refusing to process the event that carries it.
    """
    form, kind, reason = _classify(value)
    return PrincipalClassification(form=form, kind=kind, reason=reason)


def is_canonical_principal_id(value: Any) -> bool:
    """True iff ``value`` satisfies §2.1 in full."""
    return _classify(value)[0] is PrincipalForm.CANONICAL


def principal_id_kind(value: Any) -> str | None:
    """§2.6 ``actor_id_kind``: the canonical kind prefix, or ``None`` for anything else.

    ``None`` for a bare legacy id *and* for junk. A non-canonical prefix is not a kind —
    reporting ``"witness"`` here would readmit the fourth convention §2.3 cut.
    """
    return _classify(value)[1]


# ---------------------------------------------------------------------------
# Validation — raises. The §2.7 "Yes, always" rows and the cutover-gated append row.
# ---------------------------------------------------------------------------


def _refuse(value: Any, form: PrincipalForm, reason: str | None, path: str) -> NoReturn:
    if form is PrincipalForm.BARE_NAME:
        raise RegistaError(
            ErrorCode.PRINCIPAL_ID_NOT_CANONICAL,
            f"{path} {value!r} is a legacy bare name and is refused at creation "
            f"post-cutover (TRUST-DOMAIN.md §2.4 convention 2). Use the canonical "
            f"{sorted(PRINCIPAL_KINDS)} ':' <stable-opaque-subject> form; the legacy "
            f"name keeps binding to its historical events and is joined to the "
            f"canonical principal by a signed, scoped regista.principal-alias/v1 event "
            f"(§2.5) — which joins records for reporting and never satisfies signature "
            f"binding.",
            {
                "reason": reason,
                "path": path,
                "form": str(form),
                "remedy": "principal_alias_bound",
                "alias_payload_type": "regista.principal-alias",
            },
        )
    raise RegistaError(
        ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL,
        f"{path} {value!r} does not satisfy the canonical principal grammar "
        f"(TRUST-DOMAIN.md §2.1): {reason}",
        {"reason": reason, "path": path, "form": str(form)},
    )


def validate_principal_id(value: Any, *, path: str = "principal_id") -> str:
    """Enforce §2.1 strictly. Returns the id unchanged; raises otherwise.

    The §2.7 always-strict paths call this: principal registration, key enrolment,
    project acceptance, and delegation-credential subjects. It is also what the
    cutover-gated ``append_event`` actor_id check runs once a project's cutover event has
    been written.

    Two distinct refusals, so an operator can tell "you used the old convention" from
    "that is not an identifier":

    * :attr:`~regista._errors.ErrorCode.PRINCIPAL_ID_NOT_CANONICAL` — a legacy bare name
      (§2.4 convention 2). The message points at the §2.5 alias path.
    * :attr:`~regista._errors.ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL` — everything else,
      including ``key:*``.
    """
    form, _kind, reason = _classify(value)
    if form is not PrincipalForm.CANONICAL:
        _refuse(value, form, reason, path)
    return str(value)


def parse_principal_id(value: Any, *, path: str = "principal_id") -> PrincipalId:
    """Strictly parse ``value`` into a :class:`PrincipalId`. Raises like
    :func:`validate_principal_id`."""
    form, kind, reason = _classify(value)
    if form is not PrincipalForm.CANONICAL or kind is None:
        _refuse(value, form, reason, path)
    text = str(value)
    return PrincipalId(kind=kind, subject=text.split(":", 1)[1], text=text)


# ---------------------------------------------------------------------------
# §2.2 backend-safe naming
# ---------------------------------------------------------------------------


def backend_name(principal_id: str) -> str:
    """Derive the §2.2 backend-safe name for ``principal_id``.

    ``"rp-" || lowercase_hex(SHA256(domain || utf8(principal_id))[0:16])``.

    Deliberately **not** a ``:``→``-`` substitution: substitution collides
    (``human:it-admin`` and ``human-it:admin`` share a spelling) and the ratified decision
    is a collision-resistant derived name. The mapping is one-way, which is why §2.2
    requires both that the canonical id be stored *inside* the secret and that a lookup
    verb exist (:func:`resolve_backend_name`, ``regista principal resolve-backend-name``);
    without them the KV tree is unauditable by hand.

    Accepts a non-canonical id on purpose: legacy principals already hold secrets and must
    stay resolvable. Grammar enforcement belongs at the creation paths (§2.7), not here.
    """
    if not isinstance(principal_id, str) or not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id must be a non-empty string to derive a backend name",
            {"reason": "empty_principal_id"},
        )
    digest = hashlib.sha256(
        BACKEND_NAME_DOMAIN + principal_id.encode("utf-8")
    ).digest()[:_BACKEND_NAME_DIGEST_BYTES]
    return BACKEND_NAME_PREFIX + digest.hex()


def is_backend_name(value: Any) -> bool:
    """True iff ``value`` has the shape :func:`backend_name` produces."""
    return isinstance(value, str) and BACKEND_NAME_RE.fullmatch(value) is not None


def resolve_backend_name(
    name: str, candidates: Iterable[str]
) -> str | None:
    """Reverse a §2.2 backend name by derive-and-compare over ``candidates``.

    Returns the matching principal id, or ``None`` when no candidate derives to ``name``.
    There is no inverse of SHA-256; this is the lookup §2.2 mandates, and it is only as
    complete as the candidate set the caller supplies. A ``None`` therefore means "not
    among the principals I was given", never "not a principal".
    """
    if not is_backend_name(name):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{name!r} is not a regista backend name (expected 'rp-' + 32 lowercase hex)",
            {"reason": "malformed_backend_name", "backend_name": name},
        )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate and backend_name(candidate) == name:
            return candidate
    return None


# ---------------------------------------------------------------------------
# §2.6 computed conflict state
# ---------------------------------------------------------------------------


def mapping_status(
    actor_id: Any,
    *,
    mapped_actor_ids: Iterable[str] | None = None,
) -> MappingStatus:
    """Whether ``actor_id`` has a deliberately assigned canonical principal.

    ``mapped_actor_ids=None`` yields :attr:`MappingStatus.NOT_EVALUATED` — silence, not a
    claim. A canonical actor id is :attr:`MappingStatus.SELF_CANONICAL`: it already *is* a
    principal, so no assignment is owed.
    """
    if is_canonical_principal_id(actor_id):
        return MappingStatus.SELF_CANONICAL
    if mapped_actor_ids is None:
        return MappingStatus.NOT_EVALUATED
    population = mapped_actor_ids if isinstance(mapped_actor_ids, frozenset | set) else set(
        mapped_actor_ids
    )
    return MappingStatus.MAPPED if actor_id in population else MappingStatus.MAPPING_ABSENT


def identity_consistency(
    actor_id: Any,
    actor_kind: str | None,
    *,
    mapped_actor_ids: Iterable[str] | None = None,
) -> IdentityConsistency:
    """Compute §2.6's ``identity_consistency`` for one event.

    Precedence, most specific first:

    1. a non-canonical actor id with an evaluated-and-absent mapping →
       :attr:`~IdentityConsistency.MAPPING_ABSENT` (§2 consequence 2: "an unmapped writer
       is ``mapping_absent``, not a guess");
    2. any other non-canonical actor id → :attr:`~IdentityConsistency.ACTOR_ID_UNGRAMMATICAL`
       (§2.6: a bare legacy id has ``actor_id_kind = null``, so it is neither consistent nor
       a *kind* conflict);
    3. canonical, and the row's ``actor_kind`` disagrees with the canonical kind →
       :attr:`~IdentityConsistency.PRINCIPAL_KIND_CONFLICT` — the ~231k
       ``human:itadmin`` / ``actor_kind=agent`` corpus;
    4. canonical with a NULL ``actor_kind`` → :attr:`~IdentityConsistency.ACTOR_KIND_ABSENT`;
    5. otherwise :attr:`~IdentityConsistency.CONSISTENT`.

    This is **reporting only**. It changes no verdict: §2.6 asks for the state to be
    surfaced, and §2.7's last row forbids verification from refusing on grammar.
    """
    kind = principal_id_kind(actor_id)
    if kind is None:
        if (
            mapped_actor_ids is not None
            and mapping_status(actor_id, mapped_actor_ids=mapped_actor_ids)
            is MappingStatus.MAPPING_ABSENT
        ):
            return IdentityConsistency.MAPPING_ABSENT
        return IdentityConsistency.ACTOR_ID_UNGRAMMATICAL
    if actor_kind is None:
        return IdentityConsistency.ACTOR_KIND_ABSENT
    if actor_kind in ACTOR_KIND_BY_PRINCIPAL_KIND[kind]:
        return IdentityConsistency.CONSISTENT
    return IdentityConsistency.PRINCIPAL_KIND_CONFLICT


__all__ = [
    "ACTOR_KIND_BY_PRINCIPAL_KIND",
    "BACKEND_NAME_DOMAIN",
    "BACKEND_NAME_PREFIX",
    "BACKEND_NAME_RE",
    "FORBIDDEN_KINDS",
    "MAX_PRINCIPAL_ID_BYTES",
    "MAX_SUBJECT_LENGTH",
    "PRINCIPAL_KINDS",
    "SUBJECT_EDGE_FORBIDDEN",
    "IdentityConsistency",
    "MappingStatus",
    "PrincipalClassification",
    "PrincipalForm",
    "PrincipalId",
    "backend_name",
    "classify_principal_id",
    "identity_consistency",
    "is_backend_name",
    "is_canonical_principal_id",
    "mapping_status",
    "parse_principal_id",
    "principal_id_kind",
    "resolve_backend_name",
    "validate_principal_id",
]
