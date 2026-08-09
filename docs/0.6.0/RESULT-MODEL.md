# regista S1 — Verification Result Model

**Status:** design input for S1 remediation. Not a code change.
**Companion documents:** `FIELD-MATRIX.md` (what is signed), `CUTOVER-POLICY.md` (what an
operator does about it).

---

## 1. The problem this replaces

Today the question "is this event verified?" has **nine mutually incompatible answers** in one
codebase. Each consumer reimplements part of verification and assigns "verified" its own
meaning:

| # | Vocabulary | Produced by |
|---|---|---|
| 1 | bare `bool` | `verify_event` (`_signing.py:326`), `verify_event_with_public_key` (`:570`), `verify_content_anchor` (`_anchoring.py:152`), `_verify_seal_event` (`_archive_segments.py:47`), `MetaMixin.verify_event_signature` (`_api_meta.py:33`), `InMemOpsMixin.verify_event_signature` (`_in_mem_ops.py:23`) |
| 2 | `PrincipalVerificationResult` (4 fields) | `_signing.py:604-609`, only from `_verify_principal_binding_core` (`:668`) |
| 3 | `dict` of 4 keys | `_api_meta.py:64-90` — flattens (2) and loses the type |
| 4 | ad-hoc `dict` of 16 keys | `verify_segment` (`_archive_segments.py:688-708`) |
| 5 | `BundleVerificationReport` (18 fields, incl. a magic string `signature_check`) | `_bundle.py:75-113`, immediately `.to_dict()`ed at `__init__.py:663` |
| 6 | counters only, reasons logged then discarded | `ReplayReport` (`_types.py:600-654`) |
| 7 | `str` status | `AnchorProvider.verify` (`_anchoring.py:122`), `_ops.py:722` |
| 8 | exception | `_ReplayHaltError` (`_replay.py:422`), `RegistaError(REPLAY_HALTED)` (`_in_memory_replay.py:324`), `RegistaError(ACTOR_SIGNER_MISMATCH)` (`_principal_keys.py:378`) |
| 9 | a counter increment and nothing else | witness `sig_verified` (`_witness.py:719-725`, `_in_mem_witness.py:357-385`), replay `principal_binding_failures` (`_replay.py:1108-1109`) |

Two consequences make this an S1 blocker rather than a tidiness complaint:

- **`verify_event` returns `False` with no reason** (`_signing.py:568`). "Tampered payload",
  "wrong key", "unknown envelope shape" and "hash_alg mismatch" are indistinguishable. Adding
  row reconciliation to a function with that return type would produce a new failure mode that
  nobody can triage — and the pressure to add a bypass would be immediate.
- **Some paths already treat "nothing verified" as success.** `BundleVerificationReport.verified`
  (`_bundle.py:659-666`) does not include `signatures_verified > 0`: a bundle in which every
  signature was unverifiable still reports `verified=True` provided `errors` is empty. That is
  exactly the silent-pass shape S1 must make structurally impossible.

---

## 2. The type

One structured result, produced by exactly one function, consumed by every path.

```python
# src/regista/_verification.py  (new module)

from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


class EnvelopeVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"          # also chain-less v3 — byte-identical, see FIELD-MATRIX §1
    V3 = "v3"
    V4 = "v4"
    V5 = "v5"
    ABSENT = "absent"       # canonical_envelope IS NULL (pre-002 rows)
    UNPARSEABLE = "unparseable"
    UNKNOWN_SCHEMA = "unknown_schema"
    KEYLESS_DUMMY = "keyless_dummy"   # InMemory zero-byte material, see CUTOVER §5


class Applicability(StrEnum):
    """The single field every caller is allowed to branch on."""
    FULLY_AUTHENTICATED = "fully_authenticated"
    LEGACY_PARTIAL = "legacy_partial"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


class TrustedKeySource(StrEnum):
    PRINCIPAL_REGISTRY = "principal_registry"   # principal_keys, the anchored root
    KEYSET_FILE = "keyset_file"                 # local KeySet (_keys.py)
    SUPPLIED_PUBLIC_KEY = "supplied_public_key" # offline bundle / auditor export
    BUNDLE_EMBEDDED = "bundle_embedded"         # public keys carried in the bundle
    NONE = "none"                               # no key resolved — never a pass


class FailureReason(StrEnum):
    # envelope
    ENVELOPE_ABSENT = "envelope_absent"
    ENVELOPE_UNPARSEABLE = "envelope_unparseable"
    ENVELOPE_UNKNOWN_SCHEMA = "envelope_unknown_schema"
    ENVELOPE_SCHEMA_INCOMPLETE = "envelope_schema_incomplete"
    # signature
    SIGNATURE_INVALID = "signature_invalid"
    CANONICAL_HASH_MISMATCH = "canonical_hash_mismatch"
    SCHEME_UNRESOLVABLE = "scheme_unresolvable"
    # key / principal
    KEY_UNRESOLVABLE = "key_unresolvable"
    KEY_REVOKED = "key_revoked"
    KEY_NOT_VALID_AT_TIME = "key_not_valid_at_time"
    KEY_ID_MISMATCH = "key_id_mismatch"
    UNREGISTERED_SIGNER = "unregistered_signer"
    PRINCIPAL_ACTOR_MISMATCH = "principal_actor_mismatch"
    # reconciliation
    ROW_FIELD_MISMATCH = "row_field_mismatch"
    ENTITY_ALIAS_MISMATCH = "entity_alias_mismatch"
    # chain
    CHAIN_LINK_MISMATCH = "chain_link_mismatch"
    CHAIN_LINK_ABSENT = "chain_link_absent"
    # legacy
    LEGACY_ENVELOPE_VERSION = "legacy_envelope_version"
    UNSIGNED_EVENT = "unsigned_event"


@dataclass(frozen=True)
class FieldMismatch:
    field: str                  # envelope field name, or "work_item_id!=entity_id"
    envelope_repr: str          # SHORT, redactable rendering — never a raw payload
    row_repr: str
    presence_only: bool = False # absent-vs-NULL disagreement rather than value


@dataclass(frozen=True)
class VerificationResult:
    # --- identity -------------------------------------------------------
    event_id: UUID
    entity_kind: str
    entity_id: UUID
    global_seq: int | None            # structural only; never authenticated

    # --- envelope -------------------------------------------------------
    envelope_version: EnvelopeVersion
    envelope_present: bool
    envelope_schema_valid: bool

    # --- signature ------------------------------------------------------
    signature_valid: bool
    scheme_id: str | None             # DERIVED from key metadata, not the row
    row_scheme_id: str | None         # what the row claimed, for reporting only
    hash_alg: str | None              # taken from the ENVELOPE for v4/v5

    # --- trusted key ----------------------------------------------------
    trusted_key_source: TrustedKeySource
    trusted_key_id: str | None
    principal_id: str | None
    principal_binding_verified: bool

    # --- reconciliation -------------------------------------------------
    row_reconciled: bool
    mismatched_fields: tuple[FieldMismatch, ...] = ()
    authenticated_fields: frozenset[str] = frozenset()
    unsigned_fields: frozenset[str] = frozenset()

    # --- chain ----------------------------------------------------------
    prev_event_hash_ok: bool | None = None          # None = not checked here
    prev_global_event_hash_ok: bool | None = None

    # --- outcome --------------------------------------------------------
    applicability: Applicability = Applicability.UNVERIFIABLE
    reasons: tuple[FailureReason, ...] = ()
    legacy_reason: str | None = None    # human text, only when LEGACY_PARTIAL
    detail: str | None = None           # human text, never machine-parsed

    # --- convenience ----------------------------------------------------
    @property
    def ok(self) -> bool:
        """The ONLY boolean bridge. True iff nothing was left unauthenticated."""
        return self.applicability is Applicability.FULLY_AUTHENTICATED

    @property
    def acceptable_under(self, policy: "VerificationPolicy") -> bool: ...
```

### 2.1 The one function that produces it

```python
def verify_event_strict(
    row: EventRow,                    # the raw DB row / Event, never pre-massaged
    *,
    keys: TrustedKeyResolver,         # resolves key_id -> (public_key, scheme, validity)
    policy: VerificationPolicy,
) -> VerificationResult: ...
```

`verify_event_strict` replaces the *decision* logic in `verify_event` (`_signing.py:326-567`).
`verify_event` itself should be kept only as a thin deprecated shim returning `result.ok`,
marked for removal at the cutover, so that no caller silently keeps its old semantics.

### 2.2 The policy object

```python
@dataclass(frozen=True)
class VerificationPolicy:
    """Bounded, explicit, and non-silent. There is no 'lenient' mode."""
    accept_legacy_before_global_seq: int | None   # the cutover watermark, CUTOVER §3
    accept_legacy_versions: frozenset[EnvelopeVersion]   # e.g. {V4}; never {}
    accept_unsigned_keyless: bool = False         # InMemory keyless only
    require_principal_binding: bool = True
```

**There is no field on `VerificationPolicy` that can turn a signed-field mismatch into a
success.** `mismatched_fields` non-empty ⇒ `applicability = INVALID`, unconditionally, in every
policy. That is a class invariant asserted in `__post_init__`, not a convention.

---

## 3. Strict envelope parsing

The current classifier is permissive by construction. `classify_envelope_version`
(`_signing.py:305-323`) uses `issuperset`:

```python
if "actor_kind" in keys and "actor_metadata" in keys and _V5_FIELDS.issuperset(keys): return 5
if "entity_kind" in keys and "hash_alg" in keys and _V4_FIELDS.issuperset(keys):      return 4
if _V3_FIELDS.issuperset(keys) and (keys & _V3_CHAIN_FIELDS):                         return 3
if keys == _V2_FIELDS:                                                                return 2
return 1
```

So an envelope holding *any subset* of v5's fields classifies as v5; and — the real hole —
**anything that matches nothing at all falls through to `return 1`.** `{}`, `{"x": 1}`, and an
attacker-authored object all become "a v1 envelope". Since v1 signs only six fields, being
classified v1 is the weakest possible claim and therefore the most attractive target.

### 3.1 Required / optional sets, normative

| Version | REQUIRED (exact) | OPTIONAL |
|---|---|---|
| v1 | `event_id, work_item_id, actor_id, on_behalf_of, transition, payload` | — |
| v2 | v1 + `key_id, event_seq, workflow_name, workflow_version, timestamp` | — |
| v3 | same REQUIRED as v2 | `prev_event_hash, global_seq, prev_global_event_hash` |
| v4 | `event_id, entity_kind, entity_id, actor_id, key_id, event_seq, workflow_name, workflow_version, timestamp, hash_alg, on_behalf_of, transition, payload` | same three |
| v5 | v4 REQUIRED + `actor_kind, actor_metadata` | same three |

### 3.2 The algorithm

```
parse strict JSON (no duplicate keys, no NaN/Infinity, top level must be an object)
for version in (v5, v4, v3, v1):            # highest first
    if REQUIRED[version] ⊆ keys and (keys − REQUIRED[version]) ⊆ OPTIONAL[version]:
        if version is v3 and no optional key present: return V2
        return version
return UNKNOWN_SCHEMA                        # NEVER v1
```

Rules that follow from it and must be stated in the implementation:

1. **A missing REQUIRED field is `UNKNOWN_SCHEMA`, not a lower version.** A v5 envelope without
   `actor_metadata` is not a v4 event.
2. **An unrecognised key is `UNKNOWN_SCHEMA`.** No forward-compatibility tolerance: an unknown
   key in a signed envelope is either a future version this build cannot evaluate, or an
   attacker's field. Both must halt, not degrade.
3. **`UNKNOWN_SCHEMA` maps to `Applicability.INVALID`**, never `UNVERIFIABLE`. The envelope
   exists and its bytes are wrong for every known schema. (`UNVERIFIABLE` is reserved for "no
   envelope to evaluate".)
4. **v2 and chain-less v3 are one schema.** Reported as `V2`; not a defect, see FIELD-MATRIX §1.
5. The classifier operates on the **stored bytes only**. Nothing about the row informs the
   version. Today `verify_event` mixes them: `has_chain_fields` is computed from *row* values
   (`_signing.py:360-364`) and steers which candidate branch runs.

**Measured:** across 351,371 estate events, the strict and permissive classifiers agree on
every one (0 disagreements). On the deliberately corrupted test corpus, the injected
`{"event_id":"x","attacker_field":1}` envelope is `UNKNOWN_SCHEMA` under strict rules and
**`v1` under the current permissive rules** — the hole, reproduced.

---

## 4. No fallback to a rebuilt candidate. Ever.

`verify_event` currently assembles up to six candidate envelopes and returns `True` on the
first that verifies:

- chain branch (`_signing.py:366-489`): stored envelope, then a rebuilt v5, then a rebuilt v4,
  then a rebuilt v3;
- non-chain branch (`:491-567`): rebuilt v4, stored (if v2), rebuilt v3, rebuilt v2, rebuilt
  v1, and a "bare" v1 with `on_behalf_of` dropped (`:548-552`).

Every rebuilt candidate is constructed **from the row columns under attack**. The stored
envelope being tried first does not help: verification returns on the *first* success, and the
row-built candidates are the fallback if the stored one fails. Worse, when the stored envelope
verifies, the function returns `True` at `_signing.py:487` having compared **nothing** to the
row except `actor_kind`/`actor_metadata`, and only for `stored_ver == 5` (`:474-486`).

**Normative rule.** Once `canonical_envelope IS NOT NULL`:

> The stored bytes are the only envelope. If they fail to parse strictly, fail signature
> verification, or fail row reconciliation, the result is `INVALID`. No candidate is rebuilt,
> no alternative version is attempted, no field is dropped to try again.

Rebuilding from row columns survives in exactly one place — the *offline reconstruction* of a
**missing** envelope (`canonical_envelope IS NULL`), where there is nothing to fall back
*from*. That path is governed by CUTOVER-POLICY §4 and may never write a reconstructed envelope
unless canonical hash **and** signature uniquely prove the exact candidate.

The `on_behalf_of`-dropping candidate at `_signing.py:548-552` deserves separate mention: it
means an event whose row carries an `on_behalf_of` delegation can verify against an envelope
that signed **no delegation at all**. Under the strict model that candidate simply does not
exist.

---

## 5. Applicability: the four outcomes

| Applicability | Meaning | Required conditions |
|---|---|---|
| `FULLY_AUTHENTICATED` | every field the consumer may read is covered by a valid signature over the stored bytes, and the row agrees | envelope present ∧ schema valid ∧ version ∈ policy's full set (v5 today) ∧ signature valid under a key from a trusted source ∧ `trusted_key_source != NONE` ∧ `mismatched_fields == ()` ∧ principal binding verified (when required) |
| `LEGACY_PARTIAL` | the signature is valid over the stored bytes and the row agrees on **every field that version signs**, but the version leaves named fields unsigned | all of the above **except** version is a legacy version explicitly listed in `policy.accept_legacy_versions` **and** `global_seq < policy.accept_legacy_before_global_seq`. `unsigned_fields` is non-empty and `legacy_reason` is populated. |
| `INVALID` | something that should have verified did not | any of: signature invalid, canonical-hash mismatch, `mismatched_fields != ()`, `UNKNOWN_SCHEMA`, unparseable envelope, entity-alias mismatch, key revoked / not valid at time / id mismatch |
| `UNVERIFIABLE` | there is nothing to verify against | `canonical_envelope IS NULL` (pre-002 rows); or no trusted key could be resolved at all; or the keyless-dummy InMemory case when `policy.accept_unsigned_keyless` is false |

**`INVALID` and `UNVERIFIABLE` are deliberately distinct.** An operator's response differs
completely: `INVALID` means investigate a possible database write attack (CUTOVER §2);
`UNVERIFIABLE` means an evidentiary gap that predates the envelope column (CUTOVER §4).
Collapsing them — as today's `bool` does — is why the audit's central defect went unnoticed.

---

## 6. How `legacy_partial` is prevented from becoming a silent pass

The design review's hard constraint: *there must be NO mode which turns a signed-field mismatch
into success, and legacy statuses must be explicit, bounded by a fixed cutover, and surfaced in
CLI/API output and exit status.* Six mechanisms, each structural rather than conventional:

1. **`legacy_partial` is never reachable from a mismatch.** `mismatched_fields != ()` forces
   `INVALID` before the legacy branch is evaluated. Legacy describes fields the version *never
   signed*; it can never describe fields that were signed and disagree. Asserted as a class
   invariant in `VerificationResult.__post_init__`, so the type cannot be constructed in a
   contradictory state.

2. **`ok` is `applicability is FULLY_AUTHENTICATED` — legacy is not `ok`.** Every current
   boolean caller that migrates to `.ok` therefore becomes *stricter*, not laxer. Any caller
   that wants to accept legacy must say so explicitly by naming the applicability, which makes
   the acceptance greppable.

3. **`unsigned_fields` is mandatory and non-empty for legacy.** A `LEGACY_PARTIAL` result
   carries the exact field names that were not authenticated (e.g.
   `{actor_kind, actor_metadata, global_seq, scheme_id, work_item_id}` for v4). A consumer that
   reads `actor_kind` off a `LEGACY_PARTIAL` result can be made to check membership; a consumer
   that cannot is a bug the type makes visible.

4. **Bounded by a fixed cutover watermark.** `policy.accept_legacy_before_global_seq` is a
   concrete integer per project (CUTOVER §3). An event with `global_seq` at or above it and a
   legacy envelope version is `INVALID`, not `LEGACY_PARTIAL` — so legacy cannot creep forward
   as new events are written. Because `global_seq` is unsigned, the watermark is an
   *administrative* bound, not a cryptographic one, and the policy must say so in its docstring
   and in CLI output: it bounds *policy scope*, it does not authenticate anything.

5. **Surfaced in output and exit status.**
   - JSON: every verification-bearing command emits
     `{"applicability": ..., "unsigned_fields": [...], "legacy_reason": ..., "reasons": [...]}`.
   - Human output: a legacy result prints a `LEGACY` marker plus the unsigned field list, on
     every line — not a footnote.
   - Exit codes, unified across the family: **`0` = all `fully_authenticated`; `2` = at least
     one `legacy_partial`, none worse; `1` = at least one `invalid`; `3` = at least one
     `unverifiable`, none invalid.** Worst status wins. This replaces today's inconsistency,
     where `regista timestamp verify` prints `verified=False` and exits `0`
     (`_cli.py:566-...`), `regista assurance` always exits `0` (`_cli.py:1456`), and
     `regista anchor verify` exits non-zero only for the exact string `"failed"`
     (`_cli.py:676-677`).
   - Counts of `legacy_partial` appear in `ReplayReport`, `BundleVerificationReport` and the
     segment/anchor results as first-class fields, not log lines.

6. **The escape hatch is deleted, not disabled.** Candidate rebuilding (§4) is removed from the
   verify path entirely. There is no flag to re-enable it. A flag would be the silent pass.

---

## 7. Call-site migration map

Every site below currently produces one of the nine vocabularies in §1. This is the complete
inventory, with the mapping each must adopt.

### 7.1 The core (`_signing.py`)

| Site | Today | Becomes |
|---|---|---|
| `verify_event` (`:326-567`) | `bool` | deprecated shim → `verify_event_strict(...).ok`; scheduled for deletion at cutover |
| `verify_event_with_public_key` (`:570-600`) | `bool` | returns `VerificationResult` with `trusted_key_source = SUPPLIED_PUBLIC_KEY`. Note it currently passes `prev_event_hash`/`prev_global_event_hash` but **not** `global_seq` (`:594-595`) — correct per FIELD-MATRIX §3.1 and now moot, since nothing is rebuilt |
| `verify_event_with_principal_binding` (`:795-816`) | `PrincipalVerificationResult` | returns `VerificationResult`; `principal_id`/`trusted_key_id`/`principal_binding_verified` absorb the old four fields, `reasons` absorbs the `error` string's taxonomy (`unregistered-signer`, `key-revoked`, `key-id-mismatch`, `key-not-valid-at-time`, `scheme-mismatch`, `signature-verification-failed` → the `FailureReason` members) |
| `verify_event_dict_principal_binding` (`:819-883`) | `PrincipalVerificationResult` | same; the dict input path stays for the bundle/offline case |
| `_verify_principal_binding_core` (`:668-792`) | `PrincipalVerificationResult` | retained internally, folded into the `VerificationResult` builder. **Fix in passing:** `elif scheme_id == "hmac-sha256": pass` (`:697`) lets a row-claimed HMAC scheme skip the key-id filter — with scheme derived from key metadata (FIELD-MATRIX §3.2) that branch disappears |
| `PrincipalVerificationResult` (`:604-609`) | 4-field dataclass | deleted; superseded |

### 7.2 Replay

| Site | Today | Becomes |
|---|---|---|
| `_replay.py:1038` | `if not verify_event(...)` → raise `_ReplayHaltError` (`:422`, `:1070-1073`) | branch on `applicability`. `INVALID` → halt as today, but the halt carries `reasons` + `mismatched_fields` names. `UNVERIFIABLE` → halt unless policy permits, and record distinctly. `LEGACY_PARTIAL` → a **counted, reported** entry, never a silent continue |
| `_replay.py:1106-1118` | `verify_event_dict_principal_binding` → `warnings += 1`, error string logged to structlog and **discarded** | the result is stored on the `ReplayReportEntry`; the error taxonomy survives into the report |
| `_replay.py:953` | `_requires_principal_registration` keyed on the **row's** `scheme_id` | keyed on the **derived** scheme. Closes the "claim HMAC to opt out of binding" path |
| `_replay.py:1034` | `get_scheme(evt.get("scheme_id", "hmac-sha256"))`, no try/except | scheme resolution moves into `TrustedKeyResolver`; an unresolvable scheme is `SCHEME_UNRESOLVABLE`, not an exception escaping replay |
| `_in_memory_replay.py:298`, `:324-328` | `verify_event` → `RegistaError(REPLAY_HALTED)` | same mapping as `_replay.py`. `verify_principal_binding` is currently a documented no-op (`:184-190`, `:483`) — that must become an explicit `UNVERIFIABLE`/`NONE` key source, not a hardcoded `False` |
| `ReplayReport` (`_types.py:600-654`) | counters `replayed_ok/replayed_drift/halted/warnings/principal_binding_failures` | adds `fully_authenticated`, `legacy_partial`, `invalid`, `unverifiable` counts and per-entry results |

### 7.3 Bundle / offline

| Site | Today | Becomes |
|---|---|---|
| `_bundle.py:690-810` `_verify_event_signatures` | a **full parallel verifier** that calls `scheme.verify(bytes(evt.canonical_envelope), ...)` at `:799-805` and **never reconciles the row**; returns `(verified, unverifiable, errors)` | deleted; delegates to `verify_event_strict`. This function is the audit's defect in its purest form: it trusts the stored envelope verbatim and reads the row separately |
| `_bundle.py:767-793` inline principal binding | duplicated scheme/validity/revocation logic | deleted; `TrustedKeyResolver` with `trusted_key_source = BUNDLE_EMBEDDED` |
| `_bundle.py:767` `if key["scheme"] != evt.scheme_id` | the **only** place today that cross-checks the row's scheme claim against key metadata | becomes the universal rule (FIELD-MATRIX §3.2) |
| `BundleVerificationReport` (`_bundle.py:75-113`) | 18 fields incl. magic `signature_check` string ∈ {`enforced`, `skipped_v1_bundle`, `enforced_none_verified`}; `verified` (`:659-666`) **excludes** `signatures_verified > 0` | `verified` becomes `all(r.applicability is FULLY_AUTHENTICATED for r in results)`; adds the four counts; `signature_check` magic string deleted. **`enforced_none_verified` must stop being a passing state.** |

### 7.4 Segments

| Site | Today | Becomes |
|---|---|---|
| `_archive_segments.py:47-84` `_verify_seal_event` | `bool` collapsing five distinct failures (`:58`, `:65`, `:66`, `:70`, `:78`) | `VerificationResult` for the seal event |
| `_archive_segments.py:597-708` `verify_segment` | ad-hoc 16-key dict; `seal_event_verified` bool ANDed into `verified` (`:679-687`) | a `SegmentVerificationResult` carrying the seal's `VerificationResult` plus the chain findings; `verified` derived from applicability |
| `_cli.py:820-830` | reads keys `errors`/`warnings` that `verify_segment` **never returns** — dead branches | removed with the shape change |

### 7.5 Anchoring

| Site | Today | Becomes |
|---|---|---|
| `_anchoring.py:152-250` `verify_content_anchor` | `bool` with **nine** distinct `return False` paths | returns a result carrying which check failed. Its docstring at `:205-219` already admits it cannot detect a `payload`-only mutation — under the new model that mutation is caught by row reconciliation in replay/bundle, and the anchor result should say which layer is responsible rather than implying coverage it lacks |
| `_ops.py:722-738` | merges a `bool` and a provider `str` into one `str` | provider status and content-anchor result stay distinct in the structure; the string is a rendering, not the model |

### 7.6 Assurance, review gate, witnesses, API, CLI

| Site | Today | Becomes |
|---|---|---|
| `_assurance.py:201-219` `_lineage_verification` | returns `"verified"`/`"asserted"` from the **row's** `scheme_id` and `is_asymmetric`, with **no signature check at all**; `except Exception: return "asserted"` | consumes a `VerificationResult`. `"verified"` requires `FULLY_AUTHENTICATED`. A `LEGACY_PARTIAL` event whose `actor_kind` is in `unsigned_fields` can never be `"verified"` — today it can |
| `_review_validators.py:107`, `:155`, `:260`, `:327`, `:417` | the gate reads `actor_id`, `actor_kind`, `actor_metadata`, `on_behalf_of`, `payload` and **never reads `signature`, `canonical_envelope`, `payload_canonical_hash` or `scheme_id`** | the gate must take `VerificationResult`s alongside events and refuse to derive authorship from a field present in `unsigned_fields`. This is the single highest-value consumer change: it is where unsigned `actor_kind` becomes an authorisation decision |
| `_witness.py:709-725`, `_in_mem_witness.py:357-385` | `sig_verified` bool selects an UPDATE branch and goes nowhere. No `verify_event` call anywhere in the witness path — **the local event's own signature is never checked before shipping it to a witness** | verify before delivery; store the result's applicability on the receipt |
| `_api_meta.py:33-62` `verify_event_signature` | `bool`; `except RegistaError: return False` (`:59`) collapses "unknown key_id" into "bad signature" | returns `VerificationResult` |
| `_api_meta.py:64-90` `verify_event_principal_binding` | dataclass → plain dict | returns `VerificationResult`; `.to_dict()` for JSON transport only |
| `_in_mem_ops.py:23-39` | returns `False` when `self._key_set is None` — reports *"signature invalid"* for events that were **never signed** | returns `UNVERIFIABLE` with `UNSIGNED_EVENT`, per CUTOVER §5 |
| `sidecar/routes.py:610-625` | `{"valid": bool}`, always HTTP 200 | full result body; HTTP status still 200, but `applicability` is in the body and clients branch on it |
| `_cli.py` verify family (`:305`, `:566`, `:663`, `:805`, `:881`, `:962`, `:911`, `:1456`) | exit codes `0`/`0`/`0|1`/`0|1`/`0|1`/`0|1`/`0|1|3`/`0` | the unified 0/1/2/3 scheme in §6 mechanism 5 |

---

## 8. Consumers that read row columns and therefore need a result

For completeness, the row columns each consumer reads and currently trusts without
reconciliation (from the call-site sweep):

| Consumer | Reads | Trusts unreconciled today |
|---|---|---|
| replay (`_replay.py:429-436`) | all 23 columns | all of them; only the signature is checked, and only against the stored envelope |
| review gate (`_review_validators.py`) | `transition`, `actor_id`, `actor_kind`, `actor_metadata`, `on_behalf_of`, `payload` | **all of them** — no crypto is read at all |
| segments (`_archive_segments.py:21-27`) | all 23 | all |
| anchoring (`_anchoring.py:163-164`) | `event_id`, `global_seq`, `canonical_envelope`, `signature`, `prev_global_event_hash`, `payload_canonical_hash`, `hash_alg` | `payload` and `scheme_id` are **not read** — the documented blind spot at `:205-219` |
| bundle (`_bundle.py:117-125`) | all 23 | all |
| assurance (`_assurance.py:286-295`) | `transition`, `actor_id`, `actor_kind`, `actor_metadata`, `on_behalf_of`, `payload`, `scheme_id` | all |
| witnesses (`_witness.py:580-587`) | all 23, with nulls **deleted** from the outbound dict (`:620-634`) so the witness sees a shape-varying event | all |

---

## 9. Open questions for the implementer

1. **`FieldMismatch.envelope_repr` / `row_repr` and secrecy.** Rendering the two values makes
   triage possible but puts payload content into logs and CLI output. Proposal: render a
   type-and-length summary plus a truncated hash by default, with full values behind an
   explicit `--show-values`. The preflight tool takes the stricter line and emits **field names
   only**.
2. **Whether `chain-link` results belong on the per-event result or a separate chain result.**
   Chain validity is a property of an *ordered pair* of events. I have modelled
   `prev_event_hash_ok` / `prev_global_event_hash_ok` as optional per-event fields (`None` when
   not evaluated in that context) rather than forcing every caller to have the predecessor in
   hand. An alternative is a separate `ChainVerificationResult`. Owner call.
3. **The `verify_event` shim's lifetime.** Keeping it eases migration but preserves a boolean
   that hides the new failure modes. Recommend deleting it in the same release, accepting a
   larger diff, because a surviving boolean is exactly the shape the escape hatch had.

---

## 10. `VerificationResultV6` — owned here (`RECONCILIATION.md` Resolution 2)

> **ADDED 2026-08-09 by the P0.1 overlay application.** This document was frozen for v1–v5.
> `RECONCILIATION.md` Resolution 2 assigned the v6 result model here — it was the first of three
> ownerless artifacts, and an unowned result model means every consumer invents its own answer to
> "what did this verification actually establish?", which is the defect class S1 exists to close.
> Implemented in `_verification.py`. `V6-ENVELOPE.md` §9.4 and `CUTOVER-CLASSIFICATION.md` §7 are
> the *rationale index* for these additions: they name which v6 rule forces each one. Where they
> and this section differ in completeness, **this section is normative**.

### 10.1 Added fields

Extend the S1 `VerificationResult` (§2) with these **non-optional** fields:

```python
epoch_position:       "pre_cutover | is_cutover | post_cutover | no_cutover | unknown"
attribution:          "individual | shared_secret | none"
checkpoint_binding:   "externally_pinned | checkpoint_bound | unbound | not_applicable"
unbound_properties:   frozenset[str]
trust_domain_id:      str | None
trust_root:           "externally_pinned | trust_log_only | bundled_only | absent"
root_governance:      "co_signed | solo | solo_effective | unknown"
key_binding:          ("accepted_in_project | bootstrap_external | trust_log_only | "
                       "retrospective | legacy_registry | legacy_unbound | unresolved | "
                       "mismatched | after_use | recovery_rotated")
revocation_status:    ("not_revoked | revoked_before_use | indeterminate_window | "
                       "suspect_declared | unknown")
identity_consistency: ("consistent | principal_kind_conflict | actor_id_ungrammatical | "
                       "mapping_absent")
producer_consistency: ("matches_published_policy | contradicts_published_policy | "
                       "policy_not_supplied | not_applicable")
```

Add `EnvelopeVersion.V6`, and these failure reasons:

`ENVELOPE_UNCANONICAL`, `PROJECT_BINDING_MISMATCH`, `TRUST_DOMAIN_MISMATCH`,
`KEY_BINDING_UNRESOLVED`, `KEY_BINDING_NOT_BEFORE_USE`, `KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`,
`WORKFLOW_DEFINITION_MISMATCH`, `WORKFLOW_REGISTRATION_UNRESOLVED`, `DELEGATION_CHAIN_INVALID`,
`EPOCH_VIOLATION`, `PRODUCER_POLICY_MISMATCH`.

Add these policy inputs: `pinned_project_instance_id`, `pinned_trust_domain_id`,
`cutover_checkpoint_event_hash`, `producer_policy`.

`_NEVER_SIGNED` becomes **version-dependent**: `scheme_id` is signed in v6 and is not in the set
for a v6 event; `global_seq` is never signed in any version.

`payload_canonical_hash` semantics are likewise version-dependent — v1–v5 hash the canonical
envelope, v6 hashes the signature input (`V6-ENVELOPE.md` §9.4). This is the single easiest place
to introduce a v6 verification bug.

### 10.2 Class invariants

Enforced in `__post_init__`, alongside the four already there (`_verification.py:418-443`). These
are asserts, not conventions.

1. **Any contradiction is `INVALID`, and no policy can waive it** — signed-field, project,
   trust-domain, workflow, delegation, epoch or producer-policy.
2. **Post-cutover v4/v5 or HMAC is `INVALID` / `EPOCH_VIOLATION`.**
3. **Pre-cutover v4/v5 is never `FULLY_AUTHENTICATED` once a checkpoint exists.** (This is the
   ~334,000-event reclassification. It changes no byte and no cryptographic check; it corrects a
   claim boundary. Preflight reports the before/after distribution so it is expected rather than
   discovered.)
4. A normal v6 event is fully authenticated **only** with `key_binding = accepted_in_project`.
5. A valid checkpoint or project initialisation may instead use `key_binding =
   bootstrap_external`, but **only** with `trust_root = externally_pinned` **and**
   `checkpoint_binding = externally_pinned`. Bootstrap without an external pin is not a bootstrap;
   it is an unauthenticated first event.
6. `trust_log_only` is distinct from both an external pin and bundled-only material. It is the
   honest middle state, and most online verifications land there.
7. A valid HMAC event has `attribution = shared_secret`, `key_binding = legacy_unbound`, and
   `LEGACY_PARTIAL`. For `regista-prod-001` the report additionally carries reason
   `disclosed_shared_secret` and **may not imply origin authentication** (WI-278).
8. `unsigned_fields` remains **row-column vocabulary**; `unbound_properties` is **semantic
   vocabulary** (`CUTOVER-CLASSIFICATION.md` §7.2). Do not merge them: one answers "which column
   was not covered by a signature", the other "which property is not established at all".
9. **Missing pins produce explicit unbound / not-checked states.** A check is never silently
   skipped because its input was absent. `producer_consistency = policy_not_supplied` is the
   model case.
10. Retained from `TRUST-DOMAIN.md` §8.3: `key_binding ∈ {mismatched, after_use}` ⟹ `INVALID`;
    `retrospective` ⟹ not `FULLY_AUTHENTICATED` with `legacy_reason =
    "retrospective_key_binding"`; `legacy_registry` ⟹ not `FULLY_AUTHENTICATED` and
    `"key_binding" ∈ unsigned_fields`; `revocation_status == revoked_before_use` ⟹ `INVALID`; a
    v6 event with `key_binding == legacy_registry` **raises** (programming error).

### 10.3 The boolean bridge, and the one that does not exist

The only boolean bridge remains:

```python
result.ok == (applicability is FULLY_AUTHENTICATED)
```

Review and gate code uses **`acceptable_under(named_policy)`**, never a bare attribute.
`REVIEW-VERDICTS.md` §4.1 rule 1 cites `result.accepted`, which **does not exist in this model**
(`RECONCILIATION.md` collision 23) — read that rule as `acceptable_under(<the named policy>)`,
with the policy named in the report so an auditor can see which one was applied.

An implementation that reintroduces a general-purpose boolean has reintroduced the escape hatch:
a boolean cannot carry `LEGACY_PARTIAL`, `bootstrap_external` or `policy_not_supplied`, so every
caller re-derives them, and they re-derive them differently.
