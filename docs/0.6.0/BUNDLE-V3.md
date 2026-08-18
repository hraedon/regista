# BUNDLE-V3 — frozen contract for the regista 0.6.0 signed audit bundle

Status: **FROZEN for Stage 0**. Contracts only. No production source changed.
Owner of this document: bundle v3 format + verification (audit item S3, S4, S5/BC-016; WI-209, WI-269, WI-240, WI-259, WI-261).
Verified against post-S1 code at `334b995` (`fix(signing): authenticate the row, not just the envelope (WI-267) (#37)`), which is `origin/main`. Line citations are against that tree.

Companion document: `REVIEW-VERDICTS.md` (same author, same freeze).

---

## 0. Interfaces I consume, and what I require of them

I do not specify these. I state the minimum each must provide for bundle v3 to be implementable. Names follow the Stage 0 freeze list at `ARCHITECTURE-0.6.0.md:712-718`; if a sibling lands its artifact under a different filename, the numbered item is the binding reference.

| From | Artifact (Stage 0 item) | What bundle v3 requires |
|---|---|---|
| Sibling A | v6 envelope schema + canonicalization (item 2) | (A1) A stable **canonical envelope byte string** per event and a stable **JCS** function I can call over my own statement. (A2) `project_instance_id` and `trust_domain_id` **inside** the signed envelope (S9). (A3) `scheme_id` **inside** the signed envelope (S2), so bundle v3 never has to infer scheme from a row column. (A4) A frozen, **version-aware** definition of `event_hash`: v1–v5 use `sha256(canonical_envelope ‖ signature)` and v6 uses the domain-separated, length-framed construction in `V6-ENVELOPE.md` §5.3. The membership leaf in §3.3 uses the referenced event's version-derived hash. |
| Sibling B | trust-domain genesis / key lifecycle / publication channel (item 5) | (B1) A **trust policy file** format the auditor receives out of band, carrying at minimum the fields in §4.2. (B2) A **fingerprint function** over a public key, identical to the one the genesis document and the enrollment events use, so a pinned fingerprint and a bundled key are comparable without me re-deriving it. (B3) The genesis document's **signer set and threshold visible in the artifact** (owner decision Q1, WI-272) — bundle v3 must be able to restate the governance mode it verified under, so §4.5 requires a field for it. (B4) A **bundle-signing authority** that is nameable by fingerprint in the trust policy *independently of the bundle*. (B5) A signed **trust-log checkpoint** with a hash the auditor can pin. (B6) The `regista.action-delegation/v1` credential (WI-008) — optional for v3, consumed only in `REVIEW-VERDICTS.md` §5; it authorises an action and never establishes principal kind. |
| Sibling D | preflight tool (item 7 / Stage 0 preflight extension) | (D1) Per-project canonical-JSON preflight output containing chain genesis hash, head hash, event count, envelope/scheme counts, and identity conflicts — bundle export **must** compare its own observation against a preflight result before signing (§5.2), and the auditor may be given the preflight output as corroborating evidence. |
| Me → siblings | | Bundle v3 needs **nothing** from segments or anchors (§7). Sibling B's publication channel is the only source of the head pin that makes `complete-store` checkable (§3.5). |

---

## 1. What is being killed, and why patching failed

S4 says bundle membership has **no local patch** (`AUDIT-REPORT.md:52-55`) because the artifact carries no signed statement of what it should contain. The area has since been patched four times:

| Patch | Landed as | What it added | Why it is a heuristic |
|---|---|---|---|
| WI-254 (a) | `559fa3c` | anchor every segment record; check manifest counts | `_verify_manifest_counts` (`src/regista/_bundle.py:496-543`) — its own docstring concedes "the bundle hash is unkeyed and therefore attacker-recomputable, so this check does not make the artifact unforgeable" (`:505-508`) |
| WI-254 (b) | `cacc173` | reconcile every segment record against its signed seal event | `_reconcile_segment_with_seal` (`src/regista/_bundle.py:1234-1289`) — real, but only for stores that *have* segments; the estate has **zero** |
| WI-255 | `559fa3c` | manifest count↔section comparison for all four sections | `_MANIFEST_COUNT_SECTIONS` (`src/regista/_bundle.py:488-493`) — counts a tamperer edits in the same pass as the deletion |
| window gate | in `334b995` tree | reject windows an export could not have produced; require every event inside the declared window | `_window_is_impossible` / `_verify_declared_window` (`src/regista/_bundle.py:1017-1115`) |

Every one of them is the same shape: **the claim is unsigned, so the check must argue about plausibility.** `_exported_window`'s docstring is the clearest confession — a `until_seq = 0` manifest edit "skipped EVERY segment check in the bundle, reopening both WI-254 and WI-255 with a one-key manifest edit" (`src/regista/_bundle.py:1058-1068`). That is not a defect in the patch; it is what happens when a verifier reasons about an attacker-writable field.

The documented residual survives because the root fact is unchanged: `_canonical_bundle_bytes` (`src/regista/_bundle.py:1729-1743`) produces an **unkeyed** SHA-256 that anyone can recompute after editing anything. `bundle_hash_ok` (`:579`) therefore detects accidental corruption and nothing else.

**Bundle v3 kills the class by signing the claim.** Once `scope`, `event_count` and the membership root are inside a signature, a tamperer must forge that signature; there is nothing left for a plausibility heuristic to do, and ~900 lines of heuristic get deleted rather than maintained (§8).

---

## 2. Format decision

- `format_version` **1 is deleted, and so is 2.** Bundle v3 is the only accepted format. `_SUPPORTED_FORMAT_VERSIONS` (`src/regista/_bundle.py:41`) becomes `frozenset({3})`; a bundle declaring 1 or 2 is rejected with a named error, not downgraded.
- This kills S3 outright rather than patching it. The v1 branch at `src/regista/_bundle.py:653-657` — which sets `signature_check = "skipped_v1_bundle"` and returns `sigs_verified = 0` — ceases to exist. So does the v1 special-casing inside `_verify_manifest_counts` (`:513-517`, `:521-529`) and inside `_canonical_bundle_bytes` (`:1739-1742`).
- Rationale (from `ARCHITECTURE-0.6.0.md:169-173`): bundles are **regenerable artifacts**, unlike event history. There is no compatibility debt to honour. A v1/v2 bundle an auditor already holds is re-exported from the store; if the store is gone, the old bundle was never authenticated to anything anyway.
- **A v3 bundle is not a superset of v2.** It is a different document with a different top-level shape (§3.1). Do not add v3 keys to the v2 dict and bump a number.

---

## 3. The signed statement

### 3.1 Document shape

```json
{
  "statement": { ... },              // §3.2, the ONLY signed object
  "statement_signature": {           // §3.4
    "scheme_id": "ed25519",
    "key_id": "pk_...",
    "signature": "base64..."
  },
  "sections": {
    "events":               [ ... ], // §3.6
    "key_lifecycle":        [ ... ],
    "project_key_acceptance":[ ... ],
    "workflows":            [ ... ],
    "review_verdicts":      [ ... ],
    "checkpoints":          [ ... ],
    "bundled_key_evidence": [ ... ], // §4.3 — NEVER a root of trust
    "external_evidence":    [ ... ]  // §4.6 — classified, never trusted silently
  },
  "index": { ... }                   // OPTIONAL, derived, never verified against
}
```

Rules:

1. **`statement` is the only signed object.** Everything else is content whose digest the statement commits to. There is no second signature and no nested signature over subsections.
2. **`index` is advisory.** A verifier MUST recompute every field it would otherwise read from `index`. Emitting it is optional; consuming it in the verification path is forbidden. It exists so a human can grep a 350k-event bundle without parsing it.
3. **Unknown top-level keys are a rejection**, not an ignore. A v2 verifier's tolerance of extra keys is how `public_keys` quietly became a trust root.
4. The bundle is canonical JSON. `_reject_archive_output_name` (`src/regista/_bundle.py:70-79`, WI-210) is retained unchanged.

## OVERLAY APPLIED — 2026-08-09 (P0.1)

`RECONCILIATION.md` governs this document; superseded clauses carry **SUPERSEDED** markers where
they sit. Summary of what changed here:

| Clause | Superseded by | Replacement |
|---|---|---|
| §3.2 `scope.kind` including `declared-selection` | Resolution 4 | §3.5 — **`declared-selection` is cut from 0.6.0**; `complete-store` and `contiguous-range` only |
| §3.2 `governance` block | collision 12 | §3.2 — `TRUST-DOMAIN.md` §3.6's four-field signed `trust_root` block replaces it |
| §3.2 `signer` | collision 21 | §3.2 — one signer shape, six fields, everywhere |
| §3.2 sections | Resolution 4 | §3.2 — closed section schemas + mandatory dependency closure |
| §3.3 leaf/node construction and the legacy event hash | Resolution 4, collisions 9, 10 | §3.3 — no leading `0x00`, `scope_ordinal`, `regista.bundle.node.v1`, **version-aware** event hash |
| §4.2 trust policy | collision 11 | §4.2 — `TRUST-DOMAIN.md` §4.6 owns the one policy; `accept_legacy_shared_secret_events` |
| §5.1 axes | Resolution 4, collisions 13, 14 | §5.1 — widened axes, `trust_log_only`, attribution and key-binding counts, external checkpoint required |
| §6 `format_version` 1 | `ARCHITECTURE-FINAL.md` §5 | §6 — dropped **entirely**, not deprecated |

### 3.2 Statement schema

> **LOCAL APPLICATION — `RECONCILIATION.md` collisions 12, 21 and Resolution 4.** The schema
> example is illustrative and its counts are named-snapshot placeholders. The amended rules below
> are already part of the contract: use `trust_root`, the single signer shape or direct
> `root_signatures[]`, the closed section set and the cut `declared-selection` scope; do not
> implement an older shape merely because it appears in a worked example.

Building on `ARCHITECTURE-0.6.0.md:198-233`, with the additions marked **[+]** (see §11 DIVERGENCES for why).

```json
{
  "type": "regista.audit-bundle",
  "version": 3,
  "bundle_id": "uuid",
  "project_instance_id": "uuid",
  "trust_domain_id": "uuid",
  "created_at": "2026-08-08T21:50:22.000000+00:00",

  "scope": {
    "kind": "complete-store | contiguous-range",     // declared-selection: CUT, see §3.5
    "event_count": 352509,                            // illustrative; a measured snapshot value
    "first_event_hash": "sha256:...",
    "last_event_hash": "sha256:...",
    "preceding_event_hash": null
  },

  "event_membership_root": "sha256:...",
  "section_digests": {
    "events": "sha256:...",
    "key_lifecycle": "sha256:...",
    "project_key_acceptance": "sha256:...",
    "workflows": "sha256:...",
    "review_verdicts": "sha256:...",
    "checkpoints": "sha256:...",
    "bundled_key_evidence": "sha256:...",
    "external_evidence": "sha256:..."
  },

  "epoch": {                                        // [+]
    "cutover_event_hash": "sha256:...|null",
    "legacy_event_count": 303820,
    "v6_event_count": 48689,
    "scheme_counts": {"hmac-sha256": 303820, "ed25519": 48689}
  },

  "trust_root": {                                   // [Δ] replaces `governance` — collision 12
    "trust_domain_id": "uuid",
    "trust_domain_core_digest": "sha256:...",
    "root_governance": { "mode": "co_signed | solo | solo_effective",
                         "threshold": 2, "signer_count": 2 },
    "genesis_document_digest": "sha256:..."
  },

  "signer": {                                       // [Δ] one shape everywhere — collision 21
    "principal_id": "service:...",
    "key_id": "pk_...",
    "scheme_id": "ed25519",
    "fingerprint": "ed25519:sha256:...",
    "authority_kind": "root | registrar | scoped",
    "authority_event_hash": "sha256:..."
  },

  "exporter": {                                     // [+]
    "regista_version": "0.6.0",
    "statement_schema": "regista.audit-bundle/3"
  }
}
```

Hard rules:

- **Every section named in `section_digests` MUST be present in `sections`, and every section present MUST be named in `section_digests`.** A one-sided set is a rejection. This is what makes "delete a whole section" fail without enumerating fields — the *set of section names* is signed, not just their contents.
- `scope.event_count` MUST equal the number of leaves in the membership tree AND the length of `sections.events`. Two independent equalities, one signature.
- `epoch.legacy_event_count + epoch.v6_event_count` MUST equal `scope.event_count`.
- `trust_root.root_governance` MUST be the current governance state obtained by replaying the
  signed trust-domain governance log through the authenticated trust-log checkpoint. It is not
  copied from genesis, configuration or a mutable projection. A verifier compares the replayed
  state with the signed statement and the sole trust policy from `TRUST-DOMAIN.md` §4.6; a mismatch
  is `invalid`. An estate rooted by a solo signer therefore says so **in every bundle it produces**,
  satisfying WI-272's binding constraint that lab mode be visible in the artifact.
- `signer.fingerprint` is redundant with `key_id` **on purpose**: the auditor pins fingerprints, not key ids (B2), and a signed self-statement of the fingerprint means the pin comparison never has to route through the bundled registry.

> **SUPERSEDED — `RECONCILIATION.md` collisions 12, 21 and Resolution 4.** Four changes to the
> statement above, all reflected in the JSON:
>
> 1. **`governance` is replaced by `trust_root`** — the four-field signed block from
>    `TRUST-DOMAIN.md` §3.6/§4.6. C's smaller block could not carry the core digest an auditor
>    pins, so a verifier holding a policy had nothing in the bundle to compare it against. Mode
>    spellings are `co_signed | solo | solo_effective`; **`single_signer_lab` is retired.**
> 2. **One signer shape**, six fields, in every signed publication (bundle, checkpoint, catalog,
>    producer policy). A **direct root-threshold** signature does not invent a principal id: it
>    uses `root_signatures[]` and omits `signer`.
> 3. **`declared-selection` is cut** (§3.5), so `scope.selection` disappears with it.
> 4. **Section schemas are closed, and export computes dependency closure.**
>    `events` carries canonical envelope/signature records only. `key_lifecycle`,
>    `project_key_acceptance`, `workflows`, `review_verdicts` and `checkpoints` carry **sorted
>    event-hash references into `events`** — never extracted payload duplicates, which are a
>    second copy of signed data for a consumer to read instead of the signed one.
>    `bundled_key_evidence` carries exact public-key material records; `external_evidence` is
>    convenience-only and **never raises an axis**. **Unknown section names or nested keys
>    reject.**
>
>    Closure is computed for signing authority, lifecycle, acceptance, workflow, delegation,
>    checkpoints and verdict supersession. **Missing closure in `complete-store` is invalid**; a
>    bounded range reports the named dependency as outside scope — never silently valid.

### 3.3 Membership — the part that must not require enumerating fields

**Leaf.** For the event at `scope_ordinal` `i` (0-based, **project-chain traversal order**, local
to the signed scope):

```text
leaf_i = SHA256( b"regista.bundle.member.v1\x00" ‖ uint64be(i) ‖ event_hash_i )
```

where `event_hash_i` is the **version-aware** event hash: v1–v5 use
`SHA256(canonical_envelope ‖ signature)`; **v6 uses the domain-separated, length-framed
construction at `V6-ENVELOPE.md` §5.3.** Every event reference — here and everywhere else — uses
the *referenced event's* version-derived hash.

**Tree.** RFC 6962 (Certificate Transparency) Merkle tree, with named domains:

```text
MTH({})        = SHA256()                       // empty, unreachable: empty bundles are rejected
MTH({d0})      = leaf_0                          // leaves are already domain-tagged above
MTH(D[n])      = SHA256( b"regista.bundle.node.v1\x00" ‖ MTH(D[0:k]) ‖ MTH(D[k:n]) ),
                 k = largest power of 2 < n
```

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4, collisions 9 and 10.** Three corrections:
>
> 1. **The event hash is version-aware.** Hardcoding the legacy formula would compute a v6
>    event's identity with the v1–v5 construction, so a v6 event's membership leaf would not
>    match the hash the chain itself commits to. Every hash reference in a mixed-epoch bundle —
>    and every bundle over a cut-over project is mixed — depends on this.
> 2. **No leading `0x00` on the leaf, and no bare `0x01` on interior nodes.** The domain tags
>    (`regista.bundle.member.v1\x00`, `regista.bundle.node.v1\x00`) *are* the separation; the
>    extra byte was an unreconciled difference between this document and the architecture, and
>    two implementations differing by one byte produce two different roots and one very confusing
>    incident.
> 3. **The ordinal is `scope_ordinal`, local to the signed scope**, derived from chain traversal.
>    It is never `global_seq` and never a store-wide index.
>
> **Byte vectors for the leaf, the node, an odd-length tree and a mixed-epoch tree are frozen
> under P0.3.** Do not implement this section without them.

Three reasons this exact tree and not a rolling hash:

1. **Named domains provide leaf/interior separation.** Leaves use
   `regista.bundle.member.v1\x00`; interior nodes use `regista.bundle.node.v1\x00`. Do not add a
   separate positional `0x00` or `0x01` byte: the domain tags, together with the RFC 6962 split,
   are the frozen construction.
2. **No odd-node duplication.** The Bitcoin-style "duplicate the last node" rule admits two distinct leaf sequences with the same root. RFC 6962's split-at-largest-power-of-two has no such collision.
3. It buys **single-event inclusion proofs** for free. Bundle v3 does not use them, but a later "prove this one event was in the bundle you already verified" workflow needs no format change.

**Ordering is by project-chain traversal, never by `global_seq` and never by event UUID.** `global_seq` is unsigned by construction — `_verification.py:430-434` asserts it can never appear in `authenticated_fields`, and the preflight shows all 351,371 live events carry it as an unsigned field. Ordering the membership tree on it would let a row-write attacker permute the tree without touching a signed byte. Traversal is: from the genesis event named by `scope.first_event_hash`, follow `prev_global_event_hash` links forward to `scope.last_event_hash`.

**What this detects, without enumerating fields:**

| Attack | Detected by |
|---|---|
| delete any event | leaf count ≠ `scope.event_count`; root ≠ signed root |
| inject any event | same |
| replace an event | its `event_hash` changes ⇒ root changes |
| reorder events | ordinal changes ⇒ leaves change ⇒ root changes |
| delete a whole work item | its events are leaves; root changes |
| truncate the tail | `scope.last_event_hash` no longer reachable; count short |
| delete a whole section | section name in signed `section_digests` with no section present |
| edit the key registry | `section_digests.bundled_key_evidence` mismatch |
| edit the manifest counts | there is no manifest; `scope` is signed |
| edit the export window | there is no window; `scope` is signed |

The last two rows are the four prior patches, retired.

### 3.4 What is signed, by whom, over what bytes

**Signature input:**

```text
b"regista.audit-bundle.v3\x00" ‖ JCS(statement)
```

- `JCS` is RFC 8785 as implemented by `src/regista/_jcs.py`. The audit attacked this canonicalizer and could not break it (`AUDIT-REPORT.md:105-106`: RFC mixed-script UTF-16BE vectors, all 12 ES6 number-serialization boundary vectors, nine hostile inputs rejected fail-closed). It is the one primitive here I am willing to build on without re-litigating.
- The domain prefix is mandatory and MUST NOT be omitted "because JCS output is unambiguous". It is what stops a v3 statement being replayed as some other JCS-signed regista object under the same key.
- **Signer:** a principal enrolled in the trust domain and named in the trust policy as a permitted **bundle-signing authority** (B4). Scheme MUST be `ed25519`. There is no HMAC bundle signature — an HMAC statement signature would be verifiable only by the operator, which is the S5 circularity wearing a different hat.
- The bundle-signing key MAY be the project's writer key, but the trust policy decides that, not the bundle.

### 3.5 Scope kinds — what each can and cannot prove

| `scope.kind` | Required fields | Proves | Does not prove |
|---|---|---|---|
| `complete-store` | `first_event_hash` = project genesis; `last_event_hash` = head observed by signer; `event_count`; `preceding_event_hash: null` | the signer attested this is the whole chain as it stood at `created_at`, and the presented bytes are exactly that | that the signer's observation was the true head. **Only an independently pinned head (from sibling B's publication channel) closes this.** Without one, tail truncation after the last published checkpoint is undetectable — `ARCHITECTURE-0.6.0.md:875` residual 6 |
| `contiguous-range` | `preceding_event_hash` MUST be non-null (or the range starts at genesis) | the range is anchored to the chain immediately before it, so a chunk cannot be silently relocated | anything about events outside the range |
| ~~`declared-selection`~~ | — | — | **CUT FROM 0.6.0** — see below |

> **CUT — `RECONCILIATION.md` Resolution 4 and FINAL SCOPE.** `declared-selection` does not ship
> in 0.6.0. Two reasons, and the second is the decisive one:
>
> 1. There is **no completeness proof** available for it and no concrete release requirement that
>    needs an attested-completeness mode.
> 2. Its proposed epoch clamp **mislabels an all-v6 selection as legacy** (§5.1). A scope kind
>    whose verdict is wrong in the safe-looking direction is worse than an absent feature.
>
> `export` produces `complete-store` by default and `contiguous-range` when given range bounds.
> There is no third mode and no `--selection` argument. If a filtered export is needed later, it
> arrives with its own verdict semantics, not by re-enabling this row.

### 3.6 Event record shape

```json
{ "canonical_envelope": "base64...", "signature": "base64..." }
```

**Nothing else.** Not `transition`, not `payload`, not `actor_id`, not `global_seq`.

This is the direct consequence of S1. Post-S1, `_verify_event_signatures` no longer runs its own verifier; it delegates to `verify_event_strict` (`src/regista/_bundle.py:832-836`) which parses the envelope and reconciles every duplicated row column (`_reconcile`, `src/regista/_verification.py:956`). Under bundle v3 there **are no duplicated row columns** — the projection is recomputed from the envelope at parse time. `_row_to_event_dict` (`src/regista/_bundle.py:1671-1726`), which today exports 20 columns alongside the envelope, is deleted.

Note the encoding change: base64, not hex (`:1697-1706` uses hex today). Rationale: a 352k-event bundle is size-bound (`MAX_BUNDLE_BYTES = 512 MiB`, `:46`), and base64 is 33% overhead against hex's 100%. This materially changes whether the estate's largest project fits in one bundle. Any change here must be reflected in the `section_digests.events` computation (§3.7).

Consequence for the S1 corpus: `events` records whose `canonical_envelope IS NULL` (pre-002 rows, `EnvelopeVersion.ABSENT` at `src/regista/_verification.py:87`) **cannot be represented in a v3 bundle at all**. Export MUST fail closed on them rather than emit a record with a null envelope. Sibling D's preflight (D1) is where an operator learns this before cutover, not at export time.

### 3.7 Section digests

For each section: `SHA256( b"regista.bundle.section.v1\x00" ‖ section_name ‖ 0x00 ‖ JCS(section_array) )`.

The section name is inside the hash input, so two sections cannot be swapped even if their contents happen to be structurally compatible.

---

## 4. Trust root

### 4.1 The structural fix is the function signature

Today:

```python
def verify_audit_bundle_offline(bundle_path: str | Path) -> BundleVerificationReport:   # _bundle.py:546
```

**One argument.** There is no parameter through which external trust material could be supplied, and the CLI calls it with one argument (`src/regista/_cli.py:1000`). S5/BC-016 is not a bug in the key-selection logic at `_bundle.py:723-753`; it is a bug in this signature. Every "remember to pass the trust file" discipline fails eventually. Making it un-passable makes it un-forgettable.

Bundle v3:

```python
def verify_audit_bundle_v3(
    bundle_path: str | Path,
    trust: TrustPolicy | AcceptBundledKeys,     # REQUIRED. No default. No None.
) -> BundleReport:
```

- `TrustPolicy` is constructed only from an auditor-supplied file or explicit fingerprints. It cannot be constructed from a bundle.
- `AcceptBundledKeys` is a distinct, deliberately awkward type carrying the operator's explicit acceptance. It is not a `TrustPolicy` and does not subclass one. There is no implicit conversion.
- There is **no** third state. A caller who has nothing must choose one of the two and live with the verdict ceiling that choice imposes (§5.2).

This is the S5 fix. Everything below is elaboration.

### 4.2 Trust policy contents (consumed from sibling B)

> **AMENDED — `RECONCILIATION.md` collision 11 and Resolution 4.** `TRUST-DOMAIN.md` §4.6 owns
> the **one** trust policy schema; this section consumes it and defines no competing shape. Two
> field-level consequences: the legacy toggle is `accept_legacy_shared_secret_events` (not
> `accept_hmac_prefix` — the legacy region is mixed, not a prefix), and fingerprints alone cannot
> supply verification keys. **Key material and trust are separate inputs:** bytes may come from
> `bundled_key_evidence`, authority comes only from the auditor's pin.

Bundle v3 consumes the policy owned by `TRUST-DOMAIN.md` §4.6 and MUST reject a policy missing
the fields that section requires. It does not define a second trust-policy schema. The relevant
fields are `trust_domain_id`, `trust_domain_core_digest`, `genesis_document_digest`,
`required_root_governance`, `root_signer_fingerprints`, `min_root_signatures`, `publication`,
`accepted_project_instance_ids`, `min_trust_log_checkpoint`, `known_project_checkpoints`,
`bundle_signing` and `legacy_epoch_policy`. `known_project_checkpoints` is optional; supplying
the project's signed head and count is what upgrades `complete-store` from an attestation to a
checked claim (§3.5). The legacy policy uses `accept_legacy_shared_secret_events`, not a prefix
model. There is no competing `governance_expectation` or `permitted_bundle_signers` field.

WI-209's `--trusted-fingerprints <file>` (acceptance criterion 4) is subsumed: repeated
`--trusted-fingerprint <fp>` remains as a minimal ad-hoc form for the caller-supplied trust
material, and every policy-dependent axis it cannot answer reports `not_checkable` rather than
passing.

### 4.3 The bundled registry is evidence, never a root

Three mechanisms, because one is not enough:

1. **Naming.** The section is `bundled_key_evidence`, not `public_keys`. No code path can read it as a root by habit or by autocomplete. `BundleKeyResolver` (`src/regista/_verification.py:758`) is renamed `BundledKeyEvidenceResolver`.
2. **Typing.** The resolver used in the default path is built **only** from `TrustPolicy`. The evidence resolver is a different type, constructed only where an `AcceptBundledKeys` value is in scope. `TrustedKeySource.BUNDLE_EMBEDDED` (`src/regista/_verification.py:106`) already exists and is already recorded per event by `verify_event_strict` — bundle v3 makes it **load-bearing**: any use of it clamps the final verdict (§5.2, rule C).
3. **Reporting.** The report always names which root authenticated what, per event, aggregated. There is no report shape in which "verified" appears without an adjacent statement of the root.

**The one thing bundled evidence is genuinely good for** — and WI-209 got this right — is *corroboration*, not authentication. Given a policy-pinned root, the verifier can check the bundled registry ⇄ chain consistency: every key it names must have a matching signed enrollment event **inside the bundle**, whose fingerprint equals the registry row's. Disagreement is a finding. Agreement adds nothing to the trust chain but tells the auditor the operator's own records are self-consistent, which is worth reporting.

### 4.4 WI-209's three requirements, restated for 0.6.0

WI-209 specified this area first and most of it survives. Where it changes, it is because anchoring is being deleted (`ARCHITECTURE-0.6.0.md:641-673`).

| WI-209 acceptance criterion | 0.6.0 disposition |
|---|---|
| 1. Registry⇄chain consistency — every registry key used for verification has a matching `principal_enrolled` event in the bundle whose fingerprint equals `sha256(public_key)` | **Kept, and strengthened.** No longer "a registry key with no enrollment is reported and treated as operator-asserted" — under v3 a key with no enrollment event is **not usable for verification at all**, because verification keys come from the policy. The consistency check becomes a corroboration finding (§4.3), which is the correct demotion. Enrollment events live in `sections.key_lifecycle` and are themselves strict-verified. |
| 2. Enrollment-before-use ordering — a key verifies only events after its enrollment; rotation/revocation bound the window the same way | **Kept verbatim, and it is now checkable.** Enrollment-before-use MUST be evaluated on **chain ordinal** (membership-tree position) and on the signed `timestamp`; `global_seq` is only an unsigned locator and never a security ordering input. The ordinal check is new. |
| 3. Anchor coverage report — distinguish anchored bindings from unanchored-tail bindings | **Replaced.** There are zero `anchor_receipts` estate-wide (verified: `affected_anchors=[]` for all 26 schemas in `preflight-s1.json`), and anchoring is being deleted. The axis WI-209 wanted survives as **`epoch_binding`** (§5.1 A6): bindings covered by an externally-authenticated **cutover checkpoint** versus bindings in the post-checkpoint tail. Same shape, honest mechanism. `ARCHITECTURE-0.6.0.md:271-273` says the same thing; I am agreeing with it explicitly and naming the replacement axis. |
| 4. `--trusted-fingerprints <file>`; fail closed on disagreement with the bundle registry | **Kept and hardened.** WI-209 made it an option. Bundle v3 makes trust material a **required argument** (§4.1). "Fail closed on disagreement" is retained: a bundled key whose fingerprint contradicts a pinned fingerprint for the same key id is `invalid`, not merely reported. |
| 5. Genesis ceremony runbook published through a channel the operator does not solely control | **Kept; owned by sibling B.** Owner decision Q2 (WI-272) settles the channel: a dedicated public git repository under an account distinct from the estate's operational identity, one command, canonical JSON. Bundle v3 consumes its output as `known_project_head` and `min_trust_log_checkpoint`. |

WI-209's stated out-of-scope (CT-style key transparency, witness countersignatures) remains out of scope, and the reasoning has *strengthened*: the owner's Q2 decision explicitly accepts that the channel cannot prevent a false publication, only make substitution detectable.

### 4.5 Governance visibility

> **AMENDED — collision 12 and WI-280.** The block is now `statement.trust_root` (§3.2), and
> `root_governance` inside it is the **replayed current governance state**, not a copy of a
> genesis field (`TRUST-DOMAIN.md` §3.3). The obligation below is unchanged in force: governance
> is visible in every artifact, and a verifier holding neither the genesis document nor a policy
> expectation reports `unverified_restatement`. Mode spellings are `co_signed | solo |
> solo_effective`.

`statement.trust_root.root_governance` (§3.2) is not decoration. WI-272's binding constraint is that single-signer lab mode must be visible in the artifact, "not merely in configuration", because "if lab mode is invisible, anyone can claim `co_signed` governance and no verifier can check, which makes the default theater".

Bundle v3's obligation: restate, inside the signed statement, the current signer count / threshold /
mode obtained by replaying the signed governance log. A verifier holding the authenticated trust log
compares the statement to that replay; the sole trust policy supplies the required governance
expectation when one is configured. A verifier that cannot replay the log reports
`root_governance: unknown` or `unverified_restatement`, never a genesis-derived value.

### 4.6 External evidence section

`sections.external_evidence` carries anything the operator obtained from outside: a copy of the published trust-log checkpoint, a countersignature, a future anchor receipt. Every entry is a tagged object `{class, source, obtained_at, content}` where `class` is one of `operator_asserted | independently_pinned_copy | third_party_signed`.

Rule: **an entry in this section never raises a verdict axis.** It can only corroborate one the policy already raised, or produce a *contradiction finding*. A copy of a checkpoint carried inside the bundle is worth exactly nothing as evidence of that checkpoint; it is worth something as a *convenience* when the auditor separately pinned the same value and wants to see them agree. This is `bundled_key_evidence`'s lesson applied one level up, pre-emptively, so nobody has to reopen BC-016 a third time.

---

## 5. The verdict model

### 5.1 Decision on WI-269: the split is STILL NECESSARY, and must be WIDENED

**A signed bundle does not collapse the split.** Three independent arguments:

**(i) Signing moves the circularity, it does not remove it.** If bundle v3 shipped its own signing public key inside `bundled_key_evidence` and the verifier accepted it, S5 reappears one level up and is *harder to see*, because now there is a real signature to point at. The "which root" axis must therefore survive and must apply to the membership signature itself, not only to the events. A single boolean cannot express "correctly signed, against a key from the artifact".

**(ii) The membership signature and event authentication are different claims about different objects.** The statement signature says *who attested to this bundle's contents*. It says nothing about whether the 303,820 legacy HMAC events inside are individually attributable — and per `ARCHITECTURE-0.6.0.md:870`, they are not, ever. A bundle can be perfectly externally authenticated and contain history that is cryptographically weak by construction. Collapsing those into one boolean either lies upward (calls HMAC history authenticated) or lies downward (calls a correctly signed bundle unverified).

**(iii) The practical driver settles it.** Post-S1, `verified` requires `sigs_verified > 0` (`src/regista/_bundle.py:676-684`). The estate is 303,820 of 352,509 events HMAC — **86%** (`ARCHITECTURE-0.6.0.md:820`) — and the HMAC secret is deliberately never exported (`:794-798`). So *every* current estate bundle is `verified=False` and `bundle export` exits 3 without `--allow-unverified` (`src/regista/_cli.py:990-991`). The S1 comment says this plainly and defers the fix (`:667-675`). With a v3 statement signed by an Ed25519 bundle-signing key, an HMAC-era bundle can say something **true and strong**: *the membership statement is authenticated to an externally pinned root, the cutover checkpoint is authenticated to that root, and the legacy events inside are exactly the bytes that checkpoint committed to — while remaining individually unattributable.* That is a genuinely useful audit position, and it is unreachable with one boolean.

So: **keep WI-269's split, and add a fourth axis for membership.** WI-269 named three; a signed bundle needs the membership dimension WI-269 explicitly put out of scope ("NOT IN SCOPE: S4"). The two items compose; neither subsumes the other.

**Axes.** Each is reported independently. Each is `not_checkable` when the supplied trust material cannot answer it — never silently `false`, because "we did not check" and "the check failed" are the exact conflation S1 exists to eliminate.

| # | Axis | Values |
|---|---|---|
| A1 | `structure` | `parsed` \| `malformed` |
| A2 | `membership_signature` | `valid_external_root` \| `valid_bundled_key` \| `invalid` \| `absent` |
| A3 | `membership_consistency` | `complete_for_claimed_scope` \| `mismatch` \| `not_checkable` |
| A4 | `event_authentication` | `full` \| `legacy_partial` \| `none_verifiable` \| `invalid` — aggregated from per-event `Applicability` (`src/regista/_verification.py:93-99`) |
| A5 | `event_trust_root` | `externally_pinned` \| `trust_log_only` \| `bundled_only` \| `absent` — aggregated from per-event `TrustedKeySource` (`:102-107`) |
| A11 | `event_attribution_counts` | `{individual, shared_secret, none}` — counts, not a verdict |
| A12 | `key_binding_counts` | counts per `RESULT-MODEL.md` §10 `key_binding` value, **including `recovery_rotated` and `legacy_unbound`** |
| A6 | `epoch_binding` | `checkpoint_externally_authenticated` \| `checkpoint_present_unauthenticated` \| `checkpoint_absent` \| `checkpoint_invalid` |
| A7 | `scope_corroboration` | `matches_pinned_head` \| `no_pin_supplied` \| `contradicts_pinned_head` |
| A8 | `registry_chain_consistency` | `consistent` \| `inconsistent` \| `not_applicable` (§4.3) |
| A9 | `governance` | `matches_policy` \| `unverified_restatement` \| `contradicts_policy` |
| A10 | `identity_conflicts` | integer count + list |

WI-269's three map on as: `internally_consistent` → A1+A3; `signatures_valid_against_bundled_keys` → A2/A5 value `bundled_*`; `authenticated_to_external_root` → A2/A5 value `external*`. Nothing is lost; the axes are just cut where the checks actually differ.

> **AMENDED — `RECONCILIATION.md` Resolution 4 and collision 13.** C's WI-269 split survives and
> **widens**. Four changes to the axis table:
>
> 1. **A5 gains `trust_log_only`** — log present and internally consistent, but no
>    caller-supplied policy pinning the genesis (`TRUST-DOMAIN.md` §8.3). It is neither an
>    external pin nor bundled-only material, and collapsing it into either is a lie in one
>    direction or the other.
> 2. **A11 `event_attribution_counts` and A12 `key_binding_counts` are added.** The frozen axes
>    overgeneralised *all* legacy events as unattributable. That is wrong: legacy **Ed25519**
>    events are individually signature-verifiable (`attribution: individual`) while legacy
>    **HMAC** events are not (`attribution: shared_secret`). A report that cannot tell them apart
>    understates 49,652 events and overstates nothing — but it is still an inaccurate report of
>    what the auditor holds.
> 3. **Reports display legacy HMAC, legacy Ed25519 and v6 counts separately.** One mixed number
>    is not a summary; it is a lost distinction.
> 4. **A key whose bytes travelled inside the bundle is `externally_pinned` if its recomputed
>    fingerprint matches an auditor pin.** Trust comes from the pin, not from the transport.
>    Arbitrary bundled bytes with no matching pin remain `bundled_only`. (`RECONCILIATION.md`
>    Resolution 4; this is the precise form of "key-material source and trust source are
>    separate", collision 11.)

### 5.2 The summary field

WI-269 permits "a single summary field only if it is defined as the WEAKEST of the three". Bundle v3 defines `applicability`, ordered, and it is the **minimum** over the rules below.

| Value | Reached when |
|---|---|
| `invalid` | any axis is `malformed` / `mismatch` / `invalid` / `contradicts_*`, or any event is `Applicability.INVALID` |
| `unauthenticated` | parses, A3 = `complete_for_claimed_scope`, but nothing was authenticated to anything: A2 = `absent`, or A2 = `valid_bundled_key` without an explicit `AcceptBundledKeys` |
| `bundle_rooted` | A2 = `valid_bundled_key` **with** explicit `AcceptBundledKeys`, and/or A5 = `bundled_only`. **Never a trust statement.** Ceiling rule C below |
| `legacy_checkpoint_bound` | A2 = `valid_external_root`, A6 = `checkpoint_externally_authenticated`, and the events in scope are legacy-epoch (A4 = `legacy_partial` or `none_verifiable`). **Requires an externally pinned checkpoint** — a bundled-only checkpoint is `checkpoint_present_unauthenticated` and cannot exceed `bundle_rooted` (collision 14). **Mixed `complete-store` scope** qualifies only if every legacy event is covered by the pinned checkpoint, every v6 event is fully authenticated, and no epoch violation exists |
| `externally_authenticated` | A2 = `valid_external_root`, A5 = `externally_pinned`, A4 = `full` for every in-scope event |

Clamping rules, applied after the table:

- **Rule C (circularity ceiling):** if any key used for any verification had `TrustedKeySource.BUNDLE_EMBEDDED`, `applicability` is clamped to `bundle_rooted`. No exception, no override flag. This is the mechanical form of "keys harvested from the artifact they authenticate can never authenticate it".
- ~~**Rule S (scope ceiling):**~~ **WITHDRAWN with `declared-selection` (§3.5).** The clamp is
  what killed the scope kind: it labels an all-v6 selection `legacy_checkpoint_bound`, i.e. as
  legacy, which is false in the direction that sounds cautious. With only `complete-store` and
  `contiguous-range` remaining, there is no scope ceiling.
- **Rule H (head ceiling):** `scope.kind = "complete-store"` with A7 = `no_pin_supplied` does **not** clamp, but the report MUST carry `tail_truncation_undetectable: true`. This is `ARCHITECTURE-0.6.0.md:875` residual 6 made machine-readable rather than left in release notes.

**There is no `verified: bool`.** Not deprecated — absent. If a caller-supplied policy is present, `policy_satisfied: bool` may be emitted, and it is true only when every requirement the caller named is met. `BundleVerificationReport.verified` (`src/regista/_bundle.py:84`) and its `to_dict` key (`:104`) are deleted.

### 5.3 Divergence from the architecture's verdict list

`ARCHITECTURE-0.6.0.md:284-290` proposes final values `externally_authenticated | internally_consistent | legacy_checkpoint_bound | invalid | unverifiable`. I keep three of five and change two:

- **`internally_consistent` → `unauthenticated`.** Applying WI-272's rule ("the name must not promise more than the check performs") to the verdict names themselves. "Internally consistent" reads as a positive result. It is the *absence* of one: a well-formed document whose signature nobody could check. An auditor skimming a report should not have to know that the good-sounding value is the bad one. Same defect class as `lineage_verification` returning `"verified"` (WI-263).
- **`unverifiable` dropped as a final value.** It survives per-event as `Applicability.UNVERIFIABLE` (`src/regista/_verification.py:99`) and aggregated as A4 = `none_verifiable`. As a *final* value it duplicated `unauthenticated` while sounding more like an error, and the boundary between them was never definable.
- **`bundle_rooted` added.** The architecture's list has no home for "signed, but against a key from the artifact" — it would have to land in `internally_consistent`, which is precisely the flattening WI-269 exists to prevent.

---

## 6. `format_version` 1 is deleted — and here is what goes with it

S3's fix in the audit was "treat 'signatures not enforced' as a verification failure" (`AUDIT-REPORT.md:50-51`). Bundle v3 does better: there is no configuration under which signature enforcement is optional, because the format that permitted it does not exist.

Deleted from `src/regista/_bundle.py`:

| Lines | What | Why it can go |
|---|---|---|
| `41` | `_SUPPORTED_FORMAT_VERSIONS = {1, 2}` | becomes `{3}` |
| `653-657` | the v1 branch setting `signature_check = "skipped_v1_bundle"` | S3 itself |
| `513-517`, `521-529` | v1/v2 version-gating inside `_verify_manifest_counts` | no manifest |
| `1739-1742` | the v1 conditional in `_canonical_bundle_bytes` | no unkeyed hash |
| `99`, `119` | `signature_check` report field and its three magic strings (`"enforced"`, `"skipped_v1_bundle"`, `"enforced_none_verified"`) | replaced by axes A2/A4/A5, which carry the same information without a string an operator must interpret |

`signature_check = "enforced_none_verified"` (`:664-665`) deserves a note: it is a **correct** signal invented under duress because the boolean could not carry it. It is exactly A4 = `none_verifiable`. The axis model absorbs it and the string goes.

---

## 7. What bundle v3 needs from segments: **nothing**

Assumption stated in the brief and confirmed independently: zero `event_segments` and zero `anchor_receipts` exist estate-wide. Verified in `preflight-s1.json` — all 26 schemas report `affected_segments: []` and `affected_anchors: []`.

**Bundle v3 requires no segment input, produces no segment output, and its verifier contains no segment code path.**

The only thing segments ever gave the bundle was a claim about a contiguous run of events, reconciled against a signed seal event (`_reconcile_segment_with_seal`, `src/regista/_bundle.py:1234-1289`). That claim is now made directly by `scope` + `event_membership_root` inside the statement signature — one signature instead of a mutable side row plus a seal event plus a reconciliation table plus a windowing gate.

If a future release reintroduces storage segmentation, it enters bundle v3 as ordinary signed events in `sections.events` and as nothing else. **A verifier must never take a fact from a side-table row.** That is S6's general form and it is the rule, not a preference.

---

## 8. Deletion accounting

Rather than kept. Line counts are from the `334b995` tree.

### Inside `src/regista/_bundle.py` (1,743 lines)

| Region | Lines | Count | Disposition |
|---|---|---|---|
| `_slice_receipts_to_verifiable` | 134-172 | 39 | **delete** — anchors gone |
| `_slice_segments_to_window` | 175-209 | 35 | **delete** — segments gone |
| `_verify_manifest_counts` + `_MANIFEST_COUNT_SECTIONS` | 485-543 | 59 | **delete** — signed `scope` and `section_digests` replace it |
| `_verify_anchor_offline` | 846-1008 | 163 | **delete** — anchors gone |
| `_as_seq_bound`, `_window_is_impossible`, `_exported_window`, `_verify_declared_window` | 1010-1115 | 106 | **delete** — see below |
| seal reconciliation + segment record/chain verification (`_SEAL_RECONCILED_FIELDS` … `_verify_segment_chain_offline`) | 1118-1669 | 552 | **delete** — segments gone |
| `_row_to_event_dict` | 1671-1726 | 56 | **delete** — §3.6, records are envelope+signature only |
| `_canonical_bundle_bytes` | 1729-1743 | 15 | **delete** — replaced by JCS over the statement |
| **Total deleted** | | **~1,025** | **59% of the module** |

The window gate (106 lines) deserves its own justification, because it is the newest patch and the least obviously disposable. It exists *only* because `since_seq`/`until_seq` were unsigned manifest keys. Its entire job is arguing that a declared window is "a shape an export could have produced" (`src/regista/_bundle.py:1018-1027`). Under v3 the scope is inside the signature: editing it invalidates the statement, so there is no implausible-but-accepted window to reason about. The check that survives — "every event lies inside the declared scope" (`:1084-1088`) — becomes a two-line comparison against signed `scope.first_event_hash` / `last_event_hash` / `event_count`, and it is now a *cryptographic* check rather than a plausibility one. **Signing the claim deletes the need for the heuristic.** That is the whole thesis of bundle v3 in one function.

### Whole modules (Stage 4, `ARCHITECTURE-0.6.0.md:789-800`)

| Module | Lines | Tests | Test lines |
|---|---|---|---|
| `src/regista/_archive_segments.py` | 861 | `tests/test_archive_segments.py` | 486 |
| `src/regista/_anchoring.py` | 839 | `tests/test_anchoring.py` | 1,559 |
| `src/regista/_timestamping.py` | 706 | `tests/test_timestamping.py` | 829 |

Plus their CLI verbs, sidecar routes, maintenance jobs and README/spec claims. **~2,400 production lines and ~2,900 test lines removed, against ~1,025 lines removed from `_bundle.py` — roughly 6,300 lines deleted to close S3, S4, S7, S10 and the `event_segments` half of S6.**

### Retained from `_bundle.py`

- `_reject_archive_output_name` (`:70-79`, WI-210) — unchanged.
- `MAX_BUNDLE_BYTES` (`:46`, WI-240) — unchanged; still a hard export refusal.
- The empty-bundle refusals (`:244-259` export, `:604-614` verify, WI-240 / review N5) — **strengthened**: under v3 an empty bundle also has no membership root to sign, so it is rejected twice.
- The self-verify-after-write discipline (`:381-402`) — **strengthened**, see §9.
- Post-S1 delegation to `verify_event_strict` (`:832-836`) — this is the keystone and is retained wholesale.

*(Successor note, 2026-08-17, P1.4 as landed — an interim weakening for
**pre-P1.4 bundles**, stated so an auditor is not misled about what a clean
verdict on an old artifact now means. `_canonical_bundle_bytes` still folds a
bundle's `anchor_receipts` and `segments` sections into the unkeyed bundle
hash — that is deliberate, so a v1/v2 artifact exported before P1.4 stays
hash-recomputable — but the checks that read those sections are deleted. The
consequence: an old bundle whose receipt or segment records were rewritten and
whose bundle hash was then recomputed verifies clean. The unkeyed hash was
never adversarial evidence (an editor can always restore agreement), so
nothing that was cryptographic is lost; what is lost is the structural
cross-checking that used to catch such an edit anyway — receipt/segment
anchoring, seal reconciliation and the segment chain walk. An auditor holding a
pre-P1.4 bundle should treat its receipt and segment sections as unverified
carried data and take the event-level findings — chain walk, key registry,
`verify_event_strict` — as the whole of the verdict. Zero receipts and zero
segments existed estate-wide, so no bundle regista actually exported carries
such a section. Closed at P3.3, where the signed statement replaces the
unkeyed hash and a v2 artifact is no longer accepted at all.)*

### `tests/test_bundle.py` (2,334 lines)

WI-269 flagged the real cost: 38 `assert not verified` sites, of which ~33 sit on HMAC fixtures where `verified=False` is now trivially true, so they prove "the tamper was detected" rather than "the signature check detected it". With the axis model, **each must be re-pointed at the specific axis that should have caught its tamper.** A membership tamper asserts A3 = `mismatch`; a key-swap asserts A2/A5; a legacy-event tamper asserts A4 = `invalid`. This is the majority of the implementation effort in this area and it should be scheduled as such, not treated as test churn.

---

## 9. Export contract

1. **Strict-verify the source before signing.** Export runs `verify_event_strict` over every event it intends to include and refuses to sign a statement over a corpus containing `Applicability.INVALID`. Signing a membership root over known-bad events would make regista attest to them.
2. **Compare against preflight (D1).** If a preflight result for the project is supplied, `scope.event_count` / `first_event_hash` / `last_event_hash` MUST match it. A mismatch aborts. This is how "the head moved under us mid-export" becomes an error rather than a silently narrower bundle.
3. **WI-259 — read the complete logical stream.** Export reads `events` consolidated with any `events_archive` rows (Stage 4 restores them first, `ARCHITECTURE-0.6.0.md:681-683`). A `complete-store` scope that silently omitted archived rows would be a signed false statement, which is strictly worse than today's unsigned one.
4. **WI-261 — refuse an existing destination unless `--overwrite`.** The current code does `os.replace` onto the destination unconditionally (`src/regista/_bundle.py:379`).
5. **Atomic replacement only after successful self-verification.** Today the order is write → `os.replace` → verify (`:372-396`), so a failed self-verification leaves the bad artifact **at the destination**. Under v3: write to `.partial` → self-verify the `.partial` → `os.replace` only on success. The `BUNDLE_WRITE_CORRUPT` path (`:390-396`) is retained but re-pointed at the statement signature instead of the unkeyed hash.
6. **Dependency closure is computed and included (`RECONCILIATION.md` Resolution 4).** Export
   walks the closure for signing authority, key lifecycle, project acceptance, workflow
   registration, delegation, checkpoints and verdict supersession. **Missing closure in a
   `complete-store` bundle is invalid** — not a warning, not a smaller bundle. A
   `contiguous-range` bundle names each dependency that falls outside its scope, and a verifier
   reports it as outside scope rather than treating its absence as satisfaction.
7. **HMAC-era export is a normal success.** With v3, exporting from an 86%-HMAC store produces a bundle whose statement signature is externally verifiable. `--allow-unverified` (`src/regista/_cli.py:990`) is deleted; the exit code is driven by the `applicability` the export's own self-verification reached, and `legacy_checkpoint_bound` is exit 0.

---

## 10. Auditor workflow

If an auditor cannot follow this without me present, the design has failed. Written as instructions to the auditor.

### What you receive

**From the operator, in one file:** `bundle.json` — the v3 bundle.

**From a channel the operator does not solely control** (sibling B's publication repository, plus a direct exchange at bootstrap):
1. `trust-policy.json` — or, minimally, one or more root fingerprints.
2. The current published estate catalog, containing per-project head hash and event count.
3. The published trust-log checkpoint hash.

**Never accept item 2 or 3 from inside the bundle.** A copy inside the bundle appears in `sections.external_evidence` and is worth nothing on its own (§4.6). If the operator hands you fingerprints by the same route they handed you the bundle, you have not authenticated anything — say so in your report rather than proceeding.

### What you pin

Before running anything, record — in your own notes, outside the bundle:
- root fingerprint(s), and the date/route you received them;
- the project head hash and event count from the published catalog;
- the trust-log checkpoint hash;
  - the expected current governance state (`co_signed`, `solo` or `solo_effective`) obtained by
    replaying the signed governance log through that checkpoint. Do not infer it from a genesis
    copy or from configuration; verify the current signer set, threshold and mode against the
    policy and the monotone-log rules. `solo_effective` exists precisely to stop an estate listing
    several fingerprints at threshold 1 and calling itself `co_signed`.

On a **repeat** audit, first confirm the channel still publishes the same fingerprint and that its history shows no rewrite. That is the property the channel buys you (owner decision Q2): it cannot prevent a false publication, only make substitution detectable.

### What you run

```
regista bundle verify bundle.json \
    --trust-policy ./trust-policy.json \
    --known-head <head_hash>:<event_count> \
    --json
```

Or, when you have only fingerprints:

```
regista bundle verify bundle.json \
    --trusted-fingerprint sha256:... \
    --trusted-fingerprint sha256:... \
    --json
```

There is no third form. If you supply neither, the command refuses to run (§4.1). If the operator tells you to run it with `--accept-bundled-keys`, they are asking you to authenticate the bundle against keys carried inside the bundle; the result is clamped to `bundle_rooted` and is not an external authentication. It is occasionally useful — it proves the operator's own records are self-consistent — but do not write it up as anything more.

### What each answer means

| `applicability` | Exit | What you may write in your report | What you must NOT write |
|---|---|---|---|
| `externally_authenticated` | 0 | "Every event in the declared scope is individually signature-verifiable against a key chaining to the root fingerprint I pinned on <date>, and the bundle's membership is signed by a permitted authority under that root." | that timestamps are true; that the operator could not have fabricated history before creating it — see below |
| `legacy_checkpoint_bound` | 0 | "The membership statement and the cutover checkpoint verify against my pinned root. The N legacy events in this bundle are exactly the bytes the cutover signer committed to, and have not changed since. They are **not** individually attributable to the principals they name." | "the legacy history is verified"; "actor X performed action Y" for any legacy event |
| `bundle_rooted` | 2 | "Signatures verify, but against keys carried inside the artifact. This is self-consistency, not authentication. I have no external evidence about this bundle." | anything containing the word "verified" without the qualifier |
| `unauthenticated` | 2 | "The document is well-formed and internally consistent. Nothing in it was authenticated to anything I hold." | anything positive |
| `invalid` | 1 | quote the failing axis and the finding verbatim | — |

Always read these alongside the summary, because they are not visible in it:

- **`tail_truncation_undetectable: true`** (Rule H) — the operator could have withheld events after the last head you pinned, and nothing in the bundle can reveal it. Your pin date bounds the claim. Say so.
- ~~**`scope.kind: "declared-selection"`** (Rule S)~~ — **the scope kind is cut from 0.6.0** (§3.5). A bundle declaring it is rejected, not attested. If you are handed one, you are looking at a pre-0.6.0 artifact or a non-conforming exporter.
- **`A9 root_governance: unverified_restatement`** — the bundle's replayed governance state was not
  checked against the authenticated trust log and policy. Check it, or downgrade the claim.
- **`A8 registry_chain_consistency: inconsistent`** — the operator's key registry disagrees with their own signed enrollment events. This does not affect authentication (your root did that), but it is a finding worth raising on its own.

### What no answer ever means

Even at `externally_authenticated`, per `ARCHITECTURE-0.6.0.md:866-882`: regista 0.6.0 provides no trusted timestamp and no public anchoring; signed actor and model-lineage metadata proves what the signer asserted, never what generated the action; and a host operator controlling all roots, private keys and publication channels can fabricate a valid-looking history. Your report should state the boundary, not just the result.

---

## 11. DIVERGENCES

Where I depart from `ARCHITECTURE-0.6.0.md` §2 or WI-209, or where they are ambiguous. Recorded rather than quietly chosen.

**D1 — `internally_consistent` renamed to `unauthenticated`.** Architecture `:286`. Applying WI-272's naming rule to verdict names. §5.3.

**D2 — `unverifiable` dropped as a final verdict value.** Architecture `:290`. Retained per-event as `Applicability.UNVERIFIABLE`, aggregated as A4 `none_verifiable`. Its boundary against `internally_consistent` was never definable. §5.3.

**D3 — `bundle_rooted` added as a final value.** Not in the architecture's list, which has nowhere to put "correctly signed against a key from the artifact" except the value it renames to `unauthenticated`. That flattening is the thing WI-269 exists to prevent. §5.2.

**D4 — Merkle tree fully specified (RFC 6962).** Architecture `:236-247` specifies the leaf but not the interior node, the odd-node rule, or leaf/interior domain separation. A Merkle root without those is a second-preimage hazard and two implementations will disagree. §3.3.

**D5 — Enrollment-before-use is ordered by chain ordinal, not `global_seq`.** WI-209 acceptance criterion 2 says "events with global_seq after its enrollment event". `global_seq` is unsigned by design (`src/regista/_verification.py:430-434`) and a row-write attacker can move an event across any `global_seq` watermark. Ordering a security check on it is unsound. §4.4.

**D6 — WI-209's anchor-coverage axis is replaced, not dropped.** WI-209 criterion 3 assumes anchoring. Zero receipts exist and anchoring is deleted. The axis becomes `epoch_binding` (A6): checkpoint-covered vs post-checkpoint tail. §4.4.

**D7 — Event records are base64, not hex.** The current exporter hex-encodes (`src/regista/_bundle.py:1697-1706`); the architecture's example uses base64 (`:190-195`) without saying it is a change. It is, and it matters: at 352k events the difference is whether the estate's largest project fits under `MAX_BUNDLE_BYTES`. Flagged so it is a decision, not a transcription. §3.6.

**D8 — `epoch`, `trust_root.root_governance`, `signer.fingerprint` and `exporter` are part of the
statement.** Architecture `:200-232` omits them. `root_governance` is the current state replayed
from the signed trust-domain log, not a genesis-derived input to `trust_domain_id`; it is required
by WI-272's visible-artifact constraint. `epoch` makes `legacy_checkpoint_bound` computable without
re-scanning; `signer.fingerprint` lets pin comparison bypass the bundled registry; `exporter` is
diagnostic. §3.2.

**D9 — `external_evidence` may never raise a verdict axis.** Architecture `:186` says "optional externally obtained evidence, explicitly classified" but does not say what classification *does*. Left unstated, someone will make a bundled copy of a checkpoint count as external evidence, which is BC-016 again. §4.6.

**D10 — Trust material is a required function argument with no default.** Architecture `:258-263` says the verifier "requires one of" the trust inputs, which reads as a runtime check. Runtime checks on optional parameters get bypassed. Making it un-passable is stronger than making it required. §4.1.

**D11 — Export self-verifies before `os.replace`, not after.** Current order (`src/regista/_bundle.py:372-396`) leaves a failed artifact at the destination. Architecture `:314` says "atomic temporary-file replacement only after successful self-verification", which agrees with me and contradicts the code; noting it explicitly so it is not read as already-done. §9 rule 5.

**D12 — `--allow-unverified` is deleted rather than retained.** Not addressed by the architecture. It exists (`src/regista/_cli.py:990`) solely because post-S1 every HMAC bundle fails. With v3 an HMAC bundle reaches `legacy_checkpoint_bound` honestly, so the escape hatch has no remaining legitimate use, and every escape hatch is eventually load-bearing in someone's CI. §9 rule 6.

---

## 12. Least-confident areas

Flagged for the owner and for implementation review.

**L1 — RESOLVED: `declared-selection` is deleted, not clamped.** The concern was that it is the one scope kind whose verdict rests on an attestation, and that Rule S's clamp was a policy decision this document made rather than one the architecture stated. `RECONCILIATION.md` Resolution 4 settles it in the safer direction — and adds the sharper reason: the clamp **mislabels an all-v6 selection as legacy**, so the "cautious" behaviour is itself wrong. No concrete 0.6.0 requirement needs filtered export. §3.5.

**L2 — Chain-ordinal traversal at 352k events across a broken chain.** The membership tree requires a total order derived by following `prev_global_event_hash` from genesis. If the chain has a break, there is no traversal and therefore no bundle. That is correct behaviour, but it means a store with one broken link cannot export **any** bundle, including the diagnostic one an operator most wants at that moment. I do not have a good answer. A `--diagnostic` export producing an explicitly unsigned, explicitly `invalid`-verdict artifact is the obvious shape, and it is also exactly the escape hatch D12 argues against.

**L3 — Base64 vs hex sizing (D7).** I have not measured actual envelope sizes at scale. If the largest project still exceeds `MAX_BUNDLE_BYTES` under base64, the chunking story returns and `contiguous-range` becomes the common case rather than the exception — which changes which axes are usually `not_checkable`. Sibling D's preflight should report a projected bundle size per project so this is decided on numbers.

**L4 — Whether the bundle-signing key should be permitted to equal the project writer key.** I left it to the trust policy (§3.4). Separating them is better hygiene, but it is another key to provision in a one-way ceremony (`ARCHITECTURE-0.6.0.md:772`, WI-235's codec contract), and the marginal security is small when the same operator holds both. Sibling B owns this and should decide it deliberately.

**L5 — `epoch.scheme_counts` in the statement is a self-report.** It is checkable by re-scanning the events in the bundle, and the verifier should do so. But for a `contiguous-range` bundle the counts describe only the range, while the natural reading is "the project". I specified range semantics; the field name invites the wrong reading and may want renaming to `scope_scheme_counts`.

**L6 — Interaction with `events_archive` consolidation (§9.3).** WI-259 says export must read the complete logical stream. Stage 4 restores archived rows *before* cutover (`ARCHITECTURE-0.6.0.md:681-683`). If any project is exported between now and that restoration, a `complete-store` statement would be a signed false claim. The safe rule is: **`complete-store` is forbidden until archive consolidation is confirmed complete for that project**, and export must check rather than assume. I have specified the check but not the mechanism by which export learns consolidation is done; that likely belongs to sibling D's preflight.
