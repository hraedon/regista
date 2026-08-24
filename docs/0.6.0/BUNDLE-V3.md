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

  // SUPERSEDED — the `epoch` block is DROPPED and FORBIDDEN; see the E2 marker below §3.2's
  // hard rules. It is not a member of the statement, and a statement carrying it is rejected.

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
- ~~`epoch.legacy_event_count + epoch.v6_event_count` MUST equal `scope.event_count`.~~
  **SUPERSEDED — decision E2, wording confirmed at the Phase B implementation review
  (2026-08-23). The `epoch` block does not exist, so neither does this rule.**
- `trust_root` and `signer` are **closed objects**: exactly the members listed above, no more.
  A `trust_root` or `signer` carrying an unlisted member is a rejection, for the same reason
  §3.1 rule 3 rejects an unlisted top-level key.
- **Exactly one of `signer` and `root_signatures` is present.** A statement carrying both, or
  neither, is a rejection.
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

> **SUPERSEDED — decision E2 (`EPOCH-RESET.md:69`), normative wording CONFIRMED at the Phase B
> implementation review, 2026-08-23.** The statement `epoch` block — `cutover_event_hash`,
> `legacy_event_count`, `v6_event_count`, `scheme_counts` — is **dropped**, and the E2 question
> the 2026-08-23 amendment left open ("*forbidden* or merely *not emitted*") is settled in the
> strict direction:
>
> 1. **`epoch` is not a member of the statement.** The statement's member set is **closed** to
>    exactly `type`, `version`, `bundle_id`, `project_instance_id`, `trust_domain_id`,
>    `created_at`, `scope`, `event_membership_root`, `section_digests`, `trust_root`, `exporter`,
>    and exactly one of `signer` / `root_signatures`. Export does not emit `epoch`.
> 2. **A statement carrying `epoch` is REJECTED, not ignored.** §3.1 rule 3 rejects unknown
>    *top-level* keys because "a v2 verifier's tolerance of extra keys is how `public_keys`
>    quietly became a trust root"; the same argument applies one level down and with more force,
>    because the statement is the *signed* object. A tolerated `epoch` block would be signed
>    content that no verifier checks — attacker-chosen counts inside a valid signature, which is
>    the S4 shape this document exists to remove. So the closed member set is enforced at verify
>    with a named error, and `epoch` is named explicitly in the refusal so an operator holding a
>    pre-E2 artifact reads a diagnosis rather than "unknown key".
> 3. **There is no migration path and none is owed.** §2's rationale applies unchanged: bundles
>    are regenerable artifacts, no pre-E2 v3 bundle was ever exported (`BUNDLE-V3.md`'s §3.2 was
>    contract-only until Phase B), and a re-export costs one command.
> 4. **D8 loses its `epoch` limb** and L5 lapses with the field. The remaining D8 additions
>    (`trust_root.root_governance`, `signer.fingerprint`, `exporter`) are unaffected.

### 3.3 Membership — the part that must not require enumerating fields

**Leaf.** For the event at `scope_ordinal` `i` (0-based, **project-chain traversal order**, local
to the signed scope):

```text
leaf_i = SHA256( b"regista.bundle.member.v1\x00" ‖ uint64be(i) ‖ event_hash_i )
```

> **SUPERSEDED — `EPOCH-RESET.md:69`, wording confirmed at the Phase B implementation review
> (2026-08-23). There is ONE event-hash construction, because there is one epoch.**
> `event_hash_i` is the v6 event hash: the domain-separated, length-framed construction at
> `V6-ENVELOPE.md` §5.3 (`regista.event.hash.v1`). The version-aware dispatch below, and the
> mixed-epoch requirement in correction 1 of the next marker, **lapse** with the mixed corpus
> `EPOCH-RESET.md:69` deleted. A v3 bundle cannot contain a v1–v5 event at all: §3.6 already
> refuses to represent an event with no v6 canonical envelope, so the legacy formula has no
> reachable input. Keeping a second construction alive for an empty case is how two
> implementations end up disagreeing about a hash nobody ever computes.

~~where `event_hash_i` is the **version-aware** event hash: v1–v5 use
`SHA256(canonical_envelope ‖ signature)`; **v6 uses the domain-separated, length-framed
construction at `V6-ENVELOPE.md` §5.3.** Every event reference — here and everywhere else — uses
the *referenced event's* version-derived hash.~~

**Tree.** RFC 6962 (Certificate Transparency) Merkle tree, with named domains:

```text
MTH({})        = SHA256()                       // empty, unreachable: empty bundles are rejected
MTH({d0})      = leaf_0                          // leaves are already domain-tagged above
MTH(D[n])      = SHA256( b"regista.bundle.node.v1\x00" ‖ MTH(D[0:k]) ‖ MTH(D[k:n]) ),
                 k = largest power of 2 < n
```

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4, collisions 9 and 10.** Three corrections:
>
> 1. ~~**The event hash is version-aware.** Hardcoding the legacy formula would compute a v6
>    event's identity with the v1–v5 construction, so a v6 event's membership leaf would not
>    match the hash the chain itself commits to. Every hash reference in a mixed-epoch bundle —
>    and every bundle over a cut-over project is mixed — depends on this.~~
>    **SUPERSEDED by `EPOCH-RESET.md:69` — one epoch, one construction; see the marker above.**
>    Corrections 2 and 3 stand unchanged and are the load-bearing half.
> 2. **No leading `0x00` on the leaf, and no bare `0x01` on interior nodes.** The domain tags
>    (`regista.bundle.member.v1\x00`, `regista.bundle.node.v1\x00`) *are* the separation; the
>    extra byte was an unreconciled difference between this document and the architecture, and
>    two implementations differing by one byte produce two different roots and one very confusing
>    incident.
> 3. **The ordinal is `scope_ordinal`, local to the signed scope**, derived from chain traversal.
>    It is never `global_seq` and never a store-wide index.
>
> **Byte vectors for the leaf, the node and an odd-length tree are frozen under P0.3**
> (`tests/vectors/v6/bundle-merkle-empty.json`, `-single`, `-two`, `-three`, `-five`). Do not
> implement this section without them. The mixed-epoch vector is retired with the mixed corpus
> (`EPOCH-RESET.md:66`) and is not a conformance target for the bundle-v3 implementation.

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
| 3. Anchor coverage report — distinguish anchored bindings from unanchored-tail bindings | ~~**Replaced.** There are zero `anchor_receipts` estate-wide (verified: `affected_anchors=[]` for all 26 schemas in `preflight-s1.json`), and anchoring is being deleted. The axis WI-209 wanted survives as **`epoch_binding`** (§5.1 A6): bindings covered by an externally-authenticated **cutover checkpoint** versus bindings in the post-checkpoint tail. Same shape, honest mechanism.~~ **SUPERSEDED — decision E3; see the marker below this table. `epoch_binding` is dropped: there is no cutover checkpoint to be covered by. WI-209 criterion 3 is DROPPED OUTRIGHT, not replaced.** |
| 4. `--trusted-fingerprints <file>`; fail closed on disagreement with the bundle registry | **Kept and hardened.** WI-209 made it an option. Bundle v3 makes trust material a **required argument** (§4.1). "Fail closed on disagreement" is retained: a bundled key whose fingerprint contradicts a pinned fingerprint for the same key id is `invalid`, not merely reported. |
| 5. Genesis ceremony runbook published through a channel the operator does not solely control | **Kept; owned by sibling B.** Owner decision Q2 (WI-272) settles the channel: a dedicated public git repository under an account distinct from the estate's operational identity, one command, canonical JSON. Bundle v3 consumes its output as `known_project_head` and `min_trust_log_checkpoint`. |

> **SUPERSEDED — decision E3 (`EPOCH-RESET.md:69`), normative wording CONFIRMED at the Phase B
> implementation review, 2026-08-23.** Axis A6 `epoch_binding` (§5.1) does not exist, and row 3
> above therefore names no replacement. The reasoning is the same as E2's and it is worth being
> exact about the difference from D6: D6 argued that WI-209's anchor-coverage axis should be
> *replaced* rather than dropped, because the property it wanted — "which bindings are covered by
> something external" — was real even after anchoring went. Under the epoch reset the *specific*
> external thing A6 named, a cutover checkpoint over a legacy region, has no referent: there is
> no legacy region. A6's four values are all statements about that checkpoint, so all four are
> permanently `checkpoint_absent`. **The general property survives, and it survives where it was
> always properly located** — A5 `event_trust_root` and A7 `scope_corroboration`, which say
> whether the trust root and the head were externally pinned. So nothing measurable is lost;
> what is removed is a third axis that would report the same constant on every artifact regista
> can produce. A published axis whose value is fixed by construction teaches an auditor that a
> distinction exists where none does.

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
| ~~A6~~ | ~~`epoch_binding`~~ | **DROPPED — decision E3, see §4.4's E3 marker and the E3 marker below this table. The axis does not exist and its number is not reused.** |
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

> **SUPERSEDED — decision E3, normative wording CONFIRMED at the Phase B implementation review,
> 2026-08-23.** **A6 `epoch_binding` is struck from the axis table.** The axis set is
> A1–A5 and A7–A12; the number 6 is retired and not reused, so a report emitted by an older
> implementation and one emitted by this one cannot silently disagree about what "A6" meant.
> Every other row is unaffected, and the AMENDED marker above stands in full. The reasoning is
> in §4.4's E3 marker. **`legacy_epoch_policy` and `accept_legacy_shared_secret_events` in the
> §4.2 policy field list are likewise vestigial under the reset** — a policy may carry them and a
> verifier reads them, but with no legacy events in scope they can never change a verdict; that
> is `TRUST-DOMAIN.md` §4.6's field to retire or keep, not this document's.

### 5.2 The summary field

WI-269 permits "a single summary field only if it is defined as the WEAKEST of the three". Bundle v3 defines `applicability`, ordered, and it is the **minimum** over the rules below.

| Value | Reached when |
|---|---|
| `invalid` | any axis is `malformed` / `mismatch` / `invalid` / `contradicts_*`, or any event is `Applicability.INVALID` |
| `unauthenticated` | parses, A3 = `complete_for_claimed_scope`, but nothing was authenticated to anything: A2 = `absent`, or A2 = `valid_bundled_key` without an explicit `AcceptBundledKeys` |
| `bundle_rooted` | A2 = `valid_bundled_key` **with** explicit `AcceptBundledKeys`, and/or A5 = `bundled_only`. **Never a trust statement.** Ceiling rule C below |
| ~~`legacy_checkpoint_bound`~~ | ~~A2 = `valid_external_root`, A6 = `checkpoint_externally_authenticated`, and the events in scope are legacy-epoch (A4 = `legacy_partial` or `none_verifiable`). **Requires an externally pinned checkpoint** — a bundled-only checkpoint is `checkpoint_present_unauthenticated` and cannot exceed `bundle_rooted` (collision 14). **Mixed `complete-store` scope** qualifies only if every legacy event is covered by the pinned checkpoint, every v6 event is fully authenticated, and no epoch violation exists~~ **DROPPED — decision E3; see the marker below the clamping rules.** |
| `externally_authenticated` | A2 = `valid_external_root`, A5 = `externally_pinned`, A4 = `full` for every in-scope event |

Clamping rules, applied after the table:

- **Rule C (circularity ceiling):** if any key used for any verification had `TrustedKeySource.BUNDLE_EMBEDDED`, `applicability` is clamped to `bundle_rooted`. No exception, no override flag. This is the mechanical form of "keys harvested from the artifact they authenticate can never authenticate it".
- ~~**Rule S (scope ceiling):**~~ **WITHDRAWN with `declared-selection` (§3.5).** The clamp is
  what killed the scope kind: it labels an all-v6 selection `legacy_checkpoint_bound`, i.e. as
  legacy, which is false in the direction that sounds cautious. With only `complete-store` and
  `contiguous-range` remaining, there is no scope ceiling.
- **Rule H (head ceiling):** `scope.kind = "complete-store"` with A7 = `no_pin_supplied` does **not** clamp, but the report MUST carry `tail_truncation_undetectable: true`. This is `ARCHITECTURE-0.6.0.md:875` residual 6 made machine-readable rather than left in release notes.

> **SUPERSEDED — decision E3, normative wording CONFIRMED at the Phase B implementation review,
> 2026-08-23.** The `legacy_checkpoint_bound` verdict value is **dropped from the lattice.** The
> ordered values are `invalid` < `unauthenticated` < `bundle_rooted` < `externally_authenticated`.
>
> Two consequences a reviewer should check rather than assume:
>
> 1. **No verdict is silently promoted.** `legacy_checkpoint_bound` sat between `bundle_rooted`
>    and `externally_authenticated`, and its entry conditions required A4 to be *worse* than
>    `full`. Under the reset there are no legacy events, so the only bundles that could have
>    reached it are bundles that now either reach `externally_authenticated` on their own merits
>    (A4 = `full` for every event) or fall to `unauthenticated`/`invalid`. Removing the row
>    cannot lift anything: nothing that failed `externally_authenticated`'s conditions passes
>    them now.
> 2. **Exit-code semantics collapse to three values, not two.** §9 rule 7 and §10's table both
>    gave `legacy_checkpoint_bound` exit 0. With the row gone, exit 0 is reachable only from
>    `externally_authenticated`, which is *stricter* — an HMAC-era store could have exited 0 and
>    now no store can, because no store contains HMAC-era events.
>
> **Rule C and Rule H are unaffected.** Rule C's clamp target (`bundle_rooted`) survives, and
> Rule H's `tail_truncation_undetectable` flag is orthogonal to the epoch.

**There is no `verified: bool`.** Not deprecated — absent. If a caller-supplied policy is present, `policy_satisfied: bool` may be emitted, and it is true only when every requirement the caller named is met. `BundleVerificationReport.verified` (`src/regista/_bundle.py:84`) and its `to_dict` key (`:104`) are deleted.

### 5.3 Divergence from the architecture's verdict list

> **SUPERSEDED in part — decision E3, normative wording CONFIRMED at the Phase B implementation
> review, 2026-08-23.** This section's arithmetic ("I keep three of five and change two") is
> restated: of the architecture's five values, **two are kept** (`externally_authenticated`,
> `invalid`), **two are changed** (`internally_consistent` → `unauthenticated`; `unverifiable`
> dropped as a final value), **one is dropped outright** (`legacy_checkpoint_bound`), and one is
> added (`bundle_rooted`). The three bullets below stand as written; what changes is only that
> `legacy_checkpoint_bound` is no longer among the kept values. This is a consequence of the
> epoch reset, **not a reversal of the judgement** that recorded it as worth keeping: at the time
> the estate held 303,820 unattributable events and the value was the only honest thing a report
> could say about them. `EPOCH-RESET.md` removed the population, not the argument.

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
   P3.3/WI-289 will carry action-delegation documents in a closed
   `sections.action_delegation_credentials` section covered by the signed section digest. Each
   document will be addressed only by its recomputed action-delegation hash. A complete-store v3
   artifact missing a referenced credential will be invalid; a partial artifact that names the
   missing dependency will be unverifiable. Bundle v2 does not transport credentials, and delegated
   audit from bundle-v2 evidence is therefore unverifiable rather than silently trusted.
7. ~~**HMAC-era export is a normal success.** With v3, exporting from an 86%-HMAC store produces a bundle whose statement signature is externally verifiable.~~ **SUPERSEDED in part — decision E3, wording confirmed at the Phase B implementation review (2026-08-23): there is no HMAC era to export from, and `legacy_checkpoint_bound` is dropped from the lattice (§5.2).** What survives, and is the operative rule: `--allow-unverified` (`src/regista/_cli.py:990`) is deleted; the exit code is driven by the `applicability` the export's own self-verification reached. Exit 0 requires `externally_authenticated`. A v3 export whose self-verification lands at `bundle_rooted` or `unauthenticated` is a non-zero exit, because there is no longer a legacy corpus for which a lower verdict was the honest ceiling.

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
| ~~`legacy_checkpoint_bound`~~ | ~~0~~ | ~~"The membership statement and the cutover checkpoint verify against my pinned root. The N legacy events in this bundle are exactly the bytes the cutover signer committed to, and have not changed since. They are **not** individually attributable to the principals they name."~~ **DROPPED — decision E3 (§5.2). A 0.6.0 bundle never reaches this verdict; if a tool reports it to you, it is not a conforming v3 verifier.** | ~~"the legacy history is verified"; "actor X performed action Y" for any legacy event~~ |
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

**D6 — ~~WI-209's anchor-coverage axis is replaced, not dropped.~~** ~~WI-209 criterion 3 assumes anchoring. Zero receipts exist and anchoring is deleted. The axis becomes `epoch_binding` (A6): checkpoint-covered vs post-checkpoint tail.~~ **SUPERSEDED — decision E3, wording confirmed at the Phase B implementation review (2026-08-23). The divergence is now the opposite one: WI-209 criterion 3 is dropped outright and nothing replaces it, because the coverage relation it wanted (covered by an external checkpoint vs not) is answered by A5 and A7 rather than by an axis of its own. §4.4, §5.1.**

**D7 — Event records are base64, not hex.** The current exporter hex-encodes (`src/regista/_bundle.py:1697-1706`); the architecture's example uses base64 (`:190-195`) without saying it is a change. It is, and it matters: at 352k events the difference is whether the estate's largest project fits under `MAX_BUNDLE_BYTES`. Flagged so it is a decision, not a transcription. §3.6.

**D8 — `trust_root.root_governance`, `signer.fingerprint` and `exporter` are part of the
statement.** Architecture `:200-232` omits them. `root_governance` is the current state replayed
from the signed trust-domain log, not a genesis-derived input to `trust_domain_id`; it is required
by WI-272's visible-artifact constraint. `signer.fingerprint` lets pin comparison bypass the
bundled registry; `exporter` is diagnostic. §3.2.

> **SUPERSEDED in part — decision E2, wording confirmed at the Phase B implementation review
> (2026-08-23).** D8 no longer lists `epoch`, and its justification for it ("`epoch` makes
> `legacy_checkpoint_bound` computable without re-scanning") falls with E3's removal of that
> verdict. The block is forbidden at verify, not merely unemitted — §3.2's E2 marker carries the
> rule and the reasoning. The three remaining D8 additions are unchanged.

**D9 — `external_evidence` may never raise a verdict axis.** Architecture `:186` says "optional externally obtained evidence, explicitly classified" but does not say what classification *does*. Left unstated, someone will make a bundled copy of a checkpoint count as external evidence, which is BC-016 again. §4.6.

**D10 — Trust material is a required function argument with no default.** Architecture `:258-263` says the verifier "requires one of" the trust inputs, which reads as a runtime check. Runtime checks on optional parameters get bypassed. Making it un-passable is stronger than making it required. §4.1.

**D11 — Export self-verifies before `os.replace`, not after.** Current order (`src/regista/_bundle.py:372-396`) leaves a failed artifact at the destination. Architecture `:314` says "atomic temporary-file replacement only after successful self-verification", which agrees with me and contradicts the code; noting it explicitly so it is not read as already-done. §9 rule 5.

**D12 — `--allow-unverified` is deleted rather than retained.** Not addressed by the architecture. It exists (`src/regista/_cli.py:990`) solely because post-S1 every HMAC bundle fails. With v3 an HMAC bundle reaches `legacy_checkpoint_bound` honestly, so the escape hatch has no remaining legitimate use, and every escape hatch is eventually load-bearing in someone's CI. §9 rule 6.

---

## 12. Least-confident areas

Flagged for the owner and for implementation review.

**L1 — RESOLVED: `declared-selection` is deleted, not clamped.** The concern was that it is the one scope kind whose verdict rests on an attestation, and that Rule S's clamp was a policy decision this document made rather than one the architecture stated. `RECONCILIATION.md` Resolution 4 settles it in the safer direction — and adds the sharper reason: the clamp **mislabels an all-v6 selection as legacy**, so the "cautious" behaviour is itself wrong. No concrete 0.6.0 requirement needs filtered export. §3.5.

**L2 — RESOLVED (owner ruling O4, 2026-08-23 amendment): export refuses, fail-closed; a forensic dump is a separately named non-evidentiary command.** Chain-ordinal traversal at 352k events across a broken chain. The membership tree requires a total order derived by following `prev_global_event_hash` from genesis. If the chain has a break, there is no traversal and therefore no bundle. That is correct behaviour, but it means a store with one broken link cannot export **any** bundle, including the diagnostic one an operator most wants at that moment. I do not have a good answer. A `--diagnostic` export producing an explicitly unsigned, explicitly `invalid`-verdict artifact is the obvious shape, and it is also exactly the escape hatch D12 argues against.

**L3 — MOOT (decision E1, 2026-08-23 amendment): the empty-genesis estate removes the sizing pressure; base64 stands.** Base64 vs hex sizing (D7). I have not measured actual envelope sizes at scale. If the largest project still exceeds `MAX_BUNDLE_BYTES` under base64, the chunking story returns and `contiguous-range` becomes the common case rather than the exception — which changes which axes are usually `not_checkable`. Sibling D's preflight should report a projected bundle size per project so this is decided on numbers.

**L4 — RESOLVED (owner ruling O3, 2026-08-23 amendment): permitted, provided the key explicitly bears `may_sign_bundles`.** Whether the bundle-signing key should be permitted to equal the project writer key. I left it to the trust policy (§3.4). Separating them is better hygiene, but it is another key to provision in a one-way ceremony (`ARCHITECTURE-0.6.0.md:772`, WI-235's codec contract), and the marginal security is small when the same operator holds both. Sibling B owns this and should decide it deliberately.

**L5 — LAPSED (decision E2, wording confirmed at the Phase B implementation review,
2026-08-23): the `epoch` block is gone, so `epoch.scheme_counts` has no referent and the
renaming question it raised has no subject.** ~~`epoch.scheme_counts` in the statement is a
self-report. It is checkable by re-scanning the events in the bundle, and the verifier should do
so. But for a `contiguous-range` bundle the counts describe only the range, while the natural
reading is "the project". I specified range semantics; the field name invites the wrong reading
and may want renaming to `scope_scheme_counts`.~~ The general warning L5 raised — that a signed
self-report describing a *scope* invites reading as a report about the *project* — survives and
applies to `scope` itself; §3.5's table is where that distinction is now carried.

**L6 — Interaction with `events_archive` consolidation (§9.3).** WI-259 says export must read the complete logical stream. Stage 4 restores archived rows *before* cutover (`ARCHITECTURE-0.6.0.md:681-683`). If any project is exported between now and that restoration, a `complete-store` statement would be a signed false claim. The safe rule is: **`complete-store` is forbidden until archive consolidation is confirmed complete for that project**, and export must check rather than assume. I have specified the check but not the mechanism by which export learns consolidation is done; that likely belongs to sibling D's preflight.

---

## Bundle v3 pre-implementation decisions — 2026-08-23 (WI-289 Phase A)

Six questions this document left open were settled before Phase B implementation begins.
E1–E3 follow from `EPOCH-RESET.md`: the estate starts at genesis, so there is one epoch
and no legacy seam. O1, O3 and O4 are owner rulings on scope and on two of §12's
least-confident areas.

| # | Clause | Decision | Standing |
|---|---|---|---|
| E1 | §3.6 event record encoding | **Confirmed as written.** Event records ship `base64`. | Final |
| E2 | §3.2 statement `epoch` block | **Dropped as vacuous, and FORBIDDEN at verify.** | Wording landed at Phase B; awaiting review ratification |
| E3 | §5.1 A6 `epoch_binding`, §5.2 `legacy_checkpoint_bound` | **Dropped as vacuous.** A6 struck from the axis table; the verdict value struck from the lattice. | Wording landed at Phase B; awaiting review ratification |
| O1 | §9 export contract, §9 rule 6 credential transport | **Verification-complete v3 is the full production ceremony.** Credential transport deferred post-cutover. | Owner-ratified, final |
| O3 | §12 L4 (`:752`), §3.4 | **RESOLVED.** The statement signer MAY be the project writer key, if that key bears `may_sign_bundles`. | Owner-ratified, final |
| O4 | §12 L2 (`:748`) | **RESOLVED.** Export over a broken chain is refused, fail-closed. | Owner-ratified, final |

**E1 — event records ship base64 (§3.6), and the sizing argument that made it contentious
is gone.** D7 and L3 flagged base64-vs-hex as a decision resting on unmeasured envelope
sizes at 352k events, with `MAX_BUNDLE_BYTES = 512 MiB` as the constraint that would
decide it. Under the empty-genesis estate there are no 352k events to size: the corpus
starts at zero and the pressure that made this a judgement call does not exist. Base64
stands as §3.6 specifies it — not because the sizing was measured, but because nothing
turns on it any more. L3 is therefore closed as moot rather than resolved; if the estate
later grows into `MAX_BUNDLE_BYTES`, the chunking story L3 describes returns on its own
merits and this decision does not prejudge it.

**E2 — the statement `epoch` block is dropped as vacuous.** §3.2's `epoch`
(`cutover_event_hash`, `legacy_event_count`, `v6_event_count`, `scheme_counts`) and the
§3.2 hard rule `epoch.legacy_event_count + epoch.v6_event_count == scope.event_count`
exist to make a *mixed* corpus self-describing. `EPOCH-RESET.md:69` deletes the mixed
corpus: "Version-aware event hashing and mixed-epoch membership trees are dropped: there
is one construction, because there is one epoch." A signed block whose only possible
value is `{cutover_event_hash: null, legacy_event_count: 0, v6_event_count: N,
scheme_counts: {"ed25519": N}}` restates `scope.event_count` and asserts nothing a
verifier could not derive — and D8's justification for it (making
`legacy_checkpoint_bound` computable) falls with E3. L5's `scope_scheme_counts` renaming
question lapses with the field.

**E3 — axis A6 `epoch_binding` and the `legacy_checkpoint_bound` verdict path are
dropped.** Same premise, same conclusion. A6's four values are all statements about a
cutover checkpoint (§4.4, D6); `legacy_checkpoint_bound` (§5.2, §9 rule 7, §10) is
reachable only when the events in scope are legacy-epoch (A4 = `legacy_partial` or
`none_verifiable`). With no legacy epoch, A6 is permanently `checkpoint_absent` and the
verdict is unreachable — and an unreachable verdict in a published verdict lattice is
worse than an absent one, because auditors read the lattice as a description of what can
happen. The axes A1–A5 and A7–A12 are unaffected. §5.3's reasoning for *keeping*
`legacy_checkpoint_bound` from the architecture's list is superseded by the reset, not
by a reversal of judgement.

**Status of E2 and E3 — wording landed at Phase B, 2026-08-23.** Direction was ratified by
two-lineage concurrence 2026-08-23 (Claude + gpt-5.6-sol) with the wording explicitly held
back: Sol declined to endorse final normative text without an implementation review, and
that reservation is recorded rather than smoothed over. **The Phase B implementation has now
been done, and the wording is landed with SUPERSEDED / DROPPED / LAPSED markers on every
affected clause: §3.2 (JSON example, hard rules, and a normative E2 marker), §3.3 (the
version-aware event hash and the mixed-epoch vector, superseded by `EPOCH-RESET.md:69`),
§4.4 (row 3 and a normative E3 marker), §5.1 (the A6 row and a normative E3 marker), §5.2
(the `legacy_checkpoint_bound` row and a normative E3 marker), §5.3 (a restated
divergence count), §9 rule 7, §10 (the auditor's verdict table), §11 D6 and D8, and §12 L5.**
This paragraph is what a reviewer ratifies; the markers are what they check it against.

**The open question is answered in the strict direction: the `epoch` block is FORBIDDEN at
verify, not merely not emitted.** The amendment asked "whether the `epoch` block becomes
*forbidden* or merely *not emitted*, and whether a v3 verifier must *reject* a statement
carrying it under the unknown-top-level-key rule (§3.1 rule 3)". The answer is yes to
rejection, on three grounds, in decreasing order of weight:

1. **The statement is the signed object, so tolerance there is worse than tolerance at the
   top level.** §3.1 rule 3's stated reason for rejecting unknown top-level keys is that "a v2
   verifier's tolerance of extra keys is how `public_keys` quietly became a trust root". A
   tolerated member *inside* the statement is attacker-chosen content carried under a valid
   signature that no verifier checks — a signed field with no verifier is exactly the S4 shape.
   So the statement's member set is closed and enforced, and rule 3's principle is applied one
   level down rather than merely gestured at.
2. **The standing repo rule is to prefer the stricter default**, because loosening later is
   cheaper than tightening. If a later release wants an epoch-like block, it adds it to the
   closed set in a reviewed diff; nothing about refusing it now makes that harder.
3. **The refusal names the field.** A bare "unknown statement key" would leave an operator
   holding a pre-E2 artifact guessing; the implementation names `epoch` and cites E2, so the
   error is a diagnosis.

**What Phase B deliberately did NOT decide**, so a reviewer does not read silence as a ruling:
the sibling documents that still mention the dropped names are untouched —
`ARCHITECTURE-0.6.0.md:345` (verdict list), `CUTOVER-CLASSIFICATION.md:444`
(`legacy_checkpoint_bound` as a ceiling) and `RECONCILIATION.md`'s Resolution-4 discussion
(exempt: it is the overlay). `BUNDLE-V3.md` owns the bundle verdict lattice, so its markers
are authoritative for the lattice; whether the siblings carry their own markers is a spec-set
sweep, not a bundle decision, and it is left for whoever owns that sweep.

**O1 — verification-complete bundle v3 IS the full normative production ceremony.**
The six properties this document specifies — the statement signature (§3.4), Merkle
membership over the event set (§3.3), chain-derived ordering (§3.3), anti-downgrade (§6:
`format_version` 1 deleted outright rather than deprecated), a fail-closed required trust
policy (§4.2, §4.6), and the export discipline (§9 rules 1–5, 7) — together satisfy the
production ceremony in full. Shipping them is not a partial delivery awaiting a further
tranche before v3 can be called done.

**Credential transport is separate, deferred work, not a gap in the ceremony.** §9 rule 6
anticipates action-delegation documents travelling in a closed
`sections.action_delegation_credentials` section addressed by recomputed
action-delegation hash. That is deferred to post-cutover work of its own. The deferral is
safe for the specific reason that the pre-existing behaviour already fails closed rather
than degrading quietly: `CHANGELOG.md:204` records that "Signed portable credential
transport remains P3.3/WI-289 work; bundle-v2 delegated audit is unverifiable", and §9
rule 6 says the same in normative form — a bundle missing a referenced credential is
`invalid` (complete-store) or `unverifiable` (partial), never silently trusted. Deferring
work whose absence already produces the honest verdict is a scheduling decision; deferring
work whose absence produces a false verdict would not be.

> Note on citation: earlier drafts referred to credential transport as "§9.6". `§9.5`/`§9.6`
> do not exist — §9 carries numbered rules, not subsections — and `RECONCILIATION.md:578`
> already ordered that spelling fixed. The clause is **§9 rule 6**.

**O3 — L4 is RESOLVED: the bundle statement signer MAY be the project writer key, provided
the key explicitly bears `may_sign_bundles`.** §12 L4 left the question to the trust policy
(§3.4) and named the tension: separate keys are better hygiene, but each additional key is
another one-way provisioning ceremony, and the marginal security is small when one operator
holds both. The resolution takes the scope mechanism as the answer rather than key
separation. `may_sign_bundles` is already a member of the project-local acceptance `scopes`
block (`TRUST-DOMAIN.md` §5.8) and of the `bootstrap_key_acceptance` object, so the
authority to sign bundles is an *explicit, signed* property of a key — not an implication of
holding the writer key. A writer key without the scope cannot sign a bundle statement.
Because the permission is scope-carried, separating the two keys later needs a new
acceptance event and no format change: the artifact shape is identical whether one key or
two bear the scope. This is the property that makes deciding it now cheap.

**O4 — L2 is RESOLVED: evidentiary export over a broken chain is refused, fail-closed.**
§12 L2 described the trap honestly — the membership tree needs a total order derived by
following `prev_global_event_hash` from genesis, so one broken link means no bundle at all,
including the diagnostic bundle an operator most wants at that moment — and offered
`--diagnostic` as the obvious shape while noting it is exactly the escape hatch D12 argues
against. **D12 prevails.** Export refuses. Any forensic capability must be a separately
named command that is unmistakably non-evidentiary: not a flag on `export`, not a mode of
it, and producing an artifact no verifier will accept as a bundle. A flag on the
evidentiary command is eventually load-bearing in someone's CI, and the failure mode is a
forensic dump that gets read as an audit bundle — the precise conflation this document
exists to remove. The operator's diagnostic need is real and is answered by a different
tool, not by weakening this one.

No bundle code is implemented by WI-289 Phase A. `src/regista/_bundle.py` is untouched.

---

## Bundle v3 implementation status — WI-289 Phase B, 2026-08-23

Phase B implements the **verification-complete v3 core** and nothing beyond it. Recorded
here so a reviewer can tell a deliberate phase boundary from a gap, and so Phase C and
Phase D know exactly what they are extending.

**Landed.** §2 and §6 (format acceptance and anti-downgrade; `_SUPPORTED_FORMAT_VERSIONS`
is `frozenset({3})` and a v1/v2 artifact is refused by name before any other check), §3.1
(document shape, closed top-level and section key sets, advisory-and-unread `index`), §3.2
as amended (the closed statement member set including E2's forbidden `epoch`, `trust_root`,
the single signer shape, `complete-store`/`contiguous-range` only), §3.3 (RFC 6962
membership over chain-derived ordinals, conformant to the five frozen
`tests/vectors/v6/bundle-merkle-*.json` through the production functions), §3.4 (the
ed25519 statement signature over the domain-prefixed JCS bytes), §3.6 (base64 event
records carrying envelope and signature and nothing else), §3.7 (section digests), owner
ruling O3 (`may_sign_bundles` enforced at build **and** re-derived from the signed
acceptance at verify) and owner ruling O4 (a chain that cannot be totally ordered is a
refusal, with no diagnostic flag and no partial artifact).

The reference sections (`key_lifecycle`, `project_key_acceptance`, `workflows`,
`review_verdicts`, `checkpoints`) are **recomputed at verify** from a closed
transition/payload-type map rather than read from the artifact — a section a verifier
derives cannot be edited. §1's argument is that a check reading an attacker-writable field
can only argue about plausibility, so anything derivable is derived.

**Deliberately not landed, and where it goes.** None of these is an oversight:

| Clause | Owner | Consequence at Phase B |
|---|---|---|
| §4.1–§4.6 trust-root resolution, `TrustPolicy` / `AcceptBundledKeys`, the required-argument signature | Phase C — **landed** | The verifier takes an **optional** caller-supplied statement public key and reports its absence as "not checked". It never resolves a key from the artifact — not from `bundled_key_evidence`, not from an acceptance payload — because that is §5.2 rule C's clamp and a core that harvested the key would make the clamp unreachable. |
| §5.1 axes, §5.2 `applicability` and the clamps, §5.3 | Phase C — **landed** | The report carries per-check facts, not axes, and still emits the `verified` boolean §5.2 deletes. Its Phase B definition is *stricter* than v2's: it requires the statement signature to have been checked and valid. |
| §3.2's `root_governance` as the **replayed** governance state | Phase C — **landed (partial)** | Export requires it as a caller input and refuses by name without it. A project store holds no governance state at all, so deriving it would falsify the one field WI-272 requires to be true in every artifact. The other two `trust_root` digests *are* restated, from the genesis event's signed payload, and a verifier cross-checks them against that event when it is in scope. |
| §3.2 item 2's direct root-threshold `root_signatures[]` | Phase C — **landed** | Recognised and **refused**, not tolerated. Checking it needs the current root signer set and threshold; accepting the shape unchecked would be a signed object with no verifier. |
| §9 rules 1–5 and 7: the export ceremony, the preflight comparison, `.partial`-then-self-verify-then-`os.replace` (D11), `--allow-unverified`'s deletion, exit codes, CLI flags | Phase D | The write order is still v2's (write, rename, verify) and is marked wrong in the module docstring rather than quietly fixed, so the reorder lands with the tests that pin it. `regista bundle export` errors cleanly until D wires the trust material. |
| §9 rule 6's full dependency closure | Phase D | Phase B closes exactly one dependency, the one O3 needs: the signer's authority event must be inside a `complete-store` bundle, and a bounded range reports it as outside scope. Lifecycle, workflow, delegation and verdict-supersession closure are D's. |
| §9 rule 6 credential transport (`sections.action_delegation_credentials`) | Phase E, deferred post-cutover by O1 | The section set is **closed**, so a bundle carrying one is refused rather than accepted with an unread section. Per O1 the deferral is safe because the pre-existing behaviour already fails closed. |

**One construction detail that has no frozen vector**, stated rather than left for a second
implementer to discover: §3.7's section-digest tag `regista.bundle.section.v1` is **not** in
the P0.3 vector manifest — the frozen set covers the membership leaf, node and tree only.
It is pinned by regista's own tests instead. A future vector for it would be cheap and is
worth having.

---

## Bundle v3 implementation status — WI-289 Phase C, 2026-08-23

Phase C implements the **trust root, the axis model and the auditor CLI** — §4, §5 and §10.
Recorded here so a reviewer can tell a deliberate phase boundary from a gap; this note
mirrors Phase B's and is what a reviewer ratifies against the code.

**Landed.** §4.1 the required-argument signature `verify_audit_bundle_v3(bundle_path, trust:
TrustPolicy | AcceptBundledKeys) -> BundleReport` — no default, no `None`, and a dynamic
caller supplying anything else is refused; §4.1 the two distinct trust types (`AcceptBundledKeys`
is not a `TrustPolicy`, does not subclass one, and is un-constructable without typing its
acknowledgement, so there is no implicit conversion); §4.2 `TrustPolicy` consumes the
`TRUST-DOMAIN.md` §4.6 schema and refuses a policy missing a required field, plus the minimal
ad-hoc `--trusted-fingerprint` form whose policy-dependent axes report their not-checkable
value; §4.3 `BundleKeyResolver` renamed `BundledKeyEvidenceResolver`, the default path built
from a separate `PolicyKeyResolver` (bytes from evidence, trust from the pin — see the §5.1
amendment-4 clarification below), and any `BUNDLE_EMBEDDED` use clamped by Rule C; §4.6
external evidence never raises an
axis (it is not read into any axis); §3.2 item 2 direct `root_signatures[]` now **verified**
against the policy's pinned root signer set and `min_root_signatures` (Phase B refused the
shape; Phase C accepts a well-formed one and checks it); §5.1 the axes A1–A5 and A7–A12, each
reported independently and each with a not-checkable value distinct from a failure; §5.2 the
ordered lattice `invalid < unauthenticated < bundle_rooted < externally_authenticated`, the
summary as the weakest over the table, Rule C (circularity ceiling) and Rule H
(`tail_truncation_undetectable`); the deletion of `verified: bool` from
`BundleVerificationReport` and its `to_dict` key, with every reader migrated
(`verify_audit_bundle_offline`'s report property `self_verification_ok`, export's self-check,
the CLI, `_ops`, `__init__`); §10 the auditor CLI — `regista bundle verify` takes
`--trust-policy` | repeated `--trusted-fingerprint` | `--accept-bundled-keys`, plus
`--known-head <hash>:<count>` and `--json`, **refuses to run** with none, and maps the verdict
to the §10 exit codes (0 externally_authenticated only, 2 bundle_rooted | unauthenticated,
1 invalid) with the per-axis facts and the tail-truncation / unverified-restatement / registry
notes in the human output.

**Reused rather than reimplemented** (the Phase B lesson — a parallel implementation drifts):
event authentication (A4) and the per-event trust source (A5) come from `verify_event_strict`
with the policy's pins threaded in (`pinned_trust_domain_id`, `pinned_project_instance_id`,
`cutover_checkpoint_event_hash`); the signer-authority (O3) and structural checks come from
Phase B's `verify_bundle_v3_core`; the offline signing-authority resolver
(`resolve_bundle_signing_authority`) is unchanged.

### CLARIFIES §5.1 amendment 4 — `externally_pinned` means chain-to-root, not per-key pinning

> This is the **implementer's reconciliation, PENDING review** — it records the reading the
> Phase-C implementation adopts, for the reviewers to ratify or correct; it is not itself a
> record of a completed review. It does not edit §5.1's ratified amendment-4 text; it states
> the operative reading where that text, read literally, underspecifies against §10 and §4.4
> criterion 2 — the governing clauses.
>
> §5.1 amendment 4 reads: "A key whose bytes travelled inside the bundle is `externally_pinned`
> if its recomputed fingerprint matches an auditor pin." Read as *per-key* pinning — a key is
> external iff its own fingerprint is in the pin list — this is **wrong in the direction that
> manufactures false external authentication**: it lets a verifier reach
> `externally_authenticated` by pinning every project writer key's own fingerprint, when the
> §10 workflow the auditor actually follows is to pin the **root** and let the acceptance chain
> carry trust down to the writer keys ("pin the root fingerprint(s) and let the acceptance chain
> do the rest"). §4.4 criterion 2 is explicit that authority flows along a chain with
> **enrolment-before-use** and rotation/revocation windowing. The whole architecture —
> trust-domain roots, `principal_key_enrolled`/`principal_key_accepted` events, the
> `trust_event_hash` cross-link — is chain-to-root.
>
> **Operative semantics (what Phase C implements):** a key is `externally_pinned` iff it is
> authenticated by a *signed chain to a policy-pinned ROOT fingerprint*. Amendment 4's
> fingerprint-match is the **base case only** — a root signing directly (a chain of length
> zero). A non-root project key (writer, bootstrap) is `externally_pinned` only through its
> signed acceptance/enrolment chain to a pinned root; its own fingerprint being pinned is not
> sufficient and is not the model. Key *material* (bytes) still travels in `bundled_key_evidence`
> and trust still comes only from the auditor's pin (§4.2 unchanged) — what this fixes is *which*
> pin, and *how* it reaches a non-root key.
>
> **Consequence, stated so it is not read as a gap (WI-337):** the chain-to-root walk for a
> project key crosses from the project chain into the **trust log** (writer → project acceptance
> → project genesis bootstrap → trust-log enrolment → pinned root). Every trust-log verifier in
> the tree — `verify_trust_log_chain`, `resolve_enrolled_key`, `load_published_checkpoint` — is
> **store-backed**, and §8.4 forbids the offline verifier from fetching. There is no offline,
> signature-verified trust-log artifact yet; **producing one is WI-337.** So Phase C's offline
> verifier authenticates the base case (a directly-pinned root) but **cannot** complete a
> non-root key's chain offline. A self-contained project bundle therefore reports its event keys
> as `bundled_only` and **cannot reach `externally_authenticated`** — the honest, fail-closed
> boundary, not a silent pass. Reaching `externally_authenticated` for a project bundle is
> WI-337-blocked. A verifier that faked it — by trusting caller-supplied trust-log referents
> without verifying their signatures and ancestry — would be committing the exact
> false-external-authentication class this document exists to remove (that was the Phase-C
> round-1 defect, now removed).

**Deliberately not landed, and where it goes.** None of these is an oversight:

| Clause | Owner | Consequence at Phase C |
|---|---|---|
| §4.5 `root_governance` as a **replay-confirmed** `matches_policy` | WI-337-adjacent | A9 lands the axis and the policy comparison: a restated mode outside `required_root_governance` is `contradicts_policy` (a finding → `invalid`), and a consistent one is `unverified_restatement` — because the `bundle verify` path is handed the policy and the head pin (§10), **not** an authenticated trust log to replay. `matches_policy` is reachable only with a trust-log replay, which is store-backed (WI-337); A9 therefore never silently claims a match it did not confirm (§4.5: "a verifier that cannot replay reports `unverified_restatement`"). |
| §4.4 criterion 2 chain-to-root for a **non-root** project key, and hence `externally_authenticated` for a project bundle | **WI-337-blocked** | See the amendment-4 clarification above. Completing a writer/bootstrap key's chain to a pinned root needs authenticated trust-log material, and the only trust-log verifiers are store-backed while §8.4 forbids fetching. There is no offline signature-verified trust-log artifact (WI-337), so a project bundle verified offline reports `bundled_only`/`bundle_rooted`/`unauthenticated` honestly and never reaches `externally_authenticated`. The base case (a directly root-signed statement or event) **is** authenticated. |
| §10 CLI `--trust-log` flag to present authenticated trust-log material | **WI-337-blocked** | Deliberately NOT added. The only trust-log source today is the live store (a DSN); wiring a DSN fetch into the offline auditor tool contradicts §8.4 ("a verifier that silently fetches its own trust material has no trust root at all") and the §10 offline workflow, and inventing a published-artifact format is out of scope. So the CLI's exit-0 (`externally_authenticated`) verdict is **unreachable for a project bundle until WI-337 publishes an offline, signature-verifiable trust log**; it is reported here rather than shipped as a documented-but-unreachable top verdict. The CLI's other verdicts (bundle_rooted, unauthenticated, invalid) are fully reachable. |
| §9 export ceremony, preflight, `.partial`-then-self-verify-then-`os.replace`, `--allow-unverified`'s deletion, export exit codes | Phase D — **landed** | See the Phase D status note below. `verify_audit_bundle_offline` survives only as an integrity-report vehicle for existing tests; the export self-check now runs through `verify_audit_bundle_v3` (there is one v3 verifier). |
| §9 rule 6 credential transport | Phase E (deferred post-cutover by O1) | Unchanged: the section set is closed, so a bundle carrying one is refused. |

---

## Bundle v3 implementation status — WI-289 Phase D, 2026-08-23

Phase D implements the **§9 export ceremony** and the **§9 rule 6 dependency closure beyond
the signer's authority**, and closes the last bundle-v3 gap. This note mirrors Phase B's and
Phase C's and is what a reviewer ratifies against the code.

**Landed.** §9 rule 1 — `export_audit_bundle` strict-verifies every event over the
archive-consolidated window before signing and refuses to sign a corpus containing any
`Applicability.INVALID` (`_bundle._strict_verify_export_source`); an `UNVERIFIABLE` event
(an unpinned genesis bootstrap) is not invalid and is exported honestly. §9 rule 2 (D1) — an
optional `preflight` (`{event_count, first_event_hash, last_event_hash}`) is compared against
the derived scope and any mismatch aborts before a byte is written (`_compare_preflight`; CLI
`--preflight`). §9 rule 3 (WI-259) — the export read consolidates `events` with
`events_archive` (`_windowed_source_sql`), so a `complete-store` claim covers the complete
logical stream. §9 rule 4 (WI-261) — an existing destination is refused up front unless
`overwrite=True` (CLI `--overwrite`). §9 rule 5 (D11) — the write order is now write to
`.partial` → self-verify the `.partial` through `verify_audit_bundle_v3` → `os.replace` only
on success; a failed self-verification leaves the `.partial` for inspection and never touches
the destination, and `BUNDLE_WRITE_CORRUPT` is re-pointed at the statement signature. §9
rule 7 — `--allow-unverified` is deleted; export returns the self-verified `applicability`
and the CLI maps it through the same §10 exit table (`_BUNDLE_VERDICT_EXIT`), so exit 0
requires `externally_authenticated`. Export is wired end to end: signing material is the
store's own key set and the replayed `root_governance` is supplied via CLI flags
(`--root-governance-mode/-threshold/-signer-count`), so `regista bundle export` produces a
real signed v3 statement rather than erroring by name.

§9 rule 6 — the dependency-closure walk beyond Phase B/C's signer authority
(`_bundle_v3.compute_dependency_closure`) covers key lifecycle and project acceptance (each
event's `signing.key_binding_event_hash` anchor), workflow registration
(`workflow.registration_event_hash`) and its supersession
(`supersedes_registration_event_hash`), acceptance revocation
(`payload.acceptance_event_hash`) and the review-verdict subject
(`reviewed_through_event_hash`). A `complete-store` missing a named dependency fails A3
(`dependency_closure_ok=False` → `membership_consistency=mismatch` → `invalid`); a
`contiguous-range` names each out-of-scope dependency as a report note (Resolution 4). In a
linear project chain a complete-store's missing dependency also breaks chain ordering
(`chain_ordered=False` fires first), so chain-ordering is the primary enforcer and the
`dependency_closure_ok=False` verdict is **defence in depth** — reachable on its own terms
only by a forged-but-orderable bundle, where it fails closed
(`tests/test_bundle_v3.py::TestDependencyClosureReachesInvalid`). The observable rule-6
behaviour in normal operation is the contiguous-range naming.

**Concurrency and publication (WI-340 fix round, F1/F2).** Export takes the
`event_chain_head` sentinel `FOR UPDATE` at the start of its read transaction — the discipline
the writer and `archive_events` already use — so no append can advance the head between the
read and the signature; a `complete-store` is signed over one stable snapshot and its
chain-ordered scope is asserted equal to the head captured under that lock, or export aborts
(`_lock_export_snapshot_head`, F1). Publication of the self-verified `.partial` is atomic and
no-clobber for `overwrite=False`: it is `os.link`ed onto the destination, which the kernel
refuses if the destination appeared in the window after the up-front `exists()` check, rather
than clobbering it with `os.replace` (`_publish_verified_partial`, F2).

**Deliberately NOT landed, and where it goes.** None is an oversight:

| Clause | Owner | Consequence at Phase D |
|---|---|---|
| `externally_authenticated` for a project bundle (export exit 0) | **WI-337-blocked** | The export self-check uses `AcceptBundledKeys` (self-consistency) and is clamped to `bundle_rooted` by Rule C, and a project bundle cannot reach `externally_authenticated` offline until WI-337 publishes a signature-verifiable trust log (Phase C's amendment-4 clarification). So a healthy project export self-verifies at `bundle_rooted` and the CLI exits 2 — the honest ceiling, not a write failure. The bundle IS written. |
| §10 CLI `--trust-log` flag | **WI-337-blocked** | Still deliberately NOT added, for the reason Phase C recorded: the only trust-log source today is the live store, and wiring a DSN fetch into the offline auditor contradicts §8.4; inventing an offline trust-log artifact format is WI-337, not Phase D. |
| §9 rule 6 credential transport (`sections.action_delegation_credentials`) | Phase E (deferred post-cutover by O1) | Unchanged: the section set stays closed, so the closure walk never reaches into a credential section and a bundle carrying one is refused rather than accepted with an unread section. |
