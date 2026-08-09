# regista correctness audit — findings and remediation plan

**Date:** 2026-08-08
**Scope:** regista at `origin/main` (`b103753`), i.e. 0.5.6-as-held, including every fix merged during the pre-publish review rounds.
**Method:** seven independent agents, one per correctness property, each required to *reproduce* every claim; every finding then attacked by two independent skeptics (one on mechanism, one on consequence). Findings that either skeptic killed are not reported here.
**Result:** 78 agents, 35 findings surviving refutation — 13 critical, 20 high, 2 medium; 20 classified structural.

**Threat model.** Actor identity and metadata are self-asserted, so defeating a wholly dishonest actor is out of scope. In scope: (1) honest-but-heterogeneous histories must classify correctly; (2) **an attacker with database write access** — this is the model regista's own design assumes, and it is what signing, chaining and anchoring exist to defeat; (3) an offline-bundle attacker who recomputes the unkeyed bundle hash. Almost every finding below is a database-write finding. None of them say "a remote user can forge your history."

---

## 1. Verdict on the fundamentals

**regista's correctness core does not currently deliver its central guarantee.** The claim the whole system rests on — that a signed, hash-chained event log makes tampering evident — does not hold against a database-write attacker, because *the thing being verified is not the thing being read*.

One defect accounts for the majority of the critical findings, and seven agents auditing seven different properties each found it independently, in seven different framings:

> **Signature verification authenticates the stored `canonical_envelope`. Every consumer — chain verification, replay, the review gate, segment verification, anchoring, and the offline bundle — reads the *unsigned row columns*, which are never reconciled against that envelope.**

This is not inference. `_signing.py:366-378` puts the stored envelope first in the candidate list, and the code's own comment states the trade-off plainly:

> *"Try the stored envelope first (it's the canonical truth for signature verification). For v5, we additionally check that the provided actor_kind/actor_metadata match the stored envelope's values ... **without requiring every caller to pass all envelope fields**."*

WI-208 patched exactly two fields — `actor_kind` and `actor_metadata`, and only on v5 envelopes. Every other signed field (`transition`, `payload`, `timestamp`, `event_seq`, `prev_event_hash`, `prev_global_event_hash`, `on_behalf_of`, `key_id`, `entity_id`, `workflow_name`/`version`) can be rewritten in the row while the signature still verifies over the untouched envelope. Downstream, every verifier reads the row.

That is why the same defect surfaces as "chain verification walks unsigned columns", "replay certifies rewritten history", "the bundle's event records are never bound to the envelope", "segment verification verifies no signatures", and "`on_behalf_of` promotes self-reviewed to independently-reviewed".

**The honest summary:** the cryptography is sound, the canonicalizer is correct, and the plumbing is careful — but the signatures are not load-bearing where it matters, and several subsystems that report "verified" are checking either nothing or the wrong thing. This is fixable, and the fix is well-defined.

Two further systemic conclusions:

- **Nothing in the estate is actually anchored.** RFC 3161 verification is unauthenticated by default (no trust anchor ⇒ CMS signature never checked, yet a positive verdict is returned); the timestamp batch commits only to event *UUIDs*, so it witnesses no content; and the OpenTimestamps provider — the only one documented as a real public anchor — cannot execute against the pinned library version at all, with tests passing against a `sys.modules` stub implementing an API that does not exist. Documented guarantees that rest on anchoring currently rest on nothing.
- **Detection is frequently non-blocking even when it works.** A detected hash-chain break is a `warnings` counter; `regista replay` prints it and exits 0. An empty event log verifies clean. Work items with no events are never compared at all.

---

## 2. Structural findings

### S1 — The row is not authenticated; the envelope is *(root cause)*
**Severity: critical.** `_signing.py:366-378, 455-489`. Everything in §1. Roughly ten findings, including six criticals, are instances of this one gap.

**Fix.** Make the *row* the authenticated artifact. Either rebuild the envelope from row columns and verify only that (stored bytes become a debugging aid, and any divergence fails closed), or keep the stored-envelope fast path and add a **total** reconciliation pass: after a signature verifies, parse the envelope once and require every duplicated column to equal its signed counterpart. Generalise WI-208 from two fields to all of them. This is a contained change with a large blast radius of benefit — it closes findings across all seven properties simultaneously.

### S2 — `scheme_id` is outside the signed envelope and decides whether signatures are checked
**Severity: critical.** `_bundle.py:741-754`, `_signing.py:140-190`. Relabelling an ed25519 event as `hmac-sha256` exempts it from verification, while the bundle's own key registry still names its key as ed25519. *(In-database downgrade does fail closed — see §4 — but the offline bundle path does not.)*
**Fix.** Interim: an event whose `key_id` resolves to an asymmetric registry key must be verified as asymmetric regardless of its self-declared `scheme_id`, and disagreement must be an error. Proper: put `scheme_id` inside the signed envelope in a v6 scheme.

### S3 — `format_version=1` downgrade disables all signature checking
**Severity: critical.** `_bundle.py:646-667`. A v1 manifest collapses the bundle to an unkeyed hash chain, rewritable end to end, still reporting `verified=True`.
**Fix.** Treat "signatures not enforced" as a verification *failure*, not a report string; refuse a v1 manifest whose events carry asymmetric signatures.

### S4 — Bundle membership is unauthenticated
**Severity: critical.** `_archive_segments.py:153-199`. Whole work items can be erased, histories truncated, events injected — all `verified=True`. The bundle contains no signed statement of what it should contain.
**Fix.** No local patch exists. Partial hardening now: for an unwindowed export require `global_seq` to be exactly contiguous with no bridge points other than genesis. Proper: sign the bundle, or carry a signed membership manifest.

### S5 — The bundle's trust root is circular (BC-016, reproduced)
**Severity: high.** `_bundle.py:706-736`. The verifier takes its public keys from the bundle it is authenticating; re-signing forged events with an attacker key and swapping the registry entry yields `verified=True` with `signature_check=enforced`.
**Fix.** `bundle verify --trust-keys <file>` / pinned fingerprints, with the bundled registry used only as a convenience copy the operator explicitly accepts, and the report distinguishing "verified against a pinned root" from "verified against the bundle's own keys". **This directly contradicts the recorded BC-016 resolution and should be treated as reopening it.**

### S6 — Unsigned side tables are used as verification oracles
**Severity: high.** Four instances, each one `UPDATE` away from rewriting a guarantee:
- `principal_keys` — every key-lifecycle guarantee (`_principal_keys.py:137-153`).
- `workflow_registry.definition` — replay's oracle; the `content_hash` column that would prove tampering is never consulted (`_replay.py:1165`).
- `event_segments` — replay bridges chain holes over unauthenticated segment rows; one forged `INSERT` hides an arbitrary deletion (`_replay.py:783-796`).
- `event_chain_head` — the only witness to tail truncation (`_replay.py:799-817`).

**Fix.** Promote each to a signed event on the entity chain, demoting the table to a replayed projection. `principal_entity_id()` already exists (`_principal_keys.py:53`) and is unused by these functions — the intended design appears to have been started and not finished.

### S7 — Anchoring witnesses nothing
**Severity: critical/high.** `_timestamping.py:456-502` (unauthenticated RFC 3161 by default; replay hardcodes a config that can never have a trust anchor); `_timestamping.py:84-96` (batch Merkle tree over `uuid.bytes`, so content can be rewritten under a pre-committed ID); `_anchoring.py:355-441` (OpenTimestamps provider non-functional against the pinned library; tests use a fake module).
**Fix.** Make `tsa_cert_path` mandatory for any positive verdict and return a distinct `unverifiable` status otherwise; build the batch tree over `sha256(canonical_envelope || signature)` leaves; port or remove the OTS provider. **Until then, narrow `spec.md` §17.9.2 and the README to what is actually true.**

### S8 — Assurance is inferred from transition names, not from a signed gate verdict
**Severity: high.** `_assurance.py:235, 299`. Four instances: assurance is computed from bare transition strings (forgeable via `append_event` on any workflow that does not define the review transitions); it is *not monotone* — appending one ordinary agent-authored note can upgrade an item to `INDEPENDENT_AND_ACCEPTED`; it verifies nothing, so a DB-write attacker flips `HUMAN_ACCEPTED` to `INDEPENDENT_AND_ACCEPTED` with one `UPDATE`; and the review is **not bound to the content it reviewed**, so an author can rewrite an item after the cross-lineage pass and self-accept, reaching `done` reporting `INDEPENDENTLY_REVIEWED` under the strict profile.
**Fix.** Have the gate write its decision (relation, author set, acknowledgment, and a content hash of what was reviewed) into the signed event payload, and have `compute_assurance_level` read *only* that signed verdict — refusing to count a review event whose payload carries none. Freeze the author set as of the deciding pass and treat post-pass authorship as a downgrade.

### S9 — No project/tenant binding in any signed envelope
**Severity: high.** `_signing.py:135-190`. A signed event replays verbatim into a different project.
**Fix.** Add `project_name` (ideally a per-project instance UUID) to the v6 envelope. Interim: never share a key file across projects, and *enforce* that rather than assuming it.

### S10 — Live segment verification never reconciles against the signed seal
**Severity: critical.** `_archive_segments.py:679-687`. The WI-254/255 work fixed this for the *bundle* path; the live-store path never got it, so a DB-write attacker truncates a sealed segment and both `verify_segment` and `verify_archive_chain` report `verified=True`. Segment verification also verifies no event signatures at all.
**Fix.** Port `_reconcile_segment_with_seal` into `verify_segment`, reading the seal from `canonical_envelope`; verify event signatures there (the machinery already exists — `_verify_seal_event` does it for one event).

---

## 3. Local defects (patchable, ranked)

1. **`register_principal_key` supersedes without setting `valid_to`** (`_principal_keys.py:124-153`) — the only CLI rotation path leaves a rotated-out key valid forever. One-line fix plus the missing test assertion; add a `principal rotate` verb so operators aren't funnelled through `register`.
2. **Chain breaks exit 0** (`_cli.py:305-336`) — give `ReplayReport` a `chain_breaks` count distinct from `warnings` and exit non-zero. "The log is not the log that was signed" must not be advisory.
3. **`_verify_hash_chain` treats NULL `prev_event_hash` as a passing link** (`_replay.py:157-177`) — legitimate only at `event_seq == 1`; take the genesis test from the signed envelope.
4. **Work items with no events are never compared** (`_replay.py:546`) — fabricated projection rows and a fully deleted log both replay clean. Diff processed ids against `wi_ids` and halt on the remainder.
5. **Whole-store vs scoped replay disagree** on a deleted projection row (warning vs `halted`) — same corpus, opposite verdicts.
6. **`workflow_name`/`version`/`work_item_type` never replayed or compared** — a mid-life workflow substitution is invisible.
7. **`archive_events` deletes witness receipts** (`_archive.py:101-123`) to satisfy a foreign key, discarding attestation evidence, and makes an intact store's anchor unverifiable.
8. **`_verify_anchor_offline` reports `verified=True` for a receipt it skipped**; **`principals.verify_binding()` asserts a binding it never verifies**; **three verifiers implement three different revocation semantics**, giving the same chain opposite verdicts.
9. **`replay` reports `principal_binding_verified=True` with 0 failures when 100% of events were skipped** — the WI-223 signal is vacuous on an HMAC store.

---

## 4. What is genuinely sound

The audit attacked these and could not break them. This is not filler — it is what can be relied on.

- **The RFC 8785 canonicalizer is correct.** Key ordering matched the RFC's own mixed-script UTF-16BE vectors; all 12 ES6 number-serialization boundary vectors (exponent thresholds, denormals) matched; nine hostile inputs all rejected fail-closed (≥2^53 integers, NaN/Infinity, non-string keys). No collisions between logically distinct values.
- **The WI-208 cross-check works for the two fields it covers** — mutating `actor_kind` or `actor_metadata` on a v5 event fails verification and *halts* replay.
- **In-database scheme downgrade fails closed** — `UPDATE events SET scheme_id='hmac-sha256'` on an ed25519 event is caught online (the offline bundle path is S2).
- **Envelope deletion and `hash_alg` substitution fail closed.**
- **All four `sign_event` call sites pass `actor_kind`**, so every event written by 0.5.6 gets a v5 envelope.
- **Key rotation semantics are right when `valid_to` is actually set** — rotated-out keys still validate old events; post-rotation events are rejected by both verifiers. `actor_id` and `key_id` row tampering are both caught.
- **Append-time chain serialization is correct under concurrency** — 8 threads × 6 work items racing through one pool produced no chain anomaly; the global walk follows hash links rather than sorting on `global_seq`, so allocation gaps cannot reorder it.
- **The review gate's *logic* is sound** where it isn't bypassed: the deliberate human-proxy loosening admits no hidden mind (verified across six delegation shapes); separation of duties holds through delegation; multi-pass histories downgrade correctly; a reviewer who authors after its own pass is caught; `request_changes` carries the same acknowledgment obligation; `principal_kind` ingress validation is real and canonicalising; 296 gate tests pass.
- **Replay's read-only and writable paths agree** on a deliberately divergent corpus; per-item ordering is tie-free; genesis selection is order-stable; direct `current_state` tampering and unrepaired event deletion are both caught as drift; halts are never mistaken for agreement.
- **The WI-254/255 bundle fixes hold** for the attacks they were built against: manifest count edits, impossible windows, segment-record edits against the signed seal on an ed25519 store, and the unbounded-window seal requirement. Mid-history event deletion within a work item is caught. Empty bundles are rejected.
- **`seal_segment` refuses to seal over a broken chain**, and the events/`events_archive` seam fails closed on a divergent duplicate.

---

## 5. Remediation plan

**Phase 1 — must precede any release.** These are bounded, and Phase 1 alone converts "signatures are decorative" into "signatures are load-bearing".

| # | Item | Notes |
|---|---|---|
| 1 | **S1: total envelope↔row reconciliation** | The keystone. Closes ~10 findings across all seven properties. |
| 2 | **S2 interim + S3: bind `scheme_id` to the registry key; make unenforced signatures a failure** | Cheap; both are one-sided checks. |
| 3 | **S10: port seal reconciliation + signature verification into `verify_segment`** | The code already exists in the bundle path. |
| 4 | **Local defects 1–5** | `valid_to`, non-zero exit on chain breaks, NULL-prev fail-closed, uncompared work items, path parity. |
| 5 | **Narrow every claim that outruns the code** | `spec.md` §17.9.2, README "event integrity", the BC-016 resolution, `lineage_verification` (WI-263), witness enrollment (WI-264). Non-negotiable: shipping an honest description costs nothing and is the difference between a gap and a misrepresentation. |

**Phase 2 — the trust root.** S5 (`--trust-keys` out-of-band root), S6 (signed key/workflow/segment/head events, tables demoted to projections), S8 (signed gate verdict bound to reviewed content). Each is a design change with migration implications; S6 is the precondition for most remaining "unsigned oracle" findings.

**Phase 3 — anchoring, and the v6 envelope.** S7 (mandatory trust anchor, content-committing batch tree, OTS port-or-remove), S4 (signed bundle / membership statement), S9 + S2-proper (`project_name` and `scheme_id` inside a v6 signed envelope). This is where the estate's anchors work belongs, and it is the honest home for the BC-016 trust root.

**Dependencies worth stating:** S1 precedes almost everything (other fixes read fields it makes trustworthy). S6 precedes retiring the "unsigned oracle" class. Anchoring (S7) is the precondition for any claim of external tamper-evidence, and the estate has none today.

---

## 6. Release recommendation

**Do not ship this as 0.5.6.** Ship **0.6.0** after Phase 1, with Phase 2 and 3 sequenced afterwards as their own releases.

Rationale: Phase 1 changes what verification *means* — after the reconciliation fix, events and bundles that previously verified may correctly stop verifying. That is a semantic change, not a patch, and it deserves a minor version and release notes that say so plainly. It also makes the 0.5.6 changelog's framing wrong: it currently reads as a set of gate and bundle fixes, when the actual story is "signature verification was not binding, and now is."

The seven fixes already merged remain correct and valuable — they are a genuine prerequisite, not wasted work — but shipping them alone would put a version number on a spine whose central guarantee doesn't hold, which is exactly what holding the release was meant to avoid.

---

## 7. What this audit did not cover

- **Two refuter agents were lost to a usage limit** (both on RFC 3161 findings); those two findings carry one skeptic verdict rather than two. Everything else has two.
- **Lower-severity findings were not refuted.** Verification was capped at the top five findings per property; the remainder are recorded but unconfirmed. Nothing critical or high was dropped.
- **Unreproduced suspicions** (~25 across the seven properties) were deliberately excluded from the findings above. They are in the journal and are the natural starting point for a second pass.
- **Not audited as properties:** the sidecar HTTP surface and its authn/authz, secrets handling and Vault integration, migration safety and ordering, the CLI contract and error envelopes, claims/leases beyond concurrency, webhooks and hooks, and multi-tenancy/isolation beyond the project-binding finding. Any of these could hold defects of comparable severity.
- **No performance, availability or DoS analysis** was attempted.
- **The findings are code-level and reproduced against a live Postgres**, but no fix has been implemented or verified yet. Every remediation above is a *proposal*, and several (S1 especially) need their own design review before implementation — the pre-publish rounds showed repeatedly that fixes in this area introduce new surfaces.

---

# ADDENDUM — independent design review of this plan (2026-08-08)

The remediation plan above was design-reviewed before implementation by the same
independent reviewer (gpt-5.6 lineage) that gated the release three times. Verdict:
**proceed with modifications.** Full text: `SOL-DESIGN-REVIEW.md`. The plan is amended
as follows; where this addendum and §5/§6 above disagree, **this addendum governs**.

## Confirmed

- **S1 is genuinely the common cause**, not a narrative imposed on separate bugs.
  `verify_event()` returns as soon as the stored envelope verifies (`_signing.py:366-376,
  462-487`); replay then applies the row's `transition`/`payload` (`_replay.py:990-1003,
  1120-1163`); bundles verify the envelope but make policy decisions from row fields
  (`_bundle.py:741-807`).
- **0.6.0, not 0.5.6.** Confirmed.

## Correction — findings that SURVIVE a complete S1 fix

Do not mark these closed when S1 lands: **S2, S3, S4, S5, S6, S7, S9, S10, and all five
local defects.** **S8 only partially** — S1 stops unsigned transition rewriting but not a
legitimately signed, semantically fake `adversarial_pass`, and adds no binding between a
verdict and the content reviewed.

> "The main mistake would be treating S1 as though it made every downstream 'verified'
> claim true automatically. It does not; it makes trustworthy event semantics *possible*."

Also: **`global_seq` is unsigned by design** (`spec.md:667-674`, assigned after signing).
S1 must not imply otherwise.

## Design decision — S1 takes option (b), with constraints

**The stored canonical envelope is the cryptographic artifact; the row is its indexed
projection.** Verify the exact stored bytes, then require every field signed by that
envelope version to agree with its row representation before any consumer uses the row.

Rebuild-from-row (option a) is **rejected** for concrete reasons: signatures, chain hashes,
seals and anchors commit to the *stored bytes*, not a later re-serialization; `global_seq`
is assigned after signing so a generic rebuild would wrongly include it; and migration 031
backfilled `entity_kind`/`entity_id`/`hash_alg` into rows that never signed them.

Required properties of the central verifier:
- Parse the envelope once; require a JSON object with known required/optional fields.
- **Reject unknown schema versions** rather than classifying arbitrary subsets as v1 —
  current classification is permissive (`issuperset`, `_signing.py:305-319`).
- Reconcile optional fields by **presence**, not only value (absent ≠ null ≠ row NULL).
- Derive the signing scheme from **trusted key metadata**, never from row `scheme_id`.
- Enforce `work_item_id == entity_id` for work-item v4/v5 events.
- Preserve exact stored bytes for chain hashing.
- **Never fall back to a rebuilt candidate after a parse/signature/reconciliation failure** —
  that would recreate exactly the escape hatch being removed.

## Compatibility — a preflight tool, not an assumption

The set of newly-failing events is **not guaranteed empty**: pre-migration rows may have
`canonical_envelope IS NULL` (`migrations/002`, nullable, never backfilled), and historical
v3/v4 rows carry unsigned migration backfills that must not be rejected for absence.

Therefore 0.6.0 must ship a **dry-run preflight command** reporting envelope version,
signature validity, mismatched fields, missing envelopes, unsigned legacy fields, and
affected segment/anchor ids. Operator remedy for a mismatch in a genuinely signed field:
restore the row from the signed envelope or a trusted backup, or quarantine — **never
silently accept, and never routinely re-sign history** (re-signing rewrites event heads,
successor links, the global chain, seals and anchors: a cryptographic history rewrite, not
a migration).

Legacy handling must be bounded and observable — explicit statuses (`fully_reconciled`,
`legacy_v4_partial`, `legacy_missing_envelope`, `mismatch`), a fixed cutover version, and
**no `allow_legacy` mode that turns a signed-field mismatch into success**. The InMemory
backend needs the same reconciliation; its keyless mode must report as **unsigned** rather
than passing through the strict verifier.

## Phase 1 is amended — two additions are mandatory

**A. S10 must be coupled to replay's segment bridging.** Fixing `verify_segment()` alone is
insufficient while replay still trusts raw `event_segments` rows as jump links
(`_replay.py:250-271, 308-345, 782-796`). One segment-verification primitive — member
row/envelope reconciliation, member signature verification, chain verification, signed-seal
reconciliation, boundary/count verification — must gate **both** live verification and
replay bridging. Otherwise the main replay path bypasses the fix.

**B. S5 must be resolved at the public verdict boundary.** A bundle verifier cannot honestly
return a general `verified=True` while taking its root keys from the artifact under
verification. Either bring minimal `--trust-keys`/pinned fingerprints into Phase 1, **or**
split the result into `internally_consistent` / `signatures_valid_against_bundled_keys` /
`authenticated_to_external_root`, the last false-or-unknown without external trust.
**Documentation narrowing alone is insufficient while the API still returns `verified=True`.**

Anchoring (S7) may stay deferred **only if every anchoring claim and positive status is
narrowed or disabled** — including `README.md:26` ("RFC 3161 timestamping … for event
integrity") and the third-party anchoring guarantee at `spec.md:640-657`.

S8 should move forward, or the assurance surface must be explicitly downgraded — given 0.5.6
was framed around gate correctness, claiming strong review assurance without a signed,
content-bound verdict is not defensible.

## Order — S1 is the first code dependency, not the first action

Before implementation: (1) write the **authenticated-field matrix** for every envelope
version; (2) define strict envelope schemas and verification-result states; (3) **inventory
real stores** with the dry-run checker; (4) define the cutover and legacy policy. Without
these, an implementation can silently reinterpret historical data.

Must be implemented **together**: S1 + S2-interim (reconciliation cannot trust row
`scheme_id`); S1 + **all consumers sharing one primitive** (fixing only `verify_event()`
leaves `_bundle.py:801-807` exposed); S10 + replay bridging; chain-break counters + CLI exit
status; local defects 4 and 5 (one definition of missing membership); S3 + the bundle verdict
split.

## Adopted structural recommendation — one verified-event result model

Rather than a collection of boolean patches, every verifier returns **structured evidence**:
envelope version and schema validity, signature validity, trusted-key source, row
reconciliation result and mismatched fields, authenticated vs unsigned fields,
principal-binding result, chain-link result, legacy/degraded reason, and a final
applicability of `fully_authenticated` / `legacy_partial` / `invalid` / `unverifiable`.
Replay, bundles, segments, assurance, witnesses and the CLI all consume that one result.
Today each path reimplements part of verification and assigns "verified" a different meaning.

The roadmap is accordingly re-divided **by guarantee, not by subsystem**:
1. Authenticated event semantics — strict envelope parser, S1, scheme binding, common verifier
2. Authenticated traversal — chains, segment bridges, completeness verdicts, CLI exit status
3. Authenticated trust root — pinned bundle roots, signed key lifecycle
4. Authenticated review decision — content-bound gate verdict
5. External evidence — functioning content-committing anchors

## Release notes must state the boundary, not "improved integrity"

Ten specific statements are required (see `SOL-DESIGN-REVIEW.md` §6), including: the old
failure mode in plain terms; that existing mismatches now fail closed, with the preflight and
repair procedure; that historical v3/v4/missing-envelope records have explicitly limited
authentication scope; that bundles are externally authenticated **only** against
operator-supplied pinned trust material; that **no external anchoring guarantee exists yet**;
and that hash chains cannot independently prove complete membership or detect all tail
truncation without a trusted external checkpoint.

---

# SCOPE ADDITION — ed25519 cutover joins 0.6.0 (owner decision, 2026-08-08)

Owner: *"Please roll the ed25519 work into the scope for 0.6.0. I'm not sure that HMAC has much
of a purpose given the intended use of this project."* Filed as **WI-270**.

**Why this belongs in Phase 1 rather than later.** §1 of this report concluded that S1 makes
signatures load-bearing. It does not make them *checkable by anyone else*. The estate signs with
HMAC; the secret is deliberately never exported; therefore an auditor handed a bundle cannot
verify it — structurally, not as a defect. S1 surfaced this honestly by making `verified=False`
for HMAC bundles. Until this changes, three remediations are ceilinged:

- **WI-269** (bundle verdict split) has no reachable `authenticated_to_external_root` state.
- **S5 / BC-016** pinned trust roots are meaningless when no verifiable public key exists.
- The project's core proposition — hand a third party a record they can independently check —
  does not exist for any store in the estate.

**The rule, and its asymmetry:** *stop HMAC signing; keep HMAC verification forever.* The 351,371
existing events are HMAC-signed and cannot be re-signed — that would rewrite event heads,
successor links, the global chain, seals and anchors, which `CUTOVER-POLICY.md` forbids as a
cryptographic history rewrite rather than a migration. HMAC signing survives only for
dev/test/InMemory and must be refused in a production posture (doctor check plus a strict mode
that fails closed).

**Unavoidable consequence, to be stated plainly in the release notes:** every existing store
acquires a permanent seam — an HMAC prefix that is internally-consistent-only, and an ed25519
suffix that is independently verifiable.

**Mitigation for the prefix — a signed cutover checkpoint.** At cutover, sign a statement with the
new ed25519 key asserting *"as of `global_seq` N, the chain head was H."* Individual historical
events remain unverifiable by a third party, but the whole prefix becomes anchored to a
publishable key: a verifier can establish that the history shown is the history that existed at
cutover and has not been altered since. This converts "trust us about everything before the
cutover" into "verify one signed statement about it."

**Sequencing:** WI-267 (S1) first — it must matter that signatures are load-bearing before the
algorithm choice matters. WI-269 with or after, so its top verdict state becomes reachable.

**This raises the priority of S6, it does not lower it.** Once published public keys are the trust
root, `principal_keys` being an ordinary unsigned mutable table is the weak link in the chain —
as is unanchored witness enrollment (WI-264). Signed key lifecycle moves from "Phase 2 hardening"
to "the thing the new trust root rests on."
