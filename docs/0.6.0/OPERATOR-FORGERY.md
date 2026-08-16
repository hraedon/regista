# OPERATOR-FORGERY.md — the residual threat model after 0.6.0 (WI-007)

**Status:** FROZEN CONTRACT, Stage 0. Normative for what 0.6.0 may claim.
**Companion:** `TRUST-DOMAIN.md` (same directory) specifies the mechanisms referenced here.
**Code baseline:** `origin/main` at `334b995` (post-S1). Citations are `file:line` against that
tree.

WI-007 is a *decision* item, open since 2026-07-01. Its original framing: BC-196 established that
HMAC is symmetric, so an external auditor cannot verify the log without holding the operator's
secret, and proposed Ed25519 as the structural fix for external verifiability — but *asymmetric
signing alone does not defend against operator forgery*, because the entity holding the private
key can fabricate anything.

This document closes the analysis and leaves the item open by design. It states which attacks
0.6.0 defeats, which it does not, and — the part that turns a disclaimer into a roadmap — what
would have to become true for each survivor to close, in terms an operator can act on.

The architecture is blunt and this document does not soften it:

> A host/root operator who can read all online private keys, alter the code before signing,
> impersonate every principal, control the offline root, and control every publication/witness
> channel **can fabricate an internally valid history**. Ed25519 does not solve that.
> — `ARCHITECTURE-0.6.0.md:531-539`

> A local witness configured and stored by the same operator is not an independent external
> witness. — `ARCHITECTURE-0.6.0.md:880` (limitation 11)

---

## 1. Adversary classes

Precision matters here because "operator forgery" collapses six very different adversaries into
one phrase, and 0.6.0 defeats three of them completely.

| Class | Capability | Post-0.6.0 outcome |
|---|---|---|
| **A0** | Remote API caller. No keys, no DB access. | **Defeated.** Was already out of scope; nothing here weakens it. |
| **A1** | Arbitrary write access to the PostgreSQL store. No private keys, no code control. | **Defeated.** This is the audit's threat model and the one 0.6.0 is built for. §2. |
| **A2** | A1 + can read the private keys the application service credential can reach (one Vault path, one principal class). | **Partially defeated.** Can forge as the principals whose keys it reached; cannot forge as others, cannot forge key lifecycle, cannot forge the root. §2.7. |
| **A3** | Host root. All online keys, code before signing, build pipeline. Not the offline root. | **Not defeated for new history.** Detectable in one specific way: it cannot produce root-authorised key lifecycle, so its forgeries either use existing keys (leaving them in the log) or fail to bind. §3, R1/R10. |
| **A4** | A3 + the offline root private key(s). | **Not defeated.** Can mint principals, keys, delegations, checkpoints. Internally valid history. |
| **A5** | A4 + control of the publication channel/account. | **Not defeated, and not detectable by a first-time auditor.** Detectable to an auditor holding a *prior* pin, and only for *changes* after that pin. R3. |
| **A6** | A5 + the co-signer is not independent (same person, or both keys in one custody). | **Not defeated and not detectable at all.** The artifact shows two signatures. R2. |

The defender's one durable asset is an **auditor holding a prior pin**. Every residual below is
ultimately a statement about how much that asset does or does not cover.

---

## 2. What 0.6.0 closes

Against **A1** — database write access, no private keys. Each row names the mechanism and where
it lands, because "closed" should be checkable.

| Attack | Why it fails | Mechanism |
|---|---|---|
| Modify an event's `transition`/`payload`/`timestamp` in the row | Row↔envelope reconciliation is total; any signed-field mismatch is `INVALID` under every policy | S1, `_verification.py:331-345` (`VerificationPolicy`: "There is no field here that can turn a signed-field mismatch into a success"), invariant at `:418-427` |
| Insert a fabricated event | Requires a valid Ed25519 signature by a key with a project-local acceptance preceding it in the chain | `TRUST-DOMAIN.md` §5.10 |
| Delete an event before a published checkpoint | Breaks the committed head/count in the cutover checkpoint or a published trust-log checkpoint | `ARCHITECTURE-0.6.0.md:475-477`; `TRUST-DOMAIN.md` §4.3 |
| Reorder events | Order is hash-linked, not `global_seq`; `global_seq` can never appear in `authenticated_fields` | `_verification.py:428-434` (asserts it) |
| `UPDATE principal_keys` to add a key, un-revoke a key, or change a fingerprint | The table is a projection; no verifier resolves a v6 key from it; the doctor projection check fails | `TRUST-DOMAIN.md` §5.9; conformance test 13 |
| Swap `scheme_id` to `hmac-sha256` to skip verification | `scheme_id` is inside the signed v6 envelope and is derived from trusted key metadata, never the row | S2; `_verification.py:391-392` |
| Mutate `workflow_registry.definition` to change replay | Events bind `workflow.definition_hash` | `ARCHITECTURE-0.6.0.md:79` |
| Replay a signed event into a different project | `project_instance_id` is signed | S9 |
| Insert or mutate witness rows and present them as trust evidence | Witness lifecycle/enrolment is not a 0.6.0 trust mechanism; any retained webhook delivery is non-evidentiary and cannot raise a verification result | `ARCHITECTURE-FINAL.md` §5; `RECONCILIATION.md` FINAL SCOPE |
| Rewrite a bundle's contents | Signed membership statement over an ordered membership root | S4; `ARCHITECTURE-0.6.0.md:198-248` |
| Substitute the bundle's key registry to make forged events verify | The registry is `BUNDLE_EMBEDDED`; `externally_authenticated` is unreachable when any event resolves that way | S5/BC-016; `TRUST-DOMAIN.md` §8.2 |
| Flip `HUMAN_ACCEPTED` → `INDEPENDENT_AND_ACCEPTED` with an `UPDATE` | Assurance reads only signed, content-bound verdicts | S8 `[→ sibling C]` |
| Insert a key registered in another schema to make cross-schema events "verify" | Existence is trust-domain-scoped and signed; authorisation is a signed project acceptance | WI-241; `TRUST-DOMAIN.md` §6.2 |

**What is new in this list relative to pre-0.6.0** is the bottom half. S1 alone made signatures
load-bearing; it did not make key lifecycle, membership, trust roots or review verdicts
checkable. The design review was explicit that S2–S10 all survive a complete S1 fix
(`AUDIT-REPORT.md:176-181`).

### 2.7 The A2 boundary, and why key custody separation is load-bearing

`ARCHITECTURE-0.6.0.md:527` states it in one line and it deserves expansion, because it is the
only place in 0.6.0 where an *operational* control changes the *cryptographic* outcome:

> Key custody must enforce separate Vault policies per principal or principal class. A database
> service credential must not be able to read every private key.

If one credential can read every private key, A2 collapses into A3 and the per-principal
signatures prove nothing beyond "somebody with the service credential signed this". The
separation is what makes `actor.principal_id` mean anything under partial compromise.

**A verifier cannot check this.** It is `custody.declared_backend` /
`custody.declared_policy_ref` in the enrolment payload (`TRUST-DOMAIN.md` §5.5) — a signed claim
about custody, not evidence of custody. That is R8.

---

## 3. What remains

Eleven residuals. Each has: the statement, why it is irreducible *in 0.6.0*, the closing
condition (what would have to be true), the evidence a verifier could check once closed, and an
honest cost. This is the roadmap.

---

### R1 — The "offline root" is a policy claim, not a verifiable property

**Statement.** The genesis document declares `custody.declared_mode` per signer
(`TRUST-DOMAIN.md` §3.2). Nothing in any artifact distinguishes a root key generated on an
air-gapped machine and stored on paper from a root key sitting in the estate's own Vault. A3
therefore may in fact be A4.

**Why irreducible in 0.6.0.** Proving custody requires a hardware attestation the key never left
a device (TPM/HSM/YubiKey attestation certificates), and hardware-token integration is explicitly
excluded from 0.6.0 (`ARCHITECTURE-0.6.0.md:857`).

**Closing condition.** Root keys generated on and non-exportable from an attesting device, with
the device's attestation certificate chained to a manufacturer root, carried in
`signers[].custody.attestation` — the field already reserved in the genesis schema.

**Evidence once closed.** A verifier validates the attestation chain and reports
`custody_verified: true` per signer instead of `custody_declared` only.

**Cost.** Two hardware tokens (~$100), plus attestation-chain validation code. The genesis format
already has the field, so this closes **without a new epoch** (`TRUST-DOMAIN.md` §3.5). Low cost,
real reduction: it moves A3 out of A4.

---

### R2 — Co-signer independence is unverifiable

**Statement.** The owner's decision requires an independent co-signer by default (WI-272), and
`TRUST-DOMAIN.md` §3 makes the *threshold* a monotone state in the signed governance log. A
`solo_effective` estate may upgrade to `co_signed` without changing `trust_domain_id`; lowering the
threshold is rejected. What the log cannot make structural is **independence**. Two distinct public
keys prove two distinct keys. They do not prove two distinct people, two distinct custodies, or two
distinct interests. One person holding both keys produces a document indistinguishable from genuine
co-signing. This is A6.

**Why irreducible in 0.6.0.** There is no protocol-level notion of "a different person". The
nearest approximations — a custodian countersignature from a third party, or an external identity
attestation — are the extension points, not the release.

**Closing condition (in increasing strength).**
1. Each root signer's custody attested to a *different* hardware device (R1) — closes "both keys
   in one file", not "both devices in one drawer".
2. A custodian countersignature over `trust_domain_core_digest` by a party with no operational
   access to the estate — the `countersignatures` array, already in the format
   (`TRUST-DOMAIN.md` §3.5).
3. Threshold signing where one share is held by an organisation with an independent interest.

**Evidence once closed.** `root_governance.independence` moves from the hard-coded
`"unverifiable"` (`TRUST-DOMAIN.md` §3.6) to `"attested_by:<custodian>"` with a verifiable
countersignature.

**Cost.** (1) is nearly free once R1 is done. (2) costs a willing third party and a five-minute
ceremony — the format cost is zero because the field exists. (3) is a governance change, not an
engineering one.

**This is the residual the owner's decision most directly targets and least fully closes**, and
saying so is the point of naming it.

---

### R3 — Publication is separated by account, not by control

**Statement.** The channel is a public git repo under a GitHub account distinct from the estate's
operational identity (WI-272), bootstrapped by direct exchange. Both accounts are the same
human's. An operator who wishes to publish a false fingerprint can do so, and can maintain a
consistent false history indefinitely. This is A5.

**What it does buy, exactly.** The owner's reasoning is correct and should not be diluted: the
channel's job is to make **substitution detectable**, and it does that.

- An auditor who recorded fingerprint F and commit C at time T can prove at T+1 that the
  repository still says F and that C is still an ancestor of the head.
- A force-push that removes or rewrites a published checkpoint is detectable to *anyone* holding
  a prior clone, permanently.
- Third-party retention means the operator cannot make an inconvenient prior publication vanish
  from every copy.

**What it does not buy.** It cannot make the *first* fingerprint honest, and an auditor with no
prior observation has no leverage at all. `TRUST-DOMAIN.md` §4.5 requires `regista trust recheck`
to print this.

**Closing condition.** A publication channel the operator cannot rewrite even in principle: a
real transparency log with independent monitors (Sigstore/Rekor, CT-style), or a public
timestamping anchor over the checkpoint digests. Both are explicitly out of 0.6.0
(`ARCHITECTURE-0.6.0.md:852-853`, and §7 deletes anchoring outright).

**Evidence once closed.** `anchors[]` entries on the genesis document and each checkpoint —
again, the field exists and adding it requires **no new epoch**.

**Cost.** Rekor is free and the integration is small; the honest blocker is that anchoring
verification must be done properly or not at all, which is exactly why S7's implementation is
being deleted rather than patched (`ARCHITECTURE-0.6.0.md:654-659`). Doing it right needs real
interoperability tests. **Recommended as the first post-0.6.0 trust item**, because it converts
"detectable to someone who was watching" into "detectable to anyone, later".

---

### R4 — There is no trusted time

**Statement.** Every timestamp in the system is a signed actor claim (`occurred_at`, `signed_at`,
`registered_at`, `revoked_at`). Ordering is established by hash chains, which are relative, not
absolute. An operator can produce a history whose entire timeline is fiction while every signature
verifies.

**Why irreducible in 0.6.0.** All anchoring is deleted (`ARCHITECTURE-0.6.0.md:641-670`): RFC 3161
returns positive verdicts without a trust anchor (`_timestamping.py:487-495`), the batch tree
commits to `uuid.bytes` and therefore witnesses no content (`_timestamping.py:84-129`), and the
OpenTimestamps provider cannot execute against the pinned library (`_anchoring.py:355-437`). The
correct action is removal, not repair. Nothing replaces it in this release.

**Partial mitigation that does exist.** Git commit timestamps in the publication repo are set by
GitHub, not the operator, for the *server-side* record. This is weak evidence — force-pushable,
not signed by GitHub in any form the tooling verifies — and must not be presented as anchoring. It
is worth recording the observed commit sha and observation time in the trust policy
(`TRUST-DOMAIN.md` §4.6 `publication.observed_at`) precisely so that a *later* contradiction is
visible.

**Closing condition.** One anchoring provider meeting the four bars the architecture sets
(`:663-668`): commitment over chain heads/content hashes, full certificate/path/time validation,
receipts surviving retention independently, and positive status impossible without configured
trust material.

**Evidence once closed.** `anchors[]` on checkpoints; a distinct
`external_time_evidence: valid` verdict dimension, which already exists in the architecture's
verdict model (`:284`) and is permanently `absent` in 0.6.0.

---

### R5 — Pre-cutover history is bindable but not attributable, and may have been fabricated before cutover

**Statement.** 303,820-odd HMAC events exist. HMAC is symmetric: a valid HMAC proves only that a
holder of the shared secret produced it, and the operator is such a holder. The cutover checkpoint
binds the exact legacy bytes, but as `ARCHITECTURE-0.6.0.md:495` states, WI-270's wording must be
tightened from "the history that existed at cutover" to **"the exact history the cutover signer
committed to."** Without an independent observer at cutover, those are not the same claim.

**Why irreducible.** Permanently. Re-signing history is a cryptographic history rewrite, not a
migration, and is forbidden (`AUDIT-REPORT.md:313-317`). This residual never closes for existing
data; it only stops growing.

**Closing condition.** For *new* history: the cutover itself. From the checkpoint onward, every
event is individually attributable to a key with a signed lifecycle. For *existing* history:
nothing. It is a permanent seam and the release notes must say so.

**Evidence.** `event_authentication: legacy_partial` and the checkpoint's
`previous_epoch.scheme_counts` — the size of the seam is published, per project, in a signed
event.

---

### R6 — Retrospective key attestations do not prove enrolment-before-use

**Statement.** `legacy_key_binding_attested` (`TRUST-DOMAIN.md` §6.3) makes the ~12.9k
`agent_provenance` Ed25519 events (WI-241) verifiable by a third party holding only that project's
material. It proves the signatures verify under the named key and records a human's signed
assertion about a registry row in another schema. It does **not** prove the key was registered
before the events were signed, that the source row was not created or altered afterwards, or that
the named actor controlled the key at signing time. `ARCHITECTURE-0.6.0.md:873` (limitation 4)
says exactly this.

**Why irreducible.** `principal_keys` has no signed history — that is S6. There is no ordering
evidence between a `agent_notes` registry row and the `agent_provenance` chain: no shared chain,
no checkpoint, and `global_seq` is per-schema and unsigned. The evidence needed to prove it was
never created.

**Closing condition.** None for the existing corpus. For everything after cutover, signed
enrolment plus project-local acceptance gives enrolment-before-use by chain traversal
(`TRUST-DOMAIN.md` §5.10).

**Enforcement.** `key_binding == "retrospective"` implies `applicability != FULLY_AUTHENTICATED`
as a class invariant, not a policy setting (`TRUST-DOMAIN.md` §8.3). No policy can accept these
as fully authenticated, including a policy written by the operator.

---

### R7 — A locally configured witness is not an independent witness

**Statement.** `ARCHITECTURE-0.6.0.md` limitation 11 remains: a witness configured and stored by
the same operator is not an independent witness. 0.6.0 does not ship signed witness enrolment or
receipt verification as a trust mechanism. If webhook delivery is retained for consumers, it is
transport only; a row, callback or locally stored receipt cannot raise an assurance or trust axis.

**Why irreducible in 0.6.0.** Independence is a property of who runs the witness and where a
receipt is retained, neither of which is established by this release. Positive witness-independence
work and witness federation are cut from the final scope.

**Closing condition, in order of increasing strength.**
1. A later release must retain receipts by the witness *and* make them obtainable by the auditor
   directly from it.
2. A witness running on infrastructure the estate operator does not administer.
3. A witness operated by a party with an independent interest, publishing its own signed
   checkpoint feed.

**Evidence once closed.** A later release may move `witness_independence` off
`"not_established"` only after the independent acquisition conditions are implemented and tested.

**Consequence for 0.6.0.** No witness operation produces a positive independence or trust-root
claim. The false `spec.md` wording about an anchored `principal_keys` registry is corrected, and
the future signed lifecycle remains only under the explicit CUT marker in `TRUST-DOMAIN.md` §7.

---

### R8 — Custody separation is a claim a verifier cannot check

**Statement.** §2.7's per-principal Vault policy separation is what keeps A2 from collapsing into
A3, and it is invisible to every artifact. An estate with one Vault policy granting the service
credential read on `regista/keys/*` produces artifacts byte-identical to a properly separated
estate.

**Why irreducible in 0.6.0.** Proving it requires the key never being readable by the signer's
own process — HSM-backed signing, or a signing service with its own authorisation boundary. Both
are beyond the release.

**Closing condition.** Signing performed by a service that holds the key and authenticates the
caller per principal, so a compromised application credential yields *signing* for one principal
rather than *possession* of every key.

**Evidence once closed.** `custody.declared_backend` becomes checkable at least to the extent of
a signing-service receipt naming the authenticated caller.

**Interim, and worth doing at cutover because it is nearly free.** `regista doctor` in production
posture asserts that the configured secret backend is not `file` and that the number of Vault
paths readable by the application credential equals the number of principals it is expected to
sign for. That is an *operational* check with no cryptographic force, and it must be reported as
such — but it catches the accident, which is the common case.

---

### R9 — Model-lineage and actor metadata are assertions

**Statement.** Owner decision WI-272 Q3, strict: 0.6.0 claims only **principal-signed
model-lineage assertion**. A principal can sign a truthful claim to be `claude-opus` or an
untruthful one, and 0.6.0 cannot tell them apart. A signature proves *who asserted*, never *what
generated the action*. `independently_reviewed` is **policy evidence, not cryptographic proof of
independence**.

**Why irreducible.** Regista sees a signed payload. There is no harness attestation in the loop.

**Closing condition.** Harness-issued lineage attestation: the key enrolment (or a per-session
credential) carries an attestation from the harness/model provider that this key is used by that
model, verifiable to the provider's root.

**Evidence once closed.** `lineage_claim_status` moves from `signed_assertion` to
`attested_by:<issuer>`.

**Naming rule, which applies beyond this residual.** WI-272: *the name must not promise more than
the check performs.* Same defect class as WI-263 (`lineage_verification` reporting `"verified"`
for what is only a scheme property — `_lineage_verification` at `_assurance.py:201`, consumed at
`:368` and `:392`). Apply it to **assurance-level names
as well as field names** — `INDEPENDENTLY_REVIEWED` is itself a name that promises more than the
check performs, and renaming it is in scope for whoever owns S8.

---

### R10 — The signing code is under the operator's control

**Statement.** Signing happens inside a process the operator built, deployed and can modify. A3
can patch the signer to emit a chosen `occurred_at`, a chosen payload, or a chosen chain
predecessor, and every resulting signature is genuine. No verifier can distinguish "the honest
signer signed this" from "a patched signer signed this", because both are the same key over the
same canonical bytes.

**Why irreducible.** This is the general limit of software attestation and it is not specific to
regista.

**Closing condition.** Reproducible builds plus a signed provenance attestation (SLSA-style) for
the regista artifact, and enrolment payloads that name the attested build digest the key is
authorised to be used from.

**Evidence once closed.** A verifier could check "this key's enrolment authorises signing only
from build B", and separately check B's provenance. Weak in isolation (an operator controls the
build too) but meaningful when combined with R1 and R3.

**Cost.** Real. Not recommended for the release after 0.6.0; R3 and R1 buy more per unit effort.

---

### R11 — Recovery rotation is resolved by Resolution 5

**Resolution.** Recovery rotation requires signatures from the **current root threshold**. The
online registrar may prepare and submit the request, but it cannot authorise recovery. Normal
rotation remains dual-authorised by the outgoing key and registrar. Root-key and registrar-key
recovery use the same current-root-threshold rule.

`mode: "recovery"` remains a signed, visible classification (`key_binding: recovery_rotated`) in
verification and bundle reports. Visibility records the exceptional path; it is not a substitute
for the root-threshold prevention rule. This closes the registrar takeover path in 0.6.0 under
`RECONCILIATION.md` Resolution 5.

---

## 4. Residual summary

| ID | Residual | Adversary | Closes with | Cost | Order |
|---|---|---|---|---|---|
| R1 | Offline root unproven | A3→A4 | Hardware attestation in `signers[].custody.attestation` | ~$100 + validation code | **2nd** |
| R2 | Co-signer independence unverifiable | A6 | Custodian countersignature / distinct attested devices | A willing third party | **3rd** |
| R3 | Publication controlled by the operator | A5 | Transparency log or public anchor in `anchors[]` | Small integration, real test cost | **1st** |
| R4 | No trusted time | all | One correct anchoring provider | Interop testing | with R3 |
| R5 | Legacy HMAC events unattributable | all | Never, for existing data | — | permanent |
| R6 | Retrospective bindings ≠ enrolment-before-use | all | Never, for existing data | — | permanent |
| R7 | Witness not independent | A3+ | Externally operated witness | Infrastructure | 4th |
| R8 | Custody separation unverifiable | A2 | Signing service / HSM | Significant | 5th |
| R9 | Lineage is an assertion | all | Harness-issued attestation | Upstream dependency | blocked |
| R10 | Signing code under operator control | A3 | Reproducible builds + provenance | High | last |
| R11 | Recovery rotation escalation | A2 | **Resolved by current root threshold** | landed in 0.6.0 | closed |

R1, R2 and R3 close **without a new epoch** — the genesis and checkpoint formats already carry
`custody.attestation`, `countersignatures[]` and `anchors[]` (`TRUST-DOMAIN.md` §3.5, §4.3). That
is the concrete payoff of the owner's "leave format room ... without requiring a new epoch"
constraint, and it is why the format room is not speculative generality.

R11 is closed by Resolution 5: an online registrar can no longer authorise recovery without the
current root threshold. Its `recovery_rotated` label remains so the exceptional path is visible.

---

## 5. What 0.6.0 may claim

Verbatim-usable. Anything stronger than these sentences is an overclaim.

1. Regista 0.6.0 makes event semantics, identity lifecycle, review verdicts and exported
   membership **cryptographically checkable against externally pinned Ed25519 trust material**,
   while preserving older history under explicitly limited legacy semantics.
2. An attacker with **arbitrary write access to the database and no private keys** cannot modify,
   insert, delete or reorder events, cannot alter key lifecycle, cannot alter workflow definitions
   used by replay, and cannot alter a signed bundle, without detection by a verifier holding
   external trust material.
3. Each post-cutover event is attributable to a **specific enrolled key** whose enrolment,
   rotation and revocation are themselves signed events, and whose authorisation to sign in that
   project precedes its first use **by chain traversal**.
4. The trust root of an estate is an externally published genesis document with a stable
   `trust_domain_id`; current governance is replayed from a monotone signed log and stamped into
   every verification result, bundle and publication. A threshold increase is a signed upgrade;
   a threshold decrease is rejected without changing the domain.
5. Substitution of published trust material is **detectable** to any party holding a prior
   observation of the publication channel.

## 6. What 0.6.0 must not claim

These are `ARCHITECTURE-0.6.0.md:868-882`'s twelve, plus the five limits in
`RECONCILIATION.md` Resolution 6. Release notes must state all of them plainly.

1. Historical HMAC events are **not** independently attributable to individual principals. (R5)
2. The cutover checkpoint binds **the exact legacy bytes the checkpoint signer committed to**; it
   does not prove pre-cutover history was honest when created. (R5)
3. Historical v4/v5 Ed25519 events are individually signature-verifiable but gain project
   placement only through the later checkpoint.
4. Retrospective key attestations do **not** prove contemporaneous enrolment-before-use. (R6)
5. A signed bundle proves what its signer attested, and is externally authenticated **only**
   against auditor-supplied trust material.
6. Without a fresh externally published checkpoint, **tail truncation after the last known
   checkpoint may remain undetectable**.
7. 0.6.0 provides **no trusted timestamp and no public anchoring guarantee**. (R4)
8. Signed actor/model-lineage metadata proves what the signer **asserted**, not what generated the
   action. `independently_reviewed` is policy evidence, not cryptographic proof of independence.
   (R9)
9. Delegation credentials prove authorisation under the configured trust root, not subjective
   human intent.
10. **A host operator controlling all roots, private keys and publication channels can fabricate a
    valid-looking history.** (A4–A6)
11. **A local witness configured and stored by the same operator is not an independent external
    witness.** (R7)
12. `global_seq` remains an unsigned database index and is not cryptographic ordering evidence.
13. A valid legacy HMAC proves knowledge of a shared value that is now disclosed; it does not
    prove origin, creation time, or pre-disclosure existence. (WI-278)
14. The 304,333 `regista-prod-001` events have no store-side principal/key binding. A verifier
    cannot infer one from the operator key file or create one retrospectively. (WI-275)
15. The cutover checkpoint contains the disclosure. It does not remediate it: an externally
    observed head can detect later substitution, but neither that head nor the checkpoint proves
    that earlier HMAC history was honestly produced.
16. Distinct root signatures prove distinct keys, not distinct people or custody; publication
    under a distinct account is address separation, not independent control. Per-principal custody
    separation is likewise a declared property that no artifact evidences. (R2, R8)
17. The producer block is a principal-signed assertion. Matching a published host/harness policy
    makes inconsistency detectable; it is not remote attestation of the process or model. (R9)

---

## 7. Disposition of WI-007

**WI-007 remains open**, narrowed from "no defense against operator forgery" to a specific,
answerable decision set. `ARCHITECTURE-0.6.0.md:550` says it "should remain open as a narrowed
decision item rather than being marked resolved"; this section is that narrowing.

The item's original text asked whether asymmetric signing alone defends against operator forgery.
**Answered: it does not, and it was never going to.** What 0.6.0 delivers is a different and
narrower thing — it moves the boundary from "trust the operator about everything" to "trust the
operator about **root custody, co-signer independence and publication control**, and verify
everything else". Three named trust assumptions instead of one unbounded one is a real result, and
it should be described that way rather than as a defence.

Proposed successor items, so WI-007 stops being a single unfalsifiable question:

| New item | Question | Blocked on |
|---|---|---|
| WI-007a | Adopt a public anchor / transparency log for checkpoint digests? (R3, R4) | Owner priority; anchoring interop tests |
| WI-007b | Hardware-attested root custody? (R1, and it substantially helps R2) | ~$100 and a ceremony |
| WI-007c | Obtain a custodian countersignature over `trust_domain_core_digest`? (R2) | Identifying a willing third party |
| WI-007d | **Move recovery rotation from registrar to root threshold?** (R11) | **Resolved by `RECONCILIATION.md` Resolution 5; no longer open** |
| WI-007e | Externally operated witness, or delete the witness subsystem? (R7) | Depends on 007a |

WI-007 itself becomes the parent decision: *which of R1/R2/R3 does the owner intend to close, and
in which release.* That is answerable. "Defend against operator forgery" is not.

---

## 8. One paragraph for the release notes

> Regista 0.6.0 makes event semantics, identity lifecycle, review verdicts and exported
> membership cryptographically checkable against externally pinned Ed25519 trust material, while
> preserving older history under explicitly limited legacy semantics. It defeats an attacker with
> full write access to the database. It does not yet provide external timestamping or
> transparency-log publication, and it does not protect against an operator who controls every
> private key and every observation channel. The estate's trust root is an externally published
> genesis document with a stable trust-domain identifier, while current governance is replayed from
> a monotone signed log and is visible in every artifact the estate produces — but two signatures prove two keys,
> not two people, and the publication channel makes substitution detectable rather than
> impossible. Those three assumptions — root custody, co-signer independence, publication control
> — are what remains, and they are named individually so they can be closed individually.
