# regista 0.6.0 — legacy / cutover classification policy (FROZEN CONTRACT)

**Status:** Stage 0 contract. Frozen before implementation, per `ARCHITECTURE-0.6.0.md`
§ SEQUENCING / "Stage 0", item 7 ("Legacy/cutover classification policy").
**Not a code change.**

**Relationship to `CUTOVER-POLICY.md`.** That document is the S1 policy for a store
with **one** epoch. This document extends it to the two-epoch model and, in §8, **corrects four
of its rules** that the 0.6.0 architecture invalidates. Everything in it not listed in §8
remains in force — in particular §2 (a mismatch in a genuinely signed field), §2.2 (never
silently accept; never routinely re-sign), §4 (missing envelopes), and §5 (the InMemory
backend).

**Companions.** `V6-ENVELOPE.md` (the v6 contract, companion deliverable),
`FIELD-MATRIX.md` (what v1–v5 sign), `RESULT-MODEL.md` (the result shape
this extends in §7).

**Code baseline — every `file:line` in this document is against `origin/main` @ `334b995`**
("fix(signing): authenticate the row, not just the envelope (WI-267) (#37)"), the post-S1
keystone. Sources were read with `git show origin/main:<path>`; the shared `rc-build` regista
checkout is on `release/0.5.6`, which **predates the
Phase 1 merges**, so its working-tree files are pre-S1 and must not be used to check these
citations. Verify every code citation with `git show 334b995:<path>`, never against a working
tree. Where `ARCHITECTURE-0.6.0.md` cites pre-S1 line numbers, this document gives the
post-S1 location and says so.

**Owned elsewhere.** Sibling B owns the trust-domain log, `trust_domain_id`, key lifecycle and
`legacy_key_binding_attested`. Sibling C owns bundle v3 and review verdicts. Sibling D owns the
preflight inventory tool. Where this policy depends on their artifacts it names the dependency
and does not design it.

---

## OVERLAY APPLIED — 2026-08-09 (P0.1)

`RECONCILIATION.md` governs this document; each superseded clause carries a **SUPERSEDED** marker
where it sits.

| Clause | Superseded by | Replacement |
|---|---|---|
| §1 — the ground-truth count table | overlay change 12 | §1 — the post-S1 measured snapshot; counts belong to a **named snapshot**, never to a document |
| §2.3/§4.4 — checkpoint transition vs `workflow: null` | Resolution 3, collision 6 | `transition` is a required non-empty string on every v6 event; the checkpoint names `project_cryptographic_epoch_started` |
| §4.2 — checkpoint payload | Resolution 4, collision 7 | §4.2 — the **union schema**: A's measured fields plus B's trust material, one vocabulary |
| §4.2 `governance` | collision 7, WI-280 | `root_governance` with `co_signed \| solo \| solo_effective` |
| §4.2 — the first-event key binding | Resolution 1 | The payload embeds `bootstrap_key_acceptance`; the checkpoint hash is the project's first key-binding anchor |
| §7 — result-model extension | Resolution 2 | `RESULT-MODEL.md` §10 owns `VerificationResultV6` |

---

## 1. The ground truth this is designed against

> **SUPERSEDED — `RECONCILIATION.md` overlay change 12.** The table below is the
> architecture-era measurement and is **stale**. The measured post-S1 snapshot
> (`preflight-live.json`, read-only against the live estate on `origin/main`) is:
>
> | Fact | Value |
> |---|---|
> | Events, estate-wide | **353,985** |
> | `scheme_id = hmac-sha256` | **304,333** |
> | `scheme_id = ed25519` | **49,652** |
> | Envelope v5 / v4 | **335,290 / 18,695** (zero v1–v3) |
> | `agent_provenance` | **349,066** events |
> | Row↔envelope mismatches, missing envelopes, unknown schemas | **0**; chains clean |
> | Rows in `event_segments` / `anchor_receipts` / `tsp_batches` / `witness_registrations` / `witness_receipts` | **0** |
> | Projects able to cut over today | **0 of 26** — no project signs with a locally-bound Ed25519 key |
> | Events resolvable only from the operator key file (`regista-prod-001`) | **304,333 (86%)**, with **zero** `principal_keys` rows anywhere (WI-275) |
>
> Two rules follow, and they are why the stale table is marked rather than silently rewritten:
>
> 1. **Counts belong to a named snapshot and to the locked ceremony transaction** — never to
>    source code, a document, or a frozen payload. The S1-era snapshot is `preflight-s1.json`
>    (351,371 events at 2026-08-08 19:20); the post-S1 one is `preflight-live.json`. Cite the
>    snapshot, always.
> 2. **The store moved ~500 events *during* measurement.** Rehearsal and ceremony therefore
>    require **quiesced writers**; a byte-comparison against a moving store is not a comparison.
>
> §1's four consequences below remain correct — none of them depends on the exact figures.

> **HISTORICAL SNAPSHOT — `preflight-s1.json` / `preflight-s1.txt`.** The following table is
> retained as the S1-era measurement only. It is not a 0.6.0 ceremony input; use a named,
> quiesced preflight snapshot and re-measure inside the cutover transaction.

Measured, not assumed. Not re-derived here.

| Fact | Value | Source |
|---|---|---|
| Events, estate-wide | **352,509** | brief / architecture-era measurement |
| `scheme_id = hmac-sha256` | **303,820** (86.2%) | same |
| `scheme_id = ed25519` | **48,689** (13.8%) | same |
| Envelope v5 | **94.7%** | same |
| Envelope v4 | **5.3%** | same |
| Envelope v1 / v2 / v3 | **0** | same |
| Row↔envelope mismatches in signed fields | **0** | same, and `preflight-s1.json` (26 schemas, all `mismatch_field_counts` empty) |
| `event_segments` rows | **0**, estate-wide | `CUTOVER-POLICY.md` §7; `ARCHITECTURE-0.6.0.md` §8 |
| `anchor_receipts` rows | **0**, estate-wide | same |
| Project schemas | **26** | `preflight-s1.txt` |
| `agent_provenance` | 346,476 events; already **mixed** HMAC + Ed25519 | `preflight-s1.txt`; `ARCHITECTURE-0.6.0.md` §4 |

Four consequences drive the whole design:

1. **Mixed-scheme verification is not hypothetical.** `agent_provenance` — 98% of the estate by
   volume — already contains both HMAC and Ed25519 events on one project chain. Any design that
   treats the legacy region as "an HMAC prefix" is wrong before it ships
   (`ARCHITECTURE-0.6.0.md` §4, "Do not describe the legacy region simply as an 'HMAC prefix.'").
   The per-event classification in §3 is therefore per **event**, never per project or per range.
2. **There is nothing to repair.** Zero mismatches means `CUTOVER-POLICY.md` §1 step 3
   ("remediate or quarantine") is a no-op for this estate. The classification below is about
   labelling honestly, not about fixing damage.
3. **Segments and anchors are irrelevant to the cutover.** Zero rows of each, and both
   subsystems are deleted in 0.6.0 (`ARCHITECTURE-0.6.0.md` §7, §8). The re-signing cascade in
   `CUTOVER-POLICY.md` §2.2 loses its seal/witness/anchor rows and keeps its event rows — which
   is where the prohibition's force actually came from anyway (§8.2).
4. **The preflight has a shelf life.** The S1 measurement recorded 351,371 events at
   2026-08-08 19:20 (`preflight-s1.txt`, `FIELD-MATRIX` §9); the figure above is
   352,509. The estate is live and appended ~1.1k events between measurements. Therefore the
   head, count and per-scheme counts that go into a checkpoint payload MUST be re-measured
   **inside the cutover transaction**, under the locks, and compared to the approved preflight —
   which is exactly `ARCHITECTURE-0.6.0.md` §8 steps 1–3. A preflight number is an expectation
   to confirm, never a value to copy into a signed artifact.

**Unresolved count discrepancies to settle in preflight, not now.**
`ARCHITECTURE-0.6.0.md` §3 says "48,688 historical Ed25519 signatures" while Stage 6 says
"all 48,689 historical Ed25519 signatures resolve", and the brief gives 48,689. Separately,
`FIELD-MATRIX` §9 labels its 351,371/351,371 signature-valid line "(HMAC-SHA256, real key
material)", which cannot be literally true if 48,689 events are Ed25519 — most likely the label
is imprecise and the resolver used each key's own scheme (`KeySetResolver`,
`_verification.py:712-732`, takes the scheme from `KeyEntry.scheme`). Both are sibling D's to
resolve; neither changes any rule below.

---

## 2. The epoch model

### 2.1 Two epochs, one chain

A project's event chain is continuous across the cutover. What changes at the cutover is which
rules apply to events appended **after** it.

```
  genesis ──► … legacy events (v4/v5, HMAC and/or Ed25519) … ──► legacy head
                                                                     │
                                             chain.previous_project_event_hash
                                                                     ▼
                                        ┌──────────────────────────────────────┐
                                        │  CUTOVER CHECKPOINT                  │
                                        │  v6, Ed25519, entity.kind="project"  │
                                        │  transition =                        │
                                        │  project_cryptographic_epoch_started │
                                        └──────────────────────────────────────┘
                                                                     │
                                                                     ▼
                                          … v6 Ed25519 events only, forever …
```

### 2.2 Epoch membership is a chain position, not a timestamp and not a `global_seq`

An event is **post-cutover** iff its position in the project chain — obtained by walking
`prev_global_event_hash` / `chain.previous_project_event_hash` from genesis — is strictly after
the checkpoint's. It is **pre-cutover** iff strictly before. It is the checkpoint iff it is the
checkpoint.

This is a strict improvement on the S1 watermark, which used `global_seq`
(`CUTOVER-POLICY.md` §3, implemented at `_verification.py:1563-1580`). `global_seq` is unsigned
by design and was backfilled by a `(timestamp, event_id)` proxy for pre-017 rows
(`017_events_global_seq.sql:8-14`), so an attacker with row-write access could move an event
across the watermark. A chain position cannot be moved without breaking a hash link.

**Cost of the improvement, stated honestly.** Chain position is not available to a verifier that
holds one event in isolation. Rules:

- A verifier that has walked the chain supplies `chain_ordinal` and `checkpoint_ordinal`, and
  the result carries `epoch_position ∈ {pre_cutover, is_cutover, post_cutover}`.
- A verifier that has not must report `epoch_position = unknown`, and **must not** report
  `FULLY_AUTHENTICATED` for any envelope version below 6. A legacy envelope of unknown epoch
  position is at best `LEGACY_PARTIAL`, because the one thing that could make it acceptable —
  being genuinely pre-cutover — has not been established.
- `global_seq` may be used as an **index hint** to locate candidate rows, never as the
  determination. `ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 12:
  *"`global_seq` remains an unsigned database index and is not cryptographic ordering evidence."*

### 2.3 The label downgrade nobody should be surprised by

> **HISTORICAL S1 STATE.** Under the pre-cutover S1 policy,
> `full_authentication_versions = {V5}` (`_verification.py:350-352`), so 94.7% of the named
> S1-era estate reported `FULLY_AUTHENTICATED`. This is not the post-cutover 0.6.0 result model.

**After a project cuts over, that changes for that project's pre-cutover events.** v5 does not
sign project identity, trust domain, scheme, key binding, workflow definition or authorization.
Once v6 exists in the same store, calling a v5 event "fully authenticated" means two different
things depending on which store you are looking at, which is precisely the naming failure the
owner ruled against: *"the name must not promise more than the check performs"*
(`ARCHITECTURE-0.6.0.md` § OWNER DECISIONS, item 3).

**Ruling.** At cutover, per project:

```
full_authentication_versions : {V5}          ->  {V6}
accept_legacy_versions       : {V4}          ->  {V4, V5}
```

Every pre-cutover event therefore reports `LEGACY_PARTIAL` at best, with a non-empty
`unbound_properties` set (§7.2). Roughly **334k events change label without any change to their
cryptography.** This will look like a regression in any dashboard that counts
`fully_authenticated`, and release notes must say so before someone reports it as a bug. The
events are exactly as sound as they were; the label got honest.

---

## 3. The states, and what each is verifiable *for*

Applied per event. `applicability` values are `RESULT-MODEL.md` §5's.

### 3.1 State table

| # | State | Envelope | Scheme | Position | `applicability` (post-cutover store) | Verifiable for |
|---|---|---|---|---|---|---|
| L1 | legacy Ed25519, v5 | v5 | ed25519 | pre-cutover | `LEGACY_PARTIAL` | Individual signature attribution to the holder of one private key; every field v5 signs (FIELD-MATRIX §1); chain links; membership in the legacy region via the checkpoint |
| L2 | legacy Ed25519, v4 | v4 | ed25519 | pre-cutover | `LEGACY_PARTIAL` | As L1 **minus** `actor_kind` / `actor_metadata`, which v4 does not sign |
| L3 | legacy HMAC, v5 | v5 | hmac-sha256 | pre-cutover | `LEGACY_PARTIAL` | Integrity of the signed bytes **to a holder of the shared secret**; every field v5 signs; chain links. **Not** individual attribution |
| L4 | legacy HMAC, v4 | v4 | hmac-sha256 | pre-cutover | `LEGACY_PARTIAL` | As L3 minus `actor_kind` / `actor_metadata` |
| L5 | legacy, no stored envelope | — | — | pre-cutover | `UNVERIFIABLE` | Nothing. Pre-002 evidentiary gap (`CUTOVER-POLICY.md` §4). **Measured 0 estate-wide** |
| L6 | legacy, unparseable / unknown schema | — | — | pre-cutover | `INVALID` | Nothing. The bytes exist and match no schema (`RESULT-MODEL.md` §3 rule 3). Measured 0 |
| L7 | keyless dummy (InMemory only) | — | — | n/a | `UNVERIFIABLE`, reason `UNSIGNED_EVENT` | Nothing. Never signed (`_verification.py:1073-1087`, `:1236-1252`). A **Postgres** row with this byte pattern is `INVALID`, not exempt |
| C | the cutover checkpoint | v6 | ed25519 | *is* the cutover | `FULLY_AUTHENTICATED` | Everything v6 binds, **plus** the legacy binding claim of §4 |
| V6 | post-cutover event | v6 | ed25519 | post-cutover | `FULLY_AUTHENTICATED` | Everything v6 binds (`V6-ENVELOPE.md` §3): signer, scheme, project, trust domain, key binding, workflow definition, authorization, both chain links |
| X1 | **epoch violation** — envelope < 6 after the checkpoint | v1–v5 | any | post-cutover | `INVALID`, reason `EPOCH_VIOLATION` | Nothing. A legacy envelope after the cutover is a regression, not history (§5) |
| X2 | **epoch violation** — v6 with a non-Ed25519 scheme, production posture | v6 | hmac-sha256 | post-cutover | `INVALID`, reason `EPOCH_VIOLATION` | Nothing (§5.2) |
| X3 | pre-cutover event whose position cannot be established | any < 6 | any | unknown | `LEGACY_PARTIAL` at best, never `FULLY_AUTHENTICATED` | §2.2 |

**Before a project has cut over**, states L1–L4 keep the S1 mapping: v5 → `FULLY_AUTHENTICATED`,
v4 → `LEGACY_PARTIAL` (`_verification.py:1556-1580`). The change in §2.3 is triggered by the
checkpoint's existence, not by the release.

### 3.2 What HMAC events are not — cannot-claim item 1

> **Historical HMAC events are not independently attributable to individual principals.**
> (`ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 1.)

An HMAC-SHA256 signature proves that *someone holding the shared secret* produced these bytes
(`_signing_scheme.py:98-123`). Verification requires the same secret, so a verifier who can
check the signature could also have produced it. Consequences that must appear in the result,
not only in prose:

- The result carries `attribution = shared_secret` for every HMAC event. Never `individual`.
- `actor_id` / `actor.principal_id` on an HMAC event is a **signed claim by the secret holder**,
  not proof that the named principal acted. It is inside the signed bytes and cannot have been
  changed after the fact by a database-only attacker — that much is real — but it identifies no
  one to a party outside the secret holder's control.
- 303,820 events (86.2% of the estate) are in this class permanently. **No amount of 0.6.0 work
  changes it**, and historical re-signing is explicitly out of scope
  (`ARCHITECTURE-0.6.0.md` § "Work that should not enter 0.6.0") — and would in any case be a
  cryptographic history rewrite, which `CUTOVER-POLICY.md` §2.2 forbids for reasons that remain
  correct.
- The review gate and assurance must not treat an HMAC event's actor as an authenticated
  identity. Post-S1 the result already carries enough to enforce this
  (`RESULT-MODEL.md` §7.6); with `attribution` it becomes checkable rather than inferable from
  `scheme_id`.

### 3.3 What legacy Ed25519 events are — cannot-claim item 3

> **Historical v4/v5 Ed25519 events are individually signature-verifiable but gain project
> placement only through the later checkpoint.** (item 3.)

The 48,689 Ed25519 events are genuinely stronger than the HMAC population: an auditor with the
public key can verify them without being able to produce them. `attribution = individual`.

But v4/v5 sign no project identity (`AUDIT-REPORT.md` §2, S9 — none of the five builders emits
one, `_signing.py:15-194`). So a valid legacy Ed25519 signature says "this principal signed
these bytes", not "this principal signed these bytes **into this project**". The same event,
byte for byte, verifies identically if it is replayed into a different project's store. What
places it in *this* project is:

1. its chain links, which bind it to the events before and after it; **and**
2. the cutover checkpoint, which binds that whole chain — head, count, genesis — into the new
   epoch under an Ed25519 key that resolves through the externally pinned trust domain (§4).

There is a further limit specific to these events: their key registration evidence may live in
another schema (WI-241 — the `agent_provenance` Ed25519 events registered in `agent_notes`).
The remedy is sibling B's retrospective `legacy_key_binding_attested` event, and it is
explicitly **not** proof of contemporaneous enrollment-before-use
(`ARCHITECTURE-0.6.0.md` § cannot-claim item 4). So the honest reading of a legacy Ed25519
event is: *individually signature-verifiable; project placement checkpoint-derived; key
chronology retrospectively attested.*

### 3.4 What `global_seq` is not — cannot-claim item 12

> **`global_seq` remains an unsigned database index and is not cryptographic ordering
> evidence.** (item 12.)

Restated here because it is the rule most likely to be quietly violated by a reporting tool:

- Not in any envelope version (FIELD-MATRIX §3.1; measured 0 of 351,371 envelopes carry it).
- Assigned post-signing (`_events.py:257-294`; `spec.md:677-679`).
- Backfilled by a `(timestamp, event_id)` proxy for pre-017 rows
  (`017_events_global_seq.sql:8-14`), so the backfilled order is not append order.
- Never in `authenticated_fields`, enforced as a class invariant
  (`_verification.py:430-434`).
- May appear in a checkpoint or membership statement only as an **informational maximum**
  (`ARCHITECTURE-0.6.0.md` §1, §4: *"`max_global_seq` is informational"*).

A verifier may sort by it for display. It may never conclude order, completeness, or epoch
membership from it.

---

## 4. The cutover checkpoint

### 4.1 What it is

The first post-migration event in each project: a v6 Ed25519 event on a project-system entity
(`entity.kind = "project"`, `V6-ENVELOPE.md` DD-7) with
`transition = "project_cryptographic_epoch_started"`, `workflow = null`, `entity_seq = 1`,
`chain.previous_entity_event_hash = null`, and
`chain.previous_project_event_hash = <the legacy head>`.

Its `previous_project_event_hash` is the one legacy-domain link in the whole v6 corpus
(`V6-ENVELOPE.md` §6.6); the payload must state the construction (D-2 there, and §4.2 here).

### 4.2 Payload

`ARCHITECTURE-0.6.0.md` §4's payload, plus the three fields this document adds (§10, D-1/D-2/D-3):

```json
{
  "type": "regista.project-cutover",
  "version": 1,
  "previous_epoch": {
    "allowed_envelope_versions": [4, 5],
    "event_count": 12345,
    "genesis_event_hash": "sha256:...",
    "head_event_hash": "sha256:...",
    "head_hash_construction": "sha256(canonical_envelope||signature)",
    "max_global_seq": 12997,
    "scheme_counts": { "ed25519": 345, "hmac-sha256": 12000 },
    "envelope_version_counts": { "4": 700, "5": 11645 }
  },
  "new_epoch": {
    "envelope_version": 6,
    "production_signing_scheme": "ed25519",
    "project_instance_id": "uuid",
    "trust_domain_id": "uuid",
    "trust_domain_core_digest": "sha256:...",
    "genesis_document_digest": "sha256:...",
    "trust_log_checkpoint": {
      "checkpoint_seq": 12,
      "head_event_hash": "sha256:...",
      "document_digest": "sha256:..."
    },
    "root_governance": { "mode": "co_signed", "threshold": 2, "signer_count": 2 },
    "bootstrap_key_acceptance": { }
  }
}
```

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4 / collision 7, and Resolution 1.** The payload
> above is the **union schema**: this document's measured fields plus `TRUST-DOMAIN.md`'s trust
> material, in **one** vocabulary. Five changes against the frozen text:
>
> 1. **`type` and `version` are explicit** — `regista.project-cutover`, version 1.
> 2. **`trust_log_checkpoint_hash` becomes the three-field `trust_log_checkpoint` object**
>    (`checkpoint_seq`, `head_event_hash`, `document_digest`), and `trust_domain_core_digest` and
>    `genesis_document_digest` join it. A single hash could not tell a verifier *which*
>    checkpoint, nor let it reach the pinned genesis.
> 3. **`governance` → `root_governance`**, with wire values `co_signed | solo | solo_effective`.
>    B's hyphenated spellings and C's `single_signer_lab` are retired.
> 4. **`bootstrap_key_acceptance` is added and is mandatory** — the exact object at
>    `RECONCILIATION.md` Resolution 1 (`principal_id`, `key_id`, `scheme_id`, `public_key`,
>    `fingerprint`, `trust_event_hash`, `trust_log_checkpoint`, `scopes`). This is what makes the
>    checkpoint the project's **first key-binding anchor** and dissolves the bootstrap
>    circularity: the checkpoint's own `signing.key_binding_event_hash` is `null`, authorised
>    externally, and every later event references the checkpoint's hash or a subsequent
>    acceptance.
> 5. **Count maps are sorted by key and each sums to `event_count`**, and their values are
>    **measured under the cutover transaction** — never copied from preflight. `max_global_seq`
>    stays informational.
>
> **`entity.id` of the checkpoint is exactly `project_instance_id`.** An empty project uses
> `project_initialized` — not a fiction that it had a legacy epoch: previous count maps are
> empty and all previous hashes, including `previous_project_event_hash`, are `null`.

Field rules:

| Field | Rule |
|---|---|
| `allowed_envelope_versions` | The exact set observed, sorted ascending. For this estate: `[4,5]`. Not a policy wish — a measurement. |
| `event_count` | Count of events on the project chain at cutover, measured **inside the transaction** (§1, consequence 4). |
| `genesis_event_hash` | Hash of the project's first event, in `head_hash_construction`. `null` iff `event_count == 0`. |
| `head_event_hash` | Hash of the legacy head, same construction. `null` iff `event_count == 0`. Must equal the checkpoint's own `chain.previous_project_event_hash`. |
| `head_hash_construction` | **Added by this document.** Sole permitted 0.6.0 value: `"sha256(canonical_envelope||signature)"`. Without it a verifier must infer which hash domain the head is in. |
| `max_global_seq` | Informational only (§3.4). |
| `scheme_counts` | Per-scheme counts over the legacy region, measured in the transaction. Must sum to `event_count`. |
| `envelope_version_counts` | **Added by this document.** Same shape, keyed by envelope version. Needed to verify `allowed_envelope_versions` is exhaustive rather than asserted; must also sum to `event_count`. |
| `production_signing_scheme` | `"ed25519"`. |
| `project_instance_id` | Must equal the checkpoint envelope's own `project_instance_id`. |
| `trust_log_checkpoint` | The three-field trust-domain checkpoint object (`checkpoint_seq`, `head_event_hash`, `document_digest`) the cutover signer observed. Referent owned by sibling B. |
| `root_governance` | **Added by this document; renamed by the overlay.** Records the trust domain's **replayed current** signer set, threshold and mode **in the artifact**, per the owner's binding constraint that solo mode be *visible in the artifact, not merely in configuration*. `mode ∈ {"co_signed","solo","solo_effective"}` — see `TRUST-DOMAIN.md` §3.3/§3.4 (WI-280: governance is a monotone signed log, not part of the `trust_domain_id` derivation). |
| `bootstrap_key_acceptance` | **Added by the overlay (Resolution 1).** The exact acceptance object that authorises the checkpoint's own signer. Mandatory. Its `scopes` must include `may_accept_keys` and `may_sign_checkpoints`. |
| `trust_domain_core_digest`, `genesis_document_digest`, `trust_log_checkpoint` | **Added by the overlay (collision 7).** Together they let a verifier walk from the checkpoint to an externally pinned genesis without holding the trust log. |

**An empty project** (`event_count == 0`) has `genesis_event_hash = null`,
`head_event_hash = null`, `max_global_seq = null`, empty count maps, and the checkpoint's
`chain.previous_project_event_hash = null` — the checkpoint is then the project's genesis.

### 4.3 What a valid checkpoint lets a verifier conclude

Given: the checkpoint verifies under a key that resolves through an **externally pinned** trust
domain; the auditor holds the legacy events; the auditor has walked the whole legacy chain and
arrived at exactly `head_event_hash` with exactly `event_count` events starting at
`genesis_event_hash`.

**MAY conclude:**

1. The presented legacy bytes are **the exact bytes the cutover signer committed to**, and have
   not changed since. Any post-cutover modification, insertion, deletion or reordering anywhere
   in the legacy region breaks a chain link, the count, or the head.
2. The legacy region belongs to this `project_instance_id` and this `trust_domain_id` — because
   the checkpoint says so and the checkpoint is bound to the legacy head.
3. The scheme and version composition of the legacy region is as stated, if the recomputed
   counts match `scheme_counts` and `envelope_version_counts`.
4. Individual legacy **Ed25519** events additionally carry individual attribution (§3.3).
5. The estate's current root governance mode, from `root_governance` (§4.2) — the state replayed
   from the signed trust-domain governance log, visibly (`solo`, `co_signed` or `solo_effective`).

**MAY NOT conclude:**

1. That pre-cutover history was **honest when created**. The checkpoint binds bytes, not truth.
   `ARCHITECTURE-0.6.0.md` § cannot-claim item 2, with the WI-270 wording tightened from
   "the history that existed at cutover" to **"the exact history the cutover signer committed
   to"** — without an independent observer at cutover those are not the same claim, and an
   operator who fabricated history *before* signing the checkpoint produces an identical
   artifact.
2. **Who** produced any HMAC event (§3.2).
3. That any timestamp reflects real time. `occurred_at` and legacy `timestamp` are signed actor
   claims; 0.6.0 provides no trusted timestamp (cannot-claim item 7).
4. That each HMAC actor attribution is independently authentic (`ARCHITECTURE-0.6.0.md` §4,
   "What the checkpoint proves").
5. That the legacy Ed25519 keys were enrolled before use (cannot-claim item 4).
6. That the chain has not been **truncated at the tail after the checkpoint**. The checkpoint
   binds everything before it; nothing in the store binds what should come after it. Only an
   externally published, later checkpoint detects tail truncation (cannot-claim item 6). See
   §5.4.
7. Anything at all, if the checkpoint's key resolves only through material carried in the same
   artifact being verified. That is `trust_root = bundled_only`, and it is circular (S5). The
   verdict is `legacy_checkpoint_bound` at best, never `externally_authenticated`
   (`ARCHITECTURE-0.6.0.md` §2, verdict model — sibling C's).

### 4.4 Uniqueness and well-formedness

A checkpoint is structurally invalid unless all hold:

1. **At most one** `project_cryptographic_epoch_started` event exists for a given
   `project_instance_id`. Two is not "the later one wins"; it is `INVALID` for the project. (An
   attacker holding the epoch key could otherwise sign a second checkpoint naming a different
   legacy head, and present whichever history suits them.)
2. It is the **first** v6 event: no v6 event has a chain position before it.
3. `chain.previous_project_event_hash == previous_epoch.head_event_hash`.
4. `chain.previous_entity_event_hash == null` and `entity_seq == 1`.
5. `workflow == null` and `transition == "project_cryptographic_epoch_started"`.
   > **CONFIRMED against the overlay — `RECONCILIATION.md` Resolution 3 / collision 6.** This
   > rule was the *correct* half of a direct contradiction with `V6-ENVELOPE.md`'s frozen
   > "`workflow` null ⇒ `transition` null". The overlay resolves it in this document's favour:
   > workflow **evaluation** and lifecycle **transition naming** are separate concerns, and
   > `transition` is a required non-empty string on **every** v6 event. `V6-ENVELOPE.md` §1.6 has
   > been amended accordingly. Nothing changes here; it is recorded so nobody re-opens it.
6. `payload.new_epoch.project_instance_id == envelope.project_instance_id`.
7. The signing key resolves through the externally pinned trust domain, and
   `signing.key_binding_event_hash` **is `null`** — the checkpoint is one of exactly three
   positions where that is legal.

   > **SUPERSEDED (and D-4 discharged) — `RECONCILIATION.md` Resolution 1, Bootstraps A and B.**
   > The bootstrap is specified, and it is not "sibling B's to specify" any more. For the
   > checkpoint:
   >
   > - `signing.key_binding_event_hash = null` (`V6-ENVELOPE.md` §1.4). A null anywhere outside
   >   the three permitted transitions is `INVALID` / `KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`.
   > - The authorisation comes from the payload's `bootstrap_key_acceptance` (§4.2), which must
   >   resolve **through the pinned genesis and a verified trust-log checkpoint**, and the event
   >   signer must be **exactly** that accepted key.
   > - The checkpoint's own event hash becomes the project's first key-binding anchor. The next
   >   event — including the first standalone `principal_key_accepted` — references it.
   >
   > A verifier that cannot reach the pinned genesis reports `key_binding: bootstrap_external`
   > **only** with `trust_root: externally_pinned` and `checkpoint_binding: externally_pinned`
   > (`RESULT-MODEL.md` §10.2 invariant 5); otherwise the checkpoint is not authenticated, and a
   > checkpoint that is not authenticated binds nothing.

---

## 5. The one-way rule

> **No new v4/v5 or HMAC event may follow a signed v6 cutover checkpoint.**
> (`ARCHITECTURE-0.6.0.md` §1.)

### 5.1 Write-time enforcement

After the checkpoint commits, in that project:

- `append` **rejects** any envelope below v6.
- `append` **rejects** HMAC signing.
- The doctor fails production posture if any active writer lacks Ed25519 custody.
- HMAC signing survives **only** under an explicit test/development posture, and never in a
  project that has a checkpoint.
- HMAC **verification** remains permanently available — 303,820 events depend on it.

**The authority is the signed checkpoint, not a posture row.** `ARCHITECTURE-0.6.0.md` §4:
*"verifier treats either condition as structural invalidity, regardless of mutable policy
rows"*, and §8: *"The signed event, not the mutable posture row, tells future verifiers where
strict v6 rules begin."* Concretely:

- The append path determines "has this project cut over?" by reading and **verifying** the
  checkpoint event, under the same global append lock it already takes
  (`_lock_global_chain_head`, `_events.py:65-99`, `SELECT … FOR UPDATE`). Taking the same lock
  removes the TOCTOU window against a concurrent cutover.
- A projection may cache the answer for speed; a cache miss must fall back to the signed event,
  and a cache that disagrees with the signed event is a defect, not an override.

### 5.2 Scheme enforcement is separate from version enforcement

X1 (envelope < 6) and X2 (v6 with a non-Ed25519 scheme) are distinct violations with distinct
reasons, because they have different diagnoses: X1 means an old binary or an old code path is
still writing; X2 means Ed25519 custody failed and something fell back. Collapsing them into one
"epoch violation" string costs the operator the one piece of information that decides what to do
next.

Both are `INVALID` with reason `EPOCH_VIOLATION`, distinguished by `detail`.

### 5.3 Offline verification of the rule

An auditor with a complete store or a `complete-store`-scoped bundle v3:

```
1. Walk the project chain from genesis by hash links.
   (Never by global_seq — §2.2, §3.4.)
2. Locate the unique project_cryptographic_epoch_started event; require §4.4.
3. Require every event at a chain position < checkpoint  to classify as v4 or v5.
   A v6 event before the checkpoint is INVALID.
4. Require every event at a chain position > checkpoint  to classify as v6
   AND to have signing.scheme_id == "ed25519".
   Any other value is INVALID / EPOCH_VIOLATION.
5. Require the recomputed legacy count, genesis and head to equal the
   checkpoint payload's.
6. Require the recomputed scheme_counts and envelope_version_counts to equal
   the payload's, and each to sum to event_count.
```

Step 6 is what makes `allowed_envelope_versions` a checked statement rather than an assertion,
and it is why §4.2 adds `envelope_version_counts`.

**The walk must cover the complete logical stream.** If any events were moved to
`events_archive`, they must be consolidated back before cutover without changing envelope,
signature, event hash or chain values (`ARCHITECTURE-0.6.0.md` §8; WI-259 for export). A chain
walk over the live table alone, in a store with archived rows, will report a chain hole that is
an artifact of the read, not of the data.

### 5.4 What enforcement cannot detect

An attacker who holds the epoch signing key **and** database write access can delete the
checkpoint together with every v6 event after it, leaving a store that looks like a project
which never cut over. Nothing inside the store detects this: the legacy chain is intact and
self-consistent, and the absence of a checkpoint is indistinguishable from never having had one.

The only defence is external: the estate cutover catalog, containing all 26 checkpoint hashes,
published through the independent channel (`ARCHITECTURE-0.6.0.md` §8 and § OWNER DECISIONS
item 2 — a dedicated public git repository under an account distinct from the estate's
operational identity). An auditor who holds the catalog notices a missing checkpoint
immediately.

This is cannot-claim item 6 in its most operationally relevant form, and it is the reason the
owner's *"publication must be one command emitting canonical JSON"* constraint is a security
requirement rather than an ergonomics preference: **an unpublished checkpoint is worth nothing**
against this attack.

---

## 6. Per-project, not per-estate

There is no atomic cutover across 26 schemas (`ARCHITECTURE-0.6.0.md` §8). The operational unit
is one signed checkpoint per project, followed by one externally published estate catalog
containing all 26 checkpoint hashes.

Consequences for classification:

- Projects are in **different epochs at the same time**, legitimately, for the duration of the
  ceremony. A verifier must resolve epoch policy per `project_instance_id`, never estate-wide.
- A cross-project consumer (the review gate reading `agent_provenance` while `agent_notes` has
  cut over, say) will see mixed applicability. That is correct, and every consumer must accept a
  `VerificationResult` rather than a boolean (`ARCHITECTURE-0.6.0.md` § Stage 1).
- The estate catalog is the only artifact that says the ceremony finished. A partial catalog is
  a partial ceremony and must be visible as such.
- **The InMemory backend has no checkpoint and is permanently in the legacy epoch** unless one
  is explicitly created. Keyless events stay `UNVERIFIABLE` / `UNSIGNED_EVENT`
  (`CUTOVER-POLICY.md` §5.2, implemented `_verification.py:1073-1087`, `:1236-1252`). The
  epoch rules must not make in-memory tests fail as `EPOCH_VIOLATION`.

---

## 7. Result-model extension

> **SUPERSEDED (ownership) — `RECONCILIATION.md` Resolution 2.** `RESULT-MODEL.md` §10 owns
> `VerificationResultV6` and is normative; D-5 is discharged. The additions below remain the
> *minimum this policy needs* and are the rationale index for the epoch-related fields
> (`epoch_position`, `checkpoint_binding`, `attribution`, `unbound_properties`, and
> `EPOCH_VIOLATION`). Implement from `RESULT-MODEL.md` §10.

`RESULT-MODEL.md` is frozen for the single-epoch world. These additions are the minimum this
policy needs.

### 7.1 New enum members

```python
class EnvelopeVersion(StrEnum):
    ...
    V6 = "v6"

class EpochPosition(StrEnum):
    PRE_CUTOVER  = "pre_cutover"
    IS_CUTOVER   = "is_cutover"
    POST_CUTOVER = "post_cutover"
    NO_CUTOVER   = "no_cutover"    # this project has not cut over
    UNKNOWN      = "unknown"       # chain position not established — §2.2

class Attribution(StrEnum):
    INDIVIDUAL    = "individual"     # asymmetric signature, key resolves to one principal
    SHARED_SECRET = "shared_secret"  # HMAC — §3.2
    NONE          = "none"           # unsigned / unverifiable

class CheckpointBinding(StrEnum):
    EXTERNALLY_PINNED = "externally_pinned"  # checkpoint key chains to pinned trust material
    CHECKPOINT_BOUND  = "checkpoint_bound"   # valid checkpoint, root not externally pinned
    UNBOUND           = "unbound"            # no checkpoint covers this event

class FailureReason(StrEnum):
    ...
    EPOCH_VIOLATION = "epoch_violation"
```

### 7.2 New `VerificationResult` fields

| Field | Type | Meaning |
|---|---|---|
| `epoch_position` | `EpochPosition` | §2.2 |
| `attribution` | `Attribution` | §3.2 |
| `checkpoint_binding` | `CheckpointBinding` | §4.3 |
| `unbound_properties` | `frozenset[str]` | Properties v6 binds that **this** envelope version does not: e.g. `{project_instance_id, trust_domain_id, scheme_id, key_binding, workflow_definition, authorization}` for v5. Distinct from `unsigned_fields`, which names **row columns** — mixing the two would silently change the meaning of a shipped field and of the invariant at `_verification.py:439-443`. |

`unsigned_fields` keeps its exact current meaning and its invariant. For v6, `scheme_id` leaves
it (`V6-ENVELOPE.md` §3.1); `global_seq` never does.

### 7.3 New `VerificationPolicy` fields

| Field | Type | Meaning |
|---|---|---|
| `pinned_project_instance_id` | `UUID \| None` | `None` means project binding cannot be checked; the result must **report** that, not skip it |
| `pinned_trust_domain_id` | `UUID \| None` | as above |
| `cutover_checkpoint_event_hash` | `str \| None` | The checkpoint the verifier expects, ideally from the externally published catalog. `None` = discover from the chain and report `checkpoint_binding = checkpoint_bound` at best |
| `full_authentication_versions` | (existing) | `{V5}` before cutover, `{V6}` after (§2.3) |
| `accept_legacy_versions` | (existing) | `{V4}` before cutover, `{V4, V5}` after (§2.3) |
| `accept_legacy_before_global_seq` | (existing) | **Deprecated at cutover.** Retained only for projects with no checkpoint. Superseded by chain position (§2.2, §8.3) |

**The class invariant is unchanged and extends:** there is no policy field that turns a
signed-field mismatch into a pass, and there is none that turns an `EPOCH_VIOLATION` into a
pass either (`_verification.py:418-443`; `RESULT-MODEL.md` §6, mechanism 6).

### 7.4 Exit codes

`RESULT-MODEL.md` §6 mechanism 5's scheme is unchanged — `0` all fully authenticated, `2` at least one
legacy, `1` at least one invalid, `3` at least one unverifiable, worst wins. `EPOCH_VIOLATION`
maps to `INVALID` and therefore exit `1`.

Note the consequence of §2.3: a post-cutover store scanning its own legacy region will exit `2`,
not `0`, forever. That is correct — the store *does* contain events whose properties are
partial — and CI expectations must be set accordingly rather than by relaxing the classification.

---

## 8. Corrections to `CUTOVER-POLICY.md`

Four rules there are invalidated by the 0.6.0 architecture. Everything else stands.

### 8.1 §2.1(b) — the anchor-receipt dating advice is inapplicable

`CUTOVER-POLICY.md` §2.1(b) advises bounding *when* a divergence happened by using
`anchor_receipts.submitted_at` + `target_global_seq`. There are **zero `anchor_receipts` rows
estate-wide**, and 0.6.0 deletes the anchoring subsystem outright
(`ARCHITECTURE-0.6.0.md` §7). The advice was never actionable here and becomes permanently
unactionable.

**Replacement.** Bound the divergence with:

1. the signed cutover checkpoint — any event on the project chain at or before the checkpoint
   had its envelope, signature and chain hash fixed at the checkpoint's commit;
2. the externally published estate catalog, which fixes the checkpoint's own hash at
   publication time;
3. failing both, ordinary backup timestamps, with the honest caveat that the event log cannot
   date its own divergence.

### 8.2 §2.2 — the re-signing cascade loses three rows and keeps its force

The cascade table lists segment seals, witness receipts and anchor receipts among what a
re-sign would invalidate. Segments and anchors are deleted with zero rows to preserve; witness
enrollment is being rebuilt as signed events (WI-264, sibling B). Those three rows become moot.

**The prohibition is unchanged**, because its force came from the event rows: a re-sign changes
`canonical_envelope`, `signature`, `payload_canonical_hash`, the event's head hash, the
successor's `prev_event_hash`, every subsequent event in the entity chain, and the global chain
from that point forward. All of those remain exactly true post-S1
(`_events.py:227-228`, `:318-322`; `V6-ENVELOPE.md` §5.3).

**And the cutover makes it worse in a new way.** After a checkpoint is published, re-signing any
pre-cutover event changes the legacy head, so the published checkpoint no longer matches the
store — and a third party cannot distinguish a well-intentioned repair from the attack. This is
the property the estate did *not* have before (zero anchors meant no external commitment
existed). **The window in which a re-sign was merely expensive closes at the first published
catalog.** `ARCHITECTURE-0.6.0.md` § SEQUENCING / Rollback puts the same rule in operational
terms: after publication, no rollback — repair forward with another signed event.

### 8.3 §3 — the `global_seq` watermark is superseded for cut-over projects

`CUTOVER-POLICY.md` §3 defines the cutover as an envelope-version floor plus a `global_seq`
watermark `W`, and is explicit that `W` is administrative, not cryptographic. That remains a
correct S1 design and remains in force **for projects that have not cut over**.

For a project with a checkpoint:

| `CUTOVER-POLICY.md` §3 | 0.6.0 replacement |
|---|---|
| floor `= v5` | floor `= v6` for post-cutover positions; `v4` remains the legacy floor for pre-cutover positions |
| watermark `W` = `max(global_seq)+1` | the checkpoint's **chain position** (§2.2) |
| `accept_legacy_versions = {v4}` | `{v4, v5}` (§2.3) |
| bound is administrative | bound is **cryptographic** — it cannot be moved without breaking a hash link |
| set once per project, never moved forward | the checkpoint is append-only and unique (§4.4) |

`accept_legacy_before_global_seq` should be marked deprecated in the same release that ships the
checkpoint, not removed — stores that have not cut over still need it.

### 8.4 §7 — the estate snapshot is superseded but not wrong

`CUTOVER-POLICY.md` §7 records 351,371 events; §1 above records 352,509. Both are correct at
their measurement times. The correction is to the **usage**: no number from a preflight run may
be copied into a signed checkpoint payload. It is an expectation to compare against a
measurement taken inside the cutover transaction (§1, consequence 4).

---

## 9. Operator runbook delta

Per project, extending `ARCHITECTURE-0.6.0.md` §8 with the verification points this policy
requires. (The full ceremony, including backup, root publication, key provisioning and the
estate catalog, is Stage 7 there.)

```
 1. Acquire the global append lock and a project cutover advisory lock.
 2. Re-run strict verification INSIDE the transaction.
      -> require zero INVALID; every UNVERIFIABLE dispositioned in advance
 3. Consolidate any events_archive rows into the single logical stream first;
    halt on divergent duplicates.                     (ARCHITECTURE §8)
 4. Walk the project chain by hash links; record:
      genesis_event_hash, head_event_hash, event_count,
      scheme_counts, envelope_version_counts, max_global_seq
 5. Compare all six against the approved preflight result.
      -> any difference: ABORT. Do not "update the expectation".        (§1.4)
 6. Build the checkpoint payload from the values measured at step 4,
    never from the preflight file.
 7. Append project_cryptographic_epoch_started as the first v6 Ed25519 event.
 8. Set the runtime projection to v6/Ed25519-only.       (cache, not authority §5.1)
 9. Commit.
10. Re-read the checkpoint FROM STORAGE and verify it, including §4.4 (1)-(7).
11. Attempt one v5/HMAC append and require it to be rejected.  <- proves §5.1
12. Emit the checkpoint's event_hash for the estate catalog.
```

Steps 5, 10 and 11 are additions this document makes to the architecture's sequence; step 11 in
particular is the only step that tests the one-way rule as *deployed* rather than as *intended*.

Rollback stays exactly as `ARCHITECTURE-0.6.0.md` § SEQUENCING / Rollback specifies. Restated
because it is the part that must not be improvised at 2 a.m.: before any checkpoint commits,
roll back freely; after a checkpoint commits but before publication and before any subsequent
write, restore the complete backup **only** if the checkpoint is explicitly abandoned and never
published; after publication or any post-cutover event, **no rollback to 0.5.x** — keep the
service read-only and repair forward with another signed event. Never delete the checkpoint,
never rewrite history, never resume HMAC signing.

---

## 10. Divergences from `ARCHITECTURE-0.6.0.md`

**D-1 — the checkpoint payload needs `envelope_version_counts`.** §4.2. Without it,
`allowed_envelope_versions` is an assertion by the cutover signer that a verifier cannot check
against the events it holds. With it, step 6 of §5.3 makes it a checked statement. Cheap to
add, impossible to add later without a payload version bump.

**D-2 — the checkpoint payload needs `head_hash_construction`.** §4.2, and
`V6-ENVELOPE.md` §6.6 / D-2. The checkpoint carries a legacy-domain hash in a v6 field; the
architecture does not say so, and a verifier that infers the construction has reintroduced
domain confusion.

**D-3 — RESOLVED: the checkpoint payload carries `root_governance`.** §4.2. The field is the
current signer set, threshold and mode replayed from the signed trust-domain governance log. It is
visible in the artifact without making governance part of `trust_domain_id`; the monotone log and
the sole trust policy determine whether the restatement is valid.

**D-4 — RESOLVED: the checkpoint uses Bootstrap A/B.** §4.4(7). The checkpoint's
`signing.key_binding_event_hash` is `null` as the unique first project event, and its mandatory
`bootstrap_key_acceptance` is externally authorised through the pinned genesis and verified
trust-log checkpoint. The checkpoint's own event hash becomes the first project-local key-binding
anchor; the next event references it. There is no self-referential acceptance and no unresolved
registrar or sibling ownership gap.

**D-5 — "the first post-migration event in each project" is ambiguous for empty projects.**
`ARCHITECTURE-0.6.0.md` §4. Four of the 26 schemas have ≤ 5 events and at least conceptually a
project can have zero. §4.2 specifies the empty case (all-null hashes, empty count maps,
checkpoint is genesis); the architecture does not.

**D-6 — `agent_provenance` is 98% of the estate, and the architecture's per-project ceremony
treats all 26 projects as comparable units.** Steps 2 and 4 of §9 walk and strictly verify
346,476 events under a global append lock. The other 25 projects together are ~6,000 events.
Whatever the ceremony's per-project time budget is, it is dominated by one project, and a
read-only pre-verification pass immediately before taking the lock (so that the in-transaction
pass re-verifies a known-clean store) is likely necessary. This is an operational divergence,
not a schema one, but it belongs to whoever sequences Stage 7.

**D-7 — the architecture's cannot-claim list is release-notes prose; three of the items need to
be machine-readable.** Items 1, 3 and 12 are per-event properties an automated consumer must
branch on, not sentences in a changelog. §7.2's `attribution`, `epoch_position` and
`checkpoint_binding` fields are this document's answer. Without them, every consumer
re-implements the distinction — which is the failure mode `RESULT-MODEL.md` §1 catalogues nine
instances of.

---

## 11. What I am least confident about

**LC-1 — the label downgrade in §2.3.** I am confident it is *correct*: after v6 exists,
calling a v5 event "fully authenticated" promises project, scheme, key-binding and workflow
binding that v5 does not perform. I am less confident it is *operationally survivable* without
an intermediate step. 334k events change label at cutover, and if any gate, dashboard or CI job
keys on `fully_authenticated`, they all break at once, in the release where the store is also
being migrated. An alternative — keep v5 as `FULLY_AUTHENTICATED` for pre-cutover positions and
carry the shortfall only in `unbound_properties` — is weaker but staged. I have specified the
strict version because the owner's naming rule points that way; the owner should confirm it
knowing the blast radius.

**LC-2 — whether chain-position determination is affordable on every verification path.**
§2.2 requires a chain walk to establish epoch position, and `agent_provenance` has 346k events.
The online append path only needs "does a checkpoint exist" (cheap). Replay already walks the
chain. But a single-event API call (`verify_event_signature`, `_api_meta.py`) cannot walk, so it
must return `epoch_position = unknown` and never `FULLY_AUTHENTICATED` for a legacy envelope.
That is the honest answer and it also makes that API strictly less useful than it looks today,
which callers will notice.

**LC-3 — the checkpoint-key bootstrap (D-4).** I have argued option (b) is the only coherent
one, but I do not own the key-lifecycle schema and cannot freeze it. If sibling B chooses
differently, §4.4(7) changes and this policy must follow.

**LC-4 — whether `attribution` belongs on the result or is derivable.** It is derivable
(`is_asymmetric` on the resolved scheme, `_signing_scheme.py:90-95`). I put it on the result
because WI-263's whole finding was that deriving a trust claim from a scheme property and naming
it `"verified"` is a lie (`_assurance.py:201-219`). Making it an explicit field with an explicit
name is the corrective; making it derivable-but-unnamed is how the original defect happened. I
am confident about the direction and not about the field count — the result dataclass is
becoming large, and a large result object is its own maintenance hazard.

**LC-5 — the 48,688 / 48,689 discrepancy and the `FIELD-MATRIX` §9 HMAC label (§1).** I flagged
both rather than reconciling them, because reconciling them requires querying the estate store,
which is sibling D's job and outside my read-only remit. If the second turns out to be a real
defect in the preflight tool — i.e. it verified Ed25519 events against HMAC key material and
reported success — that would be a significant finding about the measurement, not about the
estate. I think it is a labelling imprecision. I have not proved it.
