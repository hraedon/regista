# Plan 022 — Entity generalization + crypto-agility: the one envelope cycle (v4)

**Status:** Proposed 2026-06-22. Foundational. Companion to dossier Plan 006
(convergence-on-regista); referenced by agent-provenance and the dossier knowledge
seam. Not started.
**Owner:** regista
**Enables:** dossier Plan 006 §5 (knowledge entity), agent-provenance non-work-item
attestation, cross-entity references, post-quantum migration without a future
envelope bump.
**Spec touched:** §17 (signing envelope + signing scheme), §13/§16 (core model,
links), §18 (projection invariants), the §3 isolation tenet (carefully — see §5).
**Related:** Plan 011 (pluggable signing — Ed25519 already landed), Plan 015
(trust-envelope), BC-196/216/217 (asymmetric / per-principal keys), Plan 013
(witness co-signing), Plan 019 (transparency-log anchoring).

---

## 1. Motivation — bump the envelope *once*

Several pending capabilities each want to change the **signed envelope** or the
**core event schema**. Done piecemeal, each is a version bump with its own replay-
compatibility burden and migration — the exact tax Plan 015 avoided by batching six
BCs into one envelope move. This plan bundles every envelope-/schema-touching
decision into a single **v3 → v4** cycle so the core is disturbed once, coherently.

The criterion for inclusion is strict: **does it change what is in the signed
envelope or the core event schema?** If yes, it is in this plan. If no (new workflow
features, custom fields, comments, attachments, saved views, notifications), it is
*additive* and explicitly **out** — cheap to add later, no reason to batch.

Three decisions meet the criterion: **entity generalization** (§3), **crypto-
agility incl. PQC-readiness** (§4), and **cross-project references** (§5).

## 2. Envelope v4 at a glance

Current v3 canonical JSON (RFC 8785 JCS):
`{event_id, work_item_id, actor_id, key_id, event_seq, workflow_name,
workflow_version, timestamp, on_behalf_of, transition, payload, prev_event_hash?,
global_seq?}`

v4 changes, all in one bump:

- `work_item_id` → **`entity_kind` + `entity_id`** (§3).
- add **`hash_alg`** (identifies the chain/canonical-hash algorithm; §4.2).
- `key_id` stays; the **scheme/alg** it resolves to is registry-driven, not a closed
  set (§4.1); hybrid/PQC schemes need no envelope shape change (§4.3).
- `prev_event_hash` semantics unchanged except the algorithm is now *named* by
  `hash_alg` rather than implied SHA-256.

Replay classifies v4→v3→v2→v1. Pre-v4 events verify under their existing envelope;
no re-signing of history.

## 3. Decision 1 — Entity generalization (work-item is one kind among many)

**Problem:** every event binds to a `work_item_id` under a workflow. The knowledge
entity (dossier Plan 006 §5), agent-provenance events with *no active work item*,
and future kinds cannot exist without manufacturing junk work-items.

**Change:** events bind to an **entity** identified by `(entity_kind, entity_id)`.
`work_item` becomes the first kind; `note` (knowledge) and `session`/`agent-run`
(provenance) are added incrementally *after* the shape lands.

- **Schema:** add `entity_kind TEXT NOT NULL DEFAULT 'work_item'`; treat the existing
  `work_item_id` as `entity_id` (add `entity_id`, backfill `= work_item_id`, keep
  `work_item_id` as a generated/compat column through a deprecation window). Indexes,
  the escalation-idempotency partial index, and link indexes generalize to
  `(entity_kind, entity_id)`.
- **Lock target generalizes** (§17): from the `work_items_current` row to the
  entity's canonical row. Per-entity hash chain replaces per-work-item; `event_seq`
  is per-entity. Pagination cursor generalizes to `(entity_kind, entity_id)`.
- **Workflow is a property of a *kind*, not the core.** `work_item` has a state
  machine; `note` has none (created/edited/superseded events, no transitions);
  `session` is append-only attestation. The validator/transition machinery applies
  only to kinds that declare a workflow.
- **Forward-compatible, build incrementally.** This plan lands the *shape* (envelope
  v4 + schema + lock/chain/pagination generalization) and `work_item` parity. New
  kinds are then additive and need **no** further envelope bump — which is the entire
  point of doing it now.

## 4. Decision 2 — Crypto-agility and post-quantum readiness

Goal: nothing in v4 should make adopting a post-quantum signature (or a stronger
hash) require *another* envelope bump or a schema migration. regista is already
partly agile (pluggable `SigningScheme`, `scheme_id` per event, `KeyEntry.alg`,
variable-length `BYTEA` for `signature`/`public_key`/`prev_event_hash`). This plan
removes the remaining hardcoded blockers and adopts asymmetric keys operationally.

### 4.1 Open the scheme set (registry-driven, no allowlist)
`_keys.py` hardcodes `scheme not in ("hmac-sha256", "ed25519")` and branches on
`alg == "HMAC-SHA256"`. Replace the closed allowlist with **resolution against the
`SigningScheme` registry**: a key is valid iff its declared scheme is registered.
Adding `ml-dsa-65` (Dilithium) or `slh-dsa-128s` (SPHINCS+) later is then a registry
entry + optional dependency, touching no envelope and no schema.

### 4.2 Hash-algorithm agility
The chain hash and `payload_canonical_hash` are hardcoded SHA-256 (and key
fingerprints use sha256). SHA-256 is post-quantum-acceptable (~128-bit vs Grover),
but agility must not require a future bump. Add **`hash_alg` to the v4 envelope** and
to the chain computation (`prev_event_hash = hash_alg(prev_canonical_envelope ∥
prev_signature)`), defaulting to `sha-256`, so moving to `sha-384`/`sha3-256` later
is a config change classified at verification time, not a new envelope version.

### 4.3 Hybrid / large signatures — no schema change needed
PQC signatures are large (Dilithium ~2.4 KB, SPHINCS+ 8–50 KB) and PQC transitions
favor **hybrid** (classical + PQC, secure if either holds). Two properties keep this
free:
- **Size:** `signature BYTEA` is already uncapped. **Forbid** any fixed-width
  signature column, any index on raw signature bytes, and any inlining of signatures
  where size is constrained. (Audit item for v4.)
- **Hybrid:** model a hybrid scheme as a single registered `SigningScheme` (e.g.
  `hybrid-ed25519-mldsa65`) whose signature is a structured composite the scheme
  verifies, stored in the one `signature BYTEA`. No multi-column, no envelope change.
  (Witness co-signing, Plan 013, remains the *separate* mechanism for independent
  third-party signatures; hybrid is about the *primary* signer's own agility.)

### 4.4 Adopt asymmetric keys operationally (BC-216/217)
Ed25519 exists but HMAC-SHA256 is still the default. For dossier's regulated-
provenance thesis and agent-provenance's independent-verifiability, land
**per-principal key resolution**: each principal (human, agent) signs with its own
key; `key_id`→principal binding is verifiable; revocation via `revoked_at`. HMAC
stays the zero-config default; asymmetric is the path for deployments that need
verify-without-the-secret. This is adoption, not new crypto.

## 5. Decision 3 — Cross-project references *without* breaking isolation

regista's core tenet (§3) is **no cross-project state**: each project is its own
Postgres schema; today cross-project links are rejected (`LINK_CROSS_PROJECT`). The
team-agentic-dev vision needs an entity in project A to reference one in project B
(dossier work-item ↔ a shared knowledge note; a breadcrumb ↔ an upstream issue).
Resolve the tension by making references **value-references, not enforced links**:

- A cross-project reference is a **local, signed assertion**: `{target_project,
  target_entity_kind, target_entity_id, content_hash?}` recorded as a typed link
  event in the *referring* project. It is a reference *by value*, like a URL or a
  foreign key you don't enforce — **no cross-schema FK, join, or transaction.**
- **Resolution and freshness are the referrer's concern** (optionally pinned by
  `content_hash` for tamper-evidence of *what was referenced*). This is exactly how
  witness/anchor records already reach outside a project without sharing state.
- The **isolation tenet is preserved**: no global state, no cross-schema coupling,
  the federated UI still renders each project independently and resolves references
  as links, not joins.

This also subsumes the **typed/attributed link model** for the Confluence backlink:
links are typed (`references`, `blocks`, `duplicates`, …), every link create/remove
is a signed event on the source entity, and the same record shape carries an
optional `target_project` for the cross-project case (absent ⇒ intra-project).

## 6. What v4 bundles vs. what stays out

**In (this cycle, because it touches the envelope/core schema):** entity
`(kind,id)`; `hash_alg`; registry-driven scheme resolution; hash-alg agility; hybrid-
ready signature storage rules; per-principal key adoption; typed links with optional
cross-project value-reference.

**Out (additive — add anytime, no batching value):** concrete new entity kinds
beyond `work_item` parity (note/session land *after* the shape); concrete PQC scheme
implementations (register when a vetted library is chosen); federation UI;
attachments; custom-field expansions; comments; notifications/webhooks beyond the
existing witness/anchor hooks.

## 7. Backward compatibility

- **Replay** classifies envelope v4→v3→v2→v1; historical events verify unchanged.
- **Backfill** `entity_kind='work_item'`, `entity_id=work_item_id` for existing rows;
  keep `work_item_id` readable through a deprecation window.
- **`hash_alg` defaults to `sha-256`** so pre-v4 chains validate identically.
- **No re-signing of history.** New invariants apply to v4-and-later events.

## 8. Phasing (each independently landable, all within one envelope version)

1. **v4 envelope shape + schema generalization** (entity `(kind,id)`, `hash_alg`,
   lock/chain/pagination), `work_item` parity, replay v4→…→v1, full backfill. No new
   kinds yet — proves the generalization is behavior-preserving.
2. **Crypto-agility hardening:** registry-driven scheme resolution (kill the
   allowlist), hash-alg agility wiring, the size/index audit, hybrid-scheme seam.
3. **Per-principal asymmetric adoption** (BC-216/217): key→principal resolution,
   revocation, dossier/agent-provenance opt-in. HMAC remains default.
4. **Typed links + cross-project value-references** (§5), with `content_hash` pinning.
5. *(Downstream, additive, not this plan):* `note` and `session`/`agent-run` kinds
   registered by dossier Plan 006 §5 and agent-provenance respectively.

## 9. Open questions / risks

- **Migration scale.** `work_item_id` is pervasive (indexes, escalation idempotency,
  partial indexes, archive table). The generalization is mechanical but wide; stage
  it behind the compat column and verify projection equivalence before dropping
  `work_item_id`.
- **Isolation-tenet review.** §5 reframes references as value-references to *preserve*
  isolation, but it is a real softening of "no cross-project state" — wants an
  explicit adversarial review against the spec's §3 thesis before P4.
- **Hybrid-scheme complexity.** A composite `SigningScheme` is clean in principle but
  the verifier must enforce *both* legs by default (secure-if-either is a *liveness*
  posture, not a *security* one) — pin the policy when the first PQC scheme is chosen.
- **Hash-chain migration of *existing* chains.** `hash_alg` agility covers *new*
  events; rolling an existing chain to a stronger hash is a separate, later operation
  (re-anchor, not re-sign) — out of scope here, but the `hash_alg` field is what makes
  it possible without a future envelope bump.
- **PQC library choice.** Deliberately deferred (§6) — register a scheme only against
  a vetted implementation (liboqs/`ml-dsa` once stable); the design must not assume
  one before then.
