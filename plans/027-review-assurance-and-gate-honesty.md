# Plan 027 — Review assurance: gate honesty under a single model

**Status:** Proposed 2026-07-02
**Author:** Claude (Fable 5), from the 2026-07-02 single-model deployment review
**Strategic role:** The suite deploys **Claude-only at first**, which quietly
weakens the family's central correctness mechanism. The canonical workflow's
`adversarial_pass` step assumes a *cross-lineage* reviewer — a different model that
fails differently from the author. Claude-reviewing-Claude shares failure modes, so
the same gate that means "independently reviewed" in a two-model world means
"self-reviewed" in a one-model world — while the recorded event looks identical.
An attestation that overstates its own assurance is worse than none. This plan
makes the gate **honest about the assurance it actually delivered**: it records the
reviewer's lineage, treats same-lineage review as a *degraded* state that cannot
reach `done` on its own, and ships a **strict deployment profile** where a human
accept is required. It builds directly on per-actor signing (Plan 026) — the
reviewer is already a distinct signed principal, so its lineage is knowable.

## Ground truth at time of writing

- regista ships the **canonical workflow** (`regista.canonical_workflow_yaml()`):
  full lattice + amend, roles `{human, agent, system}`, a **relaxed gate by
  default** (homelab — human accept works but isn't required), built-in dual-mode
  review validators (Plan 023). Both faces register it verbatim.
- The proven review shape (convergence e2e) is: agent files/works/submits →
  **cross-lineage agent reviewer** `adversarial_pass` → human accept. The reviewer
  is a *separate agent principal* — so the workflow already models "who reviewed"
  as distinct from "who authored." That is the seam this plan uses.
- **Nothing records the reviewer's lineage/model**, and nothing distinguishes
  "reviewed by a different model" from "reviewed by the same model." Under the
  relaxed gate, a same-model `adversarial_pass` reaches `done` unaccompanied.
- Plan 026 (per-actor Ed25519) makes each principal — including the reviewer —
  cryptographically identified, so lineage can be an attested property, not a
  guess.

## Principles this plan must hold

- **The record states the assurance it delivered, never more.** A self-reviewed
  item and a cross-lineage-reviewed item must be *distinguishable in the signed
  history*. This is the whole point — an auditor reads the assurance level, they
  don't infer it.
- **Same-lineage review is a valid state, just a weaker one.** We do not forbid
  Claude reviewing Claude (it's better than nothing and it's all there is at
  first). We forbid it from *silently* counting as independent review. Weaker
  assurance requires a compensating control (human accept) to reach `done`.
- **Deterministic gates carry more weight when review is degraded.** The strict
  profile leans on what does *not* share the author's failure modes — the built-in
  validators, and (at the consumer) mypy/tests/lab. The gate policy makes that
  explicit rather than pretending review alone suffices.
- **Structurally ready for the second model, today.** When a second model arrives,
  cross-lineage review must "just work" — no redesign. The reviewer is already a
  principal; this plan only adds lineage *comparison*, so adding a genuinely
  different reviewer lineage flips items from degraded to fully-assured with zero
  schema change.

---

## Phase 1 — Reviewer lineage on the record

### WI-1.1 — Capture reviewer lineage on the review event
- Extend the `adversarial_pass` (and reject) transition to record the reviewing
  principal's **lineage** (model family / identity, sourced from the principal
  registry — Plan 026 — plus the harness-declared model, e.g. cairn's
  `CAIRN_HARNESS_*`). The author's lineage is likewise on the authoring events.
  A pure comparison `same_lineage(author, reviewer)` is derivable from the signed
  record, not asserted out-of-band.
- **AC:** a review event carries the reviewer's lineage; `same_lineage` is computed
  from two signed events, not from config; a fixture with author==reviewer lineage
  and one with distinct lineages classify correctly; mypy --strict clean.

### WI-1.2 — Assurance level as a first-class, derived property
- Define an `AssuranceLevel` closed set — e.g. `SELF_REVIEWED` (same lineage, no
  human accept), `INDEPENDENTLY_REVIEWED` (cross-lineage), `HUMAN_ACCEPTED`,
  `INDEPENDENT_AND_ACCEPTED` — computed deterministically from the item's signed
  events. It is a *view over the history*, stored nowhere mutable, so it can never
  disagree with the record. `assert_never` over the set.
- **AC:** each level computes correctly from fixture histories; the level for a
  same-model-reviewed-then-human-accepted item is `HUMAN_ACCEPTED`, not
  `INDEPENDENTLY_REVIEWED`; the computation is a pure function of the event log.

## Phase 2 — Gate profiles (relaxed stays; strict ships)

### WI-2.1 — The strict deployment gate profile
- A **strict gate profile** (alongside the existing relaxed default) that a
  deployment selects: an item reviewed by the **same lineage** as its author
  **cannot** reach `done` without a human accept; a cross-lineage review can. The
  relaxed profile (homelab) is unchanged. The profile is a registered property of
  the workflow deployment, not per-item, so it can't be dodged item-by-item.
- **AC:** under strict, a same-lineage `adversarial_pass` leaves the item short of
  `done` until a human accept; a cross-lineage pass reaches `done`; under relaxed,
  current behavior holds; the active profile is recorded in the signed history so
  an auditor sees which gate was in force.

### WI-2.2 — Gate decision is itself attributed and signed
- The gate's decision (which profile, why `done` was permitted — "cross-lineage
  review" vs "human accept") is recorded as part of the transition, so the *reason*
  an item reached `done` is auditable, not just the fact.
- **AC:** the `done` transition carries the gate rationale; a strict-profile item
  that reached `done` names whether it did so by independent review or human
  accept; verify surfaces it.

## Phase 3 — Closeout

### WI-3.1 — Migration + docs
- The homelab converged store adopts the strict profile for the regulated
  deployment (its own choice; relaxed stays available for local dev).
  `docs/review-assurance.md`: the assurance levels, the single-model degradation
  and why it matters, the strict profile, and the honest statement that this
  proves *what review happened*, not that the review was *good* — a compensating
  control, not a guarantee of quality.
- **AC:** the doc states the degradation honestly; the strict profile is
  documented as the multi-user/regulated default; consumers (dossier Plan 014,
  agent-notes) reference it.

## Interim: the review story before per-actor signing lands

Per-actor Ed25519 (Plan 026) is on the critical path and depends on
Plan 025's secret-backend resolver and provision command. If those slip,
the review-assurance story must not be blocked with no fallback. The
**interim review posture** (HMAC-only, pre-Plan-026):

1. **Record the reviewer's `actor_id` and harness-declared model on the
   review event** — this is already possible with the current actor field
   and `CAIRN_HARNESS_*` env vars. It is not cryptographically bound (a
   shared HMAC key could forge it), but it is *better than nothing* and
   is the data Plan 027 WI-1.1 will upgrade to a signed property.
2. **Compute `same_lineage` from the recorded actor/model, not from
   signatures.** The comparison is the same; only the *trust* in the
   inputs differs. Flag it as `lineage: asserted` (HMAC-era) vs
   `lineage: verified` (post-Plan-026) so an auditor sees the
   difference.
3. **Embed the trust caveat in the bundle** (the 2026-05-24 roadmap's
   discipline): "actor attribution is HMAC-bound, not per-actor
   signed; the operator can forge the actor field. Per-actor Ed25519
   (Plan 026) closes this gap." This is the same FIM-positioning
   framing provenance Plan 003 §3.5 used for the first demo bundle.
4. **The strict gate can ship on `lineage: asserted`.** The human-accept
   requirement for same-lineage review is a workflow policy, not a
   cryptographic property — it does not need per-actor signing to
   enforce. What it loses without 026 is the *non-repudiation* of the
   reviewer's identity, not the gate itself.

**Upgrade path:** when Plan 026 lands, events signed with per-actor
keys flip `lineage` from `asserted` to `verified` automatically (the
verifier checks the actor↔signer binding). No schema migration, no
re-signing — the chain transitions from asserted to verified
mid-stream, the same way it transitions from HMAC to Ed25519.

## Sequencing & notes

- **Depends on Plan 026** (per-actor signing) — reviewer lineage is only
  trustworthy if the reviewer principal is cryptographically identified. Sequence
  after 026's registry lands.
- **But the interim posture (above) is deployable without 026.** If 026
  slips, ship the strict gate + asserted lineage + the caveat. The
  upgrade is automatic when 026 lands.
- **Consumers surface, don't recompute:** dossier's UI (Plan 014) shows the
  assurance level and gate rationale from this plan; it does not re-derive them.
  agent-notes' `adversarial-review` skill records the reviewer lineage it ran under.
- **This is the honest answer to "one model weakens review":** we can't
  manufacture a second lineage, but we can refuse to let the record *pretend* there
  was one, and we can require a human when there wasn't. When the second model
  arrives, items simply start reaching `INDEPENDENTLY_REVIEWED` on their own — the
  ceiling this plan installs is exactly the thing that lifts.
