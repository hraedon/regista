# Plan 023 — Built-in review-gate validators + dual-mode accept policy

**Status:** Proposed 2026-06-28. Foundational unblocker for the convergence.
Companion to dossier Plan 007 / agent-notes Plan 010. Not started.
**Author:** Opus 4.8
**Strategic role:** Move the canonical review-gate validators
(`adversarial_review`, `human_gate`) out of dossier and into regista as
**registerable built-ins**, and parameterize the human-accept requirement into a
**dual-mode gate policy** (strict / relaxed). This is the single foundation gap
on the convergence critical path: until both faces (dossier + agent-notes) can
register the *same* gate from *one* implementation, agent-notes cannot adopt the
canonical workflow without either duplicating provenance-critical logic (drift)
or registering a workflow with no gate (a self-review hole).

---

## 1. Problem

The canonical v3 workflow's two-stage gate is implemented **only in dossier**
(`dossier/src/dossier/validators.py`): `adversarial_review` (cross-lineage +
separation-of-duties + `review_note`, with the `same_lineage_acknowledged`
escape hatch) on the `in_review` exits, and `human_gate` (a human accepter
distinct from every adversarial-pass identity, delegation-aware) on the
`in_human_review` exits.

agent-notes is a separate repo and a deliberately *thin* regista face; it cannot
import dossier without violating that boundary. Three options were weighed in
agent-notes Plan 010 §3:

- **(A) Promote to regista built-ins — chosen.** One implementation, both faces
  register/consume it, zero drift, the gate enforces identically wherever the
  transition runs.
- (B) Vendor copies into agent-notes — rejected (provenance-critical logic
  duplicated across faces is exactly the drift risk the stack exists to kill).
- (C) Register the lifecycle without the validators — rejected (lets agent-notes
  self-review; a provenance hole).

This plan executes (A).

## 2. The dual-mode gate (decided 2026-06-28)

The human-in-the-loop requirement is now a **policy**, not a hardcoded rule. One
invariant holds in **both** modes; only the second stage toggles.

**Invariant G (both modes):** no work-item reaches `done` without at least one
**cross-lineage adversarial review pass** by an actor whose `model_lineage` is
distinct from every author of the work, who is not an author, and who left a
`review_note`. This is the integrity-bearing guarantee and is never relaxed.

| Mode | Stage 1 (`adversarial_review`) | Stage 2 (`human_gate`) |
|---|---|---|
| **strict** (workplace posture) | required, cross-lineage, distinct reviewer | a **human** accepter, distinct from every adversarial-pass identity (delegation-aware) |
| **relaxed** (homelab default) | required, cross-lineage, distinct reviewer | accept permitted by **any** actor (incl. a non-human, incl. the author); the cross-lineage pass *is* the gate |

So in relaxed mode an agent may file → another-lineage agent (or a human)
reviews → the work closes, with no human bottleneck per item, while the
mixed-chain integrity guarantee (Invariant G) still holds. Strict mode is the
same code path with the human requirement switched on.

**Default:** `relaxed`, set per registered workflow. The homelab deployment runs
relaxed; a workplace deployment registers the workflow with `strict`.

## 3. Design

### 3.1 Where the policy lives

The mode is a property of the **registered workflow**, read by the built-in
validator at transition time — not a global server setting (one regista instance
may host both a strict and a relaxed project). Concretely, the `human_gate`
built-in resolves `require_human` from the workflow definition's validator
binding (e.g. a `params: {require_human: true}` on the transition's validator
annotation, or a top-level workflow policy field the validator reads via
`ValidatorContext`). The exact carrier is an implementation choice; the contract
is: **the validator is parameterized, the parameter is per-workflow, and it
defaults to relaxed.**

### 3.2 Validator built-ins

- `adversarial_review(ctx)` — **mode-independent.** Port dossier's logic verbatim
  (separation of duties, cross-lineage check over `model_lineage`,
  `review_note` requirement, `same_lineage_acknowledged` acknowledged-escape).
  This is Invariant G's enforcement.
- `human_gate(ctx, *, require_human: bool)` — **mode-dependent.** When
  `require_human` is true: the accepter must be a human (per the actor's
  principal type) and distinct from every adversarial-pass identity
  (delegation-aware, all cycles — preserve dossier's
  `_adversarial_pass_identities` traversal). When false: the accepter may be any
  actor distinct from… *(decision §6.1)*; the stage's job is only to confirm a
  valid Stage-1 pass exists and record the accept event.

Both must be **registerable by name** through regista's existing validator
registration path (the same mechanism dossier uses today at runtime), so a
workflow YAML can reference `adversarial_review` / `human_gate` as built-ins
without the consumer providing an implementation.

### 3.3 Delegation awareness

Keep dossier's delegation traversal (`derive_authors`,
`_adversarial_pass_identities`) — Plan 021 already put `on_behalf_of` on
`ValidatorContext`, so the regista-native versions consume it directly rather
than re-deriving from event metadata.

## 4. Work items

- **WI-1 — Port validators into regista.** New module (e.g.
  `src/regista/_review_validators.py`): `adversarial_review`, `human_gate`,
  and the helpers (`derive_authors`, `_check_separation_of_duties`,
  `_require_review_note`, `_adversarial_pass_identities`, `_event_lineage`).
  Port dossier's tests alongside (they are the behavioral contract).
- **WI-2 — Parameterize `human_gate` (dual-mode).** Add the `require_human`
  parameter; wire policy resolution from the registered workflow (§3.1). Default
  relaxed. Strict and relaxed each get explicit test coverage.
- **WI-3 — Register as built-ins.** Expose both through regista's validator
  registry so a workflow YAML references them by name; no consumer-supplied impl.
- **WI-4 — dossier consumes from regista.** Delete `dossier/src/dossier/
  validators.py`; dossier registers the regista built-ins instead. dossier's
  79-test suite must stay green (this is the regression oracle that the port is
  behavior-preserving). *Cross-repo: lands in dossier, gated on WI-1..3.*
- **WI-5 — Tests.** Strict mode: human accept required, non-human accept rejected
  at `human_gate`, human distinct from reviewers enforced. Relaxed mode: agent
  accept after a cross-lineage pass reaches `done`; **Invariant G still fails
  closed** when no distinct-lineage review exists (the relaxation must not leak
  into Stage 1). Delegation cycles covered in both.

## 5. Sequencing & non-goals

- **Order:** WI-1 → WI-2 → WI-3 → (WI-4 in dossier) → WI-5. WI-4 is the proof the
  port is faithful; do not declare done until dossier's suite is green against the
  regista-provided validators with its own copy deleted.
- **Unblocks:** agent-notes Plan 010 (which registers the canonical workflow with
  these built-ins) and dossier's strict/relaxed deployment split.
- **Non-goal:** any new gate *semantics* beyond the human/non-human toggle. The
  cross-lineage and separation-of-duties logic ports verbatim; this plan does not
  redesign the gate, only relocates and parameterizes it.

## 6. Decisions to surface

1. **Relaxed-mode accepter constraint.** In relaxed mode, may the accepter be the
   *original author* (self-close after an independent review pass), or must it be
   any actor distinct from the author? The user's framing ("agents closing after
   human or agent review") reads as **self-close permitted once an independent
   cross-lineage review has passed** — i.e. Stage 1 carries the
   separation-of-duties weight and Stage 2 may be the author. Recommend that
   reading; confirm before WI-2.
2. **Policy carrier.** Per-transition validator `params` vs a workflow-level
   policy field. Recommend per-transition `params` (keeps the gate self-describing
   in the workflow YAML, no out-of-band config).

## 7. Cleanup (housekeeping, not blocking)

- Delete the stale `wip/plan-022-p5-entity-kind` branch (−5,690 lines, predates
  main; obsolete since 022 P1 landed) and the merged `feat/plan-019…`,
  `feat/plan-021…`, `feat/global-event-hash-chain` branches once confirmed merged.

## 8. Risks

- **Faithful port.** The cross-lineage / delegation traversal is subtle; WI-4's
  green dossier suite is the non-negotiable oracle. Do not refactor logic during
  the move — port first, simplify later under its own change.
- **Policy leak into Stage 1.** The relaxation must touch *only* `human_gate`. A
  test must assert that relaxed mode does **not** weaken `adversarial_review`
  (Invariant G). This is the one place a subtle bug would silently gut the
  guarantee.
