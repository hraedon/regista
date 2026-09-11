# Plan 006 — SLA-Based Auto-Transitions: Design Exploration

**Status:** Design exploration (NOT a plan, NOT implementation-ready)
**Owner:** plm
**Sibling:** plans/003-recurring-work-items.md (in flight; not yet on disk)
**Spec touched:** §3 (Out of scope), §17 (event model), §18 (projection invariants), §20 (Consumer Expectation Boundary), FR-10 (escalation), FR-12 (role-gating), FR-15 (signing), FR-16 (replay), FR-24 (actor → roles), FR-26 (`update_not_before`)

This document maps a design space. It does not pick a winner. It exists so that, when a future agent reopens "auto-escalate after N hours," the inheritance of constraints is visible rather than re-discovered.

## 1. Problem Statement

Consumers (notably software-factory-2) want: *"if a work-item has been in state X for more than N hours, transition it to state Y."* Concrete examples:

- A `review` work-item that nobody picks up within 48h should auto-transition to `escalated` so a human is paged.
- A claim that an agent held but never released (orphan) should release after the TTL — regista already does this via `sweep_expired_claims` (FR-09a), but only releases the claim; the work-item stays in its current state.
- A `draft` PR that has had no activity for 7 days should auto-transition to `stale` for triage.
- A scheduled `not_before` gate fires (sibling plan 003 territory): the work-item is "ready" but consumers want regista to *advance* it rather than merely *unblock* it.

Today regista satisfies none of these. `spec.md:740` is explicit: *"Enforce SLAs or deadlines. No 'must complete by' semantics, no deadline timers, no auto-cancel on missed deadline."* `spec.md:735` adds: *"Detect work stuck in a state for too long. No 'this work-item has been in state X for N hours, escalate' primitive."* The feature is a consumer concern, by current spec. The question this document asks is whether *moving* it into regista is coherent, and if so under which design.

## 2. Invariant Inventory

The features touches these regista guarantees:

1. **Role-gated transitions (FR-12, `_contract.py:106`).** *"A transition by an actor whose role is not in the workflow's role-gating list for that transition is rejected"* (AC-13). Every transition has an `allowed_roles` list and the caller's claimed role must intersect it.
2. **Actor-attributed events (FR-03, §17).** Every event has `actor_id`, `actor_kind` ∈ {`agent`, `human`, `system`} (`_contract.py:11` — *the `system` kind already exists in the contract enum, though no current code path emits as system*), `actor_metadata` including `role`, `role_source` ∈ {`config`, `env`, `prompt`}.
3. **Actor → roles enforcement (FR-24, `_contract.py:122`).** If an `actor_id` has any rows in `actor_roles`, the claimed role must be in its registered set. Backward-compatible (un-registered actors are trusted).
4. **HMAC-SHA256 signing (FR-15, `_signing.py`).** The library is the sole signer. The canonical envelope covers `{event_id, work_item_id, actor_id, transition, payload}`. Server-stamped fields are excluded from signing precisely because callers cannot know them.
5. **Deterministic replay (FR-16, `_replay.py`).** *"Replay — rebuild a `work_items_current_replay_<timestamp>` projection from the event log on demand. Each historical transition validates against the workflow version recorded on its event"* (`spec.md:149`). The drift count must remain zero for an undefected projection (AC-27, AC-29). Replay must not depend on wall-clock at replay time.
6. **Projection invariant (BR-11, §18).** `work_items_current` is fully derivable from `events`; regista writes to it only inside the event-append transaction.
7. **Library, not daemon (AGENTS.md §Key Design Decisions).** Regista runs in-process. There is no resident regista worker that wakes itself up.
8. **§20 self-imposed boundary.** Regista explicitly does NOT do dwell-time monitoring, scheduling, SLAs, or notification. Moving inside this boundary is itself a load-bearing decision, not a free implementation choice.

## 3. Design Options

### (a) Reserved `system` actor signs SLA transitions

A reserved actor (e.g. `actor_id = "regista:sla"`, `actor_kind = "system"`) is the signer. Workflow YAML declares SLA-eligible transitions:

```yaml
transitions:
  - name: escalate_stale_review
    from: review
    to: escalated
    allowed_roles: [reviewer, system]
    sla:
      after_state: review
      duration_hours: 48
      actor: regista:sla
```

A poller (in-process thread or admin CLI command) finds eligible work-items and calls the normal `transition()` API as that actor.

- **Role-gating:** `allowed_roles` includes `system`; FR-12 passes.
- **Actor-attribution:** present; `role_source` becomes `workflow` (new value) or `config`.
- **Signing:** unchanged — the SLA actor has an HMAC key like any other.
- **Replay:** clean *iff* the SLA fire-event is in the log. It is — the poller used the normal append path.
- **Determinism:** clean. Replay reads the existing event; it does not re-evaluate the SLA condition.
- **Concerns:** introduces a regista-owned actor identity. Today no built-in actor exists; *every* actor is project-provided. This bends BR-09's threat model ("authenticated actors trusted not to misdeclare role") — regista is now an actor in its own model. Also re-opens §20: this is unambiguously "SLA enforcement," which regista said it would not do.

### (b) External admin actor (status-quo extension)

No regista change. A consumer (or the admin CLI from plan 002) configures an actor like `oncall-bot@team`, runs a periodic job (`cron`, K3s `CronJob`, host scheduler), queries `query_work_items()` filtered by `last_event_seq` age, and calls `transition()` as that actor.

- **Role-gating:** workflow declares `oncall-bot`'s role as permitted for the escalation transition.
- **All invariants:** untouched. This is the path §20 currently endorses.
- **Replay:** trivially clean — looks like any other transition.
- **Concerns:** *every* consumer reinvents this. There is no shared primitive, no discovery, no operator visibility. The policy lives outside the workflow definition, which is bad for the federated UI's "render any workflow generically" goal (FR success condition, `spec.md:21`).

### (c) Soft signal — `sla_breached` event, no transition

Regista emits a non-transition event (`sla_breached`) when a workflow-declared threshold is exceeded. A hook handler (FR-13) — owned by the consumer — decides whether to transition, and signs the transition as a real actor.

- **Role-gating:** untouched; the consumer's hook actor satisfies it.
- **Actor-attribution:** the `sla_breached` event still needs an author. Same `system` actor question as (a), but for an *informational* event rather than a state-changing one — significantly lower stakes.
- **Replay:** the `sla_breached` event is in the log; subsequent transitions (if any) are also in the log. Clean.
- **Determinism risk:** what triggers the emission of `sla_breached`? If regista emits it on its own clock, replay must skip the trigger and just replay the existing row — which it would, since replay reads events, not policy. OK.
- **Concerns:** still introduces a system-emitted event. But: regista already emits non-actor-driven events in spirit — `escalated` (FR-10) and `hook_dead_lettered` are emitted by the regista process itself when conditions are met. The actor on those events today is the actor whose action *triggered* the condition (the claim-acquirer). A wall-clock-triggered `sla_breached` has no such triggering actor.

### (d) Derived state — SLA expiry as a projection, not a transition

Don't transition at all. Instead, augment the projection (or a sibling view) with `sla_status: "ok" | "breached"` computed from `now() - last_state_change_at` against workflow declarations. Queries can filter on it. The work-item physically stays in `review`.

- **All transition invariants:** untouched. There is no SLA transition.
- **Replay:** clean. The derived field is not in `events`; it is computed on read like `claimable_now` (`spec.md:113`).
- **Concerns:** does not satisfy the consumer's actual ask. "Auto-escalate" implies the work-item *moves*; downstream actors poll `current_state IN (escalated)`. A derived `sla_status` requires consumers to query `current_state=review AND sla_status=breached` — strictly more capable, but requires every consumer to know to ask. Also: the projection update is no longer "transactionally consistent" with events (BR-11) for this field; it would have to be defined as a read-time view, not a stored column.

### (e) Workflow-declared transition with deferred actor binding

Workflow YAML names the actor that "owns" the SLA transition:

```yaml
transitions:
  - name: escalate_stale_review
    sla: { after_hours: 48, in_state: review }
    on_fire:
      actor_id: oncall@team        # must exist in actor_roles
      role: reviewer
      role_source: workflow
```

When the poller fires, it signs as `oncall@team` (whose HMAC key regista already holds, since it's a normal actor) with the declared role. A flag (`payload.sla_triggered: true`) is set so observers can distinguish.

- **Role-gating:** the declared `role` must be in the transition's `allowed_roles` and (if FR-24 is active for that actor) in the actor's registered set. Passes if configured correctly.
- **Signing key access:** the poller must have HMAC key access for the declared actor. That is operationally awkward — `oncall@team` is presumably a human or external service; regista signing as them muddies the audit trail. The signature *attests* "this actor performed this action," which is now false.
- **Replay:** clean; event is in the log.
- **Concerns:** the audit lie is the killer. FR-15's *"signed audit trail of which actor claimed which role for each transition"* (BR-09) becomes "signed audit trail of which actor *the workflow nominated to be blamed*." That is a worse position than (a)'s honest "regista did this."

### (f) Hybrid: derived state (d) + explicit `mark_breached` API

Regista exposes `mark_breached(work_item_id, actor_id, ...)` — an event-emitting mutation that records the breach as a transition-style event but does NOT change `current_state`. The derived view in (d) tracks it. Consumers can then call `transition()` as a real actor if they want to advance the state. The "who decided to mark this breached" is the caller — same model as (b), but with a regista-blessed verb.

- **Role-gating:** N/A or new gate (`can_mark_breached`).
- **Replay:** clean.
- **Concerns:** adds API surface without removing the consumer's polling responsibility — gives up much of the value.

## 4. Determinism / Replay Analysis

The replay invariant (AC-27, FR-16) is the hardest constraint. Replay reads events in order and re-applies them; it does not re-evaluate wall-clock conditions. So:

- For **any** option where SLA firing produces an event (a, c, e, f), replay is trivially clean — the event is the record of "this happened at this time," and replay does not recompute the trigger condition.
- For **option (d)** (pure derivation), there is no event, so no replay impact at all — but also no state movement.
- The dangerous shape, **NOT among the options above** and to be explicitly rejected, is: "the projection update logic checks wall-clock at apply time and transitions implicitly." That would mean replay-at-time-T1 produces a different projection than replay-at-time-T2 for the same event log, violating BR-11. *Any* option must record the SLA firing as an event at the time it fires, not have it inferred at replay time.

Subtle point for (a) and (c): the *firing wall-clock* and the *event timestamp* must agree by construction — regista stamps the timestamp server-side (`spec.md:138`), so this is automatic.

## 5. Interaction with Recurring Work-Items (Plan 003, in flight)

Plan 003 (a sibling agent is drafting it) likely needs a mechanism to "wake up at a scheduled time and create / advance a work-item." Both features share:

- **A thing inside or adjacent to regista that has a notion of wall-clock and a polling cadence.** Today the closest existing primitive is the hook-consumer thread (FR-13, `_hooks.py`) — it already runs in-process with a 30s poll. An SLA poller could plausibly piggyback on the same infrastructure.
- **The `not_before` gate.** FR-26 (`update_not_before`) is a partial precedent: it mutates a wall-clock-relevant field via an event (`not_before_set`). The pattern "*record a future intent as an event, act on it when the time comes*" is reusable for both.
- **Workflow YAML declaration.** Both features want declarative configuration in the workflow file rather than imperative consumer wiring.

Shared primitive worth considering: a regista `Scheduler` (in-process, per-`Regista` instance, opt-in) that owns the polling loop and dispatches to either feature. *This itself violates the "library not daemon" stance more than a hook consumer does* — the hook consumer is opt-in and event-driven; an SLA scheduler is timer-driven. Worth surfacing as an open question rather than presuming the answer.

Coordination ask: plan 003's author and this document's author should align on whether the polling loop is a shared concept before either feature lands.

## 6. Comparison Matrix

| Option | Invariant impact | Replay-safety | Policy author | Complexity | Reversibility | Blast radius if misconfigured |
|---|---|---|---|---|---|---|
| (a) System actor | Adds reserved actor; bends §20 hard | Clean | Workflow YAML | Medium | High (un-declare in YAML) | Medium — wrong SLA fires real transitions |
| (b) External actor | None | Clean | External (consumer) | Zero in regista | High | Bounded by consumer cron config |
| (c) Soft signal | Adds regista-emitted informational event | Clean | Workflow YAML + hook | Medium | High (drop hook) | Low — hook decides whether to act |
| (d) Derived state | None on transitions; adds derived field | Clean (no events) | Workflow YAML | Low-medium | High | Very low (read-only) |
| (e) Deferred-actor signing | Audit-trail truthfulness; key access expansion | Clean | Workflow YAML | Medium-high | Medium | High — wrong actor identity in log |
| (f) Hybrid mark_breached | Adds API; minor | Clean | Workflow YAML + consumer | Medium | Medium | Medium |

## 7. Tentative Recommendation (hedged)

Lean: **(c) soft signal + (d) derived state**, in that combination, with **(b) external actor** as the fallback for consumers that want to act on the signal.

Reasoning:

- **(d) alone** preserves every invariant and the §20 boundary, but doesn't satisfy the auto-transition ask. It earns its keep as a query helper.
- **(c)** is the smallest possible spec amendment: regista gains the ability to emit one new wall-clock-driven event type without ever signing a state transition itself. The actor on that event can plausibly be `actor_kind = "system"` with a reserved `actor_id` — and `_contract.py:11` already admits `system` as a valid kind, so the contract change is smaller than (a)'s.
- The combination lets consumers either (i) read the derived state and act, or (ii) install a hook on `sla_breached` and act, or (iii) ignore both and rely on (b).
- **(a)** is more powerful but commits regista to actually owning state transitions on its own clock, which is a larger philosophical move than I can endorse from a design exploration. If consumers turn out to overwhelmingly want regista-owned transitions (not just signals), (a) is the natural extension and (c) does not foreclose it.
- **(e)** I would reject on audit-trail grounds.

**Decision should be deferred until:**

- Plan 003 (recurring work-items) is on disk, so we can decide on shared polling infrastructure as one design.
- At least two consumers have written and run option (b) for real, and we know what they actually configured. Premature regista primitives generalize the wrong shape.
- A spec amendment to §20 is drafted explicitly — moving the boundary should be a conscious act, not a side effect.

## 8. Open Questions

- Does §20's *"Enforce SLAs or deadlines"* disclaimer survive any of these options? (a), (c), (e) require its retraction or refinement; (b), (d), (f) coexist with it.
- Is `actor_kind = "system"` with an `actor_id` of `regista:sla` (or similar) ergonomically and operationally acceptable? Where do its HMAC keys live? Are they per-project or regista-wide?
- For (c): what is `role_source` on a regista-emitted event? The current vocabulary is {`config`, `env`, `prompt`} — none fits.
- Should the polling cadence be per-`Regista` instance, per-workflow, or per-transition? What's the discovery story for "is the SLA poller running?"
- Does the SLA poller respect `not_before` (don't fire SLA before a work-item is even eligible)?
- Replay-on-revoked-key (FR-25): if the regista-actor's key is rotated/revoked, does past-regista-signed-event replay survive? (Yes, same mechanism as any other actor; worth confirming.)
- How does the SLA timer reset interact with `update_not_before` (FR-26)?
- Does an SLA-triggered transition release an active claim? Today `transition()` releases claims implicitly (AC-08); an SLA poller firing on a claimed work-item would steal from the active claim-holder. That may be desirable for `stale claim → release` but undesirable for other cases.
- Could (a)/(c) be implemented entirely as a workflow-author-owned hook plus a thin regista "tick" event, without regista ever being the *originator* of a state-changing event?

## 9. What This Is NOT

- Not an implementation plan. No file paths, line counts, or migration numbers.
- Not a commitment that regista will ever ship any of these.
- Not a §20 amendment proposal. §20 stands until a separate, deliberate amendment retracts the SLA clause.
- Not coordinated with plan 003's actual contents (which do not yet exist on disk at time of writing). Shared infrastructure is *speculated*, not designed.
- Not exhaustive — there are surely hybrids and variants not enumerated (e.g., "regista emits a hook only; the hook is the entire mechanism" might collapse to (c)).
- Not a normative ranking — the lean in §7 reflects this author's reading of the invariants today, not a consensus position.
