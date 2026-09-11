# Plan 003 — Recurring Work-Item Generation

**Status:** Draft
**Author:** planning agent
**Date:** 2026-05-15
**Spec touchpoints:** §3 (Scope), §5 FR-01/FR-02/FR-26, §7 BR-05/BR-06, §17 (concurrency), §20 (Consumer expectation boundary)
**Sibling plans:** none in `plans/` yet — this is plan 003 by request; 001/002 are reserved.

---

## 1. Motivation & Scope

Regista's `not_before` is a one-shot gate on a single work-item (`spec.md` lines 33, 118, 206; `src/regista/_work_items.py:82,278`). A caller that wants "run this task every Monday at 09:00" must keep its own schedule out-of-band and call `create_work_item` itself. That out-of-band scheduler is then *not* a regista actor — the new work-items get attributed to whatever ad-hoc cron job created them, and the audit trail loses the "this was a recurrence fire" signal.

**This plan adds first-class recurrence: a project registers a recurrence rule that points at a work-item template; regista emits fresh work-items on the rule's schedule, each created through the normal signed-event path with a `system:scheduler` actor.**

**In scope (use cases enabled):**
- Periodic agent jobs (nightly replay audit, hourly health probe, weekly retro).
- Pre-built work-items that an operator wants surfaced at a future fixed time (one-shot with `count=1` is a degenerate recurrence).
- "Time-spawned" backlog items where consumers want regista to be the single signer of the creation event.

**Out of scope (call out explicitly to prevent feature creep):**
- SLA auto-transition / dwell-time monitoring (covered separately; spec §20 forbids).
- "When event X happens, fire Y" — event-driven (non-time) triggers.
- Cron-as-a-service for arbitrary code: regista spawns work-items, not callable hooks. The hook subsystem already handles "do work in response to events" (FR-13).
- Max-retry policies on the spawned items (those follow the workflow's own attempt threshold, FR-10).
- Rescheduling running work-items (FR-26 `update_not_before` already does that).

---

## 2. Data Model

**Decision: a new `recurrence_rules` table, not a field on `work_items_current`.**

Rationale:
- A rule has its own lifecycle (active/paused/cancelled, last-fired-at, next-fire-at) distinct from any individual work-item. Embedding it on a template work-item would conflate "the template" with "the live schedule state" and force ad-hoc semantics on the template (does its claim block firing? does its state matter?).
- `work_items_current` is a *projection* of events (BR-11). A mutable `next_fire_at` field on it would either need its own event type and replay rule per tick, or it would be a non-projection column — both bad.
- The regista already has precedent for adjacent operational tables that aren't pure projections: `hook_queue`, `hook_dead_letter`, `actor_roles`.

### Schema sketch (new migration `010_recurrence_rules.sql`)

```sql
CREATE TABLE recurrence_rules (
  rule_id         uuid PRIMARY KEY,
  workflow_name   text NOT NULL,
  workflow_version int NOT NULL,
  work_item_type  text NOT NULL,
  template        jsonb NOT NULL,   -- { custom_fields, not_before_offset_seconds, payload_seed }
  schedule_kind   text NOT NULL CHECK (schedule_kind IN ('rrule','interval')),
  schedule_expr   text NOT NULL,    -- iCal RRULE string OR ISO-8601 duration
  timezone        text NOT NULL DEFAULT 'UTC',
  start_at        timestamptz NOT NULL,
  end_at          timestamptz NULL,
  count_remaining int NULL,         -- NULL = unbounded; decremented per fire
  status          text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','paused','exhausted','cancelled')),
  last_fired_at   timestamptz NULL,
  next_fire_at    timestamptz NOT NULL,  -- precomputed; index target
  created_by      text NOT NULL,    -- actor_id of the registrant
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_recurrence_due ON recurrence_rules (next_fire_at)
  WHERE status = 'active';
```

**Template shape:** `template.custom_fields` is the per-spawn `custom_fields` dict; `template.not_before_offset_seconds` (optional, default 0) lets the rule push the spawned item's `not_before` forward of fire time (e.g., fire at 09:00 but only claimable at 09:15); `template.payload_seed` is a free-form jsonb merged into the `created` event payload so spawned items are distinguishable in the log.

**Schedule expression:** **iCal RRULE** (RFC 5545) for the general case; **ISO-8601 duration** (`PT5M`, `P1D`) for the "every N period" shortcut. Cron-string syntax is explicitly rejected: cron has no timezone or DST contract and no rules-engine library in the Python stdlib. RRULE is timezone-aware via the separate `timezone` column. Python implementation uses `dateutil.rrule` (already permissive license).

**Rule identifier:** UUIDv4, separate from any work-item; spawned items carry `payload.recurrence_rule_id` so they're searchable.

---

## 3. Execution Model

**Options considered:**

| Option | Pros | Cons |
|---|---|---|
| (a) In-process background thread (mirrors `start_hook_consumer`) | Already-blessed pattern (`_hooks.py:380-388`); signs events via the same code path; works in library-mode | New responsibility (regista isn't a daemon today); caller must invoke `start_recurrence_consumer()` or it stalls |
| (b) Caller polls `regista.due_recurrences()` and invokes `fire_recurrence(rule_id)` | Regista stays passive — perfectly aligned with §20 ("scheduling … explicitly out of scope") | Pushes the timing loop onto every consumer; spreads the "is regista the signer" responsibility thin |
| (c) `pg_cron` / NOTIFY-based DB trigger | Single instance; cluster-friendly | `pg_cron` is an extension not present in vanilla Postgres 15; would force a new infra dependency (violates "minimal infra" principle, spec line 315); cannot reach into regista's signing code from inside Postgres |

**Decision: (b) primary, (a) optional convenience.**

The regista library exposes:
- `due_recurrences(now=None) -> list[DueRecurrence]` — read-only; returns rules whose `next_fire_at <= now()` and `status='active'`.
- `fire_recurrence(rule_id, actor_id='system:scheduler', actor_kind='system') -> tuple[WorkItem, Event, NextFireAt]` — atomically:
  1. `SELECT ... FOR UPDATE SKIP LOCKED` on the rule row.
  2. Re-check `next_fire_at <= now()` and `status='active'` (no-op return if not).
  3. Call `create_work_item(...)` (existing path — full signing, FR-02 validation, FR-15 envelope) with `actor_id='system:scheduler'`, `actor_kind='system'`, and payload containing `{recurrence_rule_id, scheduled_fire_at}`.
  4. Compute next `next_fire_at` from the RRULE/interval and stamp `last_fired_at`. Decrement `count_remaining`; if zero, set status `exhausted`.
  5. Commit. The whole thing is one Postgres transaction, taking the canonical lock on the new work-item's row via the existing `create_work_item` path.
- `start_recurrence_consumer(poll_interval_seconds=30)` / `stop_recurrence_consumer()` — convenience thread mirroring `_hooks.py:380`. Default off. Calling it is the difference between "passive" and "active" deployment.

This keeps option (b) as the primitive (regista-as-library, caller-as-driver) and option (a) as ergonomics on top, so both shapes are first-class.

**Signing path:** `fire_recurrence` calls the public `create_work_item` (no internal back door). That means HMAC-SHA256 over the canonical envelope (§17.7) is computed inside the library; AC-33 (no pre-signed events) is preserved by construction.

---

## 4. Actor Attribution

Spawned-item creation events carry:
- `actor_id = "system:scheduler"` (configurable per-project via `Regista(..., scheduler_actor_id=...)` but defaults to that literal).
- `actor_kind = "system"` (already an enumerated kind — `__init__.py:416,480,578,1050,1109,1256`).
- `actor_metadata = {"recurrence_rule_id": "<uuid>", "role_source": "config", "role": "<rule.template.role|'scheduler'>"}`.

**Interaction with role-gating (FR-12, FR-24):**
- `created` is the first event; there is no "transition out of state" gate to check on creation in the standard MVP. Custom workflows that gate creation through a `creating` transition must list the rule's claimed role in `allowed_roles`. Recommendation: the rule registrant chooses the role at rule-creation time and stores it in `template`.
- If FR-24 enforcement is opt-in active for `system:scheduler`, the registrant must `register_actor_role('system:scheduler', '<role>')` first; rule creation should fail-fast with `ACTOR_ROLE_NOT_AUTHORIZED` if the claimed role isn't registered.
- The HMAC key for `system:scheduler` lives in the same key set (FR-15 / `_keys.py`); rotation works identically.

---

## 5. Idempotency & Catch-Up

**Guarantee: at most one spawn per scheduled fire-instant, even across crashes and concurrent firers.**

Mechanism:
- The rule row's `next_fire_at` is the source of truth. Advancing it to the *next* slot is what marks "this fire has been claimed". The `SELECT ... FOR UPDATE SKIP LOCKED` plus the re-check in step 2 of §3 makes concurrent `fire_recurrence` calls safe: only one wins per slot, others see `next_fire_at` already advanced and return no-op.
- **Catch-up policy is per-rule:** add `catchup_policy text CHECK (IN ('fire_once','fire_all','skip'))` to the table (default `fire_once`).
  - `fire_once` — if 6 slots were missed during downtime, fire one work-item now and skip to the next future slot. Recommended default.
  - `fire_all` — fire 6 work-items in sequence. Useful for "every backup must have produced an item." Each call to `fire_recurrence` advances by exactly one slot, so the consumer loop drives the catch-up; a single transaction never spawns more than one item, which keeps lock duration bounded.
  - `skip` — drop all missed slots silently and resume at the next future slot.
- Spawned work-item's creation event carries `payload.scheduled_fire_at` (the *slot time*, not the actual fire time). Replay (FR-16) thus shows exactly which slots were honored.

Idempotency-on-retry within a slot is automatic: `create_work_item` is event-id-keyed (BR-12). `fire_recurrence` derives the event_id deterministically as `uuid5(rule_id, scheduled_fire_at.isoformat())`, so a partial-failure retry of the same slot returns the same row.

---

## 6. Interaction with `not_before`

- Spawned item's `not_before = scheduled_fire_at + template.not_before_offset_seconds`. Default offset is zero, meaning the item is claimable the moment it appears.
- If the rule fires late (catch-up), the *scheduled* slot time is still the basis, so a missed item is immediately claimable on landing — usually desired.
- `update_not_before` (FR-26) on a spawned item works unchanged: the consumer can reschedule individual spawns without touching the rule.

---

## 7. Implementation Steps

1. **Migration `010_recurrence_rules.sql`** — table + index above. Run via existing `_migrations.py` machinery.
2. **`_recurrence.py`** — pure functions: `compute_next_fire(rule, after)`, `parse_schedule_expr(kind, expr, tz)`. Add `python-dateutil` to `pyproject.toml` if not already pinned (`uv.lock` check).
3. **API additions on `Regista`** in `__init__.py`:
   - `register_recurrence_rule(...) -> RecurrenceRule`
   - `update_recurrence_rule(rule_id, *, status=..., schedule_expr=..., template=...)`
   - `cancel_recurrence_rule(rule_id)`
   - `list_recurrence_rules(status=...)`
   - `due_recurrences(now=None) -> list[DueRecurrence]`
   - `fire_recurrence(rule_id) -> FireResult`
   - `start_recurrence_consumer(poll_interval_seconds=30)` / `stop_recurrence_consumer()`
4. **InMemory backend parity** (`_in_memory.py`) — for property tests; mirror the `SKIP LOCKED` semantics with a per-rule lock.
5. **Public types** (`_types.py`) — frozen `RecurrenceRule`, `DueRecurrence`, `FireResult`.
6. **Error codes** (`_errors.py`) — `RECURRENCE_RULE_NOT_FOUND`, `RECURRENCE_RULE_EXHAUSTED`, `RECURRENCE_SCHEDULE_INVALID`, `RECURRENCE_TEMPLATE_INVALID`.
7. **Observability** — counters: `recurrence_rules_registered`, `recurrence_fires_total`, `recurrence_fires_skipped` (slot already advanced), `recurrence_consumer_loops_total`.
8. **Spec amendment** — add FR-28 (recurrence) under §5 "Scheduling"; amend §3 to note that recurrence is in scope while orchestration / SLA enforcement remain out. Cross-reference §20.
9. **AGENTS.md** — append API entries to the §"Public API" block.
10. **Example** in `examples/recurring_replay_audit.py` — registers a daily-at-03:00 rule that spawns a replay-audit work-item.

---

## 8. Test Approach

- **Unit:** `compute_next_fire` over a matrix of RRULEs and intervals; DST transitions (US/Eastern spring-forward 2026-03-08, fall-back 2026-11-01); leap day; end-of-month rollover (`FREQ=MONTHLY;BYMONTHDAY=31` in February).
- **Timezone:** rule stored with `timezone='America/New_York'` fires at the correct UTC instant pre- and post-DST. Verify via `dateutil.tz`.
- **Concurrency property test** (extend `tests/test_property_conformance.py` style): N concurrent threads call `fire_recurrence` on the same due rule; assert exactly one new work-item per slot, regardless of N.
- **Catch-up:** advance the clock past 5 slots without firing; each policy produces the documented count of work-items.
- **Crash safety:** kill the firer between rule update and work-item commit (use a `psycopg` injection point or transaction abort) — assert no rule state changes when the work-item insert fails.
- **Idempotency on retry:** call `fire_recurrence` twice for the same slot (force same UUIDv5); second call is a no-op returning the first work-item.
- **Signing:** verify the spawned item's event has a valid signature under `system:scheduler`'s key. Test that the rejection of pre-signed events (AC-33) still holds.
- **Role enforcement:** with FR-24 enforcement on, registration fails if `system:scheduler`'s claimed role isn't registered.
- **Migration round-trip:** apply `010` against a fresh DB; replay reports zero drift on a project with active rules.

---

## 9. Open Questions / Risks

- **Q1: Should the `template` reference a registered "template work-item" rather than carrying an inline jsonb dict?** Pro: editable as a normal work-item; reusable across rules. Con: muddies what "claim" / "transition" mean on a template (would it be terminal? frozen?). Lean: inline jsonb in v1; revisit if multiple rules want to share a template.
- **Q2: Multi-instance firing.** Two regista library instances running against the same DB will both fire. `SKIP LOCKED` makes that safe (one wins per slot), but the consumer-thread default of 30s on both means doubled load on the index. Mitigation: document and let operators run one consumer. No code change needed.
- **Q3: Clock skew.** Regista uses Postgres `now()` (BR-08); the rule's `next_fire_at` is server-clock-relative. Fire instants are therefore consistent regardless of client clock skew. Good.
- **Q4: RRULE expressiveness vs. complexity.** RRULE is a large RFC; we should pin to a tested subset (`FREQ`, `INTERVAL`, `BYDAY`, `BYMONTHDAY`, `BYHOUR`, `BYMINUTE`, `COUNT`, `UNTIL`). Document the supported subset in AGENTS.md.
- **Risk: schema-per-project means recurrence rules live per project schema.** Cross-project recurrence is not supported (consistent with BR-04). A "spawn a work-item in project A every time project B fires" use case is out of scope.

---

## 10. Out of Scope (Explicit)

- SLA auto-transitions, dwell-time gates, "if state X for N hours then escalate."
- Max-retry policies on spawned work-items (workflow's `attempt_threshold` already governs FR-10).
- Event-driven triggers (when event X is appended, spawn Y) — possible future "reactive rules" plan; uses hooks today.
- Cron-string syntax for `schedule_expr`.
- A regista-managed *executor* for the spawned item — regista spawns; the agent/consumer claims and runs (BR-05).
- Cross-project rules.
- A REST/HTTP scheduler endpoint — regista remains a library (Phase 2 deployment-shape decision, §10).
