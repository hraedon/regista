# Specification: substrate

**Spec Level:** 3
**Desired Level:** 3
**Date:** 2026-05-03 (revised 2026-05-05 — review pass v3, 2026-05-05 — Phase 3 additions, 2026-05-18 — v5, 2026-05-23 — v6, 2026-05-24 — v7, 2026-05-24 — v8)
**Extensions active:** None

**Revision history:**
- 2026-05-18 — v5: RFC-001 (revert migration 010 partitioning; events table is flat with global `UNIQUE(event_id)`). BC-194 (heartbeat coalescing: `claim_heartbeat` events suppressed within `max(60s, ttl/2)` threshold). `ensure_event_partitions` is now a no-op returning `[]`. Partition gauges (`events_default_rows`, `events_partition_horizon_days`) removed. Migrations renumbered 010–013 (no production data). `heartbeat_claim` gains optional `coalesce_threshold` parameter. Plan 010: `on_behalf_of` delegation field added to signing envelope; integrity-protected but self-attested.
- 2026-05-23 — v6: Signing envelope updated to v2 (BC-214). Previously server-stamped fields (`timestamp`, `event_seq`, `key_id`, `workflow_name`, `workflow_version`) are now included in the canonical signing envelope, signed by the library before the event is persisted. This removes an ambiguity between InMemory and Postgres backends (BC-220) and prepares for asymmetric verification (Plan 011). Backward compat: replay verifies v2 first, then falls back to the old v1 envelope for pre-v6 events. KeyEntry gains `alg`, `public_key`, `role`, `revoked_at`, and `principal_id` fields (BC-216, BC-217, BC-218).
- 2026-05-24 — v7: Plan 011 (pluggable signing, Ed25519 + HMAC-SHA256) implemented. `scheme_id` column added to `events` (migration 015). `SigningScheme` protocol, `HMACSHA256Scheme`, `Ed25519Scheme`, registry in `_signing_scheme.py`. KeyEntry gains `scheme` field (default `hmac-sha256`). Replay resolves scheme per event. Plan 012 (RFC 3161 timestamping) implemented with Merkle tree batching, `tsp_batches` table (migration 016), `TimestampOps` facade, `MaintenanceThread._maybe_timestamp_events`. Replay gains `verify_timestamps` parameter to cross-reference events against confirmed TSP batches. New error codes: `SIGNING_SCHEME_NOT_FOUND`, `TSA_NOT_CONFIGURED`, `TSA_SUBMISSION_FAILED`, `TSA_VERIFICATION_FAILED`.
- 2026-05-24 — v8: BC-233 (event hash chain). `prev_event_hash BYTEA` column added to `events` (migration 018). Each event's `prev_event_hash` is `SHA-256(prev_canonical_envelope ∥ prev_signature)`, binding each event to its predecessor within the work-item's event sequence. Signing envelope v3 includes `prev_event_hash` (hex) and `global_seq` when present. Replay verifies the hash chain per work-item and increments `warnings` on chain break. InMemory backend computes `prev_event_hash` identically. Plan 014 (`global_seq BIGSERIAL` on events, migration 017) already landed in v7 cycle.
- 2026-05-05 — v4: Phase 3 additions. FR-24 (actor → allowed_roles enforcement, closing BR-09 fast-follow). FR-25 (continue-on-revoked replay flag). AC-35/AC-36 added. §12 Phase 3 updated. §16 decision items resolved: actor role enforcement (implemented), retention policy (deferred with guidance), Postgres version (pinned to 15+). BR-09 updated from "deferred fast-follow" to "implemented."
- 2026-05-05 — v3: integrated third reviewer pass on API shape and consumer expectations. Adds FR-05b (structured work-item query, MVP), §19 Public API Surface (substrate library as sole signer; service-wrapping is mechanical), §20 Consumer Expectation Boundary (explicit non-goals consumers commonly assume substrate provides), BR-13 (per-project DB isolation as load-bearing assumption with documented migration path), refinement to FR-15 (library-as-sole-signer clause). ACs 32–34 added. Reviewer points on links projection and signing envelope complexity were considered and held as designed.
- 2026-05-05 — v2: integrated two-reviewer correctness pass. Adds API-layer idempotency, gap-free `event_seq` allocator + canonical lock target (§17), projection invariants (§18), HMAC-SHA256 + RFC 8785 canonical signing envelope, transition-validator vs hook split, custom-field type vocabulary, trust tiers on `actor_metadata`. Resolves §13 Q8 (domain-expert review).

---

## 1. Problem Statement

**Problem:** Multi-role agent pipelines (and other project work) coordinate via ad-hoc conventions and flat files (`reasoning.log`). No durable claims, no typed handoffs, no event history, no schema for state, no path to a human-facing view. The Software Factory feels this most, but the same gap exists across all the operator's projects, and they need a shared way to reason about work without sharing state globally.

**User/Operator:** Single operator running on a homelab K3s cluster with Postgres available. Currently zero humans-in-the-loop; agents are the primary actors. Non-revenue, license-cost-bound, token-spend unconstrained.

**Success condition:** A substrate defined as a strict, versioned core schema and protocol — work-items, events, claims/leases, actors, link types — that each project deploys as its own isolated instance (own Postgres schema within a shared database; no cross-project state). On top of the core, each project declares its workflow declaratively: states, transitions, role-gating per transition, typed custom fields per work-item type (with `ui_visible` flag), and link types. Side effects are hooks the project owns; the substrate dispatches events but executes no project code. A future federated UI reads the contract and renders any project's workflow generically — pane-of-glass without shared state. Existing `reasoning.log` continues to work alongside.

---

## 2. Glossary

| Term | Definition |
|---|---|
| **Substrate** | The library + Postgres schema + protocol providing coordination and durable state for agent pipelines. Library deployment; one substrate instance per project. |
| **Project** | A logical unit of related work; corresponds 1:1 to one Postgres schema within a shared database. Hosts one or more workflow definitions. |
| **Workflow** | A named, versioned declarative state machine describing how a particular kind of work proceeds. A project may register many workflows (e.g., spec generation, implementation, review). |
| **Workflow definition** | A YAML file (validated against substrate's JSON Schema) declaring states, transitions, role-gating, custom fields per work-item-type, link types, attempt threshold, and per-hook retry overrides. |
| **Work-item** | A discrete unit of trackable work. Has a workflow, a work-item-type within that workflow, a current state, custom fields, links to other work-items, a `needs_review` flag, and a `not_before` timestamp. |
| **Work-item-type** | A category within a workflow (e.g., `spec`, `feature_request`, `bug`). Declares its own custom fields and allowed link types. |
| **Event** | An immutable record appended to the per-project event log describing what happened to a work-item. The authoritative history. |
| **Actor** | An identified entity that performs operations. Has an `actor_id`, `actor_kind` (`agent` / `human` / `system`), and optional `actor_metadata` (jsonb). |
| **Claim** | A durable lease an actor holds on a work-item to indicate active work. Has TTL, attempt number, and explicit release. |
| **Hook** | A side effect dispatched on transitions. Sync hooks gate the transaction; async hooks are queued and dispatched at-least-once. |
| **Link** | A typed directed reference between work-items in the same project. Created and removed via events. |
| **Workflow version** | A registered, immutable instance of a workflow definition. Work-items pin the version they were created against. |
| **Reasoning log** | Existing flat-file convention in the Software Factory. Continues to operate alongside the substrate. |

---

## 3. Scope

**In scope:**
- Core schema: work-items, events, claims, actors, links
- Per-project Postgres schema isolation (one schema per project within a shared database)
- Workflow definition format (YAML + JSON Schema), parsing, semantic validation, versioned registry
- Claim lifecycle: acquire, heartbeat/renew, release, expire, auto-steal with attempt tracking
- Transactional event append + denormalized current-state update
- Event log read with structured query shapes
- Replay: rebuild current-state projection from event log into a fresh table
- Sync and async hook dispatch (async via durable queue table; LISTEN/NOTIFY as latency optimization, polling as correctness mechanism)
- Pluggable actor identity verifier (HMAC default; OIDC-ready)
- Key rotation via key-set-with-status (active / deprecated / revoked)
- Startup integrity check (migrations applied; workflow-substrate version compatibility)
- Structured logging + Prometheus metrics

**Out of scope:**
- Cross-project state, queries, or links
- DB provisioning (operator creates the DB; substrate runs migrations against it)
- Disk-level durability and backups (operator policy; separate concern)
- Scheduling beyond `not_before` timestamp (no scheduler engine)
- Retry / SLA / automation engines layered above coordination
- Workflow file composition across files via `extends:` — **implemented (FR-29)**
- Notification / paging / email (substrate flags + emits events; consumers are project policy)
- A human-facing UI (federated UI is downstream and consumes the substrate; not part of this build)
- Removal of registered workflow versions (registry is append-only)

---

## 4. MVP Definition

**MVP is:** The substrate library replaces `reasoning.log` for one workflow in the Software Factory: agents create work-items in a declared workflow, claim them durably, transition them through validated states with role-gating, and the event log captures every operation with full replay support.

**MVP functional requirements:** FR-01, FR-02, FR-03, FR-04, FR-05, FR-05b, FR-06, FR-07, FR-08, FR-09a, FR-09b, FR-11, FR-12, FR-15, FR-16, FR-17, FR-19, FR-20, FR-21, FR-22, FR-23.

**Rationale:** The minimum that earns its keep over `reasoning.log` is one factory workflow running on the substrate with durable claims, attempt tracking, replay, role enforcement, and observability. Hooks (FR-13), escalation consumers (FR-10), dead-letter requeue (FR-14), and lint helpers (FR-18) are real but their consumers don't yet exist; shipping them in MVP would be features without users.

**Note to implementing agent:** This reflects value priority. Some non-MVP requirements may be architecturally load-bearing — surface conflicts before writing code rather than reordering silently.

---

## 5. Functional Requirements

**Core primitives:**

- FR-01 **[MVP]**: Define a work-item with project-declared workflow (pinned version), work-item-type, current state, custom-typed fields, links (derived from event stream — see FR-22/FR-23), `needs_review` flag, `not_before` timestamp.
- FR-02 **[MVP]**: Create a work-item — validates workflow registered, work-item-type declared in that workflow, generates ID, validates initial custom field values against type schema, records `created` event.
- FR-03 **[MVP]**: Append events to immutable per-project event log. Each event carries:
  - `event_id` — client-supplied UUIDv4. Doubles as the API-layer idempotency key for event append. Unique within a project DB, enforced by a database-level unique index on `events(event_id)`. Duplicate `event_id` returns the original event row deterministically (not an error); enables safe retry across transient failures (BR-12). Cross-work-item reuse of the same `event_id` is rejected with `EVENT_ID_GLOBAL_COLLISION`.
  - `work_item_id`
  - `event_seq` — **gap-free** monotonic per work-item; allocated under the canonical lock (§17.2, §17.4).
  - `actor_id`, `actor_kind` — authenticated via HMAC (FR-15). Trust tier: *authenticated*.
  - `actor_metadata` (jsonb) — agents SHOULD include `model`, `provider`, and `role_source` (`config` / `env` / `prompt`). Content-hash fields `context_hash` and `prompt_template_hash` enable per-attempt and per-template correlation in telemetry. Trust tier: *actor-claimed* (signed-by-actor but not validated against any registry; see BR-09 and §17.9).
  - `on_behalf_of` (jsonb, optional) — delegation indicator for agent actors acting under a human principal. Contains `principal_id` (required, string), optional `scope` (list of strings), and optional `authenticated_at` (ISO-8601 string). Trust tier: *actor-claimed*; tamper protection is HMAC over the field, but authorization is self-attested by the caller. See Plan 010.
  - `key_id` — authenticated.
  - `workflow_version` — pinned at work-item creation; immutable thereafter (BR-02).
  - `timestamp` — Postgres `now()`, server-stamped (BR-08). Trust tier: *server-stamped*.
  - `transition`, `payload` — caller-supplied.
  - `payload_canonical_hash` — SHA-256 of the canonical signing envelope (FR-15). Stored to enable retroactive verification independent of jsonb round-trip behavior across Postgres versions.
  - `signature` — produced by the key's declared signing scheme (default HMAC-SHA256; see FR-15, Plan 011).
  - `scheme_id` — signing scheme identifier (`"hmac-sha256"` or `"ed25519"`); resolves to `SigningScheme` at verification time.
  - `prev_event_hash` — SHA-256 of `(canonical_envelope ∥ signature)` of the preceding event in the same work-item's event sequence. `None` for the first event (event_seq=1). Provides tamper-proof ordering within a work-item's event chain (BC-233). Replay verifies the chain and increments `warnings` on break.
  - `global_seq` — `BIGSERIAL` monotonic across the entire project. Enables coherent batch timestamping (Plan 014) and cross-work-item event ordering.
  - **Optional `expected_event_seq` API parameter** for optimistic locking: if supplied, append rejects with "concurrent modification" when `current_max(event_seq) + 1 != expected_event_seq`. Complements idempotency (idempotency handles retried requests; expected_seq handles concurrent modification by a different actor).
- FR-04 **[MVP]**: Write events and update `work_items_current` denormalized table in a single Postgres transaction.
- FR-05 **[MVP]**: Read event log with query shapes: by-work-item (ordered by `(timestamp, event_seq)`), by-actor, by-time-range, by-transition.
- FR-05b **[MVP]**: Structured work-item query against `work_items_current` (not the event log). Filter shapes (combinable, AND semantics):

  - `workflow_name`, `workflow_version` (the latter optional; absent = any pinned version)
  - `work_item_type` (one or many)
  - `current_state` (one or many)
  - `claimed_by` (actor_id) — work-items currently held by a specific actor
  - `claimable_now` (bool) — unclaimed-or-expired AND `not_before <= now()`
  - `needs_review` (bool)
  - `has_link_type` (link type) — work-items that are the source of a link of given type

  Pagination via stable `work_item_id` cursor (ordered ascending); default page size 100, max 1000. The cursor is `work_item_id`-only rather than `(last_event_seq, work_item_id)` so that ordering is fixed regardless of concurrent appends — pagination cannot skip or duplicate a work-item that is touched mid-scan. The trade-off is that pages are not ordered by recency; consumers who want "freshly active first" should sort the page contents client-side or filter by `last_event_seq` range. Indexes required to satisfy NFR-perf-1: `(workflow_name, workflow_version, current_state)`, `(claimed_by)`, `(needs_review) WHERE needs_review`. This is the foundation query for agent claim-discovery ("what work is available for me to claim now") and for the federated UI's list views; without it consumers reach into `work_items_current` directly and the substrate's API surface is incomplete.
- FR-06 **[MVP]**: Acquire a claim on a work-item. Respects `not_before` (rejects if in future); rejects if work-item is already claimed and unexpired (Postgres row lock — first wins, second receives "claim contested" rejection, not an error).
- FR-07 **[MVP]**: Renew a claim via heartbeat before TTL expiry. **Stale-heartbeat protection:** if `claims.actor_id != heartbeat.actor_id` OR `attempt_number` has advanced since the claim was acquired, the heartbeat is rejected with a "claim lost" signal and the agent must stop work.
- FR-08 **[MVP]**: Release a claim explicitly via `release_claim()`. Successful state transitions release implicitly.
- FR-09a **[MVP]**: Lazy auto-expire on claim queries — `expires_at < now()` filters at read time. `sweep_expired_claims()` helper for hygiene; lazy is the correctness mechanism.
- FR-09b **[MVP]**: Auto-steal expired claims on next acquire; increment `attempt_number`; preserve prior claim history in event log.
- FR-10: Flag `needs_review` and emit `escalated` event when `attempt_number` ≥ workflow-declared threshold. Idempotency: unique partial index `(work_item_id) WHERE transition = 'escalated'`; second insert raises and is silently dropped.
- FR-11 **[MVP]**: Validate state transitions against the **work-item's pinned workflow version** (not the latest); reject invalid transitions.
- FR-12 **[MVP]**: Validate role-gating per transition against the work-item's pinned workflow version; reject if actor's declared role isn't permitted for that transition. If actor has registered roles (FR-24), the declared role must also be in the actor's registered set.
- FR-13: Two distinct side-effect primitives on transitions, with materially different contracts:

  - **Transition validator (in-transaction, synchronous):** runs inside the same Postgres transaction as the event append, while the canonical lock is held (§17.2). Gates commit. **Trusted code, no enforced bounds** (BC-192): validators run synchronously in the caller's thread; substrate does not enforce wall-clock or I/O limits. A hanging validator hangs the transaction. The Postgres `statement_timeout` (5s) protects against blocking DB operations made via the transaction's connection, but not pure-Python loops or external I/O. **Should NOT perform I/O** — local computation only (validation, derivation, cross-field invariants, sanity checks). Validators that need to call out to other systems should instead enqueue an async hook.

  - **Hook (async, durable):** written to a durable `hook_queue` table on commit. Consumer woken via Postgres LISTEN/NOTIFY (latency optimization). The NOTIFY payload is **wakeup-only** (an `event_id` reference); it is never a data channel — Postgres NOTIFY has an 8KB payload cap and consumers must read the full hook payload from `hook_queue`. Polling sweep runs always at fixed default 30s interval (correctness mechanism, independent of NOTIFY). At-least-once delivery; retry-with-backoff (substrate-defined defaults; project-overridable per hook in workflow def). After max retries, row moves to `hook_dead_letter` table and a `hook_dead_lettered` event is emitted.

  Naming intent: the in-transaction primitive is called a *validator*, not a "sync hook," because consumers and project authors should reach for hooks by default and reach for validators only when the work is *necessarily* atomic with the transition. Hooks may evolve freely; validators are a narrow exception path.
- FR-14: Replay dead-lettered hooks via `requeue_dead_lettered_hook(id)` — resets retry counter; re-enters queue; re-failure follows same policy.
- FR-15 **[MVP]**: Verify actor identity via pluggable verifier before recording any event.

  - **Algorithm:** Pluggable via `SigningScheme` protocol (Plan 011). Default: HMAC-SHA256. Alternative: Ed25519 (via PyNaCl, optional dependency). Scheme is declared per key in the key file (`KeyEntry.scheme`); `scheme_id` is persisted on each event row.
  - **Library is the sole sanctioned signer.** The substrate library's public API accepts unsigned event field tuples; the library performs RFC 8785 canonicalization, signs using the key's declared scheme, and persists. The API does NOT accept pre-signed events from callers and rejects any attempt to submit one. Rationale: canonicalization is an invariant — if every caller (Python agent, future sidecar client, federated UI service) implements JCS independently, the audit promise depends on every implementation being byte-identical, which is not a defensible position. Consolidating the canonicalizer in one place is the only sustainable defense. Future service-wrapper deployments (sidecar) MUST expose the same unsigned-fields API and sign inside the wrapper process; they MUST NOT expose a passthrough that accepts pre-signed events on the wire (see §19.2).
  - **Canonical signing envelope (v3):** the bytes signed are RFC 8785 (JCS) canonical JSON serialization of `{event_id, work_item_id, actor_id, key_id, event_seq, workflow_name, workflow_version, timestamp, on_behalf_of, transition, payload, prev_event_hash?, global_seq?}`. Keys whose values are `None` are omitted from the canonical JSON. `prev_event_hash` (hex-encoded) and `global_seq` are included when present, making the signing envelope integrity-cover the chain linkage and global ordering. Lexicographically sorted keys, no whitespace. This covers all integrity-relevant event fields, including those previously treated as "server-stamped" (v1). Backward compatibility: replay classifies the envelope version at verification time — v3 first, then v2, then v1 for pre-v6 events.
  - **Storage of canonical bytes:** The canonical envelope bytes (RFC 8785 serialized v3 envelope) are persisted as `canonical_envelope BYTEA` on every event row. `payload_canonical_hash` (SHA-256 of the canonical envelope) is also persisted. Re-verification at replay time uses the stored envelope bytes directly, not jsonb re-serialization, so signature stability survives Postgres version upgrades that change jsonb canonicalization.
  - **Key set:** per-actor, with status `active` / `deprecated` / `revoked`. Each event carries `key_id`. Hot-reload via mtime polling at default 30s interval. K3s Secret atomic-swap (symlink) is compatible with mtime polling. Inotify and SIGHUP are NOT used (platform-coupled and process-control-coupled respectively).
  - **Behavior:**
    - Unknown `key_id`: reject; structured log with `actor_id_claim`, `key_id_claim`, `event_id`; signature contents NOT logged.
    - Revoked `key_id`: reject (including retroactively, where re-verification occurs).
    - Deprecated `key_id`: accept; emit structured warning.
  - **Trust tiers** (consumed by §17.9 and §11):
    - *Authenticated* — `actor_id`, `key_id` (scheme-verified: HMAC-SHA256 or Ed25519).
    - *Server-stamped* — `timestamp`, `event_seq` (substrate writes; not under actor control).
    - *Actor-claimed* — `actor_metadata` (incl. `role`, `model`, `provider`, `role_source`, `context_hash`, `prompt_template_hash`) — signed by actor but not validated against any registry. FR-24 provides opt-in enforcement: when an actor has registered roles, the claimed role is validated against the actor's allowed set; otherwise it is trusted.
- FR-16 **[MVP]**: Replay — rebuild a `work_items_current_replay_<timestamp>` projection from the event log on demand. Each historical transition validates against the workflow version recorded on its event. Output is a fresh table; substrate does NOT mutate live `work_items_current` in place. Operator decides whether to atomically swap (rename) or diff for verification.

  Substrate also produces a companion `replay_report_<timestamp>` table categorizing each work-item:

  - `replayed_ok` — replayed final state matches live `work_items_current`.
  - `replayed_drift` — replayed final state differs from live. **This is the actionable signal.** Possible causes: bug in projection update logic, direct edit to `work_items_current` outside the substrate API (forbidden by §18), missed event (corruption — usually accompanied by `event_seq` gap).
  - `halted` — replay could not complete on this work-item; halt reason recorded (`revoked_key`, `missing_workflow_version`, `unrecognized_transition`, `signature_verification_failed`, etc.).
  - `warnings` — count of events skipped during signature verification (when `continue_on_revoked=True`) or events not covered by confirmed TSP batches (when `verify_timestamps=True`); informational, not a defect signal.

  The report is the operator's primary interface to replay; comparison logic does not need to be authored per-replay. Nonzero `replayed_drift` count is a defect signal. `halted` rows are operator alerts; live projection is untouched on halt. Nonzero `warnings` count with zero `halted` and zero `drift` indicates a clean replay with historical key rotation.

  **Timestamping verification:** `replay(verify_timestamps=True)` cross-references every event's `event_seq` against confirmed `tsp_batches` rows. Events not covered by any confirmed batch increment `warnings`. This is informational — timestamping is opportunistic and a gap does not indicate a defect in the event log itself.

**Workflow definition (project-owned, declarative):**

- FR-17 **[MVP]**: Parse and validate workflow definition (YAML + JSON Schema). Declares: `version` (required integer), `substrate_version` (required, semver), states, transitions, role-gating per transition, custom typed fields per work-item-type (each field has `type` + `ui_visible` flag, default `false`), link types per work-item-type pair, attempt threshold, per-hook retry overrides.

  - **Custom field type vocabulary** (closed set; expansion requires a substrate minor version bump):
    - `string`
    - `integer`
    - `boolean`
    - `timestamp` (ISO 8601 / Postgres `timestamptz`)
    - `json` (free-form jsonb)
    - `enum` (declared values list)
    - `work_item_ref` (constrained to a `work_item_id` in the same project DB; declared target work-item-type optional)

  - **Compatibility rule (consumed by FR-20):** `library_major == workflow.substrate_version_major` AND `library_full_version >= workflow.substrate_version`. Workflows can require newer minor versions (new field types, new validators) — older libraries refuse to start against them. Workflows cannot require newer majors.

  - **Validation passes:**
    - (a) YAML syntactic — rejects with line-numbered error.
    - (b) JSON Schema — rejects with JSON-pointer error.
    - (c) Structural / semantic — reachability (every state reachable from start), terminal-state declaration consistency (states with no outgoing transitions must be declared terminal), role-binding consistency (roles referenced in transitions must be declared at workflow level), type-vocabulary consistency (every field type drawn from the closed set above), `work_item_ref` target-type consistency (referenced work-item-types declared in same workflow).

  - **Registry uniqueness:** `(workflow_name, version)` is unique within a project DB. Content-based idempotency: re-registration of the same `(name, version)` with identical content (SHA-256 of JCS-canonicalized definition) returns the existing row; re-registration with different content rejects with `WORKFLOW_VERSION_CONFLICT`. This is divergence detection, not anti-idempotency — the operational intent is to catch accidental re-registration of a different workflow under the same key. *Amended per BC-022: original spec language ("first wins; second rejects") was imprecise about the idempotent case.*

  Any failure rejects registration with an operator-actionable error message including source location. Existing registered versions remain valid.

**Tooling:**

- FR-18: `validate_actor_metadata(event, expected_schema)` lint helper — non-enforced, callable on the event log to flag conformance drift against documented conventions.

**Operational:**

- FR-19 **[MVP]**: Per-project Postgres schema isolation. One database hosts all projects; each project gets its own schema. Multiple workflow definitions may be registered within that schema. Substrate has no `provision_project_db()` primitive; database existence is a precondition (operator-shaped). `Substrate.create_project()` creates the project schema and runs migrations. Substrate fails fast with a clear error if the schema doesn't exist.
- FR-20 **[MVP]**: Startup integrity check — verify (a) all schema migrations are applied; (b) every registered workflow declares a `substrate_version` compatible with the running library version. Refuse to start otherwise; operator runs migration command and re-launches.
- FR-21 **[MVP]**: Structured logs per substrate operation including `project_id`, `work_item_id`, `operation`, `duration`, `outcome`, `actor_id`. Substrate is a library, not a daemon: it exposes a `prometheus_client.CollectorRegistry` (or labelled metrics) that the host application mounts on its own HTTP server. Substrate does not run an HTTP server. Counters: events appended, claims acquired/expired/stolen, hooks dispatched/succeeded/failed/dead-lettered, transitions accepted/rejected, validators succeeded/failed/timed-out, replay drift count, idempotency-key collisions, expected-seq-mismatch rejections.
- FR-22 **[MVP]**: Create a link between work-items — validates target exists in same project DB, validates link type is allowed by workflow def for the work-item-type pair, records `link_created` event with `(from, to, type)`.
- FR-23 **[MVP]**: Remove a link between work-items — records `link_removed` event with `(from, to, type)`. Previous link history remains in event log.

**Actor authorization:**

- FR-24: Actor → allowed_roles enforcement. New `actor_roles` table with `(actor_id, role)` unique rows. Public API: `register_actor_role(actor_id, role)`, `unregister_actor_role(actor_id, role)`, `list_actor_roles(actor_id=None)`. Enforcement semantics: during FR-12 role-gating, after checking the claimed role against the transition's `allowed_roles`, if the actor has any rows in `actor_roles`, the claimed role must also be in the actor's registered set. Actors with no registered roles are trusted (backward compatible with pre-FR-24 behavior). This is opt-in enforcement: registering a single role for an actor activates enforcement for that actor. Error code: `ACTOR_ROLE_NOT_AUTHORIZED` with detail including `actor_id`, `claimed_role`, and `allowed_roles`. Closes BR-09 fast-follow.

**Replay:**

- FR-25: `continue_on_revoked` replay flag. When `True`, replay skips signature verification for events signed with revoked or unknown keys, logs a structured warning per skipped event, and continues processing the work-item. The replay report's `warnings` count aggregates these skips. When `False` (default), behavior is unchanged: replay halts on revoked-key events. Use case: operator wants a complete replay report for audit despite having rotated keys, without halting on historical revoked-key events.

**Scheduling:**

- FR-26: `update_not_before()` — reschedule a work-item's `not_before` timestamp after creation. Emits a `not_before_set` event with the new timestamp (or `null` to clear). Updates the projection. Required because `not_before` is mutable (§18.2: "derived from the most recent `not_before_set` event") but had no API to produce updates. Claim acquisition (FR-06) continues to respect `not_before` regardless of when it was set.

**Validation:**

- FR-27: Custom field type validation at transition time. When a transition provides `custom_fields_update`, each field's value is validated against the work-item-type's field definition (same type vocabulary as FR-17: `string`, `integer`, `boolean`, `timestamp`, `json`, `enum`, `work_item_ref`). Unknown fields and type mismatches are rejected with `CUSTOM_FIELD_VIOLATION` before the transition proceeds. This extends creation-time validation (FR-02) to the update path.
- **FR-28**: Recurring work-item generation (Plan 003). Register a recurrence rule that creates work-items on a schedule. Supports interval (`P1D`, `PT1H`) or RRULE schedules. Rules live in the new `recurrence_rules` table. Public API: `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence`, `update_recurrence_rule`, `cancel_recurrence_rule`.

  - **Interval schedule note**: ISO-8601 durations containing months (`P1M`) or years (`P1Y`) are converted to `timedelta` using a fixed baseline (1970-01-01), which yields 31 days for `P1M` and 365 days for `P1Y`. This is an approximation; true calendar-month or calendar-year scheduling requires RRULE.
- **FR-29**: Workflow file composition (Plan 004). Workflows may declare `extends: <path>` to inherit from a base workflow file. Child overrides parent with deep-merge semantics, keyed list merge by `(name, from)` for transitions and `name` for states/roles/types, and `__append`/`__remove` modifiers. Cycle detection, max depth (8), and compose-root path escape protection. New error code `WORKFLOW_COMPOSE_ERROR`.

---

## 6. Data

**Inputs:**
- **Workflow definition file (YAML):** declares states, transitions, role-gating, custom fields, link types, attempt threshold, retry overrides, `version`, `substrate_version`. Validated at registration.
- **HMAC key set (K3s Secret, JSON-shaped):** per-actor key entries with `key_id` and `status` (`active` / `deprecated` / `revoked`). Hot-reloaded.
- **Postgres connection string:** one per substrate library instance; identifies the project DB.

**Outputs:**
- **Event records** (table `events`): authoritative append-only log
- **Current-state projection** (table `work_items_current`): denormalized, transactionally-consistent with events
- **Hook queue rows** (table `hook_queue`): pending and dead-lettered
- **Structured log lines:** stdout, structured JSON
- **Prometheus metrics:** standard exposition endpoint

**Persisted state (per project DB):**
- `events` — append-only event log; single flat table with global unique index on `event_id`
- `work_items_current` — current-state denormalization; rebuildable from `events`
- `claims` — current claim per work-item (or null), with `actor_id`, `acquired_at`, `expires_at`, `attempt_number`
- `hook_queue` — pending async hooks with retry metadata
- `hook_dead_letter` — terminally-failed async hooks (quarantine, replayable via FR-14)
- `actor_roles` — per-actor role mappings for FR-24 enforcement; opt-in, backward compatible
- `workflow_registry` — registered workflow definitions, append-only (versioned, immutable once referenced)
- Migration metadata (substrate-managed, e.g., Alembic-equivalent)

Retention: indefinite for v1. Operator-driven archival when volume warrants. Re-partitioning is a known recipe (declarative `PARTITION BY RANGE (timestamp)`) if a single project exceeds ~10M events/month.

---

## 7. Business Rules

- BR-01: Workflow registry is append-only. Substrate provides no primitive to remove a registered workflow version. Operator-level removal is operator's responsibility; orphaned references are detected at next replay.
- BR-02: Work-items pin the workflow version they were created against. In-flight work-items continue to operate on their pinned version regardless of newer versions registered later.
- BR-03: Events are immutable. The event log is append-only. No update or delete primitive exists.
- BR-04: Cross-project links are not supported. Links are restricted to work-items in the same project DB.
- BR-05: The substrate is not a durable execution engine. It is a coordination + state plane. Workflow orchestration (Temporal-style) is a layer projects may add on top using substrate as the durable state record.
- BR-06: The substrate writes no project code, executes no project-supplied code outside of explicit hook contracts, and dispatches no notifications. All side effects are project-owned.
- BR-07: Hooks are declarative-only at registration; their implementations are project-owned. The substrate dispatches; the substrate does not embed a sandbox.
- BR-08: Postgres `now()` (transaction-stable) is the time authority. Agent-supplied clocks may live in `actor_metadata` for diagnostics but are not used for ordering or correctness.
- BR-09: **Authorization is enforced when actor roles are registered; audit-only when not.** HMAC verification proves `actor_id` (authenticated). The role used for role-gating (FR-12) is read from `actor_metadata.role` — an *actor-claimed* field. FR-24 adds an `actor_roles` table mapping `actor_id → allowed_roles`. When an actor has registered roles, FR-12 enforces that the claimed role is in the actor's registered set (rejects with `ACTOR_ROLE_NOT_AUTHORIZED` if not). When an actor has no registered roles, the claimed role is trusted (backward compatible with MVP behavior). The substrate guarantees a *signed audit trail* of which actor claimed which role for each transition; FR-24 makes this enforceable on a per-actor basis. `actor_metadata.role_source` ("config" / "env" / "prompt") provides post-hoc audit of misdeclaration sources.

- BR-10: **Concurrency contract.** Every event-producing operation on a work-item acquires a row lock on the canonical lock target (the work-item's row in `work_items_current`) via `SELECT FOR UPDATE` at the start of the transaction. All mutations on a given work-item serialize through this lock. Cross-work-item operations (links) acquire both rows in ascending `work_item_id` order to prevent deadlock. Isolation level: READ COMMITTED. See §17.

- BR-11: **Projection invariant.** `work_items_current` is fully derivable from `events`. Substrate writes to it only inside the event-append transaction. Direct `UPDATE` / `DELETE` on `work_items_current` outside the substrate's API is forbidden by contract; recommended Postgres role separation enforces this at the database level. Drift between the live projection and an event-log replay is detected via FR-16 `replay_report`. See §18.

- BR-12: **API-layer idempotency.** All event-emitting mutation operations (event append, transition, claim acquire / release, link create / remove) accept a client-supplied `event_id` (UUIDv4) that doubles as the idempotency key. Duplicate `event_id` returns the original result deterministically rather than producing a second logical operation; this makes caller-side retry across transient failures (DB connection drop, partial response) safe. Operations with structural idempotency do not take an explicit key: `register_workflow` is idempotent on `(workflow_name, version)` (the natural uniqueness constraint); `heartbeat_claim` is idempotent on `(work_item_id, actor_id, attempt_number)` (a repeated heartbeat from the same claim-holder simply extends the TTL). Consolidating idempotency on `event_id` — rather than carrying a parallel `idempotency_key` table — is sufficient because every audit-relevant mutation is now an event (BC-005), and the events table enforces `event_id` uniqueness via a database unique index (migration 014). Cross-work-item reuse of the same `event_id` raises `EVENT_ID_GLOBAL_COLLISION`.

- BR-13: **Per-project schema isolation is a load-bearing assumption, with a documented migration path.** The "one Postgres schema per project" choice (FR-19) is what makes cross-project queries impossible by construction (BR-04) and gives clean backup/restore boundaries. One shared database keeps the connection pool count constant regardless of project count. At homelab scale (≤10 projects, single operator, current design context), this is correct. It is NOT correct at multi-team / multi-org scale: hundreds of schemas can still be managed but a `tenant_id`-in-shared-schema model with row-level security becomes preferable. The public API (§19) is shaped so this boundary can shift without API changes: a `Substrate` handle owns one logical project namespace; whether that namespace maps to a dedicated schema or to a `tenant_id` partition within a shared schema protected by row-level security is internal. A future migration to tenant_id-in-shared-schema requires a one-time data move per project plus addition of a `project_id` column scoped by RLS to `events`, `work_items_current`, `claims`, `hook_queue`, `hook_dead_letter`, `workflow_registry`. No FR signature changes. Consumers should not assume schema-per-project as a permanent fixture; if a deployment approaches the operational pain threshold (subjective, but ~30+ projects is a fair signal), plan the migration before it compounds.

---

## 8. Error and Failure Handling

| Failure | Trigger | Response | Notification |
|---|---|---|---|
| Invalid YAML at registration | Workflow file fails YAML parse | Reject; error includes line number | Caller sees error |
| Schema-invalid workflow | Workflow file fails JSON Schema | Reject; error includes JSON pointer | Caller sees error |
| Semantically broken workflow | Reachability / terminal / role-binding check fails | Reject; error names the offending element | Caller sees error |
| Custom field type violation | Field value doesn't match declared type at create or transition | Reject; field-specific error; no partial write | Caller sees error |
| Invalid transition | Transition not declared in workflow for source state | Reject | Caller sees error |
| Role-gating violation | Actor's role not permitted for transition | Reject | Caller sees error |
| Concurrent claim contention | Two acquires on same work-item | First wins atomically; second receives "claim contested" | Caller sees rejection; not logged as error |
| Stale heartbeat | Heartbeat from agent who lost the lease | Reject with "claim lost" signal; agent must stop | Caller sees rejection |
| Sync hook failure | Hook raises or times out (default 5s) | Transaction rolls back; state unchanged; event NOT recorded | Structured log; caller sees error |
| Async hook failure | Hook raises during dispatch | Retry per backoff schedule; after max retries, move to dead-letter; emit `hook_dead_lettered` event | Structured log; observable via metrics |
| Dead-letter requeue failure | Re-failure after `requeue_dead_lettered_hook` | Same policy; back to dead-letter | Structured log |
| Unknown key_id at verify | Event signed with unrecognized key_id | Reject; structured log with `actor_id_claim`, `key_id_claim`, `event_id` (no signature) | Log only |
| Revoked key_id at verify | Event signed with revoked key | Reject; emit alert | Structured log |
| Revoked key encountered at replay | Replay hits a revoked-key event | Halt replay on that work-item; live projection untouched | Operator alert |
| DB connection failure mid-write | Postgres connection drops during operation | Surface error to caller; substrate does NOT retry; caller decides retry semantics | Caller sees error |
| Migrations not applied at startup | Schema version mismatch | Refuse to start with clear instruction | Operator runs migration |
| Substrate / workflow version mismatch | Registered workflow declares incompatible substrate version | Refuse to start | Operator decides upgrade or downgrade |
| Cross-project link attempt | Link target work-item not in same DB | Reject at link create | Caller sees error |
| Workflow version removed externally | Operator deletes a referenced row | Detected at next replay; replay fails on affected work-items | Operator alert |
| LISTEN/NOTIFY connection drop | Network blip in hook consumer | Polling fallback drains queue at 30s interval; consumer reconnects opportunistically | Structured log |
| Duplicate event_id on retry | Caller retries with same `event_id` | Return original result deterministically; no new event row; metric increments | Caller sees idempotent success |
| `expected_event_seq` mismatch | Optimistic-lock check fails | Reject with "concurrent modification"; caller may refetch state and retry | Caller sees rejection |
| NOTIFY payload would exceed 8KB | Hook event payload large | Library always uses wakeup-only NOTIFY (event_id reference); consumer reads full payload from `hook_queue` | Internal — not surfaced |
| Replay drift detected | Replay output differs from live `work_items_current` | Record in `replay_report` as `replayed_drift`; replay continues; operator action required | Operator alert via report |
| Concurrent workflow version registration | Two registrations of same `(name, version)` | Same content → idempotent (returns existing row); different content → rejects with `WORKFLOW_VERSION_CONFLICT` | Caller sees idempotent success or rejection |
| Actor role not authorized | Actor claims role not in their registered set | Reject with `ACTOR_ROLE_NOT_AUTHORIZED`; detail includes `actor_id`, `claimed_role`, `allowed_roles` | Caller sees rejection |
| Actor role already registered | Duplicate `register_actor_role` for same `(actor_id, role)` | Idempotent — silently returns without error | Caller sees idempotent success |
| Invalid actor kind | `actor_kind` not in {agent, human, system} | Reject with `INVALID_ACTOR_KIND` | Caller sees rejection |
| Actor role not registered | `unregister_actor_role` for nonexistent mapping | Reject with `ACTOR_ROLE_NOT_REGISTERED` | Caller sees rejection |
| Validator performs I/O (contract violation) | Validator code calls out to network/disk | Behavior undefined; operator-actionable structured log; treat as bug | Structured log |

---

## 9. Non-Functional Requirements

- **NFR-perf-1 — Claim acquisition latency:** p99 < 100ms at expected scale (≤50 concurrent agents per project, ≤10k active work-items per project). Sustained latency above 1s indicates a defect (missing index, lock contention, query plan regression) and should be investigated, not budgeted around. — *derived from: "what latency indicates a bug" framing; operator wants tight bounds at homelab scale.*

- **NFR-durability-1 — Event log durability (process / OS crash):** All committed events survive process and OS crash. Postgres `synchronous_commit = on`; substrate sets this **per session** on its own connections (does NOT assume cluster-level configuration). WAL fsynced before commit return; recovery via WAL replay on Postgres restart. — *derived from: "Zero loss tolerable... when you debug a stuck pipeline three days later, 'the event log is missing the bit where it broke' is the worst possible failure."*

- **NFR-durability-2 — Disk-level durability:** Out of substrate scope. Disk corruption / disk loss are operator backup concerns. — *derived from: "durability is against process and OS crash, not disk failure... that's a backup concern, separate NFR."*

- **NFR-dispatch-1 — Hook delivery mechanism:** Async hooks delivered via durable queue table; consumer wakeup via LISTEN/NOTIFY (latency optimization) AND fixed-interval polling sweep (correctness mechanism, runs always; default 30s). — *derived from: operator's preference to specify mechanism rather than latency, ensuring NOTIFY drop ≠ correctness break.*

- **NFR-dispatch-2 — Happy-path dispatch lag:** With consumer connected and NOTIFY received, p99 dispatch lag < 1s from event commit to hook execution start. — *derived from: "the next agent should be able to start immediately."*

- **NFR-dispatch-3 — Worst-case dispatch lag:** When NOTIFY is missed or consumer is reconnecting, dispatch lag bounded by polling interval (default 30s). — *derived from: explicit acknowledgment that NOTIFY is best-effort; polling is the floor.*

- **NFR-rotation-1 — Key rotation without downtime:** HMAC key rotation supported via key-set-with-status (`active` / `deprecated` / `revoked`); events carry `key_id`; deprecated-key use emits structured warning; revoked-key use rejects (including retroactively where re-verification occurs); hot-reload of key set without restart. — *derived from: "compatibility with minimal infra... constrains us least in terms of future growth."*

- **NFR-sync-hook-timeout — Sync hook bound:** Sync hooks bound by workflow-declared timeout; substrate default 5s; timeout = failure = transaction rollback. — *derived from: prevention of misbehaving hooks wedging a project by holding row locks.*

- **NFR-observability-1 — Operability:** Every substrate operation produces a structured log line with `project_id`, `work_item_id`, `operation`, `duration`, `outcome`, `actor_id`. Prometheus metrics expose substrate health. — *derived from: "for a substrate that orchestrates agent work, 'how do I know it's healthy' is going to bite eventually."*

---

## 10. High-Coupling Decisions

When resolving any of these during implementation, the implementing agent must explicitly note how the intent signals in Section 15 influenced the resolution.

| Decision | Status | Notes |
|---|---|---|
| Core data model | Decided | work-item / event / claim / actor / link shapes specified in FR-01 through FR-23. Event includes `event_id`, `work_item_id`, `event_seq`, `global_seq`, `actor_id`, `actor_kind`, `actor_metadata`, `on_behalf_of` (optional), `key_id`, `workflow_version`, `timestamp`, `transition`, `payload`, `prev_event_hash` (optional, BC-233). |
| State persistence strategy | Decided | Hybrid: events authoritative, `work_items_current` is a transactionally-consistent projection updated in same Postgres transaction as the event append. Rebuildable from events via FR-16. |
| Durable execution engine | Decided | None. Substrate is coordination + state, not orchestration. Postgres-only, library-mode. Projects may layer Temporal on top if needed. |
| Identity & authorization | Decided | Pluggable verifier. HMAC default with key-set-with-status; OIDC-ready via the same `actor_id` shape. Threat model: authenticated actors trusted not to misdeclare role; actor → allowed_roles deferred (see BR-09). |
| Schema versioning mechanism | Decided | Library version IS the contract version. Workflow declares `substrate_version`; FR-20 enforces compatibility at startup. Migrations ship with substrate library. |
| Per-project isolation mechanism | Decided | Separate Postgres schema per project within a shared database. Engine-enforced isolation via `search_path`; clean backup/restore per schema; cross-project queries impossible (which is the design intent). One schema hosts one project's workflow definitions. Single connection pool shared across all projects. |
| Hook dispatch contract | Decided | Sync hooks (in-process, gate transaction, 5s default timeout) AND async hooks (queue table + LISTEN/NOTIFY + always-on polling). Project picks per-hook in workflow def. |
| Deployment shape | Decided | Library. Substrate is imported and called as Python; runs in-process; talks directly to Postgres. Non-Python projects deferred (migration to sidecar would be additive). |
| Workflow file composition | Deferred with flexibility | Single-file workflows in v1. Loader can grow `!include` / merge conventions later without breaking existing files. |
| Schema partitioning policy | Single flat table | Migration 014 restored non-partitioned `events` with global `UNIQUE(event_id)`. Re-partitioning is a known recipe if a project exceeds ~10M events/month. |
| Actor → allowed_roles mapping | Decided | Implemented as FR-24 (Phase 3). `actor_roles` table; opt-in enforcement; backward compatible. Closes BR-09. |
| `continue_on_revoked` replay flag | Decided | Implemented as FR-25 (Phase 3). Replay skips revoked-key events with warning logging when flag is `True`. |
| Postgres version | Decided | Postgres 15+ required. No earlier-version compatibility guarantee. |
| Concurrency contract | Decided | Canonical lock = `work_items_current` row; `SELECT FOR UPDATE`; isolation READ COMMITTED; cross-work-item ordering ascending `work_item_id`. Specified in §17. |
| `event_seq` allocator | Decided | Gap-free per-work-item, allocated under canonical lock (§17.4). Trade-off: marginally slower per-write vs. dramatically simpler downstream consumer contract (no gap-handling logic). |
| Signing envelope | Decided | Pluggable `SigningScheme` (Plan 011): HMAC-SHA256 (default) or Ed25519. Key declares scheme in `KeyEntry.scheme`; `scheme_id` persisted on each event row. Envelope v3: RFC 8785 (JCS) canonical JSON of `{event_id, work_item_id, actor_id, key_id, event_seq, workflow_name, workflow_version, timestamp, on_behalf_of, transition, payload, prev_event_hash?, global_seq?}`. Keys with `None` values omitted. Backward compat: replay classifies envelope version (v3→v2→v1) at verification time. `prev_event_hash` (BC-233) chains each event to its predecessor: `SHA-256(prev_canonical_envelope ∥ prev_signature)`, stored as `prev_event_hash BYTEA`. `global_seq BIGSERIAL` enables coherent cross-WI timestamping (Plan 014). |
| Trust tiers in event fields | Decided | *Authenticated*: `actor_id`, `key_id` (scheme-verified). *Server-stamped*: `timestamp`, `event_seq`. *Actor-claimed*: all of `actor_metadata` (role, model, provider, role_source). |
| API-layer idempotency | Decided | Client-supplied UUIDv4 idempotency key required on every mutation. `event_id` doubles as the key for event append. Duplicates return original result. Optional `expected_event_seq` for optimistic locking. |
| Validator vs hook split | Decided | "Transition validator" = in-transaction, no I/O, gates commit. "Hook" = async, durable queue, retryable, dead-letter on max retries. Naming forces correct mental model. |
| Public API surface | Decided | Substrate exposes a protocol, not a Postgres connection. Public API takes unsigned event fields; library is sole signer (canonicalization + HMAC are internal). No Postgres connection / cursor / migration object leaks across the boundary. Service-wrapping is mechanical, not architectural (§19). |
| Consumer expectation boundary | Decided | Substrate is coordination + state, but already implements claims/TTL/escalation/hook dispatch. §20 enumerates explicitly what substrate does NOT do (dwell-time monitoring, work distribution, sagas, scheduling, notifications, SLAs, hierarchy rollups, role enforcement, project code execution) so consumers know what they must build above the substrate. |
| Project isolation as load-bearing | Acknowledged | Schema-per-project is correct at homelab scale and intentional (BR-04). Migration path to tenant_id-in-shared-schema documented in BR-13: API surface unchanged; one-time data move per project; RLS-scoped `project_id` columns added. Document set expectations rather than rearchitecting now. |

---

## 11. Acceptance Criteria and Test Plan

- AC-01 [FR-01]: Given a registered workflow with declared work-item-type, when a work-item is created, the work-item record contains workflow + pinned version, type, current state (initial), custom fields (default values), `needs_review=false`, and `not_before` (nullable).
- AC-02 [FR-02]: Given an unregistered workflow, when create is called, the operation rejects with "workflow not registered." Given an undeclared work-item-type, rejection with "type not declared in workflow." Given invalid initial custom field values, rejection with field-specific error and no partial write.
- AC-03 [FR-03]: Given a verified actor, when an event is appended, the row contains all specified fields including a per-work-item monotonic `event_seq`. Two events appended in the same transaction share `timestamp`; their `event_seq` differ and are monotonic.
- AC-04 [FR-04]: Given a state transition, the event row and the `work_items_current` row are updated in a single transaction; on transaction rollback, neither change is visible.
- AC-05 [FR-05]: Read-by-work-item returns events ordered by `(timestamp, event_seq)`. Read-by-actor / read-by-time-range / read-by-transition return correctly filtered results. Indexes support each query at NFR-perf-1 latency.
- AC-06 [FR-06]: Given a work-item with `not_before` in the future, claim acquisition rejects. Given an unclaimed work-item, two concurrent acquires result in exactly one success and one "claim contested" rejection.
- AC-07 [FR-07]: Given a valid claim, heartbeat before expiry succeeds and extends `expires_at`. Given a heartbeat from an actor whose claim was stolen (different `actor_id` in claim row, OR `attempt_number` advanced), heartbeat rejects with "claim lost."
- AC-08 [FR-08]: Explicit `release_claim()` clears the claim. A successful state transition clears the claim implicitly.
- AC-09 [FR-09a]: A query for claimable work-items excludes any whose `expires_at < now()`. `sweep_expired_claims()` removes expired rows; correctness does not depend on it being run.
- AC-10 [FR-09b]: An acquire on a work-item with an expired claim succeeds; the new claim row has `attempt_number = previous + 1`; the prior claim's history is preserved in the event log.
- AC-11 [FR-10] *(non-MVP)*: Once `attempt_number` reaches workflow-declared threshold, `needs_review=true` and exactly one `escalated` event is emitted (unique partial index ensures idempotency).
- AC-12 [FR-11]: A transition not in the work-item's pinned workflow version is rejected, even if it exists in a newer registered version.
- AC-13 [FR-12]: A transition by an actor whose role is not in the workflow's role-gating list for that transition is rejected.
- AC-14 [FR-13] *(non-MVP)*: Sync hook failure rolls back the transaction; sync hook timeout (default 5s) triggers rollback. Async hook is enqueued; on consumer connection it is delivered ≤ 1s p99; without consumer, polling sweep delivers within polling interval. Failed async hook retries per schedule; after max retries, lands in dead-letter and emits `hook_dead_lettered`.
- AC-15 [FR-14] *(non-MVP)*: `requeue_dead_lettered_hook(id)` resets retry counter and re-enqueues. Re-failure follows same policy.
- AC-16 [FR-15]: An event signed with unknown `key_id` is rejected; structured log includes `actor_id_claim`, `key_id_claim`, `event_id`; no signature contents in log. Revoked `key_id` rejects. Deprecated `key_id` accepts with structured warning.
- AC-17 [FR-16]: `replay()` produces `work_items_current_replay_<ts>` table; live `work_items_current` is unchanged. Each historical transition is validated against the workflow version recorded on its event. Encountering a revoked-key event halts replay on that work-item with operator alert.
- AC-18 [FR-17]: Workflow file with YAML syntax error rejects with line number. Schema-invalid file rejects with JSON pointer. Semantically broken file (unreachable state, undeclared terminal, undeclared role) rejects with element-named error. Valid file registers and is callable.
- AC-19 [FR-19]: Connecting to a non-existent project DB fails fast with operator-actionable error. Multiple workflow definitions register in a single project DB.
- AC-20 [FR-20]: Substrate refuses to start when migrations are outstanding. Substrate refuses to start when any registered workflow declares an incompatible substrate version.
- AC-21 [FR-21]: Every substrate operation produces a structured log with the specified fields. Prometheus counters are exposed and increment on the corresponding events.
- AC-22 [FR-22]: Link create with cross-project target rejects. Link create with disallowed type for the work-item-type pair rejects. Valid link creates and emits `link_created`. Target in terminal state still allowed.
- AC-23 [FR-23]: Link remove emits `link_removed`. Prior link history remains in event log.
- AC-24 [BR-12 / FR-03]: Calling event append twice with the same `event_id` produces exactly one row in `events`. The second call returns the result of the first deterministically. Same property for `event_id` on transition, claim acquire, claim release, and link create / remove (all event-emitting mutations). `heartbeat_claim` is structurally idempotent (repeated heartbeats from the same claim-holder extend TTL without producing duplicate effects) and does not take an explicit key; it may emit a `claim_heartbeat` event subject to coalescing (§17.10).
- AC-25 [FR-03]: Calling event append with `expected_event_seq` not equal to `current_max(event_seq) + 1` for the work-item rejects with "concurrent modification."
- AC-26 [FR-15]: Re-verifying a stored event's signature uses the stored `canonical_envelope` bytes, not jsonb re-serialization. A simulated jsonb-formatting change (e.g., key reordering on round-trip) does NOT invalidate previously verified events.
- AC-27 [FR-16]: `replay_report_<ts>` contains exactly one row per work-item processed, categorized as `replayed_ok`, `replayed_drift`, or `halted`. Drift count of zero is the success criterion for a no-bug projection.
- AC-28 [BR-10 / §17]: Two concurrent transitions on the same work-item serialize via row lock. Witnessed property: first sees `event_seq = N`, second sees `event_seq = N+1`; no duplicate seq; no skipped seq even under high contention. (Property test: dozens of concurrent threads, hundreds of operations.)
- AC-29 [BR-11 / §18]: A direct `UPDATE work_items_current SET current_state=...` performed outside the substrate API is detectable: the next replay reports the affected work-item as `replayed_drift`. (Operator role separation, when configured per §18.4, prevents this scenario at the database level.)
- AC-30 [FR-13]: A transition validator that performs I/O (e.g., HTTP call) is a contract violation. The substrate does not enforce this prohibition mechanically (validators are project code), but the spec contract is testable via documentation + linting helper (FR-18 fast-follow).
- AC-31 [FR-13]: NOTIFY payload for a hook event is always the `event_id` reference, never the full event payload. Consumer reads full payload from `hook_queue` keyed by `event_id`. Verified by inspecting raw NOTIFY messages.
- AC-32 [FR-05b]: A query with multiple filters (e.g., `workflow_name=X AND current_state IN (a, b) AND claimable_now=true`) returns exactly the work-items satisfying all filters. Pagination with the stable `work_item_id` cursor returns subsequent pages with no overlap and no skip, even when work-items matching the filter are concurrently appended-to during the scan (the cursor ordering is independent of `last_event_seq`). Indexes ensure p99 < NFR-perf-1 latency at expected scale.
- AC-33 [FR-15 / §19.2]: The public API rejects any attempt to submit a pre-signed event (a request shape carrying a caller-supplied `signature` or `payload_canonical_hash` field is refused with "library is sole signer"). Verified by attempting to construct such a request via the public API and observing the rejection.
- AC-34 [§19.4]: No public API type signature exposes a Postgres connection, cursor, session, ORM model, migration object, raw SQL string, or jsonb canonicalization helper. Verified by static inspection of the public API module's exports against the forbidden list in §19.4.
- AC-35 [FR-24]: An actor with no registered roles can perform any transition whose `allowed_roles` includes their claimed role (backward compatible). An actor with registered roles who claims a role NOT in their registered set is rejected with `ACTOR_ROLE_NOT_AUTHORIZED`, even if that role is in the transition's `allowed_roles`. An actor with registered roles who claims a role IN their registered set is accepted. Error detail includes `actor_id`, `claimed_role`, `allowed_roles`.
- AC-36 [FR-25]: `replay(continue_on_revoked=True)` produces a report with `halted == 0` and `warnings >= N` where N is the number of events signed with revoked or unknown keys, and the replayed state matches the live projection for all work-items. `replay(continue_on_revoked=False)` halts on the first revoked-key event (unchanged behavior).
- AC-37 [FR-26]: `update_not_before()` emits a `not_before_set` event and updates the projection. Subsequent `acquire_claim()` respects the new value. Setting to `null` clears the gate. Replay correctly derives `not_before` from the most recent `not_before_set` event.
- AC-38 [FR-27]: A transition with `custom_fields_update` containing an invalid enum value, unknown field name, or wrong type is rejected with `CUSTOM_FIELD_VIOLATION`. No partial write occurs. Valid updates are applied and persisted in both the event payload and the projection.

**Untestable items:**

| Item | Reason |
|---|---|
| Disk-level durability behavior under hardware failure | External dependency (hardware) — operator backup concern, not testable in substrate scope |
| HMAC verifier behavior under future OIDC integration | Future code — testable when the OIDC verifier is added |
| Cross-language non-Python agent integration | Out of MVP — sidecar deferred |
| Federated UI rendering correctness | Different system; substrate testable independently |

---

## 12. Work Decomposition

### Value Phases — owned by the operator

- **Phase 1 (MVP):** FR-01, FR-02, FR-03, FR-04, FR-05, FR-05b, FR-06, FR-07, FR-08, FR-09a, FR-09b, FR-11, FR-12, FR-15, FR-16, FR-17, FR-19, FR-20, FR-21, FR-22, FR-23 — substrate replaces `reasoning.log` for one Software Factory workflow with durable claims, role enforcement, replay, structured work-item discovery, and observability.
- **Phase 2 (Fast-follow):** FR-10 (escalation flag), FR-13 (hooks), FR-14 (dead-letter requeue), FR-18 (lint helper) — adds reactivity once consumers exist.
- **Phase 3 (Authorization + replay resilience):** FR-24 (actor → allowed_roles enforcement), FR-25 (continue-on-revoked replay flag) — closes BR-09; makes replay practical after key rotation.
- **Phase 4 (Future):** Federated UI; OIDC verifier; workflow file composition; operator-driven archival.

### Implementation Phasing — owned by the implementing agent

The implementing agent determines build sequence based on architectural dependencies. This includes invisible infrastructure (DB schema, migrations, HMAC key loading) that must exist before user-facing FRs can be exercised.

**Known prerequisites identified during spec:**
- All MVP FRs require Postgres schema (`events`, `work_items_current`, `claims`, `workflow_registry`, `hook_queue`) and a migration framework — substrate-ships, runs on first boot.
- FR-02, FR-06, FR-11, FR-12 require FR-17 (workflow registry + parser) before they have anything to validate against.
- FR-03, FR-06, FR-07, FR-08, FR-09b, FR-16, FR-22, FR-23 require FR-15 (verified actor) before any event can be recorded.
- FR-15 requires HMAC key set loading — K3s Secret with documented JSON shape; substrate reads secret name from project config.
- Operator precondition: project DB exists. Substrate fails fast otherwise.

**Dependency hints** *(intent-level only):*
- FR-17 likely first; FR-15 second; then FR-01/FR-02/FR-03/FR-04 (the create path); then FR-05/FR-05b (read + structured query); then FR-06/FR-07/FR-08/FR-09a/FR-09b (claim lifecycle, which depends on FR-05b for claim-discovery); then FR-11/FR-12 (validation); then FR-22/FR-23 (links); then FR-16 (replay); FR-20 / FR-21 cross-cutting.

**Limitation:** Dependency hints reflect intent and logical inference. Implementing agents must derive actual build order from the codebase. Do not treat these as authoritative.

---

## 13. Open Questions

| Question | Category | Owner |
|---|---|---|
| Workflow file composition (`!include` / cross-file merge) | Cheap to change | Implementing agent — additive |
| Per-hook retry override defaults — what's the right per-hook tuning? | Cheap to change | Project authors at use time |
| Disk-level durability / backup policy | Out of scope | Operator |
| Real scheduler beyond `not_before` | Cheap to change | Future scope; `not_before` reserves the design space |
| ~~Actor → `allowed_roles` enforcement~~ | **Resolved v4** | Implemented as FR-24. |
| ~~`--continue-on-revoked` replay flag~~ | **Resolved v4** | Implemented as FR-25. |
| ~~Domain-expert review for distributed-systems correctness~~ | **Resolved v2** | Two-reviewer correctness pass completed. |

---

## 14. Assumptions

- Postgres is available on the homelab K3s cluster and is healthy enough to provide standard ACID semantics. Rationale: explicitly stated in vibe spec.
- The operator runs all agents and trusts them not to misdeclare their role by default (actor-claimed trust tier). FR-24 provides opt-in enforcement when the threat model warrants it. Rationale: homelab single-operator context; enforcement is available but not required.
- Workflow files are authored by the operator (not by untrusted parties). Rationale: homelab single-operator context; YAML parsing safety follows from this.
- License-cost-bound but token-spend unconstrained — substrate may be liberal with logging detail and event payload size. Rationale: stated explicitly in vibe spec.
- Federated UI design is downstream and will adapt to the substrate's contract, not vice versa. Rationale: vibe spec states UI is future; substrate is authoritative source.
- Python is acceptable as the substrate's implementation language. Rationale: existing factory codebase is Python; Q1 answer "library; if we need non-Python, trivial to migrate" implies acceptance for MVP.

---

## 15. Handoff State

**Decisions made:**
- Library deployment, in-process Postgres calls. Migration to sidecar is additive if non-Python actors arrive.
- Hybrid persistence: events authoritative, `work_items_current` transactionally projected. Single Postgres transaction per state change.
- Postgres-only coordination; substrate is not a durable execution engine. Temporal-style orchestration is a layer projects may add on top.
- Per-project schema isolation; one schema per project within a shared database; multiple workflows per schema. Database is a precondition; `create_project()` creates the schema and runs migrations.
- Workflow files are versioned in a per-project registry; entries are immutable once referenced; work-items pin the version they were created under; replay validates against historical versions.
- Custom fields are per-workflow-per-work-item-type with declared types and `ui_visible` flag (default `false`).
- Side effects via hooks: sync (in-transaction, 5s default timeout) or async (durable queue + LISTEN/NOTIFY + always-on polling).
- Identity via pluggable verifier; HMAC default with key-set-with-status (active/deprecated/revoked); events carry `key_id`; OIDC-ready via the same actor model.
- Postgres `now()` is the time authority; `event_seq` provides per-work-item total ordering.
- Links are events (`link_created` / `link_removed`); current links are derived; cross-project links unsupported.
- Substrate does not retry on connection failure; caller's responsibility.
- Workflow registry is append-only — no removal primitive.
- **(v2)** Concurrency contract: canonical lock target = `work_items_current` row; READ COMMITTED + row lock; gap-free per-work-item `event_seq` allocator (§17).
- **(v2)** Projection invariant: `work_items_current` fully derived from `events`; no out-of-band updates; drift detected via FR-16 replay report (§18).
- **(v2)** API-layer idempotency: client-supplied UUIDv4 on every mutation; `event_id` doubles as event-append idempotency key; optional `expected_event_seq` for optimistic locking.
- **(v2)** Signing: HMAC-SHA256 over RFC 8785 canonical JSON envelope `{event_id, work_item_id, actor_id, transition, payload}`; canonical hash stored alongside signature for jsonb-independent re-verification.
- **(v2)** Renaming: in-transaction side effects are *transition validators* (no I/O, gate commit); async side effects are *hooks* (durable queue, retryable). The split forces the right mental model.
- **(v2)** Closed custom field type vocabulary: `string`, `integer`, `boolean`, `timestamp`, `json`, `enum`, `work_item_ref`. Expansion requires a substrate minor version bump.
- **(v2)** Trust tiers on event fields: *authenticated* (`actor_id`, `key_id`) / *server-stamped* (`timestamp`, `event_seq`) / *actor-claimed* (`actor_metadata`). BR-09 elevated from "fast-follow" to "audit, not enforcement, in MVP."
- **(v3)** Structured work-item query (FR-05b) added as MVP. Closes the API gap where agents would otherwise reach into `work_items_current` directly to discover claimable work.
- **(v3)** Public API surface formalized (§19): protocol, not a Postgres connection. Substrate library is the sole sanctioned signer; canonicalization is internal. Service-wrapping is mechanical, not architectural.
- **(v3)** Consumer expectation boundary (§20): explicit enumeration of what substrate does NOT do (dwell-time monitoring, work distribution, sagas, scheduling, notifications, SLAs, hierarchy rollups, role enforcement, project code execution).
- **(v3)** Per-project DB isolation (BR-13) acknowledged as load-bearing; migration path to tenant_id-in-shared-DB documented. API surface unchanged either way.
- **(v4)** Isolation model updated: schema-per-project (one database, one schema per project) replaces the originally specified DB-per-project. Connection pool shared across all projects; `SET LOCAL search_path` scopes each transaction. FR-19, BR-13, and §10 decisions table updated accordingly. Rationale: eliminates per-project connection pools, reduces operational overhead, maintains the same isolation guarantees via engine-enforced `search_path`.
- **(v4)** Actor → allowed_roles enforcement (FR-24): opt-in enforcement via `actor_roles` table. Actors with no registered roles are trusted; actors with registered roles must claim a role in their set. Closes BR-09.
- **(v4)** Continue-on-revoked replay flag (FR-25): `replay(continue_on_revoked=True)` skips revoked-key events with warnings instead of halting. `ReplayReport.warnings` tracks count.
- **(v4)** Postgres version pinned to 15+. Retention policy: always-grow at homelab scale; re-partition at ~10M events/month if needed.
- **(v4)** `update_not_before()` API (FR-26): closes the spec gap where `not_before_set` events existed in replay but no API could produce them. Emits event, updates projection, supports idempotency.
- **(v4)** Custom field validation at transitions (FR-27): extends creation-time validation (FR-02) to the update path. Rejects unknown fields and type mismatches in `custom_fields_update`.

**Pending / deferred:**
- Event log retention policy: always-grow at homelab scale; re-partition at ~10M events/month if needed (see §16).
- Workflow file composition (`!include`): deferred; loader extension is additive.
- `--continue-on-revoked` replay flag: ~~deferred operator-tooling concern~~ **Implemented as FR-25.**
- OIDC verifier implementation: deferred until human users arrive.
- Sidecar / non-Python integration: deferred until needed.

**Intent signals (from the original vibe spec):**
- *"Generalize it and have it work for all projects more generally"* — relevance: substrate must be project-agnostic; resist factory-specific concepts leaking into core schema.
- *"One source of truth for all projects ... one pane of glass we can feed projects into when we eventually make a human readable UI"* — relevance: shape the contract so federated UI is additive, not a redesign trigger. Workflow definitions, custom fields with `ui_visible`, and event log shape all serve this.
- *"Non-revenue homelab project; license costs are the binding constraint, token spend is not"* — relevance: prefer richly-logged, verbose, debug-friendly implementations over throughput-optimized; never select tools by per-seat licensing.
- *"Compose with, not replace, the existing reasoning.log convention"* — relevance: substrate must not assume sole ownership of agent state; reasoning.log continues to coexist.
- *"Currently zero humans-in-the-loop, but the design should not foreclose that"* — relevance: actor model and identity verifier shaped to accept humans without schema migration; keep `ui_visible` and pluggable verifier honest.
- *"Idempotency and exactly-once semantics per task type, not globally"* — relevance: substrate doesn't enforce exactly-once globally; per-hook retry policy and dead-letter behavior are project-tunable; sync-hook-rollback gives exactly-once-per-transition where needed.
- *"What's substrate concern vs. agent concern"* — relevance: substrate is coordination + state; agents own work, hooks, scheduling, retries beyond the dispatch primitive. Resist scope creep.
- *"Minimum API surface needs to be to keep a future UI cheap"* — relevance: read-event-log primitives (FR-05) and current-state queries are the UI's primary surface; design indexes and query shapes for the UI's future use, not just hot-path agent operations.

---

## 16. Delta to Next Level

What would be required to reach Level 3:

- ~~Resolve domain-expert review pass: distributed-systems correctness review of the event-sourcing + transactional-projection model, the sync/async hook semantics, the claim race conditions, and the replay-into-fresh-table approach.~~ **Resolved v2.** Two-reviewer correctness pass completed.
- ~~Decide actor → `allowed_roles` mapping concretely (in or out for v2; if in, the data model adjustment needed).~~ **Resolved v4.** Implemented as FR-24. Opt-in enforcement via `actor_roles` table. Backward compatible.
- Decide event log retention policy concretely (always-grow vs. re-partition trigger threshold vs. archival-to-cold-storage SOP). **Deferred with guidance:** always-grow is correct for homelab scale (≤10k work-items, ≤100k events per project). Re-partitioning is a known recipe if a single project exceeds ~10M events/month. Operator-driven archival is a separate concern. Migration 014 restored a single flat `events` table; re-introducing partitioning later is a focused 1–2 week project when actually needed.
- Decide on a workflow file composition mechanism if and when needed (or formally drop it). **Deferred.** Single-file workflows in v1. Loader can grow `!include` / merge conventions later without breaking existing files. No concrete need identified.
- Pin Postgres major version supported and document the matrix. **Decided v4.** Postgres 15+ required (used in test infrastructure; features used: JSONB, LISTEN/NOTIFY, `FOR UPDATE` row locks, declarative partitioning available when needed). No Postgres-14-or-earlier compatibility guarantee.
- Decide initial workflow definition for the first Software Factory pilot — needed before MVP can ship, but is a downstream artifact, not a substrate concern. **Not a substrate decision.** Operator defines the pilot workflow.

---

## 17. Concurrency Contract

This section is normative. All implementations of substrate operations must conform. It exists because correctness depends on a single canonical serialization mechanism for per-work-item state; without it, multiple agents will infer incompatible locking strategies.

### 17.1 Isolation level

All substrate transactions run at Postgres isolation level **READ COMMITTED**. SERIALIZABLE is not required; substrate provides serialization via explicit row locks at well-defined points. REPEATABLE READ and SERIALIZABLE are not supported (substrate has not been designed against their stricter semantics; using them may surface false-positive serialization failures with no correctness benefit).

### 17.2 Canonical lock target

For each work-item, the row in `work_items_current` is the canonical lock target. Every event-producing operation begins by acquiring `SELECT ... FOR UPDATE` on that row (or `SELECT ... FOR UPDATE` on the work-item-create stub at creation time). All mutations on a given work-item serialize through this lock.

### 17.3 Operations that take the lock

Mutating operations (always lock):

- Event append (FR-03)
- State transition (FR-11) — append + projection update + transition validator dispatch, all within the locked region
- Claim acquire (FR-06), heartbeat (FR-07), release (FR-08), auto-steal (FR-09b)
- Link create (FR-22), link remove (FR-23) — see 17.6 for cross-work-item ordering

Non-locking operations:

- Event log read (FR-05) — MVCC snapshot semantics
- Workflow registry operations (FR-17) — operate on `workflow_registry`, which has its own uniqueness constraints
- Replay (FR-16) — operates on a snapshot; live `work_items_current` untouched

### 17.4 `event_seq` allocator

`event_seq` is **gap-free** and monotonic per work-item. Allocation happens within the locked region:

- **Recommended implementation:** a `next_event_seq` column on `work_items_current`. Read under lock, write back +1, use the read value as the new event's `event_seq`. O(1).
- **Alternative:** `SELECT COALESCE(MAX(event_seq), 0) + 1 FROM events WHERE work_item_id = $1` under the lock. O(log n) with index on `(work_item_id, event_seq)`. Functionally equivalent.

Because the canonical lock is held, no other writer to the same work-item can interleave; allocation is race-free. Gaps in `event_seq` indicate corruption (a failed in-region append that was somehow not rolled back) and are detectable by FR-16 replay.

### 17.5 Lock release

Locks are released at transaction commit or rollback (Postgres default behavior). Substrate does not use Postgres advisory locks, application-level mutexes, or non-Postgres synchronization primitives. The single mechanism is row-level `SELECT FOR UPDATE` on the canonical lock target.

### 17.6 Cross-work-item operations

`link_create` and `link_remove` touch two work-item rows. To prevent deadlock, lock acquisition order is **ascending `work_item_id`**:

```sql
SELECT * FROM work_items_current
WHERE work_item_id IN ($1, $2)
ORDER BY work_item_id
FOR UPDATE;
```

This is the only deadlock-relevant interaction in the substrate; all other operations touch a single work-item.

### 17.7 Race interaction matrix

For two concurrent operations on the same work-item:

| Op A vs Op B | Outcome |
|---|---|
| acquire vs acquire | first wins via row lock; second receives "claim contested" rejection |
| acquire vs heartbeat | serialize via row lock; if heartbeat sees different `actor_id` or advanced `attempt_number`, rejects with "claim lost" (FR-07) |
| heartbeat vs heartbeat (same actor) | serialize; both succeed; later one's `expires_at` wins |
| heartbeat vs heartbeat (different actor) | second rejects with "claim lost" |
| transition vs transition | serialize; second sees post-A state and validates against it |
| transition vs acquire | serialize; transition releases claim implicitly; subsequent acquire then proceeds |
| link create vs link create (same logical link) | serialize; `event_id` dedups if same logical operation |
| event append vs event append (same `event_id`) | second is treated as idempotent retry; returns first's row (BR-12) |

### 17.8 Connection lifecycle

Substrate sets `synchronous_commit = on` per session on its own connections (NFR-durability-1). Substrate does not assume cluster-level configuration, and does not mutate cluster-level configuration. Connection pool settings (size, idle timeout, max lifetime) are operator-tunable; defaults are sized for ≤50 concurrent agents per project.

### 17.9 Trust tiers in event fields

Consumers (UI, audit tooling, replay validators) MUST distinguish:

| Tier | Fields | Trust property |
|---|---|---|
| Authenticated | `actor_id`, `key_id` | Scheme-verified (HMAC-SHA256 or Ed25519); tampering detected at re-verification (AC-26) |
| Server-stamped | `timestamp`, `event_seq` | Substrate writes; not under actor control; trustworthy modulo substrate bugs |
| Actor-claimed | All of `actor_metadata` (incl. `role`, `model`, `provider`, `role_source`, `context_hash`, `prompt_template_hash`) | Signed-by-actor (so non-repudiable that *this actor said this*). When FR-24 actor roles are registered, `role` is additionally enforced against the actor's registered set; otherwise treated as diagnostic. |

The federated UI and downstream consumers should surface this distinction visually (e.g., role displayed with a "claimed" qualifier until enforcement lands) rather than treating all event fields as equally authoritative.

### 17.10 Heartbeat invariant

Heartbeats (`heartbeat_claim`, FR-07) extend `claim_expires_at` by `ttl_seconds`. Since BC-194, heartbeats emit a `claim_heartbeat` event **coalesced** on a threshold: a heartbeat event is appended only when `(new_expires_at - last_emitted_expires_at) >= threshold`. The default threshold is `max(60s, ttl_seconds/2)`; callers may override via the `coalesce_threshold` parameter.

This makes `claim_expires_at` replayable within a bounded tolerance: replay updates `derived_claim_expires_at` on each `claim_heartbeat` event, and drift detection tolerates differences up to the last emitted threshold. The `claims` row remains the authoritative source for live claim liveness; the projection column is a cache.

Between coalesced heartbeats, the live `claim_expires_at` may be ahead of the replayed value by up to `coalesce_threshold`. This is expected and not reported as drift. A NULL `claim_expires_at` with a non-NULL `claimed_by` is treated as non-expired by `resolve_heartbeat`; this is by design.

---

## 18. Projection Invariants

`work_items_current` is a denormalized projection of `events`. This section defines what that means precisely, what guarantees the substrate makes about it, and how drift is detected.

### 18.1 Authoritative source

The `events` table is the single authoritative source of work-item state. Every column on `work_items_current` is derivable from `events` for that `work_item_id`. There are NO fields on `work_items_current` that exist *only* there.

### 18.2 Substrate-managed fields on `work_items_current`

Each row reflects:

- `work_item_id`
- `workflow_name`, `workflow_version` — derived from the `created` event (pinned thereafter, BR-02).
- `work_item_type` — derived from the `created` event.
- `current_state` — derived from the most recent state-changing event.
- `custom_fields` (jsonb) — derived from the cumulative effect of state-changing events.
- `needs_review` (bool) — derived from the most recent `escalated` event (FR-10).
- `not_before` (timestamptz) — derived from the most recent `not_before_set` event.
- `last_event_seq` — equal to `MAX(event_seq)` for that `work_item_id`.
- `last_event_at` — equal to `timestamp` of the latest event.
- `next_event_seq` — equal to `last_event_seq + 1`; convenience column for the allocator (§17.4).

`current_links` is **NOT** projected onto `work_items_current`. Links are derived on demand from `link_created` / `link_removed` events. (Justification: link cardinality varies; projecting them creates a separate denormalization with its own consistency burden. Read-time derivation is fine for MVP scale.)

### 18.3 Update protocol

Substrate updates `work_items_current` **only** inside the same transaction as the corresponding event append, after the event row has been inserted, before commit, while the canonical lock (§17.2) is held.

No other code path writes to `work_items_current`. Direct `UPDATE` / `DELETE` outside the substrate API is forbidden by contract.

### 18.4 Postgres role separation (recommended)

To enforce the projection invariant at the database level, the operator should grant the application a Postgres role with:

- `INSERT, SELECT` on `events`
- `SELECT, UPDATE` on `work_items_current` (only via substrate's stored functions if the substrate ships them)
- `INSERT, SELECT, UPDATE` on `claims`, `hook_queue`, `hook_dead_letter`
- `INSERT, SELECT` on `workflow_registry`
- No `DELETE` on any of the above

This is recommended, not required. Substrate operates correctly without it; role separation defends against bugs in adjacent application code that might "fix" projection rows by hand.

### 18.5 Drift detection

Drift is detected by replay (FR-16). The `replay_report_<ts>` table categorizes each work-item:

- `replayed_ok` — replayed final state matches live `work_items_current`.
- `replayed_drift` — replayed final state differs from live. **This is an actionable defect signal.** Possible causes (in descending order of likelihood):
  1. Bug in substrate's projection update logic.
  2. Direct edit to `work_items_current` outside substrate API (forbidden by 18.3; defended by 18.4 if role separation is configured).
  3. Missed event (corruption; rare; usually accompanied by `event_seq` gaps).
- `halted` — replay could not complete on this work-item; halt reason recorded.

Operator workflow: replay periodically (e.g., nightly cron) as a correctness audit. Cost ≈ full table scan of `events`; for MVP scale (≤10k work-items per project), runs in minutes.

### 18.6 What `work_items_current` is NOT

`work_items_current` is **not**:

- A cache. It is transactionally consistent with `events`, not eventually consistent.
- A view. Materialized views cannot be transactionally updated alongside event inserts at this isolation level; the projection is a real table.
- A fast path that may be slightly stale. Reads against `work_items_current` see the same data as a replay-derived projection (modulo bugs surfaced by 18.5).

Consumers MAY assume that a successful read of `work_items_current` reflects the result of every committed event up to the read's MVCC snapshot. This is the contract that justifies its existence; without it, every read would have to traverse the event log.

---

## 19. Public API Surface

This section is normative. The substrate's public API is a **protocol**, not a set of free functions over an exposed Postgres connection. Any implementation — current in-process Python library, future sidecar over HTTP/gRPC, future federated UI service layer — MUST conform.

### 19.1 Boundary

The public API consists of the operations enumerated in FRs 02–08, FR-05b, FR-11, FR-14, FR-16, FR-17, FR-22, FR-23. Callers interact with a `Substrate` handle that owns one logical project namespace (see BR-13). The handle exposes those operations and nothing else. No `psycopg.Connection`, SQLAlchemy session, migration-runner state, raw SQL string, or jsonb canonicalization helper crosses the API boundary.

### 19.2 Signing

The substrate library is the sole sanctioned signer (FR-15). The API accepts unsigned event field tuples; the library performs RFC 8785 canonicalization, signs using the key's declared scheme (HMAC-SHA256 or Ed25519, per `KeyEntry.scheme`), and persists the event. The API does NOT accept pre-signed events from callers and rejects any request shape carrying a caller-supplied `signature` or `payload_canonical_hash` field.

This invariant is what makes the canonicalization choice (RFC 8785) sustainable: it is implemented exactly once, in one place. If callers were permitted to sign, every implementation of JCS in the ecosystem would have to be byte-identical, and the audit-trail promise would silently rot the first time one of them diverged.

### 19.3 Service-wrapping is mechanical

A future sidecar exposing the substrate over HTTP/gRPC must:

- Mirror the public operations 1:1. No consolidation, no "convenience" endpoints that bundle multiple operations behind a single call. Each public operation is independently invokable with the same argument shape.
- Accept unsigned event fields and sign inside the sidecar process. Pre-signed events on the wire are rejected, the same as in-process.
- Surface trust tiers (§17.9) in response shapes so non-Python clients can reason about field provenance.
- Honor BR-12 idempotency: same key, same response, regardless of network retry topology.

If the wrapper has to invent semantics not present in the library API to be useful, the library API is incomplete; fix the library, not the wrapper.

### 19.4 Forbidden API leaks

The following MUST NOT appear in any public type signature, return type, or exception payload:

- Postgres connections, cursors, sessions
- ORM models or row objects from any framework
- Migration objects or migration-runner state
- Raw SQL strings
- Jsonb canonicalization helpers (these are internal; see 19.2)

Internal types may exist throughout the substrate's implementation. They are not part of the API. Static inspection of the public API module (AC-34) verifies conformance.

### 19.5 What the API DOES expose

Stable, language-agnostic shapes:

- Domain types: `WorkItem`, `Event`, `Claim`, `WorkflowDefinition`, `WorkflowVersion`, `Link`, `ActorIdentity` — value objects with documented JSON serialization.
- Operation results: `AppendResult`, `ClaimResult`, `QueryPage` (with cursor), `ReplayReport`, `RegistrationResult`.
- Errors: enumerated, named, machine-distinguishable (`workflow_not_registered`, `claim_contested`, `claim_lost`, `concurrent_modification`, `invalid_transition`, `role_not_permitted`, `library_is_sole_signer`, `idempotency_collision_with_different_payload`, `signing_scheme_not_found`, `tsa_not_configured`, `tsa_submission_failed`, `tsa_verification_failed`, etc.). Error codes are part of the API contract.

---

## 20. Consumer Expectation Boundary

BR-05 says substrate is "coordination + state, not orchestration." That label is necessary but not sufficient: substrate already implements claims-with-TTL, attempt tracking, escalation, hook dispatch with retry and dead-letter, and transition validators — much of what consumers associate with orchestration. This section enumerates explicitly what substrate does NOT do, so consumers know what they must build above the substrate rather than assuming substrate handles it.

Substrate does NOT:

- **Detect work stuck in a state for too long.** No "this work-item has been in state X for N hours, escalate" primitive. Attempt-based escalation (FR-10) fires on claim-attempt count, not on wall-clock dwell time. Dwell-time monitoring is a consumer concern; the substrate provides the timestamps in the event log to compute it.
- **Distribute or assign work to actors.** Work-items are claimed by actors who poll FR-05b for claimable work; substrate does not push, route, prioritize, or load-balance. Work-stealing patterns are consumer-built on top of the claim primitives.
- **Coordinate sagas across multiple work-items.** Each event-producing operation is single-work-item (links touch two rows for ordering, but there is no multi-step transaction across work-items). Saga / compensation patterns are consumer concerns; substrate provides the durable state record they would persist progress to.
- **Schedule work for future execution.** `not_before` is a *gate*, not a scheduler — nothing wakes up at `not_before` to dispatch work. Consumers poll. A scheduler engine is explicitly out of scope (§3).
- **Notify, page, alert, or message anyone.** Escalation emits an event; consumers wire up the rest. Substrate sends no email, Slack, webhook, or push notification except via project-defined hooks the project itself implements.
- **Enforce SLAs or deadlines.** No "must complete by" semantics, no deadline timers, no auto-cancel on missed deadline.
- **Track work hierarchies or rollups.** Parent/child relationships are link-type conventions; substrate does not aggregate state ("all children done → parent ready"). Hierarchy semantics are project-defined via link types and consumer-side queries.
- **Validate that an actor's claimed role is one the actor is entitled to claim.** FR-24 provides opt-in enforcement: when an actor has registered roles via `register_actor_role`, the claimed role is validated against the actor's allowed set. When no roles are registered for an actor, the claimed role is trusted (actor-claimed per §17.9). Full RBAC (hierarchical roles, role derivation, dynamic role assignment) is not provided — consumers needing richer authorization layer such a system above substrate.
- **Run project code in-process beyond the validator/hook contracts.** No sandbox, no in-process plugins, no expression language. Project authors own all side-effect code.
- **Provide a workflow execution engine.** Substrate is a state record with transition validation; it is not Temporal. Consumers needing durable execution semantics (timers, retries-as-orchestration-primitive, child workflows, signals) layer such an engine above and use substrate as the state plane.

If a consumer's mental model assumes any of the above, the consumer is building on a substrate that does not exist. Either lift the missing capability into a layer above substrate, or contribute it back as a substrate FR — and accept the corresponding scope expansion. This list is explicit precisely because the "coordination, not orchestration" label is too easily misread, and the most common adoption failure mode is "I thought substrate would handle X."
