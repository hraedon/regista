# Plan 032 · F0 — Dependency map and deletion boundary

**Status:** Evidence. Produced for Plan 032 §4 F0 items 2 and 3 (trace the public
path; map deletions). No source, schema, tests, or published artifacts were
changed while producing it.

**Baseline measured:** `main` at `899c7f8` (working tree carries two unrelated
test edits and the Plan 032 draft, both untouched here). Package version `0.7.2`.
**Date:** 2026-09-17.

## 1. What was measured, and what was not

A static intra-package import graph over `src/regista` (112 modules, 77,506 LOC,
636 intra-package edges), plus direct inspection of the CLI command table, the
test tree, and the 50 SQL migrations.

This measures **import coupling and schema shape**. It does not measure semantic
coupling: a module that imports nothing from the trust stack can still require a
signed event to exist, or a genesis row to be present, at runtime. Two specific
gaps remain open for the rest of F0:

- **Runtime preconditions.** Nothing here proves the retained kernel *runs*
  without the removed stack. §5's schema findings show it currently cannot.
- **Test semantics.** Test files were classified by the concepts they name, not
  by what they assert. The retirement set in §4 is a candidate list requiring
  per-file disposition, per Plan 032 F0 item 4.

Classification follows Plan 032 §3. `OPTIONAL` means "Plan 032 removes this by
default, and F0 has not yet ruled" — it is not a recommendation.

## 2. Module classification

| Category | Modules | LOC | Share |
| --- | ---: | ---: | ---: |
| KERNEL — Plan 032 §3 "Keep and qualify" | 40 | 22,610 | 29.2% |
| TRUST — §3 "Remove by default" + Signing | 41 | 46,840 | 60.4% |
| OPTIONAL — recurrence, hooks, webhooks, sidecar, in-memory engine | 31 | 8,056 | 10.4% |
| **Total** | **112** | **77,506** | |

Three corrections to the obvious reading, all material:

- **`_contract` (898 LOC) is kernel, not trust.** It is the kernel's own
  validation layer: transition resolution, role gating, idempotency, claim
  acquire/heartbeat/release, link types, JSON safety, actor IDs — Plan 032's keep
  table almost line for line. 27 modules import it, overwhelmingly kernel and
  in-memory ones, which is itself the evidence. Only `validate_model_lineage`
  (model-lineage registry, on the remove list) and a function-local
  `validate_principal_id` reach out of it.
- **`_jcs` / `_vendor.rfc8785` are kernel.** Plan 032 §3 permits canonical
  serialization to remain. `_jcs` is a nine-line wrapper over RFC 8785.
- **`_reducer` (517 LOC) is trust, not kernel** — the one that goes the other
  way. Its name and its position in the event pipeline suggest the projection
  reducer. It is not. It is "Reducer v1 — the deterministic reduction of a signed
  event prefix," the function `content_state_digest` is computed over, and a
  signed review verdict binds itself to that digest. It is review-verdict
  machinery, which Plan 032 removes. It is also **imported by no production
  module at all** — only `tests/test_reducer_v1_determinism.py`,
  `tests/test_v6_vectors.py`, `tools/make_v6_vectors.py` and
  `tools/reducer_v1_sweep.py`. It is off the runtime path entirely.

  Worth preserving from it before deletion, because it is a measured finding and
  not an assumption: `datetime.fromisoformat` **accepts a different language on
  different interpreters** — CPython 3.14 parses `"2026-08-09T24:00:00Z"` as the
  following midnight, while CPython 3.12, 3.13 and PyPy 3.11 raise. Any retained
  kernel code that parses timestamps across the declared support matrix inherits
  that hazard. F0 item 5 chooses the Python range; this is an input to it.

**How much trust the kernel actually drags in.** The transitive closure of the
kernel seeds is 61 modules / 47,658 LOC, of which **24 modules and 32,705 LOC
(68.6%) are trust-classified**. That is the severing burden, and it is the number
to quote. Re-classifying `_contract` moves it only from 70.5% to 68.6%; the
correction matters for the deletion table and for removing twelve gateway edges,
not as a swing factor in the §5 decision.

One measure to avoid: intersecting the kernel closure with the *trust* closure
yields 46,343 LOC "shared" and suggests the kernel is 97% contaminated. In a
graph this dense the trust closure re-reaches most of the kernel, so the
intersection is large by construction and says almost nothing. It was computed
during this analysis and discarded; it is recorded here so it is not rediscovered
and believed.

## 3. The severing boundary

91 distinct module-to-module edges cross KERNEL → TRUST, expressed as 260
import statements (136 module-level, 124 function-local). They are not evenly
spread.

**Re-export and command surface — deletions, not severings:**

| Module | LOC | Statements | Nature |
| --- | ---: | ---: | --- |
| `_cli` | 7,710 | 71 | 10 of 21 top-level command groups are trust surface |
| `__init__` | 765 | 68 | Public re-exports of the trust API |
| `testing` / `_testing` | 275 | 36 | Test helpers for removed features |

These fall out when the features go; they need no redesign. The CLI split is
close to even: of 21 top-level groups, **10 are trust** (`bundle`, `doctor`,
`keys`, `principal`, `provision`, `secrets`, `signer`, `spec`, `trust`,
`witness`), 3 are OPTIONAL (`hooks`, `recurrence`, `webhook`), and 8 are kernel
(`actor-roles`, `config`, `events`, `replay`, `schema`, `version`, `work-item`,
`workflow`). Plan 032 requires the CLI to expose the same coordination
operations as the library; the retained 8 are what that promise has to be met
from.

**Real severing work — six modules carry it:**

| Module | LOC | Module-level | Deferred | Couples to |
| --- | ---: | ---: | ---: | --- |
| `_ops` | 1,159 | 16 | 9 | bundle, witness, v6 writer, trust projection, assurance, principal keys |
| `_event_store` | 1,209 | 4 | 10 | signing, verification, v6 writer, genesis, action delegation |
| `_transition` | 489 | 1 | 8 | verification, v6 writer/referents, action delegation |
| `_api_meta` | 524 | 2 | 7 | verification, provisioning, v6 referents, assurance |
| `_events` | 1,099 | 3 | 5 | signing, v6 writer, genesis |
| `_replay` | 1,566 | 4 | 3 | verification, signing, v6 referents, principal keys |

Together: 6 modules, 6,046 LOC, 72 of the 260 statements.

**Tail — ten modules with a single trust edge each.** Six reach `_keys`
(`_work_items`, `_links`, `_links_api`, `_claims`, `_claims_api`, `_api_base`);
the other four reach elsewhere — `_workflow_api` → `_v6_writer`, `_events_api` →
`_genesis`, `_lint` → `_lineage`, `_version_info` → `_encryption` and
`_signing_scheme`.

`KeySet` has 35 importers, which reads as pervasive coupling. In most of the tail
it is not: those modules import it, annotate a parameter, and forward it —
`_work_items` references the type twice, `_links` and `_links_api` three times
each. Two are heavier and should not be assumed mechanical: `_claims` (6
references) and `_claims_api` (5). Treat the four non-`KeySet` tail edges and
those two as small severings; the rest is a signature sweep.

**Consequence for Plan 032 §5.** §5 requires dependency evidence before choosing
between severing in place and extracting a corrected kernel into a fresh package
tree. On import coupling alone the evidence favours **severing in place**: the
work concentrates in six modules totalling ~6,000 LOC, with a mechanical tail.
Extraction is not indicated by the import graph. §5 should not be settled on this
section alone — see §5 below, which pulls the other way.

## 4. Tests

185 files, 89,770 LOC — more test code than source code. 125 files (68%) name
trust-stack concepts (`trust_log`, `bundle`, `principal_`, `witness`, `genesis`,
`action_delegation`, `signing`, `estate_catalog`, `assurance`, `custody`,
`lineage`).

That 68% is a naming measure and deliberately over-broad: a claims or idempotency
test that merely constructs a signed event to reach the behaviour under test
names `signing` but protects a retained regression. Per Plan 032 F0 item 4, each
file needs an explicit disposition — retire, or port to the unsigned path. The
useful reading is the ceiling: **at most 68% of the test tree retires, and the
floor is well above zero.** Historical coverage totals are not release
requirements.

## 5. Schema — where the import graph is misleading

50 migrations. Tables split cleanly by responsibility:

- **Kernel (11):** `events`, `event_chain_head`, `event_segments`,
  `events_archive`, `work_items_current`, `work_items_archive`, `claims`,
  `projects`, `project_identity`, `workflow_registry`, `actor_roles`
- **Trust (11):** `principal_keys`, `lifecycle_operations`,
  `lifecycle_challenges`, `lifecycle_approvals`,
  `lifecycle_effective_receipts`, `action_delegation_credentials`,
  `witness_receipts`, `witness_registrations`, `anchor_receipts`, `leaves`,
  `tsp_batches`
- **Optional (4):** `hook_queue`, `hook_dead_letter`, `recurrence_rules`,
  `webhook_registrations`

The trust tables drop out whole. Two kernel tables do not:

**`events` has required signing columns in migration `001_initial.sql`:**

```sql
key_id    TEXT  NOT NULL,
signature BYTEA NOT NULL,
```

Signing is not a later accretion on the event table; it is a `NOT NULL`
constraint on the primary event record from the first migration. Every write
path must supply both today.

**`project_identity` cannot be populated without a trust domain and a genesis
event.** It is a singleton whose `trust_domain_id`, `genesis_event_id`,
`genesis_event_hash`, `principal_id`, `key_id`, `scheme_id` and
`key_fingerprint` are all `NOT NULL`, with `scheme_id` checked to `'ed25519'`.

Plan 032's release checklist requires that "ordinary operation requires no suite
or cryptographic ceremony." **The current schema makes that structurally
impossible** — not as a policy check that can be relaxed, but as column
constraints on opening a project and appending an event.

This is the finding that qualifies §3's optimism. The import graph says six
modules; the schema says the coupling also reaches the `NOT NULL` constraints of
the primary event table and the project-open path. It confirms Plan 032 F1's call
for a **fresh schema baseline rather than a migration chain**, and it means the
six hot modules must be re-cut against a changed event record, not merely have
imports removed. The extract-versus-sever decision in §5 of the plan should be
made after a prototype of the new `events` row and open path, not before.

## 6. Estate publication hazard — not in the plan, found while mapping

Publishing a breaking `0.8.0` to PyPI is a live hazard to the private estate,
because three sibling repositories declare **unbounded** version specifiers:

| Repository | Specifier | Safe against 0.8.0? |
| --- | --- | --- |
| `agent-notes` | `regista-hraedon>=0.5.1` | **No — unbounded** |
| `dossier` | `regista-hraedon>=0.5.4` | **No — unbounded** |
| `ad-steward` | `regista-hraedon>=0.5.1` | **No — unbounded** |
| `agent-provenance` | `regista-hraedon[encryption]>=0.5.1,<0.6` | Yes |
| `agent-capability-broker` | `regista-hraedon>=0.7,<0.8` | Yes |

The exposure is concrete. The installed `agent-notes` tool — the estate's memory
layer, running against the production store — is a `uv` tool venv holding
`regista-hraedon 0.5.5` resolved from PyPI, not an editable checkout. A
`uv tool upgrade`, or any fresh install, would resolve `>=0.5.1` to a breaking
`0.8.0` whose schema baseline refuses the production database.

Two mitigations, both cheap, and both required **before** the F5 tag push:

1. Cap the three unbounded specifiers to `<0.8` in their own repositories.
2. Keep F1's refuse-unsupported-schema-before-writes behaviour as the backstop,
   so a resolution accident fails closed instead of mutating the store.

The editable `[tool.uv.sources]` mappings in `agent-notes` and `agent-provenance`
point at `../regista` and affect `uv run` inside those checkouts. Reducing
`main` will break those dev paths; it does not touch the installed tools.

## 7. The OPTIONAL set — evidence for the rulings

Plan 032 §3 removes these by default "unless F0 identifies a small independent
subset worth retaining," and warns against keeping machinery because it has
tests. 31 modules, 8,056 LOC. This section supplies the evidence; the maintainer
rules.

### In-memory backend — the only close call

Plan 032's condition is explicit: keep it "only if it shares actual
transition/reduction rules and accurately states its missing
durability/concurrency guarantees." The first half is testable now, and it
largely passes:

- Most in-memory modules import the **shared** `_contract` validation layer
  rather than restating it: `_in_mem_base`, `_in_mem_claim`, `_in_mem_ops`,
  `_in_memory_claims`, `_in_memory_events`, `_in_memory_links`,
  `_in_memory_transition`, `_in_memory_work_items`, `_in_mem_workflow`.
- `_in_memory_transition` (313 LOC) imports the real `_transition` and
  `_workflow`. Transition rules are genuinely shared, not forked.

Two exceptions that are not shared, and they are the large ones:

- **`_in_memory_replay` (794 LOC)** shares only `_errors`/`_types`. It carries
  its own `_verify_hash_chain_in_memory` and `_verify_global_hash_chain_in_memory`.
  This is a second replay implementation.
- **`_in_memory_v6` (722 LOC)** likewise, and `_in_mem_witness` (601 LOC) is
  trust-only and leaves with the trust stack regardless.

So the honest reading is **split**: the claim/work-item/transition/link surface
meets Plan 032's condition and is cheap to keep; replay does not. Retaining the
backend wholesale keeps a second replay implementation, which contradicts
"preserve one implementation of transition and reduction rules." Retaining it
without replay means the in-memory backend cannot exercise the replay contract —
which is much of what F2 must qualify. **Recommendation: retire it and use
disposable PostgreSQL fixtures**, per Plan 032's own fallback, because the part
that would justify keeping it is the part that is forked.

### HTTP sidecar — remove

1,708 LOC across 10 modules, pulling `fastapi`, `uvicorn[standard]`, `pydantic`
and `httpx` via the `sidecar` extra. It is not a thin pass-through: it ships its
own `TokenRegistry`, `AuthenticatedActor`, `require_admin` and `rate_limit`. That
is a second authentication and deployment product, which Plan 032 names as the
thing to avoid retaining by inertia. No qualification-cost case for keeping it
was found. **Remove, with its extra.**

### Recurrence, hooks, webhooks — remove

`_recurrence` (458) + `_recurrence_api` (109) + `_in_memory_recurrence` (256);
`_hooks` (662) + `_hooks_api` (70) + `_in_memory_hooks` (186) + `_in_mem_hook`
(223); `_webhooks` (85). Four of the 21 top-level CLI groups and four schema
tables (`hook_queue`, `hook_dead_letter`, `recurrence_rules`,
`webhook_registrations`) go with them.

Plan 032's product statement is that Regista owns coordination state while
callers own execution, and that it is "not a job executor, durable-code-execution
engine, scheduler." Recurrence scheduling and async delivery are execution
concerns by that definition. No independent subset worth retaining was
identified. **Remove.** The one thing to check before deleting the hook queue is
`agent-wake`'s use of it as a durable-ingest path — but that is a consumer
question for the estate, not a reason to keep it in a published MVP.

## 8. What F0 still owes

- ~~A prototype `events` row and project-open path without required signing.~~
  **Discharged** — see `prototypes/kernel/`, and §9 below for what it settles.
- **Per-file test dispositions.** §4 gives a ceiling (68%), not a decision.
- **The maintainer's ruling on §7.** The evidence is assembled; the calls are
  not mine to make. Note that the in-memory recommendation is the one place this
  map argues against retaining something that partly meets Plan 032's stated
  condition.
- **The proposed public API needed by F0a**, which this map informs but does not
  define.
- **The Python support range (F0 item 5).** The `fromisoformat` divergence
  recorded in §2 is a direct input.

## 9. The prototype, and the §5 verdict

`prototypes/kernel/` is a working `create → claim → transition → query → replay`
path against real PostgreSQL with **no keys, no trust log, no genesis ceremony
and no suite configuration**. 736 lines of implementation over a 111-line schema,
plus 468 lines of scenario and mutation checks. It is `ruff` clean and passes
`mypy --strict`, which the repository requires of every new module.

It runs Plan 032 F0a scenario 1 end to end: work filed with domain fields and a
typed link, **two real OS processes** contending for one lease, a worker/reviewer
handoff with a change request, worker death, lease expiry, takeover, and a
refused stale write from the revived worker — then replay from events alone with
no drift.

13 mutation checks establish that those refusals are not vacuous. Each breaks one
guarantee and asserts the kernel notices, **and** that the legitimate form of the
same call still succeeds: edited event payloads, deleted middle events,
idempotency keys reused for a different request, wrong and absent roles, missing
required fields, transitions out of a terminal state, reissued fencing tokens,
and `initialize()` pointed at a 0.7-era schema (refused **without mutating it**).

One defect was found by building it, and is worth carrying into whichever
implementation ships: lease *decisions* were being taken on the writing process's
clock while lease *queries* used the database clock. On hosts whose clocks
disagree, `available()` and `transition()` would disagree about whether a lease
is live. Expiry now has one authority — the database — because a coordination
store has many clients and one serialization point.

**Verdict on Plan 032 §5: extract.** §3 showed the severing work concentrating in
six modules, which read as tractable. §5 showed why that reading is incomplete:
the retained event record itself must change, so those six modules must be re-cut
against a new row regardless. Building the new row directly cost 715 lines and
produced a path that already satisfies the contract F2 must qualify. Severing
means reaching the same row through 22,610 lines carrying the history of every
design it used to serve.

The prototype is **not** a complete MVP — no CLI, pagination, pool health,
YAML/JSON Schema workflow loading, bounded field filtering, archive,
observability, async surface, or cross-project links. Completing those plausibly
lands in the low thousands of lines; that is an estimate, not a measurement, and
it does not change the order of magnitude.

Per Plan 032 F0a, the minimal implementation "must become the retained
implementation, not a throwaway second engine" — so the recommendation is to
promote this rather than sever. **The maintainer decides.** If the decision goes
the other way, the scenario and mutation checks apply unchanged to a severed
kernel: they test the contract, not this implementation.
