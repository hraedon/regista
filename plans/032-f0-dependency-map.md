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
| KERNEL — Plan 032 §3 "Keep and qualify" | 41 | 23,127 | 29.8% |
| TRUST — §3 "Remove by default" + Signing | 40 | 46,323 | 59.8% |
| OPTIONAL — recurrence, hooks, webhooks, sidecar, in-memory engine | 31 | 8,056 | 10.4% |
| **Total** | **112** | **77,506** | |

Two corrections to the obvious reading, both material:

- **`_contract` (898 LOC) is kernel, not trust.** It is the kernel's own
  validation layer: transition resolution, role gating, idempotency, claim
  acquire/heartbeat/release, link types, JSON safety, actor IDs — Plan 032's keep
  table almost line for line. 27 modules import it, overwhelmingly kernel and
  in-memory ones, which is itself the evidence. Only `validate_model_lineage`
  (model-lineage registry, on the remove list) and a function-local
  `validate_principal_id` reach out of it.
- **`_jcs` / `_vendor.rfc8785` are kernel.** Plan 032 §3 permits canonical
  serialization to remain. `_jcs` is a nine-line wrapper over RFC 8785.

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

## 7. What F0 still owes

- Per-file test dispositions (§4 is a ceiling, not a decision).
- A prototype `events` row and project-open path without required signing, to
  settle the extract-versus-sever question in Plan 032 §5.
- The OPTIONAL ruling: recurrence, hooks, webhooks, the HTTP sidecar, and the
  in-memory engine (8,056 LOC across 31 modules).
- The proposed public API needed by F0a, which this map informs but does not
  define.
