# Plan disposition index — 0.8.0 reduction

Every file under `plans/` (except this one, and the two open-decisions documents
that record rulings rather than plans — `plans/032-open-decisions.md` and
`plans/032-open-decisions-review.md`, both untouched by this pass) now carries a
short disposition marker at its top, right under its title. This file is the single
place to see all of them at once, per Plan 032 F0 item 1's requirement that no
competing normative instructions be left standing. It does not replace the markers —
open the plan itself for the full one-line "why" and any retained-behaviour caveat.

Placed here (`plans/032-plan-dispositions.md`) rather than under
`plans/032-f0-inventory/` because that directory holds F0's analysis artifacts
(dependency map, packaging, test dispositions, docs inventory) — reports written
*about* the repo at a point in time. This file is closer to those plan files
themselves: it is read alongside them, updates if a plan's disposition is ever
revisited, and is naturally discovered by anyone opening `plans/` looking for "what
happened to plan N."

**Disposition vocabulary used on the markers:**

- **HISTORICAL** — the plan describes a subsystem or design that Plan 032 §3
  removes for 0.8.0. Not deleted (git history and release tags already preserve it
  adequately, per the reviewer's standard applied to D18 below); kept in place as
  the design record, with a marker so a reader does not mistake it for current
  instruction.
- **MOSTLY HISTORICAL** — as above, but the plan's stated justification bundles a
  removed subsystem with a small piece of genuinely retained kernel behaviour;
  the marker names which part survives and why it does not depend on the removed
  part.
- **PARTIALLY RETAINED** — a specific, named subset of the plan's design survives
  into 0.8.0; the rest does not. Used only for the two plans this pass was asked
  to rule on individually (004 declined the exception; 020 kept a subset) plus 002
  and 009, found by reading their content rather than their filenames.
- **HISTORICAL — COMPLETE** — a one-time mechanical action (a rename) that already
  happened and is not a removable design; not affected by the trust-stack removal
  in either direction.
- **CURRENT** — the plan governs the 0.8.0 release itself; it is not historical.

---

## Full index

| Plan | Disposition | One-line why |
| --- | --- | --- |
| `001-events-month-partitioning.md` | HISTORICAL | Already reverted (RFC-001, `spec.md:19`); unrelated to the trust-stack removal. |
| `002-admin-cli.md` | PARTIALLY RETAINED | The small read-heavy CLI shape survives; the mandatory-signing constructor and hooks dead-letter commands go. |
| `003-recurring-work-items.md` | HISTORICAL | Recurrence scheduling is REMOVE-scope. |
| `004-workflow-composition.md` | HISTORICAL | D21: the "small independent subset" exception was considered and declined. |
| `005-http-sidecar.md` | HISTORICAL | D3: not a thin pass-through; removed with its extra. |
| `006-sla-auto-transitions-design.md` | HISTORICAL | Design exploration, never implemented, built on removed FRs. |
| `007-public-api-facade-decomposition.md` | HISTORICAL | Decomposes the pre-0.8.0 god-class (including hook/recurrence facades); the F1 kernel extraction replaces the class outright rather than promoting this architecture. |
| `008-trust-model-hardening.md` | HISTORICAL | Trust hardening is signing/key-custody machinery; `strict_roles` survives as application policy (see D16/020 marker). |
| `009-operational-runtime.md` | MOSTLY HISTORICAL | Justified mainly by recurrence/hook timers, both removed; claim-sweep need survives as ordinary caller responsibility, not a daemon requirement. |
| `010-delegation-chain.md` | HISTORICAL | `on_behalf_of` delegation is REMOVE-scope. |
| `011-pluggable-signing.md` | HISTORICAL | Signing removed as a prerequisite (D5). |
| `012-rfc3161-timestamping.md` | HISTORICAL | Timestamping REMOVE-scope; already deleted in the 0.6.0 line per `AGENTS.md:295`. |
| `013-witness-hooks.md` | HISTORICAL | Witness/anchoring REMOVE-scope. |
| `014-global-event-seq.md` | HISTORICAL | D16: historical as a timestamping design; per-item ordering survives; `BIGSERIAL` gap caveat recorded on the marker. |
| `015-wake-provenance-v1-trust-envelope.md` | HISTORICAL | Trust envelope REMOVE-scope in full. |
| `016-privileged-transitions.md` | HISTORICAL | Built on delegation chain + pluggable signing, both REMOVE-scope. |
| `017-webhook-witness-unification.md` | HISTORICAL | Unifies two REMOVE-scope subsystems. |
| `018-rename-to-regista.md` | HISTORICAL — COMPLETE | One-time completed rename; name persists into 0.8.0 unchanged. |
| `019-transparency-log-anchoring.md` | HISTORICAL | Anchoring REMOVE-scope; already marked removed in `spec.md:229`. |
| `020-validator-context-enrichment.md` | PARTIALLY RETAINED | D16: small trusted synchronous validation extension survives; delegation/lineage/unbounded-history context does not. |
| `021-validator-delegation-chain-on-context.md` | HISTORICAL | Delegation-chain-on-context; delegation itself is REMOVE-scope. |
| `022-entity-generalization-and-crypto-agility.md` | HISTORICAL | Every decision in it is signed-envelope work; signing is REMOVE-scope. |
| `023-builtin-review-gate-validators.md` | HISTORICAL | D16: suite review policy goes; generic review states/caller-written validation remain possible without it. |
| `024-global-chain-integrity-investigation-and-repair.md` | HISTORICAL | Already-complete fix to a tamper-evidence structure that is itself REMOVE-scope. |
| `025-suite-cohesion-spine.md` | HISTORICAL | Suite config/provisioning/cross-component discovery REMOVE-scope; signed spec entity goes with signing. |
| `026-per-actor-ed25519-non-repudiation.md` | HISTORICAL | Exactly the non-repudiation claim Plan 032 §1 disclaims for 0.8.0. |
| `027-review-assurance-and-gate-honesty.md` | HISTORICAL | Built-in assurance classification / model-lineage REMOVE-scope. |
| `028-event-log-retention-and-archival.md` | HISTORICAL | D16: no archival subsystem in the MVP; ordinary PG backup/restore remains required. |
| `029-backend-aware-key-custody.md` | HISTORICAL | Principal/key custody REMOVE-scope. |
| `030-payload-encryption-at-rest.md` | HISTORICAL | Field encryption serving the removed evidence system is REMOVE-scope. |
| `031-public-principal-lifecycle-and-custody-boundary.md` | HISTORICAL | Principal custody/lifecycle REMOVE-scope. |
| `032-f0-dependency-map.md` | CURRENT | Governs the current reduction; source for most dispositions above. |
| `032-final-public-release.md` | CURRENT | The plan being executed. |
| `032-open-decisions.md` | *(not marked — owned by the orchestrator)* | Records open rulings, including D16's ruling on the five plans above. |
| `032-open-decisions-review.md` | *(not marked — owned by the orchestrator)* | Reviewer's recommendations on the open-decisions list, including the D16 table this pass adopted verbatim. |

**Count:** 33 plan files carry a disposition marker (001–031 plus the two 032
governing documents). 2 files under `plans/` are excluded per this pass's
instructions (the open-decisions pair, above). 29 are HISTORICAL, 1 is
HISTORICAL — COMPLETE, 1 is MOSTLY HISTORICAL, 2 are PARTIALLY RETAINED
(002, 020), and 2 are CURRENT.

The five plans D16 specifically ruled on (`004`, `014`, `020`, `023`, `028`) are
marked using the reviewer's table in `plans/032-open-decisions-review.md` verbatim,
including 014's `BIGSERIAL`-gap caveat and 020's trusted-callback caveat.

---

## Other 0.8.0-related dispositions this pass recorded (not plans, listed here for one-stop discovery)

- **`spec.yaml`** — RETIRED (D15). No consumer found in this repo, nor in
  `/projects/dossier` or `/projects/agent-notes` (checked; not modified). Marker
  added at the top of the file itself, including the independent v8-vs-v9
  staleness finding. The workflow JSON Schema (`src/regista/_workflow_schema.json`)
  is a separate artifact, not retired, and out of scope for this pass (`src/`).
- **`NOTES-WI337.md`** — DELETED (D18). Read in full first: it is entirely trust-
  log-export/signing/root-threshold design (WI-337/347/348/349/350), 100%
  REMOVE-scope; no conclusion in it needed a home elsewhere before deletion.
- **`examples/telemetry_via_hooks.py`** — DELETED (D18). Its only teaching point
  (`register_hook_handler`) is REMOVE-scope. Its intended replacement is the two
  F0a coordination scenarios under `prototypes/kernel/` (owned by another agent
  this pass — not moved or edited here). `AGENTS.md:423` still references this
  deleted file by path (`AGENTS.md:419-423`, "Patterns → Telemetry via hooks");
  that reference is now dangling. Fixing it is F4 work (AGENTS.md rewrite), out
  of scope for this pass — flagged here and in
  `plans/032-f0-inventory/normative-conflicts-spec-agents.md` §3 so F4 does not
  miss it.
- **`spec.md` / `AGENTS.md` reconciliation** — not rewritten (F4 work, depends on
  a contract not yet settled). Full line-referenced list of every place both
  documents assert a capability 0.8.0 removes:
  `plans/032-f0-inventory/normative-conflicts-spec-agents.md`.
