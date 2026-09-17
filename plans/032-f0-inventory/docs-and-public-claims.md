# regista documentation and public-claims inventory

Branch `docs/wi364-f0-dependency-map`, baseline commit `e4faacc`. Analysis only; no file
in `/projects/regista` was modified to produce this. Written for Plan 032 F0 item 1
("explicitly reconcile `spec.md`, its sidecar, and `AGENTS.md`... do not leave competing
normative instructions") and F4 ("document the deliberate scope break").

All line numbers below were read directly from the files at this commit; re-check before
acting if the branch moves.

---

## 1. Document inventory

| Path | Size | One-line purpose | Disposition |
| --- | ---: | --- | --- |
| `README.md` | 358 lines / 12K | PyPI long-description (via `pyproject.toml` `readme = "README.md"`); feature list + quickstart | **REWRITE** — see §2, nearly every capability bullet and the entire usage example describe REMOVE-scope machinery |
| `CHANGELOG.md` | 1777 lines / 124K | Full release history, `[Unreleased]` through `0.1.0` | **MARK-HISTORICAL** for everything through `0.7.2`; add one final `0.8.0` entry describing the break. Do not delete — it is the record of what shipped and was removed |
| `AGENTS.md` | 448 lines / 44K | Developer/agent guide: architecture, source layout, full public API surface, "Status" section, conventions | **REWRITE** — it is the single most normative developer-facing doc and is currently ~70% description of REMOVE-scope subsystems presented as current, correct status (see §1a conflicts below) |
| `spec.md` | 854 lines / 120K | "Authoritative" functional spec (AGENTS.md line 8 calls it exactly that) | **REWRITE** (or supersede with a much smaller spec) — see §1a. Sections 17.9–17.14, 19, most of §5 FRs, and the revision history are REMOVE-scope and self-declared normative |
| `spec.yaml` | 448 lines / 28K | "Machine-readable sidecar to spec.md" | **REWRITE or DELETE** — stale even against the *current* spec.md (see §1a #3); would need full regeneration or should be dropped if the new spec is small enough not to need a sidecar |
| `NOTES-WI337.md` | 497 lines / 40K | Root-level implementation notes for one work item: publishing the trust log as an offline-verifiable artifact | **DELETE or move under a historical/notes path** — it is 100% REMOVE-scope (trust-log export, root-threshold signatures) and reads as a live root-level doc despite being work-item scratch notes |
| `AGENTS.md` sidecar refs: `docs/suite-config.md` | 423 lines | Suite config contract (env vars incl. `REGISTA_TRUST_GENESIS_PATH`, doctor shape, Vault/AKV secret backends) | **DELETE-scope content, MARK-HISTORICAL as a file** — entirely suite-coupling + key-custody, both on the REMOVE list |
| `docs/review-assurance.md` | 246 lines | Defines `AssuranceLevel` enum / gate-honesty model (Plan 027) | **MARK-HISTORICAL** — built-in assurance classification is explicitly REMOVE-scope (Plan 032 §3) |
| `docs/principal-lifecycle-threat-model.md` | 53 lines | Threat model for `regista.principal_lifecycle` | **MARK-HISTORICAL** — principal custody/lifecycle is REMOVE-scope |
| `docs/history-identifier-audit.md` | 1316 lines | Git-history PII/identifier leak audit (publication prep, unrelated to product docs) | **KEEP** — operational record, not a product claim, out of scope for F4 but harmless to leave |
| `docs/publication-review-checklist.md` | 66 lines | Publish-to-public checklist tracking the identifier scrub | **KEEP** — same category as above |
| `docs/0.6.0/` (19 files: `README.md`, `ARCHITECTURE-0.6.0.md`, `ARCHITECTURE-FINAL.md`, `TRUST-DOMAIN.md`, `BUNDLE-V3.md`, `V6-ENVELOPE.md`, `RECONCILIATION.md`, `IMPLEMENTATION-PLAN.md`, `OPERATOR-FORGERY.md`, `CUTOVER-POLICY.md`, `CUTOVER-CLASSIFICATION.md`, `EPOCH-RESET.md`, `FIELD-MATRIX.md`, `P0.2-REDUCER-DETERMINISM.md`, `RESULT-MODEL.md`, `REVIEW-VERDICTS.md`, `SOL-DESIGN-REVIEW.md`, `SUITE-RECONCILIATION.md`, `AUDIT-REPORT.md`, `OVERLAY-APPLICATION.md`, plus scripts/evidence) | ~many thousand lines | The frozen "start here" spec set for the entire 0.6.0 cryptographic-epoch cutover — self-described as "the set the implementation is written against," with a live gate-status table | **MARK-HISTORICAL as a whole directory** — this is the largest single block of now-obsolete normative material in the repo. `docs/0.6.0/README.md` line 5 says "It is the set the implementation is written against," present tense, and line 33 shows an active gate table ("Signed review verdicts are GO"). Nothing here says "superseded by Plan 032." A reader who opens `docs/` and starts at the top gets the full trust-domain architecture presented as live guidance |
| `docs/0.7.0/AMENDMENTS.md` | 82 lines | "**Status:** Normative for regista 0.7.0" — entity registry + action-delegation amendments to the 0.6.0 contract | **MARK-HISTORICAL** — explicitly self-declared normative today; action delegation is REMOVE-scope |
| `docs/0.7.1/AMENDMENTS.md` | 82 lines | "**Status:** Normative for regista 0.7.1" — principal-lifecycle authority, trust-genesis env var, durable schema, offline verification surface | **MARK-HISTORICAL** — same pattern, principal lifecycle + genesis are REMOVE-scope |
| `deploy/sidecar/README.md` | 78 lines | HTTP sidecar deployment guide | **DELETE** (or MARK-HISTORICAL if the directory is kept as a historical reference) — the sidecar itself is recommended for removal (dependency map §7) |
| `product-concepts/README.md` + `agent-coordination-plane.md` + `provable-compliance-workflows.md` | 6 / 56 / 52 lines | "Positioning sketches, not committed roadmap" for regista-based products | **MARK-HISTORICAL** — `provable-compliance-workflows.md` in particular is a direct, current-tense pitch built entirely on properties Plan 032 removes (see §2, item 8) |
| `debate/README.md` + `debate/00N-*.md` + `debate/positions/**` (glm-5.1, gemini-cli, kimi-k2p6-turbo subdirs, ~17 files) | small | Internal design-debate log; `debate/README.md` carries a live status table listing Plans 007–030 as "Implemented" | **KEEP as historical record**, but note `debate/README.md`'s status table (e.g. "008 Trust model hardening — Implemented", "026... — Implemented") will read as current-status confirmation of REMOVE-scope plans once those plans are gone; worth a one-line banner, not a rewrite |
| `src/regista/__init__.py` module docstring | none (no module-level `"""..."""`; file opens directly on imports at line 1) | — | **N/A** — there is no module-level docstring to reconcile. The `Regista` class docstring (line 191–196) is short and survives fine: *"Coordination and durable state for agent pipelines over Postgres. One Regista instance owns one logical project namespace..."* — no false claims here, but it's also not where a PyPI browser looks first |
| `src/regista/_cli.py` | argparse `description="Regista admin CLI"` (line 6213) | CLI entry point; 21 top-level command groups, no module or command-group level docstring beyond one-line `help=` strings | **REWRITE incidentally** — not because the text is false, but because 10 of 21 top-level groups (`bundle`, `doctor`, `keys`, `principal`, `provision`, `secrets`, `signer`, `spec`, `trust`, `witness`) and 3 more (`hooks`, `recurrence`, `webhook`) disappear; `regista --help` output itself is a "public claim" surface that will shrink by 13/21 groups |
| `examples/telemetry_via_hooks.py` | 1 file | Only example in the repo; module docstring describes a hooks-based telemetry pattern | **DELETE** — its entire teaching point is `register_hook_handler`, a REMOVE-scope feature; see §3 |
| `prototypes/kernel/README.md` + `F0a-report.md` | 78 / 155 lines | The actual working proof of the reduced product (F0a scenarios) | **KEEP, and promote** — this is the best available source material for the new README; not itself a public/published doc yet |

Not separately inventoried but confirmed absent: no `CONTRIBUTING*` file anywhere in the repo.

### 1a. Competing normative instructions (F0 item 1's specific ask)

These are places where two documents currently tell a reader (or an agent) different, contradictory things about what regista *is*, right now, before any Plan 032 reduction is applied:

1. **`spec.md:783` vs. Plan 032 §1 (plans/032-final-public-release.md:24).**
   `spec.md` line 783: *"This section is normative. The regista's public API is a **protocol**... Any implementation... MUST conform."* Section 19.2 (`spec.md:791`) then states as an invariant: *"The regista library is the sole sanctioned signer... The API does NOT accept pre-signed events."*
   Plan 032 (`plans/032-final-public-release.md:24`): *"The final contract trusts the host application and database administrators... Replay detects inconsistency and reconstructs supported state; it does not establish hostile-administrator tamper evidence, non-repudiation, model identity, or external freshness."*
   `spec.md` is still the document AGENTS.md calls authoritative (`AGENTS.md:8`) while making a signing guarantee Plan 032 explicitly retires as a supported contract. A reader following AGENTS.md to spec.md gets the old promise; a reader following Plan 032 gets the new one. Neither document points at the other's supersession.

2. **`AGENTS.md:8` vs. Plan 032 F0 item 1's own instruction.**
   AGENTS.md line 8: *"**Spec:** `spec.md` is authoritative."* No qualifier, no date, no pointer to Plan 032. This is the exact competing-instruction pattern F0 item 1 was written to catch — the reconciliation it calls for has not yet happened in the file itself.

3. **`spec.yaml:3-4` vs. `spec.md`'s own revision history (`spec.md:9`).**
   `spec.yaml` line 3: *"Regenerated against spec.md v8 (2026-05-26)."* But `spec.md` line 9 shows the current version is **v9** (2026-06-23, Plan 022 entity generalization + crypto-agility). The sidecar has been stale against its own stated source of truth independent of anything Plan 032 does — this is one of the "stale README/changelog descriptions" Plan 032 §2 warns about, caught here in the spec sidecar rather than the README.

4. **`docs/0.6.0/README.md:5` vs. everything after it.**
   Line 5: *"It is the set the implementation is written against"* — present tense, no supersession marker — while the repository has since moved through 0.7.0 and 0.7.1 *contract amendments* (`docs/0.7.0/AMENDMENTS.md`, `docs/0.7.1/AMENDMENTS.md`, both self-declared "Normative") and is now the subject of Plan 032, which removes the entire subject matter. Three layers (0.6.0 base, 0.7.x amendments, Plan 032 removal) are all live in the repo with no single document stating which one governs a given question today.

5. **`docs/suite-config.md`'s `REGISTA_TRUST_GENESIS_PATH` (line 12) vs. `Regista.__init__`'s `trust_genesis_path` docstring (`src/regista/__init__.py:238-241`) vs. Plan 032's removal of "suite configuration discovery."**
   The suite-config doc and the constructor docstring agree with each other (both describe genesis-gated lifecycle as current, working config), but both are flatly inconsistent with Plan 032 §3's "Remove by default: ... Suite configuration discovery, lock/health dependencies." No document says which one a new contributor should build against.

6. **`product-concepts/provable-compliance-workflows.md:9` vs. Plan 032 §1 (`plans/032-final-public-release.md:24`).**
   The concept doc: *"Regista's HMAC-signed canonical-JSON events with replay drift = 0 produce the artifact auditors actually want: a log that is cryptographically provable, not asserted by convention."* This is a direct, present-tense assertion of exactly the property Plan 032 says the released product will not claim (non-repudiation / tamper evidence against a hostile administrator). It is marked "sketch," but nothing marks it retracted.

---

## 2. Claims that will become false

Every claim below is quoted verbatim with file:line. All are currently true of the code (or at least asserted as current by the docs) and become false once Plan 032's REMOVE list ships.

1. **Cryptographic tamper-evidence / hash-chain claim.**
   `README.md:13`: *"**Event hash chain** — each event's `prev_event_hash` binds it to its predecessor (SHA-256 of prev envelope + signature)"*
   `README.md:312`: *"**Hash-chained events**: each event's `prev_event_hash` creates a **tamper-evident chain** within each work-item"*
   Plan 032 removes signing as a supported contract (`plans/032-final-public-release.md:70-74`) and the dependency map confirms the `events` table's `signature`/`key_id` columns are `NOT NULL` from the first migration (`plans/032-f0-dependency-map.md:170-179`) — the chain's tamper-evidence claim depends on a signature that will no longer exist by default.

2. **Trust hardening / strict enforcement framed as a security feature.**
   `README.md:23`: *"**Trust hardening** — `strict_roles` enforcement, env-var key injection, vendored RFC 8785"*
   Role gating survives (it's on the KEEP list as ordinary application-policy enforcement), but "trust hardening" as a labeled security capability, and "env-var key injection" specifically, are signing-key machinery on the REMOVE list.

3. **Delegation chain / agent-to-principal binding.**
   `README.md:24`: *"**Delegation chain** — `on_behalf_of` field for agent-to-principal binding (Plan 010)"*
   Action delegation is explicitly REMOVE-scope (`plans/032-final-public-release.md:60`).

4. **Pluggable signing / Ed25519.**
   `README.md:25`: *"**Pluggable signing** — HMAC-SHA256 (default) and Ed25519 via `SigningScheme` protocol (Plan 011)"*
   Plan 032 §3 Signing: *"Recommended default: remove signing as a prerequisite and omit cryptographic verification from the supported contract"* (`plans/032-final-public-release.md:72`).

5. **Witness co-signing.**
   `README.md:26`: *"**Witness co-signing** — external witness registration, receipt creation, and HTTP delivery (Plan 013)"*
   Witness/anchoring is explicitly REMOVE-scope.

6. **Webhooks.**
   `README.md:27`: *"**Webhooks** — push-model event delivery with auto-pause on failure"*
   REMOVE-scope ("Recurrence scheduling, async hooks/webhook delivery... Default to removal," `plans/032-final-public-release.md:65`).

7. **HTTP sidecar as a supported deployment mode.**
   `README.md:30`: *"**HTTP sidecar** — optional FastAPI pass-through for non-Python consumers with bearer-token auth"*, expanded at `README.md:229-256` with a full worked example including a `tokens.yaml` bearer-token format.
   Dependency map recommends removal outright: *"It is not a thin pass-through: it ships its own `TokenRegistry`, `AuthenticatedActor`, `require_admin` and `rate_limit`... **Remove, with its extra**"* (`plans/032-f0-dependency-map.md:266-273`).

8. **Non-repudiation.**
   `AGENTS.md:275`: *"Replay principal binding (Plan 026 WI-2.2): `replay(verify_principal_binding=True)` **closes the non-repudiation loop end-to-end**."*
   `AGENTS.md:336`: *"Plan 026 additions (Per-actor Ed25519 **non-repudiation**)"*
   `spec.md:664`: *"The trust-model claim that survives this section: events covered by a confirmed external anchor cannot be modified post-hoc without detection by any third party..."*
   Plan 032 is explicit that this is precisely the claim being retired: *"it does not establish hostile-administrator tamper evidence, **non-repudiation**, model identity, or external freshness"* (`plans/032-final-public-release.md:24`). This is the single most direct contradiction in the repo between a currently-published claim and the new product's stated contract.

9. **Third-party / external verifiability via anchoring.**
   `spec.md:649`: *"This is the canonical public-anchor story: **any third party** with the receipt and a Bitcoin node can verify that a root existed at a specific block height, without trusting the operator."*
   Already marked removed in-place at `spec.md:645` ("REMOVED by P1.4 (0.6.0)... retained as historical record only") but the surrounding section still walks through the mechanism in present-tense normative language for 60+ lines (`spec.md:643-666`), and it is reachable from spec.md's live table of contents with no historical banner at the section-header level (only inline, mid-paragraph).

10. **Audit bundles as a signature-verifiable artifact.**
    `CHANGELOG.md:6-14` (`[Unreleased]`): *"Audit bundles are format v3 only... a tamperer must now forge a signature."*
    `AGENTS.md` command list references `regista bundle export/verify` implicitly via the CLI table (`plans/032-f0-dependency-map.md:97` confirms `bundle` is one of the 10 trust-scoped top-level CLI groups). REMOVE-scope (`plans/032-final-public-release.md:61`, "audit bundles").

11. **Model-lineage / assurance-level attestation.**
    `docs/review-assurance.md` (whole file) defines `AssuranceLevel` as *"a pure view over the signed event history — computed, never stored, so it can never disagree with the record"* — an assurance claim tied to signed events. REMOVE-scope: *"Model-lineage registries, built-in assurance classification"* (`plans/032-final-public-release.md:62`).

12. **Suite integration as a first-class, documented feature.**
    `AGENTS.md`'s Plan 025 section (`AGENTS.md:344-347`) documents `regista.config.resolve()`, Vault/Azure secret backends, and `SUITE.lock` version-surface reporting as current capability. REMOVE-scope: *"Suite configuration discovery, lock/health dependencies, cross-component provisioning"* (`plans/032-final-public-release.md:63`).

13. **"Recurring work items" as a headline feature.**
    `README.md:19`: *"**Recurring work items** — interval and RRULE schedules with catch-up policies"*, with a full usage example at `README.md:116-124`. REMOVE-scope (`plans/032-final-public-release.md:65`).

14. **In-memory backend as "full conformance."**
    `README.md:33`: *"**In-memory backend** — full conformance backend for testing without Postgres"*
    This claim is arguably already overstated *today*, independent of Plan 032: the dependency map found the in-memory backend forks its own replay implementation rather than sharing the real one (`plans/032-f0-dependency-map.md:250-254`, `_in_memory_replay.py` "is a second replay implementation"). "Full conformance" is a stronger claim than the evidence supports even before any reduction — this belongs in §"stale today" below as well as here, since Plan 032's own recommendation is to retire the backend outright.

15. **Payload encryption-at-rest.**
    `AGENTS.md:246-248` (Plan 030 additions): field-level AES-256-GCM encryption primitive, described as shipped capability. REMOVE-scope: *"Field encryption/custody integrations serving the removed evidence system. Storage/database encryption becomes an explicit operator responsibility"* (`plans/032-final-public-release.md:64`).

### Where the docs already disagree with the code, independent of Plan 032

- **`spec.yaml` vs `spec.md`**, item 3 above — a straightforward version-drift staleness, not caused by the reduction.
- **In-memory backend "full conformance"** (`README.md:33`) vs. the dependency map's finding that its replay path is forked and untested-for-parity (`plans/032-f0-dependency-map.md:251-254`) — the claim is optimistic today.
- **"Ordinary use requires neither agent-suite nor trust-genesis/key-governance ceremonies"** is Plan 032's own proposition (`plans/032-final-public-release.md:16`), but it is *not yet true of the current code*: `Regista.__init__` raises `RegistaError` if `hmac_key_path is None` (`src/regista/__init__.py:257-260`, immediately after the docstring), and `project_identity` has `NOT NULL` columns for `trust_domain_id`, `genesis_event_id`, `principal_id`, `key_id`, `scheme_id` (`plans/032-f0-dependency-map.md:181-184`). This is not a documentation bug to fix by rewriting prose — it is the schema/constructor gap F1 has to close. Flagging it here because a rewritten README that simply asserts the new proposition, without F1 landing first, would itself become a false claim on day one.

---

## 3. Examples and quickstarts

There is exactly **one** file under `examples/` and no doctests were found in the docstrings inspected (`grep '>>>' ` over `src/regista` was not exhaustively run across all 112 modules, but none appeared in the files read).

| Example | Location | Would it run after reduction? | Notes |
| --- | --- | --- | --- |
| README "Usage" walkthrough | `README.md:62-127` | **No.** | Calls `Regista.create_project(..., hmac_key_path=...)` (line 66-69, signing), `sub.write_genesis(...)` / `sub.read_genesis()` (lines 75-76, trust genesis — REMOVE-scope), and `sub.register_recurrence_rule(...)` (lines 117-123, recurrence — REMOVE-scope). Every one of the three "advanced" calls in this 65-line example is on the REMOVE list; only `register_workflow_file`, `create_work_item`, `acquire_claim`, `transition`, `query_work_items`, and `replay()` (lines 90-114) are KEEP-scope. This is the repo's flagship quickstart and roughly half of it must be deleted. |
| README "Admin CLI" walkthrough | `README.md:260-307` | **Partially.** | Of the command groups shown, `workflow validate/compose`, `work-item show/create/transition`, `events show/tail/archive`, `replay`, `schema init/status`, `actor-roles list` survive; `regista recurrence list/due/fire` (283-286), `regista hooks dead-letter list/requeue` (292-294), `regista witness list/deliver/receipts` (299-302), and `regista webhook register/list` (304-306) do not. |
| HTTP Sidecar section | `README.md:229-256` | **No — the whole feature disappears.** | Entire worked example (env vars, `python -m regista.sidecar`, token file format, curl-able `/v1/` endpoints) documents a component recommended for removal. |
| `examples/telemetry_via_hooks.py` | repo root `examples/` | **No.** | Docstring (lines 1-11) states the example demonstrates hook-handler registration and rebuild-by-replay of a hook-fed reporting table. `register_hook_handler` and the hook queue are REMOVE-scope (recurrence/hooks/webhooks bucket). This is also the **only** current example in the repo, so removing hooks leaves the project with zero worked examples until F0a's prototypes are promoted. |
| `prototypes/kernel/example_handoff.py`, `example_documents.py` | `prototypes/kernel/` | **Yes — these are the ones that will run.** | Per `prototypes/kernel/F0a-report.md:18-21`: *"No keys, no trust log, no genesis ceremony, no suite configuration, no `~/.config` anything, no environment beyond a DSN."* These are not yet published/linked from README or docs — they exist only as F0a validation artifacts. |
| Workflow YAML example | `README.md:133-187` | **Yes**, mostly. | Pure workflow-definition YAML (states/transitions/roles/custom fields/link types) is KEEP-scope. `hook_defaults: max_retries: 3` (line 183-184) references the hooks system and should be dropped from the sample. |
| Workflow composition example | `README.md:191-201` | **Undecided by F0/Plan 032.** | `extends:` inheritance is in the "remove by default... unless F0 identifies a small independent subset worth retaining" bucket (`plans/032-final-public-release.md:65`); the dependency map does not rule on it. Do not assume this example survives without an explicit F0 ruling. |
| Key-format JSON example | `README.md:203-227` | **No.** | Entirely signing-key material (HMAC/Ed25519 key file schema); disappears with signing. |

**Headline-promise check (Plan 032's "ordinary use needs none of that"):** the README's *only* end-to-end usage example currently requires a key file and walks through a genesis-envelope call before doing anything else (`README.md:65-76`). This is the exact opposite of the target experience, and it is also the exact opposite of what the F0a prototype now proves is achievable (`prototypes/kernel/F0a-report.md:19-21`, 12 lines from empty database to first completed item, 0.07s, no keys). The gap between the current README and the proven prototype is the whole of F4's rewrite task.

---

## 4. Plans directory — historical-architecture candidates

`plans/` holds 33 files. Recommendation is to **mark historical**, not delete, per the task instructions. Grouped by why:

**Describe the 0.6/0.7 trust architecture directly (signing, keys, delegation, witness, anchoring, custody, encryption, assurance, lineage) — mark historical:**
- `008-trust-model-hardening.md`
- `010-delegation-chain.md`
- `011-pluggable-signing.md`
- `012-rfc3161-timestamping.md` (already superseded in-repo: AGENTS.md:295 says it "were deleted outright" — the plan file itself doesn't say so)
- `013-witness-hooks.md`
- `015-wake-provenance-v1-trust-envelope.md`
- `016-privileged-transitions.md` (origin: agent-provenance scope attestation / delegation chain, `plans/016-privileged-transitions.md:5-6`)
- `017-webhook-witness-unification.md`
- `019-transparency-log-anchoring.md` (already superseded: `spec.md:229` marks FR-30 "REMOVED by P1.4")
- `021-validator-delegation-chain-on-context.md`
- `022-entity-generalization-and-crypto-agility.md`
- `025-suite-cohesion-spine.md`
- `026-per-actor-ed25519-non-repudiation.md`
- `027-review-assurance-and-gate-honesty.md`
- `029-backend-aware-key-custody.md`
- `030-payload-encryption-at-rest.md`
- `031-public-principal-lifecycle-and-custody-boundary.md`

**Describe the old suite roadmap / recurrence / hooks / sidecar (REMOVE-scope but not "trust" per se) — mark historical:**
- `003-recurring-work-items.md`
- `005-http-sidecar.md`
- `009-operational-runtime.md` (mixed: sweep is kernel-adjacent, but recurrence + witness delivery are the bulk of `MaintenanceThread`'s stated purpose, `plans/009-operational-runtime.md:5`)

**Already self-marked complete/historical in their own status line, but worth a Plan-032 cross-reference so a reader knows the *subsystem*, not just the *plan*, is gone:**
- `024-global-chain-integrity-investigation-and-repair.md` (Status: "Complete 2026-06-30" — fixes a verifier bug in the global hash chain, a trust/tamper-evidence structure being removed)

**Ambiguous — genuinely need an F0/maintainer ruling before marking either way, do not default them to historical without a decision:**
- `004-workflow-composition.md` — `extends:` inheritance; Plan 032 defaults this to remove but allows a small-subset exception (`plans/032-final-public-release.md:65`); not yet ruled on per the dependency map.
- `014-global-event-seq.md` — global `event_seq` for coherent batch timestamping; touches "§17 (signing/integrity)" (`plans/014-global-event-seq.md:5`) and is a prerequisite the removed RFC 3161 timestamping (Plan 012) needed, but the mechanism (global sequencing) may be load-bearing for the kernel's own global hash chain / ordering guarantees independent of timestamping.
- `020-validator-context-enrichment.md` — "Not started" (`plans/020-validator-context-enrichment.md:4`); about validator context shape, not trust; likely stays relevant but should be re-read against the reduced `ValidatorContext`.
- `023-builtin-review-gate-validators.md` — moves `adversarial_review`/`human_gate` validators into regista as built-ins; Plan 032 explicitly permits "review states without identifying models" (`plans/032-final-public-release.md:62`), so parts of this may survive while its assurance/lineage framing does not.
- `028-event-log-retention-and-archival.md` — archival is not named in Plan 032's keep table but also not on the remove list; status line shows partial implementation with a known limitation (`plans/028-event-log-retention-and-archival.md:2`).

**Not trust/roadmap-obsolete, no action needed:**
- `001-events-month-partitioning.md` — already reverted (RFC-001, `spec.md:19`); harmless as historical record of a reverted decision, low priority.
- `002-admin-cli.md`, `006-sla-auto-transitions-design.md` (self-marked "NOT a plan, NOT implementation-ready," `plans/006-sla-auto-transitions-design.md:2`), `007-public-api-facade-decomposition.md`, `018-rename-to-regista.md` — architectural/organizational, not trust-specific.
- `032-f0-dependency-map.md`, `032-final-public-release.md` — current, authoritative.

---

## 5. The F4 gap list

Plan 032 §1 frames the product as: *"an embeddable work-coordination ledger for Python applications: durable ownership, validated handoffs, and replayable history across independent workers and people"* (`plans/032-final-public-release.md:14`), targeting a reader who already has scripts/workers/agents and needs shared answers to *"who owns this work, what state is it in, what may happen next, and how did it get here"* (`plans/032-final-public-release.md:16`).

What the current README actually leads with (`README.md:1-8`): *"Coordination and durable state for agent pipelines over Postgres"* — narrower audience framing (agent pipelines specifically, not "Python applications" generally), and the very next sentence pivots straight into the feature list dominated by hash chains, hooks, and a sidecar rather than the ownership/handoff proposition.

Specific gaps a first-time reader would need filled, that no current document states:

1. **The trust boundary, stated as a boundary, not scattered as caveats.** Plan 032 §1's paragraph (`plans/032-final-public-release.md:24`) — "trusts the host application and database administrators... does not establish hostile-administrator tamper evidence, non-repudiation, model identity, or external freshness" — has no equivalent anywhere in README.md or the top of AGENTS.md today. The closest existing analogue is spec.md §20's "Consumer Expectation Boundary" (`spec.md:837-853`), which is well-written but answers a different question (what regista does not *orchestrate*), not the trust/security boundary question.

2. **What a task queue or durable-execution engine would be better for.** Plan 032 §1 explicitly wants this comparison stated honestly (`plans/032-final-public-release.md:18`, naming DBOS/Temporal/Procrastinate) so the product doesn't imply undemonstrated uniqueness. No current doc makes this comparison at all.

3. **The lease-fencing contract, demonstrated.** Plan 032 §1 (`plans/032-final-public-release.md:28`) is specific that lease protection stops a stale worker from mutating *regista's own state*, not from making external side effects, and that the fencing/attempt value must be exposed and required. Neither README nor AGENTS.md currently states this distinction; the closest material is buried in `AGENTS.md:264` ("heartbeat_claim accepts optional expected_attempt_number to detect stale sessions") without the "this is not exactly-once for your external effects" framing Plan 032 requires.

4. **A quickstart that actually needs nothing.** As found in §3: the current README quickstart requires a key file and a genesis call before doing anything; the F0a prototype (`prototypes/kernel/F0a-report.md`) proves a 12-line, no-key path exists. The new README needs this quickstart, and it does not exist in any currently-published document — only in the not-yet-promoted prototype.

5. **What "MVP scope" now means, stated as a boundary list.** AGENTS.md's "Status" section (`AGENTS.md:293`) currently reads *"MVP + Phase 2 + Phase 3 + Plans 002-022 implemented. All FRs FR-01 through FR-29 are in tree"* — an accretive, everything-shipped framing that is the opposite of Plan 032's bounded-MVP-then-maintenance posture (`plans/032-final-public-release.md:26`, "no feature-expansion commitment is implied"). No document states the new, smaller boundary as a boundary (a "what's in / what's explicitly not, and won't be added without evidence" list) — the closest is Plan 032's own release checklist, which is a plan artifact, not user-facing documentation.

6. **The 0.7.2 → 0.8.0 break and preservation guidance for existing installs.** F4 requires: "no supported in-place upgrade," a preservation procedure (keep the old dump + matching environment + old keys, verify a scratch restore) (`plans/032-final-public-release.md:156-157`). Nothing published today says this, because the break hasn't shipped — but it also isn't in CHANGELOG's `[Unreleased]` section, which is entirely about *adding* trust/bundle machinery, not about the forthcoming removal. The `[Unreleased]` section itself will need to be replaced wholesale with the 0.8.0 break notice.
   Concretely important: the dependency map found three sibling private repos on **unbounded** version pins (`agent-notes`, `dossier`, `ad-steward` all specify `regista-hraedon>=0.5.x` with no upper bound, `plans/032-f0-dependency-map.md:206-208`) — the maintenance/upgrade note in the new README/CHANGELOG is not just a courtesy to hypothetical PyPI strangers, it is needed to avoid the estate's own memory-layer tool auto-upgrading into a refused schema.

7. **The maintenance commitment.** Plan 032 F4 suggests "a 90-day stabilization window for release regressions and serious security/data-loss reports, without promised new features or an SLA" (`plans/032-final-public-release.md:158`) — this is explicitly left to the maintainer's choice before publication and does not exist in any doc yet; it's a gap by design, not an oversight, but it's still a gap the new README must eventually close before F5.

---

## What I could not determine

- **Whether `examples/telemetry_via_hooks.py` is referenced from anywhere other than `AGENTS.md`'s "Patterns" section** (`AGENTS.md:423-437`). I did not grep the full test suite or CI config for references to it; if a CI smoke test runs it, deleting it needs a corresponding CI change (out of scope for this analysis, but worth flagging to whoever executes F4/F1).
- **Full doctest inventory.** I did not run a `grep '>>>'` sweep across all 112 modules in `src/regista/`; the docstrings I read (module init, CLI header, `Regista.__init__`) had none, but I cannot rule out a doctest deeper in the KEEP-scope modules (e.g., `_workflow.py`, `_replay.py`) that I did not open line-by-line.
- **Whether `debate/positions/{glm-5.1,gemini-cli,kimi-k2p6-turbo}/*.md` (12 files) contain their own capability claims worth quoting.** I confirmed the directory exists and read only `debate/README.md`'s summary table; I did not open the individual position files. Given they are dated design-debate transcripts rather than product documentation, I judged them low-value for the "claims that will become false" section, but a full pass was not performed.
- **Whether `docs/0.6.0/*.py` tooling (`check-conflicts.py`, `check-crossrefs.py`) is wired into CI or a pre-commit hook.** If so, marking the 0.6.0 docs historical (rather than deleting) should be safe for those scripts, but I did not verify they tolerate a "historical" banner without failing a cross-reference check they may run.
- **Resolved during this pass, not left open:** `pyproject.toml:63-67` (`[tool.hatch.build.targets.wheel]`) packages only `src/regista` plus `migrations` (force-included). `docs/`, `plans/`, `debate/`, `product-concepts/`, and `NOTES-WI337.md` are **git-only** — they never reach the installed wheel or sdist's importable content, only `README.md` does (as the PyPI long-description, per `readme = "README.md"` at `pyproject.toml:9`). This means the AGENTS.md/spec.md/docs/ false-claims problem is a *public-repo* exposure (anyone browsing GitHub or cloning the source), while the *PyPI-page* exposure is narrower and concentrated entirely in `README.md`'s ~15 false claims in §2 — those are the highest-priority fixes since they reach every `pip install` / PyPI-search view even if nothing else is touched. I did not separately verify whether `python -m build --sdist` includes more paths than the wheel (sdists conventionally include more, e.g. via `MANIFEST.in`/hatch sdist config) — no `[tool.hatch.build.targets.sdist]` section was found in the grepped output, so hatchling's default sdist inclusion rules would apply; not independently confirmed.
- **Whether any of the 0.6.0/0.7.x plan or contract documents are linked from external sources** (e.g., a blog post, another repo's README, or a GitHub Pages site) that would need updating in step with a "mark historical" pass. Not investigated; out of scope for a repo-local inventory.
