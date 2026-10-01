# `spec.md` / `AGENTS.md` — line-referenced reconciliation list for F4

Branch `docs/wi364-f0-dependency-map`. Written for Plan 032 F0 item 1 ("explicitly
reconcile `spec.md`, its sidecar, and `AGENTS.md`... do not leave competing normative
instructions") and as the direct input to F4 ("document the deliberate scope break").

**Scope of this file, deliberately narrow.** `plans/032-f0-inventory/docs-and-public-claims.md`
already inventories the whole documentation tree (README, CHANGELOG, `docs/`, `plans/`,
`product-concepts/`, `debate/`) and catalogued 15 claims that become false across all of
it. This file covers only the two documents Plan 032 F0 item 1 names by name —
`spec.md` and `AGENTS.md` — at a finer grain, because those two are the ones that
self-declare normative (`spec.md:783`, and `AGENTS.md:9` pointing at it) and are what
F4's spec/AGENTS rewrite will actually edit line-by-line. **This file does not rewrite
either document** — per this pass's brief, that rewrite is F4 work and depends on a
contract not yet settled. It is a punch list: every line where the document currently
asserts, as a present-tense capability or invariant, something Plan 032 §3
(`plans/032-final-public-release.md:58-68`) removes.

Every line number below was read directly from the file at this commit
(`git log -1 --format=%H` at time of writing: branch tip of
`docs/wi364-f0-dependency-map`). Re-verify before acting if the branch moves — one
citation from the earlier F0 inventory pass (`AGENTS.md:8` for the "spec.md is
authoritative" line) had already drifted to line 9 by the time this file was checked
against the live text; this document's own numbers were re-confirmed by direct read,
not copied forward.

---

## 1. The authority conflict itself

| # | Location | Text (verbatim) | Conflict |
| - | -------- | ---------------- | -------- |
| 1 | `AGENTS.md:9` | *"**Spec:** `spec.md` is authoritative. `spec.yaml` is a machine-readable sidecar."* | Points a reader at `spec.md` with no qualifier, no date, no pointer to Plan 032. `spec.md` in turn makes the exact promise (§19.2, row 3 below) Plan 032 retires. |
| 2 | `spec.md:783` | *"This section is normative. The regista's public API is a **protocol**... Any implementation... MUST conform."* | §19 (Public API Surface) is self-declared normative and includes §19.2 (signing), which Plan 032 removes as a supported contract. |
| 3 | `spec.md:791` | *"The regista library is the sole sanctioned signer (FR-15). The API accepts unsigned event field tuples... The API does NOT accept pre-signed events from callers..."* | This is the specific invariant Plan 032 retires the opposite of: `plans/032-final-public-release.md:24` — *"The final contract trusts the host application and database administrators... Replay... does not establish hostile-administrator tamper evidence, non-repudiation, model identity, or external freshness."* Signing is REMOVE-scope outright (`plans/032-final-public-release.md:70-74`, D5 in `plans/032-open-decisions.md`), so §19.2 is not merely inaccurate, it describes a mechanism that no longer exists. |
| 4 | `AGENTS.md:275` | *"Replay principal binding (Plan 026 WI-2.2): `replay(verify_principal_binding=True)` closes the non-repudiation loop end-to-end."* | Direct contradiction of `plans/032-final-public-release.md:24`'s explicit disclaimer of non-repudiation. Per-actor Ed25519 / principal binding (Plan 026) is REMOVE-scope (key custody, `plans/032-final-public-release.md:60`). |

These four lines are the crux: AGENTS.md tells a reader to trust spec.md, spec.md
promises a signer invariant Plan 032 retires, and AGENTS.md separately (line 275)
repeats the strongest form of that promise ("closes the loop end-to-end") in its own
voice. F4 has to change the pointer (item 1), the promise (item 2/3), and the
restatement (item 4) together — fixing only one leaves the others standing.

---

## 2. `spec.md` — every normative claim Plan 032 removes

Organized by section. "Removed by" cites the specific Plan 032 §3 bucket
(`plans/032-final-public-release.md:58-68`).

### Signing (FR-15, §17.9, §17.9.1, §19.2, §19.6)

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:102` | FR-03: *"`actor_id`, `actor_kind` — authenticated via HMAC (FR-15)"* | Signing removal — "authenticated" tier no longer exists without a verifier. |
| `spec.md:110-111` | FR-03: `signature` and `scheme_id` are persisted, per-event, pluggable-scheme fields | Signing removal (`§3`: "recommended default: remove signing as a prerequisite... omit cryptographic verification from the supported contract") |
| `spec.md:144-158` | FR-15 in full: pluggable `SigningScheme` verifier, HMAC-SHA256/Ed25519, "library is the sole sanctioned signer," canonical signing envelope v3, key set with `active`/`deprecated`/`revoked` status, hot-reload | Signing removal in full |
| `spec.md:616-631` | §17.9 trust-tier table: "Authenticated," "Actor-claimed," row reconciliation, "non-repudiable" language | Depends entirely on the signature verifier being removed |
| `spec.md:633-641` | §17.9.1: HMAC vs Ed25519 external-auditor trust implications, "asymmetric signing prevents *third-party* forgery" | Signing removal |
| `spec.md:683-691` | §17.12: `strict_asymmetric` mode, `export_public_keys()`, `verify_event_with_public_key()`, per-principal key binding | Key custody / crypto-agility removal (Plan 022), signing removal |
| `spec.md:789-793` | §19.2 in full (see §1 row 3 above) | Signing removal |
| `spec.md:795-804` | §19.3: *"Accept unsigned event fields and sign inside the sidecar process. Pre-signed events on the wire are rejected, the same as in-process."* | Both the sidecar (REMOVE-scope, D3) and signing (REMOVE-scope, D5) — this section describes a requirement on a component that no longer ships, enforcing an invariant that no longer exists |
| `spec.md:801` | §19.3: *"Surface trust tiers (§17.9) in response shapes"* | Trust tiers as currently defined depend on signing |
| `spec.md:824` | §19.5: error code list includes `library_is_sole_signer`, `signing_scheme_not_found`, `tsa_not_configured`, `tsa_submission_failed`, `tsa_verification_failed` | Signing + timestamping removal |
| `spec.md:826-833` | §19.6: `export_public_keys()`, `verify_event_signature()`, `Regista(..., strict_asymmetric=True)`, `verify_event_with_public_key()` | Signing / crypto-agility removal |

### Delegation (`on_behalf_of`)

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:104` | FR-03: `on_behalf_of` field — *"delegation indicator for agent actors acting under a human principal"* | Action-delegation credentials, REMOVE-scope (`plans/032-final-public-release.md:60`) |
| `spec.md:148` | FR-15 canonical envelope includes `on_behalf_of` in the signed bytes | Same — tied to the signing envelope being removed |

### Witness co-signing

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:696-709` | §17.14 in full: Ed25519 witness registration, signature verification on delivery, `principal_keys` enrollment history, webhook delivery as "non-evidentiary transport" | Witness/anchoring machinery, REMOVE-scope (`plans/032-final-public-release.md:61`) |

### Transparency-log anchoring

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:73` | §3 Scope: anchoring listed in "Out of scope" but annotated *"~~implemented (FR-30)~~ **REMOVED by P1.4**"* | Already self-marked removed in the 0.6.0 line; still describes machinery in present-tense detail immediately below (FR-30) |
| `spec.md:229` | FR-30: ~~anchoring~~ marked REMOVED by P1.4, but the entry then spends the rest of the bullet (several hundred words) describing `AnchorProvider`, `OpenTimestampsProvider`, receipt state machine, CLI verbs, error codes, in full present-tense implementation detail as "historical description follows" | Same subsystem; retained prose is long enough that a skimming reader reaches the mechanism before the removal notice fully registers |
| `spec.md:643-665` | §17.9.2 in full: same anchoring mechanism, "canonical public-anchor story," residual-risk analysis, closing claim *"events covered by a confirmed external anchor cannot be modified post-hoc without detection by any third party"* (`spec.md:664`) | Same. Note: this section already carries its own `REMOVED by P1.4` banner at `spec.md:645` — it is the one place in `spec.md` that already does what F4 needs to do everywhere else in this list. Use it as the template for the rewrite. |

### Global event hash chain / non-repudiation framing

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:674-681` | §17.11: `prev_global_event_hash`, singleton `event_chain_head` lock, `global_seq BIGSERIAL`, replay walk from genesis | Not itself signing, but built as the substrate the removed anchoring/bundle trust story sat on (§17.9.2 cites "BC-300" from this section). Plan 032's D16 ruling on Plan 014 applies directly: *"Historical as a timestamping design. Preserve per-item ordering... If any project-wide event cursor is retained it must be defined explicitly and NOT inherit this plan's guarantee"* — the same caveat applies here: a `BIGSERIAL`-backed global chain is not gap-free under concurrent commits, and F4 must not restate §17.11 as a load-bearing consistency/non-repudiation guarantee without that caveat. |

### Hooks (async) vs validators (sync) — split disposition, do not flatten

| Location | Claim | Disposition |
| -------- | ----- | ----------- |
| `spec.md:136-138` | FR-13, transition validator half: in-transaction, synchronous, gates commit | **Retained** per D16's ruling on Plan 020 — this is exactly the "small trusted synchronous validation extension" Plan 032 keeps. Not a conflict; listed here so F4 does not accidentally delete the validator half while removing the hook half. |
| `spec.md:139-142` | FR-13, hook half: durable `hook_queue` table, LISTEN/NOTIFY, retry-with-backoff, dead-letter | REMOVE-scope — "async hooks/webhook delivery," `plans/032-final-public-release.md:65` |
| `spec.md:143` | FR-14: `requeue_dead_lettered_hook` | Same — hooks REMOVE-scope |
| `spec.md:60` | §3 Scope: *"Sync and async hook dispatch"* listed as in-scope | Async half REMOVE-scope; sync half (validators) retained |
| `spec.md:205` | FR-21: metrics list includes *"hooks dispatched/succeeded/failed/dead-lettered"* | Hooks REMOVE-scope |
| `spec.md:297-299, 308, 311` | §8 error table: sync/async hook failure rows, dead-letter requeue failure, LISTEN/NOTIFY drop, NOTIFY payload cap | Async-hook rows REMOVE-scope; sync-hook-failure row retained (it is the validator-refusal case D16/020 keeps) |
| `spec.md:330, 332, 338` | §9 NFRs: hook delivery mechanism, dispatch lag, sync-hook timeout | Async NFRs REMOVE-scope; sync-hook timeout bound retained as a validator property |

### Recurrence

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:225-227` | FR-28 in full: `recurrence_rules` table, interval/RRULE schedules, public API | Recurrence scheduling, REMOVE-scope (`plans/032-final-public-release.md:65`) |

### Workflow composition (`extends:`)

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `spec.md:72` | §3 Scope: *"Workflow file composition across files via `extends:` — **implemented (FR-29)**"* | D21 ruling: remove for 0.8.0 (`plans/032-open-decisions-review.md` D21) |
| `spec.md:228` | FR-29 in full: deep-merge, keyed list merge, cycle detection, max depth, `WORKFLOW_COMPOSE_ERROR` | Same |

---

## 3. `AGENTS.md` — every normative claim Plan 032 removes

`AGENTS.md` is denser than `spec.md` here because it doubles as a change-log
("Plan NNN additions") as well as a contract. Each row below is a place the document
states current, correct, shipped behavior for a REMOVE-scope subsystem — not a place
merely mentioning a plan number in passing.

| Location | Claim | Removed by |
| -------- | ----- | ---------- |
| `AGENTS.md:9` | *"`spec.md` is authoritative. `spec.yaml` is a machine-readable sidecar."* | See §1 above — the pointer itself, plus D15's separate ruling that `spec.yaml` is retired (no consumer found; see `plans/032-plan-dispositions.md`) |
| `AGENTS.md:28` | *"Library is the sole signer (HMAC-SHA256 over RFC 8785 canonical JSON). API rejects pre-signed events."* | Signing removal |
| `AGENTS.md:51, 52, 53` | Source-layout table: `_signing.py`, `_jcs.py`, `_keys.py` described as shipped signing modules | Signing removal (module-level; out of scope for me to edit `src/`, but the AGENTS.md *description* of them as current is what F4 must change) |
| `AGENTS.md:61-62` | `_recurrence.py`, `_recurrence_api.py` described as shipped | Recurrence removal |
| `AGENTS.md:66` | `_maintenance.py` — *"MaintenanceThread — timer-driven sweep/recurrence/witness"* | Recurrence + witness halves REMOVE-scope; the sweep half (expired claims) is retained per the kernel's claim/lease contract — see the 009 plan marker for the same split |
| `AGENTS.md:67` | `_signing_scheme.py` — *"SigningScheme protocol + HMACSHA256Scheme + Ed25519Scheme"* | Signing removal |
| `AGENTS.md:70` | `_witness.py` described as shipped | Witness removal |
| `AGENTS.md:71-72` | `_config.py`, `_secrets.py` — *"Suite config resolver"*, *"Secret backend resolver: file/env/literal/vault/azure"* | Suite configuration discovery / cross-component provisioning, REMOVE-scope (`plans/032-final-public-release.md:63`) |
| `AGENTS.md:75-78` | `_principal_keys.py`, `_trust_log.py`, `_trust_projection.py`, `_estate_catalog.py` described as shipped | Trust domain / principal custody / estate catalog, REMOVE-scope (`plans/032-final-public-release.md:60`) |
| `AGENTS.md:79` | `_custody.py` — *"Backend-aware private-key custody helper"* | Key custody removal |
| `AGENTS.md:80` | `_encryption.py` — *"Payload encryption-at-rest primitive: field-level AES-256-GCM"* | Field encryption serving the removed evidence system, REMOVE-scope (`plans/032-final-public-release.md:64`) |
| `AGENTS.md:85-93` | Whole `sidecar/` package description (`app.py`, `auth.py`, `routes.py`, bearer-token registry) | Sidecar removal (D3) |
| `AGENTS.md:95-96` | `docs/suite-config.md`, `docs/review-assurance.md` listed as current reference docs | Suite config + assurance removal |
| `AGENTS.md:131-158` | "Public API (§19)" code block: `hmac_key_path=` on every constructor call, `sign_spec`/`read_spec_events`, `enroll_principal`, `verify_trust_log()` | Signing + spec-entity-signing + principal custody removal. Note: `hmac_key_path` appears as a **required-looking** kwarg on the very first two lines of the flagship code example (131, 134) — this is the same "quickstart requires a key file" problem `docs-and-public-claims.md` §3 flags for README; it exists here too. |
| `AGENTS.md:152` | *"`sub.replay(verify_principal_binding=True)` — verify event signatures against principal_keys registry"* | Principal custody removal |
| `AGENTS.md:153` | *"`sub.verify_trust_log()` — ... read-only pinned trust-log verification"* | Trust domain removal |
| `AGENTS.md:154-155` | `sign_spec` / `read_spec_events` — signed spec entity | Signing removal; also the specific mechanism D20 (test disposition ruling) retires: *"Retire with the signed spec entity"* |
| `AGENTS.md:156-157` | `enroll_principal` — *"issue+register Ed25519 keypair... backend-aware custody"* | Principal custody + key custody removal |
| `AGENTS.md:160-172` | "Phase 2 — hooks, validators, escalation, lint" block: `register_hook_handler`, `start_hook_consumer`, `claim_hooks`, dead-letter methods | Async hooks REMOVE-scope. `register_validator` (line 161) is the retained sync half — do not remove it along with the block. |
| `AGENTS.md:188-194` | Facade API block: `sub.hooks.*`, `sub.recurrence.*` | Hooks + recurrence removal |
| `AGENTS.md:198-213` | Witness facade + "legacy top-level" witness methods, in full | Witness removal |
| `AGENTS.md:215-218` | Maintenance block: `start_maintenance(sweep_interval=30, recurrence_interval=10)` | Recurrence half REMOVE-scope; sweep half retained (claim expiry sweep is ordinary kernel housekeeping) |
| `AGENTS.md:220-227` | "Suite cohesion (Plan 025)" block: `regista.config.resolve()`, `regista.secrets.resolve()`, `regista doctor --json`, `SUITE.lock` version surface | Suite configuration discovery, REMOVE-scope |
| `AGENTS.md:229-236` | Payload encryption-at-rest code block | Field encryption removal |
| `AGENTS.md:238-244` | Principal key registry facade (`sub.principals.*`) | Principal custody removal |
| `AGENTS.md:246-249` | Provisioning block: `provision()`, `provision_principal()` | Suite provisioning + key custody removal |
| `AGENTS.md:251-252` | Signer binding verification: `verify_event_principal_binding` | Principal custody removal |
| `AGENTS.md:254-257` | "Trust hardening (Plan 008)" block: `strict_roles=True`, env-var key injection, key rotation status | `strict_roles` (role enforcement) is application policy and **retained**; the surrounding "Trust hardening" framing and env-var *key* injection specifically are signing-key machinery and REMOVE-scope. Do not delete the whole block — split it, same pattern as the hooks/validator split above. |
| `AGENTS.md:272-277` | "API constraints" bullets: principal key registry locking, signer binding, per-principal signing, replay principal binding (the line-275 non-repudiation claim, already in §1), provisioning, spec entity signing | Same set as the code-block claims above, restated as prose constraints |
| `AGENTS.md:282` | Key Design Decision 2: *"Optional `start_maintenance()` runs sweep/recurrence in a background thread"* | Recurrence half REMOVE-scope |
| `AGENTS.md:284` | Key Design Decision 4: *"Signing is internal. RFC 8785 canonicalization... + HMAC-SHA256 computed inside the library."* | Signing removal — this is a top-level "Key Design Decision," i.e. exactly the kind of durable claim F4 must replace, not just the code examples |
| `AGENTS.md:293` | "Status" section: *"MVP + Phase 2 + Phase 3 + Plans 002-022 implemented. All FRs FR-01 through FR-29 are in tree."* | Accretive "everything ships" framing is the opposite of Plan 032's bounded-MVP posture (`plans/032-final-public-release.md:26`); also already noted in `docs-and-public-claims.md` §5 item 5 |
| `AGENTS.md:306-307` | "Plan 005 additions" — sidecar description as shipped current capability | Sidecar removal |
| `AGENTS.md:311-314` | "Plans 007-009 additions" — Plan 008 (trust hardening WS-1..WS-5), Plan 009 (MaintenanceThread) | Trust hardening (signing-key half) + recurrence/witness half of MaintenanceThread REMOVE-scope; `strict_roles` (WS-1) and the sweep half of Plan 009 retained |
| `AGENTS.md:316-318` | "Plans 011-012 additions" — pluggable signing, RFC 3161 timestamping | Signing + timestamping removal |
| `AGENTS.md:320-321` | "Plan 013 additions" — witness/co-signature | Witness removal |
| `AGENTS.md:329-347` | "Plans 025/026/029/030 additions" in full — suite cohesion, Vault/AKV secret backends, principal Ed25519 registry, backend-aware key custody, payload encryption-at-rest | Suite config, key custody, principal custody, field encryption — all REMOVE-scope |
| `AGENTS.md:419-423` | "Patterns → Telemetry via hooks" — points to `examples/telemetry_via_hooks.py` as *"a complete, runnable minimal example"* | The example is deleted this pass (D18). This reference now points at a file that no longer exists. **Not fixed here** — AGENTS.md is out of scope for this pass (F4 territory) — but flagged so F4 does not miss it; it is the one piece of textual breakage this pass's deletions directly cause in a file I am not allowed to edit. |

---

## 4. What survives, stated so F4 does not over-delete

Cross-referencing D16/D20's rulings so the F4 rewrite has the positive list next to the
negative one:

- **Sync transition validators** (`spec.md:136-138`, `AGENTS.md:161`, `AGENTS.md:188`
  `sub.hooks.register_validator` naming aside — the *synchronous, in-transaction*
  primitive) — retained, per D16's ruling on Plan 020. Must fail the transaction on
  refusal or exception; not a sandbox; DB `statement_timeout` does not bound arbitrary
  Python computation (spec.md:138 already says this correctly — keep it).
- **`strict_roles` / role-gating** (`spec.md` FR-12, FR-24; `AGENTS.md:270`) — retained
  as ordinary application-policy enforcement, not authentication.
- **Claim sweep** (`sweep_expired_claims`, part of `AGENTS.md:216`'s
  `start_maintenance`) — retained; only the recurrence/witness half of the maintenance
  thread goes.
- **Per-item event ordering and the per-work-item hash chain as a consistency check**
  (not the global chain, not an authenticity claim) — retained per D5/D16's ruling that
  an unkeyed hash chain is fine as long as it is never presented as authenticity
  evidence.
- **Workflow YAML validation itself** (`spec.md` FR-17, the closed field-type
  vocabulary) — retained; only `extends:` composition (FR-29) goes.

---

## 5. Independent staleness (not caused by Plan 032)

- `spec.yaml:3` — *"Regenerated against spec.md v8 (2026-05-26)"* — while `spec.md:9`'s
  own revision history is at **v9** (2026-06-23, Plan 022). This predates and is
  independent of the 0.8.0 reduction; it is additional evidence for D15's retirement
  ruling (a hand-maintained sidecar that was already a revision behind its source before
  any of this started), not something to fix by regenerating. See
  `plans/032-plan-dispositions.md` for the full D15 disposition and the consumer search
  that supports retiring it.
