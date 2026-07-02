# Plan 025 — Suite cohesion: the spine's contracts

**Status:** Proposed 2026-07-02
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** regista is the spine every other suite member is a client of,
so the contracts that let the suite deploy *as a suite* — one config vocabulary,
one store-bootstrap, one health shape, one version matrix — are regista's to
define. See `/projects/agent-suite-blueprint.md` for the whole-suite picture;
this plan is Phase A (the gate that unblocks every consumer's adoption work).
regista's own feature roadmap (Plans 019–024) is unaffected; this is additive
deployment surface, not a change to the store's semantics.

## Ground truth at time of writing

- regista is public (MIT), on `hraedon/regista`, `main` = origin. A permanent
  converged production store exists on `mvmpostgres01` (dedicated `regista` DB,
  per-project schemas, prod signing material at `~/.config/regista/keys.json`),
  stood up 2026-06-29; ~865 work-items migrated + verified.
- Consumers install via `pip install "regista @ git+…@main"` and each invented
  its **own** env vocabulary for the same three facts — DSN, signing key, project
  slug (see the blueprint §2.1 table). regista itself defines none of these
  names, so there is no canonical spelling to converge on yet.
- `deploy/sidecar/` (a Dockerfile + README) exists; there is no schema/key
  provisioning command and no version/compat surface a consumer can pin against.
- The signing/hash-chain/replay-verify primitives are shipped and proven by
  siblings (dossier, agent-notes, agent-provenance, sluice).

## Principles this plan must hold

- **Additive, not semantic.** Nothing here changes event semantics, the hash
  chain, or the workflow engine. It adds a config-name contract, a provisioning
  command, a doctor shape, and a version declaration — surface, not core.
- **regista stays a library first.** The `provision`/`doctor`/version surfaces are
  a thin CLI/API layer that imports the library; the library remains usable
  without them (consumers that embed regista are unaffected).
- **Backward compatible for one release.** Introducing canonical names must not
  break the consumers' current vars overnight; the contract defines aliases and a
  one-release deprecation, and this plan ships the *spec* the consumers adopt.

---

## Phase 1 — The config-name contract (`REGISTA_*`) + layered resolution

### WI-1.1 — Canonical env vocabulary + a layered reference loader
- Define and document the canonical suite vars: `REGISTA_DSN`, `REGISTA_KEY_PATH`
  (signing material), `REGISTA_REQUIRE_SSL`, and the convention that each consumer
  supplies its own `<TOOL>_PROJECT` slug. Ship a reference resolver in regista
  (`regista.config.resolve()`) with the **multi-user layering** (blueprint §2.6):
  process env → per-user `~/.config/agent-suite/suite.env` → system
  `/etc/agent-suite/suite.env` (or `%ProgramData%\agent-suite\suite.env` on
  Windows) → default. Any consumer calls or mirrors it.
- **AC:** `docs/suite-config.md` specifies the vocabulary + the four-level
  precedence + the one-release alias/deprecation policy; the resolver is
  unit-tested for the precedence order incl. the per-user-over-system case; a
  `suite.env.example` ships with placeholders (no real DSN); the loader resolves
  the Windows `%ProgramData%` system path.

### WI-1.2 — Secret-backend resolver (Vault / AKV / Windows-native)
- The blueprint §2.5 contract: a config value may be a literal, a `file:` path
  (default), or a `backend:` ref. Ship `regista.secrets.resolve(ref)` with
  pluggable providers behind extras — `[vault]` (HashiCorp KV v2, AppRole auth,
  reusing the homelab pattern), `[azure]` (AKV via Managed Identity / service
  principal), `[windows]` (DPAPI-protected blob via Credential Manager). The DSN
  password and `REGISTA_KEY_PATH` both resolve through it, so no consumer reads a
  plaintext key file directly.
- **AC:** each provider round-trips a secret in an integration test gated on that
  backend's availability (skipped cleanly in CI when absent); a `file:` ref is the
  default and needs no extra; an unresolvable ref fails with a named,
  backend-specific error, never a silent empty secret; the ref syntax is
  documented and stable.

## Phase 2 — `regista provision` (the bootstrap gate) + the multi-user model

### WI-2.1 — Idempotent schema + service-role + principal-key provisioning
- `regista provision --project <slug> [--project …]`: create the per-project
  schema(s) if absent, run migrations, create the **per-project service role**
  (`regista_<slug>`, scoped to that schema — blueprint §2.6) if absent. For
  **per-actor signing** (Plan 026): `regista provision-principal --project <slug>
  --principal <id>` issues an Ed25519 keypair, stores the **private key in the
  secret backend** (WI-1.2), and **registers the public key** in Plan 026's
  registry — never overwriting an existing principal key (print and exit if
  present). Re-running is a no-op; `--dry-run` prints the plan. Bootstrap step 2;
  gates every face.
- **AC:** against an ephemeral Postgres, `provision` creates N schemas + N scoped
  service roles (each able to touch only its own schema — cross-schema denied);
  `provision-principal` issues a keypair, stores the private half in the backend,
  registers the public half, and is a no-op on re-run; an existing principal key is
  never clobbered; `--dry-run` writes nothing; an unreachable DSN or backend aborts
  before any partial write.

### WI-2.2 — `provision --verify` reconciliation check
- Reports, per project, whether the schema version matches the installed regista,
  whether the service role exists with correct scope, and whether each expected
  principal's private key is resolvable from the backend **and** its public key is
  registered (Plan 026) — the precondition a consumer's `doctor` (Phase 3) consumes.
  No mutation.
- **AC:** reports version-behind / role-missing / principal-key-unresolvable /
  pubkey-unregistered as distinct, named states; exits non-zero on a drift when
  `--exit-code` is set.

### WI-2.3 — Multi-user identity + isolation documentation
- Document (in `docs/multi-user.md`) the model the faces implement against: one
  shared per-project log, per-project service-role DB access, per-human
  `principal_id` from one workplace identity source, and **per-actor Ed25519 signing
  in v1** (Plan 026) — each principal signs with its own key, verified against a
  registered public key, giving cryptographic non-repudiation. This is the contract,
  not code, but it's regista's to own because it defines what "shared backend,
  multiple users" means for every consumer.
- **AC:** the doc states the isolation guarantees and their limits honestly (DB
  boundary is per-project not per-user; per-user trust is per-actor signature +
  attribution; the guarantee proves *who signed*, not that content is *true*);
  each face plan references it.

## Phase 3 — The doctor JSON contract

### WI-3.1 — `regista doctor --json` + the documented shape
- `regista doctor --json` emits the canonical suite health shape:
  `{component:"regista", version, regista:{reachable, schema_version, projects:[…]},
  checks:[{name, status, detail}]}`. Document the shape in `docs/suite-config.md`
  as the contract every suite tool's `doctor --json` conforms to (so a suite-doctor
  umbrella can aggregate them).
- **AC:** the JSON validates against a documented schema; `reachable:false` on an
  unreachable DSN is a clean status, not a traceback; the shape doc is explicit
  enough that a consumer can conform without reading regista's source.

## Phase 4 — The version / compatibility surface

### WI-4.1 — Declared interop versions
- Expose the versions a consumer must pin against: regista library version, schema
  version, canonical-workflow version, and envelope version — as both a
  `regista.versions()` API and a `regista version --json`. This is what a
  `SUITE.lock` records and what the suite-interop CI asserts.
- **AC:** `version --json` reports all four; a golden test locks the shape; the
  numbers match what `provision`/migrations actually apply.

### WI-4.2 — Suite-interop test harness (regista's half)
- A reusable pytest fixture / helper (published in regista) that stands up an
  ephemeral store, provisions two projects, and exposes a client — the substrate
  the suite-interop CI (blueprint Phase E) uses to drive one work-item across the
  human and agent faces. regista ships the fixture; the suite repo wires the
  cross-face test.
- **AC:** the fixture provisions + tears down cleanly in CI; a smoke test drives a
  work-item through the canonical workflow to `done` using it.

### WI-4.3 — `spec.yaml` as a signed founding artifact (authoring front door)
- The authoring front door (blueprint §"The authoring front door") emits a
  `spec.yaml` (from `hraedon/socratic-specification`) that project-initiation signs
  into regista as a project's **event zero**, so the audit chain runs spec → work →
  review → done. regista's part is small: accept a signed **spec entity** (an entity
  kind per Plan 022's generalization — `entity(kind="spec")`) with a declared
  `spec_schema_version`, so the founding spec is a first-class, version-pinned,
  verifiable record like any other event. regista does **not** parse/interpret the
  spec — it stores and signs it; the schema is socratic-specification's to own and
  version.
- **AC:** a `spec.yaml` (+ `spec.md` hash) signs into a project as its first entity
  with a recorded `spec_schema_version`; `verify` includes it in the chain; an
  unrecognized spec-schema version is a named, non-fatal state (stored, flagged),
  never a silent accept; regista holds no spec-parsing logic.

## Sequencing & notes

- **This plan is the suite's gate.** WI-1.1 (config contract) and WI-2.1
  (`provision`) unblock every consumer plan; land them first.
- **No conflict with regista's feature roadmap.** Plans 019–024 (transparency-log
  anchoring, entity generalization, chain-integrity repair) are orthogonal — this
  plan touches CLI/config/packaging surface only. If entity-generalization (Plan
  022) changes the envelope version, WI-4.1 simply reports the new number; the
  contract is version-agnostic by design.
- **Homelab already satisfies the runtime** (prod store on `mvmpostgres01`); this
  plan makes that setup *reproducible and consumable*, which is what a work
  deployment needs and the homelab got by hand.
- **Cross-platform:** `provision`/`doctor`/`config`/`secrets` are stdlib + the DB
  driver + the backend SDKs — they run on Linux and Windows unchanged; the only
  OS-specific surface is the `[windows]` secret provider (DPAPI) and the
  `%ProgramData%` config path, both guarded so a Linux install never imports the
  Windows provider. The architecture/import test grows a guard for that.
- **WI-1.2 (secret backends) and WI-2.1 (service roles) are the new load-bearing
  work this revision adds** — they are what make "shared Postgres, multiple users,
  real secret custody" true rather than aspirational. Weight their review and
  their per-backend integration tests accordingly.
