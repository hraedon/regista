# Plan 026 — Per-actor Ed25519 signing (non-repudiation for the multi-user suite)

**Status:** Implemented 2026-07-06. WI-1.1–3.3 landed (Sessions 80–86); principal binding and enrollment lifecycle complete.
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** Promote per-actor cryptographic non-repudiation to **v1** of
the suite. Today regista can sign an event log with *a* key; the multi-user suite
(blueprint §2.6) needs every principal — each human and each agent — to sign with
*its own* key, so "user X's agent did Y" is provable against X's registered public
key rather than asserted in an actor field a shared key could forge. This is the
capability that makes the suite's audit story real for a regulated, multi-user
deployment, which is why it is v1 and not the deferred seam it was drafted as.
This plan is **regista core** (the envelope signing/verify path), distinct from the
suite-cohesion surface in Plan 025 (which *provisions and custodies* the keys this
plan defines).

## Ground truth at time of writing

- **The hard crypto already exists.** regista Plan 011 (Pluggable Signing) landed a
  `SigningScheme` protocol, an `Ed25519Scheme` alongside `HMACSHA256Scheme`, a
  `scheme_id` column on `events`, and a per-event verifier registry so replay
  selects the right verifier. Existing events stay HMAC; Ed25519 is opt-in per key
  entry. BC-196 accepted pluggable signing as first-class.
- **What's missing is *per-principal* identity of keys.** Signing today is keyed by
  a key *file/entry*, not by the *acting principal*. There is no principal→public-key
  registry, so a verifier cannot say "this event was signed by principal P's key,"
  only "this event verifies under key K." Non-repudiation needs the former.
- Plan 022 (crypto-agility / PQC-readiness) is the envelope layer that lets the
  scheme evolve without a break — so a future PQC scheme is a swap, not a redesign.
- Actor attribution (`actor_id`, per-schema `actor_roles`) already exists and gates
  transitions; this plan binds that identity to a key, closing the gap between
  "who the event claims to be from" and "who cryptographically signed it."

## Principles this plan must hold

- **Build on Plan 011, don't re-do it.** The `SigningScheme`/`Ed25519Scheme`
  machinery stays; this plan adds the principal-key *binding* and *registry* on top.
- **The signed actor must equal the signing key's principal.** An event whose
  `actor_id` does not match the principal that owns the verifying public key is a
  **verification failure**, not a warning — that equality *is* the non-repudiation
  guarantee. Forging an actor field no longer works because the signature won't
  bind.
- **Public keys are non-sensitive and distributable; private keys never leave the
  signer.** The registry holds public keys (freely shippable to auditors); private
  keys live only in the secret backend (Plan 025 WI-1.2), loaded by the signing
  principal's process alone.
- **Backward compatible.** Existing HMAC-signed history stays valid and verifiable;
  the chain does not need re-signing. A project opts into per-actor Ed25519 going
  forward; verify handles a chain that transitions schemes mid-stream (Plan 011
  already selects verifier per event).
- **UNKNOWN/unregistered is a named result.** An event signed by a key with no
  registered principal is an explicit verification state ("unregistered signer"),
  never silently trusted or silently dropped.

---

## Phase 1 — The principal → public-key registry

### WI-1.1 — Registry schema + API
- A registry binding `principal_id → [public_key, scheme, valid_from, valid_to,
  status]` (multiple entries per principal for rotation). Placement respects the §3
  isolation tenet — a per-project registry by default; a shared-catalog option only
  if a principal spans projects (decide with the same care Plan 012/022 gave
  cross-project references). API to register, rotate, and revoke a principal's key;
  registration is itself a signed regista event (the registry is auditable too).
- **AC:** register/rotate/revoke round-trip; a revoked key stops verifying new
  events but past events it signed stay valid (valid_from/valid_to windows);
  registration events are in the signed log; mypy --strict clean.

### WI-1.2 — Signer identity binding on the envelope
- Extend the signing path so an event records the signing `principal_id` and the
  `scheme_id` (already present), and `verify` checks: signature valid under the
  registered public key **and** the event's `actor_id` matches that key's
  principal. A mismatch is a distinct, named failure.
- **AC:** an event signed by P and claiming `actor_id=P` verifies; the same event
  with `actor_id` altered to Q fails as `actor-signer-mismatch`; an event signed by
  an unregistered key fails as `unregistered-signer`; HMAC-era events verify
  unchanged.

## Phase 2 — Per-principal signing in the client path

### WI-2.1 — Load the acting principal's private key + sign with it
- The signing context resolves the acting `principal_id`'s private key via the
  secret backend (Plan 025 WI-1.2) and signs with it. Agents and humans each carry
  a principal key; a process that lacks the acting principal's key **cannot sign as
  that principal** (it can only sign as itself) — the property that makes
  impersonation cryptographically, not just politely, impossible.
- **AC:** two different principals writing to the same project produce events that
  verify under their respective registered keys; a process without principal P's
  key cannot produce a P-signed event; the private key never appears in logs or the
  event body.

### WI-2.2 — `verify` reports per-actor attribution
- `regista verify` (and the replay/chain-verify path) reports, per event, the
  verified signing principal — so an auditor reads "these 40 events were
  cryptographically signed by principal X, these 12 by X's agent" rather than a
  bare "chain intact." Feeds cairn's gap-report (agent-provenance Plan 008 WI-3.1)
  and dossier's verified-history view.
- **AC:** verify output attributes each event to its verified signer; a chain that
  mixes HMAC-era and per-actor-Ed25519 events verifies and labels each honestly;
  `--exit-code` gates on any verification failure.

## Phase 3 — Rotation, revocation, and migration

### WI-3.1 — Key rotation + compromise revocation
- Document and test the lifecycle: rotate a principal's key (new entry, old one
  windowed out for new signing but still valid for its historical events); revoke a
  compromised key (events after the compromise marker flagged for review). Rotation
  never invalidates correctly-signed history — the audit record is append-only and
  each event is judged against the key state at its time.
- **AC:** a rotation keeps old events valid and signs new ones with the new key; a
  revocation flags post-compromise events without corrupting the chain; both are
  themselves signed registry events.

### WI-3.2 — Opt-in migration for an existing project
- A documented path to move a project from HMAC (or single-key Ed25519) to per-actor
  Ed25519 going forward, without re-signing history. The homelab converged store is
  the first migration target (it is single-operator HMAC today).
- **AC:** a project switches to per-actor signing at a cutover point; verify handles
  the mixed chain; no historical event is rewritten; `docs/non-repudiation.md`
  describes the migration + the guarantee's honest boundary (it proves *who signed*,
  not that what they wrote is *true*).

### WI-3.3 — Enrollment, escrow, and break-glass (the lifecycle mechanics) ✅ Landed
- The mechanics the human key-lifecycle UX (dossier Plan 015) and operational
  runbook (agent-suite Plan 001) sit on:
  - **Enrollment** — `regista principal enroll --principal <id>` and
    ``Regista.enroll_principal(...)``: issue keypair, private key → secret
    backend (file: by default), public key → registry, emit a signed enrollment
    event with ``entity_kind="principal"``, ``transition="principal_enrolled"``.
    Reuses ``provision_principal`` for custody and short-circuits when an active
    key already exists, so re-enrollment is idempotent and emits no duplicate
    event. **Humans never handle raw key material** — the private key lives in the
    backend and a face signs on the authenticated human's behalf; the human sees
    only a public fingerprint.
  - **Escrow / backup** — the private key's durability is the secret backend's own
    backup (Vault/AKV DR); the *registry* (public keys) rides the store's DR
    (Plan 001). An optional **break-glass escrow** seals a recovery key under
    dual-control so a lost-key principal can be re-enrolled without forging history.
  - **Break-glass** — a documented, dual-control emergency path to act/sign when the
    normal auth/identity source is unavailable, every use of which is itself a
    prominent signed event (break-glass that isn't loudly recorded is a backdoor).
- **AC:** enrollment issues+registers+signs in one idempotent call; a human's key
  never appears in a face's output or logs; a break-glass use produces a
  distinctly-flagged signed event; re-enrolling a principal after key loss preserves
  the validity of their pre-loss history (old key windowed, not deleted).

## Sequencing & notes

- **This plan and Plan 025 interlock:** 025 *provisions* per-principal keys (issue,
  store in the secret backend, register the public key) and its `doctor` checks the
  registry; 026 *uses* them in the signing/verify path. 025 WI-2.1's per-principal
  key issuance depends on 026 WI-1.1's registry existing.
- **Consumers gain non-repudiation for free** once this lands: agent-notes/cairn/
  dossier writes are already actor-attributed; per-actor signing binds that
  attribution cryptographically without a consumer code change beyond resolving the
  principal key (a Plan 025 config concern).
- **Cost is real but bounded** — the crypto (`Ed25519Scheme`) is done; this is
  registry + identity-binding + custody + lifecycle. It is the single highest-value
  provenance upgrade for the suite's regulated use case, which is why promoting it
  from the v2 seam to v1 is the right call. Weight the review of WI-1.2 (the
  actor↔signer equality check) heavily — it *is* the guarantee.
- **Not in scope:** threshold/multi-sig, hardware-token-held keys (a custody
  option Plan 025's Windows/gMSA path could later enable), and PQC schemes (ride
  Plan 022 when a scheme is chosen).