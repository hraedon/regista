# regista 0.6.0 — final architecture (authoritative entry point)

**Status: FROZEN for implementation, 2026-08-09.** Read this document first. It is short by
design: it fixes *precedence*, records the *binding decisions*, and points at the detailed
specifications. It does not restate them.

---

## 1. Precedence — read in this order, higher wins

When two documents disagree, the higher one governs. This ordering is not negotiable during
implementation; if a conflict is not resolved by it, stop and escalate rather than choosing.

| Rank | Document | Role |
|---|---|---|
| 1 | **`RECONCILIATION.md`** | The overlay. Corrects 14 parts of the architecture and resolves every cross-spec collision. **Governs everywhere.** **Applied in place to the siblings on 2026-08-09 (P0.1)** — each superseded clause now carries a marker stating its replacement; see `OVERLAY-APPLICATION.md` for the coverage matrix and `check-crossrefs.py` / `check-conflicts.py` for the two acceptance checks. |
| 2 | **This document** | Precedence, binding decisions, scope, gates. |
| 3 | `V6-ENVELOPE.md`, `CUTOVER-CLASSIFICATION.md` | Envelope format, canonicalization, hash domains, legacy classification. |
| 3 | `TRUST-DOMAIN.md`, `OPERATOR-FORGERY.md` | Trust root, key/identity lifecycle, publication, residual threat model. |
| 3 | `BUNDLE-V3.md`, `REVIEW-VERDICTS.md` | Signed bundle, verdict model, signed review verdicts. |
| 4 | `FIELD-MATRIX.md`, `RESULT-MODEL.md`, `CUTOVER-POLICY.md` | Pre-S1 frozen work. Still correct for v1–v5 semantics. |
| 5 | `ARCHITECTURE-0.6.0.md` | **Superseded in 14 places by rank 1.** Retained for reasoning and rejected alternatives. Its code citations are stale — use the concordance at `V6-ENVELOPE.md:1134-1147`. |
| — | `AUDIT-REPORT.md`, `preflight-live.json` | Evidence. Not specifications. |

**Do not treat `ARCHITECTURE-0.6.0.md` line numbers as current**, and do not reimplement the
permissive envelope classifier — S1 already made it strict.

---

## 2. What 0.6.0 is, in five sentences

0.6.0 establishes a new cryptographic epoch: strict v6 envelopes, Ed25519-only production signing,
signed identity and workflow state, content-bound review verdicts, and externally-rooted bundle v3
artifacts. Existing v4/v5 and HMAC events remain immutable and verifiable under explicitly limited
legacy semantics; a signed per-project cutover checkpoint binds each legacy history to the new
public-key epoch **without pretending to re-authenticate it**. Public keys move from project-local
mutable tables into a signed trust-domain log rooted in operator-supplied, externally published
fingerprints, with project-local tables demoted to rebuildable projections. The unused segment,
anchoring and timestamping implementations are **deleted, not repaired** — they carry no deployed
evidence and their presence preserves false security surfaces. After 0.6.0 regista can defend
against database-only tampering when signing keys are kept outside PostgreSQL; it still cannot
defeat a host operator who controls every signing key and every publication channel.

---

## 3. Binding decisions

Recorded as regista **WI-272** (governance, publication, lineage strictness, v5 relabel) and
**WI-277** (producer block). These are settled; implementation may not revisit them.

1. **Independent co-signer by default, with a one-way upgrade ratchet** (WI-280 — this *corrects*
   `TRUST-DOMAIN.md`). Governance is a **monotone signed log inside the trust domain**, not part of
   the `trust_domain_id` derivation: **the threshold may never decrease** (a verifier rejects a
   lowering event no matter who signed it), while **signers may be replaced at the current
   threshold** — so a compromised co-signer key is removable, which a pure append-only signer set
   would have prevented. Upgrading `solo_effective` → co-signed is therefore a cheap signed event
   with **no epoch change**, and downgrade is structurally impossible. Deriving governance into
   `trust_domain_id` (as the spec originally had it) made upgrade as expensive as a full epoch
   cutover *and* left downgrade equally available — expensive in both directions rather than
   impossible in one. Governance state is still **visible in the artifact, not configuration**:
   it is replayed from the signed log and stamped into verification output, every bundle and every
   published artifact. Modes: `co_signed`, `solo`, and `solo_effective` (`threshold=1` with
   `signer_count>1`) — the last exists to stop an estate listing several fingerprints, setting
   threshold 1, and calling itself co-signed. **Initial posture is `solo_effective`, deliberately
   and visibly.**
2. **Publication** to a git repository under an account distinct from the estate's operational
   identity, bootstrapped by direct exchange. **One command, canonical JSON.** The channel provides
   *substitution detection*, never prevention: retention, history and third-party hosting are the
   properties relied on, not authority. Format leaves room for a custodian countersignature or an
   anchor later **without a new epoch**.
3. **Lineage assurance is strict.** 0.6.0 claims only *principal-signed model-lineage assertion*.
   `independently_reviewed` is **policy evidence, not cryptographic proof of independence** — a
   principal can sign a truthful or untruthful claim about its own lineage and 0.6.0 cannot
   distinguish them. Governing rule, applied to every name in the release: **a name must not
   promise more than the check performs.**
4. **v5 relabels after cutover.** ~334,000 events move to `LEGACY_PARTIAL` with no byte and no
   cryptographic change. Release notes must present this as a **reclassification, not a
   regression**, and preflight must report the before/after distribution so it is expected rather
   than discovered.
5. **Principals are hosts and services, never models.** Host principals `agent:mvmcc03`,
   `agent:mvmcc02`, `agent:mvmhermes01`; service principals `service:agent-notes` and the other
   tooling identities; human `human:itadmin` (with `plm` a bound alias — same person — via
   `principal_alias_bound`, `binding_effect: reporting_join_only`, which joins records for
   reporting and never satisfies signature binding). Identities that are really models, harnesses
   or roles (`claude-fable-5`, `kimi-reviewer`, `adversarial-reviewer-*`, `opencode-session`, …)
   cease to be principals and become `producer.*` fields on an event signed by the host principal.
   A model holds no private key; treating one as a principal was a category error, and it is why
   the review gate has been comparing self-asserted strings.
6. **All three hosts are provisioned for all 26 projects.** mvmcc02 and mvmcc03 write everywhere;
   mvmhermes01 writes primarily to `vitrine` but must be able to write anywhere. There is no
   per-project host mapping to determine — 78 acceptance records, one per (host principal,
   project).
7. **`producer` block inside the signed envelope**: `{harness, harness_version, model,
   model_lineage}`, with `model_lineage` **moved** out of `actor.metadata`, never duplicated. Two
   homes for one concept is the shape that produced WI-257 and WI-250. Combined with per-host keys
   and a published host-principal → allowed-harness policy, this yields a cross-checkable
   invariant. Hosts: mvmcc03 (claude-code), mvmcc02 (claude-code, opencode, codex), mvmhermes01
   (hermes) — **not 1:1**.
8. **Recovery rotation requires the current root threshold**, not registrar authority. The
   registrar is online, and registrar-authority recovery was the only takeover path not requiring
   host root. Visible `recovery_rotated` classification is retained but is not a substitute for
   prevention.
9. **One signing key per host principal, not per harness.** mvmcc02's single host principal may
   assert any of its three allowed harnesses.
10. **No retrospective HMAC lifecycle or synthetic principal binding.** It would manufacture
   evidence that never existed.

---

## 4. Ground truth (measured, never hardcode)

From `preflight-live.json`, read-only against the live estate on post-S1 `origin/main`:

- 26 project schemas, ~353,985 events at measurement; `agent_provenance` alone holds 349,066.
- **hmac-sha256 304,333 / ed25519 49,652.** v5 335,290 / v4 18,695. Zero v1–v3.
- Zero row↔envelope mismatches, zero missing envelopes, zero unknown schemas, chains clean.
- **`regista-prod-001` signs 304,333 events (86%) and has ZERO `principal_keys` rows anywhere** —
  it resolves only from an operator key file (**WI-275**).
- **0 of 26 projects can cut over today** — no project signs with a locally-bound Ed25519 key.
- No `actor_id → principal_id` mapping exists in the store. It must be **assigned deliberately**,
  never inferred from string similarity.
- `global_seq` order is **not** chain order (45 phantom breaks when ordered that way). Security
  ordering is predecessor-link traversal only.
- Zero rows in `event_segments`, `anchor_receipts`, `tsp_batches`, `witness_receipts`,
  `witness_registrations` — the deletion premise holds.
- The store drifted ~500 events *during* measurement: rehearsal and ceremony require **quiesced
  writers**.

**Counts belong to a named snapshot and the locked ceremony transaction — never to source code or
a frozen payload.**

---

## 5. Scope

**In:** v6 envelope with producer block and full binding; consolidated result model and v5
reclassification; co-signed root with visible solo mode and root-threshold recovery; trust log,
canonical principal/host mapping, signed lifecycle, projection-only registries; per-host Ed25519
provisioning for all three hosts; forward nullable-workflow migration and signed workflow
registration; action delegation v1; signed review verdicts **conditional on reducer determinism**;
bundle v3 with signed membership and external trust policy; one-command git publication; WI-278
containment (compare/retain interim head, quiesced cutover, permanent rejection of post-checkpoint
HMAC/v5 writes); removal of inline secrets from `keys.json`; deletion of the dead subsystems;
operational blockers WI-216/235/247/251/252/260 to the extent needed for honest failure.

**Cut:** `declared-selection` bundles; positive witness-independence work; reducer extensibility
and cross-version compatibility; automatic periodic head publication; retrospective HMAC lifecycle;
repair of the old segment/anchor/timestamp/witness implementations.

**Still out:** new RFC 3161/OpenTimestamps provider; CT-style transparency or witness federation;
post-quantum; per-event signed `global_seq`; historical re-signing; new retention/object-storage
subsystem; HSM integration; unrelated encryption work; external IdP.

Quorum roots and git publication were previously excluded and are now **mandatory** (WI-272).

---

## 6. What 0.6.0 still cannot claim

Release notes must state all of these plainly. This section is not optional and not softenable.

1. Historical HMAC events are not independently attributable to individual principals — and after
   **WI-278**, successful verification under `regista-prod-001` proves only that bytes match a
   **disclosed** symmetric value. Rotation cannot repair this; the checkpoint and published interim
   head make later substitution detectable, they do not restore origin authentication.
2. The cutover checkpoint binds the exact legacy bytes its signer committed to; it does not prove
   pre-cutover history was honest when created.
3. Historical v4/v5 Ed25519 events are individually signature-verifiable but gain project placement
   only through the later checkpoint.
4. Retrospective WI-241 attestations may truthfully report `chronology_observed:
   enrollment_preceded_use` (measured: enrolment 02:40:21Z, first use 18:15:30Z) but may **not**
   claim contemporaneous project-local acceptance.
5. A signed bundle proves what its signer attested, and is externally authenticated only against
   auditor-supplied trust material.
6. Without a fresh externally published checkpoint, tail truncation after the last known checkpoint
   may remain undetectable.
7. No trusted timestamp and no public anchoring guarantee exists.
8. Signed actor/model-lineage metadata proves what the signer asserted, not which model or human
   actually generated the action.
9. Delegation credentials prove authorization under the configured trust root, not human intent.
10. A host operator controlling all roots, private keys and publication channels can fabricate a
    valid-looking history.
11. A local witness configured and stored by the same operator is not an independent witness.
12. `global_seq` remains an unsigned database index and is not cryptographic ordering evidence.

**Defensible headline:** *regista 0.6.0 makes event semantics, identity lifecycle, review verdicts
and exported membership cryptographically checkable against externally pinned Ed25519 trust
material, while preserving older history under explicitly limited legacy semantics. It does not
provide external timestamping, transparency-log publication, or protection against an operator who
controls every private key and observation channel.*

---

## 7. Gates

Detail in `RECONCILIATION.md` § THE CORRECTED SEQUENCE. Summary:

- **Gate 0 — freeze and conformance fixtures.** Overlay applied, schemas frozen, byte-level vectors
  committed, **reducer determinism proved**. Nothing else starts: incompatible hash fixtures create
  unrecoverable signed artifacts.
- **Gate 1 — trust and identity bootstrap.** Root keys, threshold-signed genesis, trust log,
  canonical host/writer principals, published producer policy.
- **Gate 2 — key provisioning. HARD PREREQUISITE.** All 26 projects must pass before rehearsal.
  *The cutover event imports prior trust authority; it does not provision a missing key.*
- **Gate 3 — quiesced full-estate rehearsal.**
- **Gate 4 — production containment ceremony.**

Parallel implementation tracks run after Gate 0 only.
