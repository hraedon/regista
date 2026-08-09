# regista 0.6.0 — implementation plan

**Read `ARCHITECTURE-FINAL.md` first** for precedence and binding decisions. This document assigns
work. Every package below names its gate, its dependencies, its owner, and — most importantly —
**how it is proved done**. A package whose acceptance criterion is "implemented" is not accepted.

## Standing rules for every package

1. **Precedence.** `RECONCILIATION.md` governs. Where a sibling spec conflicts with it, the spec is
   wrong. Do not silently choose — if the overlay does not resolve it, escalate.
2. **Read post-S1 code**, via `git -C regista show origin/main:<path>`. The shared checkout's
   working tree is on `release/0.5.6` and is **pre-S1**. Architecture line numbers are stale.
3. **Never run a writing git command in `~/projects/personal/rc-build/regista`.** Use your own
   worktree. This has caused one incident.
4. **Own database per agent** (`REGISTA_TEST_DSN`), never the shared `regista_test`.
5. **Never dump a credential store.** Inspect by explicit allowlist of non-secret fields
   (`key_id`, `principal_id`, `scheme`, `status`, `role`). This caused WI-278.
6. **Fail-then-pass evidence is mandatory.** Every test must be shown failing against unfixed code,
   with the observed output quoted. A test that cannot fail is not a test.
7. **Never weaken an assertion to make a build pass.** If an existing test encodes the old
   behaviour, change it deliberately and say so in the PR.
8. **Counts are measured, never hardcoded.** They belong to a named snapshot.
9. **Cross-lineage review before merge.** Same-lineage review is not a second opinion.

---

## Gate 0 — freeze and conformance fixtures

*Nothing else starts. Incompatible hash fixtures create unrecoverable signed artifacts.*

### P0.1 — Apply the reconciliation overlay · **owner: me** · **DONE 2026-08-09**
**Record:** `OVERLAY-APPLICATION.md`. Both acceptance halves are enforced by
`check-crossrefs.py` (0 unresolved references across 17 documents, code citations checked against
`334b995`) and `check-conflicts.py` (0 retired values stated as live rules). Re-run both before
any change to this set.
Apply `RECONCILIATION.md` to the sibling specs, or mark superseded clauses in place. Resolve the
two bootstrap circularities and the three ownerless artifacts into the documents that will be
implemented from. **Judgment-heavy and cross-cutting; I am not delegating it.**
**Done when:** every internal cross-reference resolves, and no two documents give conflicting rules
for the same field.

### P0.2 — Prove reducer v1 determinism under JCS · **owner: me** · **DONE 2026-08-09 — PASS**
**Record:** `P0.2-REDUCER-DETERMINISM.md`. Byte-identical across CPython 3.12/3.13/3.14 and PyPy
3.11, three hash seeds each. **P3.2 is GO.** Two real defects found and fixed: a cross-version
`fromisoformat` divergence that replay converted into a silent digest difference, and a JCS
number band (`2**53 <= |v| < 1e21`) that makes a signable, canonical event's digest
uncomputable — the latter forced an amendment to `V6-ENVELOPE.md` §2.5, so **P0.3's vectors must
be generated against the amended rule**.
The go/no-go for signed review verdicts. Must be byte-identical across machines and Python
versions. **If it fails, signed verdicts do not ship in this window** — transition-name inference is
removed and assurance reports `legacy_unverdicted/none` rather than shipping an unverifiable digest.
**Done when:** a committed conformance test proves byte-identity across at least two interpreters,
or the negative result is recorded and P3.2 is cut.

### P0.3 — Byte-level conformance vectors · **owner: team**
Commit vectors for: v6 envelope (regenerate — the producer block obsoleted the existing 15-key
vector at `V6-ENVELOPE.md:964-1029`), every bootstrap case, fingerprints, version-aware event
hashes, bundle Merkle tree, workflow definition digest, review subject, delegation, genesis,
checkpoint, producer policy, catalog.
**Done when:** each vector is reproducible from a clean checkout by a documented command, and a
deliberate one-byte change to each input flips its expected hash.

---

## Parallel tracks (after Gate 0 only)

### P1.1 — v6 envelope · **owner: team** · dep: P0.1, P0.3
Strict parser, 16 required members including `producer`, project/trust/scheme/workflow/delegation
binding, rejection of unknown fields and versions, no fallback on failure.
**Done when:** the mutation matrix covers every signed field (each rewrite named in
`mismatched_fields`), unknown-schema and degenerate-value cases fail closed, and the vectors pass.

### P1.2 — Forward migration: nullable workflow columns · **owner: me** · dep: P0.1
`events.workflow_name`/`workflow_version` are `NOT NULL` since migration 001, so the checkpoint —
the first v6 event in **every** project — cannot be inserted. Touches all 26 projects and is
irreversible in production. **Do not fudge with `""`/`0` sentinels**: the segment seal already does
that, and in v6 the envelope would *sign* the falsehood.
**Done when:** migration applies and rolls back cleanly on a copy of the live schema set, and a
checkpoint inserts with genuinely null workflow identity.

### P1.3 — Consolidated result model + v5 reclassification · **owner: team** · dep: P0.1
Extend `VerificationResult` for v6. Post-cutover, v4/v5 become `LEGACY_PARTIAL`.
**Done when:** preflight reports the before/after label distribution, and the ~334k relabel is
demonstrated on a copy rather than asserted.

### P1.4 — Delete the dead subsystems · **owner: team** · dep: P0.1
Remove `_archive_segments.py`, `_anchoring.py`, `_timestamping.py`, the window/segment/manifest
machinery in `_bundle.py`, and their tests (~6,300 lines). Zero rows exist estate-wide.
**Done when:** the suite is green with them gone, no security claim referencing them survives in
docs, and `regista doctor` no longer reports on subsystems that do not exist.

### P1.5 — `keys.json`: no inline secrets · **owner: team** · dep: none
ed25519 entries already use `secret_ref`; the HMAC entry embeds the value. That inconsistency
caused WI-278.
**Done when:** loading a file containing an inline secret fails with a named error and a migration
path, and legacy HMAC verification works through `secret_ref` only.

### P1.6 — Operational blockers · **owner: team** · dep: none
WI-216, WI-235, WI-247, WI-251, WI-252, WI-260 — only to the extent needed to make provisioning,
migration, doctor, replay and ceremony **fail honestly**. Also clear the dangling replay temp tables
in 23 of 26 schemas (WI-252 debris).
**Done when:** each failure path reports a distinct, actionable error rather than a generic one.

---

## Gate 1 — trust and identity bootstrap · dep: P0.*, P1.1

### P2.1 — Trust-domain genesis · **owner: owner executes, I prepare and verify**
Independent root keys, threshold-signed genesis, `trust_domain_id` derived from the binding core.
**I will not generate or handle root private key material** — I disclosed a secret in this session
(WI-278), and the trust root is precisely the wrong place to accept that risk. I will prepare the
ceremony, script the non-secret steps, and verify the artifacts afterwards.
**Done when:** genesis verifies from a fresh direct-exchange pin, `solo` vs `co-signed` vs
`solo-effective` is distinguishable from the artifact alone, and the mode is visible in every
downstream artifact.

### P2.2 — Trust log + signed key lifecycle · **owner: team** · dep: P2.1
v6/Ed25519 from its genesis event, no legacy epoch. Enrollment payloads **must carry public key
bytes** — a fingerprint alone makes the projection unrebuildable and silently defeats the remedy
(WI-273). Make the existing mutators private event-driven appliers so bypass paths break at
**import** time; documentation is not a control, and the bypass is what happened last time.
**Done when:** the registry rebuilds from signed events alone, and every previously-bypassing caller
fails to import rather than fails review.

### P2.3 — Canonical principals and host mapping · **owner: team** · dep: P2.1
Canonical `kind:subject`, kinds closed to `{human, agent, service}`; witness principals become
`service:witness.<id>` (zero live instances — cheap). Assign the `actor_id → principal_id` mapping
**deliberately**; it does not exist in the store and must not be inferred from string similarity.
**Done when:** every writing actor resolves to exactly one canonical principal, recorded as signed
scoped mappings.

### P2.4 — Publication · **owner: team** · dep: P2.1
One command, canonical JSON, distinct account, append-only index with `prev_commit` links, no
private key in the publishing process.
**Done when:** `--dry-run` is byte-identical to the real run, and a verifier pins from direct
exchange then detects a substituted fingerprint.

---

## Gate 2 — key provisioning · **HARD PREREQUISITE** · dep: Gate 1

### P3.1 — Per-host Ed25519 provisioning (WI-276) · **owner: team; key generation with owner**
One key per **host principal**, not per harness. Private material via `secret_ref`, Vault custody.
**Resolve the two `hermes-agent` keys explicitly** — the host-active key differs from the
registry-active key and neither has ever signed; do not choose by the `active` label alone.
Enroll each public key with proof of possession, and verify the signer-selection function picks
that exact key.
**Done when:** preflight reports **26 of 26 `ready_for_bootstrap_checkpoint`** — measured, not
asserted. A key existing in another schema is not ready. *The cutover imports prior trust authority;
it does not provision a missing key.*

---

## Gate 3 — quiesced rehearsal · dep: Gate 2

### P4.1 — Full-estate rehearsal · **owner: me, with team support**
Writers quiesced (the store drifted ~500 events during measurement, so byte-comparison is
impossible otherwise). Compare against the published interim head record.
**Done when:** a full rehearsal on a restored copy produces a verifying checkpoint per project and
a bundle that authenticates to an externally pinned root.

---

## Gate 4 — production ceremony · dep: Gate 3 · **owner: me, owner present**

### P5.1 — Cutover · **owner: me + owner**
Quiesced, one locked transaction per project, checkpoint signed and published, post-checkpoint
HMAC/v5 writes permanently rejected. Irreversible.
**Done when:** every project verifies end to end across the seam, the catalog is published, and a
post-checkpoint HMAC write is refused.

---

## Deferred, tracked, not in this window

### P3.2 — Signed review verdicts · **owner: team** · dep: **P0.2 passing**
Signed verdict subject with content binding, monotonicity (freeze the author set at the deciding
verdict), one `decide_lineage()` consumed everywhere, honest assurance names
(`cross_lineage_asserted`, `accepted_by_declared_human`, `same_lineage_asserted` /
`lineage_undetermined`, `legacy_unverdicted`). **WI-250 must be rewritten first — its headline
claim is stale** (`adversarial_review` does now use `LineageRelation`; the live defect is that the
check is gated on `reviewer_is_agent and agent_author`, so a human reviewer with no delegation skips
it entirely).

### P3.3 — Bundle v3 · **owner: team** · dep: P1.1, P2.4
Signed membership over a Merkle tree ordered by **chain traversal, never `global_seq`**. Trust
material is a **required argument with no default** — that function-signature change is the
structural fix for BC-016, not a policy flag. Drop `format_version` 1 entirely.
**Done when:** an auditor can follow the documented workflow without the author present, and a
bundle whose keys come only from itself cannot report external authentication.

---

## Summary of ownership

**Me:** P0.1 overlay, P0.2 reducer determinism, P1.2 forward migration, P4.1 rehearsal, P5.1
ceremony, plus final review of every team PR before merge.

**Owner:** root key generation (P2.1), present for the production ceremony (P5.1), and the four
operational inputs Gate 1–2 needs — canonical principal per host, second root custodian and key,
publication repository, and the project-to-host writer inventory.

**Team:** everything else.

**Rationale for the split:** I keep the irreversible, cross-cutting and judgment-heavy items, and
the one go/no-go gate. I deliberately do **not** take root private key material — after WI-278 that
is the wrong risk to accept, and the trust root is the worst place to accept it.
