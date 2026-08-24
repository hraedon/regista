# WI-337 — the published trust-log export

**Goal (HIGH, ceremony-critical).** Publish the trust log as a signature-verifiable
artifact so a PROJECT bundle can reach `externally_authenticated` FULLY OFFLINE (no DB).
Before this, every trust-log verifier (`verify_trust_log_chain`, `resolve_enrolled_key`,
`load_published_checkpoint`) was store-backed and §8.4 forbids the offline verifier from
fetching, so §5.4-step-8 offline external verification of a project bundle was impossible.

**Provenance (honest).** This work item was implemented across two converged lanes that
collided in one worktree, then reconciled and completed in a single pass. The
crypto-critical core (`src/regista/_trust_log_export.py`, single-author, ~1415 lines) was
treated as the intended design and verified, not rewritten; the surrounding wiring was
reconciled to it and the offline `verify-catalog` path the prior lane left mid-flight was
finished. The full test matrix, the frozen v6 vector, and the two stale-assertion
reconciliations in `test_wi330_estate_catalog.py` are this pass.

## Design

Publishes the log's **events**, not a governance-state extract. `regista.trust-log-export/v1`
is a JCS-canonical, root-threshold-signed §4.3-shaped document carrying every trust-log
event as `{canonical_envelope, signature}` plus the durable possession-challenge records
the replay consumes.

- Domain tag: `b"regista.trust-log-export.v1\x00"`.
- Framing: `DOMAIN || uint64be(len(core)) || JCS(core)`, where `core` is the document minus
  `{root_signatures, countersignatures, anchors}`.
- `trust_log_export_digest` = `sha256` over those framed bytes.
- Same signing/canonicalization machinery as genesis / checkpoint / estate-catalog — no
  parallel scheme. `events` is an ARRAY (JCS does not sort arrays), so its order is inside
  the signed bytes and is required to be EXACT replay chain order.

### Offline == online, by construction

There is exactly one verified trust-log walk (WI-303). WI-337 widened
`verify_trust_log_chain` to read its material through a `TrustLogMaterial` seam (in
`_trust_log_writer.py`): `_StoreMaterial` answers from PostgreSQL exactly as before,
`OfflineTrustLogMaterial` answers the same two reads (event rows; a possession-challenge by
id) from the published artifact. The authority semantics — threshold, rotation, registrar
liveness, enrolment-before-use, revocation — are the *same code* in both cases. An extract
would ASSERT the current root set (circular, the WI-330 FR2-1 defect one layer down); an
export of events ASSERTS nothing — the current root set is DERIVED by replaying from the
auditor's out-of-band-pinned genesis, and the artifact's own `root_signatures` are then
checked against that DERIVED set.

## Attack classes — defence + the test that proves each

All export-level tests are in `tests/test_wi337_trust_log_export.py`; refusals assert a
machine-readable `reason` (or a fail-closed ErrorCode), never message text.

| Attack | Defence | Refusal `reason` | Proving test |
|---|---|---|---|
| Forged / self-authorising artifact | signatures checked against the replay-derived active set, never a self-asserted one | `root_signer_not_active` | `test_signature_by_a_non_root_key_is_refused` |
| Root signature does not verify | ed25519 verify over the framed core against the derived key | `root_signature_invalid` | `test_root_signature_that_does_not_verify_is_refused` |
| Removed-root forgery | after A/B→A/C the replay (which contains the rotation) derives {A,C}; a B signature is by a non-active key | `root_signer_not_active` | `test_removed_root_cannot_reauthorise_the_log_that_records_its_removal` |
| Unsigned export | an empty `root_signatures` authorises nothing | `root_signatures_absent` | `test_unsigned_export_authorises_nothing` |
| Cross-domain laundering | `trust_domain_id` / `trust_domain_core_digest` / `genesis_document_digest` / `project_instance_id` must equal the pinned genesis, checked BEFORE crypto | `trust_domain_mismatch` (+ siblings) | `test_export_from_a_different_domain_is_refused`; bundle-level `test_bundle_refuses_a_log_bound_to_another_domain` |
| Sub-threshold | verified count must reach the derived threshold | `root_threshold_not_met` | `test_sub_threshold_signatures_are_refused` |
| Downgrade / claim disagreement | restated threshold/mode/actives/head/count each must EQUAL the replay | `governance_mode_mismatch` / `threshold_contradicts_replay` / `head_contradicts_replay` | `test_restated_threshold_below_the_replay_is_refused`, `test_declared_head_that_is_not_the_replay_head_is_refused` |
| Truncation (a prefix replays cleanly) | only an EXACT `expect_head` (head+count) is a complete truncation defence; `must_cover` proves reach-AT-LEAST a checkpoint, NOT freshness; report `tail_truncation_undetectable` when neither given; **both authority paths (bundle AND offline verify-catalog) require an exact head pin** (Sol #1/#2) | `head_pin_contradicted` / `pinned_checkpoint_not_covered` / `trust_log_export_unpinned` / `trust_log_export_head_pin_required` | `test_expect_head_detects_the_prefix`, `test_must_cover_detects_the_prefix`, `test_a_published_prefix_replays_cleanly_but_reports_truncation_undetectable`, `test_bundle_refuses_an_unpinned_export_for_authority`, `test_bundle_refuses_a_must_cover_only_export_for_authority`, `test_catalog_offline_path_refuses_an_unpinned_export` |
| Unsigned/sub-threshold drawn for authority via `require_signatures=False` | the bundle consumption path re-asserts signature sufficiency (`verified_root_signatures >= root_threshold`), independent of how the verification object was produced (Opus footgun) | `trust_log_export_signatures_insufficient` (`TRUST_LOG_EXPORT_AUTHORITY_INSUFFICIENT`) | `test_bundle_refuses_an_unsigned_or_subthreshold_export_for_authority` |
| Revoked-key laundering | `export_referents` withholds the enrolment/rotation that introduced a key the replay shows REVOKED; supersession is NOT withheld | (withheld set) | `test_revoked_key_introduction_is_withheld_from_referents` |
| Rotated-out key as current authority (Sol #3/#4) | the replay now marks a rotated-out key `superseded`; offline classification keeps its introduction as a historical referent but excludes it from `active_principal_keys`, so the resolver never returns it as externally pinned | (excluded from active; named finding on use) | `test_rotation_supersedes_the_old_key_but_keeps_its_history` |
| Active-set FORK via a rotation from a dead key (WI-347, Sol #3 / Opus #1) | admission AND replay require `supersedes_key_id` to be the principal's CURRENT active key (dual + recovery); superseding a `superseded`/`revoked`/unknown key is refused, so at most one active key per principal — matching the projection applier | `superseded_key_superseded` / `superseded_key_revoked` / `superseded_key_unknown` (`TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY`) | `test_rotation_superseding_a_non_current_key_is_refused_on_replay`, `test_rotation_chain_supersedes_each_current_key_leaving_exactly_one_active`, `TestRotationAdmission::test_dual_rotation_superseding_a_non_current_key_is_refused`, `::test_recovery_rotation_naming_an_already_superseded_key_is_refused` |
| Active-set FORK via an ENROLMENT alias — same material, different key_id (WI-348, Sol round-2) | admission AND replay refuse a `principal_key_enrolled` whose bytes equal an ALREADY-ACTIVE key's under a DIFFERENT key_id (a genuine idempotent re-enrol reuses the same key_id; a key change is a rotation). Belt-and-suspenders: `_classify_rotation` also refuses when a principal holds >1 active key. So replay ≡ projection: exactly one active key per principal | `enrollment_alias_key_id_mismatch` (`TRUST_LOG_AUTHORITY_INVALID`); `principal_has_multiple_active_keys` (`TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY`) | `test_reenrol_same_material_under_a_different_key_id_is_refused_on_replay`, `TestEnrollmentBindsFreshKey::test_reenroll_same_bytes_different_key_id_repro`, `::test_wi348_replay_and_projection_agree_on_active_set` |
| Non-canonical bytes | file bytes must equal `canonicalize(document)` | `not_canonical_publication_bytes` | `test_non_canonical_publication_bytes_are_refused` |
| Substitution | `expect_digest` over the framed input | `export_digest_mismatch` | `test_substituted_artifact_is_caught_by_expect_digest` |
| Tampered event | flipping a byte breaks the hash chain; the walk rejects it | fail-closed `TRUST_LOG*` code | `test_tampered_event_bytes_fail_closed` |
| Out-of-order events | array must be exact replay chain order | `events_not_in_chain_order` | `test_events_out_of_chain_order_are_refused` |

### Bundle admission gate (a verified log must still bind to THIS bundle/pin)

`_trust_log_admissible` (in `_bundle.py`) binds a verified export to the bundle and the
auditor's pin; any failure is a hard `invalid`, never a silent demotion:
- log domain == bundle statement domain, == policy pins (when pinned);
- log project != bundle project (§5.10 step 5 — the log is a separate chain);
- no `key_id` the log enrolled has bytes contradicting the bundle's `bundled_key_evidence`
  (§4.4 criterion 4).

Proving tests: `test_bundle_refuses_a_log_bound_to_another_domain`,
`test_bundle_evidence_contradicting_the_enrolled_key_is_invalid`,
`test_trust_log_requires_a_full_trust_policy_not_accept_bundled`,
`test_trust_log_must_be_a_verified_object_not_a_raw_document`. The positive end-to-end
(`test_project_bundle_reaches_externally_authenticated_offline`) reaches
`externally_authenticated` with the export and drops to `unauthenticated` without it
(`test_same_bundle_without_the_export_is_only_unauthenticated`).

## Two-reviewer ceremony remediation (commit 5b5cd0e → this pass)

The first adversarial ceremony (Sol cross-lineage REQUEST-CHANGES ×4; Opus probe-executor
PASS + 1 footgun) found four issues. All four are fixed here, each with a fail-closed test.

- **A — offline verify-catalog now refuses an unpinned export (Sol #1).**
  `_cli._resolve_root_authority` verified the export then went straight to
  `verification_root_authority()` without checking the truncation pin — the bundle path
  refused, the catalog path did not, so removed roots could publish a prefix ending before
  their rotation and forge a catalog `verify-catalog` accepted. Now the catalog path
  requires `verification.head_pin_checked` (an exact `--trust-log-export-expect-head`) and
  raises `ESTATE_CATALOG_UNVERIFIED` / `trust_log_export_unpinned` otherwise — the SAME
  fail-closed the bundle path has. Test: `test_catalog_offline_path_refuses_an_unpinned_export`
  (+ the honest counterpart `..._accepts_an_exact_head_pinned_export`).

- **B — rotation now supersedes the old key in the replay (Sol #3/#4).**
  *Scope determination:* the ONLINE / store-backed authority path is **NOT** affected —
  `_genesis_open.resolve_enrolled_key` already excludes rotated-out keys by reading the
  rotation events' `supersedes_key_id` directly (see its comment at ~line 1059). Only the
  OFFLINE classification treated a rotated-out key as current authority. Per the task's own
  conditional ("if the online path handles supersession elsewhere, fix the offline
  classification to match") the fix is: add a `superseded` state to the replay
  (`principal_key_status: Literal["active","revoked","superseded"]`), mark the outgoing key
  in `_remember_principal_key` on any rotation, and have `_bundle._trust_log_export_material`
  honour it — a superseded key stays a valid historical referent (its introduction is NOT
  withheld) but is excluded from `active_principal_keys`, so `PolicyKeyResolver` never
  returns it as externally pinned. The online path is unchanged and still correct; the
  replay state is now honest for BOTH consumers. The vacuous `test_supersession_is_not_withheld`
  (which never rotated) is REPLACED by `test_rotation_supersedes_the_old_key_but_keeps_its_history`,
  proving both halves: K1's enrolment stays a referent; K1 is not current authority, K2 is.

- **C — `require_signatures=False` authority-token footgun closed (Opus).**
  `verify_trust_log_export(require_signatures=False)` (the builder's pre-sign self-check)
  skips the root-threshold gate but still returns a verification object; the bundle path
  granted authority off it with no re-assertion. Demonstrated: an UNSIGNED export drove a
  bundle to `externally_authenticated`. Fix: `_bundle._trust_log_export_material` now
  re-asserts `len(verified_root_signatures) >= root_threshold`, raising the new
  `TRUST_LOG_EXPORT_AUTHORITY_INSUFFICIENT` / `trust_log_export_signatures_insufficient`
  (covers unsigned AND sub-threshold). New ErrorCode + `_STATUS_MAP` 400 sidecar entry.
  Test: `test_bundle_refuses_an_unsigned_or_subthreshold_export_for_authority`.

- **D — `must_cover` no longer overstates truncation defence (Sol #2). DESIGN DECISION.**
  A stale `min_trust_log_checkpoint` (predating a rotation/revocation) lets a truncated
  export cover it while hiding later events, yet still reach the top verdict. We took the
  **strict** option Sol offered: the top `externally_authenticated` verdict requires the
  ceremony's **exact** head/count pin. `_bundle._trust_log_export_material` now refuses a
  must_cover-ONLY presentation (`tail_truncation_undetectable=False` but
  `head_pin_checked=False`) with `trust_log_export_head_pin_required`, rather than granting
  authority. `must_cover` keeps its honest lesser role at `verify_trust_log_export` — it
  still refuses a prefix that does not even reach the checkpoint (`pinned_checkpoint_not_covered`)
  — it is just not, on its own, a licence for CURRENT authority. *Feasibility check:* no
  test relied on a must_cover-only export reaching the top verdict (the positive
  `_offline_scenario` uses `expect_head`), and the spec (§4.6) treats the checkpoint as a
  floor, not a sufficiency claim, so this is strictly-stricter without breaking the design.
  Test: `test_bundle_refuses_a_must_cover_only_export_for_authority`.
  *Residual after D:* an exact-head pin still cannot prove FRESHNESS on its own — it proves
  the export is not truncated relative to a head the auditor obtained out of band. The
  ceremony must obtain that head from the custodian channel (§4.6 publication), not from the
  export. This is inherent to offline verification and is now labelled honestly rather than
  papered over by must_cover.

## Round-2 remediation — WI-347 rotation-admission gap (Sol #3 / Opus finding #1)

**Pre-existing gap the WI-337 re-ceremony surfaced (both reviewers demonstrated it).**
Rotation admission never required `supersedes_key_id` to name the principal's *currently
active* key. The prior `_classify_rotation` guard rejected the outgoing key only when its
status was `revoked` (and only for a dual rotation); `classify_rotation_authority` only
required the outgoing key co-sign. So `enrol K1 → rotate K1→K2 → rotate K1→K3` all
verified — the second rotation named K1, which fix B had marked merely `superseded` (not
revoked). Result: **BOTH K2 and K3 left `active`** / `EXTERNALLY_PINNED`, a rotated-out
key minting a NEW current-authority key and forking the active set. Recovery
(`mode="recovery"`, root-authorised) had the same hole — it could name an
already-superseded outgoing key. This is a trust-model fork, cutover-critical.

**Divergence it reconciles.** The projection applier
`_principal_keys._apply_rotation_projection` supersedes EVERY active key for the principal
on each new key (`UPDATE ... SET status='superseded' WHERE principal_id=%s AND
status='active'`) — i.e. it enforces "at most one active key per principal". The offline
replay did not, so replay and projection disagreed on the malicious chain (replay left
{K2,K3} active; the projection would have left {K3}).

**The fix (`_trust_log_writer.py:_classify_rotation`, ~line 1199).** A rotation — dual OR
recovery — must name a `supersedes_key_id` whose status is `"active"`; `superseded`,
`revoked`, and unknown are all refused, with `reason` distinguishing
`superseded_key_superseded` / `superseded_key_revoked` / `superseded_key_unknown`. Because
`_classify_rotation` is the single chokepoint that BOTH admission
(`append_trust_log_event`) and replay (`_verify_lifecycle` inside
`verify_trust_log_chain`) route through, one change binds both paths — no public-API
bypass. Requiring the outgoing key to be the one live key makes each rotation supersede
exactly it, which is precisely the projection's "at most one active" invariant, so replay
and projection now land on the same active set for every admissible rotation. New
ErrorCode `TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY` with a `_STATUS_MAP` 403 sidecar
entry (enforced by the sidecar total-coverage meta-test).

**Semantic consequence (intended).** Recovery is for a *lost-but-not-revoked* key: the key
is still `active` (nobody revoked it) and root authority rotates it because the lost key
cannot co-sign. It must name that active key. A *revoked* (compromised) key leaves the
principal with no active key, and the fresh-key path is then `principal_key_enrolled` (which
`_check_enrollment_binds_fresh_key` allows precisely because no active key exists), not a
rotation. Four existing recovery/placeholder tests used a never-enrolled `pk_lost`; they now
enrol a real active key first (the realistic scenario), and one dual test that named an
unknown key now asserts the earlier `superseded_key_unknown` refusal instead of the
now-unreachable-in-this-path `superseded_public_key_unavailable`.

Tests: `test_wi337_trust_log_export.py::{test_rotation_chain_supersedes_each_current_key_leaving_exactly_one_active,
test_rotation_superseding_a_non_current_key_is_refused_on_replay}` (valid K1→K2→K3 leaves
exactly K3 active; the K1→K3-after-K1→K2 fork is refused by `verify_trust_log_chain`
directly AND cannot be built by the honest exporter);
`test_wi301_trust_log_writer.py::TestRotationAdmission::{test_dual_rotation_superseding_a_non_current_key_is_refused,
test_recovery_rotation_naming_an_already_superseded_key_is_refused}` (admission half, both
dual and recovery). The revoked-key coverage (`superseded_key_revoked`) is retained.

## Round-2 remediation — WI-348 enrolment-alias active-set fork (Sol round-2, blocking)

**Reachability settled: YES (durable).** Reproduced through the PUBLIC `append_trust_log_event`
path and the offline replay, database-backed. A registrar enrols K1 (active), then enrols an
ALIAS carrying K1's *exact* public bytes under a *different* key_id. `_check_enrollment_binds_fresh_key`
compared the offered PUBLIC BYTES to active keys and `continue`d on a match (treated it as an
idempotent no-op) regardless of key_id, so the alias was admitted and `_remember_principal_key`
marked the new key_id `active` — **two active key_ids sharing one material**. The lifecycle path
is also reachable: `_lifecycle_key_id(idempotency_key)` derives the key_id from the idempotency
key (not the material), and `request.public_key` is caller-provided, so two enrolments of the same
public key under different idempotency keys yield different key_ids feeding the same admission gate.

**Security consequence (confirmed by repro).** enrol K1 → enrol K1-alias → rotate K1→K2: the
WI-347 guard passes (it names K1, which is active), replay supersedes only the *named* K1, leaving
`{K1-alias: active, K2: active}`. The rotated-out MATERIAL survives as CURRENT external authority
via the alias — rotation fails to remove authority. Observed replay statuses after the rotation:
`{pk_k1v: superseded, pk_k1v_alias: active, pk_k2v: active}`.

**Divergence it reconciles.** The projection applier `_apply_enrollment_projection`
(`_principal_keys.py:238`) supersedes EVERY active row for the principal before inserting the new
one, so it holds exactly ONE active key. The offline replay did not, so replay and projection
disagreed on the alias chain (replay: two active; projection: one).

**The fix.** Two guards, both at the shared admission+replay chokepoints (the estate's recurring
"guard in only one path is bypassable" failure class):

1. **Root cause — `_trust_log_writer.py:_check_enrollment_binds_fresh_key` (~line 1298).** When the
   offered bytes equal an already-active key's, admit as idempotent ONLY if the offered key_id
   equals that key's key_id; same-bytes-under-a-different-key_id is refused with
   `reason="enrollment_alias_key_id_mismatch"` (`TRUST_LOG_AUTHORITY_INVALID`, which already carries
   a `_STATUS_MAP` 403 sidecar — no new code, mirroring the sibling `enrollment_key_already_present`).
   This function is called at BOTH admission (`append_trust_log_event`, ~line 2155) and replay
   (`_verify_lifecycle` inside `verify_trust_log_chain`, ~line 1444), so one change binds both paths.
2. **Belt-and-suspenders — `_classify_rotation` (~line 1234, Sol's suggestion).** A rotation refuses
   when the principal holds >1 active key (`reason="principal_has_multiple_active_keys"`,
   `TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY`). Even if some other path ever admitted a second
   active key, a rotation could not leave a stale active twin behind.

**Replay ≡ projection, enforced.** With guard 1 the alias never enters the durable log, so for
every admissible enrol+rotate history the offline replay's active set equals the `principal_keys`
projection table's active set (exactly one active per principal). Asserted directly by
`test_wi348_replay_and_projection_agree_on_active_set` (rebuilds the projection from the same
durable log and compares).

Tests: `test_wi337_trust_log_export.py::test_reenrol_same_material_under_a_different_key_id_is_refused_on_replay`
(replay half — `verify_trust_log_chain` refuses, and the honest exporter cannot even build such a
document); `test_wi301_trust_log_writer.py::TestEnrollmentBindsFreshKey::{test_reenroll_same_bytes_different_key_id_repro
(admission half, was the STEP-1 repro), test_wi348_replay_and_projection_agree_on_active_set}`. The
existing `test_reenroll_same_key_direct_append_is_admitted` (same bytes AND same key_id → genuine
idempotent no-op) still passes, so the fix does not over-refuse.

### Documentation-accuracy fixes folded in (Sol, non-blocking)

- `_genesis_open.py:~1059` — the comment claimed the writer does NOT flip the superseded
  key's status so a rotated-out key "STILL [reads] active". False since fix B. The code
  (reading supersession off the rotation events, independent of the status map) is still
  correct defence in depth; the comment now says so.
- `test_wi325_genesis_init.py:test_rotation_selects_new_key_even_though_old_status_stays_active`
  — its "exactly the state the real replay leaves: BOTH keys active" claim is stale.
  Relabelled as a DELIBERATE synthetic legacy/inconsistent state that proves
  `resolve_enrolled_key`'s independence from the status map (the test's real value), not
  what the writer now produces.
- `test_wi337_trust_log_export.py:~596` — the comment said K1 signed its enrolment event;
  the fixture's enrolment envelope is REGISTRAR-signed. Corrected to describe what is
  actually proven: retention of K1's introduction as a referent + K1's rotation
  co-signature.

## Named residuals (reviewers will probe these)

1. **Row/envelope reconciliation is vacuous offline, by construction.** `_reconcile_row`
   compares DB columns against the signed envelope to catch a tampered *row* beside an
   intact envelope. An export carries no second copy, so `OfflineTrustLogMaterial`
   synthesises the row FROM the envelope and the comparison passes trivially. Nothing is
   lost: the property the check defends (row and signed bytes agree) is provided here by
   there being no row. Named, not hidden.
2. **Authority is evaluated at the export's head, not point-in-time.**
   `verify_trust_log_chain` takes no upper bound and `effective_from_checkpoint_seq` is
   parsed but never consulted, so a rotation appended after publication makes a
   historically valid export fail an `expect_head` pin rather than being silently
   reinterpreted. A key the log has REVOKED at its head is not treated as externally pinned
   and the event that used it is named as a finding (bundle path).
3. **Possession-challenge records are attested only by the publisher's root signature.**
   They ride inside the signed core, so a root-threshold signature covers them, but there
   is no independent per-challenge attestation; a threshold-capable publisher could in
   principle publish a consistent-but-fabricated challenge set. The replay still checks the
   possession proof against the enrolment envelope, so this cannot manufacture authority
   for a key the events don't already enrol.

## What a reviewer should probe hardest

- **The truncation boundary.** The one attack the artifact cannot self-refute. Confirm
  `tail_truncation_undetectable` is reported whenever neither pin is supplied, and that the
  bundle authority path (`_trust_log_export_material`) REFUSES an unpinned export rather
  than quietly downgrading. Try a prefix that ends exactly before a `principal_key_revoked`
  and confirm `must_cover` at a later checkpoint head catches it.
- **The derived-vs-asserted seam.** Every field on `TrustLogExportVerification` must come
  from `chain.state` (the replay), never from the parsed document's claims. The document's
  restatements are only checked FOR EQUALITY. Probe by mutating each restated field and
  confirming a `*_contradicts_replay` refusal.
- **Removed-root under rotation.** Re-run the A/B→A/C rotation and confirm the removed
  root's signature is refused against the DERIVED set, and that a rotation cannot lower the
  threshold (monotonicity, `root_threshold_lowered`).
- **The bundle admission gate.** A perfectly valid export for another domain, or one whose
  enrolled key contradicts `bundled_key_evidence`, must be a hard `invalid` and be
  *withdrawn* (so no downstream axis is lifted by material just declared inadmissible), not
  a fallback to `bundle_rooted`.
- **`export_referents` withholding AND supersession (post-remediation).** Confirm a
  `compromised`-revoked key's introduction is withheld while a superseded (rotated) key's
  history is preserved — the direction that fails OPEN would retroactively unauthenticate
  honest history or authenticate a forgery. NEW: also confirm the superseded key is NOT
  returned as current authority — `principal_key_status[(p,k1)] == "superseded"` after a
  K1→K2 rotation, `k1` excluded from `_TrustLogAuthority.active_principal_keys`, and
  `PolicyKeyResolver.resolve(k1)` never `EXTERNALLY_PINNED`. Probe the double-rotation edge
  (rotate K2→K3 after K1→K2) and the recovery-rotation edge (root-authorised recovery also
  supersedes its `supersedes_key_id`).

## CLI surface added

- `regista trust publish-log --out ... [--key ...]* [--incomplete-signatures] --genesis ...`
  — walk the live store under full verification, derive every field, build canonical bytes,
  self-verify, root-sign, re-verify, write atomically. (Touches the store; needs a DSN.)
- `regista trust sign-log FILE --out ... --key ...* [--genesis ...]` — offline airgapped
  leg; re-verifies, appends signatures over the existing signed core, never rebuilds it.
- `regista trust verify-log FILE --genesis ... [--expect-digest ...] [--expect-head ...]
  [--must-cover-head ...]` — offline, read-only; exit 0 = VALID, exit 1 = refused.
- `regista bundle verify --trust-log FILE --genesis ... [--trust-log-expect-head ...]
  [--trust-log-expect-digest ...]` — offline external verification of a PROJECT bundle.
- `regista trust verify-catalog --trust-log-export FILE [--trust-log-export-digest ...]
  [--trust-log-export-expect-head ...]` — the offline alternative to `--trust-log-project`;
  the SAME verified walk runs over the export's own events (finishes the prior lane's
  `_resolve_root_authority` offline wiring).

## Frozen v6 vector

Added `trust_log_export` to the domain-tag table in `tools/make_v6_vectors.py`, a
`case_trust_log_export()` (mirrors `case_estate_catalog` — pins domain + framing on a
representative signed core), the `trust-log-export` manifest entry, and
`test_v6_vectors.py::test_trust_log_export` which cross-checks that the production
`trust_log_export_digest` reproduces the frozen framed digest and that
`TRUST_LOG_EXPORT_DOMAIN` equals the manifest tag. Regenerated
`tests/vectors/v6/trust-log-export.json` and `manifest.json`.

## New ErrorCodes

`TRUST_LOG_EXPORT_SCHEMA_INVALID` (malformed artifact) and `TRUST_LOG_EXPORT_UNVERIFIED`
(well-formed, claims did not hold). The ceremony remediation adds a third,
`TRUST_LOG_EXPORT_AUTHORITY_INSUFFICIENT` (fix C — a well-formed, correctly-replayed export
a library consumer tried to draw authority from without it reaching its own derived root
signature threshold). All three have matching `_STATUS_MAP` entries (400) in
`sidecar/errors.py`, enforced by the sidecar total-coverage meta-test.
