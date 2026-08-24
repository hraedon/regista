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
| Truncation (a prefix replays cleanly) | require `expect_head` (exact head+count) and/or `must_cover`; report `tail_truncation_undetectable` when neither given; the bundle path makes a pin MANDATORY for authority | `head_pin_contradicted` / `pinned_checkpoint_not_covered` / `trust_log_export_unpinned` | `test_expect_head_detects_the_prefix`, `test_must_cover_detects_the_prefix`, `test_a_published_prefix_replays_cleanly_but_reports_truncation_undetectable`, `test_bundle_refuses_an_unpinned_export_for_authority` |
| Revoked-key laundering | `export_referents` withholds the enrolment/rotation that introduced a key the replay shows REVOKED; supersession is NOT withheld | (withheld set) | `test_revoked_key_introduction_is_withheld_from_referents`, `test_supersession_is_not_withheld` |
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
- **`export_referents` withholding.** Confirm a `compromised`-revoked key's introduction is
  withheld while a superseded (rotated) key's history is preserved — the direction that
  fails OPEN would retroactively unauthenticate honest history or authenticate a forgery.

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
(well-formed, claims did not hold). Both have matching `_STATUS_MAP` entries (400) in
`sidecar/errors.py`, enforced by the sidecar total-coverage meta-test.
