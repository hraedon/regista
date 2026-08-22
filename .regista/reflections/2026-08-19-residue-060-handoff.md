# Residue-060 worktree — WI-295/WI-301/WI-303/WI-305 landed; manifest 26

Base: `main` @ `191b9b8`. This worktree implements the WI-305 A + B + C decision,
the WI-295 vector correction, the WI-301 dedicated production trust-log writer, and
the WI-303 verified trust-projection rebuild.

## Landed

### WI-305 B — `spec` is the seventh v6 entity kind
`V6_ENTITY_KINDS` gains `spec` (`_verification`); the null-`workflow` admission rule
admits `spec`; `tests/test_spec_entity.py` migrated to the v6 epoch recipe; contracts
amended in `V6-ENVELOPE.md` §1.2/DD-7, `TRUST-DOMAIN.md` §5.2, `RECONCILIATION.md`.

### WI-305 A — reviewer lineage in the signed review-verdict payload
- **Ingress** (`require_canonical_reviewer_lineage` in `_lineage.py`, called from
  `adversarial_review` + `human_gate`): a verdict payload declaring `reviewer_claims`
  must carry a canonical `model_lineage`, else `INVALID_MODEL_LINEAGE` — never silently
  None.
- **Read** (`verdict_reviewer_lineage` / `reviewer_model_lineage`): the gate and
  `review_lineage_relation` consume the payload claim; narrow legacy fallback only for
  persisted pre-verdict events.
- `tests/test_wi305_reviewer_lineage_payload.py` (unit) and
  `tests/test_wi305_v6_review_gate.py` (real v6 epoch) pin the vehicle.

### WI-305 C — manifest 112 → 26 (the WI-008 delegation gap only)
- `ReplayReport.principal_binding_verified` is True on a v6 epoch (acceptance-chain
  binding executed over presented evidence); the legacy `principal_keys`-row probe is
  gated off for v6 (`_replay.py`, `_types.py`).
- The pre-epoch review/HMAC/on_behalf_of nodes were triaged counterpart-first:
  `tests/test_validator_context_enrichment.py` migrated 12 nodes; the rest were
  retired into `tests/retired_tests_ledger.json` (74 entries; coverage_owed WI-305 /
  WI-008 for surviving invariants, dies_with_v5 for v5-only mechanics). Surviving
  invariants are carried by the two v6 gate test files. `test_wi224_claim_lineage.py`
  is a retirement stub.

### WI-295 — trust-genesis vector corrected to the WI-280/WI-292 shape
`tools/make_v6_vectors.py::case_trust_genesis` + `tests/vectors/v6/trust-genesis.json`
now put governance and custody outside `binding_core` (sorted top-level
`initial_custody`, top-level `initial_governance`), base64 signer public keys, 64-hex
`nonce`. Deterministic regeneration; `test_v6_vectors` / `test_trust_domain` green.

## Validation (dedicated DB `regista_test_residue060`)
- Affected-tests batch: **612 passed / 0 failed**.
- Unit review/vector/debt meta/ledger + spec + entity-kinds: all green.
- `ruff check src/ tests/ scripts/ tools/`: clean.
- `mypy` on changed modules: clean (sidecar errors are pre-existing missing-extras,
  byte-identical with changes stashed).
- `check-conflicts.py` 0, `check-crossrefs.py` 0.
- `check-epoch-debt.py --base main`: OK — 26, shrink-only vs main (126).
- `tests/epoch_blocked_manifest.json`: 26 entries (the WI-008 delegation gap).
- `tests/retired_tests_ledger.json`: 375 entries; `test_retired_tests_ledger.py` passes.

## Remaining blockers
- The 26 manifest nodes are the WI-008 delegation gap (must NOT be removed by this
  pass).
- The worktree is uncommitted and the package version remains `0.5.5`; no release has
  been cut.
- Agent-notes reconciliation remains blocked because the source expects migrations
  45-47 while the live tracker schemas remain at 44. Do not migrate the live estate
  merely to close bookkeeping items.

## Notes
- New `ErrorCode` needs a `sidecar/errors.py` `_STATUS_MAP` entry
  (`TestErrorCodeCoverage` enforces total coverage) — none added here.
- The `_replay.py` v6 detection imports `_v6_writer.read_project_identity` at module
  top (a function-scope import made mypy flag a pre-existing `type: ignore[attr-defined]`
  as unused; that ignore was removed as mypy then reported it genuinely unused).
## WI-303 (verified projection rebuild) — landed

- `_trust_log_writer.verify_trust_log_chain(conn, genesis_document) -> VerifiedChain` is the
  single shared verified walk: ordered `VerifiedLifecycle` records + final `TrustState`, in
  predecessor-link order. Per lifecycle row it enforces strict envelope/JCS/hash/signature,
  pinned project/trust ids, entity-seq continuity, envelope-actor vs `authorized_by`, key-binding
  == genesis (root) or exact `registrar_delegated` (registrar), strict payload parse, registrar
  liveness at the event's own `occurred_at` (never wall-clock), scope, and `max_operations`
  atomically in chain order. `replay_trust_state` is a thin wrapper.
- `_trust_projection.rebuild_projection(..., genesis_document=None, dry_run, acceptance_by_principal)`
  stage-verifies into a temp table, diffs, then atomically replaces; failure leaves the prior
  projection unchanged. A missing genesis is accepted only when the stored trust log is empty;
  an event-present log fails closed with `genesis_document_required`. `check_projection_consistent`
  calls the same dry-run. Doctor `trust:projection_consistent` reads the pinned genesis from
  `REGISTA_TRUST_GENESIS_PATH`; without one it skips an empty log and fails an
  event-present log (never a clean pass on unverifiable material).
- `source_event_hash` = the verified trust-log event hash; `acceptance_event_hash` stays the
  project-chain acceptance (two-chain split).
- Tests: `tests/test_wi303_projection.py` (verified rebuild, dry-run no-mutation, forged-row
  halt with projection unchanged, doctor verified dry-run).

## WI-303 cleanup — complete

- `tests/test_trust_projection.py` is fully migrated to writer-built, WI-303-valid
  chains: **48 passed**. Its ceremony coverage now uses two explicit schemas and the
  real `rebuild_projection_from_trust_log` coordinator.
- The two-chain E2E proves that `source_event_hash` is the verified trust-log hash,
  `acceptance_event_hash` is a distinct verified project-chain hash, and unstructured
  raw acceptance hashes are refused at the structured evidence seam.

## Validation

- Durable consumed possession challenges are checked at append and replay: challenge
  kind, consumption, stored proof equality, challenge/payload binding, signature, and
  event-time expiry. Rotation authority, exact `authorized_by`, and operation limits
  are checked in the same verified walk.
- The trust-log writer directly invokes strict v6 envelope validation on each signing
  path, keeping the canonical-actor source tripwire non-vacuous.
- WI-301/WI-303/trust-projection plus P17 acceptance/verifier tests: **228 passed**.
- Full trust-projection file: **48 passed**.
- `ruff check src/ tests/ scripts/ tools/`: clean.
- `mypy --strict` on the changed trust-log/projection/doctor modules: clean.
- Optional-genesis coverage: `test_wi303_projection.py` **11 passed**; current-source CLI
  empty-log dry run also passed. The combined CLI batch remains environment-blocked: its
  subprocesses resolve the installed 0.5.4 package (missing `trust`) and its database fixture
  is at migrations 1–44 while this worktree requires 1–47.
- Epoch-debt check: 26 blocked nodes, shrink-only ratchet: OK.
- Retired-test ledger test: **2 passed**.

## WI-303 adversarial follow-up — complete in this worktree

- Root registrar revocations now fail closed when the target delegation is missing,
  already revoked, or names the wrong delegation/key; later registrar events cannot
  revive a mismatched revocation.
- Verified trust state retains principal-key status. Revoked key bytes remain available
  for historical verification, but a dual rotation using a revoked superseded key is
  refused.
- Projection rebuild detects legacy/v6 primary-key collisions before deleting any live
  v6 rows; dry runs report `legacy_v6_pk_collision`, apply raises the named divergence
  error, and legacy rows remain untouched.
- Trust-log reads combine live and archived events, de-duplicate identical event IDs,
  reject conflicting duplicates, and feed one combined predecessor walk.
- Configured genesis file failures are explicit `TRUST_GENESIS_SCHEMA_INVALID` errors;
  only an absent path returns `None`. Doctor validates the pin before the empty-log
  skip. The old unverified projection reader is now a deprecated named refusal.
- Project acceptance verification now requires the acceptance to lie on the complete
  current-head-to-genesis path and rejects forks/orphans. The evidence field is named
  `signer_public_key`; the acceptor key is not compared with the enrolled key.
- Focused adversarial validation: **262 passed**, plus trust-log/principal-key tests
  **133 passed**. Ruff, strict mypy, compileall, and `git diff --check` are clean.

## Final validation (2026-08-19)

- Default suite: **3,520 passed**, 68 skipped, 26 expected epoch failures, 11 slow
  tests deselected.
- Slow lane: **11 passed**, including the 21m42s long-history replay benchmark.
- Ruff, strict mypy, `git diff --check`, epoch-debt ratchet, retirement-ledger meta
  tests, documentation conflict/cross-reference checks, and deterministic generation
  of all 27 v6 vectors are clean.
- Independent DeepSeek and GLM adversarial reviews passed after fixes for destructive
  empty-evidence rebuilds, acceptance-hash preservation, archive-aware acceptance and
  revocation traversal, and reviewer-lineage diagnostics.
