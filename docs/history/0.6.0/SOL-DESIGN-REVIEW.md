[agent-wake-opencode] INFO daemon client started, socket=/run/user/1000/agent-wake.sock, sources=["mvmcc03-claude","mvmcc03-opencode"]
[agent-wake-opencode] INFO subscribed, session_id=01KZJ3A4SZ06873P2A5DMZ6WE8 accepted_sources=["mvmcc03-opencode"]
[0m
> adversarial-reviewer-headless · gpt-5.6-sol
[0m
[0m→ [0mSkill "adversarial-review"
[0m
[0m# [0mTodos
[•] Verify S1 root cause and compare remediation forks against signing/envelope code
[ ] Assess compatibility impact on existing stores and InMemory parity
[ ] Challenge Phase 1 scope, dependency order, and coupled fixes
[ ] Evaluate release/versioning call and formulate final design verdict
[0m
[0m• [0mAnalyze signing design[90m Explore Agent[0m
[0m• [0mAssess data compatibility[90m Explore Agent[0m
[0m• [0mChallenge remediation phases[90m General Agent[0m
[0m• [0mMap S1 findings[90m Explore Agent[0m
[0m✓ [0mChallenge remediation phases[90m General Agent[0m
[0m✓ [0mMap S1 findings[90m Explore Agent[0m
[0m✓ [0mAnalyze signing design[90m Explore Agent[0m
[0m✓ [0mAssess data compatibility[90m Explore Agent[0m
[0m→ [0mRead src/regista/_signing.py[90m [offset=40, limit=570][0m
[0m→ [0mRead src/regista/_bundle.py[90m [offset=630, limit=200][0m
[0m→ [0mRead src/regista/_archive_segments.py[90m [offset=620, limit=100][0m
[0m→ [0mRead src/regista/_replay.py[90m [offset=970, limit=220][0m
[0m→ [0mRead src/regista/_event_store.py[90m [offset=90, limit=150][0m
[0m→ [0mRead src/regista/_assurance.py[90m [offset=190, limit=125][0m
[0m→ [0mRead README.md[90m [offset=1, limit=45][0m
[0m→ [0mRead spec.md[90m [offset=640, limit=55][0m
[0m→ [0mRead migrations/002_add_canonical_envelope.sql[90m [limit=20][0m
[0m→ [0mRead migrations/017_events_global_seq.sql[90m [limit=45][0m
[0m→ [0mRead src/regista/_replay.py[90m [offset=140, limit=280][0m
[0m→ [0mRead src/regista/_timestamping.py[90m [offset=75, limit=30][0m
[0m→ [0mRead src/regista/_timestamping.py[90m [offset=450, limit=60][0m
[0m→ [0mRead src/regista/_replay.py[90m [offset=530, limit=310][0m
[0m→ [0mRead migrations/031_entity_generalization.sql[90m [limit=55][0m
[0m
[0m$ [0mgit status --short --branch
## release/0.5.6...origin/release/0.5.6
[0m
[0m$ [0mgit log --oneline -10
db75c70 docs(changelog): record the round-2 fixes (seal reconciliation, principal_kind ingress)
7e1b108 docs(changelog): narrow four 0.5.6 claims Sol's round 2 found too broad
73f609d docs(changelog): correct the 0.5.6 gate and bundle claims after the pre-publish review
1a3fec0 docs(changelog): record the doctor checks, event global_seq, and lineage_verification (Sol NB-8)
3651255 docs(changelog): WI-233 wording — the strict burndown is complete, no deferred modules (Sol NB-7)
5bf728a release: prepare regista 0.5.6
b103753 fix(review): validate principal_kind at ingress and fail closed on unrecognized kinds (WI-262) (#34)
cacc173 fix(bundle): reconcile every segment record against its signed seal event (WI-254) (#33)
559fa3c fix(bundle): anchor every segment record and check manifest counts (WI-254, WI-255) (#32)
5aa5c38 fix(review): fail closed on undeclared agent authors and delegated reviewer lineage (WI-256, WI-257, WI-258) (#31)
[0m
[0m→ [0mRead src/regista/_principal_keys.py[90m [offset=100, limit=65][0m
[0m→ [0mRead src/regista/_cli.py[90m [offset=295, limit=45][0m
[0m
[0m# [0mTodos
[✓] Verify S1 root cause and compare remediation forks against signing/envelope code
[✓] Assess compatibility impact on existing stores and InMemory parity
[✓] Challenge Phase 1 scope, dependency order, and coupled fixes
[✓] Evaluate release/versioning call and formulate final design verdict
[0m
# VERDICT: proceed with modifications

The diagnosis is substantially right, and S1 should be the first implementation target. The proposed Phase 1 is not yet a sufficient release boundary, however. It must also prevent untrusted segment rows from bridging replay, and either add an out-of-band bundle trust root or stop returning an undifferentiated positive bundle-verification verdict. Otherwise 0.6.0 would still expose false-positive “verified” results.

## 1. Is the root-cause diagnosis right?

**Yes. S1 is genuinely the common cause of the row-tampering findings, not an imposed narrative.**

`verify_event()` puts the stored envelope first and returns as soon as it verifies (`src/regista/_signing.py:366-376,462-487`). Only v5 `actor_kind` and `actor_metadata` are then reconciled (`src/regista/_signing.py:468-486`). Replay subsequently applies the row’s `transition` and `payload`, not values parsed from the authenticated envelope (`src/regista/_replay.py:990-1003,1120-1163`).

The same representation split appears elsewhere:

- Offline bundles verify `evt.canonical_envelope` directly while using row-level actor, key, timestamp and scheme fields for policy decisions (`src/regista/_bundle.py:741-807`).
- Assurance consumes raw event attributes and never verifies signatures (`src/regista/_assurance.py:235-277`).
- Witnesses and public APIs likewise expose both representations.
- Existing code explicitly depends on the stored envelope being authoritative, rather than the row (`src/regista/_signing.py:369-374`).

That common cause closes attacks based on rewriting signed-but-duplicated row fields, including payload, transition, actor, delegation, workflow identity, timestamps and chain links.

### Findings that survive a complete S1 fix

Do **not** mark these closed merely because S1 lands:

- **S2:** `scheme_id` is not in v3-v5 envelopes (`src/regista/_signing.py:276-299`) and bundle verification currently trusts it before deciding whether to verify (`src/regista/_bundle.py:744-754`).
- **S3:** v1 can still skip signatures while `verified=True` is computed independently of enforcement (`src/regista/_bundle.py:646-667`).
- **S4/S5:** membership and bundled public-key trust remain self-asserted; keys are read from the artifact under verification (`src/regista/_bundle.py:690-736`).
- **S6:** mutable workflow, segment and chain-head tables remain verification oracles. Replay directly reads `workflow_registry.definition` (`src/regista/_replay.py:1165-1183`) and trusts segment/head rows (`src/regista/_replay.py:782-817`).
- **S7:** timestamp batches still hash UUIDs rather than event content (`src/regista/_timestamping.py:84-96`), and no TSA certificate still yields success (`src/regista/_timestamping.py:487-495`).
- **S8 partially survives:** S1 prevents unsigned transition rewriting, but not a legitimately signed, semantically fake `adversarial_pass`, nor the lack of a hash binding a verdict to reviewed content. Assurance still infers meaning from transition names (`src/regista/_assurance.py:238-273`).
- **S9:** no project binding is added by reconciliation.
- **S10:** member signatures and seal reconciliation do not magically appear in `verify_segment`; it currently verifies only chains, count, head and the seal event (`src/regista/_archive_segments.py:665-687`).
- **All five local defects survive independently.** S1 makes some inputs trustworthy but does not fix their control flow.

Also, `global_seq` remains unsigned by design (`spec.md:667-674`). S1 must not accidentally claim otherwise.

## 2. The S1 design fork

**Choose (b), but implement it as a strict, centralized, version-aware envelope verifier—not merely “add more comparisons” to the existing loop.**

The durable rule should be:

> The stored canonical envelope is the cryptographic artifact; the row is its indexed projection. Verify the exact stored bytes, then require every field signed by that envelope version to agree with its row representation before any consumer uses the row.

### Why not rebuild-only?

Option (a) has serious compatibility and correctness problems:

1. **Exact historical bytes matter.** Signatures, per-item/global chain hashes, seals and anchors commit to stored envelope bytes, not to whatever a later serializer reconstructs.
2. **Version skew is real.** The current verifier supports v1-v5 candidate shapes (`src/regista/_signing.py:382-567`).
3. **`global_seq` is assigned after signing.** Public verification deliberately omits it (`src/regista/_signing.py:570-600`; `spec.md:672-674`). A generic row rebuild can accidentally add it and reject valid events.
4. **Historical rows contain migration-derived fields that were never signed.** `entity_kind`, `entity_id` and `hash_alg` were backfilled (`migrations/031_entity_generalization.sql:12-24`).
5. Rebuilding every event costs serialization and canonicalization during replay while still requiring version inference.

### Required details for option (b)

The central verifier should:

- Parse the envelope once.
- Require a JSON object, exact known required/optional fields and valid field types.
- Reject unknown schema/version rather than classifying arbitrary subsets as v1. Current classification is permissive because it uses `issuperset(keys)` (`src/regista/_signing.py:305-319`).
- Optionally require `canonicalize(parsed) == stored_envelope`.
- Verify canonical hash and signature over those exact bytes.
- Reconcile every duplicated field covered by that envelope version.
- Enforce `work_item_id == entity_id` for work-item v4/v5 events; `work_item_id` is a compatibility alias (`migrations/031_entity_generalization.sql:3-10`).
- Reconcile optional fields by **presence**, not merely value. An envelope field present with `null`, absent entirely, and a row `NULL` are not necessarily the same schema state.
- Derive signing scheme from trusted key metadata and reject disagreement with row `scheme_id`.
- Preserve the exact stored bytes for chain hashing.
- If a stored envelope exists, **never fall back to a rebuilt candidate after parse, signature or reconciliation failure**. That would recreate an escape hatch.

Fields outside a historical envelope need explicit treatment:

- `scheme_id`: bind to trusted registry/key-set metadata now; sign it in v6.
- `global_seq`: validate structurally; do not pretend v5 signed it.
- v4 `actor_kind`/`actor_metadata`: report as unsigned legacy provenance.
- `signature`, canonical hash and envelope: verify as derived cryptographic artifacts, not recursive envelope fields.

Performance favors (b): one JSON parse plus comparisons is cheaper and safer than rebuilding several JCS candidates per event. Signature verification remains the dominant cryptographic operation.

## 3. What does S1 break?

### Which existing events newly fail?

For honestly produced v5 events whose rows were never altered, the duplicated signed fields should match, so a correctly version-aware S1 fix should not reject them.

The set is nevertheless **not guaranteed empty**:

- The running test/audit Postgres corpus contains deliberately divergent row/envelope examples. Those should newly fail.
- Genuine pre-migration events may have `canonical_envelope IS NULL`; the column was introduced nullable with no backfill (`migrations/002_add_canonical_envelope.sql:1`).
- Historical v3/v4 rows contain unsigned migration backfills and must not be rejected merely because those fields were absent from their envelopes (`migrations/031_entity_generalization.sql:12-24`).
- `global_seq` was backfilled using `(timestamp,event_id)` as a proxy and cannot be retroactively treated as signed (`migrations/017_events_global_seq.sql:5-16`).

There is no committed production dump proving whether an operator’s real deployment contains mismatches. Therefore the release needs a **preflight audit command**, not an assumption.

### Operator remediation

Provide a dry-run verifier reporting at least:

- envelope version;
- signature validity;
- row/envelope mismatch fields;
- missing envelope;
- unsigned legacy fields;
- affected segment/anchor IDs.

For a mismatch in a field actually signed by the envelope:

1. Restore the row from the signed envelope or a trusted backup.
2. Quarantine it if provenance is uncertain.
3. Do **not** silently accept the row.
4. Do **not** routinely re-sign history.

Re-signing rewrites the event head, successor links, global chain, seals, witness evidence and anchors. It is a cryptographic history rewrite, not a migration.

For missing envelopes, reconstruct historical candidates and persist one only when the canonical hash and signature uniquely prove the exact candidate. Otherwise classify the event as unverifiable.

### Grandfathering

A compatibility window is needed only for properties older envelopes never signed—not for disagreement in fields they did sign.

Make it bounded and observable:

- Assign explicit statuses such as `fully_reconciled`, `legacy_v4_partial`, `legacy_missing_envelope`, and `mismatch`.
- Establish a fixed cutover at the first new envelope version/global sequence.
- Require full verification after that cutover.
- Never provide an `allow_legacy=True` mode that converts a signed-field mismatch into success.
- Surface degraded legacy coverage in CLI/API reports and exit status.

### InMemory

Yes, it needs the same row-envelope reconciliation. It shares `sign_event()` but assigns `global_seq` only afterward (`src/regista/_event_store.py:107-166,214-230`). Its replay must exercise the same mutation matrix as Postgres.

Keyless InMemory currently uses zero-byte dummy cryptographic material (`src/regista/_event_store.py:134-139`). That mode should be explicitly reported as **unsigned**, not passed through the strict verifier as though it were a malformed signed event.

## 4. Is Phase 1 the right cut line?

**Not as presently written.**

### Items that belong

S1, S2-interim/S3, S10, local defects 1-5 and claim narrowing all belong. None should be removed.

### Two required modifications

#### A. Couple S10 to replay segment bridging

It is not enough to fix `verify_segment()` while replay continues using raw `event_segments.first_event_prev_hash` and `head_hash` as trusted jump links (`src/regista/_replay.py:250-271,308-345,782-796`).

Phase 1 should introduce one segment-verification primitive and require:

- member row/envelope reconciliation;
- member signature verification;
- chain verification;
- signed-seal reconciliation;
- segment boundary/count verification;

before either live verification or replay accepts the segment as a bridge.

Otherwise the main replay path bypasses the fix.

#### B. Resolve S5 at the public bundle-verdict boundary

A bundle verifier cannot honestly return a general `verified=True` while taking its root keys from the same attacker-rewritable bundle (`src/regista/_bundle.py:690-736`).

Either:

1. Bring a minimal `--trust-keys`/pinned-fingerprint input into Phase 1; or
2. Split the result into at least:
   - `internally_consistent`
   - `signatures_valid_against_bundled_keys`
   - `authenticated_to_external_root`

and ensure the last is false/unknown without external trust.

Documentation narrowing alone is insufficient while the API still returns `verified=True` (`src/regista/_bundle.py:660-687`).

### Can anchoring remain deferred?

**Yes, but only if every anchoring claim and positive status is narrowed or disabled.**

A Phase 1 release may truthfully claim:

- present event rows are reconciled with signed envelope fields;
- signatures verify against caller-supplied/key-file trust material;
- per-item and global links are checked;
- verified segments are internally consistent with signed seals.

It may not claim:

- externally anchored tamper-evidence;
- tail-truncation detection independent of mutable database state;
- offline authenticity from a self-contained bundle;
- trusted time;
- complete-log membership.

Current statements such as “RFC 3161 timestamping … for event integrity” (`README.md:26`) and the third-party anchoring guarantee (`spec.md:640-657`) must be removed or explicitly marked unavailable pending S7.

### Other deferred work

S8 should either move forward or its assurance surface must be downgraded. The current computation still derives assurance from transition names without verifying a signed gate verdict (`src/regista/_assurance.py:235-277`). Given that 0.5.6 was framed heavily around gate correctness, I recommend including the signed, content-bound verdict redesign before making strong review-assurance claims.

S6 can remain later only if 0.6.0 explicitly excludes:

- principal registry non-repudiation;
- workflow-definition provenance;
- tail completeness;
- signed/replay-derived side-table state.

That is a narrower release than the report currently implies.

## 5. The order

S1 should be the first **code dependency**, but not the first engineering action.

### Before implementation

1. Write the authenticated-field matrix for every envelope version.
2. Define strict envelope schemas and verification-result states.
3. Inventory actual stores with a dry-run compatibility checker.
4. Define the cutover and legacy policy.

Without that, an implementation can silently reinterpret historical data.

### Implement together

- **S1 + S2-interim:** reconciliation cannot use row `scheme_id` as trusted input.
- **S1 + all consumers:** replay, public-key verification, principal binding, bundle verification, witness/export paths and segment verification must share the same primitive. Fixing only `verify_event()` leaves `_bundle.py:801-807` vulnerable.
- **S10 + replay bridging:** no path may trust a segment that another path would reject.
- **Chain defect counters + CLI exit behavior:** structured chain failures and non-zero status must land together. Presently chain breaks increment warnings (`src/regista/_replay.py:993-1003`) while CLI exits only for drift/halt (`src/regista/_cli.py:330-333`).
- **Local defects 4 and 5:** whole-store and scoped replay need one definition of missing event/projection membership.
- **S3 + bundle verdict split/trust input:** “signatures not enforced” cannot remain compatible with `verified=True`.

## 6. The release call

**Agree: do not ship 0.5.6. Ship 0.6.0 only after the modified Phase 1.**

This changes the semantics of verification and may make previously successful verification fail. A minor version is appropriate in a pre-1.0 project.

The release notes must state plainly:

1. Previous versions could validate a stored envelope while consumers used divergent, unauthenticated row columns.
2. 0.6.0 verifies exact envelope bytes and reconciles all version-signed duplicated fields before consumption.
3. Existing mismatches now fail closed; provide the preflight and repair procedure.
4. Historical v3/v4/missing-envelope records have explicitly limited authentication scope.
5. `scheme_id` remains outside old envelopes but is checked against trusted key metadata; full signed binding awaits v6.
6. Bundles are externally authenticated only when verified against operator-supplied pinned trust material. Otherwise they establish internal consistency at most.
7. No external anchoring guarantee exists yet:
   - RFC 3161 without a configured certificate does not establish TSA authenticity.
   - UUID-only timestamp batches do not commit to event content.
   - OpenTimestamps is unavailable/non-functional until replaced or ported.
8. Hash chains detect many modifications, insertions and interior deletions, but without a trusted external checkpoint they cannot independently prove complete membership or detect all tail truncation.
9. Review assurance remains procedural unless/until a signed verdict is bound to the reviewed content.
10. InMemory without keys remains explicitly unsigned.

Do not say merely “improved event integrity.” State the old failure mode and the exact new boundary.

## 7. What I would do differently

I would reshape the work around a **single verified-event result model**, rather than a collection of boolean patches.

For example, every verifier should return structured evidence containing:

- envelope version and schema validity;
- signature validity;
- trusted-key source;
- row reconciliation result and mismatched fields;
- authenticated versus unsigned fields;
- principal-binding result;
- chain-link result;
- legacy/degraded reason;
- final applicability: `fully_authenticated`, `legacy_partial`, `invalid`, or `unverifiable`.

Replay, bundles, segments, assurance, witnesses and the CLI should consume that same result. Today each path reimplements part of verification and assigns different meanings to “verified.”

I would also divide the roadmap by guarantee rather than subsystem:

1. **Authenticated event semantics:** strict envelope parser, S1, scheme binding, common verifier.
2. **Authenticated traversal:** chains, segment bridges, completeness verdicts, non-zero CLI behavior.
3. **Authenticated trust root:** pinned bundle roots and signed key lifecycle.
4. **Authenticated review decision:** content-bound gate verdict.
5. **External evidence:** functioning content-committing anchors.

That decomposition makes it much harder for a local fix to create a new unverified consumer.

The remediation direction is right. The main mistake would be treating S1 as though it made every downstream “verified” claim true automatically. It does not; it makes trustworthy event semantics possible. The trust root, traversal completeness and external evidence still require explicit, separately reported guarantees.
[agent-wake-opencode] INFO notify-on-idle: published ocidle-msl5kfma-522c805d3dbbb3c1 for session ses_01bcaebfcffeE7o9MeuON5zsXS (status 202, delivery next_session)
