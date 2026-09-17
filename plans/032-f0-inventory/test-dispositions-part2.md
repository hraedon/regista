# Regista test disposition — part 2 (second half)

**Scope covered:** `ls tests/*.py | sort`, files 92–183 of 183 total (second half per
`N=183`, split at `N/2=91` so this half is index 92..183). First file:
`tests/test_public_verification_surface.py`. Last file: `tests/_wi337_fixtures.py`.
**File count covered: 92.**

Method: read each file's module docstring, imports, and full list of `def test_*` /
`class Test*` names; read bodies directly for every file whose disposition was not
obvious from that (all SPLIT/UNCLEAR files, plus spot checks on `src/regista/secrets.py`
and its call sites to settle whether the secrets-provider abstraction is kernel or
custody-only infrastructure). Classification follows the assertion, not the import list,
per the task's critical rule.

`tests/test_retired_tests_ledger.py` and `tests/test_wi289_cluster4_ledger_mapping.py`
carry **uncommitted local modifications belonging to other work** — both were read but
not touched, per instructions.

## Summary

| Disposition | Count |
| --- | ---: |
| RETIRE | 62 |
| PORT | 19 |
| SPLIT | 7 |
| UNCLEAR | 4 |
| **Total** | **92** |

HIGH-VALUE PORT tag applied to 11 files/clusters. Environment-pinned findings: 2 (one
inherited from a RETIRE file — see closing section).

## File-by-file

`tests/test_public_verification_surface.py` — RETIRE — asserts the public
`regista.verification` re-export surface for offline bundle verification (bundle
referents, chain-head hash formulas, genesis-as-expected-gap, wrong-key INVALID,
rewritten-row INVALID); exists solely to serve external bundle-verification consumers
(cairn), which goes with audit bundles/witness/signing removal.

`tests/test_read_events_conformance.py` — PORT — asserts pure event-read ordering
(full ascending read, `limit` newest-first, `before_seq` windowing, desc tiebreak on
`event_seq`) parametrized over both backends; no signing-specific assertion, only uses
the v6 harness to bootstrap a project.

`tests/test_recurrence_postgres.py` — RETIRE — recurrence-rule scheduling
(register/list/due/fire/catchup/cancel/update) against Postgres; recurrence scheduling
is explicitly removed by default.

`tests/test_recurrence.py` — RETIRE — same feature (recurrence scheduling), pure-function
and in-memory variant.

`tests/test_reducer_v1_determinism.py` — RETIRE — Reducer v1 / signed-review-verdict
digest determinism; per the dependency map this module is off the runtime path entirely
(imported by no production module) and belongs to the removed review-verdict machinery.
**Carries an environment-pinned finding worth keeping even though the file retires**: it
documents that `datetime.fromisoformat` parses `"...T24:00:00Z"` differently on CPython
3.14 vs 3.12/3.13/PyPy — any retained kernel code parsing timestamps (claim expiry,
heartbeat, `not_before`) inherits this hazard. See closing section.

`tests/test_remaining_errors.py` — PORT — asserts kernel refusal paths: claim blocked by
`not_before` in the future, undeclared work-item type rejected, unknown workflow
rejected, cross-workflow link rejected, custom-field violations (missing/unknown/wrong
type/invalid enum) on create and transition, connect-without-create refusal. No signing
assertion.

`tests/test_replay_bootstrap_policy.py` — RETIRE — asserts which entity/transition pairs
receive the "unpinned bootstrap" exemption from external-anchor verification
(`_is_expected_unpinned_bootstrap`); pure v6-genesis/verification-Applicability plumbing.

`tests/test_replay_coverage.py` — SPLIT — PORT: `TestReplayClaimLifecycle` (acquired/
stolen/released/expired derivation), `TestReplayLinkLifecycle`,
`TestReplayEscalationAndNotBefore`, `TestReplayCustomFieldsUpdate`,
`TestReplayOrphanEvents` (orphan-row halts), and `TestBC090ClaimStateDriftDetection`
(**HIGH-VALUE PORT** — tampered `claimed_by`/`claim_expires_at` detected as drift, claim
state correctly reconstructed after acquire/heartbeat/steal). Within
`TestReplayKeyFailurePaths`, `test_missing_workflow_halts` and
`test_invalid_from_state_halts` are kernel and PORT; `test_signature_mismatch_halts` is
signing-specific and RETIREs with it. RETIRE: `TestReplayContinueOnRevoked` (revoked-key
handling), `TestInMemoryReplayParity` and `TestBC095InMemoryReplaySignatureVerification`
(in-memory + signature verification — both go: in-memory replay is a forked
implementation per the dependency map, and signature verification is removed).

`tests/test_replay.py` — SPLIT — PORT: `TestAC29OutOfBandEditDrift` (**HIGH-VALUE
PORT** — a direct out-of-band UPDATE to work-item state or custom fields is detected as
drift on replay; "no drift after normal operations" is the negative control). RETIRE:
`TestAC17RevokedKeyHaltsReplay` (revoked-key/signing), `TestPrincipalBindingFailureReport`
(principal-key binding, trust-specific).

`tests/test_replay_scoped.py` — PORT — asserts scoped (single-work-item) vs whole-store
replay parity: scoped replay detects drift, raises on unknown work item, skips
whole-store verification, uses the entity index, and reports a missing projection row as
corruption; `full_replay_unchanged_when_work_item_id_none` pins that omitting the scope
argument is a no-op change. No signing-specific assertion.

`tests/test_retired_tests_ledger.py` — RETIRE — UNCOMMITTED LOCAL CHANGES, not touched.
This is a meta-test for the *existing* trust-transition-era test-retirement governance
process (pinned inventory hash, `coverage_owed`/`deferred_to` bookkeeping,
"no test vanishes without a disposition"). The mechanism itself is scaffolding built for
the v5→v6 trust migration's own reconciliation programme (`SUITE-RECONCILIATION.md`), not
a kernel behaviour; Plan 032's F0 item 4 is doing this disposition pass directly instead.
Recommend the maintainer confirm this reading — see closing section.

`tests/test_scale.py` — SPLIT — PORT: `TestReplayBenchmark` (replay at scale, long
history), `TestLinkQueryBenchmark` (link query at scale) — both exercise retained
kernel paths under load. RETIRE: `TestHookThroughputBenchmark` (hook-drain throughput;
async hooks removed).

`tests/test_secret_delete.py` — RETIRE — secret-material deletion (`delete`,
`supports_delete`) for custody offboarding. `src/regista/_secrets.py` is consumed only by
`_cli.py` (the `secrets`/`principal` trust CLI groups, not in the kept 8) and
`principal_lifecycle.py`; there is no kernel call site. RETIREs with key/principal
custody.

`tests/test_secrets.py` — RETIRE — the generic secret-provider abstraction (file/env/
literal/vault/windows-DPAPI resolution). Verified by grep: `regista.secrets` /
`regista._secrets` have exactly three importers in `src/regista` — `_cli.py`,
`__init__.py` (re-export), and `principal_lifecycle.py` — all trust/key-custody surface.
No kernel path (project creation, DSN handling, workflow/claim/event code) resolves a
secret reference. Retires with the removed custody system, not because it "mentions"
trust vocabulary but because its only production callers are that vocabulary.

`tests/test_session13_regression.py` — PORT — **HIGH-VALUE PORT**:
`TestSweepRaceCondition` guards a genuine concurrency defect (a claim-expiry sweep must
not clobber a claim re-acquired between the sweep's delete and its lock); also
`TestBeforeSeqOrdering`, `TestTtlSecondsValidation` (zero/negative TTL rejected on
acquire and heartbeat), `TestValidateFieldUpdateRejectsUnknownType`. All kernel: claims,
query ordering, custom-field validation.

`tests/test_sf2_workflows.py` — PORT — an integration test of the workflow engine
(states/transitions/roles/required fields/version pinning/typed links/escalation-by-
attempt-count) using a real multi-actor workflow definition. No cryptographic
assertion; actor ids like `agent:architect` are just the v6-shaped id convention, not a
signing dependency. Broad, valuable coverage of exactly the kept feature set.

`tests/test_signer_binding.py` — RETIRE — principal key-ops facade (`verify_binding`),
`KeySet` secret-ref resolution by `principal_id`, path-traversal protection on
`provision_principal`, replay principal-binding (superseded key validity windows),
principal-binding edge cases. All principal/key custody and binding — retires with
`provision_principal`/key lifecycle, which are not kept CLI/library surface.

`tests/test_signing_ed25519.py` — RETIRE — Ed25519 signing integration (create/read/
transition/replay of signed events, key rotation, key-load errors). Pure signing
infrastructure.

`tests/test_signing.py` — RETIRE — envelope-signing machinery: JSONB drift survival of
the *signed* canonical envelope, downgrade-envelope filtering across v3–v5, v5
sign/verify roundtrip and tamper detection. All hinge on the envelope-signing/
verification contract the plan removes by default.

`tests/test_signing_scheme.py` — RETIRE — `HMACSHA256Scheme`/`Ed25519Scheme`
implementations and the scheme registry. Pure signing-scheme code.

`tests/test_smoke.py` — PORT — the broadest single end-to-end kernel test: register
workflow (+idempotent re-register, +version conflict, +invalid YAML), create work item,
transitions (valid/invalid/role-denied/full lifecycle), events, claims (acquire/release/
contest/heartbeat), queries (by workflow/state/claimable/pagination), links, event
idempotency, replay-no-drift. This is close to the F0a "minimal public example" the plan
asks F1 to keep working — losing it would be a severe regression in confidence.

`tests/test_spec_entity.py` — UNCLEAR — tests a `sign_spec` feature: recording an
immutable "spec" document (YAML + markdown hash) as its own chained/signed event stream,
independent from and non-interfering with work-item events, with its own sequence and
replay-chain verification. This is not named in Plan 032's keep table (workflows/work
items/claims/events/idempotency/custom fields/typed links/admin) nor in its remove list.
It reads as a bespoke evidence-recording feature riding on the general signing envelope
(the name and the "chain verified" assertion both suggest it exists to give a spec
document tamper evidence, which is evidentiary/audit territory) — but it could also be a
generic "record an arbitrary typed document as an event" capability someone wants to keep
for the coordination niche (e.g., attaching a design doc to a work item). A maintainer
call is needed on whether "spec" is a kernel entity kind or evidence-system leftover.

`tests/test_stale_heartbeat.py` — PORT — **HIGH-VALUE PORT** (AC07): heartbeat rejects a
non-owning actor, rejects after the lease was auto-stolen, valid heartbeat succeeds.
Directly protects the claim/lease/heartbeat contract the plan explicitly keeps.

`tests/test_startup_integrity.py` — PORT — **HIGH-VALUE PORT**: refuses to start with
pending migrations (single or multiple), refuses on workflow/library major-version
incompatibility, starts normally when compatible, and the error names the issue list.
Maps directly onto the plan's requirement that "initialization/open must distinguish
supported new schemas... refuse unsupported schemas before writes."

`tests/test_stream_discipline.py` — PORT — **HIGH-VALUE PORT**: library logging must
default to stderr (not stdout) unless the host app configures structlog itself, and CLI
`--json` errors emit the common error envelope on stdout with exit 1. Guards the
agent-notes WI-019 root cause (stdout contamination) and is generic to the retained CLI.

`tests/test_trust_domain.py` — RETIRE — trust-domain genesis document derivation/
verification (governance modes, threshold criteria, custody blocks, mutation matrix).
Pure trust-domain governance.

`tests/test_trust_genesis_path_env.py` — RETIRE — resolves the trust-genesis file path
from an env var. Trivial, but purely genesis-specific.

`tests/test_trust_log.py` — RETIRE — trust-log event contracts (enrolment, recovery
rotation, dual rotation, registrar delegation/authority). Pure trust-domain governance.

`tests/test_trust_projection.py` — RETIRE — `principal_keys` as a rebuildable projection
from the trust log, hand-edit detection, bypass-name removal. Pure trust/key custody.

`tests/test_v6_envelope.py` — RETIRE — strict v6 envelope schema/byte/signature
conformance. Pure signing-envelope machinery.

`tests/test_v6_vectors.py` — RETIRE — byte-level conformance vectors for the entire v6
cryptographic epoch (envelope, merkle bundle, trust genesis/checkpoint, producer policy,
estate catalog, trust-log export, reducer-v1 review-subject-state). Every vector is
trust/signing-specific; nothing here is a kernel behaviour.

`tests/test_validate_yaml.py` — PORT — pure-function `validate_yaml` tests (valid YAML
from string/path, invalid syntax, schema errors, unreachable state, undeclared role,
result-shape round-trip). No database, no signing. Squarely "workflows... straightforward
YAML/JSON Schema support."

`tests/test_validator_context_enrichment.py` — UNCLEAR — tests that synchronous
transition validators receive `actor_kind`, prior-event history, and `on_behalf_of`
delegation-chain context, on both backends, with forward-compatible `ValidatorContext`
deserialization. Plan 032 explicitly removes "async hooks/webhook delivery" but says
nothing about synchronous in-process transition validators as a concept; they may be the
mechanism by which custom business-rule validation on transitions is meant to survive
(consistent with "custom fields... callers can describe work without modifying
Regista"), or they may be considered part of the same hooks subsystem slated for
removal. Needs a maintainer ruling on whether "validators" (sync, in-process, per
`test_validator_hardening.py`'s framing) are a kept extension point.

`tests/test_validator_hardening.py` — UNCLEAR — same feature as above: exception in a
validator becomes `VALIDATOR_FAILED` and rolls back the transaction; Postgres
`statement_timeout` protects against a validator DB-call hang. Its docstring is explicit
that "BC-192 removed the AST-based I/O check and the ThreadPoolExecutor-based wall-clock
timeout... validators are now trusted, synchronous, in-process" — i.e. this already
survived one simplification pass. If validators are kept, this is a HIGH-VALUE PORT
(rollback-on-failure and DB-hang protection are exactly the kind of defect that recurs
silently); if validators as a concept are cut with hooks, RETIRE. Same open question as
the file above — flagging once is not enough, the maintainer needs to decide the concept
before either file's disposition is final.

`tests/test_version_info.py` — SPLIT — PORT: PEP 561 typing marker present,
`versions()` returns a `VersionInfo`, library version non-empty, schema version is an
int, canonical workflow version/hash, schema version matches the latest migration, CLI
`version --json`/`--text`. RETIRE: `test_available_signing_schemes` and
`test_envelope_version_is_6_now_that_v6_is_the_write_path` (both signing-specific; the
latter's assertion is that the envelope version literally *is* the v6 crypto epoch,
which the kernel removes by definition).

`tests/test_version_pinning.py` — PORT — **HIGH-VALUE PORT** (AC12): a work item created
against workflow v1 rejects a v2-only transition, a v2 item accepts a v2 shortcut, a v1
item only uses v1 transitions. This is the "immutable registered versions, work-item
version pinning" contract named verbatim in the plan's keep table — the single
highest-value invariant test for that line item.

`tests/test_webhooks_archive.py` — SPLIT — PORT: `TestArchiveEvents::
test_archive_dry_run_empty` (the kernel archive-events feature; `events_archive`/
`work_items_archive` are kernel tables per the dependency map). RETIRE:
`TestWebhookLifecycle` (register/list/unregister/pause/resume), `TestWebhookSidecarRoutes`,
`TestArchiveSidecarRoutes` (all webhook delivery + HTTP sidecar, both removed).

`tests/test_wi008_action_delegation_create.py` — RETIRE — action-delegation credentials
threaded through `create_work_item`. Action-delegation credentials are explicitly
removed.

`tests/test_wi008_action_delegation_postgres.py` — RETIRE — same feature, Postgres
integration (delegated notes, revocation, max-uses, workflow-axis scoping).

`tests/test_wi008_action_delegation.py` — RETIRE — same feature, chain verification and
in-memory integration.

`tests/test_wi008_action_delegation_round_two.py` — RETIRE — same feature, round-two
regressions (two-stage accept, revocation-id hash mismatch, event-id retry, chain depth/
cycle refusals).

`tests/test_wi217_replay_memory.py` — PORT — **HIGH-VALUE PORT**: guards a real
production incident (container growing ~2 GiB per full replay). Asserts replay's peak
memory does not scale with log size (streaming, not materializing) and that the query
plan has no sort. Squarely protects "reasonable history sizes remain practical to
query/replay" — exactly the kind of regression a kernel rewrite could reintroduce by
switching back to a naive "load everything" replay.

`tests/test_wi218_pool_finalization.py` — PORT — **HIGH-VALUE PORT**, and
**environment-pinned by design**: guards clean interpreter shutdown of the connection
pool on Python 3.14 (`PythonFinalizationError` from `Thread.join()` during
finalization). Both subprocess cases fail on the pre-fix build. This is connection-pool
handling, explicitly in-scope for the kernel ("bounded pool behavior"), and it is
deliberately not marked `slow` because 3.14 is a supported runtime — losing this test
silently reintroduces a stderr crash-look-alike on process exit.

`tests/test_wi223_principal_binding.py` — RETIRE — cross-project principal-key collision
detection (a real historical defect where a shared `keys.json` signed project-A events
with project-B's key) and its two fixes: `provision_principal` collision refusal and
replay's per-project principal-binding check. Both fixes are principal/key-custody
machinery that leaves with the trust stack; the defect cannot recur once the mechanism
it exploited (shared multi-project key files with per-principal signing) is gone.

`tests/test_wi224_claim_lineage.py` — RETIRE — already fully retired in place: the file
is docstring-only ("retired under WI-305 A/C"), zero collected tests. Nothing to port;
its two surviving invariants are already carried in `test_wi305_v6_review_gate.py` /
`test_wi305_reviewer_lineage_payload.py` (both themselves RETIRE — see below, since they
are lineage/producer-identity review-gate machinery).

`tests/test_wi228_vault_approle_live.py` — RETIRE — live Vault AppRole proof (opt-in,
skipped without a real Vault). Serves the same removed key/secret custody system as
`test_secrets.py`.

`tests/test_wi228_vault_approle.py` — RETIRE — hermetic AppRole auth state machine
(no-VAULT_TOKEN resolve, method reporting, fail-closed partial credentials, lease
re-authentication). Same custody system, no kernel dependency.

`tests/test_wi229_cli_contract.py` — SPLIT — RETIRE: `TestProvisionJsonExitCode`,
`TestProvisionPrincipalJsonExitCode`, `TestVerifyVerbsJsonExitCode` (bundle verify),
`TestSecretsForbiddenEnvelope`, `TestPrincipalEnrollKeyPath` — every one of these is a
trust CLI verb (`provision`, `principal`, `secrets`, `bundle`), none in the kept 8 CLI
groups. Worth porting as a *pattern* rather than as-is: `TestJsonExitCodeAudit` sweeps
every `--json`-capable CLI verb and asserts "exit code is decided outside the format
branch" — a generic CLI-contract hygiene check. Re-scoped to the 8 retained verbs
(`actor-roles`, `config`, `events`, `replay`, `schema`, `version`, `work-item`,
`workflow`), this audit is cheap insurance against the same class of bug (JSON body says
failure, exit code says success) recurring in the kernel CLI. Recommend porting the audit
mechanism, not the trust-verb test bodies.

`tests/test_wi231_key_encoding.py` — RETIRE — the encoding contract for signing/
encryption key material (base64/base64url/hex decoding of a 256-bit key). Serves key
custody only.

`tests/test_wi234_actor_metadata_limit.py` — PORT — **HIGH-VALUE PORT**: guards a real
defect (`validate_actor_metadata`'s 64 KB cap existed but had zero call sites, so
`actor_metadata` was bounded only by the generic 1 MiB limit). The fix wires the
validator into the shared `validate_mutation_params` choke point used by every mutation
entry point (create, transition, link, claim, `not_before` update) — generic to actor
metadata on any kernel mutation, not signing-specific.

`tests/test_wi236_key_encoding_fingerprint.py` — RETIRE — signing-key encoding contract
plus the `regista keys fingerprint` operator surface. Key custody.

`tests/test_wi237_store_new.py` — RETIRE — create-only/CAS custody writes
(`store_new`) for secret-material migrations, Vault KV-v2 `cas=0` and `file:` `O_EXCL`
semantics. Key/secret custody.

`tests/test_wi242_readonly.py` — PORT — **HIGH-VALUE PORT**: replay leaves no permanent
temp-table residue, replay works under a read-only DB session, `connect()` fails closed
on a missing schema or missing migrations table (vs. creating one on normal connect).
Directly protects the plan's "distinguish supported new schemas, empty destinations, and
old/unknown schemas; refuse unsupported schemas before writes."

`tests/test_wi243_schema_leak.py` — PORT — `drop_project_schema` correctly unregisters
the catalog row, is idempotent on a missing schema, and create/drop leaves no net catalog
growth. Kernel project/schema-scoping hygiene.

`tests/test_wi246_concurrent_create.py` — PORT — **HIGH-VALUE PORT**: guards a real
production hazard (two concurrent `create_project` calls, or a concurrent
`provision`+`create_project` pair, deadlocking on conflicting advisory-lock/DDL
ordering during catalog-table creation). Real Postgres threads, not just
test-parallelism. Squarely "PostgreSQL namespace... bounded pool behavior" territory and
easy to silently reintroduce if F1 rewrites the catalog-bootstrap path.

`tests/test_wi262_principal_kind_ingress.py` — RETIRE — validates and canonicalises
`on_behalf_of.principal_kind` at ingress against a closed vocabulary tied to
action-delegation/lineage review gating. All three of principal_kind, action delegation,
and lineage review are removed.

`tests/test_wi266_fail_closed.py` — PORT — **HIGH-VALUE PORT**: the highest-value
regression file in this half after WI-246/WI-217. A correctness audit found replay
*detecting* tampering but not *failing* on it — hash-chain breaks, global-chain orphans,
forks, multiple genesis events, and head mismatches all landed as advisory warnings with
exit 0; scoped and whole-store replay disagreed on the same corruption; and a projection
row with zero backing events (fabricated row, or a fully deleted log) reported clean.
Every test here is stated to fail against the unfixed code. This is exactly the
"replay... with honest drift reporting" contract the plan names as kept, and it is the
single easiest invariant to silently regress during an F1 rewrite of the replay/reducer
path.

`tests/test_wi267_row_authentication.py` — RETIRE — "authenticate the row, not just the
envelope": `verify_event`'s reconciliation of every signed row column against the
canonical envelope, across HMAC/Ed25519, v1–v5 envelope versions, scheme binding. This is
comprehensive and well-built, but every assertion is about cryptographic signature
verification, which the plan removes as a supported contract by default. If the
maintainer keeps the optional HMAC integrity facility (plan §3 "Signing"), the row-vs-
envelope reconciliation *pattern* here (not the file) would be the thing to revisit.

`tests/test_wi285_lineage_registry.py` — RETIRE — the model-lineage family registry and
its use in delegation/producer validation. Model-lineage registries are explicitly
removed.

`tests/test_wi287_fixture_helpers_postgres.py` — RETIRE — proves the `_v6_fixtures`
harness helpers (`open_v6_epoch`, `register_test_workflow`) behave the same on Postgres
as in-memory. A meta-test for the trust/genesis test-harness itself, not a kernel
behaviour.

`tests/test_wi287_inmem_parity.py` — RETIRE — a large (1062-line) parity suite between
the in-memory backend and Postgres for v6 signing/genesis conformance
(`TestSemanticConformanceInMemory` subclassing the v6 writer conformance suite,
`TestInMemoryGenesis`, `TestMigrationHarness`, `TestWI289Cluster6` chain/envelope-
deletion detection). Nearly every assertion is v6-signing- or genesis-specific.
`TestParityBoundary`'s "a failure after a write refuses instead of faking rollback" is a
generic in-memory-backend transactional-honesty property, but per the dependency map's
own §7 finding the in-memory backend's replay is a forked second implementation and the
recommendation is to retire it entirely in favour of disposable Postgres fixtures — so
this file's few generic assertions retire along with the backend they describe rather
than surviving independently.

`tests/test_wi289_cluster4_ledger_mapping.py` — RETIRE — UNCOMMITTED LOCAL CHANGES, not
touched. A self-check that every "cluster 4" (bundle-v3 offline-verification) entry in
the retired-tests ledger points at a real discharging test in `test_bundle.py`. Bundle v3
is audit-bundle/witness machinery, explicitly removed; the ledger-mapping mechanism
itself is retirement-governance scaffolding for that removal, not kernel behaviour.

`tests/test_wi289_phase_c.py` — RETIRE — Bundle v3 trust root, axis model, and verdict
lattice (not-checkable-is-not-false, required `TrustPolicy` argument, circularity
ceiling). Audit-bundle/witness/anchoring machinery, explicitly removed.

`tests/test_wi289_v6_counterparts.py` — SPLIT — RETIRE: `TestCluster1RowReconciliation`
(row-vs-envelope signature reconciliation — signing), `TestCluster5KeyLifecycle` (key
rotation — trust), `TestLedgerMapping` (retirement-governance meta-test). PORT:
`TestArchiveEventsOnTheV6Writer` — archiving a terminal item moves its events and leaves
replay clean, a dry run counts without writing, re-running the same cutoff archives
nothing new, a dormant non-terminal item is never archived. This is the kernel's
`events_archive`/`work_items_archive` feature and these read as genuine defect-shaped
guards (idempotent re-archival, no premature archival of live work) — recommend
**HIGH-VALUE PORT** for this cluster specifically, ported off the v6 writer onto whatever
the kernel's fresh writer becomes. UNCLEAR: `TestCluster2ChainIntegrity` — asserts
general chain/ordering invariants (concurrent appends serialize onto one unbroken
project chain; the chain survives global-`seq` gaps; a forged link is reported as an
orphan break) but expressed entirely through the v6 cryptographic hash-chain formula.
Whether an ordering/tamper-evidence invariant like this survives in a non-cryptographic
form is a call for whoever designs the kernel's new event row (the dependency map's §5
and §9 say that row is being redesigned from scratch); flagging rather than guessing.

`tests/test_wi301_trust_log_writer.py` — RETIRE — the largest file in this half (2739
lines): threshold-rooted trust-log writer, genesis, registrar delegation with atomic
`max_operations`, possession-challenge admission, rotation admission, replay
verification. Entirely trust-domain governance.

`tests/test_wi303_projection.py` — RETIRE — the trust-log projection rebuild consuming
only authority-verified events. Trust-domain governance.

`tests/test_wi305_reviewer_lineage_payload.py` — RETIRE — reviewer-lineage
compatibility and the "v6 producer is the only lineage authority" boundary. Model-lineage
review policy, explicitly removed (though generic review *states* are kept, per the
plan, this file is specifically about identity/lineage-based review gating).

`tests/test_wi305_v6_assurance.py` — RETIRE — assurance-level computation
(`compute_assurance_level_from_dicts`, `gate_permits_done`) driven by signed producer
lineage and cross-/same-lineage review rules. Built-in assurance classification,
explicitly removed.

`tests/test_wi305_v6_review_gate.py` — RETIRE — the cross-lineage review gate itself
(same-lineage reviewer blocked until acknowledgement, assurance reflecting the verdict).
Same removed feature as the two files above.

`tests/test_wi310_311_312_residuals.py` — RETIRE — action-delegation revocation
authorization and `_v6_referents.store_referents` (audit-bundle referents). Both
removed.

`tests/test_wi314_custody_admission.py` — RETIRE — write-time admission validation for
`trust_domain_custody_declared` corrections (sequence contiguity, `supersedes_digest`
correctness). Trust-log governance.

`tests/test_wi315_epoch_boundary_trigger.py` — RETIRE — the DB trigger (migration 049)
that refuses a direct `events` insert lacking a v6 envelope once a project's epoch is
open — defense-in-depth against a stale pre-cutover client. The entire "v6 epoch" concept
this trigger defends goes with signing/genesis removal.

`tests/test_wi319_trust_enroll.py` — RETIRE — `regista trust enroll` CLI (possession-
proof-based principal-key enrollment). Trust/key custody.

`tests/test_wi319_trust_init_log.py` — RETIRE — `regista trust init-log` CLI (writes the
trust log's genesis event). Trust governance.

`tests/test_wi321_trust_delegate_registrar.py` — RETIRE — `regista trust
delegate-registrar` CLI. Trust governance.

`tests/test_wi325_genesis_init.py` — RETIRE — the largest genesis-specific file (2188
lines): `regista genesis init`, opening a per-project v6 epoch with a verified trust-log
chain walk and a fail-closed agent-suite gate-report check. Entirely genesis/trust/
suite-review-policy machinery — three separate removed categories in one file.

`tests/test_wi326_probe_gate_contract.py` — RETIRE — the delivery contract between
`regista.actor_boundary_signing` (a probe script) and agent-suite's genesis-gate
validator (stdout-is-one-JSON-object, exit-code-agrees-with-`ok`). This is exactly
"agent-suite review policy and suite config discovery," named for removal.

`tests/test_wi330_estate_catalog_live.py` — RETIRE — `regista trust catalog` against a
live multi-project estate. Estate catalogs are explicitly removed.

`tests/test_wi330_estate_catalog.py` — RETIRE — the estate-catalog byte contract and
fail-closed refusals, database-free. Same removed feature.

`tests/test_wi337_trust_log_export.py` — RETIRE — the published trust-log export
artifact enabling offline bundle authentication. Trust-log/bundle machinery, both
removed.

`tests/test_witness_in_memory.py` — RETIRE — witness delivery/retry/auto-pause/signing
against the in-memory backend. Witness/anchoring explicitly removed.

`tests/test_witness_integration.py` — RETIRE — witness registration and receipt delivery
against Postgres, including asymmetric (Ed25519) witness keys. Same removed feature.

`tests/test_witness_key_enrollment_in_memory.py` — RETIRE — witness key enrollment/
rotation/revocation into `principal_keys`, in-memory. Witness + key custody, both
removed.

`tests/test_witness_key_enrollment.py` — RETIRE — same feature against Postgres; notably
its own docstring says the *positive* witness-key-lifecycle path was already "CUT FROM
0.6.0" and these tests now just assert the refusal (`WITNESS_LIFECYCLE_CUT`) is honest.
Confirms witness is already half-dead upstream of this plan.

`tests/test_witness.py` — RETIRE — witness URL validation, event-filter matching, and
in-memory witness registration/delivery. Witness/anchoring, removed.

`tests/test_workflow_compose.py` — RETIRE (borderline) — workflow YAML composition:
`extends`/include resolution, deep-merge of parent/child definitions, keyed list merge,
cycle/depth/path-escape detection. Plan 032 §3 explicitly lists "workflow inheritance" in
the remove-by-default set ("unless F0 identifies a small independent subset worth
retaining. Default to removal rather than keeping machinery because it has tests.").
Flagging this explicitly rather than silently retiring: `resolve_includes`'s safety
properties (cycle detection, max depth, path-escape rejection) are a small, self-
contained, dependency-free module (no signing, no database) that a maintainer might
judge worth the "small independent subset" exception — but the plan's default is
removal, so RETIRE stands unless the maintainer overrides it.

`tests/test_work_item_ref_validation.py` — PORT — asserts the typed-link/typed-ref
contract explicitly named in the keep table: a ref must point at an existing UUID, must
match its declared type when typed, an untyped ref accepts any existing UUID, and the
same holds through `create` and `transition`, including multi-target (union-type)
refs. Directly protects "Typed links: Explicit relationships between items with simple
lookup and validation."

`tests/_trust_fixtures.py` — RETIRE — mints signed `regista.trust-genesis` documents
(solo/co-signed/threshold) with ephemeral test keys. Supports only trust-domain-genesis
tests; no test functions of its own.

`tests/_trust_log_fixtures.py` — RETIRE — trust-log event and durable-possession-evidence
fixtures (854 lines). Supports only WI-301/303/319/321/325/330/337-style trust-log tests.

`tests/_v6_fixtures.py` — UNCLEAR — a thin compatibility re-export of
`regista.testing`'s v6 harness (`make_v6_keyset`, `open_v6_epoch`, `ACTOR_PRINCIPALS`,
`Producer`, etc.). Zero test functions, but it is the shared setup fixture for a large
fraction of the files marked PORT above (smoke, sf2_workflows, session13_regression,
stale_heartbeat, replay/replay_scoped/replay_coverage, remaining_errors,
read_events_conformance, wi242/243/246, work_item_ref_validation, and more). This is not
a "retire" call in the normal sense: the kernel plainly still needs *some* way to open a
project and register a workflow before these kernel tests can run, but per the
dependency map's §5 finding, the concrete mechanism here (mint an Ed25519 keyset, open a
cryptographic v6 epoch) is exactly what F1's fresh schema baseline removes. Every PORT
file that imports this fixture will need its setup rewritten against F1's new
(non-cryptographic) open/connect path — the test *bodies* survive, the *harness* does
not. Recommend treating this file's replacement as an explicit F1 task rather than an
implicit side-effect of "delete the trust files."

`tests/_wi008_fixtures.py` — RETIRE — action-delegation credential fixtures. Supports
only the four `test_wi008_*` files, all RETIRE.

`tests/_wi337_fixtures.py` — RETIRE — in-memory trust-log + published-export + bound-
project fixtures. Supports only `test_wi337_trust_log_export.py` and (per its own
docstring) a live counterpart not in this half.

## HIGH-VALUE PORT list

1. `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection` — tampered claim
   state detected as drift.
2. `tests/test_replay.py::TestAC29OutOfBandEditDrift` — direct out-of-band state/field
   edits detected as drift.
3. `tests/test_session13_regression.py::TestSweepRaceCondition` — claim-expiry sweep
   must not clobber a concurrently re-acquired lease.
4. `tests/test_stale_heartbeat.py` (AC07) — heartbeat ownership/steal correctness.
5. `tests/test_startup_integrity.py` — refuse start on pending migrations / incompatible
   workflow version.
6. `tests/test_stream_discipline.py` — library must not contaminate stdout; CLI `--json`
   error envelope.
7. `tests/test_version_pinning.py` (AC12) — immutable workflow version pinning.
8. `tests/test_wi217_replay_memory.py` — replay must not materialize the whole log
   (real ~2 GiB/replay incident).
9. `tests/test_wi218_pool_finalization.py` — clean pool shutdown on Python 3.14 (also
   environment-pinned, see below).
10. `tests/test_wi234_actor_metadata_limit.py` — the 64 KB actor-metadata cap must
    actually be enforced at every mutation entry point.
11. `tests/test_wi242_readonly.py` — replay leaves no residue and works read-only;
    connect fails closed on missing/unmigrated schema.
12. `tests/test_wi246_concurrent_create.py` — concurrent `create_project` must not
    deadlock.
13. `tests/test_wi266_fail_closed.py` — replay must fail (not warn) on structural chain
    corruption; the single highest-value file in this half after the two above.
14. `tests/test_wi289_v6_counterparts.py::TestArchiveEventsOnTheV6Writer` — archive
    dry-run/idempotent-rerun/no-premature-archival, once re-pointed at the kernel's
    fresh writer.

## Environment-pinned findings

1. `tests/test_reducer_v1_determinism.py` (RETIRE) documents that
   `datetime.fromisoformat("...T24:00:00Z")` parses as the following midnight on CPython
   3.14 but raises on 3.12/3.13/PyPy 3.11. The *file* retires with the reducer, but the
   *hazard* does not: any retained kernel code that parses ISO-8601 timestamps (claim
   `expires_at`, `not_before`, heartbeat windows) across the declared Python support
   range inherits this divergence. Worth a standalone kernel-side test once F0 item 5
   fixes the supported Python range — this was flagged in the dependency map (§2) as an
   input to that decision, and it should not be lost just because the file carrying it
   retires.
2. `tests/test_wi218_pool_finalization.py` (PORT) is interpreter-version-pinned by
   design, not by accident: it specifically guards Python 3.14's
   `PythonFinalizationError` during interpreter shutdown. This is a legitimate targeted
   regression test, not a time-bomb, but it is worth naming here since the criteria asked
   for anything pinned to interpreter version regardless of disposition.

## What surprised me / possible gaps in the dependency map's §4

- **§4's ceiling framing understates the harness problem, not just the test-body
  problem.** The map correctly says "at most 68% retires, floor is above zero" based on
  naming. What it doesn't surface: of the ~19 files here disposed PORT, the large
  majority currently bootstrap through `tests/_v6_fixtures.py` →
  `regista.testing.open_v6_epoch`/`make_v6_keyset` — i.e. they mint an Ed25519 keyset and
  open a cryptographic v6 epoch purely to get a connected project before testing kernel
  behaviour that has nothing to do with signing. Porting these files is not "delete the
  trust assertions and keep the rest" — every one of them needs its *setup* rewritten
  against whatever F1's non-cryptographic open/connect path turns out to be. This is
  consistent with the dependency map's own §5 finding (the `events` table's `NOT NULL`
  signing columns and `project_identity`'s genesis requirement), but §4 doesn't connect
  that finding back to the test-harness cost — recommend treating "write the kernel's
  test harness" as an explicit, sized F1 task rather than an assumed side effect.
- **Two files raise a real product-scope question the plan doesn't answer**:
  `tests/test_spec_entity.py` ("spec" as a signed, independently-sequenced document
  entity distinct from work items) and the validator-context pair
  (`test_validator_context_enrichment.py` / `test_validator_hardening.py`, synchronous
  in-process transition validators). Neither is named in Plan 032 §3's keep or remove
  tables. Both are UNCLEAR here rather than guessed, because guessing wrong in either
  direction is expensive: keeping "spec" by accident re-imports an evidence-recording
  feature into a kernel that is supposed to have shed evidence concerns; cutting
  "validators" by accident may remove the only extension point through which custom
  per-transition business rules were ever meant to be enforced.
- **`test_workflow_compose.py`** is a clean, self-contained, dependency-free module
  (no database, no signing) whose only real risk is scope creep (workflow inheritance is
  execution/authoring convenience, not coordination-state machinery). It is exactly the
  shape of thing Plan 032 §3 warns against keeping "because it has tests," so I kept the
  default (RETIRE) rather than recommending an exception — but it's the one file in this
  half where "small independent subset worth retaining" reads as plausible rather than
  rhetorical, and is worth a two-minute maintainer look rather than a silent deletion.
- **The retirement-ledger meta-tests** (`test_retired_tests_ledger.py`,
  `test_wi289_cluster4_ledger_mapping.py`, and `TestLedgerMapping` inside
  `test_wi289_v6_counterparts.py`) are themselves a mini test-governance subsystem built
  for the *previous* large migration (v5→v6 trust cutover). All three retire under this
  plan's own F0 item 4, which is Plan 032 doing directly, once, what that ledger system
  was built to enforce continuously. Worth confirming the maintainer agrees the ledger
  mechanism itself is superseded rather than still-desired process for this cutover too.
