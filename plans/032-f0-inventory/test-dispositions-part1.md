# Plan 032 F0 item 4 — per-file test disposition, part 1 of 2

**Scope covered:** first half of `ls tests/*.py | sort`, files 1–91 of 183.
First file: `tests/conftest.py`. Last file: `tests/test_public_v6_testing_postgres.py`.
Count: **91 files**. The second-half pass should start at file 92,
`tests/test_public_verification_surface.py`.

Method: for every file I read the module docstring, every `class Test*` /
`def test_*` name, and — wherever the name alone did not settle it — the
fixture setup and representative test bodies, plus a source-level check of
the function/class actually being exercised (e.g. confirming `TokenRegistry`
lives in `regista.sidecar.auth`, or that `read_events_since` is a public
workflow-API method with no hook dependency at all). Classification follows
the assertion, not the filename, per the task's critical rule.

## Summary

| Disposition | Count |
| --- | ---: |
| RETIRE | 48 |
| PORT | 23 |
| SPLIT | 19 |
| UNCLEAR | 1 |
| **Total** | **91** |

For reference, a pure-naming sweep (grepping this half for trust vocabulary)
would have called roughly 55–60 of these 91 files RETIRE outright. The
assertion-level pass moves at least 7 of those into PORT or SPLIT — the two
sharpest examples are `test_hook_miss_recovery.py` (see below) and
`test_production_readiness.py`, both fully kernel despite trust-sounding
names, and the reverse case, `test_global_event_chain.py` /
`test_plan024_global_chain.py`, which read as ordinary event-ordering
regressions but turn out to bind `prev_event_hash` to the signature bytes.

## File-by-file

`tests/conftest.py` — **SPLIT**. The PostgreSQL-reachability skip fixture
(skip DB tests cleanly when no PG is reachable and `REGISTA_TEST_DSN` isn't
set) is kernel test infrastructure every PG-backed test in the suite depends
on — PORT. The `apply_epoch_marks`/`validate_xfail_report` wiring from
`_epoch_blocked` is dead process tooling for a already-closed v6 reconciliation
effort (see next entry) — RETIRE that half.

`tests/_epoch_blocked.py` — **RETIRE**. Not a test; the xfail-manifest
machinery for `SUITE-RECONCILIATION.md §2.1` (tracking tests known-broken
during the v6 cutover). The manifest it reads (`epoch_blocked_manifest.json`)
is already at `"entries": []`, `"blocker": "none"` — the reconciliation it
exists to manage is finished, and what it managed (the v6 ordinary-event
writer reconciliation) is exactly the machinery Plan 032 deletes. No future
purpose either way.

`tests/_helpers.py` — **SPLIT**. `DSN`/`KEY_PATH`/`TESTS_DIR` constants are
used by nearly every kernel test file — PORT. `seed_precut_ed25519_witness`
is witness-registration-row seeding — RETIRE with the witness feature.

`tests/reducer_v1_vectors.py` — **RETIRE**. Not a test; conformance vectors
for "reducer v1," which the dependency map (§2) already identifies as
review-verdict digest machinery reachable only from trust tests and
`tools/`, off the runtime path entirely. **Worth preserving as a fact, not a
file:** one vector (`"not_before": "2026-08-09T24:00:00Z"`) is the source of
the documented `datetime.fromisoformat` cross-interpreter divergence
(CPython 3.14 parses it, 3.12/3.13/PyPy 3.11 raise) — flagged again below
under environment-pinned findings, because any kept kernel code parsing
timestamps inherits this hazard even though this file goes.

`tests/test_actor_id_and_token.py` — **SPLIT**. `TestActorIdValidation`
(overlong actor-id / role-id rejected on create/register/unregister) is
kernel actor-id validation — PORT. `TestTokenRegistryValidation` imports
`regista.sidecar.auth.TokenRegistry` directly — confirmed sidecar-only,
RETIRE with the HTTP sidecar.

`tests/test_actor_metadata_contract.py` — **RETIRE**. `ActorMetadata`
(`role, channel, model, family, model_lineage, gate_name, attempt_n,
context_hash, prompt_template_hash`) is the assurance/review-lineage
metadata bag, and the file's own lint-helper tests (`catches_event_missing_family`,
`catches_null_metadata`) exist to support model-lineage classification. No
assertion here is about kernel actor attribution as such.

`tests/test_api_surface.py` — **PORT**, `**HIGH-VALUE PORT**`.
`TestAC33PreSignedRejection.test_public_api_has_no_signature_params` asserts
`append_event`/`transition`/`create_work_item`/`register_workflow` take no
signature parameter — this is a regression test *for* the exact contract
Plan 032 wants (no cryptographic params on the public surface), so losing it
would let signing creep back in unnoticed. `TestAC34NoPostgresTypesLeak`
(Event/WorkItem/Claim carry no psycopg-specific types) and
`TestBC195ConstructorPositionalContract` (constructor shape) are both kernel.

`tests/test_assurance.py` — **RETIRE**. 1316 lines entirely of
`AssuranceLevel`/`GateProfile`/`LineageRelation`/`compute_assurance_level`/
`human_gate` — built-in assurance classification and canonical review
policy, explicitly on the remove list. No test here asserts generic
review-state behaviour independent of model lineage.

`tests/test_bc184_bc185_metrics.py` — **SPLIT**. `TestHookQueueDepthMetric`
and `TestHookQueueDepthInMemory` (BC-184) are hook-queue-only — RETIRE.
`TestMaintenanceHealthy` and `test_maintenance_claims_swept_counter` (BC-185)
are kernel maintenance/lease-sweep observability — PORT,
`**HIGH-VALUE PORT**` (claims-swept counter is the operator-visible signal
for lease expiry actually firing). `test_maintenance_hook_leases_swept_counter`
and `test_maintenance_recurrences_fired_counter_registered` — RETIRE (hooks,
recurrence). `test_maintenance_partitions_created_counter_deprecated` — low
value either way; RETIRE (already deprecated).

`tests/test_bc188_connect_search_path.py` — **PORT**, `**HIGH-VALUE PORT**`.
BC-188 regression: `connect()` must scope `DROP` to the configured schema so
two same-named tables in sibling schemas don't collide — exactly the
project/schema-scoping guarantee the kernel keeps, and a cross-tenant-unsafe
defect class if lost.

`tests/test_bc214_216_217_218.py` — **RETIRE**. Key-entry restructuring
(HMAC/Ed25519 alg, fingerprint), key roles (actor/auditor/recovery — which
role may sign which transition type), revoked-key timing, envelope v2. All
signing/key-lifecycle.

`tests/test_bc215_219_220_221.py` — **SPLIT**. `TestBC215RevokedAtBoundary`
and `TestBC219DelegationChainFields` are key-revocation-timing and
action-delegation-chain — RETIRE. `TestBC220ClientTimestamp` asserts
`append_event`'s returned timestamp is the **client-supplied** value, not a
DB-server value — a generic kernel property (confirmed: no trust import
beyond scaffolding a valid event to append) — PORT. `TestBC221CheckpointReservation`
is the reserved-transition-name mechanism in `_contract`
(`check_reserved_transition`), which is a kernel function per the dependency
map — but the specific reserved name ("checkpoint") and its payload shape
(`merkle_root`, `tsa_token`) belong to bundle/witness checkpointing. **Flag
as needing a call**: keep the reserved-namespace mechanism, but whether
"checkpoint" itself stays reserved depends on whether anything else claims
that name once bundles go.

`tests/test_bc278_279_280.py` — **SPLIT**. `TestBC278HeartbeatCoalescingParity`
(in-memory coalescing uses wall clock, not expiry) and
`TestBC279ReplayWarnsOnUnknownTransitions` (postgres + in-memory) — PORT,
`**HIGH-VALUE PORT**` for BC279: it is precisely "honest drift reporting" on
replay, one of the kept contracts, and a defect that could recur silently.
`TestBC280HookHandlersCopyOnWrite` — RETIRE (hooks).

`tests/test_bc294_migration_repair.py` — **PORT**. Checksum-drift repair
(`repair_checksums`), autocommit migration mode, CLI `schema repair-checksums`.
Not trust-coupled — general migration-safety infrastructure the kernel
plausibly keeps for its own future schema evolution past the fresh baseline.

`tests/test_bc306_entity_kind_validation.py` — **SPLIT**.
`TestSidecarEntityKindValidation` — RETIRE (sidecar, `pytest.importorskip("fastapi")`).
`TestCoreApiEntityKindValidation` and `TestInMemoryEntityKindValidation`
(unknown `entity_kind` rejected, `work_item` / default accepted) — PORT,
basic input validation on the core API.

`tests/test_bc310_replay_isolation.py` — **PORT**, `**HIGH-VALUE PORT**`.
`REPEATABLE READ` transaction isolation for replay; replay does not observe
a concurrent write. Directly the F2 requirement ("lock ordering under
contention... replay reconstructs the same supported state").

`tests/test_bundle.py` — **RETIRE**. 2386 lines, entirely audit-bundle
export/verify against a real store (genesis digests, trust pins, revoked
signing authority, TOCTOU on the export ceremony). Audit bundles are
explicitly removed.

`tests/test_bundle_v3.py` — **RETIRE**. 2567 lines, the bundle v3 document
format itself (Merkle vectors, anti-downgrade, closed statement schema).
Same disposition as above, no database needed but same removed feature.

`tests/test_canonical_workflow.py` — **PORT**. Registers and idempotency-checks
the one canonical lifecycle workflow shared by dossier/agent-notes, and
exercises the agent-work + human-accept "north star" chain. Kernel workflow
behaviour. **Coupling to flag**: `test_canonical_request_changes_runs_note_requirement_end_to_end`
exercises the built-in `request_changes` validator, which lives in
`regista._review_validators` — the same module `test_plan023_review_validators.py`
protects and which is *mostly* RETIRE (lineage/independence logic). If that
module is deleted wholesale rather than split, this canonical-workflow test
breaks too; the note-requirement behaviour needs either extraction into a
lineage-free validator or an explicit call that the canonical workflow's
`request_changes` state also goes.

`tests/test_claim_link_idempotency.py` — **PORT**, `**HIGH-VALUE PORT**`.
Duplicate `event_id` on claim acquire/release and link create/remove
produces no duplicate events; claim events record actor metadata. This is
the idempotency + claims + links keep-table intersection almost verbatim.

`tests/test_cli_args.py` — **SPLIT**. All generic CLI exit-code/usage tests
(workflow validate, work-item show, schema status/init, replay, events
show/tail, actor-roles list, unknown command) — PORT. Two lines
(`hooks_dead_letter_list/requeue_missing_config`) — RETIRE (hooks CLI group).

`tests/test_cli_conformance.py` — **UNCLEAR**. Runs regista's CLI through
`agent_suite.conformance`, a pinned package from the **agent-suite** repo
(imported via a git+SHA reference, skipped if absent). The tests themselves
assert generic CLI contract behaviour (success/error/usage/broken-pipe
cases), which is kernel-relevant, but the mechanism is a dev-time dependency
on the very suite-wide conformance tooling Plan 032 wants regista to stop
depending on for a standalone public release. A human needs to decide
whether "no ordinary operation requires agent-suite" extends to test-time
tooling, or whether a pinned external conformance kit is acceptable dev
infrastructure that never ships.

`tests/test_client_signer.py` — **RETIRE**. Client-side Ed25519 key custody
and challenge-signing helper (`ClientSigner`) — key lifecycle/custody,
explicitly removed.

`tests/test_cli_integration.py` — **SPLIT**. Schema init/status, workflow
validate, work-item show/list, events show/tail, replay, actor-roles list,
env-var config — PORT (kernel CLI). `TestPrincipalWriteSubcommandsAreRefused`
and `TestTrustRebuildProjectionCLI` — RETIRE (principal/trust CLI groups
disappear rather than merely refuse). `TestHooksDeadLetterList` — RETIRE
(hooks).

`tests/test_concurrency.py` — **PORT**, `**HIGH-VALUE PORT**`.
`TestAC28ConcurrentSeqGapFree`: 20 concurrent workers, gap-free `event_seq`
allocation for appends and transitions. Uses a v6 keyset purely to construct
signable events (per-actor keys are today's only way to get 20 concurrent
writers) — the assertion is about sequence allocation under contention, not
signing.

`tests/test_config.py` — **RETIRE**. `SuiteConfig` reads
`AGENT_SUITE_CONFIG` / `/etc/agent-suite/suite.env` / `~/.config/agent-suite/suite.env`
— confirmed by reading `src/regista/_config.py`. This is exactly "suite
configuration discovery," explicitly on the remove list. A minimal
env-var-only DSN/key-path resolver may need to replace it, but this file's
mechanism (layered suite-wide config file discovery) is not it.

`tests/test_connection_ssl.py` — **PORT**. `require_ssl` connection option,
including pass-through from `create_project`. Kernel connection handling.

`tests/test_contract.py` — **PORT**, `**HIGH-VALUE PORT**`. Direct unit
tests of `_contract`: `validate_actor_kind`, `validate_ttl`,
`validate_not_before`, `resolve_transition`, `check_role_gating`,
`check_actor_role_authorized`, `check_append_blocked`, `check_idempotency`,
`check_expected_seq`, `validate_link_type`, `should_escalate`. Per the
dependency map's own correction, `_contract` **is** the kernel's validation
layer almost line-for-line against Plan 032's keep table. This file is
close to the closest thing to a core regression suite for the retained
kernel that exists today.

`tests/test_coverage_gaps.py` — **SPLIT**, mostly PORT. Transition-via-append
blocked, work-item/claim-not-found paths, expired-claim sweeping
(`TestSweepExpiredClaims`, `TestSweepIsASystemActionAndIsolatesFailures`),
workflow semantic errors (no initial state, unreachable state, undeclared
role), `TestExpectedAttemptNumber` (stale attempt number rejected, correct
attempt accepted), read/query filters, custom-field filter query, heartbeat
actor kind, close behaviour — all PORT, and `TestExpectedAttemptNumber` is
`**HIGH-VALUE PORT**` (this is the fencing-token stale-write refusal Plan
032 explicitly calls out as a public contract to demonstrate). `TestHookNotFound`
— RETIRE (hooks). `TestHmacKeyPathRequired` — flag as needing re-check once
F0 settles whether a key path is still mandatory for HMAC-only usage; likely
retires alongside signing but not certain from this file alone.

`tests/test_custody.py` — **RETIRE**. 733 lines, key-custody backends
(file/vault/azure/operator), principal provisioning backend-aware naming.
Key lifecycle/custody, explicitly removed.

`tests/test_docs_060_conflicts.py` — **RETIRE**. Runs
`docs/0.6.0/check-conflicts.py` against the *0.6.0* spec docs specifically.
F0 item 1 marks the 0.6 trust design and its docs historical; this checker's
subject document is being superseded, not merely its trust content.

`tests/test_doctor.py` — **SPLIT**. `TestDoctorCheck`, `TestDoctorReport`,
and most of `TestRunDoctor`/`TestRoleAttributes` (DSN reachability, schema
check, `CREATEROLE` role attribute) — PORT, kernel `doctor` CLI. `TestCustodyConsistency`
(file/vault/azure custody-ref-vs-backend checks) — RETIRE (key custody).

`tests/test_e2e.py` — **PORT**, `**HIGH-VALUE PORT**`. Full agent pipeline,
`not_before` deferral and reclaim, linked work items with lifecycle, actor
role enforcement across a pipeline. Broadest single end-to-end kernel
regression in this half; uses v6 keyset only as event-construction
scaffolding.

`tests/test_enroll_principal.py` — **RETIRE**. Principal enrolment refusal
machinery, CLI enrol refusal, provision-principal scheme — principal
custody/lifecycle.

`tests/test_epoch_blocked_meta.py` — **RETIRE**. Meta-guards for the
`_epoch_blocked` manifest mechanism (manifest nodes exist, count only
shrinks, structural failure-form pin, end-to-end xfail-rejection proof).
Same reasoning as `_epoch_blocked.py`: the reconciliation it polices is
closed (manifest is empty) and concerns the v6 writer cutover specifically.

`tests/test_events_partition.py` — **PORT**. Event-partition idempotent
setup, event storage/read-by-time-range, unpartitioned-init behaviour,
escalation-unique-per-work-item. Kernel events + `should_escalate` contract.

`tests/test_genesis.py` — **RETIRE**. 467 lines, the genesis ceremony itself
(first-write admission, concurrent-genesis-one-winner, genesis recovery,
legacy/v6 admission boundary). Genesis ceremonies are explicitly removed.

`tests/test_global_event_chain.py` — **RETIRE**. The global tamper-evident
hash chain: `prev_global_event_hash = sha256(prev.canonical_envelope || prev.signature)`
— binds the chain to signature bytes by construction, so it cannot survive
signing's removal as written. The underlying need (detect deletion/tamper
across work items) may resurface in a simpler form, but this exact
mechanism goes with signing.

`tests/test_hash_chain.py` — **RETIRE**. Same reasoning as above at smaller
scope (BC-233 first-event/replay hash-chain check); prev-hash chain
verification is signature-coupled.

`tests/test_heartbeat_coalesce.py` — **PORT**, `**HIGH-VALUE PORT**`.
`compute_coalesce_threshold`, rapid-heartbeat coalescing into one event,
coalesced heartbeat still extends the claim. Directly "durable leases,
heartbeat" from the keep table, and a specific defect class (event-storm
suppression) worth protecting by name.

`tests/test_hook_consumer.py` — **RETIRE**. Hook-consumer lifecycle
(start/stop, processing-flag reset, connected-flag, polling). Async hooks,
explicitly removed.

`tests/test_hook_miss_recovery.py` — **PORT**, `**HIGH-VALUE PORT**` (naming
trap). Despite the filename, every test calls only `regista.read_events_since(after_seq=..., limit=...)`
— a generic public cursor/pagination method on the workflow API
(`_api_workflow.py`), confirmed by grep to have no hook-queue involvement at
all. This is the sharpest example in this half of the task's warning: a
file named for a removed feature that in fact protects retained
event-history pagination.

`tests/test_hook_primitives.py` — **RETIRE**. Hook claim/complete round
trip, `SKIP LOCKED` claiming, retry-then-dead-letter, lease-expiry requeue —
all hook-queue-specific.

`tests/test_hook_toctou.py` — **RETIRE**. 570 lines, hook-ownership TOCTOU
across in-memory/postgres/**sidecar** backends. Hooks and sidecar both
removed.

`tests/test_idempotency.py` — **PORT**, `**HIGH-VALUE PORT**`.
`TestAC24IdempotencyMismatch` (same event_id + different transition/actor
rejected, identical retry returns original) and `TestAC25ExpectedEventSeq`
(optimistic-concurrency seq check). This is the idempotency keep-table item
almost verbatim.

`tests/test_in_memory_conformance.py` — **PORT**, `**HIGH-VALUE PORT**`,
with a caveat. 654 lines of workflow/work-item/transition/events/claims/
links/actor-roles/query/custom-field-filter conformance — essentially the
functional regression suite for the exact contract the kernel keeps
(`TestConformanceReplay` is the one part that touches the forked
`_in_memory_replay`). Corroborates the dependency map §7 finding that the
in-memory backend's claim/work-item/transition/link surface genuinely shares
`_contract` rather than forking it. **Caveat**: it runs against
`InMemoryRegista`, which §7 recommends retiring; if that recommendation is
taken, this file's assertions need retargeting to disposable PostgreSQL
fixtures rather than being deleted — the coverage is too valuable to lose
along with the backend it happens to run against today.

`tests/test_invariant_probe.py` — **RETIRE**. 560 lines, actor-boundary and
closed-registry measurement tied to genesis/keyset/trust-bootstrap exclusion
and model-lineage observation. This is a trust-boundary measurement tool,
not a kernel behaviour test.

`tests/test_jcs.py` — **PORT**, `**HIGH-VALUE PORT**`. JCS/RFC-8785
canonicalization: float scientific-notation boundary, integer safe/unsafe
domain, negative-zero normalization, key ordering, NFC/NFD determinism. Per
the dependency map's own correction, `_jcs` is kernel (canonical
serialization is explicitly permitted to remain), and these are exactly the
class of narrow boundary-condition regression a second implementation gets
wrong.

`tests/test_key_lifecycle.py` — **RETIRE**. 421 lines, key get/active/verify-status,
revoked/deprecated key handling, hot reload, key-id pinning on
work-item creation. Key lifecycle, explicitly removed.

`tests/test_lineage.py` — **RETIRE**. 744 lines, `resolve_model_lineage`,
`stamp_model_lineage`, service-identity exemption, delegation-lineage
flagging, cross-lineage reviewer ack logic. Model-lineage/assurance/review
machinery, explicitly removed.

`tests/test_link_errors.py` — **PORT**, `**HIGH-VALUE PORT**`. Disallowed
link type, link-target-not-found, remove-nonexistent-link, link-removed
event emitted. Directly the typed-links error-path keep-table item.

`tests/test_migration_045.py` — **RETIRE**. Tests migration 045, which drops
already-dead-subsystem tables from the *old migration chain*. F1 replaces
the chain with a fresh schema baseline ("no chain of migrations through
trust-system schemas is required"), so this migration and its test both go
regardless of the tables' trust/kernel split.

`tests/test_migrations_021_026.py` — **SPLIT**, but structurally awkward.
Individually: witness-receipt uniqueness (021, trust), hook-queue
lease-sweep index (022, hooks), `claims_expires_at` index (023, **kernel**),
events-archive table/columns (024, **kernel**), webhook-registrations
dropped (026, webhooks), webhook-sign-secret (025, webhooks),
webhook/witness-mode unification (026, trust/webhook), work-items-archive
table (029, **kernel**). The kernel-relevant assertions (archive table
parity, claims index) are real regressions worth keeping, but every test
here is written against a *specific numbered migration* in the chain F1
retires wholesale. Recommend porting the **intent** (assert the archive
tables and claims index exist and have the right shape against the fresh
baseline) rather than this file as such.

`tests/test_migration_safety.py` — **PORT**, `**HIGH-VALUE PORT**`. BC-191:
advisory-lock serialization of concurrent `run_migrations`, checksum-drift
detection, null-checksum legacy-row backfill. General migration-safety
infrastructure, not trust-specific, and squarely an F2 requirement
("correct... lock ordering under contention").

`tests/test_p17_key_acceptance.py` — **RETIRE**. 930 lines, the
`principal_key_accepted`/`principal_key_acceptance_revoked` payload
contracts and their write-time enforcement. Root/registrar-adjacent
key-acceptance machinery.

`tests/test_p17_replay_entity_kinds.py` — **RETIRE**. Replay's handling of
non-work-item entity groups (`project`, `principal`, `workflow`) inside a
v6 epoch's global hash chain — depends on the v6 chain/verifier entirely.

`tests/test_p17_system_actor.py` — **RETIRE**. `resolve_system_actor_id`
attributes system-authored events (escalation, claim expiry, hook
dead-lettering, recurrence firing) to the project's genesis-anchored
bootstrap principal — coupled to genesis/v6 epoch by construction (tests
literally assert "open_epoch resolves the genesis principal"). **Flag**:
the underlying need — system-authored events need *some* stable actor id —
will need a much simpler kernel-native answer (e.g. a fixed literal), since
the mechanism this file protects cannot survive without genesis.

`tests/test_p17_v6_verifier_boundary.py` — **RETIRE**. 2865 lines, the v6
verifier's full decision table (anchor resolution, acceptance/revocation
ordering, trust-log criteria 14/15, producer policy, delegation). Entirely
trust-domain verification.

`tests/test_p17_v6_writer.py` — **RETIRE**. 1478 lines, the v6 ordinary-event
writer's two admission gates (epoch admission, key binding, workflow
registration gate, producer authorization). Entirely genesis/trust-domain
dependent.

`tests/test_p17_witness_v6.py` — **RETIRE**. Witness countersignature
verification over v6 events. Witness/anchoring, explicitly removed.

`tests/test_p23_enrolment_inversion.py` — **RETIRE**. The principal-grammar
enrolment inversion (canonical ids enrollable, bare names refused) and the
cutover-gated append-actor-id-grammar flag. Root/registrar governance and
principal grammar, explicitly removed.

`tests/test_p23_estate_grammar_sweep.py` — **RETIRE**. Sweeps a **committed
snapshot of this private estate's own preflight output** for grammar
exceptions. This is an estate-catalog-adjacent conformance test over
real-world production data from this specific deployment, not a portable
product test at all — doubly out of scope.

`tests/test_p23_identity_consistency.py` — **RETIRE**. `principal_kind_conflict`
computation, `actor_id_kind`/`actor_kind`/`identity_consistency`
fields on verifier output. Trust-domain identity/verification.

`tests/test_p23_principal_alias_contract.py` — **RETIRE**. The
`regista.principal-alias/v1` payload contract (relation/scope kind enums,
mapping documents). Principal governance.

`tests/test_p23_principal_binding_isolation.py` — **RETIRE**. Proves alias
machinery cannot reach the binding-check import closure. Meaningless once
both the alias machinery and the binding-check trust plumbing it's isolated
from are gone.

`tests/test_p23_principal_grammar.py` — **RETIRE**. The canonical principal
grammar itself (kind sets, subject-length bounds, NFC, backend-name
derivation for Key Vault). Note: basic actor-id validation (length,
printability) is separately and adequately covered in `test_contract.py`
and `test_actor_id_and_token.py`, which are kept — this elaborate
scheme-and-kind grammar is not needed by "actor IDs are caller-supplied
attribution."

`tests/test_payload_encryption.py` — **RETIRE**. 708 lines, AES-256-GCM
field encryption/decryption. Field encryption, explicitly removed
("storage/database encryption becomes an explicit operator responsibility").

`tests/test_phase2.py` — **SPLIT**. `TestEscalation` (threshold/idempotent)
and `TestValidators` (custom validator success/failure-rollback/not-registered)
— PORT, kernel. `TestAsyncHooks` and `TestDeadLetterRequeue` — RETIRE
(hooks). `TestValidateActorMetadata` (null metadata, missing recommended
fields, invalid role source) — RETIRE, tied to the `ActorMetadata`
lint/assurance concept per `test_actor_metadata_contract.py` above.

`tests/test_phase3.py` — **SPLIT**. `TestActorRoles` (register/list/enforce),
`TestUpdateNotBefore` (deferral, matches `test_e2e.py`'s use), and
`TestCustomFieldValidationAtTransition` — PORT, all keep-table items.
`TestContinueOnRevokedReplay` (replay behaviour under key revocation, a
`continue_on_revoked` flag) — RETIRE, key-revocation-specific.

`tests/test_plan007_facade.py` — **SPLIT**, mostly PORT. Facade
property-caching and per-op-group (workflow/work-item/event/claim/link) plus
backward-compatibility assertions (`test_facade_equals_old_api`) — PORT,
useful API-stability regression. `test_hook_ops_cached` and
`test_recurrence_ops_cached` — RETIRE (2 of ~30 tests).

`tests/test_plan008_ws1.py` — **PORT**. Strict vs default actor-role
enforcement (reject unregistered actor in strict mode, reject a "prompt"
role source) across postgres and in-memory. Reads as workflow role-gating
strictness, in scope per "workflow role checks enforce application policy."
The "prompt role source" concept is not fully disambiguated from this file
alone; if it turns out to be assurance-only vocabulary, narrow this to the
unregistered-actor-strictness half only.

`tests/test_plan008_ws2.py` — **RETIRE**. `KeySet` env-var-vs-file
precedence and source logging. Key management.

`tests/test_plan008_ws3.py` — **PORT**. Vendored `rfc8785` vs the system
package, byte-for-byte, including error cases. Canonicalization, explicitly
permitted to remain.

`tests/test_plan008_ws5.py` — **RETIRE**. `KeySet` load baseline,
unknown-status handling, expected-count mismatch. Key management.

`tests/test_plan009.py` — **SPLIT**. `TestMaintenanceStartStop`,
`TestMaintenanceSweeps` (expired-claims sweep), `TestMaintenanceResilience`
(error doesn't kill the maintenance thread) — PORT, `**HIGH-VALUE PORT**`
for the claims sweep specifically (this is the maintenance-loop side of
lease expiry, the operational half of "durable leases... expiry"). `TestMaintenanceHookLeaseSweep`,
`TestMaintenanceRecurrenceFiring`, `TestMaintenanceWitnessReceiptSweep`,
`TestMaintenanceMetricsRefresh` — RETIRE (hooks, recurrence, witness).

`tests/test_plan010_integration.py` — **RETIRE**. In-memory counterpart of
action-delegation-credential tests (verified credential on append/transition,
malformed credential rejected). Action-delegation, explicitly removed.

`tests/test_plan010.py` — **RETIRE**. `validate_delegation_chain` and the
signing envelope's `on_behalf_of` field. Delegation + signing.

`tests/test_plan016.py` — **PORT**, `**HIGH-VALUE PORT**`.
`check_privileged_transition`: only a `system` actor kind may perform a
transition marked `privileged` in the workflow schema; agent/human actors
are rejected. A specific, named security-relevant transition-privilege
contract, tested across postgres and in-memory.

`tests/test_plan022_p3.py` — **RETIRE**. 741 lines, per-principal Ed25519
signing, independent verification via exported public keys, strict
asymmetric mode, key revocation, full signing lifecycle. Entirely signing.

`tests/test_plan022.py` — **SPLIT**. `TestV4EnvelopeConstruction`,
`TestClassifyEnvelopeVersion`, `TestSignAndVerifyV4`,
`TestBackwardCompatVerification`, `TestRegistryDrivenSchemeResolution`,
`TestHashAlgAgility` — RETIRE, all signing-envelope machinery. `TestEventDataclass`
(entity_kind/entity_id fields, `to_dict`/`from_dict` round trip),
`TestIntegrationEntityFields`, `TestInMemoryEntityFields` — PORT: these
assert the `Event` dataclass shape and that non-work-item entity columns
populate correctly and have a unique constraint, independent of signing —
kernel data-shape regressions.

`tests/test_plan023_review_validators.py` — **SPLIT**, heavily weighted
RETIRE. `TestDeriveAuthors`, `TestAdversarialReview`, and
`TestReviewerDelegationLineage` are ~90% lineage-independence/delegation-ack
logic — assurance/review-policy, explicitly removed. A small residual —
`test_review_note_required`/`test_review_note_missing_entirely`/
`test_finding_only_must_be_boolean` — reads as a generic "request_changes
needs a note" validator independent of lineage, but it is implemented in
the same `_review_validators.adversarial_review`/`human_gate` functions as
the lineage logic. See the `test_canonical_workflow.py` entry above for the
concrete coupling this creates. Recommend a human decide whether to extract
a lineage-free note-requirement validator or accept the canonical
workflow's `request_changes` review state changes shape too.

`tests/test_plan024_global_chain.py` — **RETIRE**. Concurrent-transitions
global-chain replay, verifier hash-walk (cycle/fork detection premised on
signed `prev_event_hash` linking), concurrent-genesis race. Same
signature/genesis coupling as `test_global_event_chain.py`/`test_hash_chain.py`.
The general "concurrent transitions replay clean" property is already
covered without hash-chain/genesis coupling in `test_bc310_replay_isolation.py`
and `test_migration_safety.py`, so no unique kernel coverage is lost by
retiring this file.

`tests/test_principal_keys.py` — **RETIRE**. `principal_keys` applier unit
tests (enrollment/rotation/revocation appliers, provenance columns,
fingerprint). Key lifecycle.

`tests/test_principal_lifecycle_contract.py` — **RETIRE**.
`EnrollmentRequest`/`ChallengeStorageScope`/`CustodyMode`, prepare-enrollment/
rotation/revocation, possession-proof challenge/response. Principal
lifecycle.

`tests/test_principal_lifecycle_durable.py` — **RETIRE**. 2207 lines, the
largest file in this half — durable principal-lifecycle operations,
approvals, cross-instance commit idempotency. Principal custody/lifecycle.

`tests/test_production_readiness.py` — **PORT**, `**HIGH-VALUE PORT**`,
naming trap in the other direction. Despite the name, this file is entirely
kernel: `TestActorKindValidation` (invalid actor_kind rejected across
create/append/transition/link/update_not_before), `TestTransitionEventIdCollision`
(idempotency), and `TestClaimStolenMetric` — the last is the
takeover/fencing semantics Plan 032 calls out explicitly ("a stolen claim
emits an event and a metric; the same actor re-acquiring does not count as
stolen").

`tests/test_property_conformance.py` — **PORT**, `**HIGH-VALUE PORT**`.
Hypothesis property-based equivalence tests over random operation sequences
for claims, transitions, escalation, and replay, plus adversarial
error-code equivalence. This is randomized fuzzing of the exact kept
contract and is rare, valuable coverage. **Caveat**: it appears to compare
behaviour across backends (uses both `InMemoryRegista`-style ops and a v6
keyset for postgres); if the in-memory backend retires per §7, this needs
retargeting to two PostgreSQL configurations or a single-backend property
suite rather than an equivalence one — but the properties themselves should
survive.

`tests/test_provision.py` — **SPLIT**. `TestProvision` (schema/role
creation, idempotent, multiple projects, dry run, cross-schema access
denied) — PORT, directly "PostgreSQL namespace... explicit configuration."
`TestProvisionPrincipal` (principal provisioning refused post-cutover) and
`TestSecretRefInKeySet` — RETIRE, principal/key trust.

`tests/test_public_trust_log_verification.py` — **RETIRE**. Public
`verify_trust_log` API, fails closed without a pinned genesis. Trust-log
verification.

`tests/test_public_v6_testing_in_memory.py` — **RETIRE**. Smoke test that
the installed `regista.testing` v6-epoch fixture helper opens correctly
in-memory. The fixture it tests exists only to set up v6 epochs for other
trust tests.

`tests/test_public_v6_testing_postgres.py` — **RETIRE**. Same as above,
postgres variant.

## HIGH-VALUE PORT list

- `tests/test_api_surface.py` — public API has no signature params
- `tests/test_bc188_connect_search_path.py` — schema-scoped DROP (cross-tenant safety)
- `tests/test_bc278_279_280.py` (BC279 half) — replay warns on unknown transitions
- `tests/test_bc310_replay_isolation.py` — REPEATABLE READ isolation for replay
- `tests/test_bc184_bc185_metrics.py` (BC185 half) — claims-swept maintenance counter
- `tests/test_claim_link_idempotency.py` — claim/link idempotency dedup
- `tests/test_concurrency.py` — gap-free seq allocation under contention
- `tests/test_contract.py` — the kernel's own validation-layer unit tests
- `tests/test_coverage_gaps.py` (`TestExpectedAttemptNumber`) — stale-attempt/fencing refusal
- `tests/test_e2e.py` — full pipeline, deferral/reclaim, linked items, role enforcement
- `tests/test_heartbeat_coalesce.py` — heartbeat event-storm coalescing
- `tests/test_hook_miss_recovery.py` — event cursor/pagination (naming trap)
- `tests/test_idempotency.py` — idempotency mismatch + optimistic seq check
- `tests/test_in_memory_conformance.py` — the broad functional conformance suite
- `tests/test_jcs.py` — canonicalization boundary conditions
- `tests/test_link_errors.py` — typed-link error paths
- `tests/test_migration_safety.py` — advisory-lock concurrency, checksum drift
- `tests/test_plan009.py` (claims-sweep half) — maintenance-loop lease expiry
- `tests/test_plan016.py` — privileged-transition actor-kind enforcement
- `tests/test_production_readiness.py` — claim-stolen/takeover metric (naming trap)
- `tests/test_property_conformance.py` — property-based fuzzing of the kept contract

## Environment-pinned findings

- **`tests/reducer_v1_vectors.py` line ~295** carries the literal vector that
  produced the documented `datetime.fromisoformat` cross-interpreter
  divergence (dependency map §2): CPython 3.14 parses
  `"2026-08-09T24:00:00Z"` as the next midnight; 3.12, 3.13, and PyPy 3.11
  raise. The file retires with the reducer, but **any kept kernel code that
  parses caller-supplied timestamps across the declared support matrix
  inherits this exact hazard** — worth a dedicated regression once F0 item 5
  fixes the Python range, wherever timestamp parsing lands in the new
  kernel.
- Scanned this half for hardcoded absolute dates and interpreter-version
  branches otherwise: all other hardcoded-date literals found (`test_bc214_*`,
  `test_bc215_*`, `test_bundle_v3.py`, `test_p17_key_acceptance.py`,
  `test_p17_v6_verifier_boundary.py`, `test_p23_*`, `test_plan010.py`,
  `test_plan022_p3.py`) are internally-consistent fixture literals (e.g. a
  hardcoded `revoked_at` compared against a hardcoded `event_timestamp`
  passed explicitly in the same test) rather than comparisons against
  `datetime.now()`/wall clock — not latent CI time bombs, and in any case
  all in files classified RETIRE. **None of the files landing in PORT or the
  PORT portion of a SPLIT in this half use a hardcoded absolute date or a
  `sys.version_info`-style branch.** `test_bc215_219_220_221.py`'s kept
  `TestBC220ClientTimestamp` correctly uses dynamic `datetime.now(UTC)`
  bounds rather than a fixed literal.

## Surprises, and where the dependency map's §4 looks right or wrong

- **§4's 68% ceiling holds, and the true number is well under it in this
  half.** Full-file RETIRE here is 48/91 (52.7%); PORT is 23/91 (25.3%);
  SPLIT (partial retirement) is 19/91 (20.9%). Even treating every SPLIT
  file as "mostly retiring" doesn't approach 68%, which matches the
  dependency map's own caution that the naming-based ceiling is
  deliberately over-broad.
- **The naming trap cuts both ways, and the reverse direction was the
  bigger surprise.** `test_hook_miss_recovery.py` and
  `test_production_readiness.py` are fully kernel despite trust/removed-
  feature-sounding names (a generic event-cursor test filed under "hook
  miss recovery"; claim-takeover/fencing semantics filed under "production
  readiness"). These are exactly the two files a naming sweep would
  misfile, and they protect two of the plan's explicitly named public
  contracts (event history query, claim fencing).
- **§7's in-memory-backend reasoning is corroborated, not contradicted, by
  this half** — but with a sharper cost than "retire it." `test_in_memory_conformance.py`
  is the single largest block of *portable* kernel
  regression coverage found in this half (654 lines exercising nearly every
  keep-table item), and it runs entirely against the backend §7 recommends
  retiring. Retiring the backend without retargeting this file's assertions
  to PostgreSQL fixtures would be a silent, large coverage loss — the
  dependency map's own "disposable PostgreSQL fixtures" fallback needs to
  explicitly inherit this file's test bodies, not just its recommendation.
- **A live, self-resolving piece of process debt was found**: the
  `_epoch_blocked`/`test_epoch_blocked_meta.py` xfail-manifest machinery is
  already at zero entries and "blocker: none" — it finished its job before
  this pass started, and its subject (the v6 writer cutover) is exactly
  what Plan 032 deletes. It costs nothing to retire and nothing survives it
  functionally.
- **One real cross-file coupling risk**: `test_canonical_workflow.py` (PORT,
  and load-bearing for dossier/agent-notes' shared workflow) calls into
  `_review_validators`, the same module that is ~90% RETIRE material per
  `test_plan023_review_validators.py`. Deleting that module wholesale
  without first extracting a lineage-free "request_changes needs a note"
  validator will break a test this pass just called high-value PORT. This
  needs an explicit decision in F1, not a side effect of the assurance
  deletion.
- **`test_migrations_021_026.py`** is the clearest case where "port vs
  retire" doesn't cleanly apply per-file: three of its ten test classes
  assert kernel-relevant table shapes (archive parity, claims index) but
  every test is anchored to a specific migration number in the chain F1
  discards outright. Recommend treating this as "port the assertions,
  retire the file" rather than a straight SPLIT.
