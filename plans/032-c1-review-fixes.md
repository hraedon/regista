# Stage C1 — Daybreak Blue remediation and qualification

Started 2026-10-05 at d631054 on isolated worktree
`/projects/.worktrees/regista-f1b`, branch `feat/wi364-f1-promote`.
Risk: high (namespace isolation, persistent integrity, release supply chain).
Actor: gpt-6.1-sol via Codex CLI. Scope: `src/regista/`, `tests/`, `scripts/`,
`.github/workflows/`, README, CHANGELOG, current docs, and Plan 032 evidence.
Acceptance: failing-first regressions for every finding, mutation proof for
security/integrity/concurrency, reviewer scripts, complete after-last-edit gates,
fresh wheel/sdist F3 qualification and independent-clone byte comparison.
No tags, uploads, dispatches or settings changes. Only the stated branch may be
pushed. Tracker writes are outside the user-authorized scope; no tracker claim or
private provenance attachment is asserted. Independent acceptance remains open
until a read-only review of the final change and evidence.

Evidence is being collected under `/tmp/regista-c1-evidence`; the final sanitized
record will be committed here. No completion is claimed by this scope declaration.

## Fixed candidate and evidence contracts

Historical C1 artifact candidate: `8ff80ade3972311c6e6568f3afae415761a9a9ca`.
Stage C2 supersedes it with `47591367476b6ec036ef439b9f4499e966eac9ff`; current
artifact hashes and qualification are in F3/F5 and the C2 report. The following matrix maps each review ID to
its fix and executable proof; the generated [gate record](032-c1-final-gates.json)
and [reviewer record](032-c1-reviewer-probes.json) supply exact results. Failing-first
logs are preserved in [regression evidence](032-c1-failing-first.json). A passing
control plus killed test-body mutants is required before mutation success is claimed.

| Finding | Change and regression test | Mutation and reviewer evidence |
| --- | --- | --- |
| SEC-H1 | Refuse `$user`, all `pg_*` and information_schema. Each operation resolves the configured literal path before relation SQL; temporary shadowing refuses. Catalog helpers are qualified. `test_special_namespace_refused`, `test_namespace_resolution_verified`, `test_namespace_tampering_refuses_operation`. | `c1_special_names`, `c1_namespace_resolution`, `c1_catalog_helper`; db1 search_path probe plus its independently rerun pg_temp arm and sibling-preservation control. |
| SEC-H2 | `initialize()` has no caller SQL parameter. Packaged SQL is pinned; tests use only a private loader seam. `test_initializer_has_no_sql_path`. | `c1_initializer_public_sql`; db1 security probe refuses the old positional initializer with TypeError; supplemental arm catches that refusal and confirms sibling sentinel preservation. |
| SEC-M1 / CONC-M3 | Named server-side cursor, batch 64, reconstructs the immutable prefix. Bounded memory, O(prefix) retry time; avoids adding snapshot columns/schema changes. `test_retry_memory_is_bounded` asserts peak below 2 MB. | `c1_retry_materializes`; both reviewers' original memory scripts measure retry peaks against 201×64 KiB and 3,001×8 KiB histories. |
| SEC-M2 | Central human renderer escapes C0/C1, DEL, ESC, bidi and line controls for all formatted stored/caller strings. JSON unchanged. `test_cli_human_controls_escaped` exercises history/show/list/lease/health; `test_cli_logging_controls_escaped` covers pool diagnostics. | `c1_human_controls`, `c1_log_binding`; db1 terminal probe must report no raw ESC/forged newline. |
| SEC-L1 / DOC-M2 | Argparse UUID types and parser errors plus field/JSON limit errors share refusal exit 2, JSON stdout error and human stderr. `test_cli_malformed_refusal`, `test_cli_uuid_arguments_are_typed`, `test_preliminary_cli_parser_refusal`. | `c1_uuid_type`, `c1_field_envelope`, `c1_json_envelope`, `c1_preliminary_parser`; supplemental db1 security CLI arms and exact stdout/stderr tests. |
| RSC-1 | One ordinary gzip member; exact canonical USTAR envelope, padding and termination; correct metadata root/name/version; byte-identical PKG-INFO and wheel METADATA. Trailer and all mutable metadata field tests in `test_distribution_vectors.py`. | C1 gzip/metadata/root artifact mutants; exact reviewer's gzip+dd append, raw trailer, metadata and root authoritative vectors must refuse. |
| RSC-2 | Every setup-uv pins 0.12.23/x86_64/official SHA-256; twine 7.0.0. `test_actions_and_uv_are_pinned`. | C1 uv_latest/uv_checksum mutants; official release .sha256 curl output recorded, no value guessed. |
| RSC-3 | Publish verification runs fail-closed identifier scan and fetched origin/main ancestry check before install/build. F5 lists allowed tag principals and external approval controls. `test_publish_requires_identifier_and_merged_commit`. | C1 publish_identifier/publish_main mutants; workflow-source regression (original finding inferred). No tag/dispatch or external-control certification. |
| RSC-4 | CI token contents:read; every workflow uses official-tag-resolved full action SHA. `test_actions_and_uv_are_pinned`. | C1 ci_permissions/ci_action_sha mutants; official git ls-remote outputs recorded (original finding inferred). |
| DOC-H1 | Committed complete portable catalog manifest checks relations, columns/types/defaults, constraints/indexes, namespace objects, FK trigger enforcement and inheritance. Fresh comparison on every write and baseline-1 open/init. Unknown version diagnostic reads remain available (A5). `test_baseline_manifest_refuses_before_write`, `test_baseline_enforcement_and_inheritance`, `test_malformed_marker_is_unsupported`. | `c1_baseline_admission`, `c1_fk_trigger_enforcement`, `c1_inheritance` and B2 occupancy/late-legacy mutants; counterfeit/partial/extra/index reviewer vectors refuse without writes. |
| DOC-H2 | Absent namespace is created transactionally after name/occupancy checks. Database CREATE is needed only when absent; precreated owned schema works without it. `test_readme_quickstart` uses absent_schema and exact README bytes; `test_initialize_precreated_owner_without_database_create`. | Namespace/baseline controls; original fresh-namespace quickstart now completes to `done`. |
| DOC-M1 | Release deletes only live matching actor/attempt; expiry remains fenced until takeover/sweep. `test_release_expired_preserves_fence`. | `c1_expired_release`; db4 repro_m1 retains expired claim and refuses the previously successful unfenced transition. |
| DOC-M3 / CONC-M2 | Absent unlink succeeds, including retries/concurrent duplicates. CLI reports ensured absence. blocked() checks only immediate counterpart and includes downstream items with an unsatisfied immediate blocker. `test_unlink_retry_and_concurrent_noop`, CLI/query tests, `test_c1_blocked_explanation`. | `c1_unlink_retry` and inverted old absent-link mutant; db2 unlink probe and db4 repro_m3 return retry success while preserving the documented blocked chain. |
| DOC-M4 | AST-generated old→new root exports and full command paths from 84bb2ec, with intentional/internal incidental imports separate. Committed JSON and complete tables. `test_mechanical_removal_inventory_is_current`, `test_c1_inventory_and_historical_checklist`. | Documentation-only mechanical check; includes every specifically reported missing public name/path. |
| DOC-L1 | Old publication-review checklist explicitly historical and removed from current-doc index. `test_c1_inventory_and_historical_checklist`. | Documentation-only index assertion. |
| CONC-M1 | Replay checks named transition source/destination against pinned workflow; per-event digest binds transition+payload without schema.sql changes. Rehashing does not hide semantic impossibility. `test_replay_pinned_transition_semantics`, `test_replay_pinned_destination`. | `c1_transition_digest`, `c1_transition_source`, `c1_transition_destination`; db2 replay semantics probe reports hash/source drift after start→edit relabel. |
| CONC-L1 | release locks the item first, same order as transition/claim/heartbeat, and drains admitted fenced writers. `test_release_drains_transition`. | `c1_release_lock`; original db2 race controller times out its paused writer instead of observing a post-release commit; threaded supplemental controller demonstrates writer commit before release returns. |

## Cost, schema pin and independent review

Stage C2 supersedes the C1 per-write design: full catalog validation now runs at
`connect()` in both modes, at `initialize()`, and before the first operation on
each new physical pooled connection. Successfully validated connections are held
in a weak set; empty destinations are never marked validated. Namespace safety
remains per operation and writes still check the version marker. Trusted
administrator DDL on live connections is outside the boundary and is detected on
the next new connection; restart/pool recycling revalidates.

C1's seven alternating batches measured create median **16.437 ms**, versus
**5.536 ms** with the manifest disabled. C2 repeats seven alternating batches of
50 writes: create median **5.803 ms**, with the historical per-write guard restored
as a same-run control at **16.841 ms**. The fingerprint alone measured **4.409 ms**.
This removes about **10.634 ms (64.7%)** versus C1's measured median and comes close to
the pre-C1 target. Network/database load changes these numbers. The historical
[benchmark evidence](032-c1-baseline-benchmark.json) and new
[C2 samples and method](032-c2-baseline-benchmark.json) retain every sample.
`schema.sql` and its version-1 pin remain unchanged. The transition+payload digest
changes the unpublished experimental data contract, which is documented explicitly;
pre-C1 stores must be recreated. No in-place upgrade was introduced.

A fresh read-only security-review agent investigated namespace/bootstrap/catalog,
retry/replay/CLI and archive/workflow boundaries. It found missing internal FK
trigger enforcement and inheritance coverage, unqualified catalog JSON helpers,
and an early CLI parser outside the refusal envelope. Each was reproduced
failing-first and corrected before the candidate commit. This is an independent
agent review using the same model, not claimed external cross-lineage acceptance.

## Qualification scope and remaining owner work

The final gates include both full interpreter suites, all F1/B2/artifact mutations,
installed examples, verbatim absent-namespace quickstart, both artifacts' F3
restart/separate-restore+valid-write scenarios, clean wheel smoke, baseline and
artifact guards, official tool provenance and every supplied reviewer script.
Some reviewer fixtures install foreign triggers; complete baseline admission
intentionally refuses them. Their raw failures are recorded, and a clean-admission
SQL fault probe retains rollback coverage rather than weakening admission.

No publication or external settings action is performed. Live tag principals,
protected-main rules, pypi environment reviewers/bypass, PyPI registration and D8's
unfamiliar-human walkthrough remain the owner prerequisites in F5. Historical CI
results do not qualify C1; current 3.12/3.13 CI results require owner confirmation.


## Qualification failures corrected

The first C1 pass completed both artifacts' F3 scenarios, but Twine 6.2.0 rejected
Hatchling's Metadata-Version 2.5. The official PyPI release metadata identified
Twine 7.0.0; the pinned 7.0.0 checker accepted both artifacts. The initial B2 hidden
legacy mutant left the no-USAGE branch protected by the newly added literal
namespace gate. Its selection now targets the USAGE-enabled branch, where deleting
the occupancy check is the actual defect. All 11 B2 mutants were then killed.
The in-progress first suites/control were interrupted to avoid qualifying mixed
inputs. They are not passing gate evidence. The final gate record reruns everything
against the corrected candidate after the last manual edit.

Tool provenance is recorded in [official tool evidence](032-c1-tool-provenance.json):
Astral's release [platform checksum](https://github.com/astral-sh/uv/releases/download/0.12.23/uv-x86_64-unknown-linux-gnu.tar.gz.sha256),
GitHub action tag refs resolved with git ls-remote, and official
[Twine release metadata](https://pypi.org/pypi/twine/7.0.0/json).


The next F1 control passed 971 tests (20 deselected), but the old schema-resource
mutant was refused by the new packaged SQL pin during setup. It was not counted
as killed. That mutant now removes the unique constraint after clean admission
of the first event, preserving both source SQL pins and admission rules while
exercising the direct duplicate-insert test in its body. No baseline pin was
rewritten. Closed-cursor rowcount was also an invalid unlink mutant premise;
refusal is now inserted while the cursor is open. CLI no-op unlink and health's
numeric-only output are positive controls, so they are excluded from unrelated
refusal/escaping mutant selections. The retry mutant restores the actual original
fetchall behavior; an ordinary cursor alone can allocate libpq memory outside
Python tracemalloc. Python 3.14 parses deep JSON iteratively and then hits the
kernel depth limit; the parser RecursionError seam separately pins the 3.11
refusal contract. These harness corrections do not change runtime behavior.
All eight corrected development selections were killed before final qualification.
The final proof includes 159 mutants and the full suites include the additional
parser-limit regression; exact final counts are in the generated gate record.

The separate [catalog-helper negative control](032-c1-helper-mutation.json) and
[historical-checklist failing-first control](032-c1-historical-regression.json)
retain their outputs. [Authoritative archive vectors](032-c1-authoritative-vectors.json)
retain the exact gzip/dd reproduction and every current metadata field/body/root
refusal. A harness glob initially included uv's hidden dist/.gitignore in Twine's
inputs; the corrected command uses only wheel and sdist files. Each authoritative
invocation uses a fresh empty HOME; reusing a populated build HOME is refused and
was discarded as invalid artifact evidence. The final records use corrected inputs.


A final completeness check found that psycopg pool diagnostics used their own
stderr logger, bypassing the CLI print renderer. A failing-first connection-log
regression reproduced raw newline/ESC/C1/bidi output while preserving the JSON
error object. CLI main now installs a filter on the pool logger which uses the
same escape function for message and exception text. Its 159-test CLI/kernel
selection passed; removing the renderer or logger binding killed the new test.
The candidate was rebuilt and both artifacts were again reproduced byte-identically
in the independent clone. Final qualification and every reviewer probe were repeated
for this changed CLI. This supersedes the interrupted 158-mutant attempt; no
interrupted or setup-error run is counted as passing final proof.


## Generated final results

All final gates passed for `8ff80ade3972311c6e6568f3afae415761a9a9ca`. Full suites: **993 passed, 67 subtests passed** on each of Python 3.14 and 3.11. F1: **159 mutants killed; 508 distinct test nodes proved**. B2: **11 killed**. Artifact/workflow: **9 killed**. Both wheel and sdist completed fresh installed examples, restart and separate-database restore followed by a valid write. All 14 original reviewer scripts and five supplemental arms are recorded; expected refusals are successful regression outcomes even when their scripts exit nonzero.

| Finding ID | Test result | Mutation result (all listed killed) | Reviewer-probe result after fix |
| --- | --- | --- | --- |
| SEC-H1 | Special names and tampered paths refused; sibling sentinel unchanged. | c1_special_names, c1_namespace_resolution, c1_catalog_helper | Original $user/pg_temp arms refused InvalidFieldError; supplemental catalog contains only sentinel. |
| SEC-H2 | Public initializer signature has only self; pinned resource test passed. | c1_initializer_public_sql | Original custom-SQL call raises TypeError; remaining arm confirms sibling table survives. |
| SEC-M1 / CONC-M3 | 600-event memory regression passed below 2 MB. | c1_retry_materializes | 3,001-event retry/replay peaks about 1.20/1.21 MB, ratio 1.0; 201×64 KiB peak 8.58 MB bounded by batch size. |
| SEC-M2 | All stored/caller human values and pool diagnostics tests passed; JSON stdout unchanged. | c1_human_controls, c1_log_binding | Original terminal probe: raw newline spoof False, raw ESC False. |
| SEC-L1 / DOC-M2 | All four malformed inputs: exit 2, exact JSON/stdout/stderr contracts, no traceback; 3.11 parser-limit seam passed. | c1_field_envelope, c1_json_envelope, c1_uuid_type, c1_preliminary_parser | Original remaining CLI arms: huge number and bad UUID exit 2, traceback False. |
| RSC-1 | Envelope, root and mutable metadata regressions passed. | gzip_tar_envelope, sdist_metadata_binding, sdist_root_binding (artifact proof) | Pristine authoritative check 0; 16 tamper variants exit 2, including exact gzip -n + dd append. |
| RSC-2 | Every uv version/platform checksum and Twine 7.0.0 pin test passed. | publish_uv_latest, publish_uv_checksum (artifact proof) | Official release checksum curl retained; both pinned Twine checks PASSED. Original finding inferred. |
| RSC-3 | Identifier/main ancestry source regression passed; owner principals explicit. | publish_identifier_gate, publish_main_ancestry (artifact proof) | Repository-source checks passed. No tag/dispatch/external-control assertion; original finding inferred. |
| RSC-4 | Every full action SHA and contents:read source regression passed. | ci_permissions, ci_mutable_action (artifact proof) | Official tag resolutions retained. Original finding inferred. |
| DOC-H1 | Counterfeit/partial/extra/missing-index and further catalog damage all refused before writes; A5 tests passed. | c1_baseline_admission, c1_fk_trigger_enforcement, c1_inheritance; B2 occupancy/legacy | Foreign trigger fixture probes explicitly refused UnsupportedSchemaError; actual post-admission rollback and timeout/pool reuse passed. |
| DOC-H2 | Verbatim README on catalog-proven absent namespace completes done; owned precreated/no CREATE privilege test passed. | initializer_missing, initializer_missing_catalog; baseline/name controls also killed. | Quickstart gate: 1 passed; both freshly installed artifacts run initialization and valid writes. |
| DOC-M1 | Expired release preserves claim/fence test passed. | c1_expired_release | Original repro retains live=False claim; unfenced write raises LeaseExpiredError. |
| DOC-M3 / CONC-M2 | Concurrent/retried absent unlink tests and immediate-counterpart docs passed. | c1_unlink_retry, absent_link_removal_refuses | Original unlink retry succeeds; original chain remains b/open and c/open. |
| DOC-M4 | Mechanical inventory, all named omissions and regeneration check passed. | Documentation-only; no security/integrity mutation required. | AST inventory generated from exact 84bb2ec root exports and full command tree; checked current. |
| DOC-L1 | Historical/index regression failed before and passed after; full documentation suite passed. | Documentation-only; no security/integrity mutation required. | Historical checklist no longer listed as current authority. |
| CONC-M1 | Pinned source/destination plus transition-bound digest regressions passed. | c1_transition_digest, c1_transition_source, c1_transition_destination | Original start→edit relabel reports payload hash and forbidden pinned-source drift. |
| CONC-L1 | Item-first release barrier regression passed. | c1_release_lock | Original synchronous controller cannot get a late commit; adapted controller waits, writer commits doing, then release returns. |

The artifact candidate and hashes are the current F3/F5 values. `schema.sql` remains unchanged; no repin occurred. The complete [exact gate output](032-c1-final-gates.json), [F1 proof map](032-c1-f1-mutations.json), [reviewer outputs](032-c1-reviewer-probes.json) and [archive refusals](032-c1-authoritative-vectors.json) are committed evidence. No source/package changes followed these gates. Later evidence-only commits do not affect either artifact hash. External owner prerequisites and the measured per-write catalog cost remain as described above; no tags, artifact uploads, dispatches or settings changes were performed.
