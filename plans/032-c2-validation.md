# Stage C2 — connection admission and full requalification

Authorized scope: isolated worktree `/projects/.worktrees/regista-f1b`, branch
`feat/wi364-f1-promote`, starting at `12bb696`. Actor: GPT-6.1 Sol via Codex.
Risk: persistent-store admission semantics. Working set: kernel, admission tests,
mutation/benchmark scripts, operations/specification, and Plan 032 evidence.
Tracker writes are not authorized; no tracker claim or private provenance is
asserted. Only this branch may be pushed. No tags, uploads, dispatches or settings
changes are authorized.

Design: namespace verification runs per operation; a weak set remembers successful
baseline admission per physical connection. First-operation validation runs outside
the pool health callback so schema refusals surface as `UnsupportedSchemaError`.
Empty destinations remain unvalidated. Initialization validates before commit and
clears prior admission before revalidation. Each write retains namespace/version
checks. Trusted administrator DDL while a connection is admitted can remain unseen
until a new physical connection; operations and the normative trust boundary state
this limitation, and a regression asserts successful live writes followed by
refusal after recycling, with no extra rows written by the refused connection.

Proof: new tests control physical identity for growth/replacement and pre-bootstrap
connections. Existing counterfeit/partial/extra/index vectors are tested before
writes on recycled connections and in both opener modes. Four initial C2 mutants cover
skipped admission, caching an empty destination, omitted existing initialization
validation, and omitted fresh initialization validation. The B2 late-legacy mutant
now removes physical admission, matching the new location of the protection.

Initial test failures exposed an invalid fixture assumption: asynchronous resets
can grow a pool during sequential setup, leaving another admitted connection after
closing only one. Tests now prepare with maximum one before controlled growth and
recycle every existing connection. These failures are not qualification evidence.
Updated focused tests passed: 71 passed in 25.29s. An independent read-only agent
review found no correctness blockers; its focused selection passed 54 tests,
130 deselected in 15.03s. This is same-model agent review, not external cross-lineage
acceptance. Full acceptance records are appended below after final qualification.


The initial full suites passed 1001 tests and 67 subtests each, but independent
follow-up review found an uncovered refusal-type regression: an ordinary write to
a precreated empty schema had become `DatabaseOperationError` from UndefinedTable,
where C1 returned `UnsupportedSchemaError`. A failing-first test confirmed it.
The cheap marker query now translates UndefinedTable to the original refusal type,
without adding queries on the successful path. A fifth C2 mutant protects this
translation. The superseded F1 proof was stopped; that interrupted run is not
passing mutation evidence. Every gate was rerun after this final runtime edit.


The preservation fix independently passed all nine C2 tests in 3.07s. The reviewer
found no blockers in its query cost, refusal translation, zero-change assertion,
subsequent pool reuse, or the fifth mutation hook. Final candidate:
`47591367476b6ec036ef439b9f4499e966eac9ff`.


## Final qualification

All final gate commands exited 0 after the last runtime edit. Pristine authoritative
validation passed and every tamper vector refused as required. All 14 original
reviewer probes and four supplemental arms are recorded. Raw typed refusals remain
visible; they are expected regression outcomes, not blanket script-exit successes.
Both artifacts passed installed examples, process restart and separate-database
restore followed by another valid write; the independent clone rebuilt identical
bytes.

```text
ruff: All checks passed!
mypy: Success: no issues found in 5 source files
suite-314: 1002 passed, 67 subtests passed in 438.38s (0:07:18)
suite-311: 1002 passed, 67 subtests passed in 438.55s (0:07:18)
prove-f1: 164 mutants killed; 516 distinct test nodes proved
prove-b2: 11 mutants killed; no survivors
prove-c1-artifacts: 9 artifact/workflow mutants killed
readme: 1 passed in 0.89s
verify-baseline: verify-baseline: ok
verify-ledger: verify-ledger: ok
check-tree: check-tree: ok
references: API and CLI references are current.
smoke: Installed wheel smoke passed (clean venv, checkout absent from import path).
pristine authoritative: check-dist: ok
tamper vectors: 16/16 refused, exit 2
reviewer originals: 14/14 executed; raw exits and four supplemental arms recorded
F3: wheel and sdist passed installed examples, restart, separate restore and another valid write
independent build: wheel and sdist byte-identical
```

Exact commands and output: [gate record](032-c2-final-gates.json),
[164-mutant selections/results](032-c2-f1-mutations.json),
[reviewer originals/arms](032-c2-reviewer-probes.json),
[authoritative vectors](032-c2-authoritative-vectors.json),
[supplemental controls](032-c2-supplemental-probes.json), and
[benchmark samples](032-c2-baseline-benchmark.json).

The five C2 mutants were each killed by test-body failures:

```text
KILLED c2_connection_admission: 4 assertions
KILLED c2_empty_connection_cached: 1 assertions
KILLED c2_initialize_validation: 1 assertions
KILLED c2_fresh_initialize_validation: 1 assertions
KILLED c2_empty_write_refusal: 1 assertions
```

Risk and scope remain as declared above. Tracker writes/claims and private provenance
attachments were not authorized and are not asserted. Independent agent source
review passed, including the final refusal fix; external cross-lineage release
acceptance and the existing F5 owner prerequisites remain owner work. This change
makes no publication or settings claim.

Final same-model read-only evidence review found no blockers: all 26 gate entries,
164 mutation selections, reviewer source hashes, archive vector outcomes, raw
artifact byte identity, F3 scenarios and benchmark medians match the report.
