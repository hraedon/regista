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
acceptance. Full acceptance records will be appended after final qualification.


The initial full suites passed 1001 tests and 67 subtests each, but independent
follow-up review found an uncovered refusal-type regression: an ordinary write to
a precreated empty schema had become `DatabaseOperationError` from UndefinedTable,
where C1 returned `UnsupportedSchemaError`. A failing-first test confirmed it.
The cheap marker query now translates UndefinedTable to the original refusal type,
without adding queries on the successful path. A fifth C2 mutant protects this
translation. The superseded F1 proof was stopped; that interrupted run is not
passing mutation evidence. Every gate is being rerun after this final runtime edit.
