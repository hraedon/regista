# Plan 032 C3 — portable baseline admission

The C1/C2 CI failures were caused by default-locale ordering in the catalog
manifest. Local PostgreSQL 15-alpine uses musl ordering even though its locale
name is en_US.utf8; Debian PostgreSQL sorts object names differently.

All eight text sort keys across six catalog aggregate orderings now explicitly
use `COLLATE "C"`. Numeric/OID equality and ordering remain locale-independent;
there are no textual inequalities or locale-formatted data in this query. SQL
deparsers describe built-in types/definitions and retain column collation names.
The manifest and fingerprint share the same query. No other catalog-derived list
is hashed. The complete record and fingerprint match the committed baseline on
Debian PostgreSQL 15, Alpine PostgreSQL 15, and Debian PostgreSQL 16 and 17.
The manifest, fingerprint and schema SQL therefore require no regeneration or
pin change: fingerprint remains
`af7d58303e81cc2c57d3c84d10ffacdbf72894a14dd6144c7ed8e3384bf367f9`.

Regression tests explicitly compare the fresh baseline record and fingerprint
with the installed committed resource. Separate template0 databases exercise
libc en_US UTF-8 and ICU und with shifted punctuation; the test first proves
their default ordering differs from C for the baseline names. Only absent
locale/provider support skips. Alpine lacks libc en_US in pg_collation, but its
ICU arm executes. Permission/creation/admission failures never skip.

CI now runs Python 3.11–3.14 on official Debian postgres:15, and Python 3.14 on
postgres:16 and postgres:17, retaining fail-hard DSN admission and full action
SHA pins. README, spec and operations identify the three tested versions.

Risk: baseline admission affects persistent schemas and fresh installs. Work is
isolated in `/projects/.worktrees/regista-f1b` on `feat/wi364-f1-promote`. Working
set: kernel catalog query, C3 regression tests, CI admission test and CI matrix,
mutation proof declaration, version guidance and Plan 032 qualification evidence.
Tracker writes/claims and private provenance attachments are not authorized;
none are asserted. This note records intent/evidence in the authorized repository.
Independent source review and the complete C2 gate set plus multi-server suites
and final-commit GitHub CI are required before reporting C3 complete.

Detailed server comparisons: [server record](032-c3-server-baselines.json).
Local qualification passed as recorded below. Final-commit GitHub CI remains a
required external gate, reported with its exact URL/jobs after the branch push.

## C3 qualification evidence

Artifact candidate: `27ebc8e1fcc603709b821d6d038720dbd4eb2966`.
Evidence-only changes to Plan 032 and CHANGELOG are excluded from the
distributions. The qualified and independently
rebuilt hashes are:

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `224c1d11498016de71c881c71ab86593a128521de9134feda8d492fb753465d8` |
| `regista_hraedon-0.8.0.tar.gz` | `93bf2a62f47a92359c82a64f0cca18d73abf9bd6d00973371dab43b92862df2f` |

```text
ruff: All checks passed!
mypy: Success: no issues found in 5 source files
suite-314-pg15: 1005 passed, 67 subtests passed in 391.42s (0:06:31)
suite-311-pg15: 1005 passed, 67 subtests passed in 391.58s (0:06:31)
suite-314-alpine: 1004 passed, 1 skipped, 67 subtests passed in 451.02s (0:07:31)
suite-314-pg16: 1005 passed, 67 subtests passed in 361.61s (0:06:01)
suite-314-pg17: 1005 passed, 67 subtests passed in 329.95s (0:05:29)
prove-f1: 165 mutants killed; 518 distinct test nodes proved
prove-b2: 11 mutants killed; no survivors
prove-c1-artifacts: 9 artifact/workflow mutants killed
readme: 1 passed in 0.83s
verify-baseline: verify-baseline: ok
verify-ledger: verify-ledger: ok
check-tree: check-tree: ok
references: API and CLI references are current.
smoke: Installed wheel smoke passed (clean venv, checkout absent from import path).
missing-dsn: expected exit 4; REGISTA_TEST_DSN is required
all-eight-clause mutant: 3 test-body failures, 0 errors, 0 skips
pristine authoritative: check-dist: ok
tamper vectors: 16/16 refused, exit 2
reviewer originals: 14/14 executed; original hashes and raw exit classifications match C2; four supplemental arms recorded
F3: wheel and sdist passed installed examples, restart, separate restore and another valid write on Debian PostgreSQL 15
independent build: wheel and sdist byte-identical
```

The source review found no blocking issue. CHANGELOG now records the matrix and
C ordering. The reviewer was a separate read-only actor who declared GPT-6
lineage; this is not claimed as a cross-lineage review. Current AGENTS.md adds
no cross-lineage acceptance gate; F5 owner acceptance remains separate. No
tracker mutation/claim or private provenance attachment is asserted.

Exact evidence: [gate commands/output](032-c3-final-gates.json),
[165 F1 mutants](032-c3-f1-mutations.json),
[all-eight-clause mutation](032-c3-collation-mutation.json),
[artifact/workflow mutants](032-c3-artifact-mutations.json),
[14 reviewer originals and four arms](032-c3-reviewer-probes.json),
[authoritative pristine/tamper](032-c3-authoritative-vectors.json),
[supplemental controls](032-c3-supplemental-probes.json),
and [independent source review](032-c3-source-review.json).

The only authorized remote write is pushing `feat/wi364-f1-promote`. No tags,
uploads, dispatches or settings changes are authorized or performed. C3 must not
be called complete on local results alone; the final commit's CI run is awaited
and every job's result reported separately before completion.
