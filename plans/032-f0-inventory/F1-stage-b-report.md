# Plan 032 F1 Stage B — promotion and removal

Working tree: `/projects/.worktrees/regista-f1b`, branch
`feat/wi364-f1-promote`, base `84bb2ec`. The supplied maintainer instruction
authorizes deletion after the closed Stage A ledger and two independent reviews.
The existing local `pre-0.8-reduction` tag is unchanged. No tracker, live estate,
other repository, publication or tag push is part of this change.

## Promoted surface

`src/regista/kernel.py` is the single transition/reduction implementation.
`src/regista/__init__.py` deliberately reexports the public classes, typed
refusals, loaders, workflow-validation API and limits in an explicit `__all__`.
`regista.cli:main` is the sole console entry point. SQL and workflow JSON Schema
load through `importlib.resources`; `initialize()` needs no repository path.
The existing optional explicit SQL-file argument remains for the original
synthetic permission tests. `py.typed` preserves typing for installed callers.

The two F0a scripts and workflows moved to `examples/`. The 521-node protection
suite moved to the sole `tests/` tree; it retains fail-hard CI admission without
a DSN. The scenario wrapper creates a distinct disposable database for each
script. The standalone mutation checker lives in `tests/test_mutations.py`.
Its obsolete check reading the deleted authoring schema is explicitly retired
as its own Stage A comment instructed: 68 checks remain. Named refusals for all
removed workflow keys remain exercised. The 139-recipe scratch proof runner
moved to `scripts/prove_f1.py`; the Stage A artifact is historical evidence,
not a claim that all recipes have been rerun for Stage B.

## Deleted paths and reasons

| Path | Treatment and reason |
| --- | --- |
| Old `src/regista/` | Replaced entirely by the protected kernel. Removes signing/trust, key custody, encryption, sidecar, in-memory engine, scheduling, hooks, witnesses, bundles and their alternate callable paths. |
| Old `tests/` | Replaced by the protected suite; removes `sidecar/`, `vectors/`, `fixtures/`, obsolete keys/workflows and tests of retired behavior after D1's closed-ledger condition. |
| `migrations/` | Deletes the 001–050 trust-system chain. Plan 032 F1 requires a fresh baseline and no in-place migration. |
| `prototypes/` | Removes the former source location after promoting its implementation, suite and examples. No second engine remains. |
| `tools/` | Only the retired v6 vector generator and old reducer/interpreter sweep were present. |
| `deploy/` | Only the removed HTTP sidecar's image and instructions were present. |
| `release/` | Its only file was the retired published-migration ledger; preserved as `published-migrations-pre-0.8.json` here. |
| `.regista/` | Old local worklog, session commands and reflections belonged to the previous suite workflow; preserved in git history. No live tracker is changed. |
| `suite.env.example` | Suite configuration and custody setup no longer belong to runtime admission. |
| `spec.yaml` | The machine-readable sidecar is retired by D15. Workflow JSON Schema remains shipped. |

Within the retained `scripts/`, `check-epoch-debt.py` was removed because its
v6 blocked-test manifest no longer exists. Identifier/publication-plumbing
scripts, `githooks/`, `publication.toml`, `LICENSE`, and the trimmed `Makefile`
remain. `plans/`, `debate/`, and `docs/` remain historical. Prior root README,
spec and agent guide are preserved under `docs/pre-0.8/`; short root guides now
point at the reduced contract. `CHANGELOG.md` and version are unchanged for F4/F5.

## Dependencies and configuration

Runtime dependencies are exactly psycopg (binary), psycopg-pool, PyYAML and
jsonschema, matching the kernel's third-party imports. Removed: structlog,
prometheus-client, python-dateutil and pynacl. Removed extras: sidecar,
ed25519, encryption, vendor-check, vault, azure, windows. The dev extra drops
agent-suite-conformance, hypothesis and types-python-dateutil; pytest,
pytest-cov, ruff, mypy and the two used stub packages remain. `uv.lock` is
regenerated. Python floor stays `>=3.11`, classifiers stay 3.11–3.14.

Hatch no longer force-includes old migrations. Its explicit source-distribution
include set ships only the current package, examples, test/gate tooling and
build inputs; historical implementation material is excluded. Mypy is strict
on exactly `src/regista`; ruff and pytest cover the retained tree.

## Schema refusal and exposed defects

Eight tests failed before the admission fix: default `connect()` returned a
handle for representative old destinations, even with a current marker placed
beside their old markers. A read-only opening check now refuses old or unknown
nonempty destinations, and every mutation and initializer checks legacy markers
before version admission. Empty destinations can initialize. Current kernel
schemas reopen. Unsupported kernel-version markers still permit diagnostic
reads and refuse writes, preserving the A5 ruling.

Fixtures use the old runner's `_regista_migrations` / `_substrate_migrations`
version/applied_at/checksum shape, representative versions 27/44/50, old
key_id/signature event columns and trust-era project_identity markers. Opening
in both modes refuses. Before/after snapshots compare rows and catalog objects;
late-added legacy tables also block init and writes. No old schema is dropped,
reset or migrated. The minimal public register/create/claim/transition/query
example is separately exercised with package-owned initialization.

The new CLI name is `check-history`. Old `replay` rebuilt projections; invoking
that old command now explicitly refuses and explains the read-only replacement.
Other removed command/import paths are absent rather than compatibility shims.

The first promoted full run passed 532 tests and failed the mutation subprocess:
the wrapper's standard psycopg keyword-form DSN exposed a URI-only test-label
helper. That harness helper now uses `make_conninfo`. No transition, reduction,
lease, field, role or idempotency behavior was changed during promotion.

## Migration guard and CI

GitHub #65 remains a blocking job named `published-migrations`. Its new
`scripts/schema-baseline.json` pins schema baseline 1 and the workflow schema.
The guard docstring records the Plan 032 F1/D1 retirement and preserved old
ledger. `verify-baseline` checks this pin; it deliberately makes no PyPI claim
for an unreleased baseline. Altered/missing/symlinked resources, extra SQL and
retired migration paths refuse. Publication below 0.8.0 refuses, while this
branch retains 0.7.2 metadata pending F4/F5.

The original reviewed-tree byte binding, ZIP/tar/path/mode checks, RECORD
verification, frozen Hatch backend closure, and exact pip/uv rebuilding of the
sdist remain. The controlled CI invocation retains full history and the clean
allowlisted environment for `check-dist --authoritative`. Local checks are
advisory and do not assert remote CI success.

CI runs the sole suite/scenarios/mutation checks on postgres:15 and CPython
3.11–3.14, plus identifier, strict typing, lint and lock consistency. It also
builds and installs the wheel into a clean temporary venv, removes inherited
Python path overrides, changes away from the checkout, checks `regista --help`
and package resources, and executes the document example on a fresh database.
The first remote run passed all four test suites and the authoritative artifact
guard, then exposed an unavailable `rg` binary in the missing-DSN assertion step.
That step now checks its log using Python standard-library code; the exit-4
requirement remains mandatory. All post-edit gates are rerun after this fix.
Retired-feature/epoch-debt/old slow-tier jobs are removed. Publication plumbing
is retained, but nothing is published here.

## Distribution and remaining qualification

The wheel's only package members are `__init__.py`, `kernel.py`, `cli.py`,
`schema.sql`, `workflow.schema.json` and `py.typed`, plus standard metadata and
LICENSE. There is one console script. The sdist contains current source,
examples/workflows, the sole tests, gates/hooks and build inputs; it contains no
retired runtime, migration chain, old extras or alternative engine.

The final handoff carries exact post-edit gate output and archive listings.
Commands include ruff, strict mypy, the full suite on 3.14 and 3.11, standalone
mutation checks and both examples on separate disposable databases, old-schema
refusals, missing-DSN CI failure, uv lock/build, wheel/sdist inspection, clean
installed smoke, identifier scanning and the artifact guard. Generated logs
are kept outside the repository so recording them does not invalidate the
post-edit checks.

Independent Stage B review and remote CI are still external acceptance, not
self-reported here. F3's full sdist-install/restart/restore qualification and
F4's full documentation/changelog/version/maintenance rewrite remain follow-on
work. The historical CHANGELOG intentionally retains retired names; refusal
fixtures, removed-workflow-key diagnostics and guard retirement deny entries
also intentionally mention removed features, without importing or calling them.
