# Plan 032 F3 — C4 distribution, restart and recovery qualification

Date: 2026-10-05. Artifact candidate: `4098196fdecf990fe8f2f788c7c9e84e0e2558dd` on
`feat/wi364-f1-promote` (draft PR #93). This repeats the C3 gates after the C4 release-workflow and canonical archive fixes.
Evidence-only follow-up commits do not change packaged inputs. All databases are
disposable child databases of the user-authorized local test service.

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `224c1d11498016de71c881c71ab86593a128521de9134feda8d492fb753465d8` |
| `regista_hraedon-0.8.0.tar.gz` | `6a1341fef8cbd464281989115178beb6ebbecd8ca0369a7c7396828cb6094b99` |

A full-depth independent clone (`--no-local --no-hardlinks`) rebuilt both artifacts
byte-identically. The authoritative guard runs there with an empty HOME, no
system/global Git configuration, replacement objects disabled and no alternates.
It rebuilds the sdist with pip and uv and binds every wheel member's bytes/mode.
The exact after-last-manual-edit commands, exit codes and stdout/stderr are in the
[C4 final gate record](032-c4-final-gates.json). Qualification requires that record
plus a green GitHub CI run on the final evidence commit.

This candidate also fixes the atomicity helper import under console pytest,
which CI exposed after the collation fix. All five full local suites were repeated
through that entry point. The wheel hash is unchanged; the sdist hash includes
the pytest configuration change. [CI follow-up evidence](032-c3-ci-followup.json)
preserves the earlier failed attempts and local reproduction.

## Installed-artifact method

[scripts/qualify_distribution.py](../scripts/qualify_distribution.py) implements
all F3 scenarios. It installs the freshly built wheel and sdist into separate
clean venvs; the sdist install builds the sdist. Closed child environments contain
only PATH, empty HOME, LANG, UV_NO_CONFIG, PIP_CONFIG_FILE and PYTHONUTF8. Installed
Python probes use `-I`; checkout/private imports are absent. Both unchanged
example scripts and YAML documents are extracted via importlib.resources.

For **each artifact**, the runner creates source, separate restore and old-schema
child databases and drops them in finally. It exercises:

- Both installed examples, with missing-field/role/holder refusals, real expiry,
  takeover and stale-attempt fencing, independent workflow vocabularies and CLI.
- Discovery, immediate-counterpart blocking, typed links, paging and filters.
- Rollback after invalid JSON and a real SQL exception. Fresh-connection admission
  refuses preinstalled foreign triggers, so the fault is installed after an admitted
  writer has queued on its event insert. Projection and history remain unchanged,
  the fault is removed and a valid write succeeds.
- Eight independent pools contesting one claim; exactly one winner and clean replay.
- An actual lease-holding worker terminated with SIGTERM, real expiry, takeover,
  stale refusal and a valid replacement write.
- A new process/connection reading six persisted items, fields and links and
  streaming clean whole-namespace replay.
- A populated pg_dump restored into a **different database**, followed by a new
  process read, another valid create/claim/transition/release and clean seven-item
  installed CLI replay. Matching PostgreSQL 15 dump/restore utilities are used.
- Representative old schemas built with migrations 001–044 and 001–050 exported
  from `84bb2ec`: opener modes and initialization refuse; complete logical dumps
  before and after are identical. These are migration-derived fixtures, not a
  certification of every historic production database.

## Reproducible commands

Set REGISTA_TEST_DSN to the authorized disposable endpoint; credentials are
sanitized in the public generated record. No production DSN is accepted as evidence.

```bash
uv venv .release-build --python .venv/bin/python
uv pip install --python .release-build/bin/python --require-hashes -r .github/build-requirements.txt
uv build --python .release-build/bin/python --no-build-isolation
uv venv .release-twine --python .venv/bin/python
uv pip install --python .release-twine/bin/python --require-hashes -r .github/twine-requirements.txt
.release-twine/bin/twine check dist/*.whl dist/*.tar.gz
PATH=/tmp/regista-pg15-tools/extracted/usr/lib/postgresql/15/bin:$PATH \
  .venv/bin/python scripts/qualify_distribution.py dist \
  --dsn "$REGISTA_TEST_DSN" --output /tmp/regista-c4-console-f3-qualified
.venv/bin/python scripts/smoke_installed.py dist
.venv/bin/ruff check src/ tests/ examples/ scripts/
.venv/bin/mypy
REGISTA_REQUIRE_DB=1 .venv/bin/pytest tests/ -q
REGISTA_REQUIRE_DB=1 /tmp/regista-py311/bin/pytest tests/ -q
.venv/bin/python scripts/prove_b2.py
.venv/bin/python scripts/prove_c1_artifacts.py
uv lock --check
.venv/bin/python scripts/check_published_migrations.py verify-baseline
.venv/bin/python scripts/check_published_migrations.py verify-ledger
.venv/bin/python scripts/check_published_migrations.py check-tree
```

The full prove_f1 run supplies every explicit mutant name, preserving historical
F1 evidence. Its unmodified control must pass, then every selected mutant must
produce test-body failures; setup errors/skips do not count. C1 supplied security,
integrity, fencing, release-barrier and bounded-retry mutants; C2 adds five
connection/initialization admission and refusal-type mutants. C3 adds default-locale
object ordering; a separate proof removes all eight C sort clauses. The artifact/workflow
proof separately requires a passing control and killed mutants for gzip, metadata,
root, permissions, uv version/checksum, action SHA, identifier gate and main ancestry.
The full suites also exercise standalone scenario mutations. Suites/proofs use
separate fresh child databases. The README Python quickstart is executed verbatim
with a catalog assertion that its namespace genuinely does not exist beforehand.

Every supplied reviewer Python script is rerun, with only its disposable DSN and
CLI venv location adapted for this worktree. Original SHA-256, adaptations, raw
exit/output and any necessary supplemental arm are in the C3 reviewer record.
The release-race script's synchronous controller now waits until its writer times
out; a threaded controller verifies the intended drain. Administrator-installed
trigger fixtures can run on an already admitted connection.
The atomic-pool script terminates that connection; its replacement refuses the
remaining foreign fixture. A supplemental arm removes the trigger/function before
replacement admission and verifies rollback plus a valid write. Both raw and
supplemental outputs are retained; the heartbeat/sweep script completes on its live
admitted connection. The exact concatenated-gzip `dd ...
oflag=append conv=notrunc`, raw trailer, metadata fields and wrong-root vectors
are run under the authoritative guard and must refuse.

## Baseline, environment and limits

`schema.sql` remains byte-identical at baseline version 1, SHA-256
`4bc366e7bda15cbe75baf42d522e22d152f1cce9966114e6bd9468e2caf8010d`;
no schema pin change or guard bypass was needed. The unpublished event digest
now binds transition and payload; pre-C1 experimental stores must be recreated.
C2 and C3 change no persisted format. C3 explicitly canonicalizes all catalog text
ordering with C collation. The complete catalog and fingerprint match the existing
committed manifest on Debian 15, Alpine 15, Debian 16 and Debian 17, so the manifest
was deliberately retained. New tests exercise real libc and ICU non-C databases.
Hashes provide consistency, not authenticity. Replay exclusions remain leases,
attempt counters, links and idempotency keys.

Local interpreters are CPython 3.14.8 and 3.11.15; the primary PostgreSQL server
is Debian 15.17 (`en_US.utf8`);
secondary suites use Alpine 15.19 (musl), Debian 16.15 and Debian 17.11;
uv is 0.12.23 and Hatchling 1.32.4 with a pinned build dependency closure.
Unchanged tools/action provenance remains in the
[C1 record](032-c1-tool-provenance.json). Full baseline validation is per physical
connection and at initialization. Only
namespace and version checks remain on each write. Administrator DDL on admitted
connections is outside the trust boundary; a new connection or application/pool
restart revalidates. Historical C2 Alpine benchmark batches measured create median
5.803 ms, versus C1 16.437 ms and its 5.536 ms marker-only control. See the
[C2 samples](032-c2-baseline-benchmark.json) and [C2 report](032-c2-validation.md).

C1 and C2 CI runs were red due to the collation defect; their local qualification
was insufficient. C4 requires final-commit GitHub CI on all six kernel matrix
combinations plus lockfile and authoritative artifacts. The exact final run and
job verdicts are reported separately after the authorized branch push; this
committed document records the local evidence before that push.
Live GitHub branch/tag/environment settings are recorded in F5. PyPI registration,
D8's unfamiliar-human walkthrough and private consumer upgrades remain owner
prerequisites. Recheck the recorded live controls before release. No tags, dispatches, uploads or settings changes are made.

## Generated C4 local gate results

```text
ruff: All checks passed!
mypy: Success: no issues found in 5 source files
suite-314-pg15: 1024 passed, 67 subtests passed in 419.37s (0:06:59)
suite-311-pg15: 1024 passed, 67 subtests passed in 419.45s (0:06:59)
suite-314-alpine: 1023 passed, 1 skipped, 67 subtests passed in 478.68s (0:07:58)
suite-314-pg16: 1024 passed, 67 subtests passed in 380.60s (0:06:20)
suite-314-pg17: 1024 passed, 67 subtests passed in 344.65s (0:05:44)
prove-f1: 165 mutants killed; 518 distinct test nodes proved
prove-b2: 11 mutants killed; no survivors
prove-c1-artifacts: 16 artifact/workflow mutants killed
readme: 1 passed in 0.94s
verify-baseline: verify-baseline: ok
verify-ledger: verify-ledger: ok
check-tree: check-tree: ok
references: API and CLI references are current.
smoke: Installed wheel smoke passed (clean venv, checkout absent from import path).
missing-dsn: expected exit 4; REGISTA_TEST_DSN is required
all-eight-clause mutant: 3 test-body failures, 0 errors, 0 skips
pristine authoritative: check-dist: ok
C3 tamper vectors: 16/16 refused, exit 2
dv2 probe_rsc1: pristine PASS; all 17 attacks REFUSED
dv2 authoritative: pristine exit 0; all 17 attacks exit 2
tool locks: pristine fresh installs pass; corrupt hashes and omitted transitive pin refused, exit 1
reviewer originals: 14/14 executed; hashes and raw exit classifications match C3; four supplemental arms recorded
F3: wheel and sdist passed installed examples, restart, separate restore and another valid write on Debian PostgreSQL 15
independent build: wheel and sdist byte-identical
```

All 29 normal qualification commands exited 0; the two supplementary release/focused
checks also passed. Missing-DSN refusal has the required exit 4. The collation
mutant's three test-body failures are expected. Alpine's only skip is unavailable
libc en_US UTF-8; its ICU regression ran. Debian 15/16/17 have no skipped tests.
Exact commands/output are in [C4 gates](032-c4-final-gates.json),
[165 kernel mutants](032-c4-f1-mutations.json),
[16 artifact/workflow mutants](032-c4-artifact-mutations.json),
[original supply-chain vectors](032-c4-dv2-probes.json),
[tool-lock refusal probes](032-c4-tool-lock-probes.json), and
[independent read-only review](032-c4-source-review.json).

The supply-chain guard rejects every probe_rsc1 attack; pristine artifacts pass
the authoritative guard in a clean full-depth clone, empty HOME and isolated Git
environment. Later evidence-only commits change no distribution input. F5 records
the live GitHub controls and mandatory owner hash comparison. Final pushed-commit
CI remains required; its URL and all job verdicts are recorded after the push.
