# Plan 032 F3 — C2 distribution, restart and recovery qualification

Date: 2026-10-05. Artifact candidate: `47591367476b6ec036ef439b9f4499e966eac9ff` on
`feat/wi364-f1-promote` (draft PR #93). This replaces the C1 qualification.
Evidence-only follow-up commits do not change packaged inputs. All databases are
disposable child databases of the user-authorized local test service.

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `7d64f71cae2697b17dc2a1ab79b5a2b686770ea4fb7a9bed3de7911c9c4c2ec0` |
| `regista_hraedon-0.8.0.tar.gz` | `091dfa27b322bdf5c5129a10f2f8327e64dc0a64df66eb42289b1b4d8cf98f1f` |

A full-depth independent clone (`--no-local --no-hardlinks`) rebuilt both artifacts
byte-identically. The authoritative guard runs there with an empty HOME, no
system/global Git configuration, replacement objects disabled and no alternates.
It rebuilds the sdist with pip and uv and binds every wheel member's bytes/mode.
The exact after-last-manual-edit commands, exit codes and stdout/stderr are in the
[C2 final gate record](032-c2-final-gates.json). Qualification completion is
determined by that record, not by historical CI results.

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
uv build
uvx --from twine==7.0.0 twine check dist/*.whl dist/*.tar.gz
PATH=/tmp/regista-pg15-tools/extracted/usr/lib/postgresql/15/bin:$PATH \
  .venv/bin/python scripts/qualify_distribution.py dist \
  --dsn "$REGISTA_TEST_DSN" --output /tmp/regista-c2-f3-qualified
.venv/bin/python scripts/smoke_installed.py dist
.venv/bin/ruff check src/ tests/ examples/ scripts/
.venv/bin/mypy
REGISTA_REQUIRE_DB=1 .venv/bin/python -m pytest tests/ -q
REGISTA_REQUIRE_DB=1 /tmp/regista-py311/bin/python -m pytest tests/ -q
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
connection/initialization admission and refusal-type mutants. The artifact/workflow
proof separately requires a passing control and killed mutants for gzip, metadata,
root, permissions, uv version/checksum, action SHA, identifier gate and main ancestry.
The full suites also exercise standalone scenario mutations. Suites/proofs use
separate fresh child databases. The README Python quickstart is executed verbatim
with a catalog assertion that its namespace genuinely does not exist beforehand.

Every supplied reviewer Python script is rerun, with only its disposable DSN and
CLI venv location adapted for this worktree. Original SHA-256, adaptations, raw
exit/output and any necessary supplemental arm are in the C2 reviewer record.
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
C2 changes no persisted format.
Hashes provide consistency, not authenticity. Replay exclusions remain leases,
attempt counters, links and idempotency keys.

Local interpreters are CPython 3.14.8 and 3.11.15; PostgreSQL is 15.19;
uv is 0.12.23 and Hatchling 1.32.4 with a pinned build dependency closure.
Unchanged tools/action provenance remains in the
[C1 record](032-c1-tool-provenance.json). Full baseline validation is per physical
connection and at initialization. Only
namespace and version checks remain on each write. Administrator DDL on admitted
connections is outside the trust boundary; a new connection or application/pool
restart revalidates. Seven alternating benchmark batches measure create median
5.803 ms, versus C1 16.437 ms and its 5.536 ms marker-only control. See the
[C2 samples](032-c2-baseline-benchmark.json) and [C2 report](032-c2-validation.md).

Historical CI runs predate this candidate. Current local gates do not assert current 3.12/3.13
CI success, external branch/tag/environment/PyPI settings, an unfamiliar-human D8
walkthrough, publication, yanking or private consumer upgrades. F5 retains those
owner prerequisites. No tags, dispatches, uploads or settings changes were made.


## Generated final gate results

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

All final gate exits are 0. Exact commands/stdout/stderr (or explicitly combined
output where captured by shell redirection) are in the linked C2 gate record.
The artifact table supplies both qualified and byte-identical rebuilt hashes.
