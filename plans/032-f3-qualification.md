# Plan 032 F3 — C1 distribution, restart and recovery qualification

Date: 2026-10-05. Artifact candidate: `8ff80ade3972311c6e6568f3afae415761a9a9ca` on
`feat/wi364-f1-promote` (draft PR #93). This replaces the pre-C1 qualification.
Evidence-only follow-up commits do not change packaged inputs. All databases are
disposable child databases of the user-authorized local test service.

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `80f5498d901aa8c52349a22e4354e540551e32da9f09768d11190573d0fddd04` |
| `regista_hraedon-0.8.0.tar.gz` | `1a2b25c8d38b1957bf113e88407279ed3754c5ec7f7913c54ea0e19ec830a8d2` |

A full-depth independent clone (`--no-local --no-hardlinks`) rebuilt both artifacts
byte-identically. The authoritative guard runs there with an empty HOME, no
system/global Git configuration, replacement objects disabled and no alternates.
It rebuilds the sdist with pip and uv and binds every wheel member's bytes/mode.
The exact after-last-manual-edit commands, exit codes and stdout/stderr are in the
[C1 final gate record](032-c1-final-gates.json). Qualification completion is
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
- Rollback after invalid JSON and a real SQL exception. C1 strict admission refuses
  preinstalled foreign triggers, so the fault is installed after an admitted
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
uvx --from twine==7.0.0 twine check dist/*
PATH=/tmp/regista-pg15-tools/extracted/usr/lib/postgresql/15/bin:$PATH \
  .venv/bin/python scripts/qualify_distribution.py dist \
  --dsn "$REGISTA_TEST_DSN" --output /tmp/regista-c1-f3-final4
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
produce test-body failures; setup errors/skips do not count. C1 adds security,
integrity, fencing, release-barrier and bounded-retry mutants. The artifact/workflow
proof separately requires a passing control and killed mutants for gzip, metadata,
root, permissions, uv version/checksum, action SHA, identifier gate and main ancestry.
The full suites also exercise standalone scenario mutations. Suites/proofs use
separate fresh child databases. The README Python quickstart is executed verbatim
with a catalog assertion that its namespace genuinely does not exist beforehand.

Every supplied reviewer Python script is rerun, with only its disposable DSN and
CLI venv location adapted for this worktree. Original SHA-256, adaptations, raw
exit/output and any necessary supplemental arm are in the C1 reviewer record.
The release-race script's synchronous controller now waits until its writer times
out; a threaded controller verifies the intended drain. Scripts that install
foreign trigger fixtures are refused by strict admission; clean-admission fault
injection retains the rollback test. The exact concatenated-gzip `dd ...
oflag=append conv=notrunc`, raw trailer, metadata fields and wrong-root vectors
are run under the authoritative guard and must refuse.

## Baseline, environment and limits

`schema.sql` remains byte-identical at baseline version 1, SHA-256
`4bc366e7bda15cbe75baf42d522e22d152f1cce9966114e6bd9468e2caf8010d`;
no schema pin change or guard bypass was needed. The unpublished event digest
now binds transition and payload; pre-C1 experimental stores must be recreated.
Hashes provide consistency, not authenticity. Replay exclusions remain leases,
attempt counters, links and idempotency keys.

Local interpreters are CPython 3.14.8 and 3.11.15; PostgreSQL is 15.19;
uv is 0.12.23 and Hatchling 1.32.4 with a pinned build dependency closure.
The tools/action provenance and measured baseline admission costs are in the C1
report and machine evidence. Fresh per-write checks intentionally incur catalog
cost; no mutable schema evidence is cached.

Historical CI runs predate C1. Current local gates do not assert current 3.12/3.13
CI success, external branch/tag/environment/PyPI settings, an unfamiliar-human D8
walkthrough, publication, yanking or private consumer upgrades. F5 retains those
owner prerequisites. No tags, dispatches, uploads or settings changes were made.


## Generated final gate results

Python 3.14: `993 passed, 67 subtests passed in 611.48s`. Python 3.11: `993 passed, 67 subtests passed in 611.64s`. F1: `159 mutants killed; 508 distinct test nodes proved`. B2: `11 mutants killed; no survivors`. Artifact/workflow: `9 artifact/workflow mutants killed`. Wheel and sdist PASS lines carry the hashes in the table; independent rebuild hashes are identical. All gate exits are 0. The authoritative pristine vector passed, and all 16 tamper variants refused with exit 2. Exact stdout/stderr and commands are retained in the linked C1 records.
