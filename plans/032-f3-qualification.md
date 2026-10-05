# Plan 032 F3 — distribution, restart and recovery qualification

Date: 2026-10-05. Candidate:
`73b3f2efaedca52a8a4c964a8b78e33447615a8f` (`feat/wi364-f1-promote`).
F1 baseline at start: `662835926578dc6ea43cd70f3f4460a936eecf99`.
Only disposable PostgreSQL was used; no production/private estate writes.

## Artifacts and environment

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `a5881f537b5495f6bb78a5e079122c57e7cc4d3965d1dfa42dcd8c8badb555b4` |
| `regista_hraedon-0.8.0.tar.gz` | `f7c2a8066f993f09d3ef149f710536d318bd1074d4812e7aefe5625f1b6812b8` |

OS: Ubuntu 24.04.5 LTS, Linux 6.17.0-1022-azure x86_64, glibc 2.39.
Qualification Python: CPython **3.14.8** (Clang 22.1.3).
Second local suite interpreter: CPython **3.11.15**.
PostgreSQL server: **15.19**, disposable service at 127.0.0.1:55499.
Qualification `pg_dump`/`pg_restore`: **15.19-1.pgdg24.04+2**.
uv: **0.12.23**. Build backend: **hatchling 1.32.4**, complete pinned dependency
closure in pyproject. Wheel and sdist isolated installs each resolved psycopg/
psycopg-binary **3.3.6**, psycopg-pool **3.3.3**, PyYAML **6.0.3**, jsonschema
**4.26.0**. Local 3.14 suite environment uses psycopg **3.3.4**, psycopg-pool
**3.3.1**, pytest **9.0.3**, ruff **0.16.0**, mypy **2.1.0**; the separate 3.11
environment uses psycopg **3.3.6**, pytest **9.1.1**, ruff **0.16.10**, mypy **2.4.0**.
These are measured distinct environments, not a claim that the lock was used for
clean package installs. CI verifies 3.11–3.14 against PostgreSQL 15.

## Exact commands and isolation

The reusable runner is [scripts/qualify_distribution.py](../scripts/qualify_distribution.py).
Its source records every inner command/probe. `DSN` below is the user-authorized
disposable endpoint; the password is intentionally represented by a placeholder
in this public report. Supply the disposable password via the environment, not
production credentials.

```bash
export REGISTA_TEST_DSN='postgresql://regista_test:<disposable-password>@127.0.0.1:55499/regista_test'
uv build
uvx twine check dist/*
sha256sum dist/*

# Matching PG15 utilities were extracted locally, with no server or settings change.
mkdir -p /tmp/regista-pg15-tools
cd /tmp/regista-pg15-tools
apt download postgresql-client-15
dpkg-deb -x postgresql-client-15*.deb extracted
cd /projects/.worktrees/regista-f1b
PATH=/tmp/regista-pg15-tools/extracted/usr/lib/postgresql/15/bin:$PATH \
  .venv/bin/python scripts/qualify_distribution.py dist \
  --dsn "$REGISTA_TEST_DSN" --output /tmp/regista-f3-candidate

REGISTA_TEST_DSN="$REGISTA_TEST_DSN" .venv/bin/python scripts/smoke_installed.py dist
.venv/bin/ruff check src/ tests/ examples/ scripts/
.venv/bin/mypy
REGISTA_REQUIRE_DB=1 .venv/bin/python -m pytest tests/ -q
REGISTA_REQUIRE_DB=1 /tmp/regista-py311/bin/python -m pytest tests/ -q
uv lock --check
.venv/bin/python scripts/check_published_migrations.py verify-baseline
.venv/bin/python scripts/check_published_migrations.py verify-ledger
.venv/bin/python scripts/check_published_migrations.py check-dist dist
```

The second suite environment was created with `uv venv --python 3.11
/tmp/regista-py311` and `uv pip install --python /tmp/regista-py311/bin/python -e
'.[dev]'`. Checkout imports are appropriate for source tests, **not** artifact
qualification. The qualification runner creates separate wheel/sdist venvs under
an otherwise empty scratch directory using `uv venv --python <3.14 interpreter>`,
then `uv pip install --python <scratch>/venv/bin/python <absolute artifact path>`.
The latter **builds the sdist**, rather than substituting the candidate wheel.

Every qualification child runs with a closed environment containing only PATH,
empty HOME, LANG, `UV_NO_CONFIG=1`, `PIP_CONFIG_FILE=/dev/null`, and PYTHONUTF8.
Installed Python probes and example scripts use **`-I`**. The checkout and sibling
checkouts are absent from their import path; printed imports were the scratch
venv's `site-packages/regista/__init__.py`. No private configuration/keys were
copied. Example resources were extracted with `importlib.resources.files` from
that installed package, with **unchanged bytes**; source/resource equality is
pinned by `tests/test_documentation.py`.

For each artifact the runner creates five uniquely named child databases (source,
separate restore, and old-schema targets) and drops all of them in `finally`.
It runs these actual inner commands, substituting its child DSNs:

```text
<installed>/bin/regista --help
<installed>/bin/python -I examples/example_handoff.py <source DSN>
<installed>/bin/python -I examples/example_documents.py <source DSN>
<installed>/bin/python -I <scratch>/probe.py --probe exercise --dsn <source DSN> --output <scratch>
<installed>/bin/python -I <scratch>/probe.py --probe restart --dsn <source DSN> --output <scratch>
pg_dump --format=custom --no-owner --no-acl --file <scratch>/populated.dump <source DSN>
pg_restore --exit-on-error --no-owner --no-acl --dbname <separate restore DSN> <scratch>/populated.dump
<installed>/bin/python -I <scratch>/probe.py --probe recover --dsn <separate restore DSN> --output <scratch>
<installed>/bin/regista --dsn <separate restore DSN> --json check-history
<installed>/bin/python -I <scratch>/probe.py --probe legacy --dsn <old base DSN> --output <scratch>
```

## Sanitized results, F3 items 1–5

**Both wheel and sdist:** import and CLI passed; `schema.sql` and
`workflow.schema.json` loaded from installed package resources. The package,
not a repository file path, supplied initialization SQL. Each artifact ran both
F0a scripts and YAML documents verbatim from installed resources.

- Handoff: two OS worker processes contended; exactly one lease owner won. Missing
  required fields, wrong holder and disallowed role refused. Reviewer requested
  changes; a new attempt expired on the real database clock, takeover succeeded,
  and the stale attempt refused. Fresh review completed the finding to `done`.
- Documents: a separate workflow/type vocabulary ran extraction, human CLI
  claim/heartbeat/rejection/correction, field clears, review and archive. Regista
  archive retries deduplicated; the illustrative external ledger's duplicate
  protection was explicitly its own. Final document state was `archived`.
- Discovery: available/owned/state-based review-ready and blocked queries, one-hop
  link-aware blocking, scalar field filters, typed links and cursor paging passed.
- The additional crash probe started an actual OS worker that claimed a short
  lease, **terminated it with SIGTERM**, waited for genuine expiry, took over with
  a greater attempt, refused its stale write, and committed a valid replacement
  write. The unchanged handoff script itself models death by expiry; it does not
  perform that termination, and this report does not claim otherwise.
- Rollback: invalid non-finite JSON and a synthetic PostgreSQL AFTER INSERT
  exception left both current item and event history unchanged. The trigger was
  removed, and a valid write succeeded. Eight independent connection pools raced
  one claim; exactly one won. Single-item and whole-namespace replay were clean.
- Restart: a new process and connection opened `require_existing=True`, read all
  six persisted items and their fields/links, verified `done`/`archived`, and
  streamed clean whole-namespace replay in batches of two.
- Recovery: a populated custom-format dump restored into a **different database**.
  A new installed-package process read six items, checked every replay report,
  then successfully created/claimed/transitioned/released another item and read
  its `done` projection plus clean history. Installed CLI whole-namespace
  `check-history --json` produced seven clean reports. This proves a usable write
  after restore, beyond verifier success.
- Legacy: exported SQL directly with `git show 84bb2ec:migrations/<name>`.
  Applied **001–044** for the 0.5-era fixture and **001–050** for 0.6/0.7 in
  separate child databases, including marker rows. These are representative
  migration-derived schemas at the requested reference, not certified copies of
  every old published database. Both opener modes and CLI initialization refused
  each. Complete logical dumps before/after were equal; no mutation occurred.

The final runner printed the following for **each** artifact (all exits 0):

```text
rollback: invalid input and injected SQL failure left state/history unchanged
contention: 8 independent connections, exactly 1 claim winner; replay clean
crash: lease-holding OS process terminated (SIGTERM); real expiry, takeover, stale refusal and valid replacement write passed
restart: new process/connection; 6 persisted items, fields/links read; whole-namespace replay clean
recover: new process/connection; 6 persisted items, fields/links read; whole-namespace replay clean
recover: another valid create/claim/transition/release persisted cleanly
0.5-era: migrations 001-044; 2 opens + init refused; complete logical dump unchanged
0.6-0.7-era: migrations 001-050; 2 opens + init refused; complete logical dump unchanged
```

`PASS` lines carried the two artifact hashes in the table. The document example
completed in about 4 seconds per clean run (not an installation/setup benchmark).
No private imports or application-specific library patches were needed.

## Matrix, scale, mutations and guards, F3 item 6

The complete source suite collects **919 tests**, with **67 subtests**. It includes
bounded replay/scale protections and executable refusal/control mutation cases.
The successful packaged-tree CI [run 37275016486](https://github.com/hraedon/regista/actions/runs/37275016486)
at `a5b0797a17fb22cabd83d2f4b1a85cfbab716f2a` passed the **3.11/3.12/3.13/3.14**
job matrix, lint/types/tests, missing-DSN hard failure, installed-wheel smoke,
lockfile check and authoritative schema/artifact guard. The exact candidate's
[run 37276210043](https://github.com/hraedon/regista/actions/runs/37276210043)
passed on the final candidate, including the test-harness timeout correction.
Final branch evidence commits have no packaged effect and receive CI too.

Exact candidate CI suite summaries (all exits 0):

```text
3.11: 919 passed, 67 subtests passed in 216.89s (0:03:36)
3.12: 919 passed, 67 subtests passed in 199.26s (0:03:19)
3.13: 919 passed, 67 subtests passed in 200.92s (0:03:20)
3.14: 919 passed, 67 subtests passed in 256.07s (0:04:16)
```


The mutation proof is run with every explicit mutant name, to preserve the
historical checked-in F1 evidence rather than rewriting it:

```bash
REGISTA_REQUIRE_DB=1 .venv/bin/python - <<'PY'
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location('proof', 'scripts/prove_f1.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
raise SystemExit(subprocess.call([
    sys.executable, 'scripts/prove_f1.py', *[m[0] for m in proof.MUTANTS]
]))
PY
```

It requires an unmodified control first and test-body assertion failures for
mutants; setup errors/skips do not count. The corrected initial run printed:

```text
CONTROL passed: 899 passed, 20 deselected, 67 subtests passed in 301.92s (0:05:01)
139 mutants killed; 467 distinct test nodes proved
```
 The standalone scenario mutation suite
is also exercised by `tests/test_scenarios.py`. Final after-last-edit gate results
are reported with the branch handoff; these commands and the successful CI are
reproducible independent evidence, not a claimed private provenance attachment.

For authoritative distribution verification, a full-depth separate clone rebuilt
both artifacts byte-identically, then passed:

```bash
git clone --no-local --no-hardlinks --branch feat/wi364-f1-promote \
  /projects/.worktrees/regista-f1b /tmp/regista-f3-authoritative
uv build --project /tmp/regista-f3-authoritative --out-dir /tmp/regista-f3-authoritative/dist
sha256sum /tmp/regista-f3-authoritative/dist/*
guard_home=$(mktemp -d /tmp/regista-f3-guard-home-XXXXXX)
env -i PATH="$PATH" HOME="$guard_home" \
  GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  /projects/.worktrees/regista-f1b/.venv/bin/python \
  /tmp/regista-f3-authoritative/scripts/check_published_migrations.py \
  check-dist --authoritative /tmp/regista-f3-authoritative/dist
```

Observed: `verify-baseline: ok`, `check-dist: ok` (authoritative); ordinary
worktree `check-dist` also passed and labeled its verdict advisory. PyPI binding
currently prints `no published 0.8.x release yet; PyPI binding not applicable`,
then `verify-ledger: ok`; **it has not qualified an uploaded 0.8.0 wheel**.
Post-publication binding remains in [F5](032-f5-release-prep.md).

## Failures found and corrected (not hidden)

1. Initial artifact restore with host PostgreSQL **18.6** utilities failed:
   `unrecognized configuration parameter "transaction_timeout"` (restore emitted
   `SET transaction_timeout = 0`). No package defect was inferred. Downloaded and
   extracted matching PG **15.19** client utilities, kept the dump/restore step
   intact, and reran wheel **and** sdist qualification successfully.
2. The new reference pin first failed because frozenset repr order was not
   deterministic; Python 3.11 then exposed a different argparse usage wrap. The
   generator sorts set values and normalizes usage whitespace only. Both versions'
   documentation tests now pass without dropping any command/option text.
3. A failing-first public-guidance test found `hook_defaults` still claiming
   synchronous validation was kept, and the adjacent old link-declaration
   explanation contradicted supported `link_type_names`. Corrected refusal
   strings, regenerated the reference, and passed the test; execution/transition
   rules were unchanged.
4. The first full suite at the bumped version failed solely on the current
   distribution assertion still expecting `0.7.2`: **1 failed, 918 passed,
   67 subtests passed in 353.68s**. Updated that positive assertion to `0.8.0`;
   historical negative vectors remain unchanged. The corrected matrix CI passed.

5. The standalone 139-mutant driver's **unmodified control** exceeded its old
   300-second timeout before any verdict. The full source suite had measured
   353.68 seconds on this host. Changed only the full-control budget to 900
   seconds; each selected mutant retains 300 seconds and the same required
   assertion failures. The failed timeout is not mutation evidence. The corrected
   control passed: `899 passed, 20 deselected, 67 subtests passed in 301.92s`.
   Those exclusions apply only to the mutation control (expensive replay-memory,
   scenario and distribution-guard selections); the full 919-test gates and CI
   include them. All 139 mutants then require individual assertion failures;
   the initial corrected run killed all 139, proving 467 distinct test nodes.
   The after-last-edit run repeats the complete proof.


F3 does not close D8's unfamiliar-human walkthrough: its preserved report remains
partial. It also does not perform publication, yanking, private consumer upgrades
or repository/PyPI settings verification. Those limits are explicit in F5.

## After-last-edit gate record

The generated [final gate record](032-f3-final-gates.json) contains each exact
command (disposable credentials sanitized), exit code and stdout/stderr after
the last manual documentation edit. Source suites on 3.14 and 3.11 and the full
mutation proof use **separate freshly created child databases** and separate
interpreters; the final artifact scenarios use their own further child databases.
All child databases are dropped after the checks. No shared checkout or source
files are mutated by those checks. Evidence-only follow-up commits leave all
packaged inputs and hashes unchanged. The handoff reports the final run's outputs.
