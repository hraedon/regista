# Plan 032 F1 — Packaging map (dependencies, extras, entry points, CI, version support)

**Scope:** analysis only, no files in `/projects/regista` were modified. Branch
`docs/wi364-f0-dependency-map`, working tree as found. Builds on
`plans/032-f0-dependency-map.md` (module classification KERNEL/TRUST/OPTIONAL)
and `plans/032-final-public-release.md` §3 (target scope) / F1 (this work
package). Every claim below is backed by a `grep`/`cat` shown or described
inline; re-run any of them to check my work.

---

## 1. Runtime dependencies

`pyproject.toml` `[project] dependencies` (8 entries):

| Dependency | Extra | Importing modules (evidence) | KEEP/DROP | Basis |
| --- | --- | --- | --- | --- |
| `psycopg[binary]>=3.2,<4` | base | 22 modules incl. `_actor_roles`, `_claims`, `_connection`, `_events`, `_links`, `_projects`, `_work_items`, `_replay`, `_workflow_api` (KERNEL) and `_genesis`, `_hooks`, `_principal_keys`, `_recurrence`, `_witness`, `_v6_writer` (TRUST/OPTIONAL) | **KEEP** | `grep -rln "^import psycopg\|^from psycopg" src/regista/` — kernel modules import it directly; database access is the product |
| `psycopg-pool>=3.2,<4` | base | `_connection.py` only | **KEEP** | `_connection.py` is the kernel's connection/pool manager |
| `pyyaml>=6.0` | base | `_workflow.py` (KERNEL — workflow YAML loading), `_in_mem_workflow.py` (OPTIONAL, retiring), `sidecar/auth.py` (TRUST, retiring) | **KEEP** | `_workflow.py` is imported by `_work_items`, `_transition`, `_cli`, `__init__` — YAML workflow support is an explicit keep-table item ("straightforward YAML/JSON Schema support") |
| `jsonschema>=4.21` | base | `_workflow.py` (KERNEL), `_lint.py` (TRUST — see below) | **KEEP** | Same reasoning: `_workflow.py`'s JSON-Schema field validation is required MVP behaviour |
| `structlog>=24.1` | base | 24 importers spanning kernel (`_claims`, `_transition`, `_workflow`, `_archive`, `_replay`, `_cli`, `__init__`) and trust/optional (`_bundle`, `_witness`, `_recurrence`, `_keys`, `_ops`, in-memory modules) | **KEEP** | Kernel modules log directly; this is the project's only logging library |
| `prometheus-client>=0.20` | base | `_observability.py` only, which is in turn imported by `__init__`, `_transition`, `_work_items_api`, `_claims_api`, `_links_api`, `_events_api`, `_api_base`, `_workflow_api` (KERNEL API surface) as well as `_hooks`, `_recurrence_api`, `principal_lifecycle`, `_ops` (TRUST/OPTIONAL) | **KEEP, flag for confirmation** | Metrics instrumentation reaches the kernel's own public API modules, not only removed features — see §1a |
| `python-dateutil>=2.9` | base | **Only** `_recurrence.py` (function-local imports at lines 37, 96, 165: `from dateutil import rrule, tz`, `from dateutil.relativedelta import relativedelta`) | **DROP** | `grep -rn "dateutil" src/regista/` returns exactly one file, and `_recurrence.py` is explicitly on the OPTIONAL/remove list ("Recurrence scheduling... Default to removal"). No other module references `dateutil` under any spelling. |
| `pynacl>=1.5` | base | **Only** trust modules: `_trust_domain.py`, `_signing_scheme.py`, `_genesis_open.py`, `_estate_catalog.py`, `_trust_log.py`, `_custody.py`, `_trust_log_export.py`, `_invariant_probe.py`, `_bundle_v3.py`, `client_signer.py`, `_cli.py` (key-generation/signing subcommands only), `_testing_v6.py` | **DROP** | `grep -rn "\bnacl\b" src/regista/` — every hit is signing, genesis, key custody, estate-catalog, or bundle machinery, all on the explicit remove list. **This is a base (non-optional) dependency today that exists solely for a feature being deleted.** Its removal also obsoletes the separate `ed25519` extra (see §2) that duplicates it. |

**1a. `prometheus-client` needs a maintainer call, not a mechanical one.**
Plan 032's keep table does not mention metrics/observability explicitly, but
`_observability.py` is imported by the kernel's own `work_items`/`claims`/
`links`/`events`/`workflow` API modules and by `__init__.py` — i.e. it
instruments the retained public surface, not only the removed features. I
found no evidence it is trust-only. Recommendation: **keep**, but flag it in
F1 execution so the maintainer can confirm metrics remain in scope for the
MVP (it is not named in Plan 032 §3, so silence there could mean either "kept
by default" or "not considered yet").

**Cross-checks performed** (per the task's "prove the non-obvious ones"
instruction):
- `PyNaCl` → `nacl` — checked, confirmed above.
- `PyYAML` → `yaml` — checked (`_workflow.py`, `_in_mem_workflow.py`, `sidecar/auth.py`).
- `python-dateutil` → `dateutil` — checked, confirmed single importer.
- `psycopg` → `psycopg` (no rename) — checked, 22 importers.
- I also verified `dateutil` and `nacl` with an unanchored grep (not just
  `^import`/`^from`) to catch function-local imports, since several of the
  hits (all of `_recurrence.py`'s and most of `_cli.py`'s nacl uses) are
  deferred imports inside functions, not module-level — an anchored-only
  grep would have under-counted these and could have produced a false "only
  N importers" claim.

---

## 2. Extras

`[project.optional-dependencies]` currently has 8 groups. Verified against
`pyproject.toml` directly (not assumed):

| Extra | Contents | Fate | Evidence |
| --- | --- | --- | --- |
| `dev` | pytest, pytest-cov, ruff, hypothesis, mypy, `types-PyYAML`, `types-jsonschema`, `types-python-dateutil`, `agent-suite-conformance==1.0.0` | **STAYS, trimmed** | `types-python-dateutil` should drop with `python-dateutil` (§1). `hypothesis` stays — it backs `tests/test_property_conformance.py`, which tests kernel invariants (claim contention, transition-sequence equivalence, replay equivalence) via `hypothesis.given`/`strategies` — see §4 note. `agent-suite-conformance` stays (generic CLI-contract conformance kit) but its existing fixture file exercises at least one to-be-removed CLI verb (`secrets --ref ...` in `tests/test_cli_conformance.py`) and needs per-case disposition, not a blanket keep. |
| `sidecar` | `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pydantic>=2.7`, `httpx>=0.27` | **DROPS ENTIRELY** | `plans/032-f0-dependency-map.md` §7 already rules this out (second auth/deployment product: own `TokenRegistry`, `AuthenticatedActor`, `require_admin`, `rate_limit`). Confirmed `httpx` has **zero** production imports anywhere in `src/regista` — its only purpose (per `.regista/worklog.md:1355`, "Added `httpx>=0.27` to `[sidecar]` extras for `TestClient` dependency") is as FastAPI `TestClient`'s transitive requirement for sidecar tests. Dropping `sidecar` drops all four packages. |
| `ed25519` | `PyNaCl>=1.5` | **DROPS ENTIRELY** | Redundant even today: `pynacl` is already an unconditional base dependency (§1), so this extra currently adds nothing (installing without it still gets PyNaCl). Once base `pynacl` is dropped, this extra has no reason to exist. README:227 documents it (`pip install regista[ed25519]` for the `ed25519` signing scheme) — that whole signing-scheme selection goes with trust removal. |
| `encryption` | `cryptography>=42.0` | **DROPS ENTIRELY** | `grep -rn "from cryptography" src/regista/` → only `_encryption.py` (`AESGCM`), imported only by `_testing.py` and `_version_info.py`. Field encryption is explicitly on the remove list ("Field encryption/custody integrations serving the removed evidence system... becomes an explicit operator responsibility"). **Flagged as referenced externally** — `agent-provenance`'s `pyproject.toml` declares `regista-hraedon[encryption]>=0.5.1,<0.6` (already `<0.6`, so unaffected by an 0.8.0 that drops the extra — see §2a). |
| `vendor-check` | `rfc8785==0.1.4` | **STAYS** | Used by exactly one test, `tests/test_plan008_ws3.py`, which cross-checks `regista._vendor.rfc8785` (the vendored RFC 8785 canonicalizer that `_jcs.py` wraps) against the real PyPI `rfc8785` package (`import rfc8785 as system`, skipped via `pytest.importorskip`-style marker when absent). `_jcs.py`/canonical serialization is explicitly permitted to remain ("Canonical serialization and consistency checks may remain"), and this is the correctness check for that vendored code — not trust machinery. Its only other consumers (`_reducer.py`, `_bundle_v3.py`, `tools/make_v6_vectors.py`, `tools/reducer_v1_sweep.py`) are trust/off-runtime-path and retire independently; they do not need to drag this extra down with them. |
| `vault` | `hvac>=2.0` | **DROPS ENTIRELY** | Sole consumer is `_secrets.py`'s Vault-backed secret-resolution backend (`_hvac()`, `try_register_azure()`-style registration) plus `_doctor.py` diagnostics for it. `_secrets.py` itself is entirely key-custody/secret-backend machinery (`file`/`windows`/`vault`/`azure`/`operator` backends for principal key material) — every importer of `_secrets.py` (`client_signer`, `_custody`, `_encryption`, `_keys`, `_provision`, `_cli` signing commands, `_doctor`) is trust-adjacent. CI comment at `.github/workflows/ci.yml:47-49` notes `vault` is installed today only "so the WI-228 AppRole tests actually run" — that test is on the trust surface. **Referenced by CI directly** (see §4) and by `docs/suite-config.md:57`. |
| `azure` | `azure-identity>=1.16`, `azure-keyvault-secrets>=4.8` | **DROPS ENTIRELY** | Same `_secrets.py` backend registry (`try_register_azure()` at `_secrets.py:1517-1589`). Referenced in `docs/suite-config.md:58`. |
| `windows` | `[]` (empty) | **DROPS** | Empty extra, exists only as a documentation marker for the DPAPI-backed `windows:` secret backend (`docs/suite-config.md:59,236-250`), which is one more `_secrets.py` custody backend on the remove list. Nothing to uninstall, but the extra name itself should be removed from `pyproject.toml` along with the feature it labels, or it becomes a dangling promise in `pip install regista[windows]`. |

**2a. Extras referenced by other repos (from `plans/032-f0-dependency-map.md`
§6, re-verified as still accurate for this packaging pass):**

| Repo | Specifier | Extra used | Safe against dropping the extra in 0.8.0? |
| --- | --- | --- | --- |
| `agent-provenance` | `regista-hraedon[encryption]>=0.5.1,<0.6` | `encryption` | **Yes** — pinned `<0.6`, will never resolve to 0.8.0 |
| (no other repo declares an extra) | — | — | — |

`agent-notes`, `dossier`, and `ad-steward` depend on plain `regista-hraedon`
with unbounded lower bounds (`>=0.5.x`) and use no extras — they are a
version-ceiling hazard (already flagged in the F0 map, out of scope for this
packaging pass) but not an extras hazard.

---

## 3. Entry points and packaged resources

**`[project.scripts]`:** one entry, `regista = "regista._cli:main"`. No other
console script is declared.

**But `[tool.hatch.build.targets.wheel]` packages the whole tree:**

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/regista"]

[tool.hatch.build.targets.wheel.force-include]
"migrations" = "regista/migrations"
```

`packages = ["src/regista"]` is a **directory** include with no exclude list
anywhere in `pyproject.toml` (`grep -n "exclude" pyproject.toml` → no hits;
there is no `MANIFEST.in` either). Hatchling will package every `.py` file
physically present under `src/regista/` regardless of whether `_cli.py`'s
command table references it or `__init__.py` re-exports it.

**Concretely, this means: trimming the CLI command table and the public
`__init__.py` re-exports is NOT sufficient to stop retired implementations
from shipping.** Two specific findings:

1. **`src/regista/sidecar/__main__.py` is a real alternate entry point
   today**, independent of `[project.scripts]`: it defines `main()` and an
   `if __name__ == "__main__":` guard, so `python -m regista.sidecar` starts
   the full HTTP sidecar (`create_app`, `TokenRegistry`) as long as `fastapi`/
   `uvicorn` happen to be importable in the environment. Dropping the
   `sidecar` extra from `pyproject.toml` does not remove this file from the
   wheel — it only stops `pip install regista-hraedon[sidecar]` from pulling
   FastAPI/uvicorn automatically. A user (or another package) that separately
   has FastAPI/uvicorn installed and runs `python -m regista.sidecar` would
   still reach it, and `import regista.sidecar` (or any trust module —
   `regista._bundle`, `regista._witness`, `regista._trust_log`, etc.) works
   from a fresh install with **no extras at all**, since none of them are
   extra-gated at the module level — extras only gate the third-party
   dependency, not the presence of the first-party module.
2. There is no packaging mechanism (module allowlist, `exclude`, separate
   package name) that would make an un-deleted trust module disappear from
   the built artifact. **The only way to satisfy Plan 032 F1's "wheels/sdists
   must not accidentally ship retired implementations as alternate entry
   points" is physical deletion of the files** (`_bundle*.py`, `_witness.py`,
   `_trust_log*.py`, `_genesis*.py`, `_estate_catalog.py`, `_custody.py`,
   `_keys.py`, `_signing*.py`, `_verification.py`, `_reducer.py`,
   `_principal_keys.py`, `principal_lifecycle.py`, `client_signer.py`,
   `_lineage.py`, `_lint.py`, `_encryption.py`, `_secrets.py`,
   `_recurrence*.py`, `_hooks*.py`, `_webhooks.py`, the whole `sidecar/`
   package, and the in-memory modules being retired) — not just severing
   imports into them, consistent with F1's own instruction to "remove dead
   callable paths, not just documentation."

**Non-`.py` packaged resources under `src/regista`:**

```
src/regista/py.typed
src/regista/_workflow_schema.json
src/regista/workflows/canonical.workflow.yaml
```

`py.typed` and `_workflow_schema.json` are kernel resources (typing marker;
the JSON-Schema used by `_workflow.py`'s validation) — keep as-is.
`workflows/canonical.workflow.yaml` needs a content check I did not perform
in depth: confirm it doesn't encode a trust/review workflow with model-lineage
or assurance states baked in (it is a *shipped example workflow*, not code,
so it is lower risk, but it should be read once before F1 ships it unchanged).

**Migrations packaging:**

`migrations/` (50 `*.sql` files, `001_initial.sql`…`050_...sql`) is
force-included into the wheel at `regista/migrations/`. The loader,
`src/regista/_migrations.py`:

- `discover_migrations()` globs `*.sql` under the installed `regista/migrations`
  directory (falling back to a sibling `../../migrations` for editable/dev
  installs), parses the leading `N_` as an integer version, and sorts — it is
  **agnostic to how many files exist or what they're named**, so replacing 50
  files with one fresh baseline (e.g. a single `001_baseline.sql`) is
  mechanically compatible with the runner as-is. No change to `_migrations.py`
  itself is required for F1's "fresh baseline instead of a migration chain."
- **What actually happens to an old (0.5–0.7.x) database when the migration
  set is replaced, traced through `_run_migrations_locked`
  (`_migrations.py:125-224`):** the drift-detector only compares a migration
  version if it is present in **both** the DB's `_regista_migrations` table
  and the current on-disk file set (`for version, path in all_migrations: if
  version not in applied: continue`). Two concrete outcomes depending on how
  the new baseline is numbered:
  - If the new baseline reuses an existing version number (e.g. ships a new
    `001_baseline.sql` with the kernel-only schema, replacing the old
    `001_initial.sql`), then on an old database version 1 is in `applied`
    (from the old run) and in `all_migrations` (from the new file) — the
    checksum comparison (`stored != current`) **will not match** (different
    file contents), and `_run_migrations_locked` raises `RegistaError`,
    `ErrorCode.MIGRATION_DRIFT`, **before running any SQL**. This happens to
    satisfy F1's "refuse unsupported schemas before writes; never
    automatically drop or reset them" — but it is an accidental side effect
    of checksum drift detection, not a designed "wrong-generation" refusal,
    and the error message ("has been modified after application") will be
    actively misleading to an operator hitting it on an old database.
  - If the new baseline instead uses a **fresh, previously-unused** version
    number (e.g. `100_baseline.sql`), an old database has no row for version
    100, so it is treated as **pending** and the loader will attempt to `CREATE
    TABLE events (...)` etc. against a schema that already has those objects —
    producing a raw Postgres "relation already exists" error instead of a
    clean, named refusal.
  - **Recommendation for F1:** don't rely on either accidental path. Add an
    explicit pre-flight check (e.g. detect trust-only tables like
    `principal_keys`/`project_identity`'s `NOT NULL trust_domain_id`, or a
    marker row) and raise a clearly-worded "unsupported/pre-0.8 schema,
    refusing without mutation" error before migrations run at all, independent
    of which version number the fresh baseline happens to pick.
- The old 50 files should not simply be deleted with no trace — F0's own plan
  (`plans/032-final-public-release.md` F4) calls for "a short preservation
  procedure" for pre-0.8 installations; consider keeping the retired SQL
  history out of the packaged `migrations/` directory but preserved somewhere
  in the repo (e.g. `migrations/historical/` or docs) so an operator restoring
  an old dump still has the schema history to consult, without it being part
  of what a fresh `0.8.0` install runs.

---

## 4. CI workflow

`.github/workflows/ci.yml` (133 lines) — one job matrix (`3.13`, `3.14`) plus
a separate `lockfile` job. Every step:

| Step | Disposition | Why |
| --- | --- | --- |
| Checkout (`fetch-depth: 0`) | **REWORK (shrink)** | Full history is fetched *specifically* because `docs/0.6.0/check-crossrefs.py` resolves `src/regista/....py:N` citations against a pinned historical commit (`334b995`) via `git show`. Once the 0.6.0 spec-consistency step (next row) is removed, shallow clone (`fetch-depth: 1`) is sufficient — this is a real, if small, CI-time win. |
| Set up Python (matrix 3.13/3.14) | **STAYS**, matrix choice tied to §5 below | |
| Install deps: `pip install -e ".[dev,vendor-check,sidecar,ed25519,encryption,vault]"` | **REWORK** | Shrinks to `.[dev,vendor-check]` per §2. The inline comment at line 47-49 ("vault included so the WI-228 AppRole tests actually run... without hvac they fail with ModuleNotFoundError") is itself evidence that `vault`/AppRole are trust-only test dependencies with no kernel fallback — those tests retire with the extra. |
| Identifier gate (`check_committed_identifiers.py`) | **STAYS** | Generic secret-scanning gate, unrelated to trust/kernel split |
| Lint (`ruff check`) | **STAYS** | Generic |
| **"0.6.0 specification set is internally consistent"** (`docs/0.6.0/check-crossrefs.py`, `check-conflicts.py`) | **DROPS** | Both scripts exist to validate the frozen 0.6.0 cryptographic-epoch spec set (`docs/0.6.0/ARCHITECTURE-0.6.0.md`, `BUNDLE-V3.md`, `EPOCH-RESET.md`, etc.) — trust/genesis/bundle-adjacent by name and by the scripts' own docstrings ("Gate 0 requires that every internal cross-reference resolves" for the 0.6.0 spec). Removing it also removes the `fetch-depth: 0` requirement above. |
| Type-check (`mypy`) | **STAYS** | Generic; scope shrinks automatically as files are deleted |
| Test + coverage (`pytest tests/ --cov=regista ...`) | **STAYS, scope shrinks** | Core gate; see §4 test-tree note below |
| **Epoch-debt ratchet** (`scripts/check-epoch-debt.py` against `tests/epoch_blocked_manifest.json`) | **DROPS** | Purpose-built for the "v6 ordinary-event writer (P1.7)" strict-xfail ledger (`pyproject.toml`'s own `epoch_blocked` marker docstring: "blocked on the v6 ordinary-event writer"). This entire ratchet — the marker, the manifest file, the ratified bootstrap SHA in the script, and the pytest marker itself — is v6/epoch machinery and retires with it. Currently reports zero debt (`"blocker": "none — WI-008 v6 action-delegation counterparts landed"`, `"entries": []`), so there is nothing live to migrate. |
| Slow tier (`pytest -m slow`) | **STAYS, REWORK** | The `slow` marker ("scale benchmarks, skipped by default") is generic and Plan 032 F3 item 6 explicitly requires "relevant scale checks" to keep running — but the current slow-tier test set needs the same per-file disposition as the rest of the tree (§ below), since some slow tests likely benchmark trust paths (bundle export, witness anchoring) that are going away. |
| `lockfile` job (`uv lock --check`) | **STAYS** | Generic, and load-bearing per this repo's own memory note (a stale `uv.lock` silently stopped matching `pyproject.toml` before this check existed) |

`.github/workflows/publish.yml` (114 lines) mirrors `ci.yml`'s install line
and needs the identical extras trim (`pip install -e
".[dev,vendor-check,sidecar,ed25519,encryption,vault]"` at line 64), plus it
pins Python at a **hardcoded `"3.14"`** for its `verify` job (line 60) rather
than a matrix — see §5. Its "Tag matches package version" and Postgres-service
steps are generic and stay unchanged.

**Services/env/secrets:** The Postgres 15 service (both workflows) stays —
kernel tests are Postgres-backed by design ("disposable PostgreSQL fixtures").
No environment variable or secret in either workflow is trust-specific by
name; `REGISTA_FORBIDDEN_IDENTIFIERS` (identifier gate) and the PyPI
publishing credentials (`pypi` environment / OIDC) are both orthogonal to the
kernel/trust split and stay.

**Test tree note (carried forward from `plans/032-f0-dependency-map.md` §4,
not re-derived here):** 125 of 185 test files (68%) name trust-stack concepts
by filename/content search; that is a ceiling, not a per-file verdict. Two
things I found in this pass worth adding to that inventory:
- `tests/test_property_conformance.py` uses `hypothesis` for genuinely kernel
  invariants (claim contention, transition-sequence equivalence, replay
  equivalence — `grep -n "def test_" tests/test_property_conformance.py`) but
  imports `_v6_fixtures.make_v6_keyset, open_v6_epoch` and `InMemoryRegista`
  (retiring backend) to set them up. This is a "port, don't retire" case: the
  properties are exactly what F2 must qualify, but the fixture plumbing needs
  replacing with the fresh unsigned-baseline setup.
- `tests/test_cli_conformance.py` (the `agent-suite-conformance` consumer)
  has at least one fixture case built around the `secrets` CLI verb
  (`argv=(*_CLI, "--json", "secrets", "--ref", ...)`), and `secrets` is one of
  the 10 trust CLI groups the F0 map already identified for removal — that
  case needs to go or be re-pointed at a retained verb.

**Current CI wall-clock:** `gh run list --branch main --limit 5` (all
`conclusion: success`, `name: CI`) gives run durations of 37m59s, 41m01s,
40m12s, 47m00s, and 34m05s — consistent with the "around 40 minutes" figure
Plan 032 should size the reduction against. Removing the 0.6.0 spec-consistency
step, the epoch-debt ratchet, and three extras' worth of dependency
installation (fastapi/uvicorn/pydantic/httpx, hvac, azure-identity/
azure-keyvault-secrets, cryptography) should shrink both install time and test
count, but I did not instrument a trial run to quantify the reduction — that
requires an actual F1 branch with the deletions applied, which is out of scope
for this analysis-only pass.

---

## 5. Version support

`pyproject.toml`: `requires-python = ">=3.11"`. `[tool.mypy]` pins
`python_version = "3.11"` for type-checking (i.e. mypy checks against the 3.11
stdlib surface even though nothing runs tests on 3.11).

Actual CI-tested versions:
- `ci.yml` matrix: `["3.13", "3.14"]` — **3.11 and 3.12 are never run in CI.**
- `publish.yml` `verify` job: hardcoded `"3.14"` only — the pre-tag gate tests
  exactly one interpreter, and it isn't the floor of the advertised range or
  even both matrix entries from `ci.yml`.

**Gap:** the package claims to support 3.11 and 3.12 (2 of the 4 versions in
the advertised range) with zero CI evidence either version installs, imports,
or passes tests. This is exactly the Plan 032 F0 item 5 mismatch ("Align the
advertised and tested range").

**A concrete reason this isn't just paperwork**, found while checking `nacl`
usage: `plans/032-f0-dependency-map.md` §2 already flagged that
`datetime.fromisoformat` parses malformed inputs differently across
interpreters (CPython 3.14 accepts `"...T24:00:00Z"` as next-midnight; 3.12,
3.13, and PyPy 3.11 raise) and attributed the finding to `_reducer.py`
(trust, off the runtime path, retiring). I re-checked which modules actually
call `fromisoformat` (`grep -rln "fromisoformat" src/regista/*.py`) and it is
**not confined to the retiring trust code**: `_contract.py`, `_types.py`,
`_workflow.py`, `_replay.py`, and `_cli.py` — all KERNEL, all retained — also
call it. So the interpreter-divergence hazard the F0 map surfaced is an input
to the *kernel's* supported range, not just a fact about deleted code.

**Recommendation:** narrow `requires-python` to what is actually exercised —
`>=3.13,<3.15` — and make `publish.yml`'s `verify` job match `ci.yml`'s matrix
(or at minimum test the floor of the declared range, 3.13, not just the
ceiling) so a tag can't publish on the strength of only the newest
interpreter. If 3.11/3.12 support is wanted for real, that requires adding
them to the CI matrix and exercising the `fromisoformat` hazard on each
before advertising it — which Plan 032 §5 explicitly rules out doing as "a new
provider/platform qualification programme" unless the maintainer chooses it.
Widening is more work than narrowing; narrowing to the tested set is the
default-compatible move.

---

## What I could not determine

- **Actual CI time saved by the F1 removals.** I have the current baseline
  (34–47 min across 5 runs) but did not run a trial build with the deletions
  applied, so I can't quantify the reduction — only enumerate which steps and
  extras go away.
- **Whether `src/regista/workflows/canonical.workflow.yaml`** (the one shipped
  example workflow resource) encodes any review/assurance states that
  reference model-lineage or trust concepts. I confirmed it exists and is
  packaged but did not read its full content against the removal list.
- **Whether `_observability.py`/`prometheus-client` is actually wanted in the
  MVP.** I found it is technically load-bearing in the retained kernel API
  (imported by `_work_items_api`, `_claims_api`, etc.), but Plan 032 §3 does
  not name metrics/observability one way or the other, so "KEEP" here is an
  evidence-based default, not a plan citation — flagging for the maintainer
  rather than asserting it.
- **The complete list of trust modules to physically delete.** §3 names the
  categories (bundle/witness/trust-log/genesis/estate-catalog/custody/keys/
  signing/verification/reducer/principal/lineage/lint/encryption/secrets/
  recurrence/hooks/webhooks/sidecar/in-memory-retiring), matching
  `plans/032-f0-dependency-map.md`'s module inventory, but I did not produce a
  final exhaustive file-by-file deletion list here — that inventory already
  exists in more detail in the F0 dependency map itself (§2-§3), and
  duplicating it file-for-file was outside this packaging-focused pass's
  scope.
- **Whether any *other* sibling repo than the five already identified in the
  F0 map** (`agent-notes`, `dossier`, `ad-steward`, `agent-provenance`,
  `agent-capability-broker`) declares a `regista-hraedon` dependency or
  extra. I re-verified the one extras-relevant case (`agent-provenance`'s
  `[encryption]<0.6` pin) but did not re-sweep the whole estate for new
  consumers since the F0 map's date (2026-09-17, same day) — treat that list
  as current only as of that sweep, not re-confirmed here.
- **Exact behavior of the drift-detector against a real 0.5.x/0.6.x/0.7.x
  database** (§3's migration-numbering analysis is a read of
  `_migrations.py`'s logic, not an executed test against a populated old
  schema). Plan 032 F3 item 5 requires exercising this with "representative
  0.5-era and 0.6/0.7-era schemas" — I traced the code path but did not stand
  up an old database to confirm the raised error empirically.
