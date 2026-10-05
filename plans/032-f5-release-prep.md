# Plan 032 F5 — 0.8.0 release preparation (no publication)

Prepared 2026-10-05. **Exact candidate commit:
`4098196fdecf990fe8f2f788c7c9e84e0e2558dd`**, branch `feat/wi364-f1-promote`,
draft [PR #93](https://github.com/hraedon/regista/pull/93). Later evidence-only
commits on that branch do not change any packaged input. Do not infer publication
from the version bump: no tag, upload, workflow dispatch, yank or settings change
was authorized or performed.

## Qualified artifacts and metadata

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `224c1d11498016de71c881c71ab86593a128521de9134feda8d492fb753465d8` |
| `regista_hraedon-0.8.0.tar.gz` | `6a1341fef8cbd464281989115178beb6ebbecd8ca0369a7c7396828cb6094b99` |

[F3 qualification](032-f3-qualification.md) records clean wheel/sdist installs,
installed resources/scenarios, restart, rollback/contention, terminated-worker
fencing, whole-namespace replay, separate restore **plus another valid write**,
and unchanged old schemas built from `84bb2ec` migrations.

Metadata inspection found Name `regista-hraedon`, Version `0.8.0`, Requires-Python
`>=3.11`, Python classifiers 3/3.11/3.12/3.13/3.14 and only the `dev` extra.
Runtime dependencies are `psycopg[binary]>=3.2,<4`, `psycopg-pool>=3.2,<4`,
`pyyaml>=6.0`, and `jsonschema>=4.21`. `pyproject.toml` and `uv.lock` agree;
there is no package `__version__` to bump. Remaining 0.7.2 literals are historical
refusal/test vectors, preservation guidance or old release history, not current
version declarations. `uv lock --check` passes. No speculative Python upper cap
was added (D13).

The wheel contains the explicit facade, kernel, CLI, `py.typed`, both schema
resources, four example script/YAML resources, entry point, metadata and license
(16 members including RECORD, including the committed baseline manifest). The sdist contains 75 regular members under its
single versioned root: retained source, examples/tests/scripts/hooks, CI,
publication declaration, README/metadata/license and test-operation files.
Retired migrations/sidecar implementations are absent. Current Git-only reference
docs and qualification reports are not distribution inputs. README is the wheel
long description. Twine 7.0.0 runs from the complete hash-locked closure in
`.github/twine-requirements.txt`, installed in a fresh venv with `--require-hashes`.

## Tag workflow and byte equivalence

`.github/workflows/publish.yml` is triggered by a pushed **`v*` tag**. Its verify
job requires merged origin/main ancestry and a fail-closed identifier scan, then
checks tag/package version, baseline/PyPI binding, lint, types and PostgreSQL tests
on 3.14. Verification and kernel CI install `uv.lock` with
`uv sync --frozen --extra dev`; there is no latest-pip upgrade or unlocked dev install.

The build job installs `.github/build-requirements.txt` with `--require-hashes`
into a fresh venv, then runs `uv build --no-build-isolation` with that interpreter.
Both authoritative pip/uv sdist rebuilds also install that hash-locked closure into
fresh venvs. The build job writes commit SHA, tag and wheel/sdist SHA-256 hashes to
`$GITHUB_STEP_SUMMARY`, then runs `check-dist --authoritative`. Its **immediately
following step** uploads immutable artifact `dist`; no Python tooling runs in
between. A separate `twine` job (`contents: read`, no OIDC or environment) downloads
that artifact and checks metadata using the hash-locked Twine venv. Publish needs
**both build and twine**, downloads the original build artifact, and runs
`uv publish --trusted-publishing always` in environment `pypi`. It does not rebuild.
A tag push is a publication action.

The build job **does rebuild**, rather than consuming a locally reviewed upload.
A fresh full-depth `git clone --no-local --no-hardlinks` of the artifact-bearing
tree, followed by the same `uv build`, produced **byte-identical wheel and sdist
SHA-256 hashes above**. C1 fixes, C2 connection admission and C3 locale-independent
catalog ordering are included in this candidate.
C4 also includes the verified C1–C3 fixes. Its sdist changes because the
release workflows, tool locks, guard and regressions are distribution inputs.
The wheel hash is unchanged. Evidence-only follow-ups exclude all packaged paths.
Rebuild tooling was uv 0.12.23 with the complete pinned Hatch backend closure
in `pyproject.toml` (Hatchling
1.32.4). The [final gate record](032-c4-final-gates.json) records the after-last-edit build
and digest comparison; publication must still retain the qualified hashes.

The #65 guard binds candidate members to committed HEAD, schema pins,
metadata/RECORD, archive names/structures and modes. The sdist must be exactly the
qualified gzip encoding: mtime `1580601600`, no filename/optional fields, level 9,
XFL 2 and OS 255, with byte equality after re-encoding. Every tar member has that
mtime, zero uid/gid, empty uname/gname/linkname, regular type `0`, zero device
fields and mode `0644` or `0755` matching the committed executable bit. It rebuilds
each sdist with **pip and uv**, comparing every wheel member's bytes and mode,
including metadata. This does not claim arbitrary wheel ZIP encodings have equal
raw hashes. Exact raw SHA-256 equality is also a mandatory human approval gate.
A changed compression implementation must be requalified; the guard fails closed.

The matrix covers Python 3.11–3.14 on Debian PostgreSQL 15, plus Python 3.14 on
PostgreSQL 16 and 17. C3's final CI run at `e4fab00367ef3a36e4310b9f0ba318befb12254a`
was [37372407234](https://github.com/hraedon/regista/actions/runs/37372407234),
**success on all eight jobs**. C4 source/evidence commit
`4548ac26aae6ef42306a28a87889a7a6acb0476a` passed
[CI run 37381874233](https://github.com/hraedon/regista/actions/runs/37381874233)
on **all eight jobs**. Its fresh full-depth independent clone also rebuilt both
qualified archives byte-identically and passed the authoritative guard.
[Exact CI job/step results and gate output](032-c4-ci.json) and
[pushed-head artifact evidence](032-c4-final-head-artifacts.json) are retained.
This document's later evidence-only update changes no packaged input; the latest
PR head's CI is checked again and reported at handoff before declaring C4 complete.

| C4 CI job | Verdict |
| --- | --- |
| Schema baseline and reviewed artifacts are immutable | **success** |
| Kernel (Python 3.11, PostgreSQL 15) | **success** |
| Kernel (Python 3.12, PostgreSQL 15) | **success** |
| Kernel (Python 3.14, PostgreSQL 16) | **success** |
| Kernel (Python 3.14, PostgreSQL 17) | **success** |
| Lockfile is current | **success** |
| Kernel (Python 3.14, PostgreSQL 15) | **success** |
| Kernel (Python 3.13, PostgreSQL 15) | **success** |
All actions use full official-tag SHAs. Every setup-uv step pins version 0.12.23
and its official x86_64 Linux release-asset checksum. The action has no `architecture` input;
that invalid input is removed. The checksum fails closed for a different release asset.

## Live GitHub protections — read-only C4 evidence

Queried with `gh api repos/hraedon/regista/rulesets`,
`gh api repos/hraedon/regista/rules/branches/main`, and
`gh api repos/hraedon/regista/environments/pypi`; details also came from each
ruleset's endpoint and `environments/pypi/deployment-branch-policies`.
Exact JSON and query timestamps are in [C4 live protection evidence](032-c4-live-protections.json).
No settings were changed by this agent; the coordinator applied H1 with owner authorization.

- Active branch ruleset **24537019** targets default branch main, forbids deletion
  and non-fast-forward updates, requires a PR and all eight named CI checks.
  There are no bypass actors. PRs need **0 approvals**, not an independent PR vote;
  strict/up-to-date status policy is off. See the evidence for each check context.
- Active tag ruleset **24537020** targets `refs/tags/v*`, restricting creation,
  update and deletion. Its sole bypass is RepositoryRole **5 (administrators)**,
  mode `always`, deliberately authorized by the owner. This is an admin-role
  release boundary, not a separately verified named-account allowlist.
- Environment **pypi** requires user reviewer **hraedon** (id 9434186), with
  `can_admins_bypass: false`. Custom deployment policies are branch **main** and
  tag **v***. **`prevent_self_review: false`** is the solo-maintainer adaptation.
  Independent approval is the owner's deliberate approval click after comparing
  both build-summary hashes; it is not a second-person separation guarantee.

## Authorized-owner release sequence

1. Review and merge PR #93 only after the exact pushed commit's eight CI jobs are green.
2. The owner tags **the merge commit** `v0.8.0` and pushes it, under separate release
   authorization. If the merge changes any distribution input, requalify and update
   F3/F5 first; the qualified commit must describe the merge's packaged inputs.
3. The tag workflow verifies and builds. Open the build job's step summary from
   the workflow run associated with the pending `pypi` deployment. It lists the
   commit SHA, tag and both artifact SHA-256 hashes. Confirm SHA/tag identify the
   intended merge commit/release and build and Twine jobs both passed.
4. **The owner compares BOTH summary hashes with the qualified hashes in this
   document before approving. Reject the deployment on ANY mismatch.** Investigate
   and requalify instead of accepting an unexplained rebuild difference.
5. Only after that comparison, the owner explicitly approves the **pypi** deployment.
   Publish uploads the build job's immutable artifact.
6. Perform the post-PyPI checks below before declaring the release complete.

## Owner-side prerequisites — must be confirmed by owner

Live GitHub controls above are verified at the recorded query time. These remaining
owner prerequisites are outside this preparation:

- [ ] PyPI trusted publisher registered for the actual repository owner/name,
  workflow filename `publish.yml`, environment **`pypi`**, project
  **`regista-hraedon`**. Old #70 tag runs failed with `invalid-publisher`; repo
  source does not prove PyPI registration is now correct.
- [ ] Review the exact candidate and the three already supplied cross-lineage
  kernel reviews/fixes; confirm final CI and artifact hashes before publication.
- [ ] Resolve D8's remaining human quickstart walkthrough, or explicitly record
  the owner's disposition. The preserved
  [D8 report](032-f0-inventory/d8-quickstart-walkthrough.md) is **partial**, and
  `032-open-decisions.md` still calls it open. Tested snippets and package runs
  do not substitute for that unfamiliar person's experience.
- [ ] Confirm the D9 private-estate checkout pin/caps in their own workstream
  before reducing main. This preparation makes no private-repository change and
  does not assert the historical unpushed correction was delivered.
- [ ] If desired, separately authorize the workflow's OIDC preflight dispatch.
  **No dispatch was performed here**, including the uploads-nothing preflight.
- [ ] Explicitly authorize publication/tag push. Set the 0.8.0 changelog/release
  publication date and **stabilization end date = publication date + 90 days**
  (D11); candidate notes remain `Unreleased`. GitHub issues are the public
  reporting route and plm@hraedon.com is the private sensitive-report route.
- [ ] Separately decide/authorize the [D12 yank recommendations](032-d12-yank-assessment.md).
  Yanking older Regista releases is recommended where possible, **non-blocking**;
  no unrelated `substrate` SDK file should be yanked on this assessment.

## Post-publication verification — owner-authorized release step

1. Read `https://pypi.org/pypi/regista-hraedon/0.8.0/json`; verify project/version,
   dependency/classifier/Requires-Python metadata, filenames and both SHA-256
   digests against the qualified/tag-build artifacts. Download the wheel and
   sdist and compute their digests independently; a metadata digest alone is
   not an independent download check.
2. From an empty directory and fresh venv, install explicitly from PyPI:
   `python -m pip install --no-cache-dir --index-url https://pypi.org/simple
   regista-hraedon==0.8.0`. Verify installed metadata/import path, `regista --help`,
   schema resources, and a disposable-database example/read/write. Use no source
   checkout or private configuration on the import path.
3. Run #65's live PyPI binding from the candidate checkout:
   `python scripts/check_published_migrations.py verify-ledger` and
   `python scripts/check_published_migrations.py check-release --version 0.8.0`.
   Require a successful **published-wheel binding**; the current prepublication
   message `no published 0.8.x release yet; PyPI binding not applicable` is not
   acceptable after uploading 0.8.0. Also rerun `verify-baseline` and the
   authoritative artifact guard on the exact downloaded/build bytes as appropriate.
4. Only then declare publication complete and record public artifact hashes,
   maintenance dates and the owner's yank disposition. None of these
   post-publication actions was performed during this preparation.

## Scope of external assurance

The ancestry check proves the tag commit is reachable from origin/main; it cannot
prove reviewer identity or historical approval from Git alone. The live GitHub
rules and the explicit owner approval with hash comparison supply the publication
boundary. Recheck live protections before release, including the admin role's
actual members. PyPI trusted-publisher registration remains owner verification.
