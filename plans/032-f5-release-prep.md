# Plan 032 F5 — 0.8.0 release preparation (no publication)

Prepared 2026-10-05. **Exact candidate commit:
`8ff80ade3972311c6e6568f3afae415761a9a9ca`**, branch `feat/wi364-f1-promote`,
draft [PR #93](https://github.com/hraedon/regista/pull/93). Later evidence-only
commits on that branch do not change any packaged input. Do not infer publication
from the version bump: no tag, upload, workflow dispatch, yank or settings change
was authorized or performed.

## Qualified artifacts and metadata

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `80f5498d901aa8c52349a22e4354e540551e32da9f09768d11190573d0fddd04` |
| `regista_hraedon-0.8.0.tar.gz` | `1a2b25c8d38b1957bf113e88407279ed3754c5ec7f7913c54ea0e19ec830a8d2` |

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
(16 members including RECORD, including the committed baseline manifest). The sdist contains 69 regular members under its
single versioned root: retained source, examples/tests/scripts/hooks, CI,
publication declaration, README/metadata/license and test-operation files.
Retired migrations/sidecar implementations are absent. Current Git-only reference
docs and qualification reports are not distribution inputs. README is the wheel
long description; `uvx --from twine==7.0.0 twine check dist/*` passes for both artifacts.

## Tag workflow and byte equivalence

`.github/workflows/publish.yml` is triggered by a pushed **`v*` tag**. Its verify
job first requires merged origin/main ancestry and a fail-closed identifier scan,
then checks tagged package version against the tag, baseline/PyPI binding, lint,
types and the PostgreSQL suite on 3.14. The build job checks out the full tagged
history, sets up Python 3.14, runs `uv build` (sdist, then wheel from sdist), runs
`check-dist --authoritative` and `uvx --from twine==7.0.0 twine check`, and uploads `dist`. The publish
job downloads **that build job's artifacts** and runs
`uv publish --trusted-publishing always` in environment `pypi` with OIDC permission.
It does not rebuild in the publish job. A tag push is a publication action.

The build job **does rebuild**, rather than consuming a locally reviewed upload.
A fresh full-depth `git clone --no-local --no-hardlinks` of the artifact-bearing
tree, followed by the same `uv build`, produced **byte-identical wheel and sdist
SHA-256 hashes above**. C1 fixes and fresh packaged resources are included in this candidate. Rebuild tooling was uv 0.12.23
with the complete pinned Hatch backend closure in `pyproject.toml` (Hatchling
1.32.4). The [final gate record](032-c1-final-gates.json) records the after-last-edit build
and digest comparison; publication must still retain the qualified hashes.

The #65 guard additionally validates exact candidate members against committed
HEAD, schema pins, metadata/RECORD, names, archive structures and modes. It rebuilds
each sdist with **both pip and uv**, comparing **every wheel member's bytes and
mode**, including generated metadata. That is content/mode equivalence, not a
claim that arbitrary ZIP compression/timestamps give identical raw archives.
The observed fresh-clone raw hashes supply the stronger byte-identity evidence
for this candidate and tooling. Owner should compare the actual tag build's
downloaded artifact hashes again before permitting upload if tooling changes.
`check-dist: ok` was obtained under `env -i`, an empty HOME, replacement objects
off, no system/global git config, a full-depth independent clone and no alternates.

The ordinary CI matrix covers 3.11–3.14. Historical runs 37275016486 and
37276210043 predate C1 and do not qualify this candidate. The current local
3.14/3.11 suites and all exact gate results are in the C1 gate record; the owner
must confirm the selected commit's current four-version CI verdict before release.
All actions use full SHAs resolved from official tags. Every setup-uv step pins
0.12.23, x86_64 and its official platform checksum; twine is pinned to 7.0.0.
External branch/tag/environment settings remain owner-verification prerequisites.

## Owner-side prerequisites — must be confirmed by owner

These are the workflow comments' prerequisites, **not verified from this repo**:

- [ ] PyPI trusted publisher registered for the actual repository owner/name,
  workflow filename `publish.yml`, environment **`pypi`**, project
  **`regista-hraedon`**. Old #70 tag runs failed with `invalid-publisher`; repo
  source does not prove PyPI registration is now correct.
- [ ] GitHub `pypi` environment requires a reviewer, prevents self-review,
  disallows administrator bypass, and restricts deployment refs to **main** and
  **v*** tags. Owner confirms these effective settings.
- [ ] Main is protected, and the **v*** tag ruleset controls tag creation.
  Environment/ref protection must constrain modified workflows as the comments
  describe; an `if:` inside a modifiable workflow is not that boundary.
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

## Owner verification of tag-ruleset principals (C1)

Before creating a `v*` tag, the owner must inspect the actual tag ruleset and list
its allowed creation/bypass principals: only the designated release-owner account
and any explicitly approved release automation identity may create the release tag.
Tag update/delete permissions and bypasses must be restricted to those same named
principals, with separate owner authorization for changing an existing release tag.
Ordinary write collaborators, PR automation, broad teams and administrators must
have no implicit bypass; record the precise account/app/team identities and their
permissions at release approval. Protect main against direct pushes and require PR
review and passing CI. The `pypi` environment must require a separate reviewer,
prevent self-review and administrator bypass, and allow only main and protected
`v*` tags. No settings inspection or mutation is claimed by C1.

Repository verification fetches origin/main and requires the tag commit to be its
ancestor, checks tag/package version, and runs the fail-closed identifier scan before
building. This proves merged ancestry; it cannot prove reviewer identity, branch
ruleset enforcement or environment settings from repository source. The owner must
verify those external controls before authorizing a tag or upload.
