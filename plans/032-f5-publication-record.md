# Plan 032 F5: 0.8.0 publication record

**Published 2026-10-05** as `regista-hraedon==0.8.0`. The 90-day stabilization window runs to **2027-01-03** (D11).

## What was published
| | |
| --- | --- |
| Tag | `v0.8.0` (annotated, object `0877938`), pointing at merge commit `1465cc9b17147dbff4348efede44ad56627c0172` (PR #93). Its tree is identical to CI-green `f0edda7`, and differs from the qualified candidate `4098196` only under `plans/`, which isn't packaged. |
| Publish run | [37389600351](https://github.com/hraedon/regista/actions/runs/37389600351): verify, build, twine and publish all succeeded; the preflight was skipped (tag event). |
| Approval | The `pypi` environment deployment was approved by the owner (`hraedon`) with the comment "SHAs match, approved", after comparing the run-summary hashes with the qualified hashes. The coordinator did not approve it. |
| Wheel | `regista_hraedon-0.8.0-py3-none-any.whl`, SHA-256 `224c1d11498016de71c881c71ab86593a128521de9134feda8d492fb753465d8` |
| Sdist | `regista_hraedon-0.8.0.tar.gz`, SHA-256 `6a1341fef8cbd464281989115178beb6ebbecd8ca0369a7c7396828cb6094b99` |

Before tagging, the coordinator built the merge commit from a fresh clone and got exactly these hashes.

## Post-publication verification (F5 step 3), 2026-10-05
1. **PyPI metadata:** `https://pypi.org/pypi/regista-hraedon/0.8.0/json` reports version 0.8.0, `Requires-Python >=3.11`, runtime dependencies `jsonschema>=4.21`, `psycopg[binary]>=3.2,<4`, `psycopg-pool>=3.2,<4`, `pyyaml>=6.0`, and both filenames, with SHA-256 digests equal to the qualified hashes.
2. **Independent download:** both files were downloaded from their PyPI URLs, and `sha256sum` matches the qualified hashes exactly.
3. **Fresh install from PyPI:** an empty directory and a fresh venv ran `python -m pip install --no-cache-dir --index-url https://pypi.org/simple regista-hraedon==0.8.0` and installed 0.8.0 into site-packages. `regista --help` works. Against Debian PostgreSQL 15 (`en_US.utf8`): initialize an absent schema → register a workflow → create → claim → transition to `done` succeeded, and the schema was dropped afterwards.
4. **#65 guard PyPI binding:** at `origin/main`, `verify-baseline: ok`, and `verify-ledger: ok` **with a real published-wheel binding**: `build_releases()` downloaded the 0.8.0 wheel and bound it to kernel schema version 1, `schema.sql` SHA-256 `4bc366e7bda1…`, which equals the committed version-1 pin. The first `verify-ledger` run, seconds after upload, printed the prepublication message because a stale PyPI CDN response hadn't caught up yet. Three re-runs shortly afterwards bound correctly. `check-release --version 0.8.0` now refuses ("already published"), as intended.

## Live release protections at publication
- Environment `pypi`: required reviewer `hraedon`, admin bypass off, deploy refs = branch `main` and tag `v*`. `prevent_self_review` is off (solo maintainer).
- Ruleset 24537019: `main` changes only through PRs, with the 8 CI checks required and no force-push or deletion; 0 approvals required (solo maintainer).
- Ruleset 24537020: creating, updating or deleting a `v*` tag is restricted to the repository admin role.

## Follow-ups
- **D12 yanks:** yank 0.5.1–0.6.0 (no consumer resolves to them). **Keep 0.7.0–0.7.2** until the frozen consumers (agent-notes, dossier, agent-provenance, agent-capability-broker, ad-steward; all `>=0.7,<0.8` or similar) are pinned to `==0.7.2` or retired. PEP 592 installers skip yanked versions except for exact pins, so yanking 0.7.x now would break fresh installs of those tools. Yanking is an owner action on pypi.org.
- The PyPI long description is the README as uploaded, which predates the dated maintenance window. The dates are in this record, the changelog and the GitHub README.
