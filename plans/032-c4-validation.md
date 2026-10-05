# Plan 032 C4 — final supply-chain findings

Artifact candidate: `4098196fdecf990fe8f2f788c7c9e84e0e2558dd`, on
`feat/wi364-f1-promote`. Kernel/CLI/schema code is unchanged from the verified C3
candidate. All tests and release-tool/workflow inputs are included in the qualified
sdist; Plan 032 evidence and reference docs are excluded from both artifacts.

| Finding | Change | Regression / mutation | Probe result |
| --- | --- | --- | --- |
| H1, already applied by coordinator | Read-only live rules/environment queries retained. Main requires a PR plus all 8 CI checks, without bypass; v* create/update/delete is admin-only; pypi requires hraedon, forbids admin bypass, allows main/v*. | Exact query JSON; no settings writes. Solo adaptations: 0 PR approvals and prevent_self_review false. | Matches owner-authorized settings; no second-person approval claim. |
| H2 | Guard immediately precedes immutable artifact upload. Hash-locked Twine runs in a separate contents-read job. Publish needs build and Twine and consumes build's original artifact. Verification/CI use uv.lock frozen; pip upgrade removed. Build and pip/uv rebuild tooling closures are also hash-locked in fresh venvs. Build summary shows both digests, SHA and tag; F5 requires rejection on any mismatch. | Upload adjacency, job permissions/dependencies, hash-required install, frozen verification and executable exact-hash summary regressions. Mutants c4_guard_upload_order, c4_twine_dependency, c4_tool_hashes, c4_frozen_verification and c4_summary_hashes are killed. | Fresh locked installations pass; corrupted dependency hashes and an omitted transitive pin each refuse with exit 1. No uvx remains in workflows. |
| M1 | Gzip re-encoding at qualified level 9 must equal the original bytes. Tar mtime, full mode, uid/gid, uname/gname, type, link/device fields and USTAR encoding are canonical; committed executable parity still applies. | Original envelope/metadata/root vectors plus c4_sdist_canonical_bytes. Both c4_gzip_encoding and c4_tar_metadata mutants are killed. | Original probe_rsc1 pristine passes; all 17 attacks refuse, including every formerly accepted variant. Authoritative CLI: pristine exit 0; all 17 attacks exit 2. |
| L1 | Invalid setup-uv architecture input removed everywhere; version/checksum retained. F5 records live settings, solo-owner approval and explicit merge → owner tag → tag build → hash comparison → approval → post-PyPI sequence. | Pin test rejects the invalid architecture input. Preflight regression now requires the new build/Twine chain. | 23 preflight/workflow tests passed. All eight jobs passed on source/evidence commit 4548ac2; exact run/jobs are recorded in F5. |

The complete tool locks are `.github/twine-requirements.txt` and
`.github/build-requirements.txt`; their `.in` files and generated command comments
record regeneration. uv 0.12.23 is bound by its official release-asset checksum. The
backend contract remains Hatchling 1.32.4 and its exact six-package closure; pip
26.2.1 is an additional hash-locked frontend. Project dependencies come from the
existing `uv.lock` via `uv sync --frozen --extra dev`.

Independent GPT-5.6 Sol investigation reproduced the baseline H2/M1 paths.
Independent read-only candidate review found no additional source/workflow bypass
or regression in `e4fab00..1806b97`. Its stale-draft F5 identity/hash finding was
corrected to the final qualified source and hashes. The follow-up commit changes
only the existing preflight test to assert the new dependency graph; it changes
no runtime or workflow behavior. Parent validation and full repeated qualification
cover that follow-up. [Review evidence](032-c4-source-review.json) separates the
reviewed source from the final test-only follow-up.

The first full attempt found a stale preflight assertion expecting publish to need
only build. It invalidated the F1 unmodified control. No kernel mutation evidence
from that attempt is accepted. Remaining obsolete-candidate suites were stopped
and their child databases dropped. The [first attempt](032-c4-first-attempt.json)
is retained, and qualification is repeated on `4098196`.

Evidence: [F3](032-f3-qualification.md), [F5](032-f5-release-prep.md),
[exact gate output](032-c4-final-gates.json),
[artifact/workflow mutants](032-c4-artifact-mutations.json),
[original supply-chain probe](032-c4-dv2-probes.json),
[tool-lock refusal probes](032-c4-tool-lock-probes.json),
[live GitHub protections](032-c4-live-protections.json),
[reviewer originals](032-c4-reviewer-probes.json),
[authoritative original tamper vectors](032-c4-authoritative-vectors.json),
and [supplemental recovery/race controls](032-c4-supplemental-probes.json).

No tracker write/claim or private provenance attachment is asserted. The user's
isolated worktree/branch is the working boundary. Only this branch may be pushed;
no tags, uploads, dispatches, settings changes or merge are authorized here.
Owner release approval, PyPI registration, D8 and private consumer disposition
remain separate release prerequisites.

## Qualified artifacts and local acceptance

| Artifact | SHA-256 |
| --- | --- |
| `regista_hraedon-0.8.0-py3-none-any.whl` | `224c1d11498016de71c881c71ab86593a128521de9134feda8d492fb753465d8` |
| `regista_hraedon-0.8.0.tar.gz` | `6a1341fef8cbd464281989115178beb6ebbecd8ca0369a7c7396828cb6094b99` |

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

All local gates passed. The 33 gate records include the expected missing-DSN
refusal and the externally observed collation-mutant kill. The sole locale skip
is documented in F3. Schema baseline-1 bytes and wheel bytes are unchanged.
Source/evidence commit `4548ac26aae6ef42306a28a87889a7a6acb0476a` passed all eight
jobs in [CI run 37381874233](https://github.com/hraedon/regista/actions/runs/37381874233).
[Exact job/step and gate evidence](032-c4-ci.json) records six 1,024-test suites,
67 subtests each, required missing-DSN refusal, installed smoke and the unchanged
schema/artifact guard. No invalid architecture-input warning occurred.
The [pushed-head rebuild](032-c4-final-head-artifacts.json) is byte-identical.
The final evidence-only follow-up also requires green CI, reported at handoff.
