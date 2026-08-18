# Suite reconciliation at the epoch boundary

**Status: RATIFIED 2026-08-16.** Owner ratified D1/D2/D3 ("Your D1/2/3
suggestions seem reasonable to me: please run a manual review using sol and
then proceed as suggested"), conditioned on a cross-lineage design review:
**openai/gpt-5.6-sol, seven rounds in session ses_ff2403264ffeK0BSJ1evKP5gAZ,
final verdict PASS with zero findings** ("the reconciliation policy and
enforcement mechanism are sound for the stated scope"). The mechanics
evolved substantially through the review rounds within the ratified
direction — the misassigned P1.3 blocker became the new P1.7 package, the
P1.4 retirement population was added, module-level skip became exact-node
strict xfail with structural form pinning, and the debt and retirement
records became machine-enforced (set ratchet, target-branch inventory
anchor, manifest-independent slow lane). **The §2.1/§2.2 enforcement
mechanism is implemented on this branch** (commits 17ddc82…e2381f8);
the RETIRE-v5 per-test triage, P1.7 itself, and D2 execution are
downstream, gated by these mechanisms. EPOCH-RESET decides the *data*
disposition ("discarded, not migrated");
no document decides the *test* disposition — the **881 epoch-caused test
failures** (fact 3; the historically quoted 892 was contaminated, and the
slow tier adds 7) are an undocumented consequence of a documented decision.
This document exists to make that consequence a decision.

## 1. Facts the proposal rests on

Verified at 88e44b8 and independently re-verified by the design review; none
of these are judgment calls.

1. **No legacy append can succeed, even after genesis.** `check_legacy_append`
   and `_admit_legacy_append_after_lock` (`src/regista/_genesis.py`) raise on
   every branch: `GENESIS_REQUIRED` before genesis, `V6_EPOCH_OPEN` after.
   PR #40's own tests assert this (`tests/test_genesis.py`). Therefore **"fix
   the fixtures to open genesis first" reconciles nothing** — it converts one
   refusal into another. Reconciliation is blocked on the v6 ordinary-event
   writer, which **no current plan package owns** (see §2.0).
2. **The in-memory backend fails closed entirely, by design.**
   `InMemoryEventStore` refuses unconditionally; README pins it as
   "legacy-only test backend … fails closed in the clean epoch **until it
   gains an equivalent v6 genesis implementation**" — conditional, not
   permanent.
3. **The failure surface is exactly the event-writing tests — 881 nodes,
   each empirically traced to the epoch boundary.** A clean full-suite run at
   the branch head with **all extras installed** (see §5) yields 848 failures
   + 26 errors / 2160 passed / 18 skipped in the default tier, plus **7 of
   the 11 slow-marked tests** (round-4 B6: the `-m 'not slow'` addopts had
   hidden the slow tier from the original accounting; an explicit `-m slow`
   pass at the tip plus its own guard-reverted control classified it — the
   8th slow failure, `test_cross_interpreter_sweep_if_alternates_available`,
   fails identically on pre-#40 main and under reversion: pre-existing, not
   epoch debt, excluded). Total manifest population: **881** — **849
   `direct`** (the live exception is the `RegistaError` refusal itself) and
   **32 `indirect`**: the refusal reaches the test through a boundary
   (fixture setup, the sidecar's HTTP 409 mapping, CLI subprocess output
   asserted on, assert-wrapped concurrency errors, downstream empty-state
   asserts). The direct/indirect split was **live-validated** by the form
   validator (§2.1) across full-suite passes, which caught three boundary
   nodes that text classification had over-marked as direct. Every one of
   the 881 is proven epoch-caused by the guard-reverted control runs (§5).
   The
   historically quoted **892/1977/97/26 was contaminated**: 72 of its
   failures (and 79 of its skips) were missing-optional-extras artifacts of a
   `--extra dev`-only environment, not epoch refusals. Passing tests are the
   ones that never append events — a **test-level** property, not a
   module-level one: affected modules also contain read-only tests that pass
   today and must keep running.
4. **Key material is a second, independent blocker.** Genesis requires an
   active Ed25519 actor-role keyset bound to the envelope principal; the
   shared `tests/test_keys.json` is a single HMAC key with no
   `principal_id`/`role`. Every legacy fixture's key material is unusable in
   the clean epoch.

## 2. The proposal

### 2.0 P1.7 — the writer gets an owner (new plan package)

The original draft assigned the ordinary-event writer, the Ed25519
test-keyset work, and the manifest-emptying criterion to P1.3. That was
wrong: P1.3's amended scope is the consolidated v6 `VerificationResult` and
nothing else (IMPLEMENTATION-PLAN §P1.3), and no other package owns ordinary
v6 writes. The proposal therefore adds:

> **P1.7 — v6 ordinary-event writer** · owner: team · dep: P1.1, P1.2,
> P1.4, P2.2, P2.3 (implementations) + P2.1 **contracts** — explicitly not
> the owner-executed trust-root ceremony. The **workflow-registration and
> producer-authorization admission checks are implemented by P1.7 itself**;
> no other package owns them. Deliverables: the post-genesis v6 append path
> behind those gates; the shared Ed25519 actor-role test keyset and genesis
> test fixture; emptying the `epoch_blocked` manifest (§2.1). **Done when:**
> the manifest is **literally empty** (its `retires_with: P1.4` entries are
> already gone via the P1.4 dependency), the retired-test ledger (§2.2)
> accounts for every node that did not return, and the suite is green with
> no epoch-blocked entries remaining.
>
> **AMENDED 2026-08-18 (owner-approved; IMPLEMENTATION-PLAN.md P1.7 carries the full
> record).** The emptying criterion is evaluated at the **joint completion of P1.7 and
> WI-287**: 167 of the manifest's nodes are blocked by the in-memory backend's epoch
> refusal — §2.3's D2 territory, decided as WI-287 after this wording was ratified — and
> P1.7 owns only the Postgres-blocked population. Ledger and green-suite clauses unchanged.

In the plan's gate graph P1.7 is sequenced **inside Gate 1's closure**, and
**Gate 3 (quiesced rehearsal) explicitly depends on P1.7** — the rehearsal
and cutover cannot complete without the ordinary writer. D3 accordingly
attaches to P1.7, not P1.3.

### 2.1 BLOCKED-ON-P1.7 — exact-node **strict xfail** with a machine-checked manifest

Tests of functionality that survives the epoch reset are **kept** and marked
**strict-xfail by exact node ID**, never by module — affected modules contain
passing read-only tests that continue to run unmarked. Mechanics:

- **Manifest**: a committed, machine-readable inventory
  (`tests/epoch_blocked_manifest.json`) listing the exact node IDs proven
  epoch-caused at the reconciliation commit (membership criterion in §5) —
  not from judgment. Each entry carries its `cause` (`direct` — failure text
  is the refusal; `indirect` — downstream presentation with committed causal
  evidence).
- **Mark application**: a `pytest_collection_modifyitems` hook in
  `tests/conftest.py` applies `pytest.mark.xfail(strict=True, reason=…P1.7…)`
  to exactly the manifest's nodes. (A bare marker registration alone would
  neither xfail nor skip; the hook is the mechanism.)
- **Failure-form pinning** (design-review rounds 3-4 B1): every manifest
  entry records its expected failure form **structurally** — the exception
  class for all entries; for `direct` entries additionally the refusal code
  compared against the structured `RegistaError.code` (not text, which would
  accept an unrelated error whose message merely mentions the code); for
  `indirect` entries the observed failure signature (e.g.
  `assert 409 == 200`, `KeyError: 'work_item'`). A
  `pytest_runtest_makereport` validator (an explicitly **outermost**
  `tryfirst` wrapper, so it always sees the finished XFAIL report) compares
  each XFAIL against the recorded form and **converts a changed failure mode
  into honest red** — strict xfail alone would absorb an unrelated new
  failure as XFAIL. `raises=` is not used: it can pin only a class. The
  validator's deny cases are proven in `tests/test_epoch_blocked_meta.py`
  both against the pure matcher and **end-to-end through the real hooks**
  (a synthetic mini-project where a matched form XFAILs and a changed form
  exits red with the validator section).
- **Why strict xfail and not skip** (corrects the previous revision, which
  wrongly claimed fixture-phase errors escape xfail — an empirical probe on
  this repo's pytest 9.1.1 shows fixture-phase exceptions report as XFAIL
  under both bare and `raises=` marks): blocked tests **keep running**, so
  the moment any node starts passing, `strict=True` turns the XPASS into a
  suite failure — the manifest must shrink in the same change. Debt
  reduction is machine-forced, with no separate probe lane to maintain. The
  cost is runtime: the blocked nodes execute and fail fast at the refusal;
  the measured full-suite wall time at the branch head is ~5.5 minutes,
  which is acceptable.
- **Meta-test enforcement**, all machine-checked:
  1. every manifest node ID must exist in the current collection (a renamed
     or deleted blocked test is loud, not silently absorbed);
  2. **shrink-only ratchet over node SETS with an external baseline**
     (round-4 B3: a count-only ratchet would allow one-for-one debt
     replacement): `scripts/check-epoch-debt.py` in CI fails if any node in
     the PR's manifest is absent from the **target branch's** manifest —
     entries can only be removed, never swapped. **Bootstrap rule**
     (round-3 B2 + round-4 B3): when the base ref has no manifest — true
     exactly once, for the establishing reconciliation PR — the manifest
     file's **sha256 must equal the ratified digest** pinned in the script;
     neither an arbitrary set nor an arbitrary same-size set can bootstrap.
     CI base ref: the PR's target branch for pull requests, the pre-push tip
     (`github.event.before`) for pushes to main (round-4 B4: `origin/main`
     on a push would compare the commit to itself). The same CI check
     enforces **inventory immutability against the target branch** (round-5
     B5): `tests/epoch_blocked_inventory.txt` must be byte-identical to the
     base ref's copy — an in-repo hash pin alone could be edited in the same
     PR as its bypass; the target branch cannot. Locally, the meta-test
     asserts the count never exceeds the ratified 881. New epoch-blocked
     entries require a ratified amendment here, not a manifest edit;
  3. **the whole slow tier executes in CI, independent of manifest
     membership** (round-5 B6; round-6 B1): the default lane inherits
     `-m 'not slow'`, so a dedicated CI step runs `pytest -m slow` with a
     single explicit deselect (the documented pre-existing failure, §5).
     *(Successor note, 2026-08-17: the deselect is removed — WI-288 fixed
     the sweep harness's interpreter resolution and the node passes
     unmarked. The manifest-independence mechanism below is unchanged.)*
     Selection deliberately does NOT key off the `epoch_blocked` marker —
     if it did, a still-failing slow node *removed* from the manifest would
     execute nowhere (shrink allowed by the ratchet, excluded from both
     lanes); manifest-independent selection makes a removed slow entry run
     unmarked and prove it passes;
  4. no test outside the manifest may fail with
     `GENESIS_REQUIRED`/`V6_EPOCH_OPEN` — ordinary red CI enforces it, and
     the meta-test documents that this is the enforcement.

**Manifest-bearing green is not "suite green" (design-review B4):** the
manifest count is a machine-readable debt figure with three bindings:

- CI publishes the count as a visible per-run output (step summary);
- **no assurance, release-readiness, or agent "verified" claim may cite the
  suite as green without carrying the debt count** — a manifest-bearing
  suite result satisfies no "suite green" precondition anywhere in the
  estate unless the claim states `green-with-epoch-debt(N)`. Pre-release
  artifacts may ship carrying the figure;
- **the release gate refuses to cut any final (non-pre-release) 0.6.x
  release while the manifest is nonempty** — regista has no separate
  release workflow (releases are version bumps whose CI runs this suite),
  so the gate is a meta-test
  (`tests/test_epoch_blocked_meta.py::test_final_060_release_refuses_nonempty_manifest`):
  a final `>= 0.6.0` version in `pyproject.toml` with entries outstanding
  is a failing suite, wherever the release is cut.

### 2.2 RETIRE — per-test, recorded in a machine-checked ledger

Two retirement populations, one mechanism:

- **RETIRE-v5**: tests whose subject is v5/HMAC mechanics the epoch reset
  deletes (v5 envelope construction, HMAC scheme selection, the v5
  chain-hash domain). Candidates concentrate in `test_signing`,
  `test_wi267_row_authentication`, `test_hash_chain`,
  `test_global_event_chain`, `test_plan024_global_chain`, and parts of
  `test_signing_ed25519` — but the retire boundary is **per-test, not
  per-module**: those modules also assert invariants (row authentication,
  chain integrity) that reappear in v6 form.
- **RETIRE-P1.4** (added by the design review): tests of subsystems P1.4
  deletes outright — `_anchoring.py`, `_timestamping.py`,
  `_archive_segments.py`, and the window/segment/manifest machinery in
  `_bundle.py`, "and their tests" (IMPLEMENTATION-PLAN §P1.4). Affected
  modules include `test_anchoring`, `test_timestamping`,
  `test_archive_segments`, `test_webhooks_archive`, and parts of
  `test_bundle` and `test_witness_integration`. Until P1.4 executes they
  ride the §2.1 manifest under an explicit `retires_with: P1.4` field;
  **P1.4's execution removes them** (into the ledger, disposition
  `deleted_by: P1.4`), and because **P1.7 depends on P1.4** (plan dep line),
  P1.7's "manifest literally empty" criterion is evaluated only after those
  entries are already gone — no arithmetic exclusion, no ambiguity between
  the plan's and this document's acceptance wording.

**Enforcement (design-review B5) — the ledger is checked, not aspirational:**

- `tests/retired_tests_ledger.json`, committed, keyed by **exact former node
  ID**, each entry carrying a disposition: `dies_with_v5`,
  `deleted_by: P1.4`, or `coverage_owed: <work item>` for invariants that
  reappear in v6.
- The full pre-reconciliation collection inventory (from the §5 run
  artifact) is committed beside it. A validator test asserts: **every node
  in the pre-inventory is either still collected, or listed in the
  epoch-blocked manifest, or present in the ledger.** A test cannot vanish
  from the suite without a recorded disposition — deletion without a ledger
  entry is a failing meta-test, not a review-time hope.
- Per-test triage of the RETIRE-v5 candidates (65 defs in
  `test_wi267_row_authentication` alone) is **completed before any deletion
  lands**; wholesale module deletion inside the reconciliation is refused by
  the validator by construction.

### 2.3 C3 / in-memory backend — owner decision D2

C3 (11 modules / 384 defs: assurance, review validators, lineage — the
EPOCH-RESET §5 genesis preconditions, i.e. the surviving core) runs on the
backend that fails closed by design. Options:

- **(a) v6 parity for `InMemoryRegista`** — **recommended**, sized as its own
  work item beside P1.7, **with the parity boundary specified (design-review
  B6)**: a shared semantic conformance suite (envelope validation, signing,
  sequencing, admission-state machine) parametrized over both backends,
  while locking, rollback, persistence, and concurrency/races remain
  **Postgres-only** — `InMemoryEventStore` has no transactional machinery
  and cannot fake it. **In-memory success never satisfies a Postgres-gated
  acceptance criterion**; the conformance split is what prevents an
  in-memory placeholder from laundering gate claims. This is consistent with
  the README's own "until it gains an equivalent v6 genesis implementation".
- **(b) Port C3 to Postgres** — no in-memory v6 implementation to maintain,
  but ~384 defs move to the slow tier and the backend is then retired.

Until D2 is decided, C3's failing nodes ride the §2.1 manifest under their
own section.

## 3. Merge ordering

**The gate and the reconciliation enter main together; neither merges red.**
Per design-review NB3, atomicity does not require identity: the
reconciliation (manifest, hook, meta-tests, ledger, retire tranche) lands as
a **stacked PR on #40**, keeping #40's substantive gate diff reviewable on
its own, and **the stacked PR is the merge vehicle** — its merge brings both
into main atomically with green CI at the merged tip. Merging #40 alone
(red) stays forbidden. #41 (docs) follows unchanged. The Ed25519 test-keyset
work belongs to P1.7 (§2.0), not to the reconciliation PR.

## 4. Owner decision points

- **D1** — ratify the taxonomy: BLOCKED-ON-P1.7 **exact-node strict xfail**
  with form pinning, ratcheted manifest + release-gate binding (§2.1),
  per-test RETIRE with the validated ledger (§2.2), landing as a stacked PR
  that is the merge vehicle (§3). (Alternatives considered: hold #40 until the writer exists — leaves
  the 0.6.0 line blocked for the whole build; merge red — corrosive; blanket
  module-level skip or xfail — suppresses passing coverage and is
  unaccountable.)
- **D2** — in-memory backend: v6 parity under the §2.3(a) conformance split
  (recommended) or PG port + backend retirement.
- **D3** — ratify **P1.7** (§2.0) as a plan amendment: the writer package
  exists, owns the keyset fixture, and its acceptance criteria include
  emptying the epoch-blocked manifest and closing the ledger.

## 5. Reproducible evidence (design-review NB4)

The counts in this document trace to committed artifacts, not prose:

- **Run command**: `uv sync --frozen --all-extras && uv run --frozen
  --all-extras pytest -q --tb=no --junitxml=<report>` against a dedicated
  Postgres (`REGISTA_TEST_DSN` shape recorded with the artifact). `--extra
  dev` alone is **not** a valid evidence environment — it produced the
  contaminated 892 figure (fact 3).
- **Manifest membership criterion**, machine-applied and causally proven
  (design-review round-2 B2): a node enters the manifest iff it is
  non-passing at the reconciliation base AND it **passes in the
  guard-reverted control run** — a run at the same commit with only
  `check_legacy_append`/`_admit_legacy_append_after_lock` and the in-memory
  refusals neutered (never committed). Result at the branch head: **all 881
  candidate nodes (874 default tier + 7 slow tier) pass under reversion,
  zero exceptions**, and the only new failures are the three
  `tests/test_genesis.py` tests that assert the guard exists — the built-in
  falsifier that the reversion changed exactly and only the admission
  gates. Correlation-only evidence ("passes on pre-#40 main") is thereby
  superseded by direct causal evidence for every node, including the 32
  indirect-presentation ones (their surface forms: the sidecar maps
  `GENESIS_REQUIRED`/`V6_EPOCH_OPEN` to HTTP 409 at
  `src/regista/sidecar/errors.py:89,94`; refused creations yield responses
  missing `work_item`; refused seeding yields empty-state asserts; CLI
  subprocess output asserted on; assert-wrapped concurrency errors).
  Nothing enters by judgment. Known pre-existing exclusion:
  `test_reducer_v1_determinism.py::test_cross_interpreter_sweep_if_alternates_available`
  (slow) fails identically on pre-#40 main and under reversion — not epoch
  debt, tracked separately. *(RESOLVED 2026-08-17, WI-288: a harness PATH
  defect in `tools/reducer_v1_sweep.py` — no reducer divergence; the node
  now passes and the CI deselect is removed.)*
- **Committed artifacts** (all in this branch), sha256 recorded in full:
  - `docs/0.6.0/evidence/suite-junit-base-9e673f9.xml.gz` —
    `451fbadca35210de1cc9b0e3c429c9783faa66d469e20c9bf04ede135760d381`
  - `docs/0.6.0/evidence/suite-junit-guard-reverted-9e673f9.xml.gz` —
    `ab4838dc90947e41ecb645a529e204165c56cba94f11518bceb136d18c750d6b`
  - `docs/0.6.0/evidence/suite-junit-slow-base-9e673f9.xml.gz` —
    `59cbef039abaf00d6da76a6ddd1d896f82fdf6685e3a59303feb763e20ffc59c`
  - `docs/0.6.0/evidence/suite-junit-slow-guard-reverted-9e673f9.xml.gz` —
    `dea835f706c9a5aa0e318974084f968fac5b2acc28f3195020edf989d83e9448`
  - `tests/epoch_blocked_manifest.json` (881 entries; its sha256 is the
    ratified bootstrap digest pinned in `scripts/check-epoch-debt.py`)
  - `tests/epoch_blocked_inventory.txt` (3073 nodes, collected with the
    marker filter disabled; **immutable** — CI requires byte-identity with
    the target branch's copy (the mechanical anchor, round-5 B5); the
    sha256 pins in `tests/test_retired_tests_ledger.py` and
    `scripts/check-epoch-debt.py` serve local runs and the one-time
    bootstrap)

  Environment: dedicated local Postgres via the default test DSN shape
  (`postgresql://regista_test:…@localhost:5432/regista_test`), python 3.13,
  `uv sync --frozen --all-extras`. The 08-15 prose figures are superseded;
  cluster tables from the static triage remain estimates of *blast radius*
  (def counts per module), and the manifest — exact node IDs from the run —
  is the normative inventory.
