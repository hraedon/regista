# Suite reconciliation at the epoch boundary

**Status: PROPOSED — owner ratification required.** Drafted 2026-08-16 from a
static triage of the full suite at the PR #40 stack tip (88e44b8; branch head
now 9e673f9). **Revised 2026-08-16 after a cross-lineage design review
(openai/gpt-5.6-sol, verdict request-changes; session
ses_ff2403264ffeK0BSJ1evKP5gAZ)** — the revision replaces the misassigned
P1.3 blocker with a new writer package, adds the P1.4 retirement population,
moves from module-level marking to exact node IDs, and makes the debt and
retirement records machine-enforced. Nothing in this document is implemented
yet. EPOCH-RESET decides the *data* disposition ("discarded, not migrated");
no document decides the *test* disposition — the 892 `GENESIS_REQUIRED`
failures are an undocumented consequence of a documented decision. This
document exists to make that consequence a decision.

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
3. **The failure surface is exactly the event-writing tests — 874 nodes,
   each empirically traced to the epoch boundary.** A clean full-suite run at
   the branch head with **all extras installed** (see §5) yields 848 failures
   + 26 errors / 2160 passed / 18 skipped. All 848 failures carry the refusal
   directly; the 26 errors/others present indirectly (sidecar HTTP 409s,
   downstream empty-state asserts) and were **proven** epoch-caused by
   running exactly those nodes on pre-#40 main: 24 pass there outright and
   the remaining 2 pass in module context (order-dependent seeding). The
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

> **P1.7 — v6 ordinary-event writer** · owner: team · dep: P1.1, P1.2, and
> the admission gates PR #40's body names (trust-domain P2.1/P2.2, canonical
> principals P2.3, workflow registration, producer authorization).
> Deliverables: the post-genesis v6 append path; the shared Ed25519
> actor-role test keyset and genesis test fixture; emptying the
> `epoch_blocked` manifest (§2.1). **Done when:** the manifest is empty, the
> retired-test ledger (§2.2) accounts for every node that did not return, and
> the suite is green with no epoch skips remaining.

D3 accordingly attaches to P1.7, not P1.3.

### 2.1 BLOCKED-ON-P1.7 — exact-node skips with a machine-checked manifest

Tests of functionality that survives the epoch reset are **kept** and skipped
by **exact node ID**, never by module — affected modules contain passing
read-only tests that continue to run. Mechanics:

- **Manifest**: a committed, machine-readable inventory
  (`tests/epoch_blocked_manifest.json`) listing the exact node IDs that fail
  or error with `GENESIS_REQUIRED`/`V6_EPOCH_OPEN` at the reconciliation
  commit, taken from a committed full-suite run artifact (§5) — not from
  judgment.
- **Skip application**: a `pytest_collection_modifyitems` hook in
  `tests/conftest.py` applies `pytest.mark.skip` with a reason naming P1.7 to
  exactly the manifest's nodes. (A bare `epoch_blocked` marker registration
  alone marks, it does not skip; the hook is the mechanism.)
- **Meta-test enforcement**, all machine-checked:
  1. every manifest node ID must exist in the current collection (a renamed
     or deleted blocked test is loud, not silently absorbed);
  2. **shrink-only ratchet**: the manifest carries its baseline count; the
     meta-test fails if the count ever exceeds the committed baseline — the
     manifest can only shrink. New epoch-blocked tests cannot be added by
     expanding the manifest; they must wait for P1.7 or get their own
     ratified amendment here;
  3. a full-suite CI lane asserts that **no test outside the manifest** fails
     with `GENESIS_REQUIRED`/`V6_EPOCH_OPEN` (an unmarked module acquiring
     the refusal is ordinary red CI — that is the enforcement, and the
     meta-test names it).

**The green check is not allowed to stand in for "no debt" (design-review
B4):** the manifest count is a machine-readable debt figure, not log output.
Two bindings make it load-bearing:

- CI publishes the manifest count as a visible per-run output (step summary),
  and
- **the release gate refuses to cut any final (non-pre-release) 0.6.x
  release while the manifest is nonempty** — enforced as a check in the
  release workflow, not as convention. Release candidates may ship with debt;
  a final may not.

Why exact-node skip and not exact-node xfail (design-review NB2): the
refusal fires during **fixture setup** for 26 of the affected nodes, and
pytest reports a fixture-phase exception under an xfail mark as ERROR, not
XFAIL — xfail semantics only reliably cover the call phase. Skip-at-collection
is deterministic across both phases. The ratchet plus P1.7's emptying
criterion carry the "this debt must reach zero" force that strict-xfail would
otherwise provide.

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
  `test_bundle` and `test_witness_integration`. These must NOT ride the
  §2.1 manifest — P1.7 cannot empty a manifest containing tests of code P1.4
  deletes. They are assigned to P1.4 and leave with it. Until P1.4 executes,
  they sit in the manifest under an explicit `retires_with: P1.4` field so
  the P1.7 emptying criterion excludes them arithmetically, not silently.

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

- **D1** — ratify the taxonomy: BLOCKED-ON-P1.7 exact-node skip with
  ratcheted manifest + release-gate binding (§2.1), per-test RETIRE with the
  validated ledger (§2.2), landing as a stacked PR that is the merge vehicle
  (§3). (Alternatives considered: hold #40 until the writer exists — leaves
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
- **Manifest membership criterion**, machine-applied from the JUnit report:
  a node enters the manifest iff it is non-passing at the reconciliation
  base AND (its failure text carries `GENESIS_REQUIRED`/`V6_EPOCH_OPEN`, OR
  it passes on pre-#40 main — the indirect-presentation cases). Nothing
  enters by judgment.
- The JUnit report, the derived manifest, and the full pre-reconciliation
  collection inventory are committed together with the reconciliation. The
  08-15 prose figures are superseded; cluster tables from the static triage
  remain estimates of *blast radius* (def counts per module), and the
  manifest — exact node IDs from the run — is the normative inventory.
