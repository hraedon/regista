# Suite reconciliation at the epoch boundary

**Status: PROPOSED — owner ratification required.** Drafted 2026-08-16 from a
static triage of the full suite at the PR #40 stack tip (88e44b8; branch head
now 9e673f9). Nothing in this document is implemented yet. EPOCH-RESET decides
the *data* disposition ("discarded, not migrated"); no document decides the
*test* disposition — the 892 `GENESIS_REQUIRED` failures are an undocumented
consequence of a documented decision. This document exists to make that
consequence a decision.

## 1. Facts the proposal rests on

Verified at 88e44b8; none of these are judgment calls.

1. **No legacy append can succeed, even after genesis.** `check_legacy_append`
   and `_admit_legacy_append_after_lock` (`src/regista/_genesis.py`) raise on
   every branch: `GENESIS_REQUIRED` before genesis, `V6_EPOCH_OPEN` after.
   PR #40's own tests assert this (`tests/test_genesis.py` asserts
   `V6_EPOCH_OPEN` after a successful `write_genesis`). Therefore **"fix the
   fixtures to open genesis first" reconciles nothing** — it converts one
   refusal into another. Reconciliation is blocked on the v6 ordinary-event
   writer (P1.3), not on test plumbing.
2. **The in-memory backend fails closed entirely, by design.**
   `InMemoryEventStore` refuses unconditionally; README pins it as
   "legacy-only test backend … fails closed in the clean epoch."
3. **The failure surface is exactly the event-writing tests.** 892 failures +
   26 errors (the errors are the same refusal raised in four event-writing
   fixtures: `test_cli_integration.py::populated_project` 15,
   `test_bc306_entity_kind_validation.py::work_item_id` 5,
   `test_anchoring.py::populated_cli_project` 4,
   `test_wi217_replay_memory.py::seeded` 2). The 1977 passing tests are the
   modules that never append events.
4. **Key material is a second, independent blocker.** Genesis requires an
   active Ed25519 actor-role keyset bound to the envelope principal; the shared
   `tests/test_keys.json` is a single HMAC key with no `principal_id`/`role`.
   Every legacy fixture's key material is unusable in the clean epoch.

## 2. Cluster disposition (the proposal)

Clusters from the static triage; counts are `def test_*` per module and are
**upper bounds on blast radius**, not failure counts (many tests in affected
modules only read).

| Cluster | Shape | Modules / defs | Disposition |
|---|---|---|---|
| C1 | Postgres fixture, event writes in test bodies | 38 / 689 | **BLOCKED-ON-P1.3** |
| C2 | Dual-backend (PG + in-memory), writes | 27 / 512 | **BLOCKED-ON-P1.3**, minus the RETIRE subset (§2.2) |
| C3 | In-memory only, writes | 11 / 384 | **OWNER DECISION D2** (§2.3) |
| C4/C5/C6 | No event writes | 51 / ~986 | No action — still passing |

### 2.1 BLOCKED-ON-P1.3 — named skip with a machine-checked manifest

Tests of functionality that survives the epoch reset (workflow, replay,
claims, links, hooks, bundling, anchoring, timestamping) are **kept**, marked
with a single module-level marker:

```python
pytestmark = pytest.mark.epoch_blocked  # requires v6 ordinary-event writer (P1.3)
```

with three enforcement properties, so ~900 skips cannot rot silently:

- a **frozen manifest** (`tests/epoch_blocked_manifest.py` or similar) lists
  every marked module; a meta-test fails if a marked module is absent from the
  manifest, if a manifest module has lost its marker, or if an *unmarked*
  module starts failing with `GENESIS_REQUIRED`/`V6_EPOCH_OPEN`;
- the skip **reason names the blocker** (P1.3 / its work item), never a bare
  `skip`;
- **P1.3's acceptance criteria include emptying the manifest** — the v6 writer
  does not ship while any module remains blocked. The manifest count is the
  debt meter, visible in every run's skip total.

Why skip-with-manifest and not `xfail`: the refusal fires at fixture/API
level, and 892 strict-xfail flips at P1.3 would be pure noise; the manifest
plus P1.3's emptying criterion carries the same "this debt must reach zero"
force with a single meta-test. Why not leave CI red: a red main teaches
everyone to ignore CI, which is a worse failure mode than counted, named,
pinned skips — the suite stays green *and honest*: everything that can run
passes; everything that cannot is enumerated.

### 2.2 RETIRE — per-test, with recorded carry-forward

Tests whose **subject** is v5/HMAC mechanics that the epoch reset deletes (v5
envelope construction, HMAC scheme selection, the v5 chain-hash domain) are
retired — deleted, not skipped. Candidates concentrate in `test_signing`,
`test_wi267_row_authentication`, `test_hash_chain`, `test_global_event_chain`,
`test_plan024_global_chain`, and parts of `test_signing_ed25519`, but **the
retire boundary is per-test, not per-module** — those modules also assert
invariants (row authentication, chain integrity) that reappear in v6 form.

Rule: a test is retired only with a recorded carry-forward decision — either
"the invariant dies with v5" or "the invariant reappears in v6; coverage owed"
with a coverage-debt entry attached to the v6 counterpart's work item.
Retirement without a carry-forward note is refused in review.

### 2.3 C3 / in-memory backend — owner decision D2

C3 is the highest-value stranded coverage: assurance (128 defs), review
validators (88), lineage (50) — exactly the EPOCH-RESET §5 genesis
preconditions, i.e. the *surviving core*, running on a backend declared
legacy-only. Options:

- **(a) v6 parity for `InMemoryRegista`** — implement genesis + the v6 writer
  for the in-memory store. Keeps the fast unit tier for the code that most
  needs dense coverage. **Recommended**, sized as its own work item beside
  P1.3.
- **(b) Port C3 to Postgres** — no in-memory v6 implementation to maintain,
  but ~384 defs move to the slow tier and the in-memory backend becomes
  permanently untestworthy in the clean epoch (then: retire the backend).

Until D2 is decided, C3 rides the §2.1 manifest under its own section.

## 3. Merge ordering

**PR #40 does not merge red.** The §2.1 marker + manifest + §2.2 retire
tranche land **in #40** (its body already contemplates "or land the suite
reconciliation in this PR"). Green then means what it says. #41 (docs) follows
unchanged. The Ed25519 test-keyset work (fact 4) belongs to P1.3's test
plumbing, not to #40.

## 4. Owner decision points

- **D1** — ratify the taxonomy: BLOCKED-ON-P1.3 skip-with-manifest (§2.1) +
  per-test RETIRE with carry-forward (§2.2), landing inside #40. (Alternatives
  considered: hold #40 until P1.3 — leaves the 0.6.0 line blocked for the
  whole writer build; merge red — corrosive; blanket xfail — unaccountable.)
- **D2** — in-memory backend: v6 parity (recommended) or PG port + backend
  retirement.
- **D3** — confirm P1.3's acceptance criterion includes emptying the
  epoch-blocked manifest.
