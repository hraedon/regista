# WI-287 handoff — D2 in-memory v6 parity, and the one thing D2 cannot deliver

Branch `agent/wi287-inmem-parity`, worktree `~/wt/regista-wi287`, **stacked on
`agent/p17-v6-writer` @ `653e1c6`** (not on `main`). Dedicated DB
`regista_test_wi287`. Tracker: **WI-287**; WI-289 cluster 6 discharged here.

Always run from the worktree root:

```
REGISTA_TEST_DSN='postgresql://regista_test:regista_test@localhost:5432/regista_test_wi287' \
  uv run --frozen --all-extras pytest -q --tb=short -p no:randomly > /tmp/out.txt 2>&1
```

Never pipe pytest through `tail`/`head`. Write to a file, read the file.

---

## 1. What landed

| Piece | Where |
|---|---|
| In-memory v6 relations + `DictConn`-shaped facade | `src/regista/_in_memory_v6.py` (new) |
| In-memory `write_genesis` / `initialize_epoch` / `read_genesis` / `recover_genesis` | `src/regista/_in_mem_genesis.py` (new), mixed into `InMemoryRegista` |
| v6 row insert + epoch-aware legacy refusal | `src/regista/_event_store.py` (`InMemoryEventStore`) |
| `PARITY_BOUNDARY_POSTGRES_ONLY` + its HTTP status | `src/regista/_errors.py`, `src/regista/sidecar/errors.py` |
| Shared conformance suite over the in-memory backend, the parity guard, the migration harness, WI-289 cluster 6 | `tests/test_wi287_inmem_parity.py` (new, 36 nodes) |
| The fixture-migration helpers `_v6_fixtures` always promised but never defined | `tests/_v6_fixtures.py` (additive: `write_test_genesis`, `accept_key`, `register_test_workflow`, `open_v6_epoch`, `project_identity_of`, `v6_producer`) |
| The same helpers proven on Postgres (kept out of the DB-free parity module) | `tests/test_wi287_fixture_helpers_postgres.py` (new, 2 nodes) |
| WI-289 cluster-6 node→counterpart mapping | `tests/retired_tests_ledger.json` (`covered_by` / `covered_in` on 6 entries) |
| D2-executed successor note + the corrected population figure | `docs/0.6.0/SUITE-RECONCILIATION.md` §2.3 |

**`tests/test_p17_v6_writer.py` and `src/regista/_v6_writer.py` are not modified.**
That was deliberate — see §3.

## 2. The backend seam: what is shared, what is mirrored

**Shared (the same functions execute on both backends, byte for byte):**
`_genesis.append_v6_genesis`, `_genesis.read_genesis_from_connection`,
`_v6_writer.append_v6_event` and every helper they call — envelope construction,
JCS canonicalization, Ed25519 signing and self-verification, §5.8 key-binding
anchor resolution (including the no-`principal_keys`-fallback rule), admission
gate 1 (workflow registration), admission gate 2 (producer authorization),
entity-sequence allocation, and both chain links.

**Mirrored (in-memory-specific, ~330 lines):** the *storage* under those
functions. `InMemoryV6Connection.execute` recognises the closed set of statements
the v6 paths issue and evaluates them over `InMemoryEventStore`'s own event list
plus two extra relations (`project_identity`, `event_chain_head`). Anything
outside that grammar is `PARITY_BOUNDARY_POSTGRES_ONLY` naming the statement.

**Why a storage facade rather than a `V6Backend` protocol.** A protocol seam puts
the *semantics* in two implementations, where they can drift — the failure a
parity ticket exists to prevent. It also needed edits to
`_v6_writer.append_v6_event` and `_genesis.append_v6_genesis`, the two functions
the sibling P1.7 branch is still changing. And it would not have solved the test
half: the shared conformance class reads rows back with SQL, so a row-query
surface was needed regardless. One mechanism, zero touch points, no possible
semantic drift. The cost is that a new statement on the Postgres path breaks
in-memory — **loudly**, which is the correct direction.

**`_v6_writer.py` touch points: none.** `_genesis.py` touch points: none.

## 3. The parity boundary, and how it is enforced

Mechanisms (all in `tests/test_wi287_inmem_parity.py::TestParityBoundary`):

1. **Backend in the node id** — every in-memory run of a shared assertion is
   `…::TestSemanticConformanceInMemory::<name>`.
2. **Whole-suite parity** — set equality between the shared class's test methods
   and the in-memory subclass's. Honest about its limit: inheritance means
   `dir()` can never come up short, so this catches an in-memory-only *extra*
   masquerading as shared coverage, and guards 3 and 3a close the two real
   subsetting routes.
3. **No weakened overrides** — function *identity* is asserted, so a subclass
   cannot redefine an inherited assertion.
3a. **No silencing marker** — `pytest.mark.skip(...)(inherited)` returns the *same*
   function with a marker attached, so it defeats both guard 2 and guard 3 while
   the suite reports SKIPPED, which reads like green. Function-level *and*
   class-level `pytestmark` are checked for `skip`/`skipif`/`xfail`. Found by
   attacking my own guard, and the mutation is in the battery below.
4. **`TestPostgresOnly` has no in-memory counterpart** — asserted on the class
   graph. This matters concretely: the chain head *does* advance in memory, so a
   subclass of that class would pass and prove nothing about serialisation.
5. **A source tripwire on the shared class** — `FOR UPDATE`, `event_chain_head`,
   `pg_advisory`, `rollback`, `isolation_level`, `threading`, `Thread(`,
   `concurrent.futures` may not appear in its executable source (docstrings and
   comments are stripped first, via `ast.unparse`, because the class's own
   docstring names those concerns in order to disclaim them).
6. **No faked rollback** — an in-memory transaction that raises *after* a write
   refuses with `PARITY_BOUNDARY_POSTGRES_ONLY` chained from the original. A
   refusal *before* any write propagates untouched (also asserted), which is what
   every admission-gate test needs.
7. **`provides_transactional_isolation is False`** — published as a fact.
8. **Read-only really is read-only** — `read_genesis` uses a connection that
   refuses writes, since it cannot execute `SET TRANSACTION READ ONLY`.
9. **The legacy door stays shut on both sides** — in-memory `check_legacy_append`
   now mirrors Postgres: `GENESIS_REQUIRED` before genesis (**message and code
   unchanged**, because the manifest pins that form for 217 nodes),
   `V6_EPOCH_OPEN` after.
10. **v6 and v5 chain heads stay separate** — a v6 append must leave
    `InMemoryEventStore._global_chain_head` (the v5-formula head) untouched.

## 4. FINDING — the 217 in-memory manifest nodes cannot leave in this WI

**Corrected measurement: the in-memory population is 217, not 167.** The 167
figure (NOTES-P17 §2) came from a name-based heuristic
(`'in_memory' in node_id or 'InMemory' in node_id`). Measured causally instead —
from a full all-extras run with the manifest disabled, classifying each failure by
whether its exception text is the in-memory refusal — the split of the 694 is:

| Cause | Nodes |
|---|---|
| in-memory refusal (`_event_store.py`) | **217** |
| Postgres genesis refusal (`_genesis.py`) | 446 |
| indirect presentations (sidecar 409, `KeyError`, empty-state) | 24 |
| slow tier (not collected in the default lane) | 7 |
| **total** | **694** |

The heuristic missed 74 in-memory nodes and wrongly claimed 30 that are the
`[real]` (Postgres) parameter of a parametrized fixture — e.g.
`test_in_memory_conformance.py::TestConformanceClaims::test_heartbeat[real]`.
Evidence: `docs/0.6.0/evidence/` is untouched; the classification script and node
list are reproducible from the run command above plus
`--junitxml`, and the node list used here is
`/home/itadmin/wt/wi287-runs/inmem_manifest_nodes.txt` (not committed — it is
derivable).

**Why none of the 217 can pass yet.** Opening an in-memory v6 epoch is now
possible, but these tests do not fail because the epoch is missing. They fail
because they call the *legacy* ordinary API, which is refused post-genesis too —
by design, on both backends. Making them pass needs the ordinary API routed to
`append_v6_event`, and that route requires five things per NOTES-P17 §3, none of
which is in-memory-specific:

1. a per-principal Ed25519 actor key (they share one HMAC key);
2. a `principal_key_accepted` event per principal;
3. a signed `workflow_registered` event per workflow;
4. a process-level `producer` identity on the handle;
5. canonical principal ids — e.g. `test_assurance.py` transitions as `"a2"` and
   `"h1"`, which the v6 grammar refuses at ingress.

Every one of those is identical work for the `[real]` parameter of the *same*
fixture, so the migration belongs with the wiring, once, for both backends — not
duplicated here. The wiring is P1.7's (its own notes call it "the first task for
the successor"). **My population is therefore 217 → 217, and that is not a
shortfall in this WI; it is a sequencing fact.** NOTES-P17 §2 option 3 ("evaluate
'manifest literally empty' at the later of P1.7 and WI-287") is the right shape,
and this measurement makes it 217/446, not 167/527.

**The acceptance-wording amendment does not remove the dependency.** Evaluating
"manifest literally empty" at the joint completion of P1.7 and WI-287 is the right
shape (it is NOTES-P17 §2 option 3), and it settles *when* the criterion is
judged. It does not make the 217 reachable from this side: they are gated on the
ordinary-API route to `append_v6_event`, which is P1.7's and is not started.
Anything else would mean inventing the producer-identity, `register_workflow`
event-emission and actor-id-canonicalisation API decisions in-memory-only, then
conflicting with P1.7 when it makes them for both backends.

**What I shipped instead, so the tranche is cheap rather than merely blocked.**
`tests/_v6_fixtures.py` documented a three-step sequence in which steps 2 and 3
were named `write_test_genesis` and `accept_key` — **neither function existed**.
Every caller open-coded them (P1.7's private `_accept` is one such copy), so each
of the 25 in-memory files *and* their Postgres siblings would have re-implemented
~25 lines of ceremony. Those helpers now exist, are backend-agnostic (they touch
only `write_genesis`, `_mgr.transaction()` and `_keys`, which both backends now
expose), and are proven on both:

* `tests/test_wi287_inmem_parity.py::TestMigrationHarness` — in memory;
* `tests/test_wi287_fixture_helpers_postgres.py` — on Postgres.

A migrated fixture becomes `open_v6_epoch(sub, keyset)` plus
`register_test_workflow(sub, name, version, definition)`. Two guards keep the
convenience honest: an unaccepted principal is *still* refused after
`open_v6_epoch` (it must not become blanket authorisation), and gate 1's refusal
is asserted before the registration is added.

**What the coordinator should do:** land P1.7's wiring, then migrate the 25
in-memory files' fixtures in the same pass as their Postgres siblings, using those
helpers. The in-memory backend is no longer the blocker for any of them —
`InMemoryRegista` can open an epoch, sign, sequence, and refuse by name, and
`tests/test_wi287_inmem_parity.py` proves it.

## 4a. RETIRE triage of the 217 — result: **zero retirements**, and why

The brief flagged `test_witness_in_memory.py`'s 20 nodes as possible RETIRE
candidates "if their subject is the cut lifecycle". Triaged per test, they are
not. All 20 are **receipt delivery**: transport invocation, retry/pause state
machine, auto-pause after consecutive failures, signature headers, payload shape,
and the delivery mutex. What §7's D-7 CUT removes is the witness **key
lifecycle** (enrolment/rotation write paths, guarded by
`ErrorCode.WITNESS_LIFECYCLE_CUT`) — a different subject. Delivery survives the
epoch reset; these tests are blocked only because delivering a receipt requires
appending an event. Deleting them would be D1's rejected "blanket skip/deletion,
unaccountable" wearing a ledger's hat.

Same conclusion for the rest of the 217: the tranche *is* the EPOCH-RESET §5
surviving core (assurance 16, review validators 13, validator context enrichment
14, lineage 4, replay coverage 8, …). **Retire-vs-pass accounting for my
population: 0 retired, 0 newly passing, 217 still manifest-resident** — and the
manifest count is unchanged at 694, ratchet-clean against both baselines.

**One boundary ambiguity worth settling before someone leans on it.**
`test_witness_in_memory.py::TestConcurrentDelivery::*` (2 of the 20) are
*concurrency* tests on the in-memory backend, which reads like a contradiction of
§2.3(a)'s "concurrency/races remain Postgres-only". Read: they exercise the
in-process delivery mutex (`InMemoryRegista._witness_delivery_lock`), not the
store's transactional concurrency — a real in-memory object with real contention,
so they belong where they are. But when the migration makes them green, **their
pass is not evidence about store-level concurrency or chain-fork safety**, and
nothing should cite it that way. The distinction §2.3(a) is actually drawing is
"the *store's* isolation is Postgres-only", not "no test may use threads".

## 5. LOUD notes for the P1.7 author / coordinator

* **The verifier clamp makes `applicability` useless as a tamper signal.**
  `_verification._verify_v6_row` returns `INVALID` /
  `ENVELOPE_SCHEMA_INCOMPLETE` for **every** v6 row, clean or tampered
  (measured). `TestWI289Cluster6` therefore asserts `row_reconciled`,
  `mismatched_field_names` and the `FailureReason` set, which are decided above
  the clamp. **When phase 2 lands, tighten those tests to assert `applicability`
  as well** — the class docstring says so; do not just delete the note. I did not
  touch `_verification.py`.
* **The seam claim in `TestSemanticConformance`'s docstring is slightly wrong and
  I did not fix it.** It says every test "is written against a `writer` fixture
  that resolves the append callable and the store handle". There is no `writer`
  fixture; the tests use `appendable`, the module-level `append_v6_event`, and raw
  SQL. The *substance* of the claim held — swapping `project`/`genesis` was
  genuinely enough — so the docstring is inaccurate rather than wrong. Fix it on
  the P1.7 branch, not here, to avoid a conflict.
* **`InMemoryRegista` gained `_mgr` and `_keys`.** Nothing in the tree
  duck-typed on their absence (checked), but if you add a
  `hasattr(x, "_mgr")` backend discriminator later, it will now be wrong.
* **`InMemoryEventStore.append_v6_row` exists and `append` must not be used for
  v6 events** — `append` advances the head with the v5
  `sha256(envelope || signature)` formula.
* **`DictConn` is a concrete alias, not a Protocol**, so the facade needs one
  `cast` at the seam (`_in_mem_genesis._as_conn`, confined to that function).
  Narrowing `DictConn` to a Protocol on the P1.7 branch would delete the need for
  it and would also type-check the in-memory backend properly. Worth doing.
* **A raising property is not an absent attribute.** My first cut made
  `InMemoryRegista._keys` refuse when no keyset was configured; that broke
  `tests/test_in_memory_conformance.py`'s
  `getattr(sub, "_key_set", None) or getattr(sub, "_keys", None)` — `getattr`'s
  default does not catch an exception raised *inside* the property, so it escaped.
  One full-suite failure, caught by the run and not by review. The refusal now
  lives in `_require_keys()`, called by the operations that need a key.

## 6. Fail-then-pass evidence

Before the implementation (src reverted, the new tests kept): **7 failed, 4
passed, 19 errors**, first line `AttributeError: 'InMemoryRegista' object has no
attribute 'write_genesis'`. After: **38 passed** (36 in-memory + 2 Postgres).

Mutation battery — each applied singly and reverted; **every mutant was killed**,
and the script asserts that (a survivor raises rather than being reported):

| Mutation | Reddens |
|---|---|
| v6 insert routed through legacy `append` | `test_a_v6_append_never_writes_the_legacy_chain_head` |
| chain head is not the v6 hash | + `TestSemanticConformanceInMemory::test_the_project_chain_links_across_entities` |
| post-write failure no longer refuses | `test_a_failure_after_a_write_refuses_instead_of_faking_rollback` |
| unmodelled statement returns empty instead of refusing | `test_an_unmodelled_statement_is_refused_by_name` |
| read-only connection allows writes | `test_a_read_only_connection_refuses_writes` |
| legacy refusal made unconditional again | `test_the_legacy_writer_is_refused_on_both_sides_of_in_memory_genesis` |
| `project_identity` row loses its singleton key | 8 failed + 14 errors |
| `open_v6_epoch` accepts every key in the file | `TestMigrationHarness::test_an_unaccepted_principal_is_still_refused_after_open_v6_epoch` |
| a conformance assertion overridden in the subclass | `test_the_in_memory_suite_overrides_no_assertion` |
| an inherited assertion silenced by `pytest.mark.skip` without redefining it (reports "1 skipped", i.e. looks green) | `test_no_conformance_assertion_is_skipped_or_xfailed` |

The battery script is `/home/itadmin/wt/wi287-runs/` (scratch, not committed);
its mutations are all one-line and reproducible from this table.

## 7. Environmental note

The WI-243 schema-leak guard fails the session with exit 1 when
`REGISTA_TEST_DSN` is **unset**, because the shared `regista_test` database
already holds stale `test_*` schemas from other worktrees (`test_fail_*`,
`test_maint_anchor_*`, …). Pre-existing, not caused by this branch; with the
dedicated DSN the guard is clean.

## 8. Validation results

| Check | Result |
|---|---|
| default lane (`-m 'not slow'`, all extras, dedicated DB) | **2643 passed, 0 failed, 687 xfailed, 18 skipped** |
| slow lane (`-m slow`) | **4 passed, 7 xfailed, 0 failed** |
| `check-epoch-debt.py --base main` | OK — 694, shrink-only node set |
| `check-epoch-debt.py --base agent/p17-v6-writer` | OK — 694, shrink-only node set |
| `tests/epoch_blocked_inventory.txt` | byte-identical to both baselines (sha `8696641a…`) |
| ruff | clean |
| mypy (`src/regista`, 102 files) | clean |
| `docs/0.6.0/check-conflicts.py` | 0 contested values |
| `docs/0.6.0/check-crossrefs.py` | 0 unresolved references |
| parity module without a database | 36 passed against an unreachable DSN |

Manifest count is unchanged at **694** by design — see §4. The debt figure any claim
about this branch must carry is therefore `green-with-epoch-debt(694)`, per
`SUITE-RECONCILIATION.md` §2.1.

**Do not run two pytest sessions against the same test database concurrently** —
the WI-243 leak guard sees the sibling session's in-flight schemas and reports a
false leak. Cost me one confused minute.
