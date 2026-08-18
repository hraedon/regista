# P1.7 handoff — what landed, what did not, and the findings that changed the plan

> **Session 2 (2026-08-18) starts at §0. Read §0 first — it supersedes parts of
> §1-§4 and records three findings the earlier notes did not have.**

Branch `agent/p17-v6-writer`, worktree `~/wt/regista-p17`, base `main` @ `e19ec47`.
Dedicated DB `regista_test_p17` (`postgresql://regista_test:regista_test@localhost:5432/regista_test_p17`).
Tracker: **WI-300**.

Always run from the worktree root:

```
REGISTA_TEST_DSN='postgresql://regista_test:regista_test@localhost:5432/regista_test_p17' \
  uv run --frozen --all-extras pytest -q --tb=short -p no:randomly > /tmp/out.txt 2>&1
```

Never pipe pytest through `tail`/`head` — it masks the exit code. Write to a file, read the file.

---

## 0. Session 2 (2026-08-18): what landed, and three findings

Commits, in order:

| SHA | Slice |
|---|---|
| `ce19e06` | Merge of `agent/wi287-inmem-parity`, + the `v6_epoch_open` shape unification and a real in-memory `append_v6` |
| `6ed569b` | §3c items 1-3: the ceremony round-trip on a real epoch, all three stubs deleted |
| (this slice) | The **remaining three legacy funnels** wired to the v6 route + the first migrated file (`test_idempotency.py`) |

### FINDING 5 — the merge had a semantic conflict the text merge did not show

`EventStore.v6_epoch_open` was declared by P1.7 as a **method** (the funnel calls
`store.v6_epoch_open()`) and implemented by WI-287 as a **property**. The merge kept both
definitions in `InMemoryEventStore`; P1.7's stub (later in the file, returning `False`)
shadowed WI-287's real one, and `_refuse_legacy_append`'s `if self.v6_epoch_open:` tested a
**bound method** for truthiness — always true. Three tests caught it. Unified as a method
(the protocol's shape); the handle-level `InMemoryRegista.v6_epoch_open` stays a property,
mirroring `Regista`. **Lesson for the next stacked merge: grep for members both branches
added, not just for conflict markers.**

`InMemoryEventStore.append_v6` is now real (same preflights as Postgres, then the shared
writer over the `_in_memory_v6` facade), and the store carries a keyset via `bind_keys`.

### FINDING 6 — §3c items 4 and 5 are blocked on a production surface that does not exist

**There is no production trust-log append path.** Verified: `principal_lifecycle.py` is the
only production writer of `principal_key_enrolled`, and it appends to the **project** chain
through the ordinary funnel. The trust-log chain is written *only* by
`tests/_trust_log_fixtures.store_trust_log_event` — a direct `INSERT INTO events` whose chain
state lives in a Python object, not in the database.

`append_v6_event` cannot serve the trust-log chain: it calls `require_v6_epoch`, and a
trust-log project has **no `project_identity`** row, because its genesis is
`trust_domain_established` (Bootstrap A), not `project_initialized` (Bootstrap B). Giving the
trust-log project a `project_initialized` genesis as well is not a fix — RECONCILIATION.md
Resolution 1 calls `trust_domain_established` "the trust-log genesis", so B-then-A inside the
trust log inverts the spec's own ordering.

So relocating enrolment to the trust-log chain needs a **new production trust-log writer**
with its own admission rules (chain root = `trust_domain_established`; binding anchor = the
trust-log genesis for root-authorised events; no `project_identity`). That is a package-sized
gap left by P2.1/P2.2, not a §3c cleanup item, and it is **not** P1.7's to invent mid-migration.
§3c items 1-3 landed anyway (see `6ed569b`): the ceremony now runs on a real epoch with **zero
stubs**, appending to the project chain, which is what production does today. The debt is
stated in `TestCeremonyPathRoundTrip`'s docstring where a reader will find it.

**WI-299 consequence.** Its closing condition ("`provision_principal` appends a signed
`principal_key_enrolled` through the writer") is now *mechanically* reachable — `6ed569b`
proves the append path works end to end for exactly that transition — but on the project
chain, i.e. carrying Finding 6's topology debt. And `provision_principal` is a non-interactive
CLI: a §5.5 enrolment needs a possession proof (it holds the key it just minted, so that part
is fine) **and an approval**, and who approves a provisioning run is a policy decision, not an
implementation detail. Auto-approving would be a bypass with extra steps. **Left for the owner
/ coordinator to decide; WI-299 is not closed and its positive clause is not restored.**

### FINDING 7 — the wiring was one funnel short of three, which is what actually gated Phase 3

`d3cce8f` wired `_event_store.append_event`. Three more refuse post-genesis, and
`_work_items.create_work_item` — the entry point almost every migrated fixture needs — goes
through the second, not the first:

1. `_events.append_event` (direct SQL; `_work_items.create_work_item` uses it),
2. `_events.append_transition_event` (direct SQL; every state transition),
3. `_events_api.append_event`'s **eager pre-flight** `check_legacy_append`, which fired before
   the store's fork could route,
4. `PostgresEventStore.allocate_seq`'s `check_legacy_append` — reached by the v6 path itself,
   via `append_v6`'s `expected_event_seq` evaluation, so `expected_event_seq` was unusable in
   the clean epoch.

All four are now epoch-aware. (1) and (2) reuse `_event_store._v6_request`, so the two
legacy-vocabulary translations — the `''`/`0` workflow sentinel becoming `null`, and
`on_behalf_of` being *refused* rather than dropped — are not duplicated and cannot drift.
(3) and (4) are conditioned rather than deleted, so the pre-genesis `GENESIS_REQUIRED` form
still comes from the earliest possible point, which is what keeps the remaining manifest
entries true.

**This was the real gate on Phase 3, not the fixtures.** With it in place a file's migration is
mechanical; without it, every migrated fixture died in `create_work_item`.

**One test had to be rewritten, and it is a strengthening.**
`tests/test_genesis.py::test_postgres_genesis_is_single_and_recoverable` asserted that
post-genesis `regista.append_event(<random uuid>, ...)` raises `V6_EPOCH_OPEN`. It now raises
`WORK_ITEM_NOT_FOUND`, because the append gets *past* the epoch door and is refused by the v6
path's own contract check — keeping the old assertion would be asserting that P1.7's wiring is
absent. The invariant the test is actually about (a **legacy writer** cannot extend the opened
epoch, `EPOCH-RESET.md` §5.1) is now pinned directly on `check_legacy_append` **and**
`admit_legacy_append`, i.e. at the two functions that enforce it, instead of through an
ordinary-API call whose meaning changed underneath it. Two assertions where there was one.

### The Phase 3 migration recipe, measured on `tests/test_idempotency.py` (6 nodes)

```python
@pytest.fixture(scope="module")
def regista(tmp_path_factory):                 # module scope -> tmp_path_factory
    keyset = make_v6_keyset(tmp_path_factory.mktemp("k"), principals=(ACTOR_1, ACTOR_2))
    sub = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(sub, keyset, principals=(ACTOR_1, ACTOR_2))
    sub.register_workflow_file(WORKFLOW_PATH)   # emits the signed registration itself
    ...
```

Three costs per file, in descending order:

1. **Canonical actor ids.** `"agent-1"` → `"agent:idem-one"`, at *every* occurrence including
   assertions. This is the bulk of the diff and it is per-file textual work.
2. The fixture rewrite above (mechanical, ~10 lines).
3. `register_workflow_file` needs no change — `_workflow_api` already appends the signed
   `workflow_registered` event post-genesis, so admission gate 1 is satisfied for free.

Measured result: **6 XPASS(strict) → 6 passed**, manifest **694 → 688**. Use
`/tmp/.../shrink.py`-style surgery on the manifest (`json.dump(..., indent=1)` + trailing
newline, and **update `baseline_count`** — the debt checker asserts
`baseline_count == len(entries)`).

### Phase 2 (verifier boundary) — NOT started, and the notes understated it by a lot

§4's design notes are sound but the *scope* is not a clamp swap. Measured against
`_verification.py`: of RECONCILIATION.md Resolution 2's `VerificationResultV6` surface,
**10 of the 11 new result fields are missing** (only `identity_consistency` exists),
**14 of 15 failure reasons are missing** (only `ENVELOPE_UNCANONICAL` exists), and **all four
policy inputs are missing** (`pinned_project_instance_id`, `pinned_trust_domain_id`,
`cutover_checkpoint_event_hash`, `producer_policy`).

There is also a structural blocker §4 does not mention: **`_verify_v6_row` cannot see any other
event.** Its inputs are the row, the parsed envelope and a `TrustedKeyResolver`. §5.10 steps
1-4 are *chain traversal over the presented material*, so the function needs a new
referent-resolver input (hash → event, plus the completeness claim) threaded through
`verify_event_strict` and its 12 call sites. The result fields are non-optional, so all 39
`VerificationResult(...)` construction sites in the tree must supply them (most via
`_base_kwargs`).

**Do not land this in pieces.** A partial Phase 2 cannot flip `applicability`, so it delivers
none of the value (WI-296's two `test_bundle` assertions stay `False`, WI-287's cluster-6
tightening stays blocked) while leaving a second, narrower clamp behind. Note also
`VerificationPolicy.full_authentication_versions` is `frozenset({V5})` — **V6 must be added or
no v6 row can ever be `FULLY_AUTHENTICATED`**, which is easy to miss.

---

## 1. Status by phase

| Phase | State |
|---|---|
| **1 — writer + admission checks** | **Landed** (`653e1c6`). `_v6_writer.py`, `tests/_v6_fixtures.py`, `tests/test_p17_v6_writer.py` (36 tests), 5 error codes. |
| **1b — contracts + partial wiring** | **Landed.** The §5.8 acceptance/revocation contracts, the accepter/signer cross-checks, `register_workflow`'s signed event, the process-level producer identity, the §2.3 timestamp helper. `tests/test_p17_key_acceptance.py` (45 tests). |
| **1c — the wiring** | **Partial** (`d3cce8f`). The `_event_store.append_event` epoch fork landed, gated on `project_identity` presence (§3d). Still open: the trust-log/project topology split (§3c step 1-3), `provision_principal`'s signed enrolment, `PrincipalLifecycle.commit()`. No fixture migrated, so the manifest is untouched. |
| **2 — verifier boundary** | **Not started.** The clamp is still at `_verification.py:2311-2324`. Design notes in §4. |
| **1b/1c blockers** | Finding 4 **resolved 2026-08-18** — the admission rule is unchanged; it was a fixture-topology bug. §3c has the taken path and the scoped remaining work. |
| **3 — empty the manifest** | **Started.** 694 → 688 (1 of 74 files migrated). §0 has the recipe and the per-file cost. The population figure is **217 in-memory / 446 Postgres / 24 indirect / 7 slow** (NOTES-WI287 §4's causal measurement), **not** §2's name-based 167. |
| **4 — full validation** | Re-run at each session-2 checkpoint; see §0. |

Phase 1b deliberately stopped short of routing `_event_store.append_event` to the writer. Doing
that before the fixtures are migrated reddens all 694 manifest nodes with a *changed* failure
form (`KEY_BINDING_UNRESOLVED` instead of `GENESIS_REQUIRED`), which the §2.1 form validator
correctly converts to honest red. **The wiring and the fixture migration must land in one
change, file by file.** Everything 1b added is either pre-genesis-inert (`register_workflow`) or
new surface no existing caller touches, which is why it lands green on its own.

---

## 2. FINDING 1 — the manifest cannot reach literally empty under P1.7's stated non-goals

> **SUPERSEDED IN TWO WAYS, 2026-08-18.** (a) The **167 figure is wrong** — it came from a
> name-based heuristic. WI-287 measured it causally at **217** in-memory / 446 Postgres / 24
> indirect / 7 slow (NOTES-WI287.md §4); the heuristic missed 74 and wrongly claimed 30
> `[real]` Postgres parameters. (b) The **owner ratified option 3** as an acceptance
> amendment (main `cf33b04`, PR #48): "manifest literally empty" is judged at the *joint*
> completion of P1.7 and WI-287. Since `ce19e06` merged WI-287 into this branch, that joint
> point is this branch — so the target IS 0 here, and §1's old "target is 167" note was
> already stale when written. Kept below for the reasoning, which still holds.

**Measured (superseded): 167 of the 694 manifest nodes (24.1%) are in-memory-backend nodes.**

```
python3 -c "
import json,collections
d=json.load(open('tests/epoch_blocked_manifest.json'))
n=[e['node_id'] for e in d['entries']]
im=[x for x in n if 'in_memory' in x.lower() or 'InMemory' in x]
print(len(n), len(im))"
# -> 694 167
```

Top contributors: `test_in_memory_conformance.py` 56, `test_witness_in_memory.py` 20,
`test_hook_toctou.py` 10, `test_validator_context_enrichment.py` 9, `test_plan022.py` 8,
`test_read_events_conformance.py` 8, `test_replay_coverage.py` 8, `test_heartbeat_coalesce.py` 7,
`test_plan010_integration.py` 6 — 25 files in all.

Their blocker is not the Postgres writer. It is `InMemoryEventStore.check_legacy_append` /
`admit_legacy_append` (`src/regista/_event_store.py:205-215`), which raise `GENESIS_REQUIRED`
unconditionally with "the clean v6 epoch is not supported by this backend". Nothing P1.7 does to
the Postgres path moves them.

The three ways out, and why two are wrong:

1. **P1.7 also implements in-memory genesis + writer.** This is `SUITE-RECONCILIATION.md`
   §2.3 decision **D2**, which is **WI-287**, which the P1.7 brief names as an explicit
   non-goal ("a sibling agent takes it after your conformance surface exists"). Doing it here
   silently absorbs another package's scope and its Postgres-gated-claim guard.
2. **RETIRE the 167 nodes with `carry_forward` to WI-287.** Mechanically impossible without
   deleting them: `tests/test_retired_tests_ledger.py:87` asserts
   `node_id not in full_collection` — a ledger entry for a node that is still collected fails.
   So this route means *deleting 167 live C3 tests* (assurance, review validators, lineage —
   `EPOCH-RESET.md` §5's surviving core) to make a manifest read zero. That is precisely the
   "blanket module-level skip or xfail — suppresses passing coverage and is unaccountable"
   alternative decision **D1** rejected, wearing a different hat.
3. **Sequence P1.7's acceptance criterion after WI-287.** The honest one. P1.7 empties the
   ~527 Postgres-backed entries; WI-287 empties the 167 in-memory ones; "manifest literally
   empty" is satisfied at the *later* of the two, not inside P1.7.

The plan text itself already uses this shape for the P1.4 tranche — "P1.7's 'manifest literally
empty' criterion is evaluated only after those entries are already gone" (§2.2) — so option 3 is
consistent with how the document handles a dependency it does not own. It just was not written
for the D2 tranche, because §2.3 says "Until D2 is decided, C3's failing nodes ride the §2.1
manifest under their own section" and then D2 *was* decided (ratified 2026-08-16) without the
acceptance wording being revisited.

**This needs an owner decision, not an agent's choice.** It is the one thing in the P1.7 brief
that cannot be satisfied as written.

---

## 3. FINDING 2 — wiring the existing writers to v6 is a fixture migration, not a call-site swap

`_event_store.append_event` is the single funnel for legacy appends (`_events.append_event` and
`_events.append_transition_event` are the two direct-SQL siblings). Routing it to
`append_v6_event` post-genesis is a small diff. The cost is in what the v6 path *requires* that
the legacy path never did, and every one of these is a correctness requirement rather than
friction:

1. **A per-principal Ed25519 actor key.** `_v6_writer._writer_key` requires
   `entry.principal_id == actor_id`. `tests/test_keys.json` is one HMAC key with no
   `principal_id`, no `role`, no public key — unusable, exactly as the plan says. Fixtures must
   move to `tests/_v6_fixtures.make_v6_keyset`, which mints one actor-role key per principal.
2. **A `principal_key_accepted` event per principal, before its first ordinary event.** Not a
   `principal_keys` row — §5.11's last row makes the projection irrelevant and the writer
   enforces that (see `TestKeyBinding::test_a_principal_keys_row_does_not_satisfy_the_binding`).
   The suite uses many actor ids; each needs an acceptance signed by the bootstrap principal.
3. **A signed `workflow_registered` event per workflow.** `register_workflow` writes only a
   `workflow_registry` row today, and admission gate 1 refuses a row. So `register_workflow`
   must additionally append the registration event post-genesis — that is the natural home, and
   it is where the `definition`-without-`raw_yaml` requirement bites.
4. **A `producer` block.** `producer.harness` is load-bearing
   (`_genesis._REQUIRED_NONEMPTY_PATHS`), so it cannot default to absent. The honest shape is a
   process-level producer identity on the `Regista` handle (the harness/model that produces
   events is a property of the running process, not of each call), refused when unset. It is
   *not* a per-append argument. `_v6_fixtures` supplies `TEST_HARNESS`/`TEST_MODEL_LINEAGE`
   (`fable` — a real family, because gate 2 refuses anything outside
   `_lineage.MODEL_LINEAGE_FAMILIES`).
5. **No `''`/`0` workflow sentinels.** `PrincipalLifecycle.commit` passes
   `workflow_name="", workflow_version=0` today (`principal_lifecycle.py:949-950`). The writer
   refuses those by name; commit() must pass no workflow at all.

Suggested order for the successor:

1. Give `register_workflow` its signed registration event, gated on genesis being present.
2. Add the process-level producer identity + the `Regista`-level genesis helper.
3. Route `_event_store.append_event` / `_events.append_event` /
   `_events.append_transition_event` to `append_v6_event` when `project_identity` exists,
   keeping the legacy refusal when it does not.
4. Wire `PrincipalLifecycle.commit()` (drop the sentinels), then delete the monkeypatches in
   `tests/test_trust_projection.py::TestCeremonyPathRoundTrip._run_ceremony:964-971` and confirm
   it passes without them. Keep a stubbed variant only if it still adds value — it probably does
   not once the real path works.
5. Only then start on the manifest, file by file, in descending node count.

---

## 3b. FINDING 3 — a surviving mutant, and the hole it exposed

Mutation **M14** (delete the `and not revoked_matches` clause in
`resolve_key_binding_anchor`) left the suite **green**. Reporting it rather than quietly
patching, because the analysis matters more than the clause:

The branch is **unreachable today**. Reaching it needs one principal/key to hold both a live
bootstrap anchor *and* a separately revoked standalone acceptance. That state cannot be built:
a standalone acceptance confers `may_accept_keys=False` (§5.8's object has no such member), the
bootstrap principal cannot accept its own key (the `self_authorisation` refusal), and no other
principal can accept at all. It becomes reachable the moment §5.8's **registrar** path lands
("…or by the registrar"), so the clause is kept, and the code says in a comment that it is
uncovered rather than implying otherwise.

Chasing M14's reachability surfaced a real hole, now fixed: **`accepted_by` was never
cross-checked against the actual signer.** An acceptance could name any authority it liked while
being signed by someone else — a free-text claim wearing a structured field's clothes, which is
the failure mode 0.6.0 exists to remove. The payload validator structurally cannot catch it (it
sees only the document), so the check lives in the writer:
`_require_authority_matches_signer` (→ `ACTOR_SIGNER_MISMATCH`) and
`_require_authority_may_accept` (→ `PRODUCER_NOT_AUTHORIZED`, reason
`may_accept_keys_not_held`). Mutations M18/M19 confirm both are load-bearing.

## 3c. FINDING 4 — RESOLVED 2026-08-18. The admission rule is UNCHANGED; it was a fixture bug.

**Decision (coordinator, on spec-conformance grounds; owner may veto): do NOT narrow
`first_write_admission`.** My favoured resolution (1) below was wrong, and the reason is worth
recording because I had the spec in front of me and missed it.

The contradiction is resolved by **topology**, not by admission-rule scope. Verified directly:

> `TRUST-DOMAIN.md` §5.2 — "The trust-domain log. One estate-wide project, with: its own
> `project_instance_id`, named in the genesis document (`trust_log.project_instance_id`)".

The trust log is **a separate project chain**, not rows in an ordinary project's `events` table.
Bootstrap A and Bootstrap B are anchors in **different chains**: B (`project_initialized`) embeds
`bootstrap_key_acceptance`, whose `trust_event_hash` + `trust_log_checkpoint` **reference** the
trust-log enrolment *by hash*, so the project store never needs to contain a trust-log event for
its genesis to verify. §6.6 ("the cross-chain ordering window") exists precisely because the two
chains have no mutual order except through `trust_log_checkpoint_observed` — they were never
designed to share a table.

So "A precedes B" is a **cross-chain fact established by reference**, and the invariant "no
project history predates project genesis" stays exactly as strict as P1.2 made it. My reading —
"the invariant is about project history, so narrow the count" — reached the right *intuition* and
then applied it to the wrong object: the fix is to stop putting trust-log events in the project's
table, not to teach the counter to ignore them. Narrowing the rule would have permanently
weakened a genesis admission check to accommodate a fixture that models a state production cannot
produce (my own words, in the original write-up below).

**The good news: the production topology is already right.** `_trust_log_fixtures.make_trust_log_project`
(`tests/_trust_log_fixtures.py:690`) already creates its **own project schema**. Only
`TestCeremonyPathRoundTrip` conflates the two, at `_project_with_identity`: it builds a `Regista`
on `trust_store.project` — the *trust-log* project — and inserts a fake `project_identity` row
there. That is the entire defect.

### The remaining work, now precisely scoped

1. `TestCeremonyPathRoundTrip._project_with_identity` provisions a **second, ordinary** project
   and opens its epoch for real via `_v6_fixtures.open_v6_epoch`, instead of faking
   `project_identity` in the trust-log project. The keyset must contain the ceremony's actor
   (`human:requester`) and `agent:ceremony`. Pass the trust store's `trust_domain_id` through to
   `genesis_envelope(..., trust_domain_id=...)` so the two chains agree on the domain.
2. `_snapshot` (`tests/test_trust_projection.py:106`) is **already store-generic** — it only needs
   `.dsn` and `.project` — so pointing it at the ordinary-project handle is a one-line change,
   not a rewrite.
3. **Delete the third stub** (`v6_epoch_open → False`) that commit `d3cce8f` added at
   `_run_ceremony`. With the right topology the test should not need it; if it still does, that is
   a new finding and not a reason to keep the stub.
4. Enrolment appends (`principal_key_enrolled`, §5.5) target the **trust-log** store; acceptance
   appends (`principal_key_accepted`, §5.8) target the **project** chain. §5.9's own column split
   is the tell: `source_event_hash` is the *trust-log* event, `acceptance_event_hash` the *project*
   event, so a rebuild that reads both chains is the spec's shape. If P2.2's
   `_trust_projection.rebuild_projection` assumes one store, extend it with a trust-log store
   reference on the call — **do not relocate events to satisfy it.**
5. WI-299's other half unblocks with (4): `provision_principal` appends its
   `principal_key_enrolled` to the trust-log store.

### Open sub-question, flagged rather than silently decided

How a **single-store dev deployment** names its trust-log schema is not specified anywhere I
found. The strict spec-conformant option — and the one to take — is that the trust-log project is
always a distinct `project_instance_id` with its own schema, configured explicitly, with **no
implicit fallback to the current project**: an implicit fallback would recreate exactly the
shared-table state that produced this finding. That means a deployment with no configured
trust-log store cannot enrol keys, which is correct (enrolment is Gate 2, after Gate 1's trust
bootstrap) rather than merely inconvenient.

### The original write-up, kept for the record

**A project that has a trust log can never write its project genesis.**

- `append_v6_genesis` refuses unless the `events` table is **empty**
  (`_genesis.first_write_admission`, `event_count != 0` → `GENESIS_ALREADY_WRITTEN`).
- The trust log lives in the **same** `events` table — `tests/_trust_log_fixtures.py:611`
  does `INSERT INTO events`, entity kinds `trust_domain` / `principal`.
- `RECONCILIATION.md` Resolution 1 requires Bootstrap **A** (`trust_domain_established`,
  the trust-log genesis) to **precede** Bootstrap **B** (`project_initialized`): "Bootstrap A
  establishes external authority; Bootstrap B imports that authority and creates project-chain
  order."

So the required order is exactly the order the admission check forbids. This surfaced as four
real failures in `tests/test_trust_projection.py::TestCeremonyPathRoundTrip` the moment the
legacy funnel started routing on `project_identity` presence — the fixture has a trust log *and*
a (fake) project identity, which is a state the writer cannot legitimately produce.

Three candidate resolutions, none of which I should pick unilaterally:

1. **`first_write_admission` counts only project-chain events**, ignoring trust-log entity kinds
   (`trust_domain`, and `principal` events whose transition is in
   `_trust_log.TRUST_LOG_TRANSITIONS`). Narrowest change; makes "empty store" mean "no project
   events", which is what the criterion is *about*. Needs care that it cannot be widened into
   "genesis may follow arbitrary events".
2. **The trust log gets its own table or its own schema.** Cleanest conceptually — two chains,
   two homes — but it is a migration plus a rewrite of `_trust_projection.rebuild_projection`'s
   query (`_trust_projection.py:217`) and of `_trust_log_fixtures`.
3. **Genesis is permitted to follow the trust log specifically**, by requiring that every
   pre-existing event be a trust-log event and that the trust log's head be the value
   `previous_project_event_hash` chains from. Effectively (1) with an explicit allow-list.

My reading favours **(1)**, because the invariant the criterion protects is "no *project* history
predates project genesis", and trust-log events are not project history. But this changes a
genesis admission rule, which is exactly the kind of thing that should not be loosened by an
implementer mid-migration — **`prefer-strict-defaults` cuts against me here**, so it needs the
owner or the coordinator.

**Until the restructure above lands:** `TestCeremonyPathRoundTrip` carries a third stub
(`v6_epoch_open → False`), added by `d3cce8f` when Finding 4 was still open. It is now known to be
a workaround for a fixture-topology bug rather than for a spec gap, so it is **debt with a
deadline**: step 3 above deletes it. It keeps testing its real subject (payload construction, the
appliers, the rebuild) in the meantime.

## 3d. What 1c actually landed, and what it did not

**Landed:** the epoch fork in `_event_store.append_event`, gated on `project_identity` presence,
so a project without genesis still refuses with `GENESIS_REQUIRED` — measured against the
manifest, whose 694 entries record exactly two forms and **no `V6_EPOCH_OPEN`**:

```
666  {"error_code": "GENESIS_REQUIRED", "exception": "RegistaError"}   (direct)
 18  {"exception": "AssertionError", "signature": "assert 409 == 200"} (indirect)
  5  {"exception": "KeyError", "signature": "KeyError: 'work_item'"}
  4  {"exception": "AssertionError", "signature": "GENESIS_REQUIRED"}
  1  {"exception": "AssertionError", "signature": "assert 0 > 0"}
```

That is *why* the gate is on identity presence rather than a flag: every recorded form stays true
for an unmigrated project, so the migration can proceed file by file without the form validator
converting the whole manifest to red at once.

Also landed: `V6AppendRequest` + `_v6_request`, the single place the legacy→v6 translation lives
(the `""`/`0` workflow sentinel becomes `null`; `on_behalf_of` is **refused**, not dropped,
because discarding it would make a delegated event read as direct action);
`PostgresEventStore.v6_epoch_open` / `.append_v6` preserving idempotency and
`expected_event_seq`; `InMemoryEventStore` answering `False` so WI-287's tranche keeps its
recorded form; and `tests/_v6_fixtures.open_v6_epoch(instance, keyset)` — the one call a migrated
fixture needs (genesis, then a standalone acceptance per principal, then the producer env).

**Not landed:** no test file has been migrated, so the manifest is still 694. `provision_principal`
still refuses (WI-299's other half is blocked on Finding 4 too — enrolment is a *trust-log* event,
so it needs the trust log, which is the state genesis forbids). Phases 2, 3 and 4 untouched.

## 4. Phase 2 design notes (the verifier boundary)

The clamp is `_verification._verify_v6_row`, final return, `_verification.py:2311-2324`:

```python
        applicability=Applicability.INVALID,
        reasons=(FailureReason.ENVELOPE_SCHEMA_INCOMPLETE,),
        detail=(
            "v6 bytes and duplicated row fields verify; project, trust, key-binding, "
            "workflow and delegation referents require the v6 verifier boundary"
        ),
```

Everything above that point already works: signature over stored bytes, scheme equality with the
trusted key, and full row reconciliation via `_reconcile_v6` (`:1946`), whose field map is exact
and needs no change.

What replaces it is `TRUST-DOMAIN.md` §5.10's six steps plus §5.11's table. Notes from reading:

- **Steps 1-4 are chain traversal, not a query.** §5.10 step 3 is explicit that reachability is
  by following `chain.previous_project_event_hash`, "not by `occurred_at` … and not by
  `global_seq`". The writer's `_anchor_candidate_rows` orders by `global_seq` and says in its
  docstring why that is legitimate *at write time* (everything committed is behind the head) —
  **the verifier may not borrow that shortcut.** It is handed possibly-adversarial material.
- **`AcceptanceScopes` and `_anchor_from_row` in `_v6_writer.py` are reusable** for step 2's
  "same principal/key/project" check; they parse the *signed envelope*, never the `payload`
  column, which is the property the verifier needs too.
- **§5.11 needs the completeness claim as an input.** `KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE`
  vs `KEY_BINDING_UNRESOLVED` turns entirely on whether the material claims completeness
  (`complete-store` bundle scope, or an online store). `VerificationPolicy` has no such field
  today; it needs one, and the default must be the *stricter* reading for an online store.
- **The new `FailureReason` members** Resolution 2 §"VerificationResultV6" enumerates are not all
  present yet — check `_verification.FailureReason` against that list before starting.
- **WI-296's genesis-key question.** The item offers two options: `write_genesis` seeds the
  `principal_keys` projection row from its `bootstrap_key_acceptance`, or the bundle carries key
  evidence from the genesis payload. **Recommendation: the bundle route.** Seeding the
  projection from genesis reintroduces exactly the coupling §5.9 rule 1 forbids ("no verifier
  resolves a key from this table for a v6 event") — a row that exists *because* the verifier
  needs it is a fallback with extra steps. The acceptance payload already repeats `public_key`
  "on purpose" (§5.8) so a bundle is self-sufficient for key material; the genesis payload's
  `bootstrap_key_acceptance` carries the same field. Export should read it from there.
- **§9 criteria 14 and 15** become testable here (`ENROLLMENT_AFTER_USE`; complete-store INVALID
  vs contiguous-range UNVERIFIABLE). Criterion 15's bundle half needs the scope input above.
- **Tests that pin the clamp will redden and must be updated, not weakened:**
  `tests/test_bundle.py:50-55` (`_V6_BOUNDARY_FINDING = "require the v6 verifier boundary"`) and
  `:461` (`assert sv["verified"] is False  # the v6 verifier boundary, not a bundle defect`).
  Those are the WI-296 assertions; flipping them to `True` is the *point* of Phase 2, and the
  comment text should be rewritten rather than deleted.

## 5. WI-299 (criterion 19's positive clause)

Not restored. The closing condition on WI-299 is: enrolment becomes a signed
`principal_key_enrolled` event applied via `_principal_keys._apply_enrollment_projection`, at
which point `provision_principal("agent:...")` succeeds instead of failing with
`PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED`. That needs step 3/4 of §3 above — `provision_principal`
has to append through the v6 writer. The adapted test is
`tests/test_p23_enrolment_inversion.py::test_enroll_principal_refuses_a_bare_name_and_accepts_a_canonical_one`;
its four current assertions are listed verbatim on WI-299 and only assertion 2 changes.

## 6. WI-289 clusters

Cluster 4 (bundle v3, ledger entries 1-11) stays owed to P3.3. Cluster 6 (in-memory parity —
ledger entries for `test_global_event_chain.py::test_bc300_in_memory_...`,
`test_hash_chain.py::TestBC233HashChainInMemory::*`,
`TestBC311ReplayChainFields::test_replay_succeeds_with_missing_envelope_in_memory`,
`test_wi267_row_authentication.py::TestInMemoryBackendParity::*`) goes with WI-287. That leaves
clusters 1, 2, 3 and 5 — roughly 39 of the 56 — as P1.7's. Several are already covered in shape
by `tests/test_p17_v6_writer.py::TestSemanticConformance` (JCS fixed point, row reconciliation,
entity/project chain links, null workflow columns) but **no node_id → new-test mapping has been
recorded on WI-289 yet**, and that mapping is part of its closure note. Do it as each counterpart
lands, not at the end.

## 7. The WI-287 parametrization seam, concretely

`tests/test_p17_v6_writer.py::TestSemanticConformance` is the seam. Every assertion in it is about
the envelope the writer produced, the verdict verification returned, or the row projection —
nothing about locking, rollback or concurrency. WI-287 parametrizes it by replacing the
`project` / `genesis` fixtures with backend-parametrized ones and changing nothing in the class
body. `TestPostgresOnly` is deliberately outside the seam (global-chain sentinel, entity-chain
predecessor refusal) per §2.3(a)'s "locking, rollback, persistence, and concurrency/races remain
Postgres-only".

## 8. Small things found while reading

- `V6-ENVELOPE.md` §2.3's `occurred_at` is a **single** lexical form with exactly six fractional
  digits. `datetime.isoformat()` emits three for whole milliseconds and the strict parser rejects
  it; use `strftime("%Y-%m-%dT%H:%M:%S.%fZ")`. Cost me one red run.
- `event_chain_head`'s column is `head_event_id`, not `last_event_id`; `workflow_registry`'s is
  `regista_version`, not `substrate_version` (renamed by migration 028).
- `principal_keys` requires `fingerprint` and `registered_by` NOT NULL — a direct-insert test
  fixture needs both.
- Any test fixture creating a project must `close()` and `drop_project_schema` or WI-243's leak
  guard fails the whole session with a nonzero exit *after* printing "N passed".
- **Every new `ErrorCode` needs an HTTP status in `src/regista/sidecar/errors.py`.**
  `tests/sidecar/test_sidecar.py::TestErrorCodeCoverage::test_all_error_codes_have_status_mapping`
  enforces total coverage and caught all five of P1.7's codes on the first full-suite run. It is a
  good guard; the mapping is not boilerplate — the 409/403/400/500 split for these five is argued
  in a comment beside them, because "unresolvable referent" (409, the caller appends the missing
  anchor) and "not permitted" (403) and "malformed" (400) are genuinely different answers.
  Note the status map is restricted to a small sanctioned set by
  `test_status_map_values_are_valid_http_codes`, so 501 is not available.
