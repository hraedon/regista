# Regression preservation map — retained behaviour to replacement obligation

**Purpose.** The reviewer's condition on D1 (EXTRACT): *"require a mapping from
retained behaviors and PORT/SPLIT assertions to their replacements before
deleting their protection."* This is that mapping. Nothing here authorizes a
deletion; it is the evidence F1 needs before deleting the old suite's
protection for a given behaviour is safe.

**Scope enumerated.** `find tests -type f -name "*.py" | wc -l` → **185**
files. Splitting only on `ls tests/*.py` (183 files) silently misses
`tests/sidecar/conftest.py` (3 lines) and `tests/sidecar/test_sidecar.py`
(1,239 lines) — exactly the trap this task warned about, and it recurs here
because `tests/sidecar/` is a real subdirectory one `find -mindepth 2` away
from the top level. `tests/vectors/v6/*.json` (29 files) and
`tests/fixtures/*.yaml` (2 files) are data, not tests, and carry no
disposition of their own — they retire or survive with whichever test file
loads them. Working total for this map: **185 test files** (183 top-level +
2 under `tests/sidecar/`), matching the count D20 cites ("out of 185, five
resisted disposition").

**Method.** Every test name and class cited below was found with `grep -nE
"^class Test|^    def test_|^def test_"` against the actual file, not copied
from the disposition reports — the reports were used to find candidates, then
each candidate file was opened and its names verified. Every `_v6_fixtures`
import claim was verified with `grep -rl "_v6_fixtures" tests/*.py
tests/sidecar/*.py`. The `test_in_memory_conformance.py` test count was
produced by `grep -cE "^\s*def test_"` against the file, not asserted from
memory. Kernel behaviour claims (which mutations do/don't emit events) were
read directly from `prototypes/kernel/kernel.py` and `schema.sql` and cross-
checked against `src/regista/_contract.py`, `_reducer.py`, `_links.py`, and
`_in_memory_replay.py` in the current tree. `kernel.py`, `schema.sql`, and
`test_mutations.py` are being actively edited by another agent while this was
written (to fix WI-367/WI-368) — line numbers and specific defect behaviour
in those three files are cited as observed at time of reading, not as a
frozen contract; the *structural* findings (which tables have no event
trail) do not depend on the in-flight fixes and are unlikely to change.

---

## Summary (read this first)

**9 retained behaviours** from Plan 032 §3's keep table are mapped below.
Prototype protection today:

| Behaviour | Prototype protects it today |
| --- | --- |
| PostgreSQL namespace isolation | **No** — no schema-scoping test exists in `prototypes/kernel/` |
| Workflows | **Partly** — validation and version-pinning shape exist, no role/required-field mutation test |
| Work items | **Partly** — create/transition covered by `test_mutations.py`; no query surface (`available`/`owned`/`in_states`) test |
| Claims/leases | **Partly, and wrongly in three ways** — the mutation checks assert takeover and fencing, but they did not (at time of reading) exercise the three defects the reviewer found live: expired-lease-still-honored, heartbeat reviving an expired lease, actor-vs-holder not checked |
| Events and projection | **Partly** — happy-path create→transition round-trips; the reviewer's two drift-blindness probes (payload overwriting reducer-owned fields; deleted final event) are not covered |
| Idempotency | **Yes** — `test_mutations.py::idem` matches the old contract's shape closely |
| Custom fields | **No** — no required/unknown/type/enum validation test exists in the prototype |
| Typed links | **No** — `link()`/`links_from()` have no test at all in `prototypes/kernel/` |
| Administration/CLI | **No** — `cli.py` exists (per F0a's finding (a)) but has no test file |

So: **0 of 9 fully protected, 4 partly, 5 not at all**, before counting the
in-flight fixes to the three claim defects. That is the honest starting
line for F1, not a criticism of the prototype — a 736-line, two-week
instrument was never going to carry 185 files of earned coverage, and F0a's
job was to prove the *shape* of the API, not qualify it.

**The `_v6_fixtures.py` blast radius, counted:** 81 of the 183 top-level test
files (44.3%) import it; 82 of 185 counting `tests/sidecar/test_sidecar.py`.
Of those 81, **45 carry at least one PORT- or SPLIT-classified assertion**
that must survive into the kernel — meaning 45 files need their *setup*
rewritten against whatever F1's connect/register path becomes before a
single one of their assertions can be ported. The other 36 of the 81 are
full-RETIRE files whose only interest in `_v6_fixtures` was bootstrapping a
signed epoch to test something else that is also going away. See §A.

**The in-memory backend costs exactly 35 tests** (counted:
`grep -cE "^\s*def test_" tests/test_in_memory_conformance.py` → 35),
spanning 13 classes that track the keep table almost one-to-one. 32 of the
35 run through the `sub` fixture parametrized `["real", "in_memory"]` — i.e.
the *same test body* already runs against real PostgreSQL today, so
retargeting is deletion of the `in_memory` parametrization branch, not new
test-writing, for those 32. The remaining 3 (`TestBC189OrphanEventDetection`
×2, `test_heartbeat_actor_kind_emitted_in_memory_with_keys`) touch
`InMemoryRegista` internals or the v6-shaped `Event` dataclass directly and
need real adaptation, not just a fixture swap. See §B.

**Replay coverage gap, the sharpest finding in this map:** the prototype's
`claims`, `claim_attempts`, and `links` tables are **never written to via an
event**. `claim()`, `heartbeat()`, `release()`, `expire_leases()`, and
`link()` in `kernel.py` all mutate their tables directly with no
`_append_event` call anywhere in any of them. `replay()` reconstructs
*only* work-item state and custom fields; it does not attempt to reconstruct
claim or link state at all, and cannot, because there is no event to
reconstruct them from. The **old** tree does exactly this today —
`_contract.py`, `_reducer.py`, and `_links.py` all treat `claim_acquired`,
`claim_stolen`, `claim_released`, `claim_expired`, `claim_heartbeat`,
`link_created`, and `link_removed` as first-class transitions, and
`tests/test_replay_coverage.py` proves the old replay path derives claim
and link state — including the fencing counter itself
(`test_claim_attempt_number_reconstructed`) — from history alone. This is a
capability the kernel currently lacks entirely, not a corner case of one it
has. See §C for the precise obligation and the open question this map is
not the place to invent an answer for.

**What is protected today and would be silently lost** if F1 proceeds
without action: everything in the "replacement obligation" column below that
says "does not exist yet" — most acutely, replay-derived claim/link
recovery (§C), all custom-field validation (§7), all typed-link error paths
(§8), and the entire administration/CLI surface (§9), none of which the
prototype currently tests at all.

**Where the keep table and the existing tests disagree about the contract:**
one clear case. `test_in_memory_conformance.py::TestConformanceReplay` and
old `_replay.py`/`_reducer.py` treat claim/link mutations as reconstructible
projections; the keep table's one line on this ("Events and projection:
... ordered history, replay of supported state with honest drift
reporting") does not say *which* projections are "supported state." The
existing tests answer "all of them, including claims and links"; the
prototype currently answers "only work-item state and fields." Plan 032 and
the open-decisions review both leave this open (the review's "Additional
choices" §3) rather than settling it — so this map does not resolve it
either; §C states the question precisely instead of guessing.

---

## Behaviour 1 — PostgreSQL namespace isolation

**Invariant.** A project's schema-per-tenant boundary is real: `connect()`
scopes destructive operations (`DROP`) to the configured schema so two
identically-named tables in sibling schemas cannot collide; `create_project`
and role provisioning are idempotent, safe to call from concurrent
callers without deadlocking on catalog DDL, and cannot be redirected outside
the configured schema by a caller-supplied name; dropping a project's schema
removes its catalog row exactly once and leaves no net catalog growth across
repeated create/drop cycles.

**What protects it today (old tree, verified by opening each file).**
- `tests/test_bc188_connect_search_path.py::TestConnectSetsSearchPath::test_drop_old_replay_tables_does_not_touch_sibling_schema` and `::test_connect_sets_search_path_session` (lines 18, 72).
- `tests/test_provision.py::TestProvision::test_provision_creates_schema_and_role`, `test_provision_idempotent`, `test_provision_multiple_projects`, `test_provision_dry_run`, `test_provision_cross_schema_denied` (lines 29–100).
- `tests/test_wi246_concurrent_create.py::TestConcurrentCreateProject::test_concurrent_create_project_no_deadlock`, `test_concurrent_provision_plus_create_project_no_deadlock`; `TestCatalogBootstrapConcurrency::test_ensure_catalog_table_concurrent` (lines 27, 47, 96) — guards a real production deadlock hazard on catalog-table creation under concurrent connects.
- `tests/test_wi243_schema_leak.py::TestDropProjectSchemaUnregistersCatalog::test_drop_removes_catalog_row`, `test_drop_is_idempotent_and_safe_on_missing_schema`; `TestCreateProjectRegistersCatalog::test_create_registers_and_drop_cleans`; `TestCatalogRowCountStableAcrossCreateDrop::test_create_drop_roundtrip_leaves_no_net_growth` (lines 36–102).

**Does the prototype protect it today?** **No.** `prototypes/kernel/` has no
`create_project`/`provision`/`drop_project_schema` equivalent at all —
`Kernel.connect()` takes a DSN and a schema string and issues `SET
search_path`, but nothing in `test_mutations.py` or the two example scripts
exercises cross-schema isolation, concurrent bootstrap, or catalog hygiene.

**Replacement obligation.** Before `test_bc188_*`, `test_provision.py`'s
kernel-relevant classes, `test_wi246_*`, and `test_wi243_*` may be deleted,
the kernel needs: (1) whatever `create_project`/schema-init equivalent it
ends up with, exercised under concurrent callers without deadlock; (2) a
`DROP`-scoping test proving a sibling schema is untouched; (3) a catalog (or
catalog-equivalent) create/drop round-trip test with no net growth. None of
this exists yet. The old assertions port with the schema/DSN plumbing
replaced, not with logic changes — this is a moderate-cost, not cheap, port
because the kernel has no provisioning layer yet at all (`kernel_meta`
existence check in `initialize()` is the only thing standing in for it).

**Deliberately changed?** No signing/trust content here. Nothing
RETIRED-BY-DESIGN in this behaviour.

---

## Behaviour 2 — Workflows

**Invariant.** A workflow version, once registered, is immutable; re-
registering identical content is a no-op (same version returned); a work
item pinned to workflow version N only accepts version-N transitions even
after version N+1 is registered; states/transitions/roles/required-fields
are validated at registration time and a semantically invalid workflow
(unreachable state, undeclared role, transition into/out of an unknown
state) is refused before it can be used.

**What protects it today.**
- `tests/test_validate_yaml.py` — `TestValidateYamlValid` (3 tests),
  `TestValidateYamlInvalidYaml::test_invalid_yaml_syntax`,
  `TestValidateYamlSchemaErrors::test_missing_name`, `test_missing_states`,
  `TestValidateYamlSemanticErrors::test_unreachable_state`,
  `test_undeclared_role_in_transition`, `TestValidateYamlResultShape` (3
  tests) — pure-function validation, no database, no signing (lines 11–130).
- `tests/test_version_pinning.py::TestAC12PinnedVersionIsolation::test_v1_work_item_rejects_v2_only_transition`, `test_v2_work_item_accepts_shortcut`, `test_v1_work_item_uses_v1_transitions` (lines 99–152) — the single highest-value test for "immutable registered versions, work-item version pinning," named verbatim in the keep table.
- `tests/test_sf2_workflows.py` — states/transitions/roles/required
  fields/version pinning/typed links/escalation-by-attempt-count against a
  real multi-actor workflow definition.

**Does the prototype protect it today?** **Partly.**
`Workflow.validate()` in `kernel.py` implements the same semantic checks
(unknown state in transition, unreachable initial state, policy naming an
unknown transition), and `register_workflow()` does content-hash comparison
for idempotent re-registration — the *mechanism* for immutability and
version pinning exists (`workflow_version` is stored per work item and
`get_workflow(name, version)` looks up the pinned version explicitly). But
`test_mutations.py` never exercises version pinning across two registered
versions, nor the semantic-validation refusal paths, nor loading a workflow
from YAML (only a `Workflow(...)` dataclass literal is used in the test
harness).

**Replacement obligation.** Two things must exist before `test_validate_yaml.py`
and `test_version_pinning.py` may be deleted: (1) a YAML-loading path in the
kernel (currently `Workflow.from_json`/`as_json` exist but nothing parses
YAML — `register_workflow_file` from the old API has no kernel equivalent
yet), with the same semantic-validation test matrix; (2) a version-pinning
mutation test: register v1, create an item, register v2, prove the v1 item
still only accepts v1 transitions. Both are essentially direct ports of the
existing assertion bodies once the kernel has a YAML front door — cheap once
that front door exists, not cheap before it does.

**Deliberately changed?** Workflow inheritance/composition
(`test_workflow_compose.py`) is RETIRED-BY-DESIGN per D21 (ruling: "remove
workflow composition — the exception was considered and declined"). No other
part of this behaviour is intentionally dropped.

> **DISCHARGED 2026-09-19.** Both replacement obligations now exist in
> `prototypes/kernel/`. (1) The YAML/JSON front door is
> `workflow.schema.json` + `load_workflow()` /
> `validate_workflow_document()` / `Workflow.from_document()` /
> `as_document()`, wired into the CLI as `workflow register --file` and
> `workflow validate --file`; both shipped scenarios now register from a
> checked-in document rather than a Python literal, so the front door is on
> the scenario path and not merely present. Its semantic matrix
> (`the document validation matrix refuses each rule and passes the clean
> file`) covers every rule `test_validate_yaml.py` asserted **plus** four the
> 0.7 loader did not have: duplicate state names, duplicate transition names,
> a declared-but-unused role, and a duplicated YAML mapping key.
> (2) Version pinning is `a work item keeps its workflow version's rules
> after a v2 is registered` — the direct port of
> `TestAC12PinnedVersionIsolation`, with the explicit-`workflow_version=1`
> leg added. Each was proven non-vacuous by reintroducing the defect into a
> scratch copy: 16 mutants, 16 killed.
>
> **One 0.7 check has no counterpart and is deliberately dropped:**
> `test_undeclared_role_in_transition` validated a transition's roles against
> a top-level role catalogue. The kernel keeps the catalogue (`roles:` in the
> document, `Workflow.role_names`) and cross-checks it in **both**
> directions, so the assertion survives in stronger form — but the 0.7 notion
> of a role *object* with its own properties does not.

---

## Behaviour 3 — Work items

**Invariant.** Public create/query/transition paths return stable IDs and
typed results/errors; discovery queries (`available`, `owned`, blocked,
review-ready) are bounded, predictably ordered over workflow-defined states
and claim facts, and reject undeclared work-item types or unregistered
workflows before creating anything.

**What protects it today.**
- `tests/test_smoke.py::TestWorkItem`, `TestTransition`, `TestQuery` (the
  broadest single end-to-end test; register/create/transition/query/replay
  in one file — F0a's own "minimal public example" shape).
- `tests/test_remaining_errors.py::TestWorkItemTypeNotDeclared::test_create_rejects_undeclared_type`, `TestWorkflowNotRegistered::test_create_rejects_unknown_workflow`, `TestDbNotFound::test_connect_without_create_rejects` (lines 57–190).
- `tests/test_in_memory_conformance.py::TestConformanceWorkItem::test_create_and_get`, `test_create_missing_required_field`, `test_create_unknown_type`; `TestConformanceQuery::test_query_by_state`, `test_query_by_workflow`, `test_query_with_cursor` (lines 62–394) — 6 of the 35 in-memory-conformance tests.

**Does the prototype protect it today?** **Partly.** `create_work_item` and
`transition` are exercised by every case in `test_mutations.py`. The
discovery query surface (`available`, `owned`, `in_states`) exists in
`kernel.py` but has **zero tests** — no pagination, ordering, or
workflow/state-filter assertion anywhere in `prototypes/kernel/`.

**Replacement obligation.** Before `test_in_memory_conformance.py`'s query
classes and `test_remaining_errors.py`'s type/workflow-refusal tests may be
deleted: a direct port of the create-refusal tests (undeclared type,
unregistered workflow — both already refuse in `kernel.py` via
`get_workflow` raising `InvalidWorkflowError`, just untested), plus new
tests for `available`/`owned`/`in_states` ordering and pagination, which
have no precedent test to port from since the prototype's query shape
(`limit`, no cursor) differs from the old API's cursor-based
`test_query_with_cursor`. This is a genuine gap, not a port.

> **CORRECTION 2026-09-19 — "just untested" was wrong for half of it.**
> `get_workflow` refuses an unregistered *workflow*. Nothing refused an
> undeclared work-item **type**: `create_work_item` took `type` as a free
> string and inserted it, and `Workflow` had no notion of a declared type set
> at all. Deleting `test_remaining_errors.py::TestWorkItemTypeNotDeclared` on
> the strength of this paragraph would have dropped the protection with
> nothing behind it — the exact failure mode this map exists to prevent, and
> a reminder that "already refuses, just untested" is a claim to *run*, not
> to read. Implemented 2026-09-19: `Workflow.types` is a closed set,
> `validate()` refuses a workflow declaring none, `create_work_item` refuses
> a type outside it without partial effect, and the document's
> `work_item_types:` is where it is declared. Covered by `an undeclared
> work-item type is refused and a declared one is created`.
>
> The discovery-query half of this obligation (`available`/`owned`/
> `in_states` ordering and pagination) was **already closed** by the paging
> work that landed after this map was written — see `keyset paging covers
> every row exactly once, and a dead cursor refuses` and `every collection
> query is bounded and resumable`.

**Deliberately changed?** No.

---

## Behaviour 4 — Claims/leases

**Invariant.** A durable lease has an expiry; heartbeat extends it only
while it is still live and only for its current holder; expiry is decided
by the database clock, not any caller's; **a takeover invalidates the
previous attempt such that a write carrying it is refused without partial
effect**; the fencing token (`attempt`) is monotonic per work item and is
never reissued, even across many takeovers; a lease-protected write must be
made by the actor who holds the lease, not merely carry a currently-valid
attempt number belonging to someone else; rapid heartbeats coalesce into one
event without failing to extend the lease.

**What protects it today (old tree).**
- `tests/test_stale_heartbeat.py::TestAC07StaleHeartbeat::test_heartbeat_rejects_different_actor`, `test_heartbeat_rejects_after_auto_steal`, `test_valid_heartbeat_succeeds` (lines 42–79).
- `tests/test_coverage_gaps.py::TestExpectedAttemptNumber::test_heartbeat_rejects_stale_attempt_number` (line 544), `test_heartbeat_accepts_correct_attempt_number` (line 560) — the fencing-token contract the plan calls out by name.
- `tests/test_heartbeat_coalesce.py::TestComputeCoalesceThreshold` (3 tests) and `TestHeartbeatCoalescing` (6 tests, lines 63–147) — event-storm suppression without breaking extension.
- `tests/test_production_readiness.py::TestClaimStolenMetric` — takeover/fencing semantics: a stolen claim emits an event and a metric, the same actor re-acquiring does not count as stolen.
- `tests/test_in_memory_conformance.py::TestConformanceClaims::test_acquire_and_release`, `test_claim_contested`, `test_heartbeat`, `test_claim_releases_on_transition` (lines 245–300) — 4 of the 35.

**Does the prototype protect it today?** **Partly, and this is the sharpest
gap in the whole map.** `test_mutations.py` at time of reading covers:
stale-attempt refusal after a real takeover (`fencing_bites`), omitted
attempt under a live lease (`attempt_required`), fencing-token monotonicity
across four takeovers (`attempt_monotonic`), and simple claim contention
(`live_lease_contested`). It does **not** cover the three defects the
reviewer's probe table records against `kernel.py` as read on 2026-09-17:
(a) transitioning with a *stale* attempt succeeds if the lease has expired
but not yet been swept by `expire_leases()` — `transition()`'s fencing check
only fires `if lease and lease["live"]`, so an expired-but-present lease row
imposes no check at all; (b) `heartbeat()` matches on `(actor_id,
attempt_number)` only, with no liveness predicate, so it can revive an
already-expired lease; (c) `transition()` never compares the calling
`actor_id` against `lease["actor_id"]` — a different actor presenting the
live holder's current attempt number succeeds. These are tracked as
WI-367/WI-368 and another agent is fixing `kernel.py` concurrently with this
document; whether the fixes land with matching regression tests is the
thing to verify before deletion, not this map's job to assert.

**Replacement obligation.** Direct, cheap ports once the defects are fixed:
`test_stale_heartbeat.py`'s three cases, `test_coverage_gaps.py`'s
`TestExpectedAttemptNumber` pair, and `test_production_readiness.py`'s
stolen-claim-metric case all translate almost verbatim to `kernel.py`'s
shape (`claim`/`heartbeat`/`transition` with `attempt`). `test_heartbeat_coalesce.py`
requires the kernel to grow heartbeat coalescing at all — `kernel.py` has no
`heartbeat` coalescing logic today; every `heartbeat()` call unconditionally
issues an UPDATE, so this is new work, not a port, if coalescing is kept. The
three reviewer-found defects each need a **named regression test** mirroring
the probe table in `plans/032-open-decisions-review.md` (expired-lease
transition refused; heartbeat cannot revive an expired lease; actor-vs-
holder mismatch refused) before the corresponding old tests may be deleted —
these are new tests, since nothing in the old suite happens to phrase the
assertion exactly this way (the old kernel's design made two of these three
states structurally unreachable, so the old suite never needed to test for
them).

**Deliberately changed?** No — this is explicitly named in Plan 032 §1 and
F2 as a required-to-harden invariant, not something being dropped.

---

## Behaviour 5 — Events and projection

**Invariant.** Every mutation appends its event and updates the current-
state projection atomically (both commit or neither does); event sequence
numbers are gap-free per work item even under concurrent writers; replay
reconstructs supported state from the event log alone and reports
disagreement with the live projection rather than silently trusting either
side; a tampered event (payload edited, or the final event of a sequence
deleted) is detected as drift, not silently accepted; reasonable history
sizes remain practical to query and replay (no whole-log materialization).

**What protects it today.**
- `tests/test_concurrency.py::TestAC28ConcurrentSeqGapFree::test_concurrent_appends_are_gap_free`, `test_concurrent_transitions_gap_free` (lines 47, 87) — 20 concurrent workers.
- `tests/test_bc310_replay_isolation.py` — `REPEATABLE READ` isolation so replay never observes a concurrent write mid-flight.
- `tests/test_replay.py::TestAC29OutOfBandEditDrift::test_direct_state_update_detected_as_drift`, `test_direct_custom_fields_update_detected_as_drift`, `test_no_drift_after_normal_operations` (lines 57–108) — direct out-of-band UPDATEs detected as drift; the negative control matters as much as the positive cases.
- `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed` (6 tests) and `TestUnvisitedProjectionRowsHalt` (6 tests, lines 90–390) — replay must *fail*, not warn, on hash-chain breaks, orphan rows, forks, and a fabricated projection row with zero backing events. This is the file the review calls "the single highest-value file... after WI-217 and WI-246."
- `tests/test_wi217_replay_memory.py` — replay's peak memory does not scale with log size; guards a real ~2 GiB-per-replay production incident.
- `tests/test_wi242_readonly.py` — replay leaves no temp-table residue and works under a read-only session.

**Does the prototype protect it today?** **Partly.**
`test_mutations.py::chain_detects_tamper` and `::chain_detects_deletion`
prove `replay()` detects an edited payload and a deleted *middle* event. It
does **not** cover the reviewer's two sharper findings: (1) transitioning
with `fields={"amount": 2}` and `payload={"fields": {"amount": 999}}`
produces a projection of `2` but a replay of `999` with `drift=[]`, because
`transition()` merges `payload` into the event's stored payload *after*
computing `merged` for the projection (`payload={"from": state, "to": to,
"fields": fields or {}, **(payload or {})}` in `kernel.py`), so a caller-
supplied `payload["fields"]` silently overwrites the reducer-owned
`fields` key that `replay()` later reads back; (2) deleting the *final*
event of a transition that changed fields (rather than a middle one)
produces `drift=[]` because `replay()`'s only comparison against the live
projection is `current.state != state` — it never compares the replayed
`fields` dict against `work_items_current.custom_fields` at all. Both are
open (WI-368) as of this reading. There is no concurrency/gap-free test, no
memory-bound test, and no read-only-session test in `prototypes/kernel/` at
all — `test_wi217_replay_memory.py` and `test_wi242_readonly.py` protect
properties the prototype has never been asked to demonstrate.

**Replacement obligation.** This is where the map's "cheap case" and
"expensive case" sit side by side. Cheap, direct ports once the payload/
field-drift defects are fixed: `test_replay.py`'s three AC29 cases port
almost unchanged (same assertion: an out-of-band edit is drift). Expensive,
new work: `test_wi266_fail_closed.py`'s 12 cases assume a global hash chain
across all work items with a documented head, which `kernel.py`'s
per-work-item-only `prev_event_hash` chain does not have an equivalent of —
these need either a per-work-item restatement of each case or an explicit
decision that whole-store tamper detection is out of scope for 0.8.0 (Plan
032 does not say either way). `test_wi217_replay_memory.py` needs a kernel
`replay()` that streams rather than materializes — `kernel.py`'s current
`history()` calls `cur.fetchall()` unconditionally, which is the exact shape
the WI-217 regression was written to catch; porting the *test* without first
changing `history()` to stream would make it fail immediately, which is
correct but means this is not a same-day port.

**Deliberately changed?** The **global** cross-work-item hash chain
(`tests/test_global_event_chain.py`, `tests/test_hash_chain.py`,
`tests/test_plan024_global_chain.py`) is RETIRED-BY-DESIGN — it binds
`prev_global_event_hash` to signature bytes by construction
(`sha256(prev.canonical_envelope || prev.signature)`), so it cannot survive
signing's removal in any form, and no plan text asks for a signature-free
replacement of the *global* (cross-item) chain specifically. The
**per-work-item** consistency chain is explicitly kept (Plan 032 §3: "atomic
append plus current-state update"; the kernel's own docstring: "kept for
CONSISTENCY only"). Do not conflate the two: retiring the global-chain tests
is correct; treating that as license to also drop per-item drift detection
would be the silent-loss failure mode this map exists to prevent.

---

## Behaviour 6 — Idempotency

**Invariant.** Identical retries (same idempotency key, same request) do not
duplicate effects; reusing a key for a materially different request refuses
without partial effect; this holds for both `append_event`-style
`event_id` reuse and explicit `idempotency_key` reuse, and for optimistic
concurrency checks (`expected_event_seq`/`expected_attempt_number` mismatch
refuses cleanly).

**What protects it today.**
- `tests/test_idempotency.py::TestAC24IdempotencyMismatch::test_same_event_id_different_transition_rejected`, `test_same_event_id_different_actor_rejected`, `test_idempotent_retry_returns_original`; `TestAC25ExpectedEventSeq::test_expected_seq_mismatch_rejected`, `test_expected_seq_match_accepted`, `test_expected_seq_on_transition` (lines 47–153).
- `tests/test_claim_link_idempotency.py` — duplicate `event_id` on claim acquire/release and link create/remove produces no duplicate events.
- `tests/test_contract.py::TestCheckIdempotency` (6 tests, lines 203–248) and `TestCheckExpectedSeq` (3 tests, lines 250–261) — the unit-level validation-layer tests, almost line-for-line what the kernel needs.

**Does the prototype protect it today?** **Yes**, for the `idempotency_key`
shape. `test_mutations.py::idem` proves: identical retry returns the
original state without duplicating the event (`last_event_seq == 1` after
two calls with the same key), and reusing the key for a different request
(`submit` instead of `start`) refuses with `IdempotencyConflictError` and
leaves the state unchanged (`state == "doing"`, not partially advanced).
This is a close, direct match to `TestAC24IdempotencyMismatch`'s intent.

**Replacement obligation.** Low. The idempotency-key mechanism is already
tested to the old contract's standard. What's missing: `expected_event_seq`-
style optimistic concurrency has no kernel equivalent or test at all —
`transition()` takes no `expected_seq` parameter, so
`TestAC25ExpectedEventSeq`'s three cases have nothing to port to yet. The
review's "Additional choices" section flags this directly: "Preserve
optimistic `expected_event_seq`-style checks; a valid lease alone does not
mean a reviewer approved the current content." Until the kernel grows that
parameter, those three tests cannot be ported — they are a gap, not a
pending port.

**Deliberately changed?** No.

---

## Behaviour 7 — Custom fields

**Invariant.** Fields are validated against the workflow's declared schema
at create and at transition (missing required field, unknown field, wrong
type, invalid enum value all refuse before any write); fields merge
(shallow) rather than replace across transitions, so a rejected proposal's
prior fields survive a rework by default; bounded filtering over custom
fields is queryable.

**What protects it today.**
- `tests/test_remaining_errors.py::TestCustomFieldViolation::test_missing_required_field_on_create`, `test_unknown_field_on_create`, `test_wrong_type_on_create`, `test_invalid_enum_on_create`, `test_custom_field_violation_on_transition` (lines 132–189).
- `tests/test_in_memory_conformance.py::TestConformanceCustomFieldFilter::test_custom_field_filter`, `test_custom_field_filter_unknown_key`, `test_custom_field_filter_nested_json_containment` (lines 448–543) — 3 of the 35.
- `tests/test_coverage_gaps.py` — custom-field filter query (per the disposition report; not independently re-verified line-by-line here beyond the class list already confirmed for `TestExpectedAttemptNumber`).

**Does the prototype protect it today?** **No.** `kernel.py`'s
`create_work_item` and `transition` accept `fields: dict[str, Any] | None`
with **zero validation** — no schema, no required/unknown/type/enum
checking anywhere in the file. `Workflow.required_fields` only checks field
*presence*, never type or enum membership. `test_mutations.py::required_field`
tests presence only (`note` missing vs. supplied). This is a real, current,
undefended gap: any caller can write any JSON-serializable value under any
key today.

**Replacement obligation.** High — this is new implementation plus new
tests, not a port. Plan 032 §3 requires "basic validated domain data," and
D7 (adopted) requires shallow-merge semantics plus "one explicit atomic way
to clear them" (e.g. `unset_fields`) that does not exist in `kernel.py`
either. Before `test_remaining_errors.py::TestCustomFieldViolation` and
`test_in_memory_conformance.py::TestConformanceCustomFieldFilter` may be
deleted, the kernel needs a field-schema concept at all, plus a documented
merge-semantics test proving old fields survive a rework (matching F0a's own
scenario 2 finding) and a test for the new explicit-clear operation D7
requires. None of this is optional per the plan; all of it is currently
absent.

**Deliberately changed?** No — the plan requires this to exist, just not
yet built. D7's "document, don't change" ruling applies to merge semantics
specifically (already correct in the design), not to validation (which is
simply missing).

---

## Behaviour 8 — Typed links

**Invariant.** Links between work items are typed and explicit; an
unregistered link type refuses; a link to a nonexistent target refuses;
removing a nonexistent link refuses; link creation/removal is itself
event-recorded (`link_created`/`link_removed`); a typed ref on a work item
(not just a link row) must resolve to an existing UUID of the declared type,
including union/multi-target ref types; links do not introduce transitive
traversal or scheduling.

**What protects it today.**
- `tests/test_link_errors.py::TestLinkErrorPaths::test_disallowed_link_type_rejected`, `test_link_target_not_found_rejected`, `test_remove_nonexistent_link_rejected`, `test_link_removed_event_emitted` (lines 35–96).
- `tests/test_work_item_ref_validation.py` — `TestWorkItemRefCreateValidation` (7 tests), `TestWorkItemRefTransitionValidation` (3 tests), `TestMultiTargetWorkItemRefCreateValidation` (4 tests), `TestMultiTargetRegistrationValidation` (4 tests) — 18 tests total, lines 79–569.
- `tests/test_in_memory_conformance.py::TestConformanceLinks::test_create_and_query` (line 303) — 1 of the 35.
- `tests/test_replay_coverage.py::TestReplayLinkLifecycle::test_replay_derives_link_created_and_removed` (line 152) — see §C.

**Does the prototype protect it today?** **No, not at all.**
`kernel.py::link()` rejects only self-links (`source == target`); it does
not check the link type against any registered vocabulary (there is no
registered link-type concept in the kernel at all — `link_type: str` is
accepted verbatim), does not check that either endpoint exists (no
`work_items_current` lookup before the `INSERT INTO links`), and
`links_from()` has no error path tested. There is no test file exercising
`link()` or `links_from()` anywhere in `prototypes/kernel/`.

**Replacement obligation.** High. The kernel needs: (1) endpoint-existence
validation on `link()` (currently absent — a link to a nonexistent UUID
silently succeeds, subject only to the FK constraint in `schema.sql`, which
will raise a raw `psycopg` integrity error rather than a typed
`KernelError`); (2) a link-type vocabulary if one is going to be validated
at all (undecided — D6's bounded link-aware query ruling is adjacent but
does not settle whether link *types* are declared per-workflow); (3) typed-
ref validation on work-item fields themselves, which is a distinct
mechanism from the `links` table and has no prototype equivalent whatsoever.
`test_work_item_ref_validation.py`'s 18 tests protect a feature — typed refs
embedded in custom fields, validated against a declared type — that does
not exist in the kernel's data model at all yet. This is the largest single
gap found in this map relative to file count: 18 tests with zero prototype
counterpart.

**Deliberately changed?** No. D6's ruling ("one bounded single-hop
read-only link-aware query") is additive to this behaviour, not a
replacement for it, and is itself unimplemented in the prototype
(`F0a-report.md` §4 records it as the one thing not fixed because it needed
a ruling, not a patch — the ruling landed 2026-09-17, after F0a's report was
written).

---

## Behaviour 9 — Administration/CLI

**Invariant.** A small CLI (init/workflow/inspection/replay/health) exposes
the same operations as the library, with no private-attribute access; JSON
and human output modes agree on exit code (a `--json` failure body must not
report exit 0); the library never contaminates stdout with logging; startup
refuses to proceed against pending migrations or an incompatible workflow
version, naming the specific issue.

**What protects it today.**
- `tests/test_startup_integrity.py::TestMigrationRequired` (3 tests),
  `TestWorkflowVersionIncompatible` (4 tests, lines 21–172) — maps directly
  onto Plan 032's "initialization/open must distinguish supported new
  schemas... refuse unsupported schemas before writes."
- `tests/test_stream_discipline.py::test_library_logging_defaults_to_stderr`, `test_app_structlog_configuration_wins`, `test_handle_error_human_mode`, `test_handle_error_json_mode_emits_envelope`, `test_handle_error_retryable_codes` (lines 30–96) — guards the agent-notes WI-019 stdout-contamination root cause by name.
- `tests/test_cli_args.py::TestCLIExitCodes` — 12 kernel-relevant cases (of
  14; 2 are hooks-only and RETIRE) covering workflow validate, work-item
  show, schema status/init, replay, events show/tail, actor-roles list,
  unknown command (lines 14–86).
- `tests/test_wi229_cli_contract.py::TestJsonExitCodeAudit` — a
  contract-hygiene sweep over every `--json`-capable verb; the review (D20)
  recommends porting the audit *mechanism*, re-scoped to the 8 retained CLI
  groups, not the trust-verb test bodies.
- `tests/test_doctor.py` — DSN reachability, schema check, `CREATEROLE` role
  attribute (per the disposition report; the kernel-relevant classes were
  not independently re-opened for this map beyond confirming the file is
  SPLIT with a clear PORT half).

**Does the prototype protect it today?** **No.** `cli.py` exists
(F0a-report.md §4(a) documents it was built specifically to prove the
library/CLI parity requirement, adding `Kernel.health()` and
`Kernel.list_workflows()` when the CLI reached for private state) but has
**no test file** anywhere in `prototypes/kernel/`. `initialize()`'s
schema-refusal behavior is exercised by `test_mutations.py::refuses_legacy`
and `::idempotent_init`, which is real coverage of the startup-integrity
*shape* (refuse-without-mutation on an unsupported schema; no-op on an
already-current one) — but there is no workflow-version-incompatibility
test, no stdout-discipline test, and no `--json` exit-code test.

**Replacement obligation.** `test_mutations.py`'s two schema-refusal cases
are a legitimate, if partial, port target for `test_startup_integrity.py::TestMigrationRequired`
— the "distinguish supported/empty/unknown schema" contract is already
proven; the "incompatible workflow version" half is not. `test_stream_discipline.py`
and `test_cli_args.py`'s 12 kernel cases are direct, cheap ports once
`cli.py` has a test file — the assertions don't change, only the module
under test does. `test_wi229_cli_contract.py`'s audit mechanism is
per D20 a "port the pattern, not the body" case: write one sweep test over
the kernel CLI's actual verb set, not a translation of the trust-verb
version.

**Deliberately changed?** The CLI groups for `principal`, `secrets`,
`bundle`, `trust`, and `hooks dead-letter` are RETIRED-BY-DESIGN (signing/
custody/bundle/hooks all removed by D5/D3/D4). `test_cli_integration.py::TestPrincipalWriteSubcommandsAreRefused`,
`TestTrustRebuildProjectionCLI`, `TestHooksDeadLetterList`, and
`test_cli_args.py`'s 2 hooks lines all retire on that basis, correctly.

---

## §A — The `_v6_fixtures.py` blast radius (quantified)

`tests/_v6_fixtures.py` is a thin re-export of `regista.testing`'s
`make_v6_keyset`/`open_v6_epoch`/`ACTOR_PRINCIPALS`/`Producer`. It has zero
test functions of its own but is the shared bootstrap every one of the
following files calls to get a connected, workflow-registered project
before testing something else — signing-adjacent or not.

**Count, method: `grep -rl "_v6_fixtures" tests/*.py tests/sidecar/*.py`.**
82 files import it (81 at the top level, plus `tests/sidecar/test_sidecar.py`).
Every match was confirmed to be a real `from tests._v6_fixtures import (...)`
statement, not a comment (`grep -H ... | grep -Ev "^\S+:\s*#"` returned all
82).

Of the 81 top-level importers, cross-referencing each against its
disposition in `test-dispositions-part1.md`/`part2.md` and the D20 rulings
gives **45 files that carry at least one PORT- or SPLIT-with-a-PORT-half
assertion** — meaning the assertion body survives, but only after the
fixture it bootstraps through is replaced:

`test_bc184_bc185_metrics.py`, `test_bc215_219_220_221.py`,
`test_bc278_279_280.py`, `test_bc306_entity_kind_validation.py`,
`test_bc310_replay_isolation.py`, `test_canonical_workflow.py`,
`test_claim_link_idempotency.py`, `test_cli_integration.py`,
`test_concurrency.py`, `test_coverage_gaps.py`, `test_e2e.py`,
`test_events_partition.py`, `test_heartbeat_coalesce.py`,
`test_hook_miss_recovery.py`, `test_idempotency.py`,
`test_in_memory_conformance.py`, `test_link_errors.py`, `test_phase2.py`,
`test_phase3.py`, `test_plan007_facade.py`, `test_plan008_ws1.py`,
`test_plan009.py`, `test_plan016.py`, `test_plan022.py`,
`test_production_readiness.py`, `test_property_conformance.py`,
`test_read_events_conformance.py`, `test_remaining_errors.py`,
`test_replay_coverage.py`, `test_replay.py`, `test_replay_scoped.py`,
`test_scale.py`, `test_session13_regression.py`, `test_sf2_workflows.py`,
`test_smoke.py`, `test_stale_heartbeat.py`,
`test_validator_context_enrichment.py` (D20: SPLIT),
`test_validator_hardening.py` (D20: PORT), `test_version_pinning.py`,
`test_wi217_replay_memory.py`, `test_wi234_actor_metadata_limit.py`,
`test_wi242_readonly.py`, `test_wi266_fail_closed.py`,
`test_wi289_v6_counterparts.py`, `test_work_item_ref_validation.py`.

The remaining 36 of the 81 (`test_bc214_216_217_218.py`,
`test_global_event_chain.py`, `test_hash_chain.py`, `test_hook_consumer.py`,
`test_hook_primitives.py`, `test_hook_toctou.py`, `test_key_lifecycle.py`,
`test_lineage.py`, `test_p17_*` ×6, `test_plan022_p3.py`,
`test_plan024_global_chain.py`, `test_principal_lifecycle_durable.py`,
`test_recurrence.py`, `test_recurrence_postgres.py`,
`test_signing.py`, `test_signing_ed25519.py`, `test_spec_entity.py`
(D20: RETIRE), `test_trust_projection.py`, `test_wi008_*` ×3,
`test_wi267_row_authentication.py`, `test_wi287_fixture_helpers_postgres.py`,
`test_wi287_inmem_parity.py`, `test_wi305_v6_assurance.py`,
`test_wi305_v6_review_gate.py`, `test_witness*.py` ×4) are full-RETIRE —
they bootstrapped through `_v6_fixtures` only to test something that is also
being deleted, so the fixture dependency costs nothing to walk away from for
these files specifically.

**What a replacement fixture must provide.** The kernel has no genesis, no
keyset, no trust log — `Kernel.connect()` takes a bare DSN and a schema
string, and `initialize()` runs `schema.sql` directly. A replacement fixture
(likely `tests/_kernel_fixtures.py` or similar, not yet written anywhere)
needs to give each of the 45 files, at minimum:
1. A connected `Kernel` against a fresh, uniquely-named schema per test (the
   old fixture's `tmp_path`-scoped keyset played this per-test-isolation
   role incidentally).
2. A registered workflow — the 45 files above use several different
   workflow shapes (`test_workflow.yaml` for most, a bespoke multi-actor
   definition for `test_sf2_workflows.py`, the canonical lifecycle YAML for
   `test_canonical_workflow.py`); the replacement needs to support loading
   a YAML file, not just a `Workflow(...)` literal, since several of these
   tests parametrize over YAML fixture files on disk.
   **(2026-09-19: this prerequisite is met — `load_workflow(path)` reads a
   YAML or JSON document. The fixture files themselves still need porting to
   the 0.8 dialect, which is a mechanical edit per file, not a missing
   capability.)**
3. Whatever the `sub` fixture's `params=["real", "in_memory"]` parametrization
   becomes once the in-memory backend retires (§B) — most of the 45 files
   use exactly this fixture, so its replacement decision is shared across
   nearly all of them, not per-file.
4. Nothing resembling a key, principal, or epoch — per D5/D1, the kernel's
   `create_work_item`/`register_workflow` take no such argument today and
   should not gain one.

**Why this is the biggest hidden cost, restated with the count behind it.**
45 files is not "the trust tests." It is roughly a quarter of the entire
185-file suite, and every one of the 20 files independently flagged
HIGH-VALUE PORT across both disposition reports is in this list. None of
their assertion bodies can be exercised until this fixture exists — F1
cannot "port tests" as file-by-file work; it must build this fixture first,
as its own task with its own estimate, exactly as D20's ruling on
`_v6_fixtures.py` states ("replace the bootstrap harness first, migrate
retained callers, then retire the v6 fixture module... an implementation
dependency, not an unresolved product feature").

---

## §B — The in-memory backend: 35 tests, mapped

`tests/test_in_memory_conformance.py`, 654 lines, **35 test functions**
(counted: `grep -cE "^\s*def test_"`), spanning 13 classes. D2 (adopted):
retire the backend, retarget these 35 to disposable PostgreSQL as part of
the same decision, not a follow-up.

**32 of the 35** run through the `sub` fixture, `@pytest.fixture(params=
["real", "in_memory"])` (line 19) — the *same test body* is already
parametrized to run against real PostgreSQL today. Retargeting these 32 is
literally deleting the `else: s = InMemoryRegista(...)` branch of the
fixture and the `"in_memory"` entry in `params`; the assertion code does not
change at all. By class: `TestConformanceWorkflow` (2), `TestConformanceWorkItem`
(3), `TestConformanceTransition` (5), `TestConformanceEvents` (5),
`TestConformanceClaims` (4), `TestConformanceLinks` (1),
`TestConformanceActorRoles` (2), `TestConformanceQuery` (3),
`TestConformanceReplay` (2), `TestConformanceUpdateNotBefore` (1),
`TestConformanceCustomFieldFilter` (3), plus
`test_heartbeat_actor_kind_emitted_real` (1) = 32.

**3 of the 35 need real adaptation, not just a fixture-parameter deletion:**
- `TestBC189OrphanEventDetection::test_orphan_with_created_event_counts_as_halted`
  and `::test_orphan_without_created_event_counts_as_halted` (lines 547,
  581) construct a raw `regista._types.Event` with v6-shaped fields
  (`key_id`, `signature`, `payload_canonical_hash`, `canonical_envelope`)
  and inject it directly into `InMemoryRegista._store.events`, bypassing the
  public API entirely, to simulate an orphan row. This needs a Postgres
  equivalent that inserts directly into the kernel's `events` table (which
  has no such columns) — the *intent* (an orphan work item whose only event
  is/isn't `"created"` is halted, not warned) ports; the mechanism does not.
- `test_heartbeat_actor_kind_emitted_in_memory_with_keys` (line 629) is
  the in-memory half of a real/in-memory parity pair and imports
  `_v6_fixtures.make_v6_keyset`/`open_v6_epoch` directly inside the test
  body (not via the `sub` fixture) specifically to construct an
  `InMemoryRegista(hmac_key_path=...)`. This test is redundant with
  `test_heartbeat_actor_kind_emitted_real` once the in-memory backend is
  gone (the "parity" it checks no longer has two sides to compare) — it
  should be dropped as a consequence of removing the backend, not ported.

**Net obligation:** 32 direct fixture-parameter deletions (no assertion
change) + 2 tests needing a Postgres-native orphan-injection mechanism + 1
test correctly dropped as redundant once its comparison target is gone. This
confirms the review's framing: "the retargeting is part of the yes, not a
follow-up" is accurate, and it is cheaper than it sounds for 32 of the 35 —
but only after §A's fixture replacement exists, since all 35 also import
`_v6_fixtures` through the `sub`/`mem_sub` fixtures.

---

## §C — Replay coverage: what's derivable from events, what isn't, and the open question

**What the prototype's events table actually records, verified by reading
every write path in `kernel.py`.** Only two calls ever append an event:
`create_work_item` (payload `{"created": {...}}`, seq 0) and `transition`
(payload `{"from", "to", "fields", **payload}`, seq N). Every other mutating
method — `claim`, `heartbeat`, `release`, `expire_leases`, `link` — writes
directly to its table (`claims`, `claim_attempts`, `links`) with **no**
`_append_event` call anywhere in any of them. This was verified by reading
the full body of each method, not inferred from their names.

**Consequently, today:**
- `work_items_current.current_state` and `.custom_fields` **are**
  reconstructible from events, subject to the two open defects in Behaviour
  5 (payload overwriting reducer-owned fields; final-event deletion not
  reconciled against custom fields).
- `claims` (who holds the lease, when it expires) is **not** reconstructible
  from events at all — there is no `claim_acquired`/`claim_released`/
  `claim_expired`/`claim_stolen`/`claim_heartbeat` event of any kind. A
  full event-log replay after restoring a events-only backup would produce
  a work item with the right state and fields and **zero information about
  who, if anyone, currently holds it**.
- `claim_attempts.last_attempt` (the fencing counter) is **not**
  reconstructible either, for the same reason. If this table were lost or
  needed rebuilding, `claim()`'s `UPDATE claim_attempts SET last_attempt =
  last_attempt + 1` would restart from whatever the row's current value is
  — there is no way to derive "the highest attempt number ever issued" from
  the event log, because no event carries an attempt number at all.
- `links` is **not** reconstructible from events — `link()` never appends
  an event, so a link's creation (or, if a removal method existed, its
  removal) leaves no trace in `events` at all.

**What the old tree does instead, verified by reading the actual
transitions and their consumers.** `src/regista/_contract.py` (lines 39–45),
`_reducer.py` (lines 47–66), `_in_memory_replay.py` (lines 610–639), and
`_links.py` (lines 181, 265, 299) all treat `claim_acquired`, `claim_stolen`,
`claim_released`, `claim_expired`, `claim_heartbeat`, `link_created`, and
`link_removed` as first-class event transitions with their own reducer
logic. `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_derives_claim_acquired`,
`test_replay_derives_claim_stolen`, `test_replay_derives_claim_released`,
`test_replay_derives_claim_expired` (lines 84–137),
`TestReplayLinkLifecycle::test_replay_derives_link_created_and_removed`
(line 152), and `TestBC090ClaimStateDriftDetection::test_claim_attempt_number_reconstructed`
(line 562) prove the old system actually does this, end to end, today —
including reconstructing the fencing counter itself from history, which is
the single most safety-critical thing on this whole list to get right if
it's rebuilt from a backup.

**The recovery contract this map needs but cannot supply.** Plan 032's keep
table says "ordered history, replay of supported state" without saying
whether claim/link state is "supported state." The open-decisions review's
"Additional choices" section names exactly this as unresolved: *"enumerate
which projections are derivable from events... At least links and monotonic
fencing counters need an explicit recovery contract; rebuilding must never
make an old token valid again."* This map is not the place to invent that
answer, so it states the question precisely instead: **does 0.8.0 promise
that restoring from an events-only backup (or replaying after a claims/links
table is lost) reconstructs who holds a lease, what its attempt number is,
and what links exist — or does it promise only that work-item state and
fields survive, with claims/links treated as ephemeral operational state
that a restore is allowed to lose?** The old suite's answer is unambiguous
("all of it, fencing counter included"); the new kernel's code today
implements the second, narrower answer by omission, not by decision.

**The one thing that is not ambiguous, regardless of which way that
question is answered:** *rebuilding must never make an old fencing token
valid again.* If claims/links recovery is added, `claim_attempts.last_attempt`
must be reconstructed as at-least the highest attempt number any surviving
`claims`/`events` evidence implies, never reset to a value an old,
already-superseded attempt could satisfy — this is the one invariant that
would turn a merely-incomplete recovery feature into a reintroduction of the
exact fencing defect Behaviour 4 already documents as open (WI-367/368). Any
recovery-contract test that gets built for this must include a case that
proves a rebuild does not reissue or validate a stale attempt number, mirror-
ing `test_mutations.py::attempt_monotonic`'s "no attempt is reissued" check
but across a simulated rebuild rather than a live takeover.

**Replacement obligation, stated as a decision gate rather than a task
list, because the task depends on the decision:** if the maintainer rules
"claims/links are reconstructible state," the kernel needs `claim_acquired`/
`claim_released`/`claim_expired`/`claim_stolen`/`claim_heartbeat`/
`link_created`/`link_removed` events added to every relevant method in
`kernel.py` before any of `TestReplayClaimLifecycle`,
`TestReplayLinkLifecycle`, or `TestBC090ClaimStateDriftDetection`'s six
tests may be deleted, plus a new fencing-counter-rebuild-does-not-revalidate-
a-stale-token test with no old precedent to port from (the old system never
needed this test because its claim_attempts equivalent was itself always
derived from events, so "rebuild" and "ordinary replay" were the same code
path — the kernel's direct-mutation design makes them different paths for
the first time). If the maintainer rules "claims/links are ephemeral
operational state, not covered by replay," then `TestReplayClaimLifecycle`,
`TestReplayLinkLifecycle`, and `TestBC090ClaimStateDriftDetection` retire as
RETIRED-BY-DESIGN, and 0.8.0's documentation (F4) needs to say so explicitly
— because right now nothing does, and a caller reading the old README's
replay claims would reasonably assume the stronger guarantee still holds.

---

## RETIRED-BY-DESIGN index (behaviours/assertions intentionally dropped, not silently lost)

Collected here from the sections above, so a reviewer can check this list
once instead of hunting through nine sections for it:

- Global cross-work-item hash chain bound to signature bytes
  (`test_global_event_chain.py`, `test_hash_chain.py`,
  `test_plan024_global_chain.py`) — cannot survive signing removal by
  construction; per-item consistency chain is kept (Behaviour 5).
- Workflow inheritance/composition (`test_workflow_compose.py`) — D21,
  exception considered and declined (Behaviour 2).
- All signing, key custody/lifecycle, principal/trust-domain governance,
  witness/anchoring, bundles, delegation, model-lineage/assurance
  classification, recurrence, async hooks/webhooks, the HTTP sidecar, and
  the estate catalog — D3/D4/D5 and Plan 032 §3's "Remove by default" list.
  Not itemized per-file here since the two disposition reports already
  carry ~112 RETIRE dispositions for these; this map's job was the PORT/
  SPLIT survivors, not re-deriving the RETIRE list.
- The signed "spec" entity (`test_spec_entity.py`) — D20 ruling: retire with
  the signed spec entity; ordinary custom fields can carry document
  references instead.
- `test_cli_conformance.py`'s dependency on the pinned `agent-suite-
  conformance` package specifically (not its generic CLI assertions, which
  D20 says to preserve as ordinary Regista CLI tests).

Everything else in this document that says "does not exist yet" is a **gap
to close**, not a dropped contract — the distinction this map exists to make
precise.
