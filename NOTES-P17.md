# P1.7 handoff — what landed, what did not, and the findings that changed the plan

> **Session 4 (2026-08-18) is PHASE 3 — the manifest march. Read §0a first; it
> corrects Finding 14 and records the migration recipe as measured. Then §0b (the
> Phase 2 verifier boundary, which supersedes §4 entirely and records findings
> 10-15), then §0 (session 2), which supersedes parts of §1-§3.**

---

## 0a. Session 4 (2026-08-18): PHASE 3 — the manifest march

### FINDING 14 WAS WRONG, and the remedy landed anyway

Finding 14 (§0b) recorded that `_replay._process_group` "files every non-work-item
entity group as an orphan halt". **Re-measured on this branch: `halted == 0`.** The
groups surfaced as **`warnings`** — `_handle_orphan_group` has had a non-work-item
early return since WI-266 (`dcf2b77`), which the finding's author did not see. A
healthy clean-epoch replay reported *seven warnings*, which is a different defect
with the same consequence for Phase 3: a migrated fixture cannot assert a clean
report.

Read this as a lesson about the finding, not only about the code. The finding says
"measured" and was not; what was measured was the *symptom under the clamp*
(a verification halt), and the halt was then attributed to the wrong branch.

The corrected semantics, implemented per the coordinator's strict-defaults call:

| Group | Before | Now |
|---|---|---|
| `work_item`, projection row present | replayed | unchanged |
| `work_item`, projection row missing | halt | unchanged |
| the five other CLOSED-registry kinds | `warnings += 1` | counted in `ReplayReport.non_work_item_groups_verified`; no halt, **no warning** |
| a kind outside the closed registry | `warnings += 1` | **halt**, fail-closed, detail names the kind |
| one entity id carrying several kinds | `warnings += 1` | **halt** |

`non_work_item_groups_verified`'s docstring states exactly what "verified" covers:
the events were carried into the **global hash-chain** verification and their kind
was checked against the registry. It deliberately does **not** claim a per-event
`verify_event_strict` verdict — the project-genesis event in this population is
legitimately `UNVERIFIABLE` without an external trust pin (Finding 11), so folding
these groups into the signature counters would make every healthy epoch report an
evidentiary gap it does not have. Read that before renaming the field.

**The mixed-kind branch is unreachable on Postgres** (groups are keyed by
`(entity_kind, entity_id)`, so a group carries one kind by construction) and IS
reachable in memory (groups key on `work_item_id` alone). It is kept in both, tested
in memory, and `test_the_mixed_kind_branch_is_unreachable_on_postgres_by_construction`
states the absence so nobody reads the in-memory coverage as Postgres coverage.

### FINDING 16 — both in-memory chain walks used the v5 head formula, so a HEALTHY in-memory v6 epoch reported five chain breaks

Found while writing Finding 14's falsifiers, and worse than Finding 14.
`_in_memory_replay` hardcoded `sha256(envelope || signature)` in **three** places:
the per-entity chain check, the global chain walk, and the head-mismatch check. The
Postgres path has used the version-aware `_event_head_hash` throughout. So no v6
event was reachable from genesis in memory, every post-genesis event was reported an
orphan, and **WI-287's parity claim was measurably false for the chain** — nothing
had asserted it, because no in-memory fixture had an epoch when WI-287 shipped.

This is mutation **M20** / Finding 15 in a second place, so the fix is structural
rather than local: the formula now lives once, at
`_signing.compute_chain_head_hash`, and `_replay._event_head_hash`, all three
in-memory sites and the head-mismatch check delegate to it. Its docstring names both
bugs, because "a version-aware formula that exists in four places is a formula that
is version-aware in three".

Adjacent cleanup with the same motive: the CLOSED six-value entity-kind registry
(`V6-ENVELOPE.md` §1.2) was hand-copied in `_verification`, `_genesis` and
`_v6_writer`. It is now `_verification.V6_ENTITY_KINDS`, imported by all four
consumers, and `test_the_closed_registry_is_one_registry` asserts object identity —
a halt on "not in the registry" is only as trustworthy as the registry being
singular.

Falsifiers: `tests/test_p17_replay_entity_kinds.py` (12 nodes, both backends).
Fail-then-pass with the two replay modules reverted and the tests kept:
**6 failed, 3 passed -> 12 passed**.

### The migration recipe, corrected by measurement (supersedes §0's version)

Two costs §0's recipe did not name, both of which cost a red run:

1. **A producer field inside `actor_metadata` is refused at ingress.**
   `actor_metadata={"role": "agent", "model": "gpt-4"}` fails with "producer fields
   must not appear in actor.metadata" — `harness`, `harness_version`, `model` and
   `model_lineage` belong to the process-level `producer` block. Drop them; keep
   `role`.
2. **`open_v6_epoch` must precede `register_workflow_file`.** The registration emits
   a signed `workflow_registered` event and is a silent no-op before genesis, so the
   wrong order surfaces much later as `WORKFLOW_REGISTRATION_UNRESOLVED` on the
   first ordinary append.

And the signal to work from: a migrated node reports **`[XPASS(strict)]`**, which
pytest prints as a FAILURE. That is the success condition, and it is what makes the
migration verifiable file-by-file without touching the manifest first.

### How the manifest surgery was derived, and why that is the trustworthy way

Not from the migrating agents' claimed node lists. From a full two-lane run with the
manifest still in place, then **intersecting the FAILED set with the manifest**:

```
FAILED lines: 215      failed & manifest: 215      failed NOT in manifest: 0
```

Zero failures outside the manifest means every failure *is* a strict-XPASS, which
means the removable set is exactly the intersection — and it means the migration
caused no collateral regression, measured rather than asserted. A claimed list can be
wrong in two directions; this is wrong in neither. Re-running after the surgery is the
second half of the check: any node removed that does not actually pass comes back as
a plain FAILED, and any node left in that now passes reds the suite as a strict-XPASS.

### What Phase 3 could NOT migrate, and why — the exact accounting

**Every one of these is a production gap, not a fixture problem.** That is the finding
of the march: with the wiring in place a fixture migration is mechanical, so what
remains is the set of places where the v6 route broke something real.

Four of the nine were P1.7's own and were **fixed** this session, which is what took
the manifest from 192 to 129:

| Fixed | Nodes recovered | The defect |
|---|---|---|
| the bare `"system"` producer identity | 36 | escalation, hook dead-lettering and recurrence firing were **impossible** in a clean v6 epoch |
| the witness receipt hash | 13 | every Ed25519 witness receipt over a v6 event failed verification, silently |
| `_api_meta`'s public-key branch | — | the public independent-verification API returned `UNVERIFIABLE` for every v6 event |
| `_in_mem_ops`' public-key branch | 14 | the in-memory twin of the same omission |

And five remain:

| Blocker | Nodes | Owner |
|---|---|---|
| **2. reviewer lineage has no v6 vehicle** | 60 | **owner/coordinator design call** |
| **3. WI-008** — `on_behalf_of` / delegated events | 36 | WI-008 |
| **4. `entity_kind = "spec"`** is not in the closed §1.2 registry | 14 | **owner decision** |
| **5. HMAC-signed ordinary events** (subject died with v5) | 26 | RETIRE — **listed, not executed** |
| **8. WI-217's memory bound vs `StoreReferents`** | 2 | **escalated — a live production property** |
| **9. in-memory `_global_chain_head` never advances** | 1 | **escalated — a fail-open gap** |

### The four fixes, and the judgment calls in them

**The system actor.** A system-authored event is now attributed to the project's own
bootstrap principal — `read_project_identity(conn).principal_id`, resolved by one
helper (`_events.resolve_system_actor_id` + its in-memory twin, which routes through
the *same* body rather than reading `project_identity` twice). This is not an invented
convention: `_workflow_api.py:59-67` already attributes `workflow_registered` exactly
this way, which is why that one call site worked while six others did not. It is
**epoch-aware** — a legacy project keeps the literal `"system"` / `"system:scheduler"`
byte for byte, because changing a legacy path would redden the still-blocked nodes
with a *changed* failure form.

The judgment call, stated plainly: this changes the actor attribution of production
events, and I made it mid-migration rather than escalating it. The reason is that not
making it means shipping a substrate where auto-escalation cannot happen — P1.7's own
wiring broke a live feature — and the correct pattern was already in the tree, put
there by P1.7. A reviewer who thinks "which principal authors a system event" is an
owner call would escalate instead; the change is one helper and eight call sites, so
reverting it is cheap.

**The witness hash.** `_witness.py` passed the row's `payload_canonical_hash` as
`Ed25519Scheme.verify`'s `envelope_hash` while passing the bare envelope as
`envelope`. For v1-v5 those coincide; under v6 the column hashes the *domain-tagged
signature input* (`V6-ENVELOPE.md` §5.3), so `compare_digest` failed on every v6 event
and every receipt over one was rejected as a bad signature. Measured:
`sha256(canonical_envelope)` = `c4fdd6bd…` vs the column's `36a808c7…`.

Two things worth reading twice. First, **the negative tests all kept passing**, because
`sig_verified` was unconditionally `False` — a test that cannot tell "bad signature"
from "we compared the wrong two hashes" tests nothing, and the control run proves it
(with the defect restored, 3 positive nodes fail and all 4 negative nodes still pass).
Second, the fix deliberately did **not** take the easier route of feeding the v6
signature input to the scheme: that would silently redefine what an external witness
must sign, and would make a witness countersignature cover byte-identical input to the
*author's* signature over the same event. §6.1's hash-domain registry has no witness
tag, and handing the witness the author's tag is the one thing domain separation exists
to prevent. **A `regista.witness.receipt.v1` tag is the principled design and is a
wire-format change — it was stopped at, not made.** Also on the record: the delivery
body never tells the witness what to sign; the protocol is convention established
solely by what two test doubles do.

**The two public-key branches.** Phase 2 threaded the referent resolver through eleven
production call sites. There were thirteen. `_api_meta.verify_event_result` and
`_in_mem_ops.verify_event_result` both omitted it on their caller-supplied-public-key
path — and `_in_mem_ops` *built* the resolver two lines above and then did not pass it.
The lesson is about the omission's shape: substituting the KEY resolver does not change
what CHAIN material a v6 verdict needs, and nothing exercised either branch against a
v6 row, so both returned `UNVERIFIABLE` for every v6 event. Worse than a false
negative: a wrong-key test passed for the *wrong reason* (`unverifiable`, not
`SIGNATURE_INVALID`).

**Two un-referented sites are LEFT, reported not fixed:**
`_signing.verify_event_with_public_key` (the bool shim) has **no `referents`
parameter at all**, so it returns `False` for every v6 event; and
`_signing.verify_event_principal_binding`'s `_verify_with_key` calls that shim, so
`verify_event_principal_binding` should report `verified=False` for every v6 event.
Nothing in the suite asserts either, which is why they are untested rather than
merely unfixed. Adding the parameter is small; deciding what a *principal-binding*
probe should present is not, given §5.9 rule 1 makes registry resolution for a v6
event a raise.

Blockers 2, 4, 5, 8 and 9 in detail, because each is a decision rather than a task:

**2 — the reviewer's lineage has no v6 vehicle.** `_review_validators.py:301` and
`_assurance.review_lineage_relation` resolve the *acting reviewer's* lineage from
`ctx.actor_metadata["model_lineage"]`. The v6 envelope **refuses** producer fields
inside `actor.metadata`, and `ValidatorContext` carries no `producer`. So a pre-append
validator cannot see the in-flight reviewer's lineage at all. Worse, the two halves of
the system now disagree: `_lineage.raw_event_model_lineage` already reads *stored* v6
events' lineage from the `producer` block, so authors' lineages resolve and the
reviewer's cannot. And `producer` is **process-level** — one value per process — so
per-actor cross-lineage distinctness has no v6 vehicle even in principle. Deciding
whether `ValidatorContext` gains a producer, or whether the cross-lineage gate moves
to a different input, is a design call. **Not invented mid-migration.**

**4 — `entity_kind = "spec"`.** `sign_spec` / `read_spec_events` are still live in
`_api_meta.py` and `_cli.py`, and `spec` is not one of the six closed kinds, so they
cannot write to a v6 epoch at all. Either `V6-ENVELOPE.md` §1.2 gains a seventh kind
or the feature is cut. Both are owner calls; the closed registry is exactly the thing
`prefer-strict-defaults` says not to widen unilaterally.

**5 — 26 RETIRE candidates, listed rather than executed**, per the brief's "more than
a handful → list for the coordinator first". `test_signer_binding.py` (14) and
`test_wi223_principal_binding.py` (12) drive HMAC-signed *ordinary* events and
unaccepted-key chains — states the clean epoch cannot produce (`_v6_writer._SCHEME_IDS
== {"ed25519"}`; a key with no project-local acceptance is refused at append). The
mechanical cost is the reason to pause: `tests/test_retired_tests_ledger.py:87`
asserts `node_id not in full_collection`, so a ledger entry **requires deleting the
test**, and deleting 26 live tests is the D1-rejected "blanket deletion,
unaccountable" wearing a ledger's hat (NOTES §2 option 2). Several invariants clearly
survive and would carry forward — "replay counts a binding failure when a key has no
active row in *this* project" survives as §5.10 step 3's anchor-reachability walk;
`principal_binding_failures == 0` meaning *checked* survives as
`ReplayReport.principal_binding_verified` — but `open_v6_epoch` writes no
`principal_keys` rows at all, so whether `principal_binding_verified` is even `True`
on a v6 project is itself unsettled. That question has to be answered before the
retirements, not by them.

**8 — Phase 2 defeated WI-217's streaming space bound, and this is a production
property, not a test.** `_replay.py` builds one `store_referents(conn)` for the whole
replay; `StoreReferents._build()` indexes every v6 event in the store and caches it
for the resolver's lifetime, so replay's peak now tracks the log size. Measured: an 8x
larger log grew replay's tracemalloc peak 5.5x against a 3.0x budget. Phase 2 noted
the per-resolver cache as a deliberate trade (per-event construction would make an
O(n) replay O(n²)) and noted that an `event_hash` generated column would remove the
indexing pass — but it did not notice that the *cache* is what WI-217 exists to
prevent. The two constraints are in genuine tension and the resolution is a migration
(the generated column) plus a bounded or streaming resolver. Neither is a
mid-migration change.

**9 — the in-memory backend cannot detect a log emptied under a live head.**
`InMemoryEventStore.append_v6_row` deliberately does not advance
`_global_chain_head` (its docstring defers that to the writer's explicit
`_advance_global_chain_head`, which the in-memory v6 path never calls), so after
`open_v6_epoch` plus eight v6 events the head is still `None`. The state WI-266's
fail-closed check looks for — head set, log empty — is therefore unreachable in
memory, while Postgres detects it correctly. A fail-open gap of exactly the class
WI-266 closed, and a second measured hole in WI-287's parity claim after Finding 16.

### Other measured findings the march turned up (not blockers)

* **`read_events()` with no filters returns trust-plane rows.** `read_events_composite`
  applies no entity-kind predicate, so an unfiltered read on a migrated project
  returns the epoch's own `project_initialized` / `principal_key_accepted` /
  `workflow_registered` events. Whether the reader should be scoped is a real
  question; one test now uses a documented event-free fixture rather than have the
  question decided by a weakened assertion.
* **`archive_events` silently breaks the v6 project chain** and reports it only as a
  bare `chain_breaks` counter with no `ReplayReportEntry` naming it —
  `_archive.py` does not update `event_chain_head`, so the head still names an
  archived event. `CUTOVER-CLASSIFICATION.md` §5.3 documents the hole as an artifact
  of the read, but `replay()` gives an operator no way to tell it from tampering.
* **`_verification` and `_replay` disagree about a nulled `canonical_envelope`.** The
  verifier says `UNVERIFIABLE` / `ENVELOPE_ABSENT` (its `AbsentEnvelopeProbe` is a
  v1-v5 reconstruction path and does not run for v6); `_replay` decides the stronger
  claim, that the row contradicts its own retained signature. Both fail closed, but a
  caller using `verify_event_result` gets the weaker of the two. Both halves are now
  pinned by tests.
* **Most test files hardcode `DSN = "postgresql://…/regista_test"`** and ignore
  `REGISTA_TEST_DSN`, so the WI-243 leak guard watches a database the tests do not
  write to. Pre-existing, and it means the dedicated-DSN hygiene the notes claim is
  largely notional. Four files were reading `TEST_DSN` instead; two are fixed.

### WI-289: clusters 1/2/3/5 discharged — 39 of 39

`tests/test_wi289_v6_counterparts.py` (40 nodes). 37 new counterparts, 2 mapped to
pre-existing tests (`test_p17_v6_writer.py::TestSemanticConformance::test_the_entity_chain_links_by_signed_v6_event_hash`
and `test_p17_v6_verifier_boundary.py::TestAgainstARealEpoch::test_a_real_row_rewrite_is_still_caught_by_reconciliation`).
The node→test mapping is recorded machine-checked in `tests/retired_tests_ledger.json`
(`covered_by`/`covered_in` per entry) with a self-check test asserting every pointer
still resolves, so a rename cannot rot the closure note.

Because Phase 2 landed, these assert an `applicability` **verdict** — which is what
cluster 6 could not do and had to be re-tightened for. Detection evidence: 11 tamper
mutations, 11 killed (19 node-runs pass with the tamper, the same 19 fail without it).

**Cluster 5 was NOT WI-301-blocked** — checked rather than assumed. Active-key
selection is `KeySet.resolve_signing_key`'s status filter and rotation is a
`principal_key_accepted` event the writer already writes; both are project-local.
WI-301 still blocks *trust-log* enrolment and rotation writes.

Ledger now: 56 WI-289 entries, **45 discharged**, 11 undischarged — all cluster 4, all
in `tests/test_bundle.py`, blocker **P3.3**.

### WI-301-blocked: nothing, as it turns out

No file's migration needed the trust-log append path. The one place it was expected —
`test_principal_lifecycle_durable.py` (27 nodes) — migrated cleanly by using
`requested_authority="root"`, the same shape the already-passing
`test_trust_projection.py` ceremony uses; anything else maps onto §5.4 registrar
authority, which needs a `delegation_event_hash` the ceremony cannot name. Registrar
delegation remains unwired and is documented as Gate 2's.

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

## 0b. Session 3 (2026-08-18): PHASE 2 LANDED — the v6 verifier boundary

| SHA | Slice |
|---|---|
| `906ed88` | The boundary: `_v6_referents.py` (new), §5.10/§5.11 in `_verification.py`, the resolver threaded through 11 production call sites, `RESULT-MODEL.md` §10.1's result surface, WI-296's two halves, WI-287 cluster-6 tightened, `tests/test_p17_v6_verifier_boundary.py` (new, 66 test functions / 78 collected nodes) |
| `768994e` | Mutation M20's survivor fix (the fixture had no multi-event entity; see finding 15), the cross-backend `store_referents` parity test, notes + CHANGELOG |

**Fail-then-pass:** with the clamp temporarily restored and the new tests kept —
**61 failed, 54 passed**. With the boundary — **115 passed** (boundary + bundle).

**Validation, final state:**

| Check | Result |
|---|---|
| default lane (`-m 'not slow'`, all extras, dedicated DB) | **2787 passed, 0 failed, 679 xfailed, 18 skipped** |
| slow lane (`-m slow`) | **4 passed, 7 xfailed, 0 failed** |
| `scripts/check-epoch-debt.py --base main` | OK — 686, shrink-only node set vs main (694) |
| `tests/epoch_blocked_inventory.txt` | byte-identical to main (sha `8696641a…`) — **never touched** |
| ruff (`src/ tests/ scripts/ tools/`) | clean |
| mypy (`src/regista`, 103 files) | clean |
| `docs/0.6.0/check-conflicts.py` | 0 contested values |
| `docs/0.6.0/check-crossrefs.py` | 0 unresolved references |
| mutation battery (23 single-line mutations) | 23 killed |

679 xfailed = the 686 manifest entries minus the 7 that live in the slow tier, so the
debt figure any claim about this branch carries is still `green-with-epoch-debt(686)`.

### The resolver design, because the next person will need to extend it

```python
class ReferentResolver(Protocol):                    # src/regista/_v6_referents.py
    @property
    def completeness(self) -> MaterialCompleteness: ...
    def resolve_referent(self, event_hash: str) -> ReferentEvent | None: ...
    def describe(self) -> str: ...
```

Two members and **no query surface** — no `fetch`, no `search`, no connection on the
protocol — because §8.4's table is a list of things the verifier is *given*.

Three properties are load-bearing and should not be traded away:

1. **Addressing is by v6 event hash**, which covers the canonical envelope bytes *and*
   the signature. A tampered presented anchor therefore does not resolve to something
   else; it does not resolve at all, and §5.11 already has a verdict for that. This is
   why the resolver never re-verifies a signature: it is sound about *content* by
   construction, and each presented event's own *authority* is the caller's separate
   per-event obligation (replay and bundle verification both verify everything they
   present).
2. **The material carries its own completeness claim.** §5.11's first two rows differ
   only in that claim. `StoreReferents` claims `COMPLETE_STORE` (flag #4's stricter
   reading — §5.11 names "an online store" beside `complete-store`);
   `BundleReferents.from_bundle` *derives* the claim from the manifest's
   `since_seq`/`until_seq` rather than being told, which is how §9 criterion 15 became
   testable before `BUNDLE-V3.md` §3.5's explicit `scope` member exists (that is P3.3's);
   `NO_REFERENTS` claims nothing.
3. **`principal_keys` is not reachable from here.** Nothing in `_v6_referents` can read
   it. The absence is structural rather than a convention.

`verify_event_strict(..., referents=...)` has **no default**. That is the deliberate
choice: a default would let a call site silently present nothing and get
`UNVERIFIABLE`/`KEY_BINDING_UNRESOLVED` for every v6 row — a second, narrower clamp.
`NO_REFERENTS` is a named greppable value, so "one row, no chain" appears in the call
site instead of being the shape of a missing argument.

**The 11 production call sites and what each presents:**

| Call site | Material | Claim |
|---|---|---|
| `_replay._replay_work_item` | `store_referents(conn)`, built **once per replay** and threaded in | `COMPLETE_STORE` |
| `_in_memory_replay.in_memory_replay` (×2: keyed and keyless) | `MappingReferents.from_pairs(store.all_events())`, once per replay | `COMPLETE_STORE` |
| `_bundle._verify_event_signatures` | `BundleReferents.from_bundle(manifest, events)` | derived from the manifest |
| `_genesis.read_genesis_from_connection` | `store_referents(conn)` | `COMPLETE_STORE` |
| `_api_meta.verify_event_result` | `store_referents(conn)` on the open project | `COMPLETE_STORE` |
| `_in_mem_ops.verify_event_result` (×2) | `MappingReferents.from_pairs(self._store.all_events())` | `COMPLETE_STORE` |
| `_signing.verify_event_result` | `referents` parameter, default `NO_REFERENTS` | `UNDECLARED` |
| `_signing.verify_event_result_with_public_key` | same | `UNDECLARED` |
| `_signing.verify_event_dict_principal_binding` | `NO_REFERENTS`, **by contract** | `UNDECLARED` |

The last one is worth reading twice: a principal-binding probe over the `principal_keys`
registry is legacy-only, and §5.9 rule 1 now makes registry resolution for a v6 event a
**raise**. Its existing `except Exception` turns that into "this entry does not bind",
which is the correct answer.

**Scoped replay presents the whole store, not the scope.** A work-item event's
key-binding anchor is a `principal` event that no work-item scope contains, so narrowing
the material to the scope would turn "the anchor is elsewhere in this store" into "the
anchor is missing" — a false finding.

**Cost, stated because it is real.** `events` has no `event_hash` column, so
`StoreReferents` builds its index with one ordered pass that recomputes every v6 hash.
It is lazy (a v1-v5-only store never pays) and cached per resolver instance, which is
why replay builds one and reuses it — per-event construction would make an O(n) replay
O(n²). An `event_hash` generated column would remove the pass; that is a migration and
was deliberately not smuggled into a verifier change.

### The completeness-claim policy input

`VerificationPolicy.material_completeness: MaterialCompleteness | None = None`.

* **Default `None` = "the material's own claim governs."** That is where completeness
  structurally belongs: a store connection knows it is complete, a windowed bundle knows
  it is not. The strictest resolver default is `StoreReferents`' `COMPLETE_STORE`, which
  is what flag #4 asked for.
* The field exists for a caller who knows *more* than the material does, and it is
  **tighten-only**. Loosening raises (`resolve_completeness`), because softening
  `complete_store` into `contiguous_range` converts §5.11's `INVALID` row into its
  `UNVERIFIABLE` row on request — the no-fallback rule with extra steps.

### §5.11 verdict-table coverage map (row → test)

All in `tests/test_p17_v6_verifier_boundary.py`.

| §5.11 row | Verdict implemented | Test |
|---|---|---|
| `h_A` absent, no completeness claim | `UNVERIFIABLE` / `KEY_BINDING_UNRESOLVED` | `TestSection511VerdictTable::test_row1_absent_anchor_with_no_completeness_claim_is_unverifiable` |
| `h_A` absent, completeness claimed | `INVALID` / `KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE` | `::test_row2_absent_anchor_in_complete_material_is_invalid` |
| `h_A` is not an acceptance | `INVALID` / `KEY_BINDING_MISMATCH` | `::test_row3_anchor_that_is_not_an_acceptance_is_invalid` |
| `h_A` for a different principal/key | `INVALID` / `KEY_BINDING_MISMATCH` | `::test_row3_anchor_for_a_different_principal_is_invalid` |
| `h_A` for a different project | `INVALID` / `KEY_BINDING_MISMATCH` | `::test_row3_anchor_from_a_different_project_is_invalid` |
| `h_A` does not precede `E` | `INVALID` / `ENROLLMENT_AFTER_USE` | `::test_row4_an_anchor_that_does_not_precede_the_event_is_invalid`, `TestCriterion14::*` |
| pre-cutover v4/v5, no key binding | **legacy path, unchanged by this work** | `::test_row5_a_pre_cutover_legacy_event_is_untouched_by_this_boundary` |
| `legacy_key_binding_attested` covers `E` | **not implemented — see finding 13** | — |
| a `principal_keys` row exists | **irrelevant**; resolving through it **raises** | `::test_row7_a_principal_keys_row_is_never_consulted_for_a_v6_event` |

Plus, beyond the table: `KEY_ACCEPTANCE_REVOKED` (§5.10 step 4) and its prospective-only
counterpart, the §5.8 scope checks, the Resolution 1 nulls, `EPOCH_VIOLATION`,
`PRODUCER_POLICY_MISMATCH`, `PROJECT_BINDING_MISMATCH`, `TRUST_DOMAIN_MISMATCH`,
`WORKFLOW_DEFINITION_MISMATCH`, `WORKFLOW_REGISTRATION_UNRESOLVED`,
`DELEGATION_CHAIN_INVALID`.

### §9 criteria 14 and 15

* **14** — `TestCriterion14::test_an_acceptance_later_in_the_chain_is_invalid_with_enrollment_after_use`
  and `::test_the_verdict_names_criterion_14s_own_section`. Read the first one's
  docstring: an event cannot *literally* name a later acceptance (the anchor is a hash of
  bytes that commit to their own chain position), so what the criterion is about, and what
  the verifier decides, is **reachability**.
* **15** — `TestCriterion15`, three tests, the third of which verifies **the same row**
  under both completeness claims so the criterion reads as a claim about the claim rather
  than about two artifacts. The `contiguous-range` verdict names the missing acceptance's
  hash *and* the scope, per "with the missing acceptance named as outside scope".

### Mutation battery: 23 mutations, 23 killed — after one survivor was fixed

Script: `/tmp/.../scratchpad/mutate.py` (not committed; every mutation is one line and
reproducible from the table in its source). Each §5.11 row and each §5.10 step has a
mutation. **M20 survived on the first pass and that survival was finding 15.**

The mutations, for reproduction: §5.11 rows 1/2 collapsed; step 2's principal/key/project
check, entity-kind scope, transition scope and unscoped-acceptance refusal each disabled;
step 3 reachability not required; step 4's revocation window ignored; step 5's
acceptance/enrolment `public_key` cross-check dropped; Resolution 1's bootstrap **position**
rule disabled; V6 removed from `full_authentication_versions`; the completeness override
allowed to loosen; chain traversal truncated to one hop; the bootstrap-without-a-pin
finding suppressed; producer-policy contradiction suppressed; workflow `definition_hash`
not reconciled; delegated authorization treated as established; caller pins not compared;
cutover pin mismatch not an epoch violation; §5.9 rule 1's raise removed; the bundle's v6
hash formula reverted; bundle key evidence from v6 payloads disabled; the bundle counting
an `UNVERIFIABLE` event as verified; the `ENVELOPE_SCHEMA_INCOMPLETE` clamp guard removed
from the invariants.

### FINDING 10 — the schema validator already enforces most of Resolution 1, so two verifier branches are unreachable

`_validate_v6_object` refuses, at parse time: a null `previous_project_event_hash`
outside a genesis transition; a null `key_binding_event_hash` outside the three bootstrap
transitions; a `project_initialized` with non-null predecessor links; a bootstrap
transition *with* a non-null key binding. `verify_event_strict` strict-parses before the
boundary runs, so **`KEY_BINDING_BOOTSTRAP_NOT_PERMITTED` is not reachable for an
ordinary event through the primitive** — such an envelope never parses.

Two consequences, both handled rather than papered over:

1. `TestResolution1PermittedNulls::test_a_null_binding_on_an_ordinary_transition_is_refused_at_ingress`
   asserts **both** halves: the schema's refusal by name, and the verdict a row carrying
   such bytes actually gets (`INVALID` / `ENVELOPE_UNKNOWN_SCHEMA`). A reader of the
   boundary would otherwise expect the specific reason and conclude the check is dead.
2. **The position rule had to be restated to stay correct.** My first cut tested
   "`previous_project_event_hash is not None`" for a bootstrap event. That is wrong:
   `project_cryptographic_epoch_started` is "the unique first v6 event in a legacy
   project" and its predecessor link legitimately names the **legacy (v5) project head**,
   which is non-null. Testing the link for null would have refused every real cutover
   checkpoint. The rule is now "**no v6 event is reachable behind it**", which a v5 head
   satisfies (it never resolves as a v6 referent) and a second bootstrap mid-epoch does
   not. Both directions are tested
   (`::test_a_bootstrap_null_with_a_v6_ancestor_is_not_permitted`,
   `::test_a_real_cutover_checkpoint_keeps_its_exemption`).

Related and deleted: a special case for "the event names its own hash". §5.8's withdrawn
self-referential acceptance is a statement about hash preimages, not policy — such an
event cannot be constructed — so the branch was unreachable and the general
not-reachable branch already returns the right verdict. Deleted rather than kept with a
test that cannot exist.

### FINDING 11 — a genesis-only bundle CANNOT self-verify true, and saying it did would be a false claim

WI-296 asks for "a healthy genesis-era export self-verifies true". Measured against
`RESULT-MODEL.md` §10.2 invariant 5, that is only half-achievable, and the honest split
is now what the tests assert:

* **A post-genesis chain self-verifies `True`** —
  `tests/test_bundle.py::TestGenesisKeyEvidence::test_a_healthy_post_genesis_export_self_verifies_true`.
  Ordinary v6 events reach `FULLY_AUTHENTICATED` with `key_binding=accepted_in_project`
  and `trust_root=bundled_only` (§5.10 step 5: without the trust log, `bundled_only` "at
  best" — and `bundled_only` is deliberately not `absent`, so §8.3's last invariant is
  satisfied).
* **A genesis-only bundle does not.** Its single event is Bootstrap B with
  `key_binding=bootstrap_external`, and invariant 5 permits `FULLY_AUTHENTICATED` only
  with `trust_root=externally_pinned` **and** `checkpoint_binding=externally_pinned`.
  §5.8 makes `externally_pinned` require the trust log **and** the pin — a project bundle
  carries no trust log. Resolution 1's own words: "Bootstrap without an external pin is
  not a bootstrap; it is an unauthenticated first event." So the verdict is
  `UNVERIFIABLE`, reported as one unverifiable signature with its reason, and **zero
  errors** — a materially different report from the clamp's `INVALID`.

This is why `BundleVerificationReport` gained `unverifiable_details`: a count with no
reason is how "nothing was checked" gets read as "everything checks out".
`TestVerifyAuditBundleOffline::test_a_caller_supplied_trust_pin_reaches_the_offline_verifier`
proves the pin is plumbed (it moves `checkpoint_binding` to `externally_pinned`), and
`TestResolution1PermittedNulls::test_a_pinned_bootstrap_event_with_the_trust_log_is_fully_authenticated`
proves the invariant is not a clamp: present the trust log and the pin and a bootstrap
event authenticates.

**Left for P3.3.** An end-to-end pinned *bundle* verdict needs bundle v3's trust-material
section so an artifact can carry the trust-log events its acceptances reference. WI-296 is
updated with exactly this split.

### FINDING 12 — two things the boundary would have crashed on, found by writing the tests

1. **A windowed export raised instead of returning a verdict.** The class invariant
   forbids `FULLY_AUTHENTICATED` with `epoch_position=unknown`, and material that does
   not present the epoch root produces exactly that. Fixed by making it an explicit
   *finding* (`EPOCH_VIOLATION`, `UNVERIFIABLE`, `unbound_properties += {"cutover_checkpoint"}`)
   rather than an assertion: an event whose epoch root the material does not show cannot
   be shown to belong to the clean epoch (`EPOCH-RESET.md` §5.1). Test:
   `::test_an_event_whose_epoch_root_is_absent_is_unverifiable`.
2. **A found revocation was reported as `revocation_status: unknown`.** Step 4 found the
   revocation and step 6 (which reads the trust log, absent here) concluded `unknown`, so
   the result contradicted itself. The step-4 finding now sets `REVOKED_BEFORE_USE`. Test:
   `::test_step4_the_reported_revocation_status_matches_what_was_found`.

### FINDING 13 — what this boundary does NOT implement, stated so nobody claims it

* **The legacy-epoch reclassification.** `RESULT-MODEL.md` §10.2 invariants 2, 3 and 7 —
  post-cutover v4/v5 or HMAC is `INVALID`/`EPOCH_VIOLATION`; pre-cutover v4/v5 is never
  `FULLY_AUTHENTICATED` once a checkpoint exists; a valid HMAC event is
  `attribution=shared_secret`, `key_binding=legacy_unbound`, `LEGACY_PARTIAL` — is the
  ~334,000-event story and is **cutover work, not verifier-boundary work**. The eleven new
  fields are populated on legacy results with their honest "not established" members
  (`epoch_position=unknown`, `trust_root=absent`, `key_binding=unresolved`) and **no
  legacy verdict changed**. `test_row5_a_pre_cutover_legacy_event_is_untouched_by_this_boundary`
  pins that as an absence.
* **§5.11's `retrospective_key_binding` row** (`legacy_key_binding_attested`, §6). The
  `KeyBinding.RETROSPECTIVE` member and its invariants exist; nothing emits it, because
  nothing writes the attestation. §9 criterion 24 belongs with WI-241's work.
* **§5.12's delegation chain.** An action-delegation credential is a *document*, not an
  event, and no channel in the presented material carries one (WI-008 has not landed). A
  `delegated` v6 event is therefore `UNVERIFIABLE` with `delegation_chain` named as
  unbound and can never be `FULLY_AUTHENTICATED`. `DELEGATION_CHAIN_INVALID` stays defined
  for the presented contradiction that becomes reachable when WI-008 lands.
* **`root_governance`** is always `unknown` and named in `unbound_properties`: deciding it
  needs the genesis *document*, which is a caller input the presented-material protocol
  does not carry. P2.1's `GenesisDocument` is the natural home for a future
  `governance=` input.
* **§6.6's `indeterminate_window`.** The member and the invariant exist (it may not be
  `FULLY_AUTHENTICATED`); emitting it needs presented trust-log **revocations** plus
  `trust_log_checkpoint_observed` events, and nothing writes the latter (it is
  `_trust_log.DEFERRED_TRANSITIONS`' "P2.4 / §6.6"). Reachable when P2.4 lands.
* **The write-time anchor query** (`_v6_writer._anchor_candidate_rows`) is untouched, as
  instructed. Its `global_seq` ordering is a documented write-time-only shortcut.
* **WI-299's positive clause** is still not restored (approval policy, §0 Finding 6).
* **WI-301** (the production trust-log append path) is untouched and still blocked on a
  design round.

### FINDING 14 — `replay()` files every non-work-item entity group as an orphan halt

Measured while writing `TestAgainstARealEpoch::test_a_real_replay_does_not_halt_on_a_healthy_v6_chain`:
`_replay._process_group` sends every group whose `entity_kind != "work_item"` down
`_handle_orphan_group`, which counts a **halt** and records "Orphaned events with no
work_item and no created event" (or "events exist but projection row missing from
work_items_current"). A v6 epoch's chain necessarily carries `project`, `principal` and
`workflow` entity events, so **every** migrated fixture that calls `replay()` will see
`halted >= 2` for reasons that have nothing to do with verification.

This predates phase 2 and is **not** a verifier problem. It is, however, a **Phase 3
blocker**: a migrated fixture asserting `halted == 0` will fail, and the tempting fix
(weakening the assertion) hides the real one. The test here asserts the precise claim
instead — no halt is a *verification* halt, and every remaining halt matches one of the
two known orphan forms.

**What Phase 3 needs to decide:** whether `_replay` should replay non-work-item entity
groups (they have no `work_items_current` row to rebuild, so "replay" means "verify and
apply the projection appliers"), or report them as a distinct non-halt category. Either
is a change to replay's contract and wants the coordinator.

### FINDING 15 — the surviving mutant, and the two weaknesses it exposed (WI-302)

**M20** reverted `_bundle._hash_event` to the v1-v5 `sha256(envelope || signature)` formula
and the suite stayed green. Reporting the analysis rather than only the fix, because the
analysis is the load-bearing part:

1. **`_verify_global_chain` reports `global_chain_ok` vacuously when NO link resolves.**
   It deliberately allows a *bridge point* — an event whose predecessor lies outside the
   presented set — because a windowed export starts mid-chain. The allowance is
   unconditional and per-event, so when every link fails to resolve, every event is an
   entry point, is immediately its own tail, `len(visited) == len(events)`, and it returns
   `ok=True`. The chain was never verified and the report said it was. **Filed as WI-302
   and NOT fixed here** — it is `BUNDLE-V3.md`/P3.3's, and the suggested bound is on the
   item (a `complete-store` bundle may have at most one entry point).
2. **The v6-era fixtures could not have caught it.** `_verify_work_item_chains` *does*
   break loudly, but only for an entity carrying two or more events — and
   `_v6_fixtures.open_v6_epoch` writes exactly one event per entity (one project event,
   one workflow registration, one acceptance per principal, all `entity_seq == 1`). So the
   per-entity check had nothing to check.

The fix here is to the **test**, plus the version-aware `_hash_event` that was already in
`906ed88`: `TestGenesisKeyEvidence`'s fixture now builds a two-event entity on purpose,
and `test_the_v6_chain_links_verify_under_the_v6_hash_formula` asserts the formula at the
primitive (`_hash_event(event) == compute_v6_event_hash(...)`) as well as through the
report — a behavioural assertion alone is satisfied by a chain check that checks nothing.
M20 dies after the change. **The CHANGELOG's first draft claimed the bug caused a false
chain break; it did not, and the entry is corrected to say what it actually caused.**

A second, smaller thing the battery is worth: mutating the *facade grammar* is not in it,
and `_genesis.read_genesis_from_connection` now depends on the in-memory facade modelling
`SELECT canonical_envelope, signature FROM events`. That dependency was working by luck
and is now pinned by
`test_wi287_inmem_parity.py::TestMigrationHarness::test_store_referents_presents_material_over_the_in_memory_facade`.

### Manifest: unchanged at 686, measured

No node newly passes. That is expected and is Finding 8 read forwards: the manifest's
recorded forms are `GENESIS_REQUIRED` (666), sidecar-409/`KeyError`/empty-state (24) and
four `AssertionError` forms — all of them *pre-genesis* refusals. Phase 2 changes what a
**verified** v6 event reports; it does not open an epoch for an unmigrated fixture, so
nothing in the manifest moves without fixture edits, and fixture edits are Phase 3.
Finding 8's list of verifying files (`test_replay_coverage.py` 29, `test_replay_scoped.py`
12, `test_replay.py` 4, `test_bc310_replay_isolation.py` 3, `test_wi217_replay_memory.py`
2, `test_global_event_chain.py`, `test_hash_chain.py`, `test_wi267_row_authentication.py`)
is now **unblocked** — subject to Finding 14.

---

## 0. Session 2 (2026-08-18): what landed, and five findings

Commits, in order:

| SHA | Slice |
|---|---|
| `ce19e06` | Merge of `agent/wi287-inmem-parity`, + the `v6_epoch_open` shape unification and a real in-memory `append_v6` |
| `6ed569b` | §3c items 1-3: the ceremony round-trip on a real epoch, all three stubs deleted |
| `378a9a1` | The **remaining legacy funnels** wired to the v6 route + the first migrated file (`test_idempotency.py`); manifest 694 → 688 |
| `e3b18cf` | In-memory signed workflow registration (Finding 9) + `test_hash_chain.py`; manifest 688 → **686** |

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

### FINDING 7 — the wiring was three funnels short, which is what actually gated Phase 3

`d3cce8f` wired `_event_store.append_event`. Three more refused post-genesis, and
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
3. `register_workflow_file` needs no change on **either** backend — `_workflow_api` appends the
   signed `workflow_registered` event post-genesis, and since Finding 9 the in-memory backend
   calls the same function, so admission gate 1 is satisfied for free.

Measured result: **6 XPASS(strict) → 6 passed**, manifest **694 → 688**; then
`tests/test_hash_chain.py` took it to **686** (2 of 3 nodes — see Finding 8). Use
`/tmp/.../shrink.py`-style surgery on the manifest (`json.dump(..., indent=1)` + trailing
newline, and **update `baseline_count`** — the debt checker asserts
`baseline_count == len(entries)`).

### FINDING 8 — **Phase 3 is NOT independent of Phase 2.** Migrate verifying files LAST.

`_replay` verifies every event through `verify_event_strict`, and the Phase 2 clamp returns
`INVALID` / `envelope_schema_incomplete` for **every** v6 row. So a *correctly* migrated fixture
makes `replay()` report `halted=1` on a perfectly good chain:

```
[REPLAY_HALTED] Signature verification failed for event ... at seq 1:
applicability=invalid; envelope=v6; reasons=envelope_schema_incomplete
```

Measured on `tests/test_hash_chain.py::TestBC233HashChain::test_replay_hash_chain_check`. The
consequence is a **sequencing constraint the brief's Phase 2 → Phase 3 order gets right and
which is worth stating explicitly**: any manifest file whose nodes call `replay()`, `verify_*`,
or the assurance/bundle paths **cannot be migrated before Phase 2**, because migrating it
changes the node's recorded failure form from `GENESIS_REQUIRED` to a clamp assertion — and
§2.1's form validator correctly refuses to absorb that, while rewriting the recorded form to
match would be exactly the "changed failure mode absorbed as XFAIL" the validator exists to
stop. Affected files include at least `test_replay_coverage.py` (29 nodes),
`test_replay_scoped.py` (12), `test_replay.py` (4), `test_bc310_replay_isolation.py` (3),
`test_wi217_replay_memory.py` (2), `test_global_event_chain.py`, `test_hash_chain.py`,
`test_wi267_row_authentication.py`.

**Last-resort pattern, used once and flagged as such:** where a file mixes verifying and
non-verifying nodes, the non-verifying ones can be migrated now if the verifying one is kept on
a *separate, unmigrated* fixture, which preserves its recorded form. `test_hash_chain.py` does
this (`unmigrated_regista`, with the reason in its docstring) and shrank the manifest by 2 of
its 3 nodes. Do **not** propagate this widely — after Phase 2 each file migrates in one pass.

### FINDING 9 — the in-memory backend never emitted its signed workflow registration

`InMemoryRegista.register_workflow` wrote only the in-memory registry dict, so an in-memory
project with an open epoch refused **every** ordinary append with
`WORKFLOW_REGISTRATION_UNRESOLVED` — a `workflow_registry` row is not a registration
(`V6-ENVELOPE.md` §1.9) and that is enforced identically on both backends. Fixed by calling
`_workflow_api._append_workflow_registration_event` — **the same function** the Postgres path
uses — over the `_in_memory_v6` facade, so the payload shape, the `raw_yaml` exclusion, the
definition hash and the workflow entity id stay one piece of code. No-op before genesis, as on
Postgres. WI-287 shipped `register_test_workflow` as a *test* helper; this is the production
half it stood in for, and nothing had exercised it because no in-memory fixture had an epoch.

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
| **2 — verifier boundary** | **LANDED** (`906ed88`). `_v6_referents.py` (new), §5.10/§5.11 in `_verification.py`, the resolver threaded through 11 production call sites, `RESULT-MODEL.md` §10.1's eleven result fields, `tests/test_p17_v6_verifier_boundary.py` (78 nodes), WI-296 both halves, WI-287 cluster 6 tightened. **§0b supersedes §4.** |
| **1b/1c blockers** | Finding 4 **resolved 2026-08-18** — the admission rule is unchanged; it was a fixture-topology bug. §3c has the taken path and the scoped remaining work. |
| **3 — empty the manifest** | **Started.** 694 → **686** (2 of 74 files; 8 nodes newly passing, 0 retired). Finding 8's Phase-2 dependency is **discharged** (§0b); read **Finding 14** before migrating any file that calls `replay()`. §0 has the recipe and the per-file cost. The population figure is **217 in-memory / 446 Postgres / 24 indirect / 7 slow** (NOTES-WI287 §4's causal measurement), **not** §2's name-based 167. |
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

## 4. Phase 2 design notes (the verifier boundary) — SUPERSEDED BY §0b

> **SUPERSEDED 2026-08-18 by `906ed88`.** Phase 2 landed; §0b is the record of what was
> built, which of these notes held, and which did not. Two did not, and the corrections
> are the interesting part:
>
> * the `AcceptanceScopes` / `_anchor_from_row` reuse suggested below was **not** taken —
>   the verifier reads presented material addressed by hash, not stored rows, so it needs
>   a different accessor. The §5.8 scope *rules* are reimplemented over the referent's
>   parsed payload (§0b's coverage map), which is the same rule, not the same code;
> * "the completeness claim needs a `VerificationPolicy` field, defaulting to the stricter
>   reading" is only half right — completeness is a property of the **material**, so the
>   resolver owns it and the policy field is a tighten-only override. See §0b.
>
> Kept below unedited because the reading it records is still the reading, and because the
> two corrections only make sense beside it.

The clamp was `_verification._verify_v6_row`, final return, `_verification.py:2311-2324`:

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
