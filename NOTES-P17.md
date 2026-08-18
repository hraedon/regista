# P1.7 handoff — what landed, what did not, and the two findings that change the plan

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

## 1. Status by phase

| Phase | State |
|---|---|
| **1 — writer + admission checks** | **Landed** (`653e1c6`). `_v6_writer.py`, `tests/_v6_fixtures.py`, `tests/test_p17_v6_writer.py` (36 tests), 5 error codes. |
| **1b — contracts + partial wiring** | **Landed.** The §5.8 acceptance/revocation contracts, the accepter/signer cross-checks, `register_workflow`'s signed event, the process-level producer identity, the §2.3 timestamp helper. `tests/test_p17_key_acceptance.py` (45 tests). |
| **1c — the rest of the wiring** | **Not started.** `_event_store.append_event` / `_events.*` still legacy; `provision_principal` still refuses; `PrincipalLifecycle.commit()` still sentinel-passing; fixtures not migrated. §3 has the sequencing. |
| **2 — verifier boundary** | **Not started.** The clamp is still at `_verification.py:2311-2324`. Design notes in §4. |
| **3 — empty the manifest** | **Not started.** Manifest still 694. **Read §2: the target is 167, not 0.** |
| **4 — full validation** | Both lanes green + all guards at each checkpoint; not re-run against a changed manifest because the manifest has not changed. |

Phase 1b deliberately stopped short of routing `_event_store.append_event` to the writer. Doing
that before the fixtures are migrated reddens all 694 manifest nodes with a *changed* failure
form (`KEY_BINDING_UNRESOLVED` instead of `GENESIS_REQUIRED`), which the §2.1 form validator
correctly converts to honest red. **The wiring and the fixture migration must land in one
change, file by file.** Everything 1b added is either pre-genesis-inert (`register_workflow`) or
new surface no existing caller touches, which is why it lands green on its own.

---

## 2. FINDING 1 — the manifest cannot reach literally empty under P1.7's stated non-goals

**Measured: 167 of the 694 manifest nodes (24.1%) are in-memory-backend nodes.**

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
