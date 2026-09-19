# Plan 032 — review of the open decisions

**Reviewer:** GPT-6. **Date:** 2026-09-17. **Baseline:** `a9f6913206fc7e08084887be15044b16d5dfb995`.

These are recommendations on [the decision list](032-open-decisions.md), not
accepted rulings or authorization to implement or publish. I read Plan 032, the
dependency and disposition reports, the prototype, the five ambiguous plans,
and relevant current implementation and packaging files. Targeted experiments
are recorded below; this was not a full implementation audit.

I support the smaller coordination product and favor extraction. The strongest
reason is the opportunity to establish one coherent contract and schema without
the trust stack. The prototype demonstrates useful workflows, but its size and
successful scenarios do not establish the cost of preserving the old kernel's
correctness. Several of those guarantees are already missing in the prototype.

I would revise the opening claim that nothing needs further analysis. Most scope
choices can be made now. Release compatibility, affected historical versions,
and prototype qualification still require evidence. Also distinguish choices
requiring the maintainer's judgment from implementation work already implied by
Plan 032: truthful documentation and CI coverage should not need separate votes.

**D1 — Extract, with an explicit regression-preservation obligation.**

Promote the prototype into the retained implementation after the F0a exit, and
reuse corrected existing validation, transaction, and serialization logic where
it fits. A changed event row supports a fresh baseline; it does not by itself
prove a rewrite is cheaper. The meaningful comparison is the completed kernel
plus its qualification burden, not 736 prototype lines against 22,610 existing
lines. Require a mapping from retained behaviors and PORT/SPLIT assertions to
their replacements before deleting their protection.

The evidence below shows why that qualification matters: expired lease writes,
caller-overwritten event fields, and incomplete drift detection. Also carry
forward namespace isolation, rollback on every failure, concurrent idempotency,
and optimistic revision checks. These are completion work, not reasons to
reintroduce the trust system.

Correct two factual premises in D1: creation and transition timestamps currently
come from `_utcnow()` in the writing process, and a datetime custom field raises
`TypeError` rather than round-tripping as a string. Avoiding timestamp parsing is
still a useful simplification, but it is not a property unique to extraction.

Finally, archive, an async API, and cross-project links are not explicit
requirements of Plan 032's keep table. I would exclude all three from 0.8.0
unless a retained scenario demonstrates a need. Keep basic diagnostics and
bounded health checks; do not silently price an old observability subsystem
back into the MVP.

**D2 — Retire the in-memory backend; preserve its useful assertions.**

Agree. A second storage engine is poor value for a product whose main promises
involve PostgreSQL durability and concurrency. Port the relevant 35 conformance
tests to disposable PostgreSQL, adapting assertions to the deliberately changed
contract. Keep fast unit tests for shared pure validation and reduction
functions. Removing the backend need not make every test a database test.

**D3 — Remove the sidecar and its extra.**

Agree. Authentication, deployment, request models, and rate limiting are a
separate supported surface. The Python API and CLI are sufficient for the two
chosen scenarios. Verify removal from wheel/sdist contents, entry points, and
current deployment documentation as well as from imports.

**D4 — Remove recurrence and asynchronous delivery; decide synchronous validators separately.**

Agree on recurrence, queued hooks, and webhooks. Preserve useful bounded event
inspection rather than an execution service. Keep trusted synchronous
transition validation as described under D16/D20: enforcing a rule within a
transition transaction is a different responsibility from delivering background
jobs.

The agent-wake question belongs to an estate upgrade. If that consumer remains
on its working release and isolated checkout, publishing a reduced package does
not require building it a replacement ingest system. Verify how it resolves
Regista before changing the shared development checkout; see D9.

**D5 — Remove signing entirely from the reduced release.**

Agree with the outcome, but optional HMAC is not inherently misleading: it can
provide a meaningful, limited integrity guarantee when described correctly.
The reason to omit it is that this product does not need the additional keys,
configuration, verification modes, and maintenance contract. Keep one validated
JSON representation for persistence and any consistency hashes. Do not use
`default=str` as an implicit field-type conversion policy.

**D6 — Allow one bounded, read-only, single-hop link-aware query.**

My preference is to include this small query capability. Reading related work
does not create a scheduler. Let the caller specify link type, direction, and
the states that count as satisfied; do not assume every terminal state means
successful completion. Use stable ordering and pagination, with no recursive
graph traversal, automatic transitions, or claim gating.

Document the result as a snapshot, not a guarantee that dependencies remain
satisfied when someone subsequently claims the work. State-based blocked
queries already meet F0a's stated requirement, so this choice should not
retroactively invalidate the scenarios or require another prototype engine.

**D7 — Keep merge semantics, but documentation alone is insufficient.**

Agree that rejection should not implicitly erase arbitrary domain data. Specify
that the merge is shallow: omitted keys survive and supplied keys replace their
previous values, including entire nested objects. Define whether null is a
value and what counts as satisfying a required field.

Provide one explicit, atomic way to clear obsolete fields, such as an
`unset_fields` argument. Validate the resulting field set and record the same
patch in history for replay. Otherwise a caller can learn that rejected data
persists but still have no supported way to remove it. Demonstrate intentional
clearing of a rejected extraction in the document example.

**D8 — Use a fresh reviewer session or person, with only the quickstart.**

Prefer a person representative of the intended Python/PostgreSQL user; a fresh
agent session with no implementation context is a practical first pass. Give
them the README, a clean environment, and the stated prerequisites. Record
missing steps, questions, commands, and elapsed setup time before helping.

The current 0.07-second measurement is execution time after prerequisites are
available, not time to first successful use. The README also assumes a working
directory and an available `psycopg` installation. The walkthrough should catch
those assumptions. This review does not satisfy D8: I have read the code.

**D9 — Cap the dependencies, but verify the artifact that consumers actually install.**

This should be a release blocker, with some development isolation work before
F1. I confirmed the three unbounded declarations in the sibling pyprojects.
At minimum exclude 0.8; constrain more tightly if a consumer is only qualified
against 0.5.x. An upper bound of `<0.8` is not evidence that 0.6/0.7 work for a
tool currently using 0.5.5.

Three source-line edits are not the complete mitigation. Existing installed or
published consumer metadata will still contain its old requirement until an
updated consumer artifact or effective installation constraint reaches that
environment. Check representative fresh installs and upgrade resolution using
those artifacts. The editable `../regista` sources also need a preserved old
checkout or another explicit boundary before main is reduced; a PyPI version
cap alone does not isolate an editable checkout. Unsupported-schema refusal is
the necessary final backstop. No sibling repository changes were made in this
review.

**D10 — Use 0.8.0.**

Agree. The scope and data-format break should lead the release notes. A 1.0
label would not demonstrate maturity or discharge maintenance obligations.
Reserve it for a stable contract justified by actual use.

**D11 — Recommend a 90-day stabilization window.**

Count from publication, publish the actual end date, and cover release
regressions plus serious security/data-loss reports in the new release line.
State the reporting route and what happens after the window: further work is
discretionary. Do not imply response times, guaranteed fixes, old-line
backports, or feature delivery. This is my proposed commitment, not a promise
made on the maintainer's behalf.

**D12 — Do not blanket-yank older releases as part of simplification.**

Assess security-driven yanks separately against specific published versions,
reachable defects, and a useful remedy or preservation route. “Nobody is
using it” is not an adequate basis, and D9 already identifies an internal
installed consumer. A finding on current main does not itself establish which
published artifacts are affected.

Yanking is preferable to deletion where justified, but it does not repair
existing installations or prevent explicit exact-version installation. Preserve
the old artifacts for restoration and document limitations. These behaviors
are described in [PyPI's yanking guidance](https://docs.pypi.org/project-management/yanking/).

**D13 — First try retaining Python 3.11; do not add the speculative `<3.15` cap.**

I disagree with narrowing solely because CI omitted two versions. Plan 032
explicitly prefers retaining the advertised minimum where feasible. Run the
smaller retained suite and installed-artifact checks on CPython 3.11–3.14; then
raise the minimum only if a concrete compatibility or maintenance cost warrants
it. My default metadata would remain `>=3.11`, with the tested versions stated
separately.

If the maintainer deliberately selects 3.13+, use `>=3.13` absent an identified
future-version incompatibility. PyPA advises against speculative upper Python
bounds; mismatching `Requires-Python` can also make installers select an older
package release. That fallback is particularly undesirable across this scope
break. See [PyPA's support-range guidance](https://packaging.python.org/en/latest/guides/dropping-older-python-versions/).

I reproduced the timestamp-parser difference on installed CPython versions:
3.11.15, 3.12.13, and 3.13.13 reject `24:00:00`; 3.14.4 accepts it. Thus the
proposed **3.13/3.14 range still contains the divergence**. An explicit parsing
contract, or avoiding string parsing, addresses that issue; D13's proposed
narrowing does not.

**D14 — Put maintained prototype code inside the gates now.**

Agree with lint/type coverage, and include the executable PostgreSQL acceptance
cases in the maintained test path. Promotion later should move that coverage,
not be the first time it exists. Passing manual Ruff/mypy checks establishes
neither continued coverage nor the coordination invariants.

**D15 — Make the revised spec authoritative; retire the spec sidecar unless a real consumer needs it.**

Agree on rewriting current documentation and marking historical designs.
`AGENTS.md` should describe contribution workflow and point to the authoritative
contract rather than duplicate hundreds of behavioral promises. Historical
documents should visibly identify the release line they describe.

My default is to retire the hand-maintained `spec.yaml` sidecar from the current
contract. Retain it only for an identified consumer and a reliable generated
or mechanically checked relationship with the source. Keep the workflow JSON
Schema: it validates a supported input format and has a different purpose.

**D16 — Resolve the five plans individually.**

| Plan | Recommendation for 0.8.0 |
| --- | --- |
| 004, workflow composition | Historical; remove inheritance. See D21. |
| 014, global event sequence | Historical as a timestamping design. Preserve per-item ordering and explicitly define any retained project-wide event cursor; do not carry over timestamp batches or a global trust chain. |
| 020, validator context | Preserve a small trusted synchronous validation extension with transition state, fields, workflow version, and asserted actor context. Remove delegation/lineage context and automatic unbounded history loading. |
| 023, built-in review gates | Historical; remove the suite policy. Generic review states and caller-written validation remain possible without built-in model-family rules. |
| 028, sealed archival | Historical; no archival subsystem in the MVP. Backup/restore remains required. AGENTS.md already records segment sealing as removed by P1.4. |

Plan 014's `BIGSERIAL` is not automatically a gap-free or commit-ordered feed.
PostgreSQL sequences can have gaps, and a transaction can allocate an earlier
number while committing after another writer. A consumer that advances past
the later visible number can miss that late commit. If live polling is retained,
qualify its cursor contract under that interleaving rather than copying the old
plan's guarantee. [PostgreSQL's sequence documentation](https://www.postgresql.org/docs/current/functions-sequence.html)
explains allocation and rollback behavior; the missed-event example is the
consequence for this proposed consumer contract.

Trusted callbacks must fail the transaction on refusal or exception. They are
not a sandbox, and database statement timeouts do not terminate arbitrary
Python computation. If limited history is exposed, disclose truncation so a
validator cannot mistake a prefix or suffix for complete evidence.

**D17 — Rewrite the published claims, and also narrow the prototype's claims.**

Agree that the new README must describe the reduced guarantee before release.
I would say: “Replay reconstructs supported state and reports checked
inconsistencies. The host application and database administrators are trusted;
unkeyed hashes do not authenticate actors or establish freshness.”

The old HMAC argument needs a threat-model qualifier: a database-only attacker
without the key cannot forge authenticated content, but a valid signed chain
alone does not establish that it is the latest complete history. Do not turn
that narrower argument into a blanket endorsement of old security claims.
The prototype's present claim to detect truncation also overstates what its
replay checks do; the same-state tail-deletion experiment below reports no
drift. Inspect the README embedded in the actual wheel/sdist metadata.

**D18 — Delete both from the current tree; git history preserves them.**

The hooks example should be replaced by the two maintained coordination
examples. Delete `NOTES-WI337.md` once any still-relevant conclusion has a home
in the current spec or tracker. A new historical directory is worthwhile only
if it helps readers more than existing history and release tags do.

**D19 — Keep the estate on preserved working versions for this release.**

Agree that the public kernel should not carry the canonical suite lifecycle.
The least work is to preserve the old environment and shared workflow while
the independent reduced product is qualified. There is no need to migrate
dossier or agent-notes merely to release 0.8.0.

If those consumers later adopt the new kernel, give the workflow one versioned
owner at the application/suite layer and have both consume it. Do not duplicate
the policy or make one face depend on the other just to share the YAML. D9's
artifact and editable-checkout safeguards make this separation real.

**D20 — Decide all five files, including the two validator files.**

The omitted validator question is more consequential to the product than the
test dependency question. My dispositions are:

| File | Recommendation |
| --- | --- |
| `test_cli_conformance.py` | Preserve generic success/error/usage/JSON/broken-pipe assertions as ordinary Regista CLI tests; remove the suite conformance dependency. A published test-only wheel is not inherently objectionable, but its suite contract should not dictate this product's CLI. |
| `test_spec_entity.py` | Retire with the signed spec entity. Ordinary custom fields can carry document references; a new generic attachment/entity subsystem is not justified here. |
| `test_validator_context_enrichment.py` | Split: port the retained synchronous validator context; retire delegation, lineage, and backend-specific parity obligations. |
| `test_validator_hardening.py` | Port refusal/exception rollback and applicable database-timeout coverage for retained synchronous validators. |
| `_v6_fixtures.py` | Replace the bootstrap harness first, migrate retained callers, then retire the v6 fixture module. This is an implementation dependency, not an unresolved product feature. |

Do not retire useful CLI behavior merely because the harness comes from the
suite, and do not preserve the signed spec entity by renaming it “attachments.”

**D21 — Remove workflow composition for 0.8.0.**

I would not take the exception. The feature includes path resolution, cycles,
depth limits, keyed list merges, append/remove modifiers, and error source maps;
its small module size understates the language it asks users to learn. Its
original duplication evidence concerns software-factory workflows, not either
retained scenario. Accept a complete validated YAML/JSON workflow; callers can
materialize one themselves. Revisit built-in composition after concrete use.

**Additional choices to make explicit before F1.**

- **PostgreSQL support:** F0 asks for this as well as Python support. Existing CI
  and compose use PostgreSQL 15. Start with that qualified target and explicitly
  identify any broader versions as unqualified until tested.
- **Protected writes and concurrent review:** define which transitions require
  a live claim, how deliberately unclaimed human actions work, and how callers
  reject changes to a revision they previously read. Preserve optimistic
  `expected_event_seq`-style checks; a valid lease alone does not mean a reviewer
  approved the current content.
- **Replay coverage:** enumerate which projections are derivable from events.
  The prototype emits work-item create/transition events but directly mutates
  claims, attempt counters, and links. It currently cannot reconstruct those
  from history. At least links and monotonic fencing counters need an explicit
  recovery contract; rebuilding must never make an old token valid again.

**Measured evidence relevant to D1, D7, D13, and D17.**

I ran focused probes against the unchanged [prototype implementation](../prototypes/kernel/kernel.py)
on CPython 3.14.4 and a
fresh disposable PostgreSQL 15.17 container. It was removed afterward. The
repository's configured localhost test database was unavailable, so no existing
database was used for these probes. No source fixes, full suite, installed-distribution checks,
or unfamiliar-reviewer walkthrough were performed.

The confirmed ownership defects are tracked as **WI-367** and the
event/projection/replay defects as **WI-368**, both open. They concern the new
prototype; this review does not establish affected published versions.

| Probe | Observed result | Relevant implementation |
| --- | --- | --- |
| Claim with a one-second TTL; wait 1.1 seconds; transition with its old attempt before any takeover | Transition succeeds. | `kernel.py:524–542` checks the attempt only when a live lease exists. |
| Heartbeat the expired lease before takeover | Lease is renewed. | `kernel.py:430–447` matches actor/attempt but not liveness. |
| Transition as a different actor while supplying the live holder's attempt | Transition succeeds. | `kernel.py:529–542` does not compare the actor to the holder. This concerns ownership semantics, not independent authentication. |
| Transition with `fields={"amount": 2}` and `payload={"fields": {"amount": 999}}` | Projection has 2; replay returns 999 and `drift=[]`. | `kernel.py:582` lets payload overwrite reducer-owned keys; `kernel.py:765–768` compares only the state. |
| Delete the final event of a transition that changes fields while remaining in the same state | Replay returns old fields and `drift=[]` although the projection contains newer fields. | `kernel.py:731–768` does not reconcile the final sequence or custom fields. |
| Pass a datetime in a custom field | `TypeError: Object of type datetime is not JSON serializable`. | `kernel.py:344` uses ordinary psycopg `Jsonb`; `_canonical(default=str)` is a separate path. |

These results are reasons to preserve proven regression tests during extraction.
They are not evidence that the smaller product boundary is wrong. Protect
reducer-owned event data, share validated reduction semantics, and compare the
whole supported projection against one coherent history snapshot.

One further static concern deserves a test when lease handling is repaired:
`get()`, `get_workflow()`, and `links_from()` leave read transactions open, while
lease predicates use `now()`. PostgreSQL's `now()` is fixed at transaction
start, so selecting the database clock is not sufficient if a lease decision
uses a timestamp captured before a long wait. Evaluate liveness at the intended
serialization point and close transactions predictably. This follows from
[PostgreSQL's current-time semantics](https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT);
I did not run a separate contention probe for it.
