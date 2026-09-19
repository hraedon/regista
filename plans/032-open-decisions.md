# Plan 032 — open decisions

Every item below is a decision, not a task. Each states the evidence, the
options, a recommendation, and what it blocks. Nothing here is waiting on more
analysis; it is waiting on a ruling.

Review: [GPT-6's recommendations and measured caveats](032-open-decisions-review.md)
(2026-09-17). These are review opinions, not accepted decisions.

---

## Rulings — 2026-09-17

The maintainer ruled the four decisions below directly. Everything else is
recorded as **adopted** (the decision list and the review concur, and the item
is reversible) or **still open**. An adopted default is a working assumption
that unblocked implementation, not a maintainer ruling; any of them can be
reopened, and the two genuinely open items must not be defaulted.

| # | Ruling | Effect |
| --- | --- | --- |
| **D1** | **EXTRACT.** Promote `prototypes/kernel/` into the retained implementation. | F1 is now completion-and-qualification of the kernel, not a sever of the old tree. The regression-preservation obligation from the review is attached: a mapping from retained behaviours and PORT/SPLIT assertions to their replacements exists **before** the protection they replace is deleted. |
| **D6** | **YES**, one bounded single-hop read-only link-aware query. | Caller supplies link type, direction, and which states count as satisfied. Stable ordering and pagination. No recursion, no automatic transitions, no claim gating. Documented as a snapshot, not a guarantee that a dependency is still satisfied when someone later claims the work. |
| **D9** | **CAP NOW.** Executed 2026-09-17; the premise was two-thirds stale and the real exposure is elsewhere — see the correction below. | See "D9 as executed". |
| **D13** | **KEEP `>=3.11`**, test 3.11–3.14. No speculative `<3.15` cap. | Plan 032 prefers retaining the advertised minimum; PyPA advises against speculative upper bounds, and a mismatched `Requires-Python` can make an installer resolve to an *older* regista release, which is the worst outcome across a scope break. The `fromisoformat` divergence is **not** addressed by narrowing — it was measured to sit inside the proposed 3.13/3.14 range too. The extracted kernel avoids it by parsing no timestamp strings at all. |

**Adopted** (concurring recommendation, no dissent): D2 retire the in-memory
backend *and* retarget its 35 conformance tests to PostgreSQL — the retargeting
is part of the yes, not a follow-up; D3 remove the sidecar and its extra, by
file deletion, since `packages = ["src/regista"]` has no exclude and
`sidecar/__main__.py` is a live entry point; D4 remove recurrence, queued hooks
and webhooks, while keeping trusted **synchronous** transition validation, which
is a different responsibility from background delivery; D5 delete signing
entirely; D7 keep shallow-merge field semantics but add one explicit atomic way
to clear them — documentation alone leaves a caller able to learn that rejected
data persists with no supported way to remove it; D10 `0.8.0`; D14 gates now;
D15 rewrite the spec to the reduced scope, retire the `spec.yaml` sidecar absent
an identified consumer, keep the workflow JSON Schema; D16 the five ambiguous
plans per the review's table; D18 delete both; D19 leave the estate on preserved
working versions for this release; D20 the five test files per the review's
table; D21 remove workflow composition — the exception was considered and
declined.

### D9 as executed — the hazard was not where the decision said it was

Checking `origin/main` rather than the working-tree checkouts (each of which sat
on an unrelated feature branch, behind its remote) changed the picture:

| Repo | Decision list said | `origin/main` actually had |
| --- | --- | --- |
| `agent-notes` | `>=0.5.1`, unbounded | **`>=0.7.0,<0.8`** — already capped, via WI-072 |
| `dossier` | `>=0.5.4`, unbounded | **`>=0.7.1,<0.8`** — already capped, via WI-040 |
| `ad-steward` | `>=0.5.1`, unbounded | `>=0.5.1` — genuinely unbounded |

Both earlier caps were stopgaps written during the 0.6.0 break and then raised
when each repo ported to v6. `ad-steward` never got the treatment: its
2026-08-31 v6-epoch migration changed provenance code and left the bound alone.
Its floor is now arguably too *low* rather than too high — the code needs a
v6-epoch regista while the metadata still claims 0.5.1 works. Flagged, not
changed; that is a separate judgement from closing this hazard.

Only `ad-steward` needed an edit. It is committed
(`f7077016bce75a0bc9f8685706b030546afcb723`, branch `fix/wi-366-regista-lt-0.8`
off `origin/main`) and **unpushed**: the repo's own pre-push publication guard
refuses it, because the repository was transferred to the `hraedon-labs` org
while `publication.toml` on main still declares `remote_owner = "hraedon"`. That
correction already exists in open PR #3 and was deliberately not merged here.
See [[reference-publication-plumbing-guard]].

**The version cap is not the real exposure.** Three findings outrank it:

1. **`ad-steward`'s CI checks out `hraedon/regista` at default-branch HEAD with
   no ref or tag pin**, then `pip install -e ./regista-src`. The moment regista's
   main is reduced, that CI builds against 0.8.0 regardless of any specifier in
   `pyproject.toml`, because the checkout step never consults it. Pinning that
   checkout to a tag or SHA is the actual mitigation, and it is a prerequisite
   for reducing main — not a follow-up.
2. **The installed tool is further behind than recorded.** The live `uv tool`
   venv holds `agent-notes-hraedon` **1.0.0** pinned to `regista-hraedon`
   **0.5.4** — not 1.1.0/0.5.5. PyPI already carries `agent-notes-hraedon` 1.1.0
   with `>=0.7.0,<0.8` baked in, so the fix exists upstream and simply has not
   reached this box. This is precisely the review's point that source edits do
   not reach installed metadata. Upgrading also adopts the v6 envelope epoch
   against the **production** store, so it is a judgement call, not a mechanic.
3. `agent-notes` and `ad-steward` both carry
   `[tool.uv.sources] regista-hraedon = { path = "../regista", editable = true }`.
   That is dev-only and absent from published metadata, so it does not reach PyPI
   consumers — and when main is reduced their `uv lock`/`uv sync` will fail
   loudly on the constraint rather than silently resolving. That is a safety
   property, but it means those two repos stop building locally the day main is
   reduced, which should be expected rather than debugged.

`dossier` resolves regista purely from PyPI with no source override, so its cap
is fully load-bearing. None of the three repos' CI consumes `uv.lock` for the
regista dependency; `ad-steward`'s lock is gitignored entirely.

**Still open, and deliberately not defaulted:**

- **D8** — the unfamiliar-reviewer walkthrough. Being measured now by two cold
  agents given the quickstart and a database and nothing else. This is the one
  F0a exit criterion that cannot be self-reported.
- **D11** — the maintenance number. The review proposes 90 days from
  publication, with the end date published and the route stated. Needs the
  maintainer's figure before F4 documentation can be written.
- **D12** — whether older releases are yanked. Unchanged: assess per published
  version against reachable defects. Note that "nobody is using them" is now
  weaker than it was, because D9 identified an internal installed consumer.

---

## Blocking F1 (the removal work itself)

### D1. Extract, or sever in place? — Plan 032 §5

**Evidence.** `plans/032-f0-dependency-map.md` §3 and §9. The severing work
concentrates in six modules (6,046 LOC) and *looks* tractable. §5 shows why that
reading is incomplete: `events.key_id` and `events.signature` have been `NOT NULL`
since `001_initial.sql`, and `project_identity` could not be populated without a
trust domain and a genesis event. The retained event record must change either
way, so those six modules get re-cut regardless.

A working kernel on the new row cost **736 lines** (`prototypes/kernel/`), runs
both F0a scenarios, and is `ruff`/`mypy --strict` clean. Severing means reaching
the same row through 22,610 lines carrying the history of every design it served.

**Recommendation: extract.** Promote the prototype, per F0a's requirement that
the minimal implementation "must become the retained implementation, not a
throwaway second engine."

**Caveat I want on the record:** the prototype is not a complete MVP (no
pagination, pool health, YAML workflow loading, bounded field filtering, archive,
observability, async surface, cross-project links). Completing it is an estimated
low thousands of lines — an estimate, not a measurement.

**A second argument for extract, found while verifying the packaging pass.**
`datetime.fromisoformat` parses a different language on different interpreters —
CPython 3.14 accepts `"2026-08-09T24:00:00Z"` as the following midnight where
3.12, 3.13 and PyPy 3.11 raise. That call site lives in **`_contract.py`,
`_types.py`, `_replay.py` and `_cli.py`** — all KEEP-classified. So the sever path
inherits the hazard into the shipped kernel and has to hunt it down module by
module. The prototype **cannot** have it: it does no timestamp parsing at all,
because timestamps are `TIMESTAMPTZ` columns written by the database's `now()`
and returned by psycopg as native `datetime`. Strings never enter the path.

(One honest asymmetry in the prototype: `_canonical()` stringifies datetimes via
`json.dumps(default=str)` when hashing, and a caller who puts a datetime into a
custom field will read it back as a string. That is a field-typing wart to
document, not the interpreter-divergence hazard.)

### D2. The in-memory backend — the only close call

**Evidence.** Dependency map §7. Plan 032 keeps it "only if it shares actual
transition/reduction rules." It half does: most modules import the shared
`_contract`, and `_in_memory_transition` imports the real `_transition`/`_workflow`.
But `_in_memory_replay` (794 LOC) and `_in_memory_v6` (722) share nothing and
carry their own chain verification — a second replay implementation, against
"preserve one implementation of transition and reduction rules."

**Recommendation: retire it**, use disposable PostgreSQL fixtures. The part that
would justify keeping it is precisely the forked part. This is the one place the
map argues against keeping something that partly meets the plan's own condition,
so it deserves a conscious "yes" rather than silence.

**Cost I did not price when I first recommended this.**
`test_in_memory_conformance.py` is 654 lines and **35 tests** covering almost
exactly the keep table, running against this backend. Retiring it without
retargeting those tests to PostgreSQL fixtures is a silent loss of the regression
coverage the kernel most needs. The recommendation stands; saying yes to it means
saying yes to the retargeting too.

### D3. HTTP sidecar

1,708 LOC, ships its own `TokenRegistry`, `AuthenticatedActor`, `require_admin`
and rate limiting, pulls fastapi/uvicorn/pydantic/httpx. Not a thin pass-through.
**Recommendation: remove**, with its extra.

### D4. Recurrence, hooks, webhooks

Execution concerns under Plan 032's own "not a job executor or scheduler."
**Recommendation: remove.** One check first: `agent-wake` uses the hook queue as
a durable-ingest path. That is a consumer question for the estate, not a reason
to keep it in a published MVP — but somebody should confirm agent-wake has
another route before the queue goes.

### D5. Signing — delete entirely, or keep an optional HMAC facility?

Plan 032 §3 makes deletion the default and says to settle it in F0. The prototype
assumes **total removal**: unkeyed hash chain for consistency only, stated as such
in the docstring and README.

**Recommendation: delete entirely.** An optional HMAC facility invites exactly the
misreading Plan 032 warns about ("unkeyed hashes must never be presented as
authenticity evidence"), and it is the thread that pulls key management back in.

---

## Blocking the F0a close

### D6. Should "blocked" be a link-aware query?

**Evidence.** `prototypes/kernel/F0a-report.md` §4. Typed links are stored, but
the discovery surface cannot ask "is anything blocking this item still
unfinished." Both scenarios report blocked work by naming a state, which Plan 032
permits — "'blocked' and 'review-ready' are queries over a caller's workflow."
But the plan *also* says links "do not introduce a dependency scheduler."

So this sits exactly on a line the plan draws deliberately, and I do not think it
is mine to cross. **No recommendation** — I can argue it either way:

- *State-based only* (status quo): simplest, honours the no-scheduler line, and
  the caller can compute blocked-ness itself from `links_from()`.
- *Add one link-aware query*: strictly more useful, and "which of my links are
  unfinished" is a query, not a scheduler. But it is the first step onto a slope.

### D7. Custom fields carry forward across transitions — document, or change?

In scenario 2, `invoice_date` from a rejected extraction survived a rework and
was still present at approval. Fields merge rather than replace. That is correct
and probably what most callers want, but nothing currently tells them, and a
caller could reasonably expect a rejected proposal's fields to be cleared.
**Recommendation: document it**, do not change it. Flagging because silence here
is how a surprising behaviour becomes a bug report.

### D8. Who does the unfamiliar-reviewer walkthrough?

Plan 032 F0a requires that "a reviewer unfamiliar with the implementation must be
able to follow the quickstart unaided; record where they needed clarification."
**This cannot be self-reported** and is recorded as the one open F0a exit
criterion. Given the stated goal — a release useful to someone who has never seen
the project — it is the measurement that matters most. Needs a person, or an
agent with no exposure to this work, given only the README.

---

## Blocking F5 (publication)

### D9. Cap the three unbounded estate pins — want me to just do it? (WI-366)

`agent-notes` (`>=0.5.1`), `dossier` (`>=0.5.4`) and `ad-steward` (`>=0.5.1`) pin
`regista-hraedon` unbounded. The installed `agent-notes` tool — the estate's
memory layer against the production store — holds 0.5.5 from PyPI, so an ordinary
`uv tool upgrade` would pull a breaking 0.8.0 into it.

This is a three-line change across three repos and I can do it now. It touches
other repositories, so I have not. **Say the word.**

### D10. Version number: 0.8.0, or 1.0.0?

Plan 032 recommends 0.8.0 as "an explicitly breaking scope reset delivering a
complete, bounded MVP" and says explicitly: "do not declare 1.0 merely to signal
closure." **Recommendation: 0.8.0**, confirm at release prep.

### D11. Maintenance commitment

Plan 032 F4 suggests "a 90-day stabilization window for release regressions and
serious security/data-loss reports, without promised new features or an SLA." The
maintainer chooses before publication; no indefinite commitment is assumed.
**Needs your number.**

### D12. Do older releases get yanked?

Plan 032 F5: "Do not automatically delete or yank older releases. Any such
action needs an affected-version assessment and separate decision." Given the
SEC-0x findings exist in published versions, this is a real question rather than
a formality. **No recommendation** — it turns on whether anyone could be running
them, and the working assumption is nobody is.

---

## Blocking the F0 close

### D13. Python support range — F0 item 5

`pyproject.toml` advertises `>=3.11`; ordinary CI runs 3.13/3.14 and publication
verification runs 3.14. Plan 032 requires the advertised and tested ranges to
agree. A packaging agent is measuring the exact gap now.

The packaging pass measured it: `requires-python = ">=3.11"`, but ordinary CI
tests only 3.13/3.14 and publication verification only 3.14. **Recommendation:
narrow to `>=3.13,<3.15`** — advertising 3.11 support that nothing tests is the
kind of claim Plan 032 F4 exists to stop.

This matters more than bookkeeping because of the `fromisoformat` divergence in
D1: the wider the advertised range, the more interpreter-dependent parsing
behaviour a retained kernel has to be correct across. Narrowing the range and
removing the parsing are two routes to the same safety, and the extract path
takes the second for free.

---

## Not blocking anything, but worth a ruling

### D14. Does the prototype move inside the CI gates?

CI lints `src/ tests/ tools/` and type-checks `src/regista` only, so
`prototypes/` is outside both. I ran `ruff` and `mypy --strict` on it by hand and
it is clean, but code outside a gate rots. If D1 goes the way I recommend this
resolves itself on promotion; if it does not, the prototype should either move
inside the gates or be deleted rather than left as un-gated example code.

---

## New, from the docs inventory — these are the publication-risk items

### D15. `spec.md` and `AGENTS.md` both self-declare normative, and both promise things 0.8.0 will not do

**Evidence.** `AGENTS.md:8` says "`spec.md` is authoritative". `spec.md` §19.2
states the library is the sole sanctioned signer, the invariant the "audit-trail
promise" rests on. `AGENTS.md:275` says replay with principal binding "closes the
non-repudiation loop end-to-end". Plan 032 §1 retires exactly that: "Replay
detects inconsistency and reconstructs supported state; it does not establish
hostile-administrator tamper evidence, non-repudiation, model identity, or
external freshness."

Also stale independently of the reduction: `spec.yaml:3` says it was regenerated
against `spec.md` **v8**, while `spec.md`'s own revision history is at **v9**.
The machine-readable sidecar is a revision behind its declared source.

Plan 032 F0 item 1 requires these be reconciled with no competing normative
instructions left standing. **Recommendation:** `spec.md` and `AGENTS.md` are
rewritten to the reduced scope, and the 0.6/0.7 `docs/` trees are marked
historical rather than deleted. Needs a ruling on whether `spec.yaml` is
regenerated or retired — a machine-readable sidecar for a much smaller product
may not earn its keep.

### D16. Five plans are genuinely ambiguous

The docs pass could classify ~19 plans as clearly historical (trust, signing,
delegation, witness, anchoring, custody, encryption, assurance) and 3 more as
tied to recurrence/hooks/sidecar. **Five resist classification:**
`004-workflow-composition`, `014-global-event-seq`, `020`, `023`, `028`. These
describe behaviour that may survive into the kernel. They need a ruling rather
than a default, because defaulting them to historical silently discards retained
design intent.

### D17. The PyPI-visible tamper-evidence claim

`README.md` is the PyPI long description (`pyproject.toml:9`) — it is the only
document that reaches the published page; `docs/`, `plans/`, `debate/`,
`product-concepts/` and `AGENTS.md` are git-only.

`README.md:312` claims: "**Hash-chained events**: each event's `prev_event_hash`
creates a tamper-evident chain within each work-item", and `README.md:13`
describes the chain as "SHA-256 of prev envelope + signature".

**That claim is defensible today and becomes false on reduction.** Checked: the
chain is `sha256(canonical_envelope ‖ signature)` and the HMAC key lives outside
the database (key file or `REGISTA_HMAC_KEY_*`), so a database-only attacker
cannot forge a link. After the reduction the chain is unkeyed, and anyone who can
write the table can recompute it. Plan 032 §3 is explicit: "Unkeyed hashes must
never be presented as authenticity evidence."

**This is the single most important line to change before publication**, and it
is not a judgement call — it is a security claim that would become untrue on a
public package under your real name. 15 such claims were catalogued in total
(hash-chain tamper evidence, trust hardening, delegation, pluggable signing,
witness co-signing, non-repudiation, third-party anchoring, audit bundles,
assurance/lineage, suite integration, webhooks, sidecar, recurrence, in-memory
conformance, field encryption). The README ones are the urgent subset because
they are the published ones.

### D18. Two deletion candidates

`NOTES-WI337.md` (a working note at the repo root) and
`examples/telemetry_via_hooks.py` (the repo's only example, which requires hooks
and would not run after the reduction). Both git-only. Delete, or move under a
historical marker?

### D19. The canonical workflow is estate-coupled — removing it is not a cleanup

`regista` ships one canonical lifecycle workflow (`canonical_workflow_yaml()`)
that **both dossier and agent-notes register**, so that the two faces share one
implementation rather than drifting. Plan 032 removes "canonical agent-suite
review policy" — but this particular artifact is load-bearing for two private
repositories today.

The published 0.8.0 should not carry a suite-specific canonical workflow. The
question is what happens to dossier and agent-notes: they pin old versions and
keep working, or the workflow moves into one of them, or it is duplicated. **This
is an estate decision, not a deletion.**

### D20. Five test files cannot be classified without a ruling

Out of 185, five resisted disposition. The two worth your attention:

- **`test_cli_conformance.py`** depends on a pinned `agent-suite-conformance`
  package. Plan 032 removes suite coupling — but this is a *test-time* dependency
  on a published wheel, not a runtime one. Is that acceptable in the reduced
  product, or does the CLI conformance kit go too?
- **`test_spec_entity.py`** covers the "spec" entity — storing and signing a
  project's founding `spec.yaml`. Signing goes (D5), but is a generic "attach a
  document to a project" concept worth keeping, or does the entity go with it?

### D21. `test_workflow_compose.py` — the one plausible exception

Plan 032 says to remove workflow inheritance "unless F0 identifies a small
independent subset worth retaining," and warns against keeping machinery because
it has tests. The disposition pass defaulted this to RETIRE per that instruction,
but flagged it as **the one place where the exception reads as plausible rather
than rhetorical**. Composition may be a small, genuinely independent feature.
Worth a look before it goes.
