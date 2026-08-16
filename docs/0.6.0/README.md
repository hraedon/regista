# regista 0.6.0 — start here

This directory is the frozen specification set for the 0.6.0 cryptographic-epoch cutover, plus
the evidence it was derived from and the tooling that keeps it honest. It is the set the
implementation is written against.

**Read in this order:**

0. **`EPOCH-RESET.md`** — owner decision, 2026-08-10. The legacy event population is discarded
   rather than migrated; the evidentiary record starts at a deliberate genesis in an empty
   store, gated on a conformance check. It has precedence over everything below for the two
   questions it decides, and it removes work from P0.3, P1.3, P3.3, P4.1 and P5.1. Read it
   first or you will implement a seam that will not exist.
1. **`ARCHITECTURE-FINAL.md`** — precedence, the binding decisions, scope, gates. Short by design.
2. **`IMPLEMENTATION-PLAN.md`** — the work packages, their owners, their dependencies, and how
   each one is proved done. **A package whose acceptance criterion is "implemented" is not
   accepted.**
3. **`RECONCILIATION.md`** — the overlay. It governs everywhere. It has already been applied to
   the sibling documents (see `OVERLAY-APPLICATION.md`), so you should not normally need to hold
   it in your head — but when a marker and a document disagree, this is the tiebreaker.

Everything else is either a detailed contract (rank 3–4 in `ARCHITECTURE-FINAL.md` §1) or
evidence. `ARCHITECTURE-0.6.0.md` is **rank 5, superseded in 14 places, retained for reasoning**
— do not implement from it.

---

## Gate status

| Gate | Package | State |
|---|---|---|
| 0 | **P0.1** apply the reconciliation overlay | **DONE** 2026-08-10 — record in `OVERLAY-APPLICATION.md` |
| 0 | **P0.2** prove reducer v1 determinism | **DONE 2026-08-09, PASS** — record in `P0.2-REDUCER-DETERMINISM.md`. **Signed review verdicts are GO** |
| 0 | **P0.3** byte-level conformance vectors | **DONE 2026-08-09** — 27 vector cases across 16 categories. Generator at `tools/make_v6_vectors.py`, vectors in `tests/vectors/v6/`, conformance test `tests/test_v6_vectors.py` (87 assertions). Review-subject vectors agree with `reducer_v1_frozen_digests.json`. Fail-then-pass evidence recorded. **Corrected after review 2026-08-09** — see below. |
| 1–4 | everything else | Gate 0 is complete; parallel tracks may begin. |

---

## If you are picking up P0.3

Read `V6-ENVELOPE.md` §10.0 first; it names the destinations and says which parts of the existing
worked example are obsolete.

| Artifact | Destination |
|---|---|
| Generator | `tools/make_v6_vectors.py` |
| Vectors | `tests/vectors/v6/` — one JSON file per case, plus a manifest with each expected digest |
| Test | `tests/test_v6_vectors.py` — regenerates from a clean checkout and compares |

`docs/0.6.0/make_vector-v6-draft.py` is **input, not the deliverable**: it predates the producer
block and generates a 15-key envelope.

**Two things P0.2 changed that P0.3 must respect:**

1. **`V6-ENVELOPE.md` §2.5 was amended.** The number rule is now magnitude-based and covers
   floats: `|v| < 2**53` for every number in `payload` and `actor.metadata`. Generate vectors
   against the amended rule, and include the negative cases — a float in `[2**53, 1e21)`
   canonicalises to an integer literal that can never be canonicalised again.
2. **Reducer v1 already has frozen digests** (`tests/reducer_v1_frozen_digests.json`). The review
   subject vectors P0.3 owes must agree with them, not re-derive them.

Acceptance is unchanged from the plan: each vector reproducible from a clean checkout by one
documented command, and a deliberate one-byte change to each input flips its expected hash.

**Corrections applied after review (2026-08-09).** The first cut of the vectors diverged from the
spec in four places and under-covered in two; all six are closed, and the frozen bytes changed:

1. **`review-subject`** froze a four-member subject with a `work_item_id` field that no document
   defines. The members are those of `REVIEW-VERDICTS.md` §2.3 less `subject_profile`, which
   `RECONCILIATION.md`:421 cuts — seven, keyed on `entity_kind`/`entity_id`. The artifact lists
   are now declared out of order so the §424 sort is actually pinned.
2. **`bundle-merkle-empty`** froze `null`; `BUNDLE-V3.md`:214 defines `MTH({}) = SHA256()`.
3. **The mixed-epoch tree** required by `BUNDLE-V3.md`:236 ("do not implement this section
   without them") was absent. Added, with a test that the hardcoded-legacy-formula mistake
   correction 1 warns about produces a different root.
4. **`key_id`** was derived as `sha256(pubkey)[:16]`, disagreeing with the value
   `V6-ENVELOPE.md` §10.1 declares for the same seed. Production key ids are random
   (`_principal_keys.py:49-50`), so nothing derives it: it is now the spec's fixture, pinned.
5. **The §2.5 negative cases** this section asks for above were missing — added as
   `payload-numeric-bounds`, which *measures* rather than asserts which values the canonicalizer
   rejects and which only a strict parser can.
6. **`occurred_at`** had no vector, so DD-4's single lexical form and P0.2's `24:00` divergence
   were unpinned. Added as `occurred-at-lexical-form`.

Two coverage notes, not defects: the canonical-order case now uses payload keys that
**distinguish UTF-16BE ordering from code-point ordering** (the sixteen ASCII top-level keys
cannot); and `§10.5`'s negative vectors remain P1.1's mutation matrix, not P0.3's.

---

## The two checks that keep this set frozen

Run both after **any** edit in this directory. They are the machine-checkable half of P0.1's
acceptance criterion, and CI runs them on every push.

```bash
python3 docs/0.6.0/check-crossrefs.py     # every reference resolves, including code citations
python3 docs/0.6.0/check-conflicts.py     # no retired value stated as a live rule
```

`check-crossrefs.py` verifies `file:line` code citations against the **pinned post-S1 tree**
(`334b995`) using `git show`, not against your working tree. That is what stops the fourteenth
architecture correction ("five stale code citations") from quietly coming back.

`check-conflicts.py` knows the inventory of values the overlay retired — the cut scope kind, the
renamed legacy-policy toggle, the retired governance spellings, the withdrawn hash domains; see
`CONTESTED` in the script for the exact list. A retired value may appear **only** inside a marker
(a `>` blockquote, a strikethrough, or a line that says why it is retired). If you are adding a
superseded note, write it as a blockquote and the checker will accept it.

---

## Standing rules for every package

From `IMPLEMENTATION-PLAN.md`, repeated because they are the ones people breach:

1. **`RECONCILIATION.md` governs.** If a sibling conflicts with it, the sibling is wrong. Do not
   silently choose — if the overlay does not resolve it, escalate.
2. **Read post-S1 code** via `git show 334b995:<path>`. Architecture line numbers are stale, and
   the shared `rc-build` checkout is on `release/0.5.6`, which is **pre-S1**.
3. **Never run a writing git command in the shared `rc-build/regista` checkout.** Use your own
   worktree. This has caused one incident.
4. **Own database per agent** (`REGISTA_TEST_DSN`), never the shared `regista_test`.
5. **Never dump a credential store.** Inspect by explicit allowlist of non-secret fields
   (`key_id`, `principal_id`, `scheme`, `status`, `role`). This caused WI-278.
6. **Fail-then-pass evidence is mandatory.** Every test must be shown failing against unfixed
   code, with the observed output quoted. A test that cannot fail is not a test.
7. **Never weaken an assertion to make a build pass.** If an existing test encodes the old
   behaviour, change it deliberately and say so in the PR.
8. **Counts are measured, never hardcoded.** They belong to a named snapshot — `preflight-s1.json`
   (351,371 events, S1-era) or `preflight-live.json` (353,985, post-S1). Cite which.
9. **Cross-lineage review before merge.** Same-lineage review is not a second opinion.

---

## Work items P0.2 raised, not yet filed

Both are real, neither blocks P0.3:

1. **Replay still fail-softs the timestamp divergence.** `_replay._parse_not_before` and
   `_in_memory_replay._try_fromisoformat` catch the `ValueError` and substitute `None`, so
   `"2026-08-09T24:00:00Z"` reduces differently on CPython 3.14 than on 3.12/3.13/PyPy. Reducer
   v1 fixes this for digests, and **now deliberately disagrees with replay**. That is the right
   split — a projection rebuild should be forgiving, a signed digest must not be — but anything
   that later assumes the two agree is wrong, and the divergence should be tracked rather than
   discovered.
2. **The reducer's field set is decided but the accept-flow rule it protects is untested.**
   Claim state is excluded from the digest (see `_reducer.reduced_field_names`), specifically so
   an accepter claiming an item does not stale the pass it is accepting. `REVIEW-VERDICTS.md`
   §2.5's accept rule has no test yet, because P3.2 has not implemented it.

---

## Where the rest of the artifacts live

| Thing | Path |
|---|---|
| Reducer v1 | `src/regista/_reducer.py` |
| Its conformance vectors and frozen digests | `tests/reducer_v1_vectors.py`, `tests/reducer_v1_frozen_digests.json` |
| Its test | `tests/test_reducer_v1_determinism.py` |
| Cross-interpreter sweep | `tools/reducer_v1_sweep.py` |
| Pre-overlay snapshot of this set | `~/audit-scratch/0.6.0-specs-pre-overlay-20260809/` on mvmcc03 (not in the repo — it exists so the overlay pass is diffable) |
