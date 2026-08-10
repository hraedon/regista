# P0.1 — overlay application record

**Status: COMPLETE, 2026-08-10.** `RECONCILIATION.md` has been applied to the sibling
specifications in place, and WI-283's local-safety hardening has been applied to the owning
documents. This document is the coverage matrix: every correction, resolution and collision in
the overlay maps to the edit that discharges it, so the claim "the overlay is applied" is
checkable rather than asserted.

**Acceptance criterion (`IMPLEMENTATION-PLAN.md` P0.1):** *every internal cross-reference
resolves, and no two documents give conflicting rules for the same field.* Both halves are
enforced by scripts in this directory and both currently pass:

```
$ python3 check-crossrefs.py --repo <regista-checkout> --code-ref 334b995
0 unresolved reference(s) across 18 documents.

$ python3 check-conflicts.py
0 contested value(s) or structural decision-coverage violation(s).
```

Run both before any change to this set. `check-conflicts.py` now checks not only retired tokens but
also local marker adjacency and required decision coverage for each owning document. A banner far
away from a stale declaration is not enough, and deleting the old token without carrying the
replacement decision is also reported. The checks are cheap and are the machine-enforced boundary
against a slow drift back into the state that made this pass necessary.

---

## 1. Method — why markers rather than rewrites

`RECONCILIATION.md` permits either applying the overlay to the siblings **or** marking their
conflicting clauses superseded in place. This pass did both, chosen per clause:

- **Marked in place, with the replacement rule stated inline** wherever the frozen text is
  load-bearing reasoning that a reader benefits from seeing corrected. The marker states the new
  rule in full, so an implementer reading only that section implements the right thing without
  knowing the overlay exists.
- **Rewritten** where the frozen text was simply a value that changed — an enum spelling, a field
  name, a JSON example, a key count. Leaving a wrong value visible next to the right one is how
  the wrong one gets copied.
- **New sections authored** for the three ownerless artifacts, in the documents the overlay
  assigns them to.

Every marker is a blockquote beginning `SUPERSEDED`, `AMENDED`, `CUT`, `WITHDRAWN`, `OBSOLETE`,
`RESOLVED` or `CONFIRMED`, a strikethrough/table marker, or an explicit local historical-snapshot
note. A marker immediately before a declaration or at the start of its section covers the
declaration; a distant banner does not. `check-conflicts.py` depends on that convention.

**Precedence when a marker and prose disagree:** the marker wins. **When a marker and
`RECONCILIATION.md` disagree:** the overlay wins and the marker is a defect — report it, do not
choose (`IMPLEMENTATION-PLAN.md` standing rule 1).

---

## 2. The two bootstrap circularities — resolved into the implemented documents

| Circularity | Was | Now, and where |
|---|---|---|
| **A — external trust domain.** Every v6 event must name a prior key acceptance, but the trust-log genesis and the per-project checkpoint are each the *first* v6 event in their chain | `signing.key_binding_event_hash` was a required string with no bootstrap (`V6-ENVELOPE.md` §1.4); the trust log required a v6 genesis with no predecessor (`TRUST-DOMAIN.md` §5.2) | `V6-ENVELOPE.md` §1.4 — the field is `string \| null`, with a three-row table of the only positions where `null` is legal and what authorises each externally. `TRUST-DOMAIN.md` §5.2 — the genesis exception. `V6-ENVELOPE.md` §8.3 S9 — the parser half. `RESULT-MODEL.md` §10.2 invariant 5 — the verifier half, requiring `trust_root = externally_pinned` |
| **B — first project-local authority.** The first acceptance in a project had nothing to reference, so it signed itself | `TRUST-DOMAIN.md` §5.8 nulled `accepted_by.key_binding_event_hash`, which left the *envelope* field impossible to fill | `TRUST-DOMAIN.md` §5.8 — self-authorisation withdrawn; the checkpoint (or `project_initialized`) is the first anchor, carrying `bootstrap_key_acceptance` in its payload. `CUTOVER-CLASSIFICATION.md` §4.2 and §4.4 rule 7 — the payload and the well-formedness rule. `V6-ENVELOPE.md` §1.4(b) — the referent widened from "`principal_key_accepted`" to "a preceding project key-binding anchor", a closed set of three |

**There is no self-referential event anywhere in the resulting design.** A checkpoint authorises
itself externally or it is not a checkpoint.

## 3. The three ownerless artifacts — assigned and authored

| Artifact | Owner assigned | Section written |
|---|---|---|
| `VerificationResultV6` | `RESULT-MODEL.md` | **§10** (new) — 12 added fields, 11 failure reasons, 4 policy inputs, 10 class invariants, and the boolean-bridge rule that kills `result.accepted`. `V6-ENVELOPE.md` §9.4 and `CUTOVER-CLASSIFICATION.md` §7 demoted to rationale indexes; `TRUST-DOMAIN.md` §8.3 marked as a subset |
| Workflow lifecycle | `V6-ENVELOPE.md` | **§1.9** (new) — entity-id derivation, `regista.workflow-registration/v1`, `regista.workflow-retirement/v1`, the length-framed definition digest, one-registration-per-`(name, version)`, retirement ordering, and bundle-completeness rules. Discharges D-6 |
| Action-delegation credential | `TRUST-DOMAIN.md` | **§5.12** (new) — `regista.action-delegation/v1`, two hash domains, depth 8, no cycles, no scope widening, project-chain ordering for revocation, and the rule that it **never** asserts `principal_kind`. Discharges D-7 and collision 16 |

## 4. The fourteen architecture corrections

| # | Correction | Applied at |
|---|---|---|
| 1 | Key binding is the release gate, not a parallel track | `ARCHITECTURE-0.6.0.md` banner; `IMPLEMENTATION-PLAN.md` Gate 2 |
| 2 | WI-275, not WI-241, is the dominant legacy key problem | `ARCHITECTURE-0.6.0.md` banner; `CUTOVER-CLASSIFICATION.md` §1 snapshot |
| 3 | Projection rebuild cannot reconstruct the legacy epoch | `TRUST-DOMAIN.md` §5.9 marker |
| 4 | The first-event key-binding rule is circular | §2 above |
| 5 | The envelope is 16 keys with a `producer` block | `V6-ENVELOPE.md` §1.1, §1.8, §8.3, §8.4 rule 7 |
| 6 | `workflow: null` semantics and the `NOT NULL` columns | `V6-ENVELOPE.md` §1.6, §9.3 M1; `CUTOVER-CLASSIFICATION.md` §4.4 rule 5 |
| 7 | `global_seq` is not chain order | `V6-ENVELOPE.md` banner note 2; `BUNDLE-V3.md` §3.3 |
| 8 | Co-signing default; publication in scope | `TRUST-DOMAIN.md` §3.4, §4 |
| 9 | Recovery at registrar authority is wrong | `TRUST-DOMAIN.md` §5.6 marker |
| 10 | v4/v5 relabel after cutover | `RESULT-MODEL.md` §10.2 invariants 2–3 |
| 11 | The HMAC disclosure narrows the legacy claim | `RESULT-MODEL.md` §10.2 invariant 7 |
| 12 | Counts are stale and belong to named snapshots | `CUTOVER-CLASSIFICATION.md` §1 marker; `FIELD-MATRIX.md` banner; `REVIEW-VERDICTS.md` §4.5; `TRUST-DOMAIN.md` §4.6 |
| 13 | Host custody is not project authority | `TRUST-DOMAIN.md` §2.1 marker |
| 14 | Stale code citations; the classifier fix already shipped | `ARCHITECTURE-0.6.0.md` banner; verified mechanically by `check-crossrefs.py --repo` |

## 5. The twenty-four collisions

| # | Collision | Discharged at |
|---|---|---|
| 1 | Checkpoint bootstrap | `V6-ENVELOPE.md` §1.4; `CUTOVER-CLASSIFICATION.md` §4.4 rule 7 |
| 2 | First-acceptance bootstrap | `TRUST-DOMAIN.md` §5.8 |
| 3 | Trust-log genesis | `TRUST-DOMAIN.md` §5.2 |
| 4 | Top-level envelope: 15 vs 16 fields | `V6-ENVELOPE.md` §1.1 |
| 5 | Entity registry | `V6-ENVELOPE.md` §1.2; `TRUST-DOMAIN.md` §5.2, §5.3 catalogue |
| 6 | Null workflow vs named transition | `V6-ENVELOPE.md` §1.6; `CUTOVER-CLASSIFICATION.md` §4.4 rule 5 |
| 7 | Checkpoint payload | `CUTOVER-CLASSIFICATION.md` §4.2 union schema |
| 8 | Fingerprint construction | `V6-ENVELOPE.md` §6.1, §10.1 |
| 9 | Event hash in bundles | `BUNDLE-V3.md` §3.3 (version-aware) |
| 10 | Bundle leaf bytes | `BUNDLE-V3.md` §3.3; `V6-ENVELOPE.md` §6.1 |
| 11 | Trust policy ownership | `TRUST-DOMAIN.md` §4.6; `BUNDLE-V3.md` §4.2 |
| 12 | Trust-root propagation block | `BUNDLE-V3.md` §3.2 (`trust_root` replaces `governance`), §4.5 |
| 13 | Verdict states / attribution | `BUNDLE-V3.md` §5.1 (A5 widened, A11, A12) |
| 14 | Checkpoint-bound summary | `BUNDLE-V3.md` §5.2 |
| 15 | Review digest registry | `V6-ENVELOPE.md` §6.1 |
| 16 | Human evidence from a credential | `TRUST-DOMAIN.md` §5.12; `REVIEW-VERDICTS.md` §3.3 |
| 17 | Publication command has no input | `TRUST-DOMAIN.md` §4.4 |
| 18 | Publication rewrite claim | `TRUST-DOMAIN.md` §4.1 |
| 19 | `index.json` self-digest; attestations | `TRUST-DOMAIN.md` §4.3 rules 2–3 |
| 20 | Producer identity has no owner | `V6-ENVELOPE.md` §1.8; `TRUST-DOMAIN.md` §4.3 producer policy |
| 21 | Catalog / bundle signer shape | `TRUST-DOMAIN.md` §4.3 rule 1; `BUNDLE-V3.md` §3.2 |
| 22 | Current head publication | `TRUST-DOMAIN.md` §4.3 rule 4 (`catalog_kind: project_heads`) |
| 23 | Cross-reference paths | Whole set made flat; `check-crossrefs.py` enforces it. Includes `RESULT-MODEL.md` §10.3 (`result.accepted`), `BUNDLE-V3.md` §11 (`§9.5`/`§9.6`), `REVIEW-VERDICTS.md` §2.3 (workflow ownership), `V6-ENVELOPE.md` §10.0 (generator path) |
| 24 | Read-only preflight vs backfill | `V6-ENVELOPE.md` §9.3 M2 (advisory, reconciled), unchanged in force |

## 6. Structural changes to the document set

**Flat and self-contained.** Every `s1-design` and `v6-design` directory prefix is gone, along with every
absolute filesystem path. Three artifacts were brought in so their citations resolve:

| File | What it is |
|---|---|
| `preflight-s1.json`, `preflight-s1.txt` | The **S1-era** measurement (351,371 events, 2026-08-08 19:20). Distinct from `preflight-live.json`, the post-S1 measurement (353,985). Two named snapshots, never one moving number |
| `SOL-DESIGN-REVIEW.md` | Evidence document cited by `AUDIT-REPORT.md` |
| `make_vector-v6-draft.py` | The draft v6 vector generator. **Input to P0.3, not the deliverable** — it predates the producer block |

**New tooling** (both are Gate 0 deliverables in their own right):

| Script | Enforces |
|---|---|
| `check-crossrefs.py` | Every sibling citation, section reference and **code citation** resolves. Code citations are checked against the pinned post-S1 tree with `git show 334b995:<path>`, which is how correction 14 stays discharged rather than decaying |
| `check-conflicts.py` | No retired value or superseded declaration is live outside a local marker; required replacement decisions remain present |

**Pre-overlay snapshot** retained at `~/audit-scratch/0.6.0-specs-pre-overlay-20260809/` so every
edit in this pass is diffable.

---

## 7. What P0.1 deliberately did not do

Named so the next agent does not assume otherwise.

1. **No line-citation re-derivation inside sibling documents.** Citations *into* documents this
   pass edited have drifted by the length of the inserted markers. Cross-document citations are
   therefore **by section** from here on; `check-crossrefs.py` verifies file and section
   existence, not that a line number still points at the sentence it once did. Every edited
   document carries this warning in its banner. Re-deriving ~200 line citations would have been
   mechanical churn with a real chance of silently mis-pointing one.
2. **No conformance vectors.** That is P0.3, and it is explicitly team-owned. §10.2–§10.4 of
   `V6-ENVELOPE.md` are marked obsolete rather than regenerated, with the repository destinations
   named.
3. **No version control.** This set is a directory, not a repository. For a specification set
   described as FROZEN, that is a real gap: there is no signed history of the freeze and no way
   to prove which bytes the team implemented against. **Recommend landing the set in the regista
   repository** (alongside P0.3's `tools/` and `tests/vectors/`) before implementation begins.
   Raised, not actioned — it is the owner's call where these live.
4. **No re-litigation of the overlay's decisions.** Where `RECONCILIATION.md` chose, this pass
   recorded the choice and its reason. Two places where the overlay's own text needed a judgement
   call are noted below.

## 8. Judgement calls made during application

Recorded because they are the places a reviewer should look hardest.

1. **`ARCHITECTURE-FINAL.md` §3 decision 1 (WI-280) contradicts `TRUST-DOMAIN.md` §3.3, and the
   overlay's body does not mention it.** `RECONCILIATION.md` predates WI-280;
   `ARCHITECTURE-FINAL.md` records it as binding and explicitly says it *corrects*
   `TRUST-DOMAIN.md`. Applied as a supersession of §3.3 consequence 1 and §5.4's
   "threshold must not change" rule, with the reasoning quoted in place. **This is the largest
   single change in this pass and it is not sourced from the overlay's numbered list** — if the
   owner reads WI-280 differently, §3.3 and §5.4 are where to look.
2. **Two preflight snapshots with different counts.** Rather than pick one, both are retained
   under distinct names and every citation says which. This is the overlay's own rule (counts
   belong to a named snapshot) applied to the overlay's own evidence.
3. **`REVIEW-VERDICTS.md` L1 was resolved in the strict direction.** The overlay says to
   simplify `subject_profile` out of 0.6.0; L1 offered that as the stricter-and-simpler
   alternative the author had declined. Applied as written — the profile is cut and staleness is
   total. This makes a diagnostic `comment` stale a verdict, which is friction the gate did not
   previously have. It is honest friction, and it removes an untested cross-version mechanism
   from inside a signed digest.
4. **`TRUST-DOMAIN.md` §7 (witness) was marked CUT rather than deleted**, and its §7.1 correction
   to `spec.md` was explicitly preserved. A false sentence in the repository should be corrected
   whether or not the feature it describes ships.

---

## 9. WI-283 local-safety hardening

The read-everything sweep found that a top banner or a later correction paragraph did not stop an
implementer from copying an earlier live-looking schema. The remediation is deliberately local:

| Owning document | Local safety boundary |
|---|---|
| `ARCHITECTURE-0.6.0.md` | Rank-5 historical sections carry local supersession/cut markers; the bundle scope example, review payload, witness lifecycle, recovery authority, rehearsal counts and 17-item non-claim list are explicitly qualified. |
| `ARCHITECTURE-FINAL.md` | The binding decisions use the monotone governance, prior-observation publication, root-threshold recovery and producer-assertion rules, with the complete non-claim set. |
| `BUNDLE-V3.md` | The statement schema is locally qualified for illustrative counts, closed sections, direct root signatures and the cut scope kind. |
| `CUTOVER-CLASSIFICATION.md` / `CUTOVER-POLICY.md` | S1-era counts and compatibility watermarks are identified as historical or administrative; signed chain position owns cutover classification. |
| `RESULT-MODEL.md` / `REVIEW-VERDICTS.md` | v6 result ownership, chain-position legacy bounds, reducer v1, and the removal of `subject_profile` are stated at the declarations they govern. |
| `TRUST-DOMAIN.md` | Governance derivation, fresh-clone limits, witness scope, recovery authority, bootstrap nulls and handoffs are locally stated; §7 is future-only. |
| `IMPLEMENTATION-PLAN.md` / `OPERATOR-FORGERY.md` | Scheduling, hard gates, witness scope, recovery resolution, prior-observation limits and the five added non-claims agree with the owning contracts. |

The checker is intentionally inventory-backed rather than a prose-quality heuristic. Its
structural guards fail when one of these declarations reappears without a local marker, while its
decision-coverage inventory fails when a future edit deletes the stale token and also deletes the
replacement rule.
