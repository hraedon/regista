# REVIEW-VERDICTS — frozen contract for signed review verdicts and computed assurance in regista 0.6.0

Status: **FROZEN for Stage 0**. Contracts only. No production source changed.
Owner of this document: review-verdict event schema + how assurance is computed from it (audit item S8; WI-269's sibling items WI-250, WI-211, WI-263; owner decision Q3 in WI-272).
Verified against post-S1 code at `334b995` (`origin/main`). Line citations are against that tree.

Companion document: `BUNDLE-V3.md` (same author, same freeze). Verdict events travel in `sections.review_verdicts` and in `sections.events`; the bundle document owns their transport, this one owns their meaning.

---

## 0. Interfaces I consume

| From | Artifact | What I require |
|---|---|---|
| Sibling A | v6 envelope schema (Stage 0 item 2) | (A1) `payload` remains **inside** the signed envelope. It is today at both v4 (`src/regista/_signing.py:132`) and v5 (`:186`); the entire design rests on it. (A2) `actor_kind` and `actor_metadata` remain inside the signed scope, as v5 introduced (`:176-177`). (A3) `project_instance_id` inside the envelope (S9), so a verdict cannot be replayed into another project. (A4) A frozen `event_hash` definition, since verdicts reference events by hash. |
| Sibling B | trust-domain / key lifecycle / delegation credentials (Stage 0 item 5) | (B1) A root/registrar-authorised signed `principal_registered` event establishes the principal's kind. This is the only mechanism by which 0.6.0 can distinguish an evidenced human reviewer from an actor that merely asserted `actor_kind="human"`. An action-delegation credential authorises an action under scope; it never establishes human kind. §5.3 depends on the registration evidence and remains fail-closed without it. (B2) Signed workflow-registration events, so the workflow definition digest that participates in the subject digest (§2.3) is itself authenticated rather than read from `workflow_registry.definition` (S6). |
| Sibling D | preflight (Stage 0 item 7) | (D1) A per-project count of work items whose history contains review transitions **without** a verdict payload. This is the size of the `LEGACY_UNVERDICTED` population (§4.5) and the owner needs the number before Stage 3 starts. |
| Me → siblings | | The verdict payload is an ordinary event payload. It needs no envelope change beyond A1–A3. `BUNDLE-V3.md` §3.6 already carries it. |

---

## OVERLAY APPLIED — 2026-08-09 (P0.1)

`RECONCILIATION.md` governs this document; each superseded clause carries a **SUPERSEDED**
marker where it sits.

| Clause | Superseded by | Replacement |
|---|---|---|
| §0 (B1), §3.3, §5.3 — a delegation credential asserts `principal_kind: "human"` | Resolution 2, collision 16 | Human kind comes from a root/registrar-authorised `principal_registered` event; the action credential never asserts it |
| §0 (B2), §2.3 §193 — workflow registration "owned by sibling B" | Resolution 2 | `V6-ENVELOPE.md` §1.9 owns the workflow lifecycle |
| §2.2/§2.3 — `subject_profile` | Resolution 4 | Cut. `content_state_digest` is over the **complete** reduced signed prefix under **reducer v1** |
| §4.1 rule 1 — `result.accepted` | collision 23 | `RESULT-MODEL.md` §10.3 — `acceptable_under(named_policy)`; `result.accepted` does not exist |
| §4.2 — acceptance values | Resolution 4 | Adds `accepted_by_credentialed_human` to the acceptance axis |
| §4.5 — estate event count | overlay change 12 | Counts belong to a **named snapshot**: `preflight-s1.json` (351,371) or `preflight-live.json` (353,985) |
| §8 L2 — "is `reduce()` deterministic enough to digest?" | **P0.2** | §8 L2 — answered by the Gate 0 conformance proof; this document does not ship signed verdicts unless it passed |
| §2.2 — reviewer claims duplicating lineage | collision 20 | The `producer` block (`V6-ENVELOPE.md` §1.8) is the source; `reviewer_claims` restates it and must reconcile, or omits the duplicates entirely |

**Scheduling note:** P0.2 passed, so signed review verdicts (P3.2) are **GO for 0.6.0**.
**WI-250 must be rewritten before implementation** —
its headline claim is stale (§3.1); the live defect is the `reviewer_is_agent and agent_author`
gating, which lets a human reviewer with no delegation skip the check entirely.

---

## 1. What is broken, verified against post-S1 code

### 1.1 Assurance is computed from bare transition strings

`compute_assurance_level` finds the deciding review by string comparison:

```python
for i, e in enumerate(events):
    if getattr(e, "transition", None) == "adversarial_pass":     # _assurance.py:240
        last_pass_idx = i
```

and acceptance the same way (`src/regista/_assurance.py:259`). Nothing checks that the event was produced by a review validator, that a validator ran at all, or that the signature verifies.

**The forgery path is `append_event`.** `append_event` (`src/regista/_events.py:140-157`) takes `transition: str | None` and runs no review validator — validators are dispatched only through the workflow transition path, from a registry built at `src/regista/__init__.py:235-237`. So on any workflow that does not define `adversarial_pass`/`accept` as gated transitions, a caller writes a properly signed event carrying the string `"adversarial_pass"` and `compute_assurance_level` counts it. The signature is real; the review never happened. S8 confirmed against `334b995`.

### 1.2 The review is not bound to what it reviewed

There is no reference anywhere in `_assurance.py` or `_review_validators.py` to item content, a content hash, or an event hash. `_require_review_note` (`src/regista/_review_validators.py:235-241`) checks only that `payload.review_note` is a non-empty string. So the audit's scenario holds exactly as written: cross-lineage pass → author rewrites the item → self-accept → `done` reporting `INDEPENDENTLY_REVIEWED` under the strict profile. The pass survives content mutation because it was never attached to content.

### 1.3 Assurance is not monotone in the author set

This is the subtlest of the four and worth spelling out, because the fix follows directly from the mechanism.

`compute_assurance_level` derives the author set over the **entire** event sequence:

```python
author_lineages, agent_author_undeclared = _author_lineage_state(events)   # _assurance.py:236
```

but restricts acceptance to events **after** the deciding pass:

```python
accept_events = [e for i, e in enumerate(events)
                 if getattr(e, "transition", None) == "accept" and i > last_pass_idx]   # :257-260
```

That asymmetry is the bug. Concrete upgrade-by-appending, all steps legal:

1. Item authored by a human only. `derive_authors` collects no `model_lineage` ⇒ `author_lineages == set()`.
2. A reviewer records `adversarial_pass` declaring `model_lineage: "kimi"`. `lineage_relation(set(), "kimi")` returns `UNKNOWN` — the "no author lineages to compare against" branch (`src/regista/_assurance.py:60-61`). `is_same = relation != DISTINCT` (`:255`) is therefore `True`.
3. A human accepts ⇒ `HUMAN_ACCEPTED`.
4. Someone appends **one ordinary agent-authored event** declaring `model_lineage: "glm"`. Now `author_lineages == {"glm"}`, `lineage_relation({"glm"}, "kimi")` returns `DISTINCT`, `is_same` becomes `False`, and the same history reports **`INDEPENDENT_AND_ACCEPTED`**.

The item was *upgraded* by adding work after the review. Nothing was tampered with; the function simply asks a question about the present author set using a review that happened in the past.

### 1.4 `lineage_verification` reports a scheme property (WI-263)

```python
return "verified" if get_scheme(scheme_id).is_asymmetric else "asserted"   # _assurance.py:217
```

Emitted into the gate rationale at `src/regista/_assurance.py:335`, `:368` and `:392`. A synthetic event carrying only `scheme_id="ed25519"` is labelled `"verified"` — no signature check, no principal binding, no key status, no validity window. The 0.5.6 CHANGELOG was rewritten to describe it precisely (`5deaf46`), which discharged the blocking finding, but the API surface still reads misleadingly. WI-263 confirmed against `334b995`.

---

## 2. The signed verdict

### 2.1 Where it lives

The verdict is the `payload` of the review event. `payload` is inside the canonical signed envelope at v4 (`src/regista/_signing.py:132`) and v5 (`:186`), and `payload_canonical_hash` is a signed field. So a verdict written into the payload is signed by construction, needs no envelope change, and — post-S1 — is reconciled against the row by `verify_event_strict` before any consumer reads it (`src/regista/_verification.py:956`, `_bundle.py:832-836`).

This is the cheapest possible mechanism for the strongest available property, and it is available *because* S1 landed. Pre-S1 this design would have been theatre: the payload column was rewritable under an intact envelope.

### 2.2 Schema `regista.review-verdict/v1`

Building on `ARCHITECTURE-0.6.0.md:558-599`. Additions and changes marked **[+]** / **[Δ]**; see §7 DIVERGENCES.

```json
{
  "type": "regista.review-verdict",
  "version": 1,
  "verdict_id": "uuid",
  "decision": "pass | request_changes | reject | accept",

  "review_subject": {
    "project_instance_id": "uuid",
    "entity_kind": "work_item",
    "entity_id": "uuid",
    "reviewed_through_event_hash": "sha256:...",
    "content_state_digest": "sha256:...",            // [Δ] §2.3
    "artifacts": [
      { "media_type": "application/vnd.git.commit",
        "locator": "regista",
        "digest": "sha256:..." }
    ],
    "declared_not_reviewed": [                       // [+] §2.4
      { "media_type": "...", "locator": "...", "reason": "..." }
    ],
    "subject_digest": "sha256:..."                   // §2.3, over everything above
  },

  "author_snapshot": {
    "as_of_event_hash": "sha256:...",                // [+] MUST equal reviewed_through_event_hash
    "principal_ids": ["..."],
    "lineages": ["..."],
    "has_undeclared_agent_author": false,
    "digest": "sha256:..."
  },

  "reviewer_claims": {
    "model_lineage": "openai/gpt-5.6",
    "harness": "opencode",
    "harness_version": "...",
    "same_lineage_acknowledged": false,
    "claim_evidence": "self_asserted"                // [+] §5.3: lineage is a signed assertion; kind comes from registration
  },

  "decided": {                                       // [Δ] renamed from computed_relation
    "lineage_relation": "distinct | same | unknown",
    "effective_lineage_relation": "distinct | same | unknown",
    "acknowledgment_required": true,
    "acknowledgment_present": false,
    "separation_of_duties_ok": true
  },

  "supersedes": {                                    // [+] accept/request_changes only
    "verdict_id": "uuid",
    "verdict_event_hash": "sha256:..."
  },

  "policy": {
    "gate_profile": "strict | relaxed",
    "validator_version": 1,
    "lineage_decision_version": 1                    // [+] §3
  },

  "review_note": "..."
}
```

**The verifier recomputes every field under `decided` and `author_snapshot` and reconciles.** Payload values are evidence to compare against, never trusted answers (`ARCHITECTURE-0.6.0.md:601`). A verdict whose `decided.effective_lineage_relation` disagrees with recomputation is `invalid` and contributes nothing — it is not "downgraded to the recomputed value", because a gate that reported the wrong answer is a gate whose other outputs are also untrustworthy.

### 2.3 The content binding — `subject_digest`

This is the part that closes the audit's headline S8 scenario, so it is specified to the byte.

**`content_state_digest`** is computed from the **signed event prefix**, not from a projection row:

```text
content_state_digest = SHA256(
    b"regista.review-subject.state.v1\x00" ‖ JCS( reduce_v1(E[0..k]) )
)
```

where `E[0..k]` is the item's event chain up to and including the event named by
`reviewed_through_event_hash`, and `reduce_v1` emits the complete content-only reduced state. Its
field set excludes lease state and `last_entity_seq`: an excluded claim, heartbeat, expiry or
intrinsic event must not change the digest indirectly through a positional counter.

Why the *reduced prefix* and not a projection-table digest: `work_items` rows are mutable side state, and S6's whole finding is that unsigned side tables must not be verification oracles. A digest over the reduced signed prefix is recomputable by an offline auditor holding only the bundle, with no database access. That property is non-negotiable — a subject binding a bundle verifier cannot check is not a binding.

**`subject_digest`** is then:

```text
subject_digest = SHA256(
    b"regista.review-subject.v1\x00" ‖ JCS({
        project_instance_id, entity_kind, entity_id,
        reviewed_through_event_hash, content_state_digest,
        artifacts, declared_not_reviewed
    })
)
```

with `artifacts` sorted by `(media_type, locator, digest)` and `declared_not_reviewed` sorted by
`(media_type, locator, reason)` before canonicalization, so two gates reviewing the same thing
produce the same digest.

**Staleness is automatic and needs no flag.** At the current head, recompute only
`content_state_digest` and compare it with the verdict's frozen value. A content-changing event
changes the digest and stales the verdict. Claim and intrinsic events leave it unchanged. The
reviewed prefix remains immutable: `reviewed_through_event_hash` says exactly what the reviewer
saw and is never advanced merely because a later non-content event exists.

> **CUT — `RECONCILIATION.md` Resolution 4.** `subject_profile` is deliberately absent. Reducer
> v1 covers one complete content field set, so there is no profile to narrow after the fact.
> `reducer_version` is inside the reduced object and therefore inside `content_state_digest`.

The workflow-registration event is owned by `V6-ENVELOPE.md` §1.9. Reducer v1 is a pure function
of the signed prefix plus the signed registrations it references. The pass / request-changes /
reject / accept supersession state machine is frozen before its reducer is coded, and competing
successors are invalid.

### 2.4 Saying what was *not* reviewed

`ARCHITECTURE-0.6.0.md:617-618` requires the signed verdict to "say exactly what was and was not reviewed" but gives no field. `declared_not_reviewed` is that field.

Regista cannot infer a repository commit by itself. The gate client supplies `artifacts`. The failure mode this guards is not a lie but an *omission*: a reviewer who read the work item and none of the code produces a verdict indistinguishable from one who read both. Requiring the exclusion to be stated makes the omission visible in the signed record, and makes "the reviewer declared no artifacts at all" a fact an auditor can query rather than an absence they must notice.

An empty `artifacts` list with an empty `declared_not_reviewed` list is **rejected at ingress**. The gate must state one or the other.

### 2.5 `accept` verdicts

Per `ARCHITECTURE-0.6.0.md:603-608`, an `accept` verdict MUST reference:

- the exact pass verdict id and event hash (`supersedes`);
- the same `subject_digest`;
- the same `reviewed_through_event_hash` and complete seven-member review subject as the pass;
- a recomputation proving the current head's `content_state_digest` still equals the pass's frozen
  value; later claim or intrinsic events are permitted because they do not alter content;
- a different effective reviewer principal where policy requires it — which the existing two-stage independence check already enforces (`src/regista/_review_validators.py:399-414`) and which is retained unchanged.

A `subject_digest` mismatch between the pass and the accept is exactly the audit's rewrite-then-self-accept scenario, and it now fails closed at the accept, before `done` is reachable.

---

## 3. One lineage implementation (WI-250)

### 3.1 What WI-250 said, and what is actually true post-S1

WI-250's headline is *"`adversarial_review` ... never uses `LineageRelation`"*. **That leg is now stale.** `adversarial_review` imports and uses it:

```python
from ._assurance import LineageRelation, review_lineage_relation      # _review_validators.py:261
...
reviewer_relation = review_lineage_relation(author_lineages, ctx)     # :289
distinct = reviewer_relation is LineageRelation.DISTINCT              # :290
```

WI-258 and WI-262 closed that. WI-250 predates both (filed 2026-08-04) and should be updated rather than implemented as written.

**Three defects survive, and one of them is WI-250's actual headline risk.**

**(a) The reviewer-kind gate — the undeclared-lineage human reviewer is still not caught.**

```python
reviewer_is_agent = ctx.actor_kind == "agent" or reviewer_kind_class in (KIND_AGENT, KIND_OPAQUE)  # :276-279
agent_author = "agent" in author_kinds or agent_author_undeclared                                   # :283
if reviewer_is_agent and agent_author and (not distinct or agent_author_undeclared):                # :292-294
```

A reviewer with `actor_kind="human"` and no `on_behalf_of` gives `reviewer_kind_class = KIND_ABSENT` (`:94-98`) ⇒ `reviewer_is_agent = False` ⇒ **the entire acknowledgment check is skipped**, whatever the author set. WI-250's exact scenario, still live at `334b995`.

It is partially mitigated downstream — `review_lineage_relation` returns `UNKNOWN` for such a reviewer (a human proxy declaring nothing contributes no claim, `src/regista/_assurance.py:141-144`), so assurance reads `SELF_REVIEWED` and the strict human gate escalates (`src/regista/_review_validators.py:380-382`). So the *severity* is lower than when WI-250 was filed. But the validator that exists to catch it does not catch it, and an agent presenting as `actor_kind="human"` — a free-form self-claim — passes the gate with no acknowledgment recorded anywhere.

**(b) Two spellings of one semantic.** `adversarial_review` folds the undeclared-author flag as a separate disjunct at `:292-294`. Every other consumer folds it through `effective_lineage_relation` (`src/regista/_assurance.py:182-198`): `compute_assurance_level` at `:252-254`, `gate_rationale` at `:346-348`, `human_gate` at `src/regista/_review_validators.py:372-379`. They agree in effect today. They are separately maintained, and separately-maintained copies of one security semantic drifting apart is *literally what WI-257 was*.

**(c) A fourth partial re-derivation.** `_adversarial_pass_identities` (`src/regista/_review_validators.py:244-257`) re-walks events collecting `actor_id` + `on_behalf_of.principal_id`, duplicating a subset of `derive_authors` (`:155-203`) with different rules.

### 3.2 The fix: decide once, sign the decision, reconcile forever after

```python
@dataclass(frozen=True)
class LineageDecision:
    author_principal_ids: frozenset[str]
    author_lineages: frozenset[str]
    has_undeclared_agent_author: bool
    reviewer_lineage: str | None
    reviewer_evidence: ReviewerEvidence          # §5.3
    relation: LineageRelation
    effective_relation: LineageRelation
    acknowledgment_required: bool
    separation_of_duties_ok: bool
    version: int = 1
```

```python
def decide_lineage(prior_events, ctx, *, as_of_event_hash) -> LineageDecision
```

- **Exactly one implementation.** `adversarial_review`, `human_gate`, `compute_assurance_level` and `gate_rationale` all call it. `effective_lineage_relation` stops being a public composition step callers may forget; it is inlined into `decide_lineage`.
- **`_adversarial_pass_identities` is deleted**; two-stage independence reads `author_principal_ids` from decisions on prior verdicts.
- **`prior_events` is the prefix up to `as_of_event_hash`**, never the whole sequence. This is where §4's monotonicity rule enters the type system rather than living in a comment.
- **The gate writes the decision into the payload** (`decided` + `author_snapshot`, §2.2). It no longer decides-then-discards. Every later consumer reads the signed decision and reconciles by recomputing. Because the decision is *data*, there is structurally only one implementation of it in the record, even if a future refactor accidentally grows a second code path — the reconciliation catches the disagreement.

That last point is the real answer to WI-250. "One implementation consumed everywhere" enforced by code review decays. Enforced by a signed field that everyone must agree with, it does not.

### 3.3 Reviewer kind must not gate the lineage semantics

The trigger changes from `reviewer_is_agent and agent_author and (...)` to:

```text
acknowledgment_required  ⟺  agent_author  ∧  effective_relation ≠ DISTINCT
                            ∧  ¬ reviewer_evidenced_non_model
```

`reviewer_evidenced_non_model` is true **only** when the effective reviewer principal has an
authenticated human registration.

> **SUPERSEDED — `RECONCILIATION.md` collision 16 and Resolution 2.** The source of
> `principal_kind` is a **root/registrar-authorised `principal_registered` event**
> (`TRUST-DOMAIN.md` §5.3), **not** a delegation credential. An action credential
> (`regista.action-delegation/v1`, `TRUST-DOMAIN.md` §5.12) has no `principal_kind` field and
> never manufactures human identity — it proves *authorisation*, not *who someone is*. So
> `accepted_by_credentialed_human` means "the accepting principal has an authenticated human
> registration", never "a delegation document said human".
>
> This makes the interim below **shorter, not longer**: human evidence arrives with principal
> registration in Gate 1, ahead of any delegation work.

The frozen text said "a trust-root-issued delegation credential asserts `principal_kind:
"human"` for the effective reviewer principal (B1)"; read it as principal registration. A bare `actor_kind="human"` is a self-claim and does not satisfy it — which is the same rule the gate already applies to `principal_kind` on the author side, where WI-262 found that treating any non-`"human"` declaration as a negative answer "cost a fail-open on unvalidated, attacker-controlled metadata" (`src/regista/_review_validators.py:130-136`). `actor_kind` is signed at v5, which proves the actor *asserted* it, not that it is true.

**Interim, if delegation credentials are not ready when Stage 3 lands:** `reviewer_evidenced_non_model` is permanently `false` and every genuine human reviewer of agent-authored work must record `same_lineage_acknowledged`. That is friction, and it is honest friction: a human reviewer is not a cross-lineage *model* reviewer, and the item genuinely is not independently reviewed in the sense the level claims. Fail closed. Do not ship the reviewer-kind gate as a stopgap — it is the defect.

---

## 4. Assurance computation

### 4.1 Only signed verdicts count

```python
def compute_assurance(
    verified: Sequence[tuple[Event, VerificationResult]],
) -> AssuranceReport
```

**The signature change is part of the contract.** `compute_assurance_level(events)` (`src/regista/_assurance.py:235`) cannot express "this event's signature verifies", so it must take verification results alongside events. Every caller changes. This is the same discipline the architecture states for all consumers: "Every consumer must accept only `VerificationResult`, not a boolean" (`ARCHITECTURE-0.6.0.md:753`).

Counting rules, in order:

1. An event contributes **nothing** unless it is acceptable under the named policy —
   `acceptable_under(named_policy)`, with the policy named in the report.

   > **CORRECTED — `RECONCILIATION.md` collision 23.** `result.accepted` **does not exist** in
   > the result model (`RESULT-MODEL.md` §10.3). The only boolean bridge is
   > `result.ok == (applicability is FULLY_AUTHENTICATED)`; everything else goes through
   > `acceptable_under(...)`. Citing a non-existent attribute in a counting rule is exactly how a
   > consumer ends up inventing its own predicate.
2. An event contributes **nothing** unless its payload parses as `regista.review-verdict/v1` under a strict parser. **A review event carrying no verdict is not a review.** It is not a downgrade signal, not a warning, not a weaker pass — it is invisible to the reducer.
3. Transition names are **not consulted at all**. The `_REVIEW_VERDICTS` frozenset (`src/regista/_review_validators.py:6`) survives only as an ingress-side hint for which transitions must carry a verdict; the reducer keys on `payload.type` and `payload.decision`. This kills the `append_event` forgery in §1.1 outright: a forged `"adversarial_pass"` string with no verdict payload contributes nothing, and a forged verdict payload has to survive recomputation of `author_snapshot`, `decided` and `subject_digest`.
4. A verdict whose recomputed `decided` or `author_snapshot` disagrees with the payload is `invalid` and contributes nothing (§2.2).
5. A verdict whose frozen `content_state_digest` does not equal the content digest recomputed at
   the item's current head is **stale** and contributes nothing to the *current* level. The full
   `subject_digest` is not recomputed with a new `reviewed_through_event_hash`; that hash records
   the immutable prefix the reviewer actually saw. The verdict remains in history and is reported
   as stale.

### 4.2 The level is two orthogonal fields, not one enum

Same reasoning as `BUNDLE-V3.md` §5.1: a single value asked to carry two independent claims will lie about one of them. `AssuranceLevel` currently carries both the review dimension and the acceptance dimension in five flat values (`src/regista/_assurance.py:17-22`), and the product is incomplete — there is no value for "reviewed, lineage undetermined, human accepted" distinct from "reviewed, same lineage, human accepted".

```
review_assurance:  none
                 | lineage_undetermined
                 | same_lineage_asserted
                 | cross_lineage_asserted
                 | legacy_unverdicted            // §4.5

acceptance:        none
                 | accepted_by_declared_human
                 | accepted_by_credentialed_human      // Resolution 4 — reachable in 0.6.0
                 | accepted_by_agent
```

> **AMENDED — `RECONCILIATION.md` Resolution 4.** The acceptance axis has **four** values.
> `accepted_by_credentialed_human` is reachable once principal registration supplies human kind
> (§5.3 as corrected), and it is the one value that may drop the `declared_` qualifier because
> the kind is authenticated rather than self-asserted. The review axis is unchanged: `none`,
> `lineage_undetermined`, `same_lineage_asserted`, `cross_lineage_asserted`,
> `legacy_unverdicted`. **"Independent" is not a cryptographic label** in any of them.

plus `AssuranceReport` carrying the deciding `verdict_id`, the `subject_digest`, the frozen `author_snapshot`, and the WI-263 replacement fields (§6).

A derived flat `label` is emitted for display and for `gate_permits_done`, computed from the pair. Nothing else may read the label.

### 4.3 Renaming, under the binding strictness decision

Owner decision Q3 (WI-272, restated at `ARCHITECTURE-0.6.0.md:928-934`) is binding: 0.6.0 claims only **principal-signed model-lineage assertion**. `independently_reviewed` is **policy evidence, not cryptographic proof of independence**. The rule that resolves both this and WI-263: **the name must not promise more than the check performs.**

Applied to every current name:

| Current (`_assurance.py:17-22`) | What the check actually performs | 0.6.0 name | Verdict |
|---|---|---|---|
| `NONE` | no deciding review found | `review_assurance: none` | fine as-is |
| `SELF_REVIEWED` | `relation != DISTINCT` (`:255`, `:349`) — **collapses `SAME` and `UNKNOWN`** | split into `same_lineage_asserted` and `lineage_undetermined` | **split** |
| `INDEPENDENTLY_REVIEWED` | the reviewer *signed a claim* to a model lineage absent from the author set | `cross_lineage_asserted` | **renamed — overclaims** |
| `HUMAN_ACCEPTED` | an actor whose signed `actor_kind` is `"human"` accepted | `acceptance: accepted_by_declared_human` | **renamed — overclaims** |
| `INDEPENDENT_AND_ACCEPTED` | both of the above overclaims, conjoined | `cross_lineage_asserted` + `accepted_by_declared_human` | **renamed — overclaims** |

**`INDEPENDENTLY_REVIEWED` → `cross_lineage_asserted`** is the headline rename and the one the owner's decision compels. "Independently reviewed" promises independence. The check performs: *a principal signed an assertion about its own model lineage, and that assertion differs from assertions other principals signed about theirs.* A principal can sign a truthful claim to be `claude-opus` or an untruthful one and 0.6.0 cannot distinguish them (WI-272 Q3). `_asserted` is the whole point of the name: it says the thing is a claim.

**Splitting `SELF_REVIEWED`** is my addition and it is a genuine finding, not tidiness. `is_same = relation != LineageRelation.DISTINCT` (`src/regista/_assurance.py:255`, and again at `:349`) collapses two states the codebase went to real trouble to separate: WI-239 introduced the three-state `LineageRelation` precisely because "the two-state boolean conflated two very different outcomes: a confirmed cross-lineage reviewer and an *undeclared* one" (`:31-39`). That fix was applied to `LineageRelation` and **never propagated to `AssuranceLevel`**, which re-collapses `SAME` and `UNKNOWN` one layer up. Today an auditor reading `SELF_REVIEWED` cannot tell "the reviewer declared a lineage that collides with an author's" from "nobody declared anything". Those warrant different follow-up actions.

**`HUMAN_ACCEPTED` → `accepted_by_declared_human`** follows the same rule one notch lower. `actor_kind` is signed at v5 (`src/regista/_signing.py:176-177`), so the assertion is authenticated and non-repudiable; it is still an assertion. When B1's delegation credentials land, a third value `accepted_by_credentialed_human` becomes reachable and *that* one may drop the qualifier.

### 4.4 Monotonicity

**Invariant (testable as a property):**

> For any event sequence `E` and any appended event `e`:
> `assurance(E ‖ e) ≤ assurance(E)` — **unless** `e` is a valid signed verdict, which is the only construct that may raise it.
>
> Equivalently: **only a signed verdict raises assurance. Every other appended event can only preserve or lower it.**

Three rules implement it:

**R1 — Freeze the comparison set at the deciding verdict.** `author_snapshot` is derived from the event prefix up to `reviewed_through_event_hash` and **only** that prefix (`decide_lineage(..., as_of_event_hash=...)`, §3.2). Assurance recomputes over the same prefix and reconciles against `author_snapshot.digest`. The §1.3 upgrade path is closed at step 4: the appended agent-authored event is outside the frozen prefix, so `author_lineages` stays empty, `effective_relation` stays `UNKNOWN`, and the level stays `lineage_undetermined`.

**R2 — Post-verdict authorship is a downgrade.** Any event after `reviewed_through_event_hash` that changes the reduced projection changes `content_state_digest`, so the verdict is stale (§4.1 rule 5) and contributes nothing. `review_assurance` falls to whatever surviving verdicts support — usually `none`. There is no "still counts, slightly weaker" state: a review of different content is not a weaker review of this content.

**R3 — Acceptance is scoped to its verdict, not to position.** The current `i > last_pass_idx` index comparison (`src/regista/_assurance.py:257-260`) is replaced by the explicit `supersedes.verdict_id` reference (§2.5). Position in a list is not a security relation.

R1 and R2 pull in opposite directions and that is deliberate: R1 stops appended work from *inflating* the claim, R2 stops appended work from being *silently covered* by a review that predates it. Together they make the function monotone non-increasing under ordinary appends, which is the property the audit found missing.

### 4.5 The legacy corpus — `legacy_unverdicted`

**This is the largest practical consequence of §4.1 and the architecture does not address it.**

There are **351,371 live events at the S1 snapshot** (`preflight-s1.txt`; the later post-S1
snapshot in `preflight-live.json` measures 353,985 — counts belong to a **named snapshot**, never
to a document, `RECONCILIATION.md` overlay change 12) and **zero** of them carry a
`regista.review-verdict/v1` payload, because the schema is being frozen here for the first time. Under rule 2, every existing work item's `review_assurance` becomes `none` on the day Stage 3 lands.

`none` means *"no review happened"*. For items that were reviewed under the 0.5.x gate, that is false — and it is false in the *harmful* direction, because the review-assurance corpus is exactly what regista exists to preserve.

So: `review_assurance: legacy_unverdicted`, meaning **"this item's review history predates the signed-verdict epoch; no assurance is computable from it, and no assurance should be inferred."** It is reported for any item whose history contains a review transition, is entirely before the project's `project_cryptographic_epoch_started` checkpoint, and carries no verdict payload.

Rules:
- `legacy_unverdicted` is **not ordered** against the other values. It is not "between none and same_lineage". It is a statement that the question cannot be answered, and any comparison operator involving it must raise rather than return a boolean.
- `gate_permits_done` treats it exactly as `none`. A legacy item that wants to reach `done` under 0.6.0 gets a fresh verdict. There is no grandfathering — grandfathering would mean trusting the transition-name inference the whole document exists to remove.
- **Do not backfill.** Synthesizing verdicts from 0.5.x history would sign an assertion nobody made, about content nobody re-read. That is the same error as the WI-241 retrospective key attestations, which the architecture already flags as not proving contemporaneous enrollment-before-use (`ARCHITECTURE-0.6.0.md:874`).
- Sibling D's preflight (D1) must report the population size per project before Stage 3 begins. If the number is large in a project that gates on assurance, that is an operational decision for the owner, not something to discover at cutover.

---

## 5. Findings, dispositions and reviewer evidence

### 5.1 WI-211 — dispositions as first-class signed events

`review_finding` and `finding_disposition` become signed payloads on the same entity chain, referencing the verdict:

```json
{ "type": "regista.review-finding", "version": 1,
  "finding_id": "uuid", "verdict_id": "uuid",
  "subject_digest": "sha256:...",
  "severity": "...", "locator": "...", "summary": "..." }
```

```json
{ "type": "regista.finding-disposition", "version": 1,
  "finding_id": "uuid", "verdict_id": "uuid",
  "disposition": "accepted | accepted_modified | rejected_noise | rejected_wrong",
  "rationale": "..." }
```

Binding requirements — the part that makes the per-lineage precision tables WI-211 wants actually mean something:

- A finding MUST carry the `subject_digest` of the verdict it belongs to. A finding whose verdict is stale is itself stale; precision computed over stale findings measures a reviewer against content it did not see.
- A disposition MUST reference a finding that exists in the same entity chain, and MUST be authored by a principal in the verdict's frozen `author_snapshot.principal_ids` or by a human accepter. **Self-disposition by the reviewer who raised the finding does not count** toward precision, for the same separation-of-duties reason the review gate already enforces (`src/regista/_review_validators.py:213-232`).
- Per-lineage precision is computed from `reviewer_claims.model_lineage` — which is an **assertion** (§4.3). Precision tables must be labelled as per-*claimed*-lineage. Same rule, one more place.

WI-211 is not on the 0.6.0 critical path. It is specified here because its binding requirements constrain the verdict schema (`verdict_id` and `subject_digest` must be referenceable), and retrofitting those later would be a schema break.

### 5.2 `ReviewerEvidence`

```
self_asserted            — actor_kind and/or actor_metadata.model_lineage, signed at v5, asserted by the subject
principal_registration   — a root/registrar-authorised `principal_registered` event establishing
                           the effective principal's kind; it does not authenticate lineage
action_delegation        — a scoped authorisation credential; it does not establish principal kind
harness_attestation      — NOT AVAILABLE IN 0.6.0
```

The third value is declared and permanently unreachable in 0.6.0, deliberately. It is the state that would let `cross_lineage_asserted` become `cross_lineage_attested`, and naming it now records what the missing evidence *is* rather than leaving the gap implicit. Owner decision Q3: "The strong claim waits for harness-issued lineage attestation."

### 5.3 What the credential does and does not buy

An authenticated human registration lets the gate treat the effective reviewer as a non-model
principal for the acknowledgment rule (§3.3). An action-delegation credential can establish that
the action was authorised under the configured scope, but it does **not** establish human kind,
lineage, intent or authorship, and it does not upgrade `cross_lineage_asserted`. Per
`ARCHITECTURE-0.6.0.md:878`, authorization evidence and identity evidence are separate claims.

---

## 6. WI-263 — deleting `lineage_verification` without losing the signal

`_lineage_verification` (`src/regista/_assurance.py:201-219`) is deleted, along with its three emission sites (`:335`, `:368`, `:392`). The architecture says to replace it with fields sourced from the common `VerificationResult` (`ARCHITECTURE-0.6.0.md:629-637`); here is the exact mapping, so the replacement is not itself a new set of aspirational names.

| New field | Values | Sourced from | Note |
|---|---|---|---|
| `event_signature_status` | `fully_authenticated` \| `legacy_partial` \| `invalid` \| `unverifiable` | `VerificationResult.applicability` (`src/regista/_verification.py:93-99`) verbatim | the enum already exists and is already honest; do not re-spell it |
| `principal_binding_status` | `verified_external_root` \| `verified_bundled_key` \| `unverified` | `VerificationResult.principal_binding_verified` (`:399`) × `trusted_key_source` (`:396`, `:102-107`) | the root axis matters here for the same reason it does in `BUNDLE-V3.md` §5.1 |
| `lineage_claim_status` | `asserted_signed` \| `asserted_unsigned` \| `absent` | envelope version + presence of `actor_metadata.model_lineage` | **never `verified`** |
| `review_subject_binding_status` | `bound` \| `stale` \| `absent` | §2.3 recomputation | new signal; the one WI-263's field was standing in the way of |

`lineage_claim_status` is worth dwelling on, because it preserves the *useful* thing `_lineage_verification` was groping at while removing the false name. The real distinction is whether the lineage claim rode **inside** the signed envelope: v5 signs `actor_kind` and `actor_metadata` (`src/regista/_signing.py:176-177`), v4 does not (`:119-133`). The preflight measures the split exactly — 332,676 v5 events versus 18,695 v4, with `actor_kind` listed as an unsigned field in play for precisely those 18,695 (`preflight-s1.txt`). So `asserted_signed` vs `asserted_unsigned` is a real, corpus-grounded, decision-relevant distinction — and it is honest, because both values say `asserted`.

What the old field got wrong was not *having* a signal. It was answering a question about signing scheme with a word that names a performed check. `asserted_signed` says exactly what happened: someone asserted a lineage, and the assertion is covered by a signature.

Update `docs/review-assurance.md` in the same change. WI-263 is explicit that code, docstring and doc move together "so the three cannot drift", and the doc currently presents the old level names as the contract (`docs/review-assurance.md`, "Assurance levels" table).

---

## 7. DIVERGENCES

**D1 — `AssuranceLevel` becomes two orthogonal fields, not a renamed flat enum.** `ARCHITECTURE-0.6.0.md:622-628` says to replace the inference but keeps the level model implicit. The current five values are an incomplete product of two dimensions (`src/regista/_assurance.py:17-22`). §4.2.

**D2 — `SELF_REVIEWED` is split.** Not in the architecture. `is_same = relation != DISTINCT` (`:255`, `:349`) re-collapses the `SAME`/`UNKNOWN` distinction WI-239 created one layer down. §4.3.

**D3 — `legacy_unverdicted` added; no backfill.** Not addressed anywhere. Without it, every one of ~351k events' worth of history reads as "no review happened" on the day Stage 3 lands. §4.5.

**D4 — WI-250's headline claim is stale and the item should be rewritten before implementation.** `adversarial_review` does use `LineageRelation` post-WI-258/WI-262 (`src/regista/_review_validators.py:261`, `:289`). Three different defects survive, one of which is WI-250's actual risk. §3.1.

**D5 — Reviewer-kind gating is removed and replaced by evidenced non-model status.** WI-250's fix direction says "a human reviewer is distinguished by `actor_kind` evidence, not by the absence of a lineage declaration". I go further: **`actor_kind` is a self-claim and is not sufficient evidence.** Only a trust-root-issued credential is. The interim is fail-closed, which adds friction for genuine human reviewers, and that is a deliberate, owner-visible cost. §3.3.

**D6 — `content_state_digest` is over the reduced *signed event prefix*, not over a work-item body or projection row.** `ARCHITECTURE-0.6.0.md:611-615` lists "canonical work-item body/frontmatter" first, which reads as a projection digest. A projection is mutable side state (S6) and an offline bundle verifier has no access to it. §2.3.

**D7 — `computed_relation` renamed to `decided` and widened.** Architecture `:589`. The gate decides more than a relation — acknowledgment requirement and separation of duties are also decisions the verifier must reconcile, and burying them makes them unreconcilable. §2.2.

**D8 — `declared_not_reviewed` added.** The architecture states the requirement (`:617-618`) without a field. §2.4.

**D9 — `compute_assurance` takes `(Event, VerificationResult)` pairs.** An API break for every caller, following from rule 1 of §4.1 and from the architecture's own "every consumer must accept only `VerificationResult`" (`:753`). Naming it as a break rather than letting it surface during implementation. §4.1.

**D10 — Transition names are not consulted by the reducer at all.** The architecture says assurance "reads only cryptographically valid `review-verdict/v1` payloads, never bare transition strings" (`:624`), which I am implementing literally: `_REVIEW_VERDICTS` survives only as an ingress hint. §4.1 rule 3.

**D11 — A review event with no verdict payload contributes *nothing*, rather than downgrading.** The audit's phrasing is "refusing to count a review event whose payload carries none" (`AUDIT-REPORT.md:76`), which I read as invisibility, not as a negative signal. Stating it because "no verdict = automatic downgrade" is the plausible alternative reading and it would make appending an unverdicted note a *lowering* operation — which would violate §4.4's invariant in the other direction and hand an attacker a denial tool.

---

## 8. Least-confident areas

**L1 — RESOLVED.** `subject_profile` is cut. Reducer v1 covers the complete content field set;
claim and intrinsic events are excluded structurally, while every event that changes what the item
says changes `content_state_digest`.

**L2 — RESOLVED by P0.2 and its 2026-08-10 corrective re-freeze. Signed verdicts are GO.** The
original 13-vector proof covered four interpreters; after removing `last_entity_seq` from the
content-only shape, the corrected digests were reproduced under CPython 3.12 and 3.13 with three
`PYTHONHASHSEED` values each. The full projection digests did not change. Artifacts are committed at
`tests/test_reducer_v1_determinism.py`, `tests/reducer_v1_frozen_digests.json` and
`tools/reducer_v1_sweep.py`; CI's 3.13 + 3.14 matrix keeps it a standing two-interpreter check.

The instinct behind L2 was right — the assumption was **false as the code stood**, in two ways,
and both were found by testing rather than by reading:

1. **`datetime.fromisoformat` is not a stable grammar across interpreters.** CPython 3.14 parses
   `"2026-08-09T24:00:00Z"` (legal ISO 8601 end-of-day) as the following midnight; CPython 3.12,
   CPython 3.13 and PyPy 3.11 raise `ValueError`. `_replay._parse_not_before` then *swallows* the
   failure and substitutes `None` — so the same signed prefix reduces to two different states,
   and a verdict signed on one host reads as stale on another, with nothing logged at the
   verifier. Reducer v1 parses RFC 3339 with an explicit grammar and **fails closed**.
2. **JCS's number form does not round-trip in the band `2**53 <= |v| < 1e21`.** The float `1e16`
   canonicalises to the integer literal `10000000000000000`, which re-parses as an integer
   outside JCS's safe domain and can never be canonicalised again — a signable, canonical event
   whose subject digest cannot be computed by anyone. Fixed by the magnitude rule now in
   `V6-ENVELOPE.md` §2.5.

**So the answer to L2's own question — "if reducer output can drift across regista versions,
`content_state_digest` needs a `reducer_version`" — is yes, and it has one.** `reducer_version`
is inside the reduced object, so it is inside the digest: a v2 reducer cannot silently produce a
v1 digest. Re-freezing the vectors is what invalidates old verdicts, and it is a deliberate act.

Two consequences to carry forward: **the reducer must never delegate to a version-dependent
parser** (an AST test enforces its dependency surface — stdlib plus the vendored canonicalizer,
no database, no `workflow_registry`), and **the field set is an owner call, not a Gate 0
question**: both variants (`include_claim_state` true/false) are proved stable, so deciding
whether lease churn stales a verdict cannot reopen this gate.

Original text, retained: **whether `reduce()` is deterministic enough to digest.** The entire subject binding assumes the replay reducer produces byte-identical output for the same signed prefix, on any machine, at any version. The audit found replay's read-only and writable paths agree and per-item ordering is tie-free (`AUDIT-REPORT.md:114-115`), which is encouraging, but "agree" is not "byte-identical under JCS". If reducer output can drift across regista versions, `content_state_digest` needs a `reducer_version` in the profile and old verdicts become unverifiable across upgrades. **This is the single assumption most likely to be wrong, and it should be tested before implementation starts, not during.**

**L3 — Friction of fail-closed human reviewers (§3.3 interim).** Every human reviewing agent-authored work must record `same_lineage_acknowledged` until delegation credentials land. Whether that is tolerable depends on how much human review actually happens in the estate; I have not measured it. If it is high-volume, the sequencing pressure to land B1 in Stage 2 is real and should be scheduled, not discovered.

**L4 — `legacy_unverdicted` population size is unmeasured.** D1 asks sibling D for it. My reasoning in §4.5 assumes it is large enough to matter and small enough that re-reviewing items that need `done` is feasible. Both halves could be wrong.

**L5 — Whether `accepted_by_agent` should exist at all.** I kept it as a reportable acceptance state because the current code silently discards a non-human accept (`src/regista/_assurance.py:275-277` falls through to the review-only levels). Reporting it is more honest than discarding it. But it creates a value that no gate profile treats as acceptance, which invites a future reader to wire it up. The alternative — reject agent `accept` verdicts at ingress — is cleaner and I did not choose it only because it is a behaviour change beyond this document's scope.

**L6 — Interaction with `close_from_open`.** `gate_rationale` special-cases it (`src/regista/_assurance.py:322-328`) and `gate_permits_done` returns `True` for it unconditionally (`:402-403`). That is a review-free path to `done`, and I have not specified how it interacts with the verdict model — presumably `review_assurance: none` with an explicit `closure_reason`, but a dismissal path that bypasses the gate deserves its own look before it becomes the obvious way around a stricter gate.
