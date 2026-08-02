# Review Assurance: Gate Honesty Under a Single Model

> Plan 027 — Review assurance: gate honesty under a single model

## The problem

The canonical workflow's two-stage review gate (`adversarial_pass` → `accept`)
assumes a **cross-lineage reviewer** — a different model that fails differently
from the author. When the suite deploys a single model (e.g., Claude-only),
the reviewer shares the author's failure modes. A `adversarial_pass` event
that means "independently reviewed" in a two-model world means "self-reviewed"
in a one-model world — while the recorded event looks identical.

An attestation that overstates its own assurance is worse than none. This plan
makes the gate **honest about the assurance it actually delivered**.

## Assurance levels

The `AssuranceLevel` enum is a pure view over the signed event history —
computed, never stored, so it can never disagree with the record.

| Level | Meaning |
|-------|---------|
| `NONE` | No review happened (e.g., `close_from_open` dismissal, or still in progress) |
| `SELF_REVIEWED` | Same-lineage adversarial pass, no human accept |
| `INDEPENDENTLY_REVIEWED` | Cross-lineage adversarial pass, no human accept |
| `HUMAN_ACCEPTED` | Same-lineage adversarial pass, human accept |
| `INDEPENDENT_AND_ACCEPTED` | Cross-lineage adversarial pass, human accept |

```python
from regista import compute_assurance_level

level = compute_assurance_level(events)
print(level)  # AssuranceLevel.INDEPENDENT_AND_ACCEPTED
```

Or via the API:

```python
level = sub.compute_assurance(work_item_id)
```

## Lineage derivation

Lineage is sourced from `actor_metadata.model_lineage` on each signed event.
The `same_lineage` function compares the reviewer's lineage against the set
of author lineages:

```python
from regista import same_lineage

same_lineage({"glm"}, "glm")      # True — same lineage
same_lineage({"glm"}, "kimi")     # False — cross-lineage
same_lineage({"glm"}, None)       # False — undeclared = independent
same_lineage(set(), "glm")        # False — no authors
```

**Undeclared lineage is treated as independent**, not same. This is the
conservative default: we don't assume two actors are the same model just
because neither declared a lineage.

### Trust caveat (pre-Plan-026)

Before per-actor Ed25519 signing (Plan 026) lands, the `actor_metadata`
field is HMAC-bound, not per-actor signed. The operator *could* forge the
actor field. Per-actor Ed25519 closes this gap — events signed with
per-actor keys flip lineage from `asserted` to `verified` automatically
(the verifier checks the actor↔signer binding). No schema migration, no
re-signing.

The strict gate can ship on `lineage: asserted` — the human-accept
requirement for same-lineage review is a workflow policy, not a
cryptographic property. What it loses without 026 is the *non-repudiation*
of the reviewer's identity, not the gate itself.

## Gate profiles

Two gate profiles ship:

| Profile | Same-lineage + non-human accept | Same-lineage + human accept | Cross-lineage |
|---------|:---:|:---:|:---:|
| `RELAXED` (default) | Permitted | Permitted | Permitted |
| `STRICT` | **Rejected** | Permitted | Permitted |

Under the strict profile, an item reviewed by the **same lineage** as its
author **cannot** reach `done` without a human accept. A cross-lineage
review can reach `done` with any acceptor. The relaxed profile (homelab)
is unchanged.

### Selecting the strict profile

Register the strict canonical workflow variant:

```python
from regista import canonical_workflow_yaml

sub.register_workflow(canonical_workflow_yaml(strict=True))
```

The strict variant adds `require_human_on_same_lineage: true` to the
`accept` and `reject` transitions' `validator_params`. When the
`human_gate` validator detects a same-lineage adversarial pass and a
non-human acceptor, it raises `ReviewRejected`.

### Gate rationale

The `gate_rationale` function explains why `done` was (or would be) permitted:

```python
from regista import gate_rationale, GateProfile

rationale = gate_rationale(events, GateProfile.STRICT)
# {
#   "profile": "strict",
#   "reason": "human_accept_for_same_lineage",
#   "assurance_level": AssuranceLevel.HUMAN_ACCEPTED,
#   "reviewer_lineage": "glm",
#   "author_lineages": ["glm"],
#   "lineage_verification": "verified",
# }
```

`lineage_verification` reports whether the deciding review event's lineage is
cryptographically bound or merely asserted (WI-215):

- `"verified"` — the deciding `adversarial_pass` is signed with a per-actor
  asymmetric scheme (ed25519) bound to its principal. Mutating the actor or
  `model_lineage` columns would invalidate that signature, so the lineage is
  non-repudiable.
- `"asserted"` — the deciding event is HMAC/v4-signed (or has no/unknown scheme).
  `actor_kind` and `actor_metadata.model_lineage` ride outside the v4 signed
  scope, so a database-write attacker could alter them without breaking the
  signature. The lineage is taken at face value.
- `None` — there is no deciding review event (no `adversarial_pass`).

The signal is informational and never changes a gate decision; it lets an auditor
tell a cryptographically-bound cross-lineage review from an asserted one.

Reasons:
- `cross_lineage_review` — cross-lineage adversarial pass (sufficient under both profiles)
- `human_accept_for_same_lineage` — same-lineage pass + human accept (sufficient under both)
- `same_lineage_acknowledged` — same-lineage pass + non-human accept (only sufficient under relaxed)
- `close_from_open` — the review-exempt dismissal path
- `not_done` — the item hasn't reached `done` yet

## The honest statement

This plan proves **what review happened**, not that the review was **good**.
A cross-lineage `adversarial_pass` means a different model reviewed the work —
it does not mean the review caught every defect. A human accept means a person
approved — it does not mean the person was right. The assurance level is a
**compensating control**, not a guarantee of quality.

The gate's value is in its **honesty**: an auditor reads the assurance level
and knows exactly what kind of review occurred, without inferring it from
context or trusting a label that overstates the case.

## Upgrade path: when the second model arrives

When a second model joins the deployment, items start reaching
`INDEPENDENTLY_REVIEWED` automatically — no redesign, no schema change.
The reviewer is already a distinct signed principal; this plan only adds
lineage *comparison*. Adding a genuinely different reviewer lineage flips
items from degraded (`SELF_REVIEWED`) to fully-assured
(`INDEPENDENTLY_REVIEWED`) with zero code change.

The ceiling this plan installs is exactly the thing that lifts.
