# Epoch reset — the evidentiary record starts at genesis, not at first run

**Status: owner decision, 2026-08-10.** This document has precedence over
`ARCHITECTURE-FINAL.md` and `RECONCILIATION.md` for the questions it decides, and it decides
only two: what happens to the existing event population, and what must be true before the
new one is opened. Everything else in the frozen set stands.

---

## 1. The decision

The legacy event population is **discarded, not migrated**. The 0.6.0 evidentiary record
begins at a deliberate genesis in an empty store. There is no cut-over from the existing
data, no mixed-epoch region, and no legacy prefix to anchor.

Deliberative content — work items, breadcrumbs, memories, decisions — is **operational
memory, not evidence**, and is migrated as ordinary rows. Its value never depended on the
signature chain and does not depend on it now.

## 2. Why, measured

Counted 2026-08-10 across all 25 schemas holding events:

| Population | Events | Scheme | Declared lineage |
|---|---|---|---|
| `agent_provenance` (cairn tool-call telemetry) | 366,297 — **98.7%** | 313,838 HMAC / 52,462 ed25519 | — |
| All 24 deliberative project schemas | **4,999** | regista's own 1,891 are **100% HMAC** | 818 (**16.4%**) |
| Total | 371,296 | | |

What that population can support: internal tamper-evidence, conditional on trusting the
operator who holds the HMAC secret, and an activity log. Both real; both operator-trusting.

What it cannot support, structurally rather than as a defect list:

- **Third-party verification.** The HMAC secret is never exported, so no outside party can
  verify any of it (`CUTOVER-POLICY.md`). Re-signing is forbidden and stays forbidden.
- **Authorship.** WI-281: 300,791 events attribute agent work to a human principal.
- **Review independence.** 83.6% of deliberative events declare no lineage at all; the
  declared 16.4% use a fragmented free-text vocabulary compared by exact string with
  DISTINCT as the default, so variance fails *open* (regista WI-285), and nothing ever
  observed the model that actually ran (agent-provenance WI-045).
- **External anchoring.** Zero anchors estate-wide (WI-264).

The evidentiary value of the existing chain is therefore approximately nil, while a large
share of the remaining 0.6.0 scope exists to carry it honestly. That is the trade this
document closes: the cost of carrying it is real, the value carried is not.

**This is a development estate, prerelease and pre-sandbox.** No consumer has ever relied on
these events as evidence. Declaring that the record *starts* at genesis is more honest than
retroactively implying guarantees over data that never had them.

## 3. What this removes from the plan

| Plan item | Effect |
|---|---|
| **P0.3** | Four vectors exist only for the seam and are deleted: `legacy-seam-checkpoint`, `version-aware-event-hash`, `bundle-merkle-mixed-epoch`, `bootstrap-cutover-checkpoint`. The remaining 23 stand unchanged. |
| **P1.2** | **Unaffected.** A project-kind genesis event carries a null workflow whether or not a legacy prefix exists, so the nullable-workflow migration is still a hard prerequisite of the first v6 append. |
| **P1.3** | The v5 reclassification half — the ~334k relabel to `LEGACY_PARTIAL` — is dropped. The consolidated v6 result model survives. |
| **P3.3** | Version-aware event hashing and mixed-epoch membership trees are dropped: there is one construction, because there is one epoch. `BUNDLE-V3.md` §3.3's mixed-epoch requirement lapses with it. |
| **P4.1** | Full-estate rehearsal is dropped. There is no migration to rehearse. |
| **P5.1** | Cut-over becomes genesis: provision keys, run the conformance gate in §5, write the first event. |

`V6-ENVELOPE.md` §6.7 DD-1's reasoning about not degrading the legacy seam is now moot but
harmless; the seam it protects will not exist.

## 4. Claims and observations are not the same thing

The failure this release exists to remove is not missing data. It is **data that reads as
complete when it is not**. Two write paths, two rules:

**Deliberative writes fail closed.** A work item, transition or review verdict that cannot
establish a load-bearing field is refused, with a named error telling the caller what to
set. Events can never be re-signed, so an accepted-but-incomplete event is permanently
unfixable history; a refusal costs one command and a retry. This is the shape of
agent-notes WI-062's `UNDECLARED_LINEAGE` guard, and it generalises to every field a later
claim depends on.

**Observational capture degrades, never blocks.** cairn must not refuse to capture, and must
never block the execution it is observing — a provenance layer that stops work when it
cannot record is a provenance layer people switch off. Partial capture beats no capture.
cairn already has the right machinery: a durable per-session degradation log mirroring the
Claude Code hook's `_mark_degraded`, written precisely so a gap is "discoverable by an
auditor rather than invisible", with no blind retries because "the degradation log is the
honest record instead."

**The bridge rule, which is where fail-closed actually lives:** a degraded observation must
never become a claim. Any consumer deriving an assurance property — independence,
authorship, review verdict — from capture that carries a degradation marker treats it as
`UNKNOWN` and fails closed *at the derivation*, not at the capture. Degradation is recorded
in-band and is never silent.

Two consequences for the current code: cairn's degradation vocabulary must grow entries for
identity and model gaps (today it covers orphaned tool calls only), and the assurance layer
must read that log rather than seeing an absent field and inferring nothing happened.

## 5. What must be true before genesis

These are preconditions on the *first write*, not a report read afterwards. The store
conformance check gates the epoch; if it does not pass, the epoch does not open.

1. **Every load-bearing field is refused when absent.** Verified by attempting a write
   without it and asserting the named error, not by reading configuration.
2. **Lineage is a closed vocabulary.** Values come from a canonical family registry and are
   rejected at ingress, as `principal_kind` now is (WI-262). Families are unversioned:
   `claude-opus-5` and `claude-opus-4-8` are the same lineage (`V6-ENVELOPE.md` §1.8).
3. **The model is observed, not asserted** — or the record says it was not. Acceptance test:
   an agent configured under one model name that dispatches to another must be captured as
   the model that ran (agent-provenance WI-045).
4. **Identity is session-scoped, and resolvable.** A host-wide lineage is legitimate only
   where the host runs exactly one model (agent-notes WI-067).
5. **The invariants are executable and scheduled.** Percentage of events with declared
   lineage, distinct lineage tokens, unresolvable tokens, scheme mix, undeclared authors —
   every defect above was seconds of SQL that nobody ran. Run continuously, these surface at
   a hundred events rather than three hundred and seventy-one thousand.

## 6. Standing rules for the new epoch

1. Fail closed at write time on anything the record's value depends on. Unfixable history is
   the expensive failure; a refused command is the cheap one.
2. Closed vocabularies for anything compared for equality. Free text plus exact-match plus
   different-by-default is a fail-open.
3. Never record an unobserved claim in a field that reads as observed. Asserted and observed
   are distinct, and the distinction is visible downstream.
4. Do not open the evidentiary record before the guarantees hold.
5. Keep the invariants executable and run them on a schedule.
6. Prefer mistakes that are fixable at read time. Where a value may need correcting later,
   keep it in a projection or mapping rather than baking it into signed bytes.

## 7. Open

- **Disposition of the discarded data.** Archived read-only for a period, or dropped. It has
  no evidentiary value either way; this is a storage and sentiment question, not a
  correctness one.
- **Where the canonical family registry lives** — regista enforces the comparison, cairn is
  the only component that sees every harness (WI-285).
- **Whether `agent_provenance` telemetry restarts empty or is retained as an operational
  log.** It is 98.7% of the volume and nobody reads historical tool-call captures.
