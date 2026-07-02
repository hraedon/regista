# Plan 028 — Event-log retention & archival without breaking the chain

**Status:** Proposed 2026-07-02
**Author:** Claude (Fable 5), from the 2026-07-02 suite-gaps review
**Strategic role:** The converged store's event log is append-only and grows
forever; agent-notes adds pgvector embeddings on top. For a year that is fine; for
a long-running regulated deployment it is a latent operational problem — unbounded
growth, and eventually a compliance question ("how long do we retain, and can we
prove the archive wasn't altered?"). This plan gives regista a **retention +
archival** story that shrinks the hot store **without breaking the hash chain or
the ability to verify archived history** — the hard part, since naive deletion
severs the `prev_event_hash` links that make the log tamper-evident.

## Ground truth at time of writing

- regista is event-sourced: an immutable append-only event log per project schema,
  each event's `prev_event_hash` binding it to its predecessor; the projection is
  rebuilt by replay. The hash chain is the tamper-evidence.
- There is **no retention or archival**: every event lives in the hot Postgres
  schema forever. `replay`/chain-verify walk the whole log.
- pgvector embeddings (agent-notes) are a projection/derivative, regenerable from
  the source — so they are not the archival problem; the event log is.
- Per-actor signing (Plan 026) and the anchoring work (Plan 019, transparency-log
  anchoring) are the trust primitives an archive must preserve: an archived segment
  must stay independently verifiable.

## Principles this plan must hold

- **Never break verifiability.** Archived history must remain chain-verifiable and
  signature-verifiable offline. Archival *relocates* events; it does not delete the
  evidence. A verifier must be able to prove the archive + the hot log together
  form one unbroken, unaltered chain.
- **Archive is append-only and sealed.** A sealed segment is immutable and carries
  a signed seal (its head hash, count, time range, and — if Plan 019 anchoring is
  present — its external anchor), so tampering with an archived segment is
  detectable without the hot store.
- **Retention is policy, applied explicitly.** The tool never silently drops
  history; an operator sets a retention policy and archival runs on it, recording
  what moved where in the (signed) log itself. A regulated shop's retention
  *minimum* is honored — nothing inside the retention window is archived out of
  reach.
- **The hot store stays correct after archival.** Replay and projection must work
  from `hot log + sealed segment heads` without needing every archived event
  resident — the segment seal is the bridge.

---

## Phase 1 — Segment sealing (the archival unit)

### WI-1.1 — Chain-preserving segment seal
- Define a **segment**: a contiguous range of events with a signed **seal**
  recording `{first_seq, last_seq, head_hash, count, time_range, anchor?}`. Sealing
  a segment leaves a single seal row in the hot schema that a chain-verify treats
  as a verified stand-in for the range — so the chain remains continuous across the
  boundary (event N+1's `prev_event_hash` still resolves, via the seal, to event
  N's hash).
- **AC:** sealing a range produces a seal whose `head_hash` matches the range's
  actual head; chain-verify across a sealed boundary succeeds; altering a sealed
  event is detected (its recomputed hash no longer matches the seal); the seal is a
  signed event itself.

### WI-1.2 — Archive store + export
- Sealed segments export to an **archive store** (a file/object-store bundle:
  events + seal + verification material), self-contained and offline-verifiable
  with `regista verify --archive <bundle>`. The hot schema retains the seal, not
  the bodies.
- **AC:** an exported archive bundle verifies offline (chain + signatures) with no
  hot DB; importing/attaching it back lets a full-history query span archive + hot
  seamlessly; the bundle carries no plaintext secret.

## Phase 2 — Retention policy + application

### WI-2.1 — Explicit retention policy
- A per-project retention policy (`keep hot: last N days / M events / everything
  referenced by an open work-item`), never archiving anything inside the declared
  compliance-retention minimum or referenced by live state. `regista archive
  --project <slug> --dry-run` shows what would move; without `--dry-run` it seals +
  exports and records the action in the signed log.
- **AC:** archival respects the retention window and never archives an event a
  live work-item/baseline references; `--dry-run` moves nothing; the archival
  action is itself a signed event naming the sealed range.

### WI-2.2 — Replay/projection over hot + sealed
- Replay and projection rebuild correctly from the hot log plus sealed-segment
  heads, fetching archived bodies only when a query actually needs pre-archive
  detail. Verify handles a chain that crosses multiple seals.
- **AC:** a projection rebuilt after archival matches the pre-archival projection
  for all retained state; a full-history verify crosses N seals and succeeds; a
  query for archived detail transparently reads the bundle.

## Phase 3 — Closeout

### WI-3.1 — Docs + first drill
- `docs/retention.md`: the segment/seal model, the retention-policy contract, the
  compliance-minimum guardrail, and how an auditor verifies an archive bundle
  independently. Drill it on the homelab store (seal + export an old range, verify
  the crossed chain, confirm projection unchanged).
- **AC:** the doc lets an auditor verify a bundle; the homelab drill seals, exports,
  and re-verifies with zero projection drift.

## Sequencing & notes

- **Lower priority than the trust gaps (Plans 026/027) and DR** — growth is a
  next-year problem, not a launch blocker — but it is a real one and the chain-
  preserving design is the kind of thing worth specifying before the log is huge,
  because retrofitting archival onto a giant single-segment log is painful.
- **Composes with anchoring (Plan 019):** if external anchoring is present, a
  segment seal carries the anchor, so an archived segment's *time* is provable
  independent of the operator — the archival analogue of the live anchor.
- **agent-suite's DR runbook (Plan 001) references this:** backup covers the hot
  store; archival bundles are part of what a full restore must reassemble and
  re-verify. The two together are the "the store survives and stays provable"
  story.
