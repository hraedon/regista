# Plan 024 — Global-chain integrity: investigate, fix, repair

**Status:** Complete 2026-06-30. **Phase 0 finding: VERIFIER BUG (not data
corruption).** The chain links are correct in every schema; the replay verifier
sorted by `global_seq` (which diverges from append order under CACHE 100)
instead of walking the chain by `prev_global_event_hash` links. Fix shipped
(verifier hash-walk + `CACHE 1` migration), all schemas re-verified clean.
Phase 3 (data repair) was not needed.
**Author:** Opus 4.8
**Strategic role:** A read-only replay sweep of the production converged store
(`mvmpostgres01`, see agent-notes [[reference-production-regista-store]]) found the
per-schema global hash chain reporting broken across **14 of 15 schemas**. The
global chain is regista's store-level tamper-evidence anchor (G2). Until we know
whether the breakage is real (append/migration bug) or spurious (replay bug), and
— if real — repair it, the converged SoT cannot be trusted as authoritative, and
the downstream agent-notes dedup (agent-notes Plan 015 WI-2) is blocked. This work
is regista's because the global chain, its append path, and its replay verifier
all live here; reimplementing repair in a client would risk hashing the chain to a
wrong value.

---

## 1. Evidence

Read-only replay sweep, 2026-06-30 (each schema replayed via `_replay.replay`;
counts are warning occurrences):

| schema | replayed_ok | drift | halted | global_chain_broken | break range (global_seq) |
|---|---|---|---|---|---|
| regista | 661 | 0 | 0 | 192 | **1205..1778** (windowed) |
| cert_watch | 319 | 0 | 0 | 430 | 2..801 |
| sf2 | 247 | 0 | 0 | 330 | 2..601 |
| gpo_lens | 84 | 0 | 0 | 79 | 2..201 |
| agent_notes | 52 | 0 | 0 | 45 | 2..144 |
| agent_provenance | 42 | 0 | 0 | 37 | 2..201 |
| agent_wake | 44 | 0 | 0 | 44 | 2..128 |
| adcs_lens | 36 | 0 | 0 | 35 | 2..128 |
| usage_dashboard | 16 | 0 | 0 | 16 | 2..113 |
| dossier | 10 | 0 | 0 | 7 | 2..201 |
| acme_adcs_ra / acb / sluice / substrate | 8–9 | 0 | 0 | 7–8 | 2..~107 |
| patina | 1 | 0 | 0 | 0 | — (single event) |

**Two distinct signatures:**

1. **Windowed (regista only):** events 1..1204 verify, 1205..1778 break, 1779+
   verify. The window coincides with a known concurrent breadcrumb-import storm
   (2026-06-29 22:27–22:39, actor `agent-notes`). Smells like a **concurrency
   race**.
2. **From-seq-2 (every other multi-event schema):** essentially every link breaks,
   including 9-event low-traffic schemas. Uniform and traffic-independent. Smells
   like a **systematic computation/version mismatch**, not a race.

**Crucially benign so far:** `replayed_drift = 0` and `halted = 0` everywhere, and
there are **no signature or per-item-chain failures** — only `global_chain_broken`.
So the per-item provenance and all signatures verify; the projection matches the
log. If the data is genuinely broken, it is the *cross-event ordering anchor*, not
the event content. **No evidence of tampering or data loss.**

## 2. Relevant code (starting points, not conclusions)

- `_events.py:_lock_global_chain_head` (line ~59) takes `event_chain_head FOR
  UPDATE`; the head hash it returns becomes the new event's
  `prev_global_event_hash` (computed at line ~198, again at ~380 for the second
  append path).
- The `events` INSERT (line ~223) **does not list `global_seq`** → it is assigned
  by a column DEFAULT (`nextval('events_global_seq_seq')`), which is
  **non-transactional**. So an event's *ordering key* (`global_seq`, via nextval)
  and its *chain link* (`prev_global_event_hash`, via the FOR UPDATE lock) are set
  by two independent mechanisms. Replay verifies by ordering on `global_seq` and
  checking each link — so if the two mechanisms can disagree on order, replay
  reports a break even though each event individually chained correctly at write
  time. **Prime suspect for signature (1).**
- The sequence reached 64301 for 1077 committed events in `regista` (~63k
  rolled-back nextval values) → heavy retry/rollback during the storm. Gaps alone
  don't break replay (it orders, not counts), but they confirm contention.
- `_replay.replay` (`_replay.py:139`) is the verifier; its global-chain
  recomputation is itself in scope (see Phase 0).
- The convergence bulk-migration wrote events through the normal append path
  (agent-notes `scripts/migrate_to_regista.py` → `create_breadcrumb` → this code),
  so migrated and native events share the write path — which makes signature (2)'s
  uniformity puzzling and worth Phase 1.

## 3. Phase 0 — Is the data broken, or the verifier? (do this FIRST)

**FINDING (2026-06-30): THE VERIFIER IS BROKEN, NOT THE DATA.**

Phase 0a (manual recompute) and Phase 0b (chain walk) were performed against
the production converged store (`mvmpostgres01`). Every schema with events was
checked:

- **Chain walk**: Starting from genesis (NULL `prev_global_event_hash`), all
  events are reachable by following `prev_global_event_hash` links. Zero
  orphans, zero forks, zero broken links in every schema.
- **`global_seq` order ≠ chain order**: The `events_global_seq_seq` sequence
  uses `CACHE 100` (migration 017). Different backend sessions cache disjoint
  blocks of 100 values. When sessions interleave their appends, `global_seq`
  order diverges from actual append (chain-link) order. Example from `dossier`:
  chain order is `[1, 101, 2, 102, 3, 4, 103, 5, 201, 301, 401]` — two sessions
  alternating, each consuming from its own cache block.
- **Root cause of false reports**: `_replay._verify_global_hash_chain` sorted
  events by `global_seq` and checked links sequentially. When `global_seq` order
  ≠ chain order, it reported "global chain mismatch" for every link where the
  `global_seq`-sorted predecessor ≠ the actual chain predecessor.
- **Per-item chains and signatures**: All verify correctly (as the evidence
  table showed: `replayed_drift = 0`, `halted = 0`).
- **Genesis (0c)**: `global_seq = 1` stores `prev_global_event_hash = NULL` in
  every schema — correct. Replay seeds from NULL. No off-by-one.

**Phase 0 decides everything downstream.** → Phase 1/3 (root-cause data
corruption, repair) are **not needed**. Phase 2 (fix verifier) is the fix.

## 4. Phase 1 — Root-cause each real pattern (only if Phase 0 says data is broken)

- **1a. Windowed race (regista):** reproduce with a concurrent-append stress test
  (N writers, one schema) and check whether `global_seq` order can diverge from
  `prev_global_event_hash` link order. Confirm/deny the nextval-vs-lock-ordering
  hypothesis. If confirmed: the fix is to assign `global_seq` **inside** the same
  critical section that locks the head and computes the link (e.g. allocate the
  ordering key under the lock, not via a free-running default), so order and link
  are always consistent.
- **1b. From-seq-2 (migrated schemas):** determine why uniform. Candidates:
  (i) a regista version / canonical-envelope change between write-time and the
  current replay (rehash mismatch); (ii) the migration inserted events in an order
  where nextval ran outside head-lock ordering at scale; (iii) genesis-seed bug
  (0c). Cross-check write-time `regista_version` (events carry workflow/version;
  the store also logs `regista.connected ... regista_version`).

## 5. Phase 2 — Fix (scope set by Phase 1)

**SHIPPED.** Two fixes:

1. **Verifier fix (`_replay.py` + `_in_memory_replay.py`):** Rewrote
   `_verify_global_hash_chain` to walk the chain by following
   `prev_global_event_hash` links from genesis, instead of sorting by
   `global_seq`. This is what migration 030's design comment intended ("a hash
   walk that is immune to global_seq gaps") — the implementation just sorted
   by `global_seq` instead of walking. The walk detects: multiple genesis,
   forks, cycles, orphans, and head-vs-tail mismatch.

2. **Append path fix (migration 034):** `ALTER SEQUENCE events_global_seq_seq
   CACHE 1`. The append path already calls `nextval` AFTER acquiring the
   `event_chain_head` FOR UPDATE lock. With `CACHE 1`, every `nextval`
   round-trips to the sequence server, so values are assigned in lock-
   acquisition order — matching chain-link order. This prevents future
   `global_seq` ordering divergence.

3. **Regression tests (`tests/test_plan024_global_chain.py`, 6 tests):**
   - Concurrent transitions replay with 0 warnings.
   - Concurrent raw appends: hash walk produces 0 warnings.
   - Verifier detects orphaned events (corrupted `prev_global_event_hash`).
   - Verifier detects cycles.
   - InMemory replay walks chain correctly.
   - `global_seq` order matches chain-link order with `CACHE 1`.

## 6. Phase 3 — Repair command (only if data is genuinely broken)

A privileged `regista` admin operation (fits the Plan 002 admin CLI), per schema:

- Recompute `prev_global_event_hash` in `global_seq` order from the unaltered,
  still-signed events; reset `event_chain_head` to the final head.
- **Auditability:** because this rewrites a tamper-evidence structure, record the
  recompute as an attested/logged operation (who, when, pre/post head hashes,
  event count) — ideally an event or a row in a repair-audit table, so the
  recompute itself is on the record.
- **Idempotent + dry-run default**, mirroring the agent-notes dedup script's
  posture: print the diff (events whose link changes) before writing.
- **Before/after gate:** the command refuses to "succeed" unless a post-repair
  replay reports `global_chain_broken == 0` for that schema.
- **Order:** fix (Phase 2) must land first — repairing before the bug is fixed
  just re-breaks on the next concurrent write.

## 7. Phase 4 — Re-verify + unblock

**DONE.** Re-ran the global chain verification against all 11 production
schemas with events. All report **CLEAN** (0 warnings). The converged store is
trusted as authoritative. Agent-notes Plan 015 WI-2 (dedup) is unblocked.

## 8. Acceptance criteria

- AC-1: ✅ Phase 0 finding recorded — **verifier bug**, not data corruption.
  Manual recompute + chain walk evidence on all 11 schemas.
- AC-2: ✅ `_replay` global-chain check corrected (hash walk); all from-seq-2
  reports disappear with no data change; 6 regression tests pin the verifier.
- AC-3: N/A (data was not broken). Append path hardened with `CACHE 1` as
  defense-in-depth; concurrent-append property test green in default CI.
- AC-4: N/A (no data repair needed).
- AC-5: ✅ No event content, signature, payload, or per-item chain was altered.
  The fix is purely in the verifier code and a sequence cache change.

## 9. Non-goals / notes

- Not changing the per-item chain, signatures, or projections — all verify today.
- Not deduplicating work-items — that is agent-notes Plan 015 WI-2, downstream of
  this.
- The WI-002/003 concurrency fixes already merged (regista `8da9183`) address
  witness/hook TOCTOU, **not** this global-chain path; do not assume they fix it.
- **Validation note (for the reviewer of the team's findings):** the single
  highest-value check is Phase 0 — do not accept a repair plan that skips it. A
  per-schema "broken from seq 2" with drift=0 is at least as consistent with a
  verifier bug as with mass data corruption, and the two have opposite remedies.
  **[Confirmed 2026-06-30: Phase 0 was the decisive check. The verifier was the
  bug, not the data.]**
