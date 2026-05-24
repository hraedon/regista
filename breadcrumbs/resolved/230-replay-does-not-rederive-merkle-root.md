---
number: "230"
title: "replay(verify_timestamps=True) does not re-derive Merkle root from current events — tamper detection is theatre"
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [replay, timestamping, plan-012, tamper-evidence]
related: ["198", "226"]
---

# BC-230 — replay verify_timestamps does not re-derive Merkle root

## Problem

After the BC-226 fix, `replay(verify_timestamps=True)` in `_replay.py:223-256` does two things per confirmed batch:

1. Adds every `event_seq` in `[first_event_seq, last_event_seq]` to a `covered` set (used later to flag uncovered events).
2. Calls `verify_tsa_token(token, merkle_root_from_row, cfg)` to confirm the TSA signed the stored Merkle root.

What it does **not** do: recompute the Merkle root from the live event log and compare to `tsp_batches.merkle_root`. The stored `merkle_root` is trusted as-is; only its TSA signature is checked.

## Why this matters

This is exactly the threat model BC-198 was supposed to defend against. The entire point of timestamping is "the operator cannot rewrite history undetected." With the current code:

- Operator with DB write access mutates events in some range.
- `tsp_batches.merkle_root` is left untouched.
- `replay(verify_timestamps=True)`:
  - "events covered" ✓
  - "TSA signed this merkle root" ✓
  - Returns 0 warnings about tampering.

The TSA token check is cryptographically sound for what it does (proves the TSA observed *some* Merkle root at *some* time) but useless for the tamper-detection property substrate claims to provide, because there is no link verified between the stored root and the current event content.

This finding is independent of BC-231 (per-WI event_seq makes the batching model itself questionable); even granting the batching model is correct, the verification is incomplete.

## Recommendation

In the `verify_timestamps` branch, for each batch row:

1. Collect the event_ids in `[first_event_seq, last_event_seq]` from `all_events` (already loaded).
2. Compute `compute_merkle_root(those_event_ids)`.
3. If it does not equal `bytes(row["merkle_root"])`, emit a `replay.merkle_root_mismatch` warning and increment `total_warnings`.

Add a test that mutates an event after the batch is recorded (e.g., update `payload_canonical_hash` directly) and confirms a mismatch warning fires.

Caveat: this BC needs BC-231 resolved first or alongside — the current per-WI `event_seq` semantics make "events in range" ambiguous when multiple work items are involved.

## Files

- `src/substrate/_replay.py:223-256`
- `src/substrate/_timestamping.py` (compute_merkle_root is already exported)

## Follow-up (2026-05-24)

The recomputation now exists in `_replay.py`, but until BC-231 lands it
groups leaves by per-WI `event_seq`, which produces wrong leaf sets in any
multi-WI batch. The tamper-detection property is therefore only sound for
single-WI deployments today. Plan 014 (`plans/014-global-event-seq.md`)
re-keys the verification block off `global_seq`, at which point the
multi-WI case also becomes load-bearing. Re-verify this BC after Plan 014
ships and add a multi-WI mutation test alongside the existing single-WI
one.
