---
number: "300"
title: Global chain hash (prev_global_event_hash) is never verified during replay
severity: medium
status: proposed
kind: improvement
author: glm-5.2
date: "2026-06-23"
tags: [plan-022, replay, global-chain, integrity, p2-review]
related: ["298", "233"]
---

## Problem

Both `_verify_hash_chain` (`_replay.py`) and `_verify_hash_chain_in_memory` (`_in_memory_replay.py`) only verify `prev_event_hash` (per-work-item chain). The `prev_global_event_hash` is stored in the database and included in the signed envelope, but never verified during replay.

This means an attacker who can modify the database could tamper with `prev_global_event_hash` values without detection during replay. The global chain's tamper-evidence relies solely on the signature (which covers the envelope including `prev_global_event_hash`), not on chain verification.

## Impact

- If signature verification is skipped (e.g., `continue_on_revoked` with unknown keys), there's no chain check for the global chain
- The per-work-item chain is verified but the global ordering chain is not
- This is a defense-in-depth gap, not a direct vulnerability (the signature covers the field)

## Fix

Add a `_verify_global_hash_chain` function that walks events in `global_seq` order and verifies `prev_global_event_hash = hash(prev_canonical_envelope + prev_signature)` for each event. Call it alongside the existing `_verify_hash_chain` in replay.

## Discovery

Found during P2 adversarial review of Plan 022 Phase 2 (crypto-agility).
