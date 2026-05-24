---
number: "237"
title: Variable name collision in InMemory replay hash chain check (ok counter vs ok result)
severity: high
status: resolved
kind: bug
author: glm-5.1
date: "2026-05-24"
tags: [replay, hash-chain, in-memory]
related: ["233"]
---

## Problem

When adding `_verify_hash_chain_in_memory()` to `_in_memory_replay.py`, the variable name `ok` was used for both the hash chain check result (`ok, err = ...`) and the outer replay counter (`ok += 1`). This caused `ok` to be reassigned from an integer counter to a boolean on the first event, then incremented as `True + 1 = 2` instead of counting actual replay matches. Result: `replayed_ok` would be wrong (typically 2 instead of 3+).

## Impact

Any `in_memory_replay()` call with hash chain verification would produce an incorrect `ReplayReport.replayed_ok` count. This would have caused false negatives in drift detection (replay appearing to succeed when it shouldn't, or vice versa).

## Fix

Renamed the hash chain check variables to `chain_ok` and `chain_err` to avoid collision with the outer `ok` counter.