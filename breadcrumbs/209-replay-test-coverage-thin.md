---
number: "209"
title: "Replay test coverage is thin — 3 tests, many untested derivation paths"
severity: high
status: proposed
kind: improvement
author: adversarial-review
date: "2026-05-22"
tags: [replay, testing, coverage]
related: []
---

# BC-209 — Replay test coverage is thin — 3 tests, many untested derivation paths

## Problem

`test_replay.py` has only 3 test methods across 2 classes. The following replay derivation paths are untested:

- `claim_stolen` transition (extracts `new_actor_id` and `expires_at` from payload)
- `escalated` transition (sets `needs_review = True`)
- `not_before_set` transition (parses `not_before` from payload)
- `claim_heartbeat` events (BC-194 coalescing, extracts `expires_at` and `coalesce_threshold`)
- `continue_on_revoked=True` flag (BC-074 fix)
- Replay halt on missing workflow definition
- Replay halt on invalid transition from state
- Signature verification failure during replay
- Orphan events without a `created` first event (Postgres path)
- Multiple work items with different states
- Cross-contamination between work items during replay

The property-based conformance tests verify replay equivalence but don't exercise these specific derivation paths. A bug in any of these paths would silently produce incorrect replay results.

## Proposed fix

Add targeted replay tests for each derivation path. At minimum: claim_stolen, escalated, not_before_set, heartbeat coalescing, continue_on_revoked, and multi-work-item scenarios.
