---
number: "213"
title: "heartbeat_claim return type doesn't distinguish TTL extension from event emission"
severity: low
status: accepted
kind: design
author: external-review
date: "2026-05-22"
tags: [claims, observability]
related: []
---

# BC-213 — heartbeat_claim return type doesn't distinguish TTL extension from event emission

## Problem

`heartbeat_claim` has two qualitatively different behaviors:
1. TTL-only extension (no event emitted — coalesce threshold not met)
2. TTL extension + `claim_heartbeat` event emission (threshold met)

The return type (`Claim`) has no field indicating whether an event was emitted. Callers that need to know whether the event log was mutated (for audit or testing) must read the event log separately.

The spec's BR-12 says heartbeat "simply extends the TTL" and describes it as "structurally idempotent," but event emission is a side effect that breaks the idempotency claim for callers observing the event log.

## Resolution

**Accepted** — this is a design tension, not a defect. The current return type (`Claim`) intentionally models the *durable claim state*, not the *event log delta*. Changing it would mean coupling the claim contract to the event log contract, which runs against the spec's invariant that projection is a derived view of events. Consumers who need event-log observability can read `events` by work_item_id and filter for `transition = 'claim_heartbeat'`. If a future use case makes this query cost-prohibitive, a separate `heartbeat_claim_detailed` method returning a `ClaimHeartbeatResult(claim, event_emitted)` could be added non-destructively.
