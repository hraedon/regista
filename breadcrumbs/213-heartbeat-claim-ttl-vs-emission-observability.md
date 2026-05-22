---
number: "213"
title: "heartbeat_claim return type doesn't distinguish TTL extension from event emission"
severity: low
status: proposed
kind: design
author: external-review
date: "2026-05-22"
tags: [claims, observability]
related: []
---

## Problem

`heartbeat_claim` has two qualitatively different behaviors:
1. TTL-only extension (no event emitted — coalesce threshold not met)
2. TTL extension + `claim_heartbeat` event emission (threshold met)

The return type (`Claim`) has no field indicating whether an event was emitted. Callers that need to know whether the event log was mutated (for audit or testing) must read the event log separately.

The spec's BR-12 says heartbeat "simply extends the TTL" and describes it as "structurally idempotent," but event emission is a side effect that breaks the idempotency claim for callers observing the event log.

## Fix

Either add an `event_emitted: bool` field to the `Claim` return (breaking change), or add a separate method/parameter for "heartbeat with event guarantee."
