---
number: "233"
title: Events are individually signed but not hash-chained — no tamper-proof ordering within a work-item's log
severity: high
status: proposed
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [security, crypto, signing, replay, hash-chain]
related: ["001", "005"]
---

## Observation

Every event is independently signed (HMAC-SHA256 or Ed25519 over a canonical envelope), and replay verifies each signature. However, there is no cryptographic binding between consecutive events in a work-item's event log. An attacker with DB write access who obtains a valid signing key could:

1. Insert a backdated event between two existing events.
2. Delete an event and the gap-free `event_seq` won't reveal it (the replay would simply skip it with a warning).

If the signing envelope included the previous event's hash (or the current `event_seq` was bound to a prior-state hash), replay could detect insertion by verifying the hash chain. Without it, individual signature verification passes for every event in the chain but the _ordering integrity_ relies entirely on DB access controls and `event_seq` monotonicity.

## Proposed

Add an optional `prev_event_hash` field to the signing envelope (v3). Each event's envelope includes `SHA-256(prev_event.payload_canonical_hash || prev_event.signature)`. Replay verifies the chain. This could be opt-in per workflow to avoid breaking existing consumers. Alternatively, bind the `event_seq` itself into the signed payload so that re-ordering is detectable.
