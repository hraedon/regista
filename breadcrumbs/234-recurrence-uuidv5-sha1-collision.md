---
number: "234"
title: Recurrence uses UUIDv5 (SHA-1) for deterministic event IDs — collision risk
severity: low
status: proposed
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [recurrence, crypto, uuidv5, sha1]
related: ["003"]
---

## Observation

`_in_memory_recurrence.py:166` and `_recurrence.py` use `uuid.uuid5(rule_id, scheduled_fire_at.isoformat())` to generate deterministic event IDs for recurrence-fired work items. UUIDv5 uses SHA-1 hashing under the hood. SHA-1 is cryptographically broken for collision resistance, though SHA-1 chosen-prefix collisions remain expensive (~$45K as of 2023).

In practice the risk is negligible:
- The input space is bounded (rule_id UUID × ISO-8601 timestamp string).
- The attacker would need to control both inputs.
- Postgres `UNIQUE(event_id)` provides a second line of defense.

## Proposed

Switch to UUIDv7 (time-ordered, non-cryptographic) and accept that recurrence event IDs are deterministic only within a single fire cycle. Alternatively, use a SHA-256 or SHA-512 based namespaced derivation outside the UUID spec. Low priority; the UNIQUE constraint already prevents collisions regardless of hash strength.
