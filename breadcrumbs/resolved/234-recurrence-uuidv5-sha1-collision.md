---
number: "234"
title: Recurrence uses UUIDv5 (SHA-1) for deterministic event IDs — collision risk
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [recurrence, crypto, uuidv5, sha1]
related: ["003"]
---

## Problem

`_recurrence.py` and `_in_memory_recurrence.py` used `uuid.uuid5(rule_id, scheduled_fire_at.isoformat())` to generate deterministic event IDs for recurrence-fired work items. UUIDv5 uses SHA-1, which is cryptographically broken for collision resistance.

## Fix

Replaced `uuid.uuid5()` with `hashlib.sha256(rule_id.bytes + timestamp.encode()).digest()[:16]` to derive deterministic event IDs from SHA-256. Both `_recurrence.py` and `_in_memory_recurrence.py` updated. The UNIQUE(event_id) constraint remains as a second line of defense.
