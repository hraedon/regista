---
number: "269"
title: "Witness and webhook are near-duplicate patterns that should be unified"
severity: medium
status: resolved
kind: design
author: reflection
date: "2026-05-26"
tags: [webhooks, witnesses, deduplication]
related: ["261", "Plan 013"]
---

## Problem

`_witness.py` and `_webhooks.py` implement nearly identical patterns:
- Registration with URL, filters, status lifecycle (active/paused/failed)
- HTTP POST delivery with headers
- Failure tracking and status transitions
- List/unregister/pause/resume operations

The witness system has retry, receipts, and delivery tracking. The webhook system has none of these (BC-268). The code is duplicated and the webhook system is strictly less capable.

## Resolution

Accepted as design tension. Unification is a significant refactor that should happen when the webhook system matures enough to warrant shared infrastructure. For now, webhooks serve a simpler push-model use case that doesn't need receipt tracking.
