---
number: "272"
title: "Webhook work_item_types filter reads from wrong event field — always skips"
severity: high
status: proposed
kind: bug
author: design-review
date: "2026-05-26"
tags: [webhooks, filter, bug]
related: ["269"]
---

## Problem

`_webhooks.py:156-159` filters `work_item_types` against `event["payload"]["work_item_type"]`. But `Event.to_dict()` puts `work_item_type` at the top level of the event dict, not inside `payload`. The filter always evaluates `None not in [...]` which is `True`, causing every event to be skipped for any webhook registered with a `work_item_types` filter.

Witness `event_matches_filter` correctly reads `event_dict.get("work_item_type")` from the top level.

## Fix

Fix filter to read from top-level `work_item_type` key, matching witness behavior. Add test exercising filter against a real `Event.to_dict()`.

Note: This will be resolved as part of the webhook→witness unification (BC-269). Filed separately so the fix is tracked independently.
