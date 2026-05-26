---
number: "246"
title: claim_hooks raises unhandled ValueError on malformed work_item_id in hook payload
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [hooks, error-handling]
related: []
---

## Problem

`claim_hooks()` passes `payload.work_item_id` directly to `uuid.UUID(raw_wi_id)` without a try/except. A corrupted or malformed `work_item_id` in the hook_queue JSONB payload causes an unhandled `ValueError` that aborts the entire claim batch, stranding all other hooks.

## Fix

Wrapped `uuid.UUID()` call in try/except. On failure, logs a structured warning and skips the row, allowing other hooks in the batch to be processed normally.
