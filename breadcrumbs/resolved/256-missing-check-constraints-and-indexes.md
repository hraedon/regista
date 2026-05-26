---
number: "256"
title: Missing CHECK constraints on tsp_batches, witness_registrations, witness_receipts status columns
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [migrations, data-integrity]
related: []
---

## Problem

Three status columns lacked CHECK constraints, allowing arbitrary string values:
- `tsp_batches.status` (should be pending/confirmed/failed/superseded)
- `witness_registrations.status` (should be active/paused/failed)
- `witness_receipts.status` (should be pending/in_progress/confirmed/failed)

Every other status-style column in the schema has a CHECK constraint.

Also: migration 020 created a non-unique index on `(witness_id, event_id)` that was superseded by migration 021's unique index on the same columns, causing unnecessary write amplification. And `sweep_expired_hook_leases` had no suitable index, causing full table scans.

## Fix

Migration 022 adds:
- CHECK constraints on all three status columns
- `DROP INDEX` for the redundant non-unique witness_receipts index
- `idx_hook_queue_lease_sweep` partial index for the hook lease sweep query
