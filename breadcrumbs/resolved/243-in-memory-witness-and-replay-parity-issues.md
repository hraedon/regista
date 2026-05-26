---
number: "243"
title: InMemory witness and replay parity issues
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [in-memory, parity, witness]
related: ["238"]
---

## Problem

1. `InMemorySubstrate.unregister_witness` did not clean up orphaned receipts from `self._witness_receipts`.
2. `register_witness` stored `headers` and `event_filter` dicts by reference — caller mutation could corrupt internal state.
3. `_in_memory_replay.py` caught exceptions silently without logging, making InMemory replay failures extremely hard to debug (Postgres replay logs each halted work item).
4. `witness_signature` (bytes) was being stored as `psycopg.types.json.Jsonb(witness_sig)` in the success path of `deliver_pending_receipts`, but the column is BYTEA. This would cause serialization errors or data corruption on read-back.

## Fix

- InMemory `unregister_witness` now filters orphaned receipts.
- InMemory `register_witness` now copies `headers` and `event_filter`.
- InMemory replay now logs halted work items with `structlog`.
- Postgres witness delivery now stores `witness_signature` as raw bytes (BYTEA), not wrapped in `Jsonb()`.
- Receipt UPDATE queries in `deliver_pending_receipts` now include `WHERE status = 'pending'` guard to prevent double-updates under concurrency.
- Removed vacuous `FOR UPDATE` on `witness_registrations` read (was on autocommit connection, so lock was immediately released).
- Added URL hostname validation in `_validate_url`.