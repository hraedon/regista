---
number: "240"
title: Missing UNIQUE constraint on witness_receipts (witness_id, event_id)
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [witness, data-integrity]
related: []
---

## Problem

No `UNIQUE(witness_id, event_id)` constraint existed on the `witness_receipts` table. If `create_receipts` was called twice for the same event (e.g., via retry or concurrent call), duplicate receipts would be created, leading to duplicate HTTP deliveries to witnesses.

## Fix

Added migration `021_witness_receipt_uniqueness.sql` with `CREATE UNIQUE INDEX`. Added `UniqueViolation` catch in `create_receipts()` to gracefully handle the race.