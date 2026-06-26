---
number: "312"
title: "InMemory witness delivery has no concurrency lock — double-delivery risk under start_maintenance"
severity: medium
status: proposed
kind: bug
author: adversarial-review (BC-307 Kimi review)
date: "2026-06-26"
tags: [in-memory, witness, concurrency]
related: ["307"]
---

## Problem

`InMemoryRegista.deliver_pending_witness_receipts()` reads `_witness_receipts`,
mutates statuses to `in_progress`, and calls the external transport — all with
no lock. Two overlapping calls (e.g., from a `MaintenanceThread` and a manual
call) can pick up the same `pending` receipts before either sets them to
`in_progress`, delivering the same event twice.

Postgres avoids this with `UPDATE ... FOR UPDATE SKIP LOCKED`. InMemory has no
equivalent.

## Fix

Add a `threading.Lock` around the select-update-delivery loop in
`deliver_pending_witness_receipts()`. The lock scope should cover:
1. Finding pending receipts
2. Setting them to `in_progress`
3. The delivery loop
4. Status updates (confirmed/failed/paused)
