---
number: "244"
title: Witness receipt delivery TOCTOU allows double-delivery
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [witness, delivery, concurrency, toctou]
related: ["239"]
---

## Problem

`deliver_pending_receipts()` fetched receipts with `SELECT ... FOR UPDATE SKIP LOCKED` inside a transaction, but that transaction committed immediately after the fetch. Receipts remained in `status='pending'`. The actual HTTP delivery and status updates happened in separate, subsequent transactions. Between the fetch commit and the per-receipt updates, a concurrent delivery thread could select the same receipts and deliver them again.

## Fix

Changed the initial SELECT to an atomic `UPDATE ... SET status = 'in_progress' ... RETURNING` that marks receipts as claimed inside the same transaction. Subsequent success/failure updates now match on `status = 'in_progress'`. Added `'in_progress'` to the witness_receipts status CHECK constraint in migration 022.
