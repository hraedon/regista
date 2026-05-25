---
number: "239"
title: Witness HTTP delivery connection leak and unbounded response
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [witness, resource-leak, security]
related: ["238"]
---

## Problem

`deliver_pending_receipts` in `_witness.py` created HTTP connections inside a `try` block but only called `conn_h.close()` on the success path. If an exception occurred between connection creation and `close()`, the connection was leaked. Additionally, `resp.read()` had no size limit, allowing a malicious witness endpoint to exhaust memory.

## Fix

- Moved `conn_h.close()` to a `finally` block with nested exception handling.
- Applied `resp.read(1_000_000)` (1MB) size limit.