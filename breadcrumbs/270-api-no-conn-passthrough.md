---
number: "270"
title: "API layer functions don't accept an existing connection for batch/transactional use"
severity: low
status: accepted
kind: design
author: reflection
date: "2026-05-26"
tags: [api, batching, transactions]
related: ["259"]
---

## Problem

`_work_items_api.create_work_item()` wraps its work in `mgr.transaction()`. When implementing `create_batch` in `_ops.py`, I had to bypass the API layer entirely and call the lower-level `_work_items.create_work_item(conn, ...)` directly. The same pattern applies to any future batch operation.

This means validation logic that lives in the API layer (e.g., `_validate_mutation_params`) is skipped in batch mode unless duplicated.

## Resolution

Accepted as design tension. The current two-layer architecture (API layer with transaction management + lower-level conn-accepting functions) works for the existing batch use case. A `_conn` passthrough parameter adds complexity for marginal benefit. Revisit if batch operations proliferate.
