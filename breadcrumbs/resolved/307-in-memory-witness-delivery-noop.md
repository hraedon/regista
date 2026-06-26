---
number: "307"
title: "InMemory witness delivery is a noop — receipts created but never delivered"
severity: low
status: resolved
kind: design
author: structural-review
date: "2026-06-25"
tags: [in-memory, witness, parity]
related: ["243", "238"]
---

## Problem

`InMemoryRegista.deliver_pending_witness_receipts()` returns 0 unconditionally
(`_in_memory.py:1019`). Witness receipts are created in-memory via
`_try_create_witness_receipts`, but there is no delivery path — no HTTP client,
no mock delivery, no status transition from pending to confirmed/delivered.

The Postgres backend (`_witness.py:410`) performs real HTTP delivery with
retry, max_failures, auto-pause, and ed25519 signature verification.

## Impact

Tests using `InMemoryRegista` that depend on witness delivery lifecycle
(receipt confirmation, failure retry, witness pause) cannot exercise those
paths. The gap is pinned by `test_deliver_pending_witness_receipts_noop`
(`test_witness.py:268`).

42 resolved breadcrumbs are InMemory parity issues, confirming this is a
recurring defect class.

## Assessment

Accepted design limitation. InMemory is a test/development backend and does
not make HTTP calls. The receipt creation path is fully implemented, which is
the important part for testing event-witness matching. Delivery lifecycle
testing correctly uses the Postgres integration tests.

If future testing needs delivery lifecycle without a real HTTP server, a
pluggable transport interface (injectable callable) would be the right design —
not an HTTP mock inside InMemory.

## Resolution

Implemented pluggable transport interface per the design suggestion above.
`InMemoryRegista.__init__` now accepts an optional `witness_transport:
Callable[[str, dict, dict], TransportResult]` parameter. When set,
`deliver_pending_witness_receipts()` iterates active witnesses, finds pending
receipts, builds the delivery payload (event dict + HMAC signature header,
matching Postgres format), calls the transport, and updates receipt/witness
state (confirmed, retry, pause) following the same logic as the Postgres
backend. When no transport is provided, the method returns 0 (backward
compatible). `TransportResult` is a frozen dataclass with `status_code`,
`body`, and `error` fields. 19 tests in `tests/test_witness_in_memory.py`.
