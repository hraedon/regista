---
number: "303"
title: Witness ed25519 delivery accepted 200 OK response without witness_signature as confirmed
severity: high
status: resolved
kind: bug
author: adversarial-review
 date: "2026-06-24"
tags: [witness, ed25519, security, signing]
related: ["297"]
---

## Description

`_witness.py.deliver_pending_receipts` treated any HTTP 2xx response from an
ed25519-registered witness as a successful co-signature, even when the JSON
body did not contain `witness_signature` or contained an invalid one. The
initial value of `sig_verified` was `True` and only became `False` when a
signature was present and failed verification. A missing signature left it
`True`, so the receipt was marked `confirmed` with no proof of co-signing.

## Impact

A compromised or misconfigured witness could claim to have co-signed an event
while providing no verifiable signature. Replay would show the receipt as
`confirmed` even though independent verification was impossible.

## Resolution

- For ed25519 witnesses, `_witness.py` now sets `requires_witness_signature = True`
  regardless of whether `public_key` is present.
- If `witness_signature` is missing or invalid, or the public key is unusable,
  `sig_verified` is set to `False`.
- Signature verification failures now share the same retry/pause path as HTTP
  delivery failures via `_apply_receipt_failure()`, honouring `max_retries` and
  `max_failures`.
- Regression tests added for missing signature and retry/pause lifecycle.

## Files

- `src/regista/_witness.py`
- `tests/test_witness_integration.py`
