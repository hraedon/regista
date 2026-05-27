---
number: "281"
title: WITNESS_DELIVERY_FAILED and WITNESS_PAUSED error codes defined but never raised
severity: low
status: accepted
kind: improvement
author: comprehensive-review
date: "2026-05-27"
tags: [errors, witness]
related: []
---

`WITNESS_DELIVERY_FAILED` and `WITNESS_PAUSED` are defined in `_errors.py` and
mapped to HTTP status codes in the sidecar, but no code in the library ever
raises them. The witness delivery code in `_witness.py` logs errors but does
not raise these codes. The auto-pause logic sets status but does not raise.

These should either be wired into the appropriate code paths or removed to
avoid confusion about the API contract.
