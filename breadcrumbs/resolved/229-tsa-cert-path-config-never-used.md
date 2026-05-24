---
number: "229"
title: "TSAConfig.tsa_cert_path accepted but never used"
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [timestamping, plan-012, config, security]
related: ["223", "225"]
---

# BC-229 — TSAConfig.tsa_cert_path accepted but never used

## Problem

`TSAConfig.tsa_cert_path` in `_timestamping.py:13` is an optional field that accepts a path to a TSA certificate:

```python
@dataclass(frozen=True)
class TSAConfig:
    tsa_url: str
    tsa_cert_path: str | None = None  # never referenced
    batch_size: int = 1000
    interval_seconds: float = 3600.0
    hash_algorithm: str = "sha256"
```

This field is **never referenced** anywhere in the codebase — `submit_to_tsa`, `verify_tsa_token`, `_build_tsr`, and all other functions ignore it entirely.

## Impact

The field creates a false sense of security. Callers who set `tsa_cert_path` expect certificate-based verification to occur, but nothing happens. This is a UX anti-pattern: accepting security-relevant configuration that has no effect.

The field was likely intended to:
1. Pin the TSA's TLS certificate for certificate pinning
2. Use the certificate to verify the TSA's PKCS#7 signature on the response (as required by RFC 3161)

Neither is implemented.

## Recommendation

Either:
1. **Remove the field** until certificate verification is implemented
2. **Implement certificate verification** using the field (as part of fixing BC-223/BC-225)
3. **Document** that the field is reserved for future use and has no effect

## Files

- `src/substrate/_timestamping.py:13`
