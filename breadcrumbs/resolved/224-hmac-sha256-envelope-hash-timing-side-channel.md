---
number: "224"
title: "HMACSHA256Scheme.verify uses == for envelope hash — timing side-channel"
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [signing, crypto, timing, plan-011]
related: ["222"]
---

# BC-224 — HMACSHA256Scheme.verify uses == for envelope hash

## Problem

In `_signing_scheme.py:66-69`, `HMACSHA256Scheme.verify` compares the envelope hash with `==` instead of `hmac.compare_digest`:

```python
return (
    _hmac.compare_digest(expected, signature)
    and hashlib.sha256(envelope).digest() == envelope_hash
)
```

The HMAC signature is compared constant-time (good), but the envelope hash uses Python's `==` operator which is **not constant-time** for bytes objects. CPython's `bytes.__eq__` short-circuits on the first differing byte.

The same issue exists in `Ed25519Scheme.verify` at line 112:

```python
return hashlib.sha256(envelope).digest() == envelope_hash
```

## Impact

An attacker who can observe timing differences in the hash comparison could potentially narrow the search space for a forged envelope hash. The practical risk is low (32-byte SHA-256 output, comparison short-circuits at byte granularity), but this violates cryptographic best practice and the principle of defense-in-depth.

The asymmetry is particularly concerning: the library correctly uses `hmac.compare_digest` for the signature but not for the hash, creating an inconsistent security posture.

## Recommendation

Replace `==` with `_hmac.compare_digest` in both `HMACSHA256Scheme.verify` and `Ed25519Scheme.verify`:

```python
# HMACSHA256Scheme.verify
return (
    _hmac.compare_digest(expected, signature)
    and _hmac.compare_digest(hashlib.sha256(envelope).digest(), envelope_hash)
)

# Ed25519Scheme.verify
return _hmac.compare_digest(hashlib.sha256(envelope).digest(), envelope_hash)
```

## Files

- `src/substrate/_signing_scheme.py:68`
- `src/substrate/_signing_scheme.py:112`
