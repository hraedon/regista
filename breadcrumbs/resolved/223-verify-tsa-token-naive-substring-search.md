---
number: "223"
title: "verify_tsa_token is not real TSA verification — naive substring search"
severity: critical
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [timestamping, plan-012, crypto, rfc-3161]
related: ["225", "226", "229"]
---

# BC-223 — verify_tsa_token is not real TSA verification

## Problem

`verify_tsa_token` in `_timestamping.py:128-137` performs a byte-by-byte substring search for the SHA-256 digest within the raw TSA response token:

```python
def verify_tsa_token(token: bytes, data: bytes, config: TSAConfig) -> bool:
    if not token or len(token) < 16:
        return False
    digest = hashlib.sha256(data).digest()
    idx = 0
    while idx < len(token) - len(digest):
        if token[idx : idx + len(digest)] == digest:
            return True
        idx += 1
    return False
```

This is **not cryptographic verification** of an RFC 3161 TSA response. A proper verification must:

1. Parse the PKCS#7/CMS signed-data structure from the TSA response
2. Verify the TSA's digital signature on the token
3. Validate the TSA certificate chain against a trusted root
4. Extract and verify the message imprint (hash algorithm OID + hash value) matches the submitted digest
5. Check the TSA's timestamp value and status info

The current implementation returns `True` if the 32-byte SHA-256 digest appears anywhere in the token bytes. This could produce **false positives** — the digest could coincidentally appear in embedded certificates, padding, or other ASN.1 structures within the token. Conversely, a TSA that uses a different hash encoding or includes the digest in a non-contiguous structure would produce false negatives.

## Impact

The entire timestamping feature (Plan 012) provides **no actual integrity guarantee**. A corrupted, forged, or replayed token would pass verification if it happens to contain the right 32 bytes. The `replay(verify_timestamps=True)` check compounds this (BC-226) — it only checks batch coverage, not token integrity.

## Recommendation

Replace the substring search with proper PKCS#7/CMS parsing. Options:
1. Use `asn1crypto` or `pyasn1` to parse the TSA response
2. Use `cryptography` library's CMS verification
3. At minimum, parse the `TSTInfo` structure to extract and compare the embedded hash

If full TSA verification is out of scope, document that `verify_tsa_token` is a heuristic check, not a cryptographic proof.

## Files

- `src/substrate/_timestamping.py:128-137`
