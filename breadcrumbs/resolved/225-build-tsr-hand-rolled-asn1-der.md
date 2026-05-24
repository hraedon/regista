---
number: "225"
title: "_build_tsr hand-rolled ASN.1 DER encoding is fragile and incomplete"
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [timestamping, plan-012, rfc-3161, asn1]
related: ["223", "229"]
---

# BC-225 — _build_tsr hand-rolled ASN.1 DER encoding is fragile

## Problem

`_build_tsr` in `_timestamping.py:97-106` manually constructs an RFC 3161 TSA request using raw byte concatenation with hardcoded values:

```python
def _build_tsr(data: bytes, config: TSAConfig) -> bytes:
    algo_oid = b"\x06\x08\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    digest = hashlib.sha256(data).digest()
    algo_seq = b"\x30\x0d" + algo_oid + b"\x05\x00"
    digest_oct = b"\x04\x20" + digest
    mi_seq = b"\x30" + bytes([len(algo_seq) + len(digest_oct)]) + algo_seq + digest_oct
    req_info = b"\x30" + bytes([len(mi_seq) + 3]) + b"\x02\x01\x01" + mi_seq
    cert_req = b"\x01\x01\xff"
    total_len = len(req_info) + 3 + len(cert_req)
    return b"\x30" + bytes([total_len]) + req_info + b"\xa0\x03" + cert_req
```

### Specific issues:

1. **DER length encoding only handles lengths < 128.** The `bytes([len(...)])` pattern produces single-byte length octets. For SHA-256 the total request is ~62 bytes (works). But if `hash_algorithm` config is changed to SHA-384/SHA-512, the lengths could exceed 127 and produce invalid DER.

2. **No nonce included.** RFC 3161 §2.4.1 recommends a nonce to prevent replay attacks. Without it, a TSA server (or attacker) could return a cached response for a different request.

3. **Hardcoded SHA-256 OID.** The `algo_oid` is the OID for SHA-256 (`2.16.840.1.101.3.4.2.1`), but `TSAConfig.hash_algorithm` accepts arbitrary strings. The config field is ignored — the request always uses SHA-256 regardless of what's configured.

4. **No TSA response parsing.** The raw response bytes are stored as-is without parsing the PKCS#7 structure to extract the actual timestamp, serial number, or status. This makes downstream verification impossible (see BC-223).

5. **`tsa_cert_path` ignored.** The `TSAConfig.tsa_cert_path` field is accepted but never referenced (see BC-229).

## Impact

The timestamping feature is built on a hand-rolled ASN.1 encoder that doesn't properly implement RFC 3161. While it may work with some TSA servers for the SHA-256 case, it's brittle, non-standard, and provides no replay protection.

## Recommendation

Use a proper ASN.1 library (`asn1crypto`, `pyasn1`, or `cryptography`) to construct and parse TSA requests/responses. At minimum:
- Support proper DER length encoding for all hash algorithms
- Include a nonce
- Parse the PKCS#7 response to extract the timestamp and status
- Honor the `hash_algorithm` config field

## Files

- `src/substrate/_timestamping.py:97-106`
- `src/substrate/_timestamping.py:10-16` (TSAConfig)
