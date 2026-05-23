---
number: "216"
title: "KeyEntry data model is HMAC-shaped; blocks asymmetric signing"
severity: high
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [keys, bc-196-blocker, asymmetric, identity]
related: ["196", "214", "215", "217", "218"]
---

# BC-216 — KeyEntry data model is HMAC-shaped

## Problem

`_keys.py:KeyEntry` at line 17-20 is three fields:

```python
@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    secret: bytes
    status: str
```

This data model cannot express:

- **Public key material.** There is no `public_key` field. For
  asymmetric signing (BC-196), the verifier needs the public key
  separately from the signing material.
- **Algorithm.** `secret: bytes` cannot distinguish an HMAC shared
  secret from an Ed25519 private key. The same field stores
  algorithm-specific bytes with no discriminator.
- **Key fingerprint.** No `fingerprint()` method. There is no
  canonical way to derive a stable identifier from the key material.

The base64-decoding gap noted by Kimi (round 3) makes this concrete:
`_keys.py:85-88` does:

```python
secret = entry["secret"]
if isinstance(secret, str):
    secret = secret.encode("utf-8")
```

For HMAC, this UTF-8-encodes a hex or ASCII password. For Ed25519,
the natural representation of a 32-byte private key is base64-encoded
in JSON. The current code would UTF-8-encode the base64 string rather
than decoding it — silently producing the wrong key bytes.

## Proposed fix

Restructure `KeyEntry` to be algorithm-aware:

```python
@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    alg: str                          # "HMAC-SHA256" | "Ed25519" | ...
    secret: bytes                     # signing material (alg-specific)
    public_key: bytes | None = None   # public verification material (asymmetric only)
    status: str = "active"
    role: str = "actor"               # see BC-218
    revoked_at: str | None = None     # see BC-215
    principal_id: str | None = None   # see BC-217
```

The key file JSON schema gains `alg`, `public_key` (optional, base64),
and explicit `encoding: "base64" | "utf8" | "hex"` for `secret`. The
`_load()` method dispatches on encoding to produce the correct bytes.

`fingerprint()` becomes a method on `KeyEntry`:

```python
def fingerprint(self) -> str:
    if self.alg == "HMAC-SHA256":
        return f"hmac:sha256:{hashlib.sha256(self.secret).hexdigest()}"
    if self.alg == "Ed25519":
        return f"ed25519:sha256:{hashlib.sha256(self.public_key).hexdigest()}"
    raise SubstrateError(...)
```

## Dependencies

- **Direct dependency of BC-196.** BC-196's acceptance criteria
  require an `alg` discriminator and a pluggable signer interface.
  This BC is the data-model piece of that.
- **Required for BC-217.** Per-principal key resolution needs a
  `principal_id` binding on each KeyEntry.
- **Couples with BC-218.** The `role` field should be added in the
  same `KeyEntry` change.
- **Indirectly enables BC-214.** The `key_id` going into the signing
  envelope is more useful when keys carry algorithm metadata.

## Timing

Lands with or immediately before BC-196 implementation. The fields can
be added now with `alg: str = "HMAC-SHA256"` as the default, allowing
existing key files to continue working unchanged.
