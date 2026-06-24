---
number: "305"
title: Malformed ed25519 witness public key could crash delivery or bypass co-signature verification
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-06-24"
tags: [witness, ed25519, security, signing]
related: ["303", "297"]
---

## Description

`Ed25519Scheme.verify()` constructed `nacl.signing.VerifyKey(key_material)`
without exception handling for malformed keys. If an ed25519 witness was
registered with a public key that was not exactly 32 bytes (e.g., via direct
database manipulation bypassing application validation), delivery would crash
with an unhandled `ValueError`. In addition, `register_witness()` and the
corresponding migration only required `public_key IS NOT NULL` for ed25519;
nothing validated the key length.

## Impact

An attacker with database write access could insert a malformed ed25519 public
key and cause all witness delivery to abort before processing other witnesses.

## Resolution

- `Ed25519Scheme.verify()` now catches `ValueError`, `TypeError`, and broad
  exceptions from both `VerifyKey()` and `verify_key.verify()`, returning
  `False` safely.
- `register_witness()` rejects ed25519 public keys that are not exactly 32 bytes.
- `InMemoryRegista.register_witness()` applies the same length check.
- Migration `032_witness_asymmetric_keys.sql` adds a CHECK constraint requiring
  `public_key IS NOT NULL` for ed25519 witnesses.
- Added tests for short-public-key verify and short-key registration rejection.

## Files

- `src/regista/_signing_scheme.py`
- `src/regista/_witness.py`
- `src/regista/_in_memory.py`
- `migrations/032_witness_asymmetric_keys.sql`
- `tests/test_witness_integration.py`
- `tests/test_bc214_216_217_218.py`
