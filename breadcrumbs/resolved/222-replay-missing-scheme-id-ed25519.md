---
number: "222"
title: Replay _EVENT_FIELDS missing scheme_id — Ed25519 events always verified with HMAC
severity: high
status: implemented
kind: bug
author: session-52
date: "2026-05-24"
tags: [plan-011, replay, signing]
---

## Problem

`_replay.py` `_EVENT_FIELDS` tuple did not include `scheme_id`. The Postgres replay SELECT query fetched all columns *except* `scheme_id`. Line 296 used `evt.get("scheme_id", "hmac-sha256")` as fallback, which always returned `"hmac-sha256"` because the key was never in the dict.

**Impact:** Any Ed25519-signed event would fail signature verification during Postgres replay because the HMAC scheme would be used to verify an Ed25519 signature. This is a silent-correctness bug — replay would halt with `REPLAY_HALTED` and no clear diagnostic.

Additionally, `Ed25519Scheme.verify()` called `nacl.signing.VerifyKey(key_material)` directly, but the replay path passes `key_entry.secret` (the 32-byte private key seed), not the public key. This caused `nacl.exceptions.ValueError: The seed must be exactly 32 bytes long` or forged-signature errors depending on the key bytes.

## Resolution

1. Added `scheme_id` to `_EVENT_FIELDS` in `_replay.py` (matching `_events.py`).
2. Added `verify_key` resolution in both `_replay.py` and `_in_memory_replay.py`: for Ed25519 events, use `key_entry.public_key` when available, falling back to `key_entry.secret`.
3. Added `encoding: "base64"` and `public_key` to Ed25519 test key files.
4. Added `get_scheme` and `available_schemes` re-exports to `_testing.py`.

## Files

- `src/substrate/_replay.py` — `_EVENT_FIELDS`, replay key resolution
- `src/substrate/_in_memory_replay.py` — replay key resolution
- `src/substrate/_signing_scheme.py` — `Ed25519Scheme.verify()` uses `VerifyKey`
- `src/substrate/_testing.py` — re-exports
- `tests/test_signing_ed25519.py` — 10 integration tests covering this exact scenario
- `tests/test_keys_ed25519.json` — fixed with base64 encoding + public_key
