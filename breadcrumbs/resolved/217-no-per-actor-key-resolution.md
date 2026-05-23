---
number: "217"
title: "KeySet has no per-actor / per-principal key resolution; one shared keyring"
severity: high
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [keys, multi-user, identity, bc-196-dep]
related: ["196", "216", "218"]
---

# BC-217 — No per-actor / per-principal key resolution

## Problem

`_keys.py:KeySet` is a single shared keyring. `active_key()` at line
149-164 returns *the* one active key. `sign_event()` callers use
`active_key()` implicitly via `_event_store.py:append_event()`.

This means:

- Every actor in the system signs with the same key.
- The `actor_id` field in the signing envelope (`_signing.py:13`) is
  purely conventional — anyone holding the key can claim any
  `actor_id`. Self-attested by design under HMAC (BC-101 acknowledges
  this).
- A multi-user deployment cannot give each user their own key.
- A multi-device user (one human, multiple machines) has no way to
  bind multiple active keys to the same principal.
- The agent-key-vs-human-key topology (round 3 Q11) cannot be
  implemented — there's no way to resolve "the human's key" vs "the
  agent's session key" given a principal_id.

Round-3 reviewers (Qwen, Kimi, Gemini) independently flagged the
single-active-key model as fundamentally incompatible with multi-user
identity.

A latent bug, noted by Deepseek (round 3): `_keys.py:89-95` loads every
key from the JSON array regardless of status, but `new_active = first
key with status='active'` only picks one. Multiple active keys are
already loaded into the dict (and addressable via `get_key()`); only
`active_key()` returns just one. This means the *storage* of multiple
active keys is already supported — only the *resolution* is missing.

## Proposed fix

1. Add `principal_id: str | None = None` to `KeyEntry` (see BC-216).
2. Add `KeySet.active_keys_for(principal_id: str) -> list[KeyEntry]`.
   Returns all active keys bound to a given principal.
3. Add `KeySet.resolve_signing_key(actor_id: str) -> KeyEntry`. The
   resolution policy:
   - If `actor_id` is a `principal_id`, return the first active key
     for that principal.
   - If `actor_id` is opaque (no principal binding), fall back to
     `active_key()` (current behavior).
4. Add an optional `key_id` parameter to `append_event()` that
   overrides automatic resolution. Useful for tooling that needs to
   sign with a specific key (recovery key, session-grant key,
   auditor key).

The current `active_key()` semantics are preserved for the single-key
case (no `principal_id` set on any KeyEntry → behaves as today).

## Dependencies

- **Depends on BC-216.** `principal_id` field on `KeyEntry` needs to
  exist before per-principal resolution makes sense.
- **Depends on BC-196** for the full security value. Under HMAC, this
  is structural-only (every "principal" still shares the secret if
  configured that way). Under Ed25519, per-principal keys are
  cryptographically separate.
- **Enables BC-218 enforcement.** Role gating (auditor keys can't
  sign actions) requires the verifier to resolve which key signed
  which event.

## Timing

Lands with BC-216, or shortly after. The `key_id` override on
`append_event()` and `transition()` is exposed at the library level.
HTTP sidecar request models defer the `key_id` parameter until BC-218
role enforcement lands, so the network surface is not widened without
the policy gate.

## Resolution note

All four changes (BC-214, BC-216, BC-217, BC-218) landed in a single
session. 821 tests pass; 18 new tests added in
`tests/test_bc214_216_217_218.py`. Sidecar deferral tracked here.
