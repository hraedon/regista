---
number: "215"
title: "Key revocation has no temporal dimension (no revoked_at); revoked keys invalidate historical events"
severity: medium
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [keys, revocation, identity, audit]
related: ["196", "197", "214", "218"]
---

## Resolution

`KeyEntry.revoked_at` was already added and wired. Session 49 added comprehensive boundary tests: exact equality rejection, predates acceptance, absent-field fallback, and mixed scenarios. All 24 new tests pass (845 total).

# BC-215 — Key revocation has no temporal dimension

## Problem

`_keys.py:KeyEntry` at line 17-20 has `status: str` with values
`active`, `deprecated`, `revoked`. `verify_key_status()` at line 166-175
rejects revoked keys unconditionally:

```python
if entry.status == "revoked":
    raise SubstrateError(ErrorCode.REVOKED_KEY_ID, ...)
```

There is no `revoked_at` field. Once a key is marked revoked, the
verifier cannot distinguish "this event was signed before the key was
compromised" from "this event was signed after compromise and is
forged." Both are rejected. This breaks historical-event verification
for any rotation event, audit bundle, or offline verifier that needs to
replay a log spanning a revocation.

For a workplace-audit use case: if a key is compromised in March and
revoked in April, events signed in January through February are valid
and should remain verifiable. The current model treats all of them as
invalid.

## Proposed fix

Add `revoked_at: str | None = None` to `KeyEntry`. Honor it in
`verify_key_status()`:

```python
def verify_key_status(self, key_id: str, event_timestamp: str | None = None) -> KeyEntry:
    entry = self.get_key(key_id)
    if entry.status == "revoked":
        if event_timestamp is None or entry.revoked_at is None:
            # No temporal context — fail closed (current behavior).
            raise SubstrateError(ErrorCode.REVOKED_KEY_ID, ...)
        if event_timestamp >= entry.revoked_at:
            raise SubstrateError(ErrorCode.REVOKED_KEY_ID, ...)
        # event predates revocation — accept with warning.
    return entry
```

JSON schema for the key file gains `revoked_at` as an optional ISO 8601
string. Default `None` is backward-compatible (current behavior
preserved when `revoked_at` is absent).

## Dependencies

- **Standalone.** Does not depend on BC-196 or any other open BC.
- **Required for BC-214 to be useful for historical verification.**
  Without `revoked_at`, the signed `timestamp` on an event has no
  point of comparison for revocation validity.
- **Touches BC-218** if implemented together — the `KeyEntry`
  dataclass should gain `role` and `revoked_at` in one change.

## Timing

Small, additive change. Can land independently. Window is open.
