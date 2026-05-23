---
number: "219"
title: "validate_delegation_chain ignores session_id despite it being a declared DelegationChain field"
severity: medium
status: implemented
kind: bug
author: external-review-r3
date: "2026-05-23"
tags: [delegation, validation, schema-drift, identity]
related: ["197", "214"]
---

## Resolution

Extended `validate_delegation_chain()` to validate `session_id`, `expires_at`, and `session_grant_event_id` (all optional non-empty strings when present). Updated `DelegationChain` dataclass with the two new fields, preserving round-trip serialization. 24 new tests pass (845 total).

# BC-219 — validate_delegation_chain ignores session_id

## Problem

`_types.py:DelegationChain` at line 64-88 declares `session_id: str |
None = None` as a typed field. `_contract.py:validate_delegation_chain()`
at line 582-613 validates:

- `principal_id` (line 590): required, non-empty string
- `scope` (line 596): optional list of strings
- `authenticated_at` (line 608): optional string

It does **not** validate `session_id`. Any value passes through:
integer, list, malformed UUID, raw bytes — all accepted. The field is
included in the canonical envelope at `_signing.py:22` and is
integrity-protected by the HMAC, so the *value* is tamper-evident, but
the *shape* is unvalidated.

This is a schema drift between `_types.py` (which promises a typed
field) and `_contract.py` (which doesn't enforce it). It matters for
two reasons:

1. **Round-3 Q11 session-grant mechanism.** A session grant event
   carries `session_id` linking actions to a delegation grant. If the
   verifier cannot trust the shape of `session_id`, it cannot reliably
   resolve grants.
2. **Schema drift creates confusion.** An auditor reading
   `DelegationChain` source code sees a typed field that doesn't exist
   in practice. Validators added later may accidentally reject events
   with currently-allowed malformed `session_id` values, creating
   silent migration problems.

## Proposed fix

Extend `validate_delegation_chain()`:

```python
session_id = on_behalf_of.get("session_id")
if session_id is not None:
    if not isinstance(session_id, str) or not session_id:
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            "on_behalf_of.session_id must be a non-empty string when present",
        )
```

Round 3 also identified that the schema needs two new optional fields
to support the session-grant topology:

```python
expires_at = on_behalf_of.get("expires_at")
if expires_at is not None and not isinstance(expires_at, str):
    raise SubstrateError(...)

session_grant_event_id = on_behalf_of.get("session_grant_event_id")
if session_grant_event_id is not None:
    if not isinstance(session_grant_event_id, str):
        raise SubstrateError(...)
```

These fields are not required for current callers (existing events
won't carry them); they are reserved hooks for the v2 session-grant
implementation.

## Dependencies

- **Independent.** Pure validation fix.
- **Required hook for v2 session-grant work** (agent-wake's Q11
  implementation).
- **Composes with BC-214.** Both touch the validation/signing
  contract, but they don't conflict.

## Timing

Small. Can land anytime.
