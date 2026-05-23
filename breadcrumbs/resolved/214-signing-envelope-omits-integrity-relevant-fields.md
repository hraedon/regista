---
number: "214"
title: "Signing envelope omits integrity-relevant fields (timestamp, key_id, event_seq, workflow_name, workflow_version)"
severity: high
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [signing, integrity, identity, bc-196-dep]
related: ["196", "197", "198", "215", "216", "220"]
---

# BC-214 — Signing envelope omits integrity-relevant fields

## Problem

`build_signing_envelope()` at `_signing.py:10-26` canonicalizes and signs
`event_id`, `work_item_id`, `actor_id`, `on_behalf_of`, `transition`, and
`payload`. Several fields that *are* on the `Event` dataclass at
`_types.py:91-108` are NOT included in the signed envelope:

- `timestamp` — set at `_event_store.py:88` (`datetime.now(UTC)`) for the
  InMemory backend, or by the Postgres column default for the Postgres
  backend (see BC-220). Either way, set after `sign_event()` runs.
- `key_id` — set at `_event_store.py:72` from `key_entry.key_id` after
  signing. Stored on the event but outside the signature.
- `event_seq` — allocated at `_event_store.py:58` before signing but
  excluded from the envelope.
- `workflow_name` and `workflow_version` — fields on the `Event`
  schema but not included in the canonical envelope.

Under HMAC, these gaps are moot: an attacker who has the HMAC secret can
forge anything. Under Ed25519 (BC-196), each becomes a concrete attack
vector against an event store an attacker has write access to:

- **`timestamp` swap:** operator backdates an event to predate a
  revocation timestamp; signature still verifies.
- **`key_id` swap:** operator changes the recorded signing key on an
  event; signature verification fails confusingly (looks like a
  signature mismatch, not a clear forgery), and an offline verifier
  cannot reconstruct which actor was responsible.
- **`event_seq` swap:** operator reorders two events to change the
  apparent sequence of tool calls; both signatures still verify.
- **`workflow_name` swap:** operator replays a signed payload from one
  workflow into a different workflow; signature still verifies, but the
  semantic meaning changes.

These were independently identified by three round-3 reviewers (GLM-5.1,
Gemini 3.5 Flash, MiMo-V2.5-Pro) reviewing the agent-wake identity design.

## Proposed fix

Add all five fields to `build_signing_envelope()`. The canonical JSON
becomes:

```python
envelope = {
    "event_id": str(event_id),
    "work_item_id": str(work_item_id),
    "actor_id": actor_id,
    "key_id": key_id,
    "event_seq": event_seq,
    "workflow_name": workflow_name,
    "workflow_version": workflow_version,
    "timestamp": timestamp,
    "on_behalf_of": on_behalf_of,
    "transition": transition,
    "payload": payload,
}
```

Backward compatibility uses the same pattern as the existing
`on_behalf_of` retry path at `_signing.py:92-98`: if verification with
the new fields fails and the event predates this change, retry with the
old envelope shape. Once all production events carry the new fields,
the retry path can be removed.

## Dependencies

- **Depends on BC-220.** The timestamp source must be unified between
  InMemory and Postgres backends before it can be meaningfully signed.
- **Blocks BC-196 implementation.** Without these fields in the
  envelope, asymmetric signing inherits the same gaps under a
  stronger threat model.
- **Related to BC-198** but does not block it. BC-198 Layer 1 (RFC 3161
  timestamping) operates over the Merkle root of an event batch; it
  works whether the per-event envelope covers `timestamp` or not.
  However, the per-event temporal integrity that BC-198's Layer 1
  anchors against benefits significantly from this fix.

## Timing

There is no production deployment. The cost of breaking backward compat
is bounded to test fixtures. Window for change is now.
