---
number: "311"
title: "Replay verify_event call omits chain fields — stored envelope is the only matching candidate for chained events"
severity: medium
status: resolved
kind: bug
author: adversarial-review (BC-308 GLM review)
date: "2026-06-26"
tags: [signing, replay, verify, chain-fields]
related: ["308", "233"]
---

## Resolution

Fixed — `prev_event_hash` and `prev_global_event_hash` are now forwarded from
the event row to `verify_event()` in both replay paths (`_replay.py` and
`_in_memory_replay.py`). This allows freshly-built v3/v4 candidate envelopes to
include chain fields and match correctly, reducing sole reliance on the stored
envelope.

**Important correction:** `global_seq` was intentionally NOT forwarded. Spec
§17.11 states "global_seq is assigned post-signing and is NOT in the signed
envelope." Passing it would cause freshly-built candidates to include it when
the original signed envelope doesn't, making them never match. Only
`prev_event_hash` and `prev_global_event_hash` (which ARE in the signed
envelope v3/v4) are forwarded.

`verify_event_with_public_key()` was already correct (passed
`prev_event_hash` and `prev_global_event_hash` but not `global_seq`). 2
regression tests added (Postgres + InMemory) that null out `canonical_envelope`
for a chained event and assert replay succeeds.
---

## Problem

`_replay.py:594` and `_in_memory_replay.py:210` call `verify_event()` without passing `prev_event_hash`, `global_seq`, or `prev_global_event_hash`. This means `has_chain_fields` is always `False` in the replay path.

For chained events (which have `prev_event_hash` in the stored envelope), the only way verification succeeds is if `stored_envelope` is present and matches. The freshly-built v3/v4 candidates are constructed without chain fields, so they cannot match a chained event's signature.

If the stored envelope is ever missing or corrupted (e.g., database corruption, migration error), verification will fail with no fallback — even though the event's chain fields are available in the event row and could be forwarded to `verify_event` to build a correct candidate.

## Impact

- **Correctness**: A missing `canonical_envelope` column value for any chained event will cause replay to halt with "Signature verification failed" — even though the event is legitimate and all fields needed to reconstruct the correct envelope are present in the row.
- **BC-308 amplification**: BC-308's filtering makes this more consequential because the filtering logic now depends on `stored_ver` being accurate, and the stored envelope is the sole path to a correct classification.

## Fix

Pass the chain fields from the event row to `verify_event` in both replay paths:

```python
verify_event(
    ...
    prev_event_hash=evt.get("prev_event_hash"),
    global_seq=evt.get("global_seq"),
    prev_global_event_hash=evt.get("prev_global_event_hash"),
)
```

This allows freshly-built v3/v4 candidates to include chain fields and match correctly, reducing sole reliance on the stored envelope.

Note: `verify_event_with_public_key()` (line 431 of `_signing.py`) already passes `prev_event_hash` and `prev_global_event_hash` but not `global_seq`. This inconsistency should also be addressed.
