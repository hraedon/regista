---
number: "304"
title: KeySet.verify_key_status compared revoked_at and event_timestamp as plain strings
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-06-24"
tags: [keys, revocation, replay, timestamp]
related: []
---

## Description

`KeySet.verify_key_status` compared `event_timestamp` and `entry.revoked_at`
using Python string comparison. Both values are ISO 8601 strings, so the
ordering is mostly correct when formats match, but it is brittle when one value
omits microseconds or uses a different timezone suffix. It also raised
`TypeError` if a naive timestamp string was mixed with an aware one.

## Impact

Replay could incorrectly reject (or accept) events signed by a revoked key when
the timestamp formats differed. A `TypeError` would crash replay on malformed
key files.

## Resolution

- Both timestamps are now parsed with `datetime.fromisoformat()` after
  normalizing `"Z"` to `"+00:00"`.
- `ValueError` and `TypeError` during parsing are caught; the safe default is to
  treat the key as revoked for the event.

## Files

- `src/regista/_keys.py`
