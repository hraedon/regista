---
number: "220"
title: "Event timestamp clock source diverges between InMemory and Postgres backends"
severity: medium
status: implemented
kind: bug
author: external-review-r3
date: "2026-05-23"
tags: [timestamp, integrity, backend-parity, bc-214-precondition]
related: ["214", "198"]
---

## Resolution

Removed `RETURNING timestamp` from Postgres INSERT in `append_event` and `append_transition_event` (_events.py). Removed `RETURNING timestamp` from `PostgresEventStore.append` (_event_store.py). The client-side `now = datetime.now(UTC)` is already computed before signing (BC-214) and is now passed explicitly into the INSERT and returned unchanged in the `Event` constructor. The DB column default is preserved as a safety net. 24 new tests pass (845 total).

# BC-220 — Event timestamp clock source diverges between backends

## Problem

The event timestamp has two different sources depending on backend:

**InMemoryEventStore:** `_event_store.py:88` sets `now =
datetime.now(UTC)` in the application process. This is the client's
clock.

**PostgresEventStore:** `PostgresEventStore.append()` at lines 250-330
omits `timestamp` from the INSERT column list. The database column has
a default of `now()` (or equivalent), so the *database server's* clock
sets the timestamp. The code then does `INSERT ... RETURNING
timestamp` (around line 323) and constructs an `Event` with the
returned value — discarding the client-side `now` from line 88.

Three round-3 reviewers (MiMo, Kimi, GLM) independently identified
this. The implications:

- Two deployments running the same code produce timestamps from
  different clock sources, depending on backend.
- The client-side `now` at `_event_store.py:88` is computed and then
  discarded in the Postgres path — dead code that misleads readers
  into thinking the application clock is authoritative.
- For BC-214 (`timestamp` in signing envelope), the question of *which*
  timestamp is signed becomes ambiguous. The client-side value? The
  DB-assigned value? They differ if clocks drift.

For an audit-credible deployment, the operator may control both the
application server and the database server clocks. Different attacks
require different clocks: backdating wants the application clock to be
trusted by the verifier; reordering wants the DB clock to control the
sequence number.

## Proposed fix

Unify the timestamp source. Recommended: client-generated timestamp,
explicitly written to the database INSERT.

```python
# _event_store.py:append_event (both backends)
now = datetime.now(UTC)
timestamp_iso = now.isoformat()

signature, canonical_hash, envelope = sign_event(
    ...
    timestamp=timestamp_iso,  # NEW (per BC-214)
)

# PostgresEventStore: include timestamp explicitly
INSERT INTO events (..., timestamp, ...)
VALUES (..., %s, ...)
```

The DB column default is preserved as a safety net but should never
fire in normal operation (every INSERT now provides the timestamp).

For deployments that want the DB server's clock as authoritative (e.g.,
trust the DB but not the application server), the configuration can
opt into the existing behavior. The default is client-clock.

## Dependencies

- **Precondition for BC-214.** Without a unified, predictable
  timestamp source, signing the timestamp produces inconsistent
  results across backends.
- **Independent of BC-196.** Pure backend-parity fix.
- **Composes with BC-198 Layer 1.** RFC 3161 anchoring provides an
  external clock that doesn't depend on this fix, but per-event
  temporal integrity benefits from a unified internal clock too.

## Timing

Must land with or before BC-214. Small change.
