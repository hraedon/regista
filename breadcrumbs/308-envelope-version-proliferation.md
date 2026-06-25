---
number: "308"
title: "Four signing envelope versions with complex backward-compat retry — correctness minefield"
severity: medium
status: proposed
kind: design
author: structural-review
date: "2026-06-25"
tags: [signing, integrity, envelope, verify]
related: ["296", "233"]
---

## Problem

`_signing.py` contains four envelope builder functions:

- **v1** (`build_signing_envelope`): minimal — event_id, work_item_id, actor_id,
  transition, payload, on_behalf_of
- **v2**: adds key_id, event_seq, workflow_name/version, timestamp
- **v3**: adds prev_event_hash, global_seq, prev_global_event_hash (still
  uses work_item_id; no entity generalization)
- **v4**: adds entity_kind, entity_id, hash_alg (replaces work_item_id
  with entity-aware fields for generalization)

`verify_event()` attempts up to 6+ envelope reconstructions in the worst case,
trying v4, v3, v2, v1, and bare-on_behalf_of variants. The branching depends on
`has_chain_fields`, `stored_ver`, and `stored_envelope` presence.

`sign_event()` always builds v4, which is correct. But the legacy
`_events.py` paths (`append_event`, `append_transition_event`) and the
`EventStore.append_event()` shared path all had subtle inconsistencies in
which fields they forwarded — Session 70 fixed `append_event`, this session
fixed `append_transition_event`. The `PostgresEventStore` path was correct
after 324db65.

## Risk

The verify path's multi-envelope retry creates ambiguity: the verifier cannot
tell from a stored envelope alone which version an old event was signed with,
and the backward-compat candidates mean a single event may validate against
multiple envelope reconstructions. This is a backward-compatibility feature
(legitimate old events must still verify), but the complexity makes it easy to
silently sign with the wrong envelope — as demonstrated by the near-misses
below. BC-296 partially addressed this by adding a v2 downgrade guard for
chained events, but the full verify path still tries v1/v2 for non-chained
events.

The real danger is not tamper acceptance (a v4-signed event cannot validate
against a v1/v2/v3 envelope because the HMAC is computed over different bytes),
but rather **developer confusion leading to silent mis-signing**: when a new
call site forgets to forward `entity_kind`/`hash_alg`, the default values
produce a valid v4 envelope that happens to match the work_item case — until
entity generalization expands and the defaults become wrong.

## Proposed Resolution

1. **Short-term**: Add a `signing_envelope_version` field to events (or derive
   from `canonical_envelope` via `classify_envelope_version`). Reject
   downgraded envelopes in `verify_event()` when the stored version is known.

2. **Medium-term**: Deprecate v1/v2/v3 envelope builders. Once all events in
   production databases are v4 (after a migration/replay cycle), remove the
   backward-compat candidates from `verify_event()`. Keep `classify_envelope_version()`
   for forensic analysis of old events.

3. **Test hardening**: Add property-based tests that verify no tampered payload
   validates against any envelope version. Current tests verify that legit
   events validate, but don't systematically test rejection of subtly-wrong
   payloads across versions.

## Context

Session 69 reverted a `global_seq` regression. Session 70 found
`append_transition_event` was not forwarding `entity_kind`/`hash_alg` to
`sign_event()` (fixed this session). These near-misses confirm the complexity
is actively causing defects.
