# Event-Log Retention and Archival (Plan 028)

## Overview

Regista's event log is an append-only, hash-chained record. As the log grows,
operators need a way to retire old events to cold storage without breaking the
cryptographic chain that replay relies on. Plan 028 introduces **segments**:
sealed, verifiable ranges of the global event chain that can be archived while
preserving chain continuity.

## Segment / Seal Model

A **segment** is a contiguous range of events in the global chain, defined by
`first_global_seq` … `last_global_seq`. When a segment is **sealed**:

1. The events in the range are read in `global_seq` order.
2. Both the **global chain** (`prev_global_event_hash` links) and the
   **per-work-item chains** (`prev_event_hash` links) are verified.
3. The segment's `head_hash` is computed as `SHA-256(canonical_envelope ‖ signature)`
   of the last event in the range.
4. The segment's `first_event_prev_hash` captures the `prev_global_event_hash`
   of the first event — the hash the first event chains from.
5. A canonical seal payload is built and signed with the project's active key
   (`entity_kind="segment"`).
6. An `event_segments` row is inserted, and a signed `segment_sealed` event is
   appended to the events table in the same transaction. The seal event becomes
   part of the auditable event log.

### Key columns in `event_segments`

| Column | Description |
|---|---|
| `segment_id` | UUID primary key |
| `first_global_seq` / `last_global_seq` | Range of global sequence numbers |
| `first_event_id` / `last_event_id` | UUIDs of the boundary events |
| `first_event_prev_hash` | The global-chain hash the first event chains from |
| `head_hash` | Hash of the last event's envelope + signature |
| `event_count` | Number of events in the segment |
| `seal_signature` | HMAC/Ed25519 signature over the canonical seal payload |
| `seal_event_id` | The `segment_sealed` event in the events table |
| `archive_path` | Optional cold-storage path |
| `archived` | Whether the events have been moved to `events_archive` |

## Chain Preservation

The global hash chain is a linked list: each event's `prev_global_event_hash`
points to the hash of the previous event's `canonical_envelope + signature`.
When events are archived (moved to `events_archive`), they leave a gap in the
live `events` table. Without bridging, replay's chain walk would hit a dead end
and emit `replay.global_chain_orphan` warnings.

### Segment Bridging in Replay

`_verify_global_hash_chain` accepts an optional `segments` list. When the walk
reaches a dead end (no successor for the current head hash), it checks whether
any segment's `first_event_prev_hash` matches the current head. If so, the walk
jumps to `segment.head_hash` and continues from there. This bridges across
archived ranges without false-positive orphan warnings.

### Verification

`verify_segment(segment_id)` re-reads the events in the segment range (from
`events` or `events_archive` depending on the `archived` flag), re-verifies both
chain types, recomputes the `head_hash`, and compares it with the stored value.
The result includes per-check booleans so operators can diagnose which part
failed.

## CLI

```bash
# Seal all events older than a cutoff timestamp
regista archive seal --before-timestamp 2025-01-01T00:00:00Z

# Dry-run (compute without writing)
regista archive seal --before-timestamp 2025-01-01T00:00:00Z --dry-run

# With an archive storage path
regista archive seal --before-timestamp 2025-01-01T00:00:00Z --archive-path s3://bucket/proj

# Verify a sealed segment
regista archive verify <segment_id> --json

# List segments (optionally filter by archived status)
regista archive list --archived true --limit 50
```

## API

```python
sub.archive.seal(before_timestamp, *, dry_run=False, archive_path=None) -> dict
sub.archive.verify(segment_id) -> dict
sub.archive.list_segments(archived=None, limit=100) -> list[dict]
sub.archive.archive_events(before_timestamp, *, dry_run=False) -> int  # existing
```

## Current Implemented Scope

- **Sealing**: events from **terminal work-items only** are verified, a
  segment record is created, and a signed `segment_sealed` event is appended.
  Events remain in the live `events` table. Non-terminal work-items' events are
  never sealed — this is the retention guardrail (WI-2.1): never archive an
  event a live work-item references.
- **Cross-segment chain bridging**: per-work-item chains that span seal
  boundaries are accepted — the first in-slice event for an entity may have a
  non-null `prev_event_hash` that references an event in a prior segment
  (cross-segment bridge). The intra-segment chain is still verified.
- **Non-contiguous global chains**: with terminal-only sealing, the selected
  events may not form a single contiguous global chain (events from
  non-terminal work-items create gaps). `_verify_global_chain` accepts bridge
  points: events whose `prev_global_event_hash` does not match any event within
  the segment are treated as chain-fragment starts linking from outside.
- **Verification**: re-reads events by stored `event_ids` (not global_seq
  range) and re-checks chain integrity and head hash. This avoids
  false-positive failures from overlapping ranges when segments are
  non-contiguous.
- **Replay bridging**: `_verify_global_hash_chain` uses segment records to
  bridge across archived ranges, preventing false orphan warnings.
- **Listing**: `list_segments` supports filtering by `archived` status and
  includes `work_item_ids`.

### Not Yet Implemented

- **Physical archival (WI-1.2)**: moving events from `events` to
  `events_archive` and setting `archived = TRUE` on the segment. The existing
  `archive_events` function moves events but does not yet integrate with
  segment records. Offline archive bundle export and `regista verify --archive`
  are not implemented.
- **Retention policy (WI-2.1 compliance-minimum)**: the terminal-only
  guardrail prevents sealing live work-items' events, but a per-project
  compliance-retention minimum window (e.g., "keep hot: last N days") is not
  yet configurable. The current guardrail is work-item-state-based, not
  time-window-based.
- **Segment deletion**: removing a segment and its archived events after a
  retention TTL.
- **Sidecar routes**: HTTP endpoints for seal/verify/list_segments.
- **InMemoryRegista**: segment operations are Postgres-only; the in-memory
  backend does not implement sealing.
- **Replay bridging across non-contiguous segments**: the replay bridge logic
  uses `first_event_prev_hash` and `head_hash` to jump across archived ranges.
  With terminal-only sealing, segments may be non-contiguous (global_seq
  ranges can overlap), so the bridge may not resolve correctly when physical
  archival is implemented. This is a known limitation to address before
  enabling archival.

### Known Limitation: Terminal-Only Sealing and Non-Contiguous Ranges

Segment sealing selects events from **terminal work-items only** — work-items
whose `current_state` is a declared terminal state in their pinned workflow
version. This implements the retention guardrail (never seal an event a live
work-item references) and prevents the spanning-entity bug where a work-item's
history is split across seal boundaries.

Because non-terminal work-items' events are excluded, the selected events may
not form a single contiguous global chain. The segment's
`first_global_seq` … `last_global_seq` range is the min/max of included events,
but events from non-terminal work-items (or events from other segments' work-
items) may fall within this range. To handle this:

- `_verify_global_chain` accepts **bridge points**: events whose
  `prev_global_event_hash` does not match any event within the segment are
  treated as chain-fragment starts that link from outside the segment.
- `_verify_work_item_chains` accepts **cross-segment bridges**: the first
  in-slice event for an entity may have a non-null `prev_event_hash` that
  references an event in a prior segment. The intra-segment chain is still
  verified for subsequent events.
- `verify_segment` reads events by stored `event_ids` (not global_seq range)
  to avoid including events from other segments or non-terminal work-items.

Deduplication (preventing re-sealing of already-sealed work-items) uses the
`work_item_ids` column on `event_segments`: a work-item already listed in any
segment's `work_item_ids` is excluded from future seals.

**Important:** sealing a terminal work-item finalizes its event stream. Events
appended after sealing (e.g., claim lifecycle, hooks, links) will not be
included in any future segment. Operators should ensure all post-terminal
activity is complete before sealing. Seal events themselves
(`entity_kind = 'segment'`) are never included in segments — they remain in
the hot log as the audit trail for archival itself.

Concurrent seal calls are serialized via `LOCK TABLE event_segments IN
EXCLUSIVE MODE` at the start of each `seal_segment` transaction.
