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

- **Sealing**: events are verified, a segment record is created, and a signed
  `segment_sealed` event is appended. Events remain in the live `events` table.
- **Verification**: re-reads events from the live or archive table and
  re-checks chain integrity and head hash.
- **Replay bridging**: `_verify_global_hash_chain` uses segment records to
  bridge across archived ranges, preventing false orphan warnings.
- **Listing**: `list_segments` supports filtering by `archived` status.

### Not Yet Implemented

- **Physical archival**: moving events from `events` to `events_archive` and
  setting `archived = TRUE` on the segment. The existing `archive_events`
  function moves events but does not yet integrate with segment records.
- **Segment deletion**: removing a segment and its archived events after a
  retention TTL.
- **Sidecar routes**: HTTP endpoints for seal/verify/list_segments.
- **InMemoryRegista**: segment operations are Postgres-only; the in-memory
  backend does not implement sealing.

### Known Limitation: Timestamp-Based Selection Under Concurrency

Segment sealing selects events by `before_timestamp` and skips events already
covered by existing segments (using `MAX(last_global_seq)` as a high-water
mark). Under high concurrency, the `global_seq` sequence (`CACHE 100`) can
allocate numbers out of actual append order, so `global_seq` order may diverge
from the true chain-link order established by `prev_global_event_hash`. This
means a segment could theoretically include an event whose chain predecessor
falls outside the segment range, causing `verify_segment` to report a chain
break. In practice this is rare — the `event_chain_head` row lock serializes
appends, and the `CACHE 100` window is small relative to typical batch sizes.
Operators should avoid sealing very small segments under sustained concurrent
load.
