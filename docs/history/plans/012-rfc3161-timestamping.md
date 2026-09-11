# Plan 012 — RFC 3161 Timestamping on Event Batches

**Status:** Draft RFC
**Owner:** regista
**Spec touched:** §17 (signing and integrity), §19 (public API surface)
**Related:** BC-198 (operator backdating defense), Plan 009 (MaintenanceThread), Plan 013 (witness hooks)

## 1. Overview

Adds trusted timestamp tokens from a third-party Time Stamp Authority (TSA) to event batches. Regista already HMAC-signs every event (FR-15), but the operator holding the HMAC key can theoretically backdate events. RFC 3161 TSA tokens provide independent, cryptographically-verifiable proof that a Merkle root over a batch of event IDs existed at a specific time.

Timestamping is **opportunistic and non-blocking.** Events are committed first, then batched and timestamped asynchronously by the maintenance thread. A missing timestamp is a warning, not an error — the event log remains complete and authoritative regardless of TSA availability.

## 2. Motivation

Regista's trust model (§17.9) has three tiers: authenticated (HMAC), server-stamped (timestamp, seq), and actor-claimed (metadata). The HMAC key holder is trusted. In multi-tenant or adversarial-operator scenarios, this trust is insufficient:

- A malicious operator with HMAC key access can insert events with arbitrary timestamps.
- An auditor examining the event log has no independent anchor to detect backdating.
- Agent-provenance workflows (pen-test tracking, regulatory compliance) require third-party time attestation.

RFC 3161 Time Stamp Tokens (TSTs) from a trusted TSA close this gap. The TSA attests that a particular hash existed at a particular time, and this attestation is independently verifiable using the TSA's certificate chain.

## 3. Design

### 3.1 Merkle tree batching

Events are batched by contiguous `event_seq` ranges across all work items. Each batch:

1. Collects all untimestamped events (those not covered by a confirmed or pending `tsp_batches` row).
2. Sorts their `event_id`s lexicographically (UUID bytes, big-endian).
3. Builds a SHA-256 Merkle tree over the sorted `event_id`s.
4. Submits the Merkle root to the TSA.
5. Stores the TSA's response (DER-encoded token) in `tsp_batches`.

The Merkle tree enables efficient inclusion proofs: given a batch and an event_id, an auditor can verify the event was part of that batch without revealing the full batch contents.

### 3.2 New module: `_timestamping.py`

```python
@dataclass(frozen=True)
class TSAConfig:
    tsa_url: str
    tsa_cert_path: str | None = None
    batch_size: int = 1000
    interval_seconds: float = 3600.0
    hash_algorithm: str = "sha256"

@dataclass(frozen=True)
class TimestampBatch:
    batch_id: UUID
    event_ids: list[UUID]
    merkle_root: bytes
    tsa_token: bytes | None
    tsa_timestamp: datetime | None
    submitted_at: datetime | None
    confirmed_at: datetime | None
    status: str  # pending | confirmed | failed

def compute_merkle_root(event_ids: list[UUID]) -> bytes:
    """SHA-256 Merkle tree root over sorted event_id bytes."""

def merkle_proof(event_ids: list[UUID], target: UUID) -> list[tuple[int, bytes]]:
    """Return the sibling hashes needed to verify `target` is in the tree."""

def submit_to_tsa(data: bytes, config: TSAConfig) -> bytes:
    """POST aTimeStampReq (DER) to the TSA. Returns DER-encodedTimeStampToken."""

def verify_tsa_token(
    token: bytes,
    data: bytes,
    config: TSAConfig,
) -> bool:
    """Verify a TSA token against the original data using the TSA's certificate."""
```

`submit_to_tsa` constructs an RFC 3161 `TimeStampReq` message:

```
version: 1
messageImprint: { hashAlgorithm: sha256, hashedMessage: <data> }
certReq: true
```

The response is parsed as a `TimeStampToken` (CMS SignedData). `verify_tsa_token` validates:
1. The CMS signature using the TSA's certificate (from `tsa_cert_path` or fetched from the token).
2. The imprint matches the submitted data hash.
3. The token time is within acceptable bounds (no future timestamps).

### 3.3 Merkle tree construction

Binary Merkle tree with SHA-256:

1. Sort `event_ids` by bytes (big-endian UUID representation).
2. Hash each `event_id` (16 bytes) to get leaf nodes: `SHA-256(event_id.bytes)`.
3. If odd number of leaves, duplicate the last leaf.
4. Pair adjacent nodes and compute `SHA-256(left || right)`.
5. Repeat until a single root remains.

The tree is deterministic given the same set of event_ids. Batch boundaries are defined by `event_seq` ranges, so the same events always produce the same Merkle root.

### 3.4 Batch lifecycle

```
                  ┌──────────┐
                  │ pending  │ ← created by maintenance thread
                  └────┬─────┘
                       │ submit to TSA
                 ┌─────┴──────┐
                 │            │
            ┌────▼────┐  ┌───▼────┐
            │confirmed│  │ failed │
            └─────────┘  └───┬────┘
                             │ retried next cycle
                             └──► back to pending (new row)
```

- **Pending**: `tsa_token` and `tsa_timestamp` are NULL. `submitted_at` is set when the TSA request is sent.
- **Confirmed**: TSA returned a valid token. `tsa_token`, `tsa_timestamp`, and `confirmed_at` are set.
- **Failed**: TSA returned an error or the token failed verification. `error_message` is set. The batch is retried on the next maintenance cycle by creating a new batch row for the same event range.

Failed batches do not block new event commits. The next cycle attempts a fresh batch covering the same (or extended) range.

## 4. Database Schema

Migration `014_tsp_batches.sql`:

```sql
CREATE TABLE tsp_batches (
    batch_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merkle_root    BYTEA NOT NULL,
    first_event_seq INTEGER NOT NULL,
    last_event_seq  INTEGER NOT NULL,
    first_event_at  TIMESTAMPTZ NOT NULL,
    last_event_at   TIMESTAMPTZ NOT NULL,
    event_count     INTEGER NOT NULL,
    tsa_token       BYTEA,
    tsa_timestamp   TIMESTAMPTZ,
    submitted_at    TIMESTAMPTZ,
    confirmed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tsp_batches_status ON tsp_batches (status);
CREATE INDEX idx_tsp_batches_confirmed ON tsp_batches (confirmed_at)
    WHERE status = 'confirmed';
```

### Column semantics

| Column | Description |
|---|---|
| `batch_id` | Unique identifier for the batch |
| `merkle_root` | SHA-256 Merkle root over `event_id`s in this batch |
| `first_event_seq` / `last_event_seq` | The `event_seq` range covered (global, across all work items) |
| `first_event_at` / `last_event_at` | Timestamp range of events in the batch (for query convenience) |
| `event_count` | Number of events in the batch |
| `tsa_token` | DER-encoded RFC 3161 TimeStampToken (NULL until confirmed) |
| `tsa_timestamp` | The TSA's attested time (NULL until confirmed) |
| `submitted_at` | When the TSA request was sent |
| `confirmed_at` | When the token was received and verified |
| `status` | `pending`, `confirmed`, or `failed` |
| `error_message` | Human-readable error from TSA or verification failure |

### Event-to-batch mapping

Events are not individually linked to batches. Instead, batch coverage is determined by `event_seq` range queries:

```sql
SELECT e.* FROM events e
WHERE e.event_seq BETWEEN
    (SELECT first_event_seq FROM tsp_batches WHERE batch_id = %s)
    AND (SELECT last_event_seq FROM tsp_batches WHERE batch_id = %s)
```

This avoids a foreign-key column on every event row and keeps the events table append-only with no timestamping-related schema changes.

### Inclusion verification query

To verify an event is covered by a confirmed batch:

```sql
SELECT b.batch_id, b.merkle_root, b.tsa_token, b.tsa_timestamp
FROM tsp_batches b
WHERE b.status = 'confirmed'
  AND b.first_event_seq <= %s
  AND b.last_event_seq >= %s
```

Where `%s` is the event's `event_seq`.

## 5. Integration Points

### 5.1 MaintenanceThread (Plan 009)

`MaintenanceThread.__init__` gains a `timestamp_interval` parameter (default `3600.0`). The `_run` loop adds a timestamping step:

```python
def _run(self) -> None:
    while not self._stop.is_set():
        # ... existing sweep, recurrence, hooks ...
        self._timestamp_events()
        self._stop.wait(timeout=self._sweep_interval)
```

`_timestamp_events` is gated on `TSAConfig` being present. If no TSA is configured, it's a no-op. The method:

1. Finds the last confirmed batch's `last_event_seq`.
2. Queries events with `event_seq > last_confirmed_seq` up to `batch_size`.
3. If no events, return.
4. Computes the Merkle root.
5. Inserts a `tsp_batches` row with `status='pending'`.
6. Submits to the TSA.
7. On success: updates the row to `confirmed`.
8. On failure: updates the row to `failed` with `error_message`.

Step 6 is the only network call. All other steps are database-local. The TSA call has a timeout (default 30s). If the call exceeds the timeout, the batch is marked failed.

### 5.2 Regista constructor

```python
def __init__(
    self,
    dsn: str,
    project: str,
    hmac_key_path: str | None = None,
    tsa_url: str | None = None,          # new
    tsa_cert_path: str | None = None,    # new
    ...
) -> None:
```

Env var fallbacks: `REGISTA_TSA_URL`, `REGISTA_TSA_CERT_PATH`.

If `tsa_url` is not provided, timestamping is disabled. `TSAConfig` is `None`. All timestamping methods return empty results.

### 5.3 Facade (Plan 007)

Add a `TimestampOps` facade to `_ops.py`:

```python
class TimestampOps:
    def trigger(self) -> TimestampBatch | None: ...
    def list_batches(self, status: str | None = None) -> list[TimestampBatch]: ...
    def verify_batch(self, batch_id: UUID) -> bool: ...
```

Exposed as `sub.timestamping.trigger()`, `sub.timestamping.list_batches()`, `sub.timestamping.verify_batch()`.

### 5.4 Replay integration

`_replay.py`'s `replay()` function gains `verify_timestamps: bool = False`. When `True`:

1. For each work item in the replay, check that events are covered by confirmed TSP batches.
2. If an event's `event_seq` falls outside all confirmed batch ranges, emit a warning: `"event_seq {seq} not covered by any confirmed TSP batch"`.
3. Warnings are collected in `ReplayReport.warnings` (already exists from FR-25).
4. Timestamping gaps are warnings, not errors. A replay succeeds even with uncovered events.

### 5.5 InMemoryRegista

`InMemoryRegista` supports `TSAConfig` in its constructor but all TSA operations are no-ops (no network calls). `list_timestamp_batches` returns empty. This matches the existing pattern where `InMemoryRegista` skips event emission without `hmac_key_path`.

### 5.6 Sidecar (Plan 005)

New endpoints:

| Method | Route |
|---|---|
| `POST /v1/timestamp/trigger` | `sub.timestamping.trigger()` |
| `GET /v1/timestamp/batches?status=...` | `sub.timestamping.list_batches(status)` |
| `POST /v1/timestamp/batches/{batch_id}/verify` | `sub.timestamping.verify_batch(batch_id)` |

## 6. Configuration

| Parameter | Constructor | Env var | Default | Description |
|---|---|---|---|---|
| `tsa_url` | `tsa_url` | `REGISTA_TSA_URL` | `None` (disabled) | TSA endpoint URL |
| `tsa_cert_path` | `tsa_cert_path` | `REGISTA_TSA_CERT_PATH` | `None` | Path to TSA certificate PEM (for verification) |
| `batch_size` | — | `REGISTA_TSA_BATCH_SIZE` | `1000` | Max events per batch |
| `timestamp_interval` | `start_maintenance(timestamp_interval=...)` | — | `3600.0` | Seconds between timestamping cycles |

Recommended TSAs:
- **Development:** FreeTSA (`https://freetsa.org/tsr`) — free, no SLA.
- **Production:** DigiCert, Sectigo, or a self-hosted `timestamp-authority` (open-source, CNCF sandbox).

### YAML configuration (optional)

```yaml
timestamping:
  tsa_url: https://freetsa.org/tsr
  tsa_cert_path: /etc/regista/tsa-ca.pem
  batch_size: 2000
```

Loaded alongside workflow YAML. Not required — env vars or constructor args are sufficient.

## 7. CLI

New `regista timestamp` subcommands in `_cli.py`:

```
regista timestamp status [--dsn ...] [--project ...]
regista timestamp verify <batch_id> [--dsn ...] [--project ...]
regista timestamp trigger [--dsn ...] [--project ...]
```

### `regista timestamp status`

Prints a summary table:

```
Batch ID                              Status     Events  First Event           Last Event            TSA Timestamp
───────────────────────────────────── ────────── ─────── ───────────────────── ───────────────────── ─────────────────────
a1b2c3d4-...                          confirmed  1500    2025-03-01T00:00:00Z  2025-03-01T01:00:00Z  2025-03-01T01:00:12Z
e5f6a7b8-...                          pending    800     2025-03-01T01:00:00Z  2025-03-01T01:30:00Z  —
```

Also shows: total batches, confirmed count, pending count, failed count, coverage percentage (events covered by confirmed batches / total events).

### `regista timestamp verify <batch_id>`

Loads the batch, re-derives the Merkle root from the event_seq range, verifies the TSA token against the Merkle root, and prints:

```
Batch a1b2c3d4-...
  Merkle root: abc123...
  TSA timestamp: 2025-03-01T01:00:12Z
  Token verification: PASS
  Event count: 1500
```

### `regista timestamp trigger`

Manually triggers a timestamping cycle. Useful for debugging or initial backfill. Connects to the database, finds untimestamped events, submits a batch to the TSA.

## 8. Backward Compatibility

- **Fully additive.** No existing tables are modified. The `tsp_batches` table is new.
- **Opt-in.** If `tsa_url` is not configured, no timestamping occurs. All new methods return empty results. No behavioral change to existing code paths.
- **Migration is benign.** `014_tsp_batches.sql` creates a new table and indexes. No data migration. No locking beyond DDL.
- **Replay unchanged by default.** `verify_timestamps` defaults to `False`. Existing replay callers see no change.
- **Maintenance thread unchanged by default.** `timestamp_interval` is only used if TSA is configured. The existing maintenance cycle adds a no-op call.
- **No new required dependencies.** RFC 3161 message construction uses `asn1crypto` (or `cryptography` which is already a transitive dependency via psycopg). The TSA HTTP call uses `urllib.request` from stdlib.

## 9. Dependencies

| Dependency | Purpose | Required? |
|---|---|---|
| `asn1crypto` or `cryptography` | RFC 3161 DER encoding/decoding | Yes (for timestamping) |
| `urllib.request` (stdlib) | HTTP POST to TSA | Yes (stdlib) |
| `hashlib` (stdlib) | SHA-256 Merkle tree | Yes (stdlib) |

If `asn1crypto` is not installed and timestamping is configured, raise `RegistaError(KEY_LOAD_ERROR, "asn1crypto required for TSA timestamping")` at construction time — fail fast, not at first batch.

Consider using `cryptography` (already in the dependency tree via psycopg's optional extras) for DER handling instead of adding a new dependency. Evaluate during implementation.

## 10. Testing

### Unit tests (`tests/test_timestamping.py`)

- **`test_merkle_root_deterministic`** — same event_ids produce same root regardless of insertion order.
- **`test_merkle_root_single_event`** — one event_id produces a valid root.
- **`test_merkle_root_empty_raises`** — empty list raises `ValueError`.
- **`test_merkle_proof_inclusion`** — given a target event_id, proof hashes verify against the root.
- **`test_merkle_proof_exclusion`** — wrong event_id fails verification.
- **`test_merkle_root_power_of_two`** — 2^n events produce a balanced tree.
- **`test_merkle_root_odd_count`** — odd number of events (duplicates last leaf).
- **`test_tsa_config_defaults`** — verify TSAConfig field defaults.

### Integration tests (`tests/test_timestamping_integration.py`)

Requires a running TSA (mock or FreeTSA). Use a mock HTTP server for deterministic tests:

- **`test_batch_creation`** — insert events, trigger timestamping, verify `tsp_batches` row created with correct event_count and seq range.
- **`test_batch_confirmation`** — mock TSA returns valid token, verify batch moves to `confirmed`.
- **`test_batch_failure_retry`** — mock TSA returns 500, verify batch moves to `failed`. Next cycle creates new batch covering the same range.
- **`test_no_duplicate_coverage`** — two batches must not overlap in event_seq range.
- **`test_timestamp_disabled`** — construct without `tsa_url`, verify `list_timestamp_batches()` returns empty and maintenance thread skips timestamping.
- **`test_replay_with_timestamps`** — `replay(verify_timestamps=True)` with confirmed batches produces no warnings.
- **`test_replay_uncovered_events`** — `replay(verify_timestamps=True)` with events outside batch range produces warnings.
- **`test_merkle_root_matches_events`** — load events from DB by seq range, re-derive Merkle root, compare to stored root.
- **`test_verify_batch_cli`** — run `regista timestamp verify <batch_id>` and parse output.

### Mock TSA server

Create a `tests/helpers/mock_tsa.py` that implements a minimal RFC 3161 responder:

1. Accepts `TimeStampReq` (DER).
2. Extracts the message imprint.
3. Signs with a test certificate.
4. Returns `TimeStampToken` (DER).

The test certificate and key are generated at test collection time and stored in `tests/test_tsa_cert.pem` / `tests/test_tsa_key.pem`.

### Property-based tests

- **Hypothesis:** given a random list of UUIDs, Merkle root computation is deterministic and proof verification succeeds for every element.

## 11. Files Changed

| File | Change |
|---|---|
| `src/regista/_timestamping.py` | **New.** TSAConfig, TimestampBatch, Merkle tree, TSA submission/verification. |
| `migrations/014_tsp_batches.sql` | **New.** `tsp_batches` table and indexes. |
| `src/regista/_maintenance.py` | Add `timestamp_interval` parameter, `_timestamp_events()` method. |
| `src/regista/__init__.py` | Add `tsa_url`, `tsa_cert_path` constructor params. Add `timestamp_pending_events`, `list_timestamp_batches`, `verify_timestamp_batch` methods. |
| `src/regista/_ops.py` | Add `TimestampOps` facade class. |
| `src/regista/_replay.py` | Add `verify_timestamps` parameter to `replay()`. |
| `src/regista/_errors.py` | Add `TSA_SUBMISSION_FAILED`, `TSA_VERIFICATION_FAILED`, `TSA_NOT_CONFIGURED` error codes. |
| `src/regista/_cli.py` | Add `timestamp` subcommand group with `status`, `verify`, `trigger`. |
| `src/regista/_event_store.py` | No changes. Events remain unchanged; timestamping is a separate concern. |
| `src/regista/sidecar/routes.py` | Add timestamp routes (3 endpoints). |
| `src/regista/sidecar/models.py` | Add Pydantic models for timestamp request/response. |
| `tests/test_timestamping.py` | **New.** Unit tests for Merkle tree and TSA operations. |
| `tests/test_timestamping_integration.py` | **New.** Integration tests with mock TSA. |
| `tests/helpers/mock_tsa.py` | **New.** Minimal RFC 3161 mock responder. |
| `AGENTS.md` | Update Public API, Maintenance, and Status sections. |

## 12. Risks

| Risk | Mitigation |
|---|---|
| TSA unavailable or slow | Batch marked `failed`, retried next cycle. Events are committed regardless. No blocking on the write path. |
| TSA returns malformed token | Verification fails, batch marked `failed`. Error message stored for diagnosis. |
| Large batch exceeds TSA size limits | `batch_size` is configurable. Default 1000 is conservative. |
| Merkle tree implementation bug | Property-based tests + determinism tests. Root is stored, so a bug is detectable post-hoc. |
| `asn1crypto` / `cryptography` dependency conflict | Evaluate during implementation. Both are widely used. Fall back to stdlib ASN.1 if feasible. |
| Clock skew between regista and TSA | TSA timestamp is authoritative. Regista's event timestamps are informational. |
| Migration 014 conflicts with future migrations | Migration numbering is sequential; 014 is next after existing 013. |
