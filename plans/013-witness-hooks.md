# Plan 013 — Witness/Co-signature Post-Append Hooks

**Status:** Draft RFC
**Owner:** substrate
**Spec touched:** §19 (public API surface), §17 (integrity and signing)
**Related:** BC-198 (agent provenance), Plan 009 (MaintenanceThread), Plan 012 (RFC 3161 timestamping), FR-13 (async hooks)

## 1. Overview

Adds a "post-append witness" mechanism that notifies external services after an event is committed to the event log. Witnesses can co-sign, acknowledge, or record events for bilateral tracking, audit federation, and agent-provenance chains.

Witness hooks differ from the existing hook queue (FR-13) in three ways:

1. **Universal scope.** Every committed event is eligible for witnessing. No workflow YAML declaration required.
2. **Fire-and-forget dispatch.** Receipt rows are inserted in the same transaction as the event. HTTP delivery happens asynchronously via the maintenance thread. No caller-side latency impact.
3. **Receipt tracking.** Each witness's response (including optional signatures) is stored for later verification.

Like Plan 012 (timestamping), witnessing is **best-effort.** A missing witness receipt is a warning, not an error. The event log remains complete and authoritative regardless of witness availability.

## 2. Motivation

### Agent provenance

Substrate's event log is signed by the operator's HMAC key. In multi-party scenarios (pen-test tracking, cross-org collaboration, regulatory audit), additional parties need independent proof that they observed an event:

- **Bilateral tracking:** A pen-test team and a customer both maintain event logs. Witness receipts from the other party prove neither side tampered with their log after the fact.
- **Witness federation:** Multiple independent auditors observe the same event stream. Any single auditor's compromise doesn't break the chain.
- **Non-repudiation:** A witness that co-signs an event provides cryptographic proof of observation, complementing the TSA timestamp (Plan 012) which proves *when* the event existed.

### Why not extend the existing hook queue?

The existing hook queue (FR-13, `_hooks.py`) is designed for workflow-internal event processing:

- Hooks are declared per-workflow in YAML (`hooks:` section).
- Hook handlers are Python callables registered in-process.
- The queue is bounded by workflow lifecycle.

Witnesses are cross-cutting: they observe *all* events (or a filtered subset) regardless of workflow. They are external HTTP endpoints, not in-process callables. Reusing the hook queue would conflate two different dispatch models and make filtering semantics confusing.

## 3. Design

### 3.1 Witness registration

Witnesses are registered via API or configuration file. Each witness has:

- A unique `witness_id` (UUID).
- A `url` to POST event data to.
- Optional `headers` for authentication.
- An optional `event_filter` constraining which events are sent.

Registration is persistent (database table). Witnesses survive process restarts.

### 3.2 Dispatch flow

```
Event committed ──► Check active witnesses
                         │
                    Filter by event_filter
                         │
               For each matching witness:
                    INSERT witness_receipts (status='pending')
                         │
               [async, maintenance thread]
                         │
                    SELECT pending receipts
                         │
               POST event data to witness URL
                         │
                  ┌──────┴───────┐
                  │              │
              2xx response   non-2xx / timeout
                  │              │
          status='confirmed'  increment consecutive_failures
          store response      │
                         if >= threshold:
                            status='failed' on witness
```

Key invariant: **no HTTP calls in the write path.** The event commit transaction only inserts receipt rows. HTTP delivery is deferred to the maintenance thread.

### 3.3 Event data sent to witness

The POST body sent to the witness URL contains the full event:

```json
{
  "event": {
    "event_id": "uuid",
    "work_item_id": "uuid",
    "event_seq": 42,
    "actor_id": "agent-coder-1",
    "actor_kind": "agent",
    "actor_metadata": { ... },
    "key_id": "key-2025-01",
    "workflow_name": "pen-test-v2",
    "workflow_version": 3,
    "timestamp": "2025-03-15T10:30:00Z",
    "transition": "close",
    "payload": { ... },
    "payload_canonical_hash": "abc123...",
    "signature": "def456..."
  },
  "receipt_id": "uuid",
  "witness_id": "uuid",
  "submitted_at": "2025-03-15T10:30:01Z"
}
```

The witness responds with:

```json
{
  "status": "confirmed",
  "witness_signature": "base64-encoded-bytes",
  "metadata": { ... }
}
```

`witness_signature` and `metadata` are optional. If provided, they are stored in `witness_receipts.witness_response` for later verification.

### 3.4 Event filter semantics

`event_filter` is a JSONB column that constrains which events trigger a receipt:

```json
{
  "transitions": ["close", "verify", "approve_exception"],
  "work_item_types": ["finding", "report"],
  "workflows": ["pen-test-v2"]
}
```

All fields are optional. `null` means "all events." Multiple fields are ANDed (must match all specified fields). Within a field, values are ORed (must match any of the listed values).

| Filter field | Matches against |
|---|---|
| `transitions` | `event.transition` (NULL events excluded if filter is set) |
| `work_item_types` | Resolved from work_item's type at event time |
| `workflows` | `event.workflow_name` |

### 3.5 Witness health tracking

Each witness tracks `consecutive_failures`. After `max_failures` (default 10), the witness is automatically paused (`status='failed'`). Paused witnesses are not sent new events but their receipts remain queryable.

A paused witness can be reactivated via `reactivate_witness(witness_id)`, which resets `consecutive_failures` to 0 and sets `status='active'`.

## 4. Database Schema

### Migration `015_witness_tables.sql`

```sql
CREATE TABLE witness_registrations (
    witness_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                    TEXT NOT NULL,
    headers                JSONB,
    event_filter           JSONB,
    status                 TEXT NOT NULL DEFAULT 'active',
    max_failures           INTEGER NOT NULL DEFAULT 10,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    max_retries            INTEGER NOT NULL DEFAULT 3,
    last_success_at        TIMESTAMPTZ,
    last_failure_at        TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE witness_receipts (
    receipt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    witness_id          UUID NOT NULL REFERENCES witness_registrations(witness_id),
    event_id            UUID NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    retry_count         INTEGER NOT NULL DEFAULT 0,
    submitted_at        TIMESTAMPTZ,
    last_attempt_at     TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ,
    witness_signature   BYTEA,
    witness_response    JSONB,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_witness_registrations_status
    ON witness_registrations (status);
CREATE INDEX idx_witness_receipts_pending
    ON witness_receipts (witness_id, status)
    WHERE status = 'pending';
CREATE INDEX idx_witness_receipts_event
    ON witness_receipts (event_id);
CREATE INDEX idx_witness_receipts_witness_event
    ON witness_receipts (witness_id, event_id);
```

### Column semantics

**`witness_registrations`:**

| Column | Description |
|---|---|
| `witness_id` | Unique identifier for the witness |
| `url` | HTTP(S) endpoint to POST event data to |
| `headers` | JSON object of HTTP headers (e.g., `{"Authorization": "Bearer ..."}`) |
| `event_filter` | JSON object constraining events, or NULL for all events |
| `status` | `active`, `paused` (operator paused), or `failed` (auto-paused after consecutive failures) |
| `max_failures` | Consecutive failures before auto-pause (default 10) |
| `consecutive_failures` | Current failure streak |
| `max_retries` | Per-receipt retry limit before dead-lettering |
| `last_success_at` / `last_failure_at` | Timestamps for monitoring |
| `created_at` / `updated_at` | Lifecycle timestamps |

**`witness_receipts`:**

| Column | Description |
|---|---|
| `receipt_id` | Unique identifier for this delivery attempt |
| `witness_id` | Which witness this receipt is for |
| `event_id` | The event being witnessed (references `events.event_id` logically, not FK — event_id is globally unique) |
| `status` | `pending`, `confirmed`, `failed` |
| `retry_count` | Number of delivery attempts |
| `submitted_at` | When the first delivery attempt was made |
| `last_attempt_at` | When the most recent delivery attempt was made |
| `confirmed_at` | When the witness confirmed receipt |
| `witness_signature` | Optional co-signature from the witness (binary) |
| `witness_response` | Full JSON response from the witness |
| `error_message` | Last delivery error message |

### No FK on `event_id`

`witness_receipts.event_id` references `events.event_id` logically but does not use a foreign key constraint. Rationale:

- The events table is append-only and never deleted. A FK would be correct but adds write-path overhead (FK check on every receipt insert).
- The receipt is created in the same transaction as the event, so the event always exists when the receipt is inserted.
- Documented as a deliberate denormalization for write-path performance.

## 5. Witness Consumer

### 5.1 Integration with MaintenanceThread

`MaintenanceThread.__init__` gains a `witness_interval` parameter (default `30.0`). The `_run` loop adds a witness delivery step:

```python
def _run(self) -> None:
    while not self._stop.is_set():
        # ... existing sweep, recurrence, hooks, timestamping ...
        self._deliver_witness_receipts()
        self._stop.wait(timeout=self._sweep_interval)
```

`_deliver_witness_receipts` is gated on having any active witnesses. If no witnesses are registered, it's a no-op.

### 5.2 Delivery algorithm

```
1. SELECT active witnesses
2. For each active witness:
   a. SELECT pending receipts FOR UPDATE SKIP LOCKED
      WHERE witness_id = ? AND status = 'pending'
      ORDER BY created_at LIMIT 50
   b. For each receipt:
      - Fetch the event from events table
      - POST event data + receipt metadata to witness URL
      - On 2xx: UPDATE receipt SET status='confirmed', witness_response=..., confirmed_at=now()
                UPDATE witness SET consecutive_failures=0, last_success_at=now()
      - On non-2xx or timeout:
                UPDATE receipt SET retry_count=retry_count+1, last_attempt_at=now(), error_message=...
                IF retry_count >= max_retries:
                    UPDATE receipt SET status='failed'
                UPDATE witness SET consecutive_failures=consecutive_failures+1, last_failure_at=now()
                IF consecutive_failures >= max_failures:
                    UPDATE witness SET status='failed'
```

### 5.3 Concurrency safety

- `FOR UPDATE SKIP LOCKED` prevents two maintenance threads from delivering the same receipt. Multiple substrate processes (per Plan 009's concurrent execution model) can safely run witness delivery.
- Receipt insertion happens inside the event commit transaction, ensuring the receipt is never visible without its event.
- Witness auto-pause is idempotent: setting `status='failed'` on an already-failed witness is a no-op.

### 5.4 HTTP delivery details

- **Timeout:** 10 seconds per request (configurable per witness in future).
- **Retry:** on any non-2xx response or network error. Retried next cycle (not exponential backoff in v1).
- **Idempotency:** The POST body includes `receipt_id`. Witnesses can use this to deduplicate. Substrate does not resend confirmed receipts.
- **Content-Type:** `application/json`.
- **User-Agent:** `substrate-witness-delivery/<version>`.

## 6. Configuration

### 6.1 API registration

```python
sub.register_witness(
    url="https://auditor.example.com/substrate-witness",
    headers={"Authorization": "Bearer token123"},
    event_filter={"transitions": ["close", "verify"]},
    max_failures=10,
    max_retries=3,
)
```

Returns `(witness_id: UUID)`.

### 6.2 YAML configuration file

```yaml
witnesses:
  - url: https://auditor.example.com/substrate-witness
    headers:
      Authorization: "Bearer token123"
    event_filter:
      transitions: [close, verify, approve_exception]
    max_failures: 10
    max_retries: 3

  - url: https://customer.example.com/substrate-witness
    event_filter: null
```

Loaded at startup. Witnesses defined in YAML are idempotently registered (by URL) on each startup. This allows declarative configuration in deployment manifests.

### 6.3 Maintenance thread parameters

```python
sub.start_maintenance(
    sweep_interval=30,
    recurrence_interval=10,
    witness_interval=30,
)
```

`witness_interval` defaults to `30.0`. Only relevant if witnesses are registered.

## 7. API

### 7.1 Public methods on `Substrate`

```python
def register_witness(
    self,
    url: str,
    headers: dict[str, str] | None = None,
    event_filter: dict | None = None,
    max_failures: int = 10,
    max_retries: int = 3,
) -> UUID:
    """Register an external witness. Returns witness_id."""

def unregister_witness(self, witness_id: UUID) -> None:
    """Remove a witness. Pending receipts are abandoned (not delivered)."""

def pause_witness(self, witness_id: UUID) -> None:
    """Pause a witness. Pending receipts are retained but not delivered."""

def reactivate_witness(self, witness_id: UUID) -> None:
    """Reactivate a paused/failed witness. Resets consecutive_failures."""

def list_witnesses(self, status: str | None = None) -> list[dict]:
    """List witness registrations, optionally filtered by status."""

def list_witness_receipts(
    self,
    event_id: UUID | None = None,
    witness_id: UUID | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Query witness receipts. At least one filter is recommended."""

def deliver_pending_witness_receipts(self) -> int:
    """Manually trigger one delivery cycle. Returns count of receipts processed."""
```

### 7.2 Facade (Plan 007)

`WitnessOps` in `_ops.py`:

```python
class WitnessOps:
    def register(self, url, headers=None, event_filter=None, ...) -> UUID: ...
    def unregister(self, witness_id) -> None: ...
    def pause(self, witness_id) -> None: ...
    def reactivate(self, witness_id) -> None: ...
    def list(self, status=None) -> list[dict]: ...
    def receipts(self, event_id=None, witness_id=None, ...) -> list[dict]: ...
    def deliver(self) -> int: ...
```

Exposed as `sub.witnesses.register(...)`, `sub.witnesses.list()`, etc.

### 7.3 Sidecar endpoints (Plan 005)

| Method | Route |
|---|---|
| `POST /v1/witnesses` | `register_witness` |
| `DELETE /v1/witnesses/{witness_id}` | `unregister_witness` |
| `POST /v1/witnesses/{witness_id}/pause` | `pause_witness` |
| `POST /v1/witnesses/{witness_id}/reactivate` | `reactivate_witness` |
| `GET /v1/witnesses` | `list_witnesses` |
| `GET /v1/witnesses/receipts?event_id=...&witness_id=...` | `list_witness_receipts` |
| `POST /v1/witnesses/deliver` | `deliver_pending_witness_receipts` |

## 8. CLI

New `substrate witness` subcommands in `_cli.py`:

```
substrate witness list [--status=active|paused|failed]
substrate witness show <witness_id>
substrate witness pause <witness_id>
substrate witness reactivate <witness_id>
substrate witness receipts [--event-id=<uuid>] [--witness_id=<uuid>] [--status=pending|confirmed|failed]
substrate witness deliver
```

### `substrate witness list`

```
Witness ID                           URL                                       Status   Failures  Last Success
──────────────────────────────────── ───────────────────────────────────────── ──────── ───────── ─────────────────────
a1b2c3d4-...                         https://auditor.example.com/witness       active   0         2025-03-15T10:30:05Z
e5f6a7b8-...                         https://customer.example.com/witness      failed   10        2025-03-14T22:00:00Z
```

### `substrate witness receipts`

Shows receipt status for a given event or witness. Useful for debugging delivery failures.

### `substrate witness deliver`

Manually triggers one delivery cycle. Useful for initial setup or after fixing a witness endpoint.

## 9. Backward Compatibility

- **Fully additive.** Two new tables, no modifications to existing tables.
- **Opt-in.** If no witnesses are registered, the witness consumer is a no-op. No receipts are created. No events are modified.
- **Migration is benign.** `015_witness_tables.sql` creates two new tables and indexes. No data migration. No DDL on existing tables.
- **Replay unchanged.** Witness receipts are not part of the replay projection. `replay()` ignores them entirely. An optional `verify_witnesses=True` flag (future work) could check receipt coverage, similar to Plan 012's `verify_timestamps`.
- **Maintenance thread compatible.** The witness delivery step is added to the existing maintenance loop. No new thread.
- **Hook queue unaffected.** Witness receipts are a separate table and dispatch mechanism. The existing `hook_queue` and `claim_hooks`/`complete_hook`/`fail_hook` lifecycle are unchanged.

## 10. Dependencies

| Dependency | Purpose | Required? |
|---|---|---|
| `urllib.request` (stdlib) | HTTP POST to witness URLs | Yes (stdlib) |
| `json` (stdlib) | Request/response serialization | Yes (stdlib) |
| No new external dependencies | — | — |

All witness delivery uses stdlib HTTP. No `httpx`, `aiohttp`, or `requests` required. The maintenance thread is synchronous (matching the existing pattern in `_maintenance.py`).

## 11. Testing

### Unit tests (`tests/test_witness.py`)

- **`test_event_filter_all`** — NULL filter matches all events.
- **`test_event_filter_transitions`** — filter with `transitions` matches only events with those transitions.
- **`test_event_filter_workflows`** — filter with `workflows` matches only events from those workflows.
- **`test_event_filter_and_semantics`** — multiple filter fields are ANDed.
- **`test_event_filter_none_values`** — events with NULL transition are excluded when `transitions` filter is set.
- **`test_witness_registration`** — register, list, verify fields.
- **`test_witness_unregister`** — unregister, verify absent from list.

### Integration tests (`tests/test_witness_integration.py`)

Uses a mock HTTP server (`tests/helpers/mock_witness.py`):

- **`test_receipt_created_on_event`** — append event, verify receipt row exists for each active witness.
- **`test_receipt_delivery_confirmed`** — mock witness returns 2xx, verify receipt status is `confirmed`.
- **`test_receipt_delivery_failed`** — mock witness returns 500, verify receipt retry_count incremented.
- **`test_receipt_dead_lettered`** — fail a receipt past `max_retries`, verify status is `failed`.
- **`test_witness_auto_paused`** — fail a witness past `max_failures`, verify status is `failed`.
- **`test_witness_reactivated`** — reactivate a failed witness, verify consecutive_failures reset.
- **`test_filter_skips_event`** — witness with transition filter, append event with non-matching transition, verify no receipt created.
- **`test_multiple_witnesses`** — register 3 witnesses with different filters, append event, verify correct receipts created.
- **`test_unregister_abandons_receipts`** — unregister witness with pending receipts, verify receipts remain but are not delivered.
- **`test_skip_locked_concurrency`** — two threads deliver from same witness, verify no receipt delivered twice.
- **`test_maintenance_thread_delivers`** — start maintenance thread, verify pending receipts are delivered.

### Mock witness server

Create `tests/helpers/mock_witness.py`:

```python
class MockWitnessServer:
    """Minimal HTTP server that records POSTed events and returns configurable responses."""

    def __init__(self, status_code=200, response_body=None):
        ...

    def start(self):
        ...

    def stop(self):
        ...

    @property
    def received_events(self) -> list[dict]:
        ...
```

The mock server runs on a random port, accepts POST requests, stores event bodies, and returns configurable responses. Tests assert on the received events and receipt status.

### End-to-end test

- **`test_witness_round_trip`** — register witness, create workflow, create work item, transition through states, verify receipts are created for each event, verify mock witness received all events in order.

## 12. Files Changed

| File | Change |
|---|---|
| `src/substrate/_witness.py` | **New.** Witness registration, receipt creation, event filtering, delivery logic. |
| `migrations/015_witness_tables.sql` | **New.** `witness_registrations` and `witness_receipts` tables. |
| `src/substrate/_maintenance.py` | Add `witness_interval` parameter, `_deliver_witness_receipts()` method. |
| `src/substrate/__init__.py` | Add witness public methods (`register_witness`, `unregister_witness`, `pause_witness`, `reactivate_witness`, `list_witnesses`, `list_witness_receipts`, `deliver_pending_witness_receipts`). |
| `src/substrate/_ops.py` | Add `WitnessOps` facade class. |
| `src/substrate/_events.py` | After event commit, call `_witness.create_receipts(event)` to insert pending receipts for matching witnesses. |
| `src/substrate/_event_store.py` | Same receipt creation hook for shared event store path. |
| `src/substrate/_errors.py` | Add `WITNESS_NOT_FOUND`, `WITNESS_DELIVERY_FAILED`, `WITNESS_PAUSED` error codes. |
| `src/substrate/_cli.py` | Add `witness` subcommand group with `list`, `show`, `pause`, `reactivate`, `receipts`, `deliver`. |
| `src/substrate/sidecar/routes.py` | Add witness routes (7 endpoints). |
| `src/substrate/sidecar/models.py` | Add Pydantic models for witness request/response. |
| `tests/test_witness.py` | **New.** Unit tests for filtering and registration. |
| `tests/test_witness_integration.py` | **New.** Integration tests with mock witness. |
| `tests/helpers/mock_witness.py` | **New.** Mock HTTP witness server. |
| `AGENTS.md` | Update Public API, Maintenance, and Status sections. |

## 13. Risks

| Risk | Mitigation |
|---|---|
| Witness endpoint slow or unresponsive | 10s timeout per request. Does not block event commits (receipts are inserted synchronously but delivery is async). |
| High-volume events overwhelm witness | `FOR UPDATE SKIP LOCKED` batches 50 receipts per cycle. `witness_interval` is configurable. Receipts queue up and drain over multiple cycles. |
| Witness registration table grows unbounded | Witnesses are registered, not per-event. Table size is bounded by the number of witnesses (typically < 10). Receipt table can be pruned by confirmed_at age if needed. |
| Receipt table grows large | Index on `(witness_id, status) WHERE status = 'pending'` keeps delivery queries fast. Confirmed/failed receipts are queryable but not scanned during delivery. Consider adding `receipt_retention_days` in future. |
| Event filter evaluation overhead | Filters are evaluated in Python after event commit (inside the transaction). Filter logic is simple dict matching. For N witnesses, N filter evaluations per event — acceptable for typical witness counts (< 20). |
| Witness receives sensitive event data | Event payloads may contain sensitive data. Witnesses are operator-configured endpoints. Document that witness URLs should use HTTPS and that event data is sent in cleartext over the TLS tunnel. Operators are responsible for trusting their witnesses. |
| Delivery during Postgres connectivity loss | Receipts remain `pending`. Next successful maintenance cycle resumes delivery. No data loss. |

## 14. Future Work

- **Witness co-signature verification.** Store `witness_signature` and provide a `verify_witness_signature(receipt_id)` method that checks the signature against the event's canonical hash.
- **Webhook secret.** Sign POST bodies with an HMAC key shared between substrate and the witness, allowing the witness to verify authenticity.
- **Receipt pruning.** `auto_prune_confirmed_receipts_older_than_days` parameter for housekeeping.
- **Exponential backoff.** Per-receipt delivery retry with exponential backoff instead of next-cycle retry.
- **Batch delivery.** Send multiple events in a single POST to reduce HTTP overhead for high-volume witnesses.
- **Replay integration.** `replay(verify_witnesses=True)` checks that confirmed receipts exist for events matching witness filters, similar to Plan 012's `verify_timestamps`.
