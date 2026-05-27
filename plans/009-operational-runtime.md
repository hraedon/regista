# Plan 009 — Operational Runtime (Regista Daemon)

**Status:** Draft RFC
**Owner:** plm
**Spec touched:** §3 (out of scope), §20 (consumer expectation boundary), AGENTS.md §Key Design Decisions (point 2)
**Related:** Plan 005 (HTTP sidecar), BC-153 (partition pruning), spec §20 ("nothing wakes up at `not_before`")

## 1. Problem Statement

Regista is a library, not a daemon. This is a deliberate design decision (AGENTS.md, spec §20). But the library requires several timer-driven operations that the consumer must manage:

| Operation | Required frequency | Consequence of missed call |
|---|---|---|
| `sweep_expired_claims()` | Every 30–60s | Expired claims linger; `claimable_now` filter returns stale results until next acquire steals them |
| `ensure_event_partitions(months_ahead=3)` | Monthly (or at month boundary) | New events land in `events_default` partition; query performance degrades |
| `sweep_expired_hook_leases()` | Every 30–60s | Leased hooks are stranded; not retried or dead-lettered until swept |
| Recurrence firing (`due_recurrences` + `fire_recurrence`) | Every 1–60s (schedule-dependent) | Recurring work-items are not created on time |
| `poll_hooks()` (if no consumer thread) | Every 1–5s | Hooks not dispatched to handlers |

Today, every consumer must:
1. Know this list exists.
2. Set up their own `threading.Timer` / `asyncio.Task` / cron / systemd timer.
3. Handle errors from each call (connection failures, transient Postgres issues).
4. Coordinate shutdown (stop timers, drain in-flight operations).

This is operational burden that scales linearly with the number of regista consumers. If three processes embed regista, all three might run `sweep_expired_claims()` concurrently (harmless but wasteful) or none might run it (harmful).

### Why the "library, not daemon" stance was correct

When regista was MVP, the consumer was a single Python process (software-factory-2). Embedding a timer loop in that process was trivial. The stance avoided:
- A daemon lifecycle to manage (PID files, health checks, graceful shutdown).
- A network boundary between the consumer and regista (serialization, auth).
- Deployment complexity (two processes instead of one).

### Why the stance is now a liability

1. **The sidecar (Plan 005) is already a daemon.** It runs a FastAPI server, accepts HTTP connections, and needs its own health checks. It already must run the timer operations for non-Python consumers.
2. **Recurrence (Plan 003) requires a scheduler.** The spec says `fire_recurrence` must be called on a timer. Without a daemon, every consumer must implement their own scheduler.
3. **The CLI (Plan 002) is one-shot.** `regista recurrence due` tells you what's due, but doesn't fire it. An operator must wrap it in cron.
4. **The "library" abstraction leaks.** Consumers see `sweep_expired_claims()`, `ensure_event_partitions()`, `poll_hooks()` — methods that are clearly infrastructure, not domain operations. Their presence on the `Regista` class violates the ISP principle (Plan 007).

## 2. Design Options

### (a) Built-in timer thread (Recommended)

Add an optional `Regista.start_maintenance()` method that spawns a background thread running all timer-driven operations. The thread uses `threading.Event` for shutdown coordination (same pattern as the existing hook consumer).

```python
sub = Regista(dsn, "my_project", hmac_key_path=...)

# Start background maintenance
sub.start_maintenance(
    sweep_interval=30,           # seconds
    partition_check_interval=3600,
    recurrence_poll_interval=10,
    hook_poll_interval=2,
)

# ... use regista normally ...

sub.stop_maintenance()  # graceful shutdown, drains in-flight ops
sub.close()
```

The thread runs a single event loop:

```
while not stop_event.is_set():
    sweep_expired_claims()
    sweep_expired_hook_leases()
    fire_due_recurrences()
    ensure_event_partitions()
    stop_event.wait(timeout=sweep_interval)
```

**Pros:** Zero-deployment overhead. Consumers who embed regista get maintenance for free. Backward compatible — `start_maintenance()` is opt-in.

**Cons:** Still a library. Multiple processes embedding regista will run concurrent sweeps (idempotent but wasteful). Thread lifecycle is the consumer's responsibility.

### (b) Standalone daemon process

A separate `regista-maintainer` process that connects to the database and runs all timer operations independently. Consumers do not need to embed anything.

```bash
regista-maintainer --dsn=... --project=my_project --hmac-key-path=...
```

**Pros:** Single maintenance process. Clear ownership of timer operations. Can be supervised by systemd/docker.

**Cons:** Another process to deploy and monitor. Shared HMAC key material. Need health-check endpoints. Violates "library, not daemon" at the process level.

### (c) Sidecar-embedded maintenance

The sidecar (Plan 005) runs maintenance as part of its lifecycle. Non-sidecar consumers run their own timers.

**Pros:** No new deployment artifact. Sidecar already has keys and a connection.

**Cons:** Couples maintenance to the sidecar deployment. In-process consumers who don't use the sidecar still need option (a).

### (d) Postgres-native scheduling

Use `pg_cron` or `pg_partman` for partition management and claim sweeping. Recurrence firing remains application-level.

**Pros:** Leverages Postgres's built-in scheduler. No application-level timer needed for partition and claim operations.

**Cons:** Requires `pg_cron` extension (not available in all Postgres deployments, especially managed). Recurrence firing still needs application code. Claim sweeping via SQL bypasses regista's signing (no events emitted for swept claims).

## 3. Proposed Design (Option A + Option B combined)

### Phase A: Built-in timer thread

Add `start_maintenance()` / `stop_maintenance()` to `Regista`. This gives every consumer a one-call solution. Implementation:

1. Single `MaintenanceThread` class in `_maintenance.py`.
2. Configurable intervals per operation type.
3. `threading.Event`-based shutdown (matching `HookConsumer` pattern).
4. Structured logging for each maintenance cycle.
5. Error resilience: transient Postgres errors are logged and retried next cycle; permanent errors (schema not found) halt the thread with an error log.

### Phase B: Standalone daemon entry point

Add `regista-maintainer` console entry point (similar to `regista` CLI in Plan 002):

```
regista-maintainer --dsn=... --project=... --hmac-key-path=... [--sweep-interval=30] [--recurrence-interval=10]
```

This is a thin wrapper around `Regista.start_maintenance()` with signal handling:

```python
import signal
sub = Regista(dsn, project, hmac_key_path=path)
sub.start_maintenance(...)

stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())
stop.wait()

sub.stop_maintenance()
sub.close()
```

### Operation scheduling matrix

| Operation | Thread interval | Daemon flag | Independent CLI command |
|---|---|---|---|
| `sweep_expired_claims()` | 30s (configurable) | `--sweep-interval` | `regista claims sweep` |
| `sweep_expired_hook_leases()` | 30s (shared with sweep) | (shared) | `regista hooks sweep` |
| `ensure_event_partitions(3)` | 3600s | `--partition-interval` | `regista schema ensure-partitions` |
| `due_recurrences()` + `fire_recurrence()` | 10s | `--recurrence-interval` | `regista recurrence fire-due` |
| `poll_hooks()` (if no consumer thread) | 2s | `--hook-interval` | N/A (thread-based) |

### Concurrent execution safety

All maintenance operations are idempotent and safe under concurrent execution from multiple processes:

- **Sweep claims:** `SELECT FOR UPDATE` serializes concurrent sweeps. Second sweeper finds nothing to sweep.
- **Sweep hook leases:** Same `FOR UPDATE` pattern.
- **Ensure partitions:** `CREATE TABLE IF NOT EXISTS` is idempotent. Concurrent calls are harmless.
- **Fire recurrences:** `SELECT FOR UPDATE` on the rule row prevents double-firing. Idempotent event_id generation (UUID5 from rule_id + scheduled_fire_at) prevents duplicate work-items.
- **Poll hooks:** `FOR UPDATE SKIP LOCKED` prevents double-processing.

## 4. Spec Impact

### §3 (Out of scope) amendment

Current: "A scheduler engine is explicitly out of scope."

Proposed amendment: Regista provides a **maintenance runtime** (timer-driven infrastructure operations) but not a **workflow execution engine**. The maintenance runtime handles claim expiry, hook lease expiry, event partition management, and recurrence firing. It does NOT schedule work-items, trigger transitions based on wall-clock, or provide durable timers for consumer workflows. The §20 boundary is unchanged.

### AGENTS.md amendment

Key Design Decisions, point 2: "Library, not daemon" is revised to:

> Regista is a library that can optionally run its own maintenance operations in a background thread. It does not require a separate daemon process for correctness, but one is provided for operator convenience (`regista-maintainer`). The library exposes a `prometheus_client.CollectorRegistry` for the host app to mount. The optional daemon exposes its own metrics endpoint.

## 5. Migration from Current Pattern

Consumers currently running their own timers can migrate by:

1. Removing custom timer code.
2. Calling `sub.start_maintenance()` after construction.
3. Calling `sub.stop_maintenance()` before `sub.close()`.

The existing `start_hook_consumer()` / `stop_hook_consumer()` are subsumed: `start_maintenance()` starts the hook consumer thread alongside the maintenance thread.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Background thread dies silently | Structured error log + optional `on_error` callback. Prometheus counter `regista_maintenance_errors_total`. |
| Multiple consumers run concurrent maintenance | All operations are idempotent and use row locks. Wasteful but safe. |
| `regista-maintainer` becomes a single point of failure | Run under systemd/docker with restart policy. Health-check endpoint in Phase B. |
| Timer intervals too aggressive for slow Postgres | Configurable intervals. Default intervals are conservative (30s sweep, 3600s partition). |
| Breaks "library, not daemon" contract | It's optional. Consumers who don't call `start_maintenance()` see no change. |
