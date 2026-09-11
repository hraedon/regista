# Plan 010 — Delegation Chain (`on_behalf_of`)

**Status:** Draft RFC
**Owner:** plm
**Resolves:** BC-197
**Spec touched:** §17 (event envelope), §19 (public API surface)
**Related:** FR-15 (HMAC signing), BC-194 (heartbeat coalesce — last envelope change)

## 1. Overview

Add an optional `on_behalf_of` field to every event, carrying a structured delegation chain that records who authorized the action when an agent acts on behalf of a human principal. The field is integrity-protected by the HMAC signature (included in the signing envelope) and stored as nullable JSONB. No projection change; the field is audit-only.

## 2. Motivation

In multi-operator deployments, an agent's `actor_id` identifies the agent, not the human who authorized it. A human operator says "deploy v2" through an agent session, but the event log only records the agent's identity. After an incident, there is no way to trace which human authorized a particular state change.

The delegation chain solves this by letting callers attach a `principal_id` (and optional session/scope metadata) at the point of action. Because it is signed, it cannot be forged or retroactively altered. Because it is stored on the event, it survives replay and is visible to downstream consumers (hooks, telemetry).

This is the resolution of BC-197.

## 3. Design

### 3.1 DelegationChain type

Add a `DelegationChain` frozen dataclass to `_types.py`:

```python
@dataclass(frozen=True)
class DelegationChain:
    principal_id: str
    session_id: str | None = None
    authenticated_at: str | None = None
    scope: list[str] | None = None

    def to_dict(self) -> dict:
        d: dict[str, object] = {"principal_id": self.principal_id}
        if self.session_id is not None:
            d["session_id"] = self.session_id
        if self.authenticated_at is not None:
            d["authenticated_at"] = self.authenticated_at
        if self.scope is not None:
            d["scope"] = self.scope
        return d

    @classmethod
    def from_dict(cls, data: dict) -> DelegationChain:
        return cls(
            principal_id=data["principal_id"],
            session_id=data.get("session_id"),
            authenticated_at=data.get("authenticated_at"),
            scope=data.get("scope"),
        )
```

The public API accepts `on_behalf_of: dict | None` (the serialized form), not the dataclass. The dataclass is an internal convenience for callers who want type-safe construction. The dict is what gets stored and signed.

### 3.2 Event dataclass change

Add to `Event` in `_types.py`:

```python
on_behalf_of: dict | None = None
```

Placed after `canonical_envelope` (last field, has default). The field is not included in `to_dict()` / `from_dict()` round-trips used by InMemory — it is populated from the store row directly. However, `to_dict()` and `from_dict()` MUST be updated to include it for completeness.

### 3.3 Signing envelope

In `_signing.py`, add `on_behalf_of` to `build_signing_envelope()`, `sign_event()`, and `verify_event()`:

```python
def build_signing_envelope(
    event_id: UUID,
    work_item_id: UUID,
    actor_id: str,
    transition: str | None,
    payload: dict | None,
    on_behalf_of: dict | None = None,
) -> bytes:
    envelope = {
        "event_id": str(event_id),
        "work_item_id": str(work_item_id),
        "actor_id": actor_id,
        "on_behalf_of": on_behalf_of,
        "transition": transition,
        "payload": payload,
    }
    return canonicalize(envelope)
```

`on_behalf_of` is placed after `actor_id` (before `transition`) to produce a stable canonical ordering. The field is nullable — `None` maps to JSON `null`, which JCS serializes deterministically.

`sign_event()` and `verify_event()` gain the same parameter, passed through to `build_signing_envelope()`.

### 3.4 Backward-compatible verification

Old events have no `on_behalf_of` in their stored canonical envelope. Replay verification uses the stored envelope when available (the `stored_envelope` parameter). For old envelopes, `verify_event()` is called with `on_behalf_of=None`, which produces an envelope containing `"on_behalf_of": null`. This will NOT match the old envelope (which does not contain the key).

Solution: `verify_event()` already accepts `stored_envelope` and compares against it. When `stored_envelope` is provided, the reconstructed envelope is not used — verification uses the stored bytes directly. Old events will verify correctly because replay passes `stored_envelope`.

When `stored_envelope` is `None` (no stored envelope, pre-Plan-002 events), `verify_event()` reconstructs from fields. In this case, we must handle backward compat. The approach: when `stored_envelope` is `None` and verification fails, retry with `on_behalf_of=None` (i.e., without the key in the envelope). This matches the old envelope structure. Add this as a single retry inside `verify_event()`.

```python
def verify_event(..., on_behalf_of: dict | None = None, ...) -> bool:
    if stored_envelope is not None:
        envelope = stored_envelope
    else:
        envelope = build_signing_envelope(..., on_behalf_of=on_behalf_of)
    if verify_hmac(envelope, signature, key):
        if hashlib.sha256(envelope).digest() == canonical_hash:
            return True
    # Backward compat: old events without on_behalf_of in envelope
    if on_behalf_of is not None and stored_envelope is None:
        old_envelope = build_signing_envelope(event_id, work_item_id, actor_id,
                                               transition, payload, on_behalf_of=None)
        if verify_hmac(old_envelope, signature, key):
            if hashlib.sha256(old_envelope).digest() == canonical_hash:
                return True
    return False
```

In practice, the backward-compat branch is rarely hit because all events since Plan 002 store `canonical_envelope`. It is a defense-in-depth measure for events predating that change.

### 3.5 Validation

Add `validate_delegation_chain()` to `_contract.py`:

```python
def validate_delegation_chain(on_behalf_of: dict | None) -> None:
    if on_behalf_of is None:
        return
    if not isinstance(on_behalf_of, dict):
        raise RegistaError(INVALID_ARGUMENT, "on_behalf_of must be a dict")
    principal_id = on_behalf_of.get("principal_id")
    if not isinstance(principal_id, str) or not principal_id:
        raise RegistaError(INVALID_ARGUMENT,
            "on_behalf_of.principal_id is required and must be a non-empty string")
    if "scope" in on_behalf_of and on_behalf_of["scope"] is not None:
        if not isinstance(on_behalf_of["scope"], list):
            raise RegistaError(INVALID_ARGUMENT, "on_behalf_of.scope must be a list")
        for item in on_behalf_of["scope"]:
            if not isinstance(item, str):
                raise RegistaError(INVALID_ARGUMENT, "on_behalf_of.scope items must be strings")
    if "authenticated_at" in on_behalf_of and on_behalf_of["authenticated_at"] is not None:
        if not isinstance(on_behalf_of["authenticated_at"], str):
            raise RegistaError(INVALID_ARGUMENT, "on_behalf_of.authenticated_at must be a string")
```

Called at the top of every public entry point that accepts `on_behalf_of`, before any other work.

New error code: `DELEGATION_CHAIN_INVALID` (not strictly needed since we reuse `INVALID_ARGUMENT`, but adds specificity for consumers).

### 3.6 Threading through append paths

The parameter flows through every layer. Each function in the chain gains `on_behalf_of: dict | None = None`.

**Layer 1 — Signing** (`_signing.py`):
- `build_signing_envelope()`: add parameter, include in envelope dict
- `sign_event()`: add parameter, pass through
- `verify_event()`: add parameter, pass through + backward-compat retry

**Layer 2 — Shared append** (`_event_store.py::append_event()`):
- Add `on_behalf_of: dict | None = None` parameter
- Pass to `sign_event()`
- Include in `Event()` construction
- `InMemoryEventStore.append()` — no change (it stores the Event as-is)

**Layer 3 — Postgres append** (`_events.py`):
- `_EVENT_FIELDS`: add `on_behalf_of` to the field list
- `_row_to_event()`: add `on_behalf_of=row["on_behalf_of"]`
- `append_event()`: add parameter, pass to `sign_event()`, include in INSERT column list and values
- `append_transition_event()`: same
- `read_events_by_work_item()`, `read_events_composite()`: no change (use `_EVENT_FIELDS`)

**Layer 3 — PostgresEventStore** (`_event_store.py::PostgresEventStore`):
- `_EVENT_FIELDS` class constant: add `on_behalf_of`
- `append()`: add `on_behalf_of` to INSERT column list and values

**Layer 3 — InMemory append** (`_in_memory_events.py`):
- `in_memory_append_event()`: add parameter, pass to `_store_append()`

**Layer 3 — InMemory transition** (`_in_memory_transition.py`):
- `in_memory_transition()`: add parameter, pass to `_store_append()`

**Layer 4 — API layer** (`_events_api.py`):
- `append_event()`: add parameter, pass to `_store_append_event()`

**Layer 4 — Transition** (`_transition.py`):
- `transition()`: add parameter, pass to `_append_transition_event()`

**Layer 5 — Facades** (`_ops.py`):
- `EventOps.append()`: add parameter, pass to `_impl()`
- `WorkItemOps.update_not_before()`: add parameter, pass to `_append_event()`

**Layer 5 — Public API** (`__init__.py`):
- `Regista.append_event()`: add `on_behalf_of: dict | None = None`, validate, pass to facade
- `Regista.transition()`: add `on_behalf_of: dict | None = None`, validate, pass to facade

**Layer 6 — InMemoryRegista** (`_in_memory.py`):
- `InMemoryRegista.append_event()`: add parameter, validate, pass to `in_memory_append_event()`
- `InMemoryRegista.transition()`: add parameter, validate, pass to `in_memory_transition()`

### 3.7 Replay

In `_replay.py`:
- `_EVENT_FIELDS`: add `on_behalf_of`
- `_replay_work_item()`: pass `evt["on_behalf_of"]` to `verify_event()`

In `_in_memory_replay.py`: same pattern — pass `on_behalf_of` from event to `verify_event()`.

No projection change. The `on_behalf_of` field is not denormalized into `work_items_current`.

### 3.8 Sidecar

In `sidecar/models.py`:
- `AppendEventRequest`: add `on_behalf_of: dict | None = None`
- `TransitionRequest`: add `on_behalf_of: dict | None = None`

In `sidecar/routes.py`:
- `append_event()`: pass `body.on_behalf_of` to `regista.append_event()`
- `transition()`: pass `body.on_behalf_of` to `regista.transition()`

## 4. Migration

New file: `migrations/014_on_behalf_of.sql`

```sql
-- BC-197: Add delegation chain to events for on-behalf-of tracking.
ALTER TABLE events ADD COLUMN on_behalf_of JSONB;
```

Nullable column. All existing rows get `NULL`. No data backfill. No index (audit-only, not queried by projection).

## 5. API Changes

### New public parameters

| Method | New parameter | Default |
|---|---|---|
| `Regista.append_event()` | `on_behalf_of: dict \| None` | `None` |
| `Regista.transition()` | `on_behalf_of: dict \| None` | `None` |
| `InMemoryRegista.append_event()` | `on_behalf_of: dict \| None` | `None` |
| `InMemoryRegista.transition()` | `on_behalf_of: dict \| None` | `None` |
| `EventOps.append()` | `on_behalf_of: dict \| None` | `None` |
| `WorkItemOps.update_not_before()` | `on_behalf_of: dict \| None` | `None` |
| Sidecar `POST /append_event` | `on_behalf_of` body field | omitted |
| Sidecar `POST /transition` | `on_behalf_of` body field | omitted |

### New internal type

`DelegationChain` in `_types.py` — internal, not part of the public API surface. Callers pass `dict`; the dataclass is a convenience for consumers who want typed deserialization.

### No new error codes

Validation uses existing `INVALID_ARGUMENT`. If we later want specificity, we can add `DELEGATION_CHAIN_INVALID` without breaking changes.

## 6. Backward Compatibility

| Concern | Resolution |
|---|---|
| Old events have no `on_behalf_of` column | Migration adds nullable column; existing rows get `NULL` |
| Old signatures don't include `on_behalf_of` | `verify_event()` backward-compat retry (see 3.4) and stored envelope path |
| Old clients don't send `on_behalf_of` | Parameter defaults to `None`; no behavior change |
| `Event.to_dict()` / `from_dict()` | Updated to include `on_behalf_of`; old dicts missing the key deserialize to `None` via `.get()` |
| `_EVENT_FIELDS` change | Only affects new code that reads the column; old events return `NULL` |
| Sidecar `extra="forbid"` | New field is optional with default `None`; old requests omitting it are unchanged |
| Replay of mixed old+new events | Old events have `NULL` `on_behalf_of`; replay passes `None` to `verify_event()` |

## 7. Testing

### Unit tests

1. **`test_signing.py`**: Verify `build_signing_envelope` includes `on_behalf_of` in canonical output. Verify `sign_event`/`verify_event` round-trip with `on_behalf_of` present. Verify backward-compat: event signed without `on_behalf_of` verifies when `on_behalf_of=None` is passed. Verify event signed without `on_behalf_of` does NOT verify when a non-None `on_behalf_of` is passed (tamper detection).

2. **`test_contract.py`**: `validate_delegation_chain` — valid chain, missing `principal_id`, wrong types, empty scope, valid scope, `None` input (no-op).

3. **`test_types.py`**: `DelegationChain.to_dict()` / `from_dict()` round-trip. `Event.to_dict()` / `from_dict()` with and without `on_behalf_of`.

### Integration tests

4. **`test_events.py`**: Append event with `on_behalf_of`, verify it is stored and returned. Append event without `on_behalf_of`, verify `None`. Transition with `on_behalf_of`, verify propagated.

5. **`test_replay.py`**: Append events with and without `on_behalf_of`, replay, verify no drift. Verify old events (no `on_behalf_of` column in envelope) still verify.

6. **`test_in_memory_conformance.py`**: Verify InMemory append/transition paths accept and store `on_behalf_of`.

7. **`test_sidecar.py`**: POST `/append_event` and `/transition` with `on_behalf_of` in body. Verify 200. Verify without `on_behalf_of` (backward compat, no error).

8. **`test_ops.py`**: Verify `EventOps.append()` and `WorkItemOps.update_not_before()` pass `on_behalf_of` through.

9. **Migration test**: Verify migration `014_on_behalf_of.sql` applies cleanly on top of existing schema. Verify `events` table has `on_behalf_of JSONB` column. Verify existing event rows have `NULL` for the new column.

## 8. Files Changed

| File | Change |
|---|---|
| `src/regista/_types.py` | Add `DelegationChain` dataclass. Add `on_behalf_of` field to `Event`. Update `Event.to_dict()` / `from_dict()`. |
| `src/regista/_signing.py` | Add `on_behalf_of` param to `build_signing_envelope()`, `sign_event()`, `verify_event()`. Add backward-compat retry in `verify_event()`. |
| `src/regista/_contract.py` | Add `validate_delegation_chain()`. |
| `src/regista/_event_store.py` | Add `on_behalf_of` param to `append_event()`. Update `PostgresEventStore._EVENT_FIELDS`, `PostgresEventStore.append()` INSERT. |
| `src/regista/_events.py` | Add `on_behalf_of` to `_EVENT_FIELDS`. Update `_row_to_event()`. Add param to `append_event()`, `append_transition_event()` — pass to `sign_event()` and include in INSERT. |
| `src/regista/_events_api.py` | Add `on_behalf_of` param to `append_event()`, pass to `_store_append_event()`. |
| `src/regista/_transition.py` | Add `on_behalf_of` param to `transition()`, pass to `_append_transition_event()`. |
| `src/regista/_ops.py` | Add `on_behalf_of` param to `EventOps.append()`, `WorkItemOps.update_not_before()`. |
| `src/regista/__init__.py` | Add `on_behalf_of` param to `Regista.append_event()`, `Regista.transition()`. Validate and delegate. |
| `src/regista/_in_memory.py` | Add `on_behalf_of` param to `InMemoryRegista.append_event()`, `InMemoryRegista.transition()`. |
| `src/regista/_in_memory_events.py` | Add `on_behalf_of` param to `in_memory_append_event()`, pass to `_store_append()`. |
| `src/regista/_in_memory_transition.py` | Add `on_behalf_of` param to `in_memory_transition()`, pass to `_store_append()`. |
| `src/regista/_replay.py` | Add `on_behalf_of` to `_EVENT_FIELDS`. Pass `evt["on_behalf_of"]` to `verify_event()`. |
| `src/regista/_in_memory_replay.py` | Pass `on_behalf_of` from event to `verify_event()`. |
| `src/regista/sidecar/models.py` | Add `on_behalf_of: dict \| None = None` to `AppendEventRequest` and `TransitionRequest`. |
| `src/regista/sidecar/routes.py` | Pass `body.on_behalf_of` in `append_event` and `transition` route handlers. |
| `migrations/014_on_behalf_of.sql` | New file: `ALTER TABLE events ADD COLUMN on_behalf_of JSONB;` |

## 9. Implementation Order

1. `_types.py` — DelegationChain + Event field
2. `_signing.py` — envelope changes + backward compat
3. `_contract.py` — validation
4. `migrations/014_on_behalf_of.sql` — schema change
5. `_events.py` — `_EVENT_FIELDS`, `_row_to_event()`, `append_event()`, `append_transition_event()`
6. `_event_store.py` — shared `append_event()`, `PostgresEventStore`
7. `_events_api.py` — API layer
8. `_transition.py` — transition path
9. `_ops.py` — facades
10. `__init__.py` — public API
11. `_in_memory_events.py`, `_in_memory_transition.py`, `_in_memory.py` — InMemory stack
12. `_replay.py`, `_in_memory_replay.py` — replay verification
13. `sidecar/models.py`, `sidecar/routes.py` — HTTP API
14. Tests (all layers)
