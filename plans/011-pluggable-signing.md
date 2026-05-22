# Plan 011 — Pluggable Signing (Ed25519 + HMAC-SHA256)

**Status:** Draft RFC
**Owner:** plm
**Resolves:** BC-196
**Spec touched:** §17 (signing), FR-15 (event authentication), §19.5 (error codes)
**Related:** BC-172 (rfc8785 SPOF — vendored in Plan 008 WS-3), Plan 008 WS-2 (key material protection)

## 1. Overview

Substrate's event signing is hardcoded to HMAC-SHA256. This plan makes the signing scheme pluggable by introducing a `SigningScheme` protocol, an `Ed25519Scheme` implementation alongside the existing `HMACSHA256Scheme`, a `scheme_id` column on the `events` table, and a registry that allows replay to select the correct verifier per event.

All existing events remain HMAC-SHA256 signed. No data migration of signatures or keys is required. The change is fully backward-compatible: existing key files, existing databases, and existing code paths work unchanged until an operator opts into Ed25519 by adding a key entry with `"scheme": "ed25519"`.

## 2. Motivation

HMAC-SHA256 is a symmetric scheme: the same key material signs and verifies. This means any process that can verify events can also forge them. For single-operator homelab deployments this is acceptable (Plan 008, BC-100). For multi-tenant or audited deployments, asymmetric signing provides:

1. **Verification-only distribution.** Public keys can be distributed to audit/consumer processes without granting signing capability.
2. **Non-repudiation.** Only the holder of the private key could have produced the signature. HMAC provides only authentication, not non-repudiation.
3. **Key rotation isolation.** Ed25519 key pairs can be rotated without the verification key ever being exposed to the signing process's memory.
4. **Industry alignment.** Ed25519 is the standard for event log integrity (Sigstore, OpenPubKey, CNCF in-toto).

BC-196 accepted: signing scheme is pluggable, Ed25519 added as a first-class option.

## 3. Design

### 3.1 SigningScheme protocol

New file `src/substrate/_signing_scheme.py`. Defines the protocol and the registry.

```python
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SigningScheme(Protocol):
    scheme_id: str

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        """Returns (signature, envelope_hash)."""
        ...

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
    ) -> bool: ...


_registry: dict[str, type] = {}


def register_scheme(cls: type) -> type:
    _registry[cls.scheme_id] = cls
    return cls


def get_scheme(scheme_id: str) -> SigningScheme:
    cls = _registry.get(scheme_id)
    if cls is None:
        raise ValueError(f"Unknown signing scheme: {scheme_id!r}")
    return cls()


def available_schemes() -> list[str]:
    return sorted(_registry.keys())
```

### 3.2 HMACSHA256Scheme

Extract the existing `compute_hmac`, `compute_canonical_hash`, and `verify_hmac` logic from `_signing.py` into a class:

```python
@register_scheme
class HMACSHA256Scheme:
    scheme_id: str = "hmac-sha256"

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        import hashlib, hmac as _hmac
        sig = _hmac.new(key_material, envelope, hashlib.sha256).digest()
        h = hashlib.sha256(envelope).digest()
        return (sig, h)

    def verify(self, envelope, signature, envelope_hash, key_material) -> bool:
        import hashlib, hmac as _hmac
        expected = _hmac.new(key_material, envelope, hashlib.sha256).digest()
        return _hmac.compare_digest(expected, signature) and hashlib.sha256(envelope).digest() == envelope_hash
```

### 3.3 Ed25519Scheme

Uses `nacl.signing` from PyNaCl. Key material is the 32-byte Ed25519 private key seed for signing, 32-byte public key for verification.

```python
@register_scheme
class Ed25519Scheme:
    scheme_id: str = "ed25519"

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        import nacl.signing, hashlib
        signing_key = nacl.signing.SigningKey(key_material)
        sig = signing_key.sign(envelope).signature
        h = hashlib.sha256(envelope).digest()
        return (sig, h)

    def verify(self, envelope, signature, envelope_hash, key_material) -> bool:
        import nacl.signing, hashlib
        verify_key = nacl.signing.VerifyKey(key_material)
        try:
            verify_key.verify(envelope, signature)
        except nacl.exceptions.BadSignatureError:
            return False
        return hashlib.sha256(envelope).digest() == envelope_hash
```

The import of `nacl.signing` is deferred to method call time. If PyNaCl is not installed, the error surfaces when the scheme is used, not at module import.

### 3.4 Key file format

`KeyEntry` gains a `scheme: str` field:

```python
@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    secret: bytes
    status: str
    scheme: str = "hmac-sha256"
```

Key file JSON gains an optional `scheme` field per key entry:

```json
{
  "keys": [
    {"key_id": "key-001", "secret": "base64...", "status": "active", "scheme": "hmac-sha256"},
    {"key_id": "key-002", "secret": "base64...", "status": "active", "scheme": "ed25519"}
  ]
}
```

Omitting `scheme` defaults to `"hmac-sha256"` — existing key files work unchanged.

`KeySet._load()` reads the `scheme` field, validates it against the registry, and stores it on `KeyEntry`. If `scheme` is `"ed25519"` and PyNaCl is not installed, `KeySet._load()` raises `SubstrateError(KEY_LOAD_ERROR, ...)` at load time — not at sign time.

### 3.5 KeySet scheme resolution

`KeySet` gains two methods:

```python
def active_scheme(self) -> SigningScheme:
    entry = self.active_key()
    return get_scheme(entry.scheme)

def get_scheme(self, key_id: str) -> SigningScheme:
    entry = self.get_key(key_id)
    return get_scheme(entry.scheme)
```

These resolve the `SigningScheme` instance for a given key entry. Used at sign time (active key) and replay time (per-event key).

### 3.6 scheme_id column on events

New migration `014_event_scheme_id.sql`:

```sql
ALTER TABLE events ADD COLUMN scheme_id TEXT NOT NULL DEFAULT 'hmac-sha256';
```

All existing rows get `'hmac-sha256'`. New events get the scheme of the active key at sign time.

The `_EVENT_FIELDS` constant in `_events.py` and `_row_to_event()` are updated to include `scheme_id`. The `Event` dataclass gains `scheme_id: str = "hmac-sha256"`.

### 3.7 sign_event / verify_event changes

`sign_event()` in `_signing.py` gains an optional `scheme` parameter:

```python
def sign_event(
    event_id, work_item_id, actor_id, transition, payload,
    key: bytes,
    scheme: SigningScheme | None = None,
) -> tuple[bytes, bytes, bytes]:
    if scheme is None:
        scheme = HMACSHA256Scheme()
    envelope = build_signing_envelope(event_id, work_item_id, actor_id, transition, payload)
    signature, canonical_hash = scheme.sign(envelope, key)
    return (signature, canonical_hash, envelope)
```

`verify_event()` gains an optional `scheme` parameter:

```python
def verify_event(
    event_id, work_item_id, actor_id, transition, payload,
    signature, canonical_hash, key,
    stored_envelope=None,
    scheme: SigningScheme | None = None,
) -> bool:
    if scheme is None:
        scheme = HMACSHA256Scheme()
    envelope = stored_envelope or build_signing_envelope(...)
    return scheme.verify(envelope, signature, canonical_hash, key)
```

When `scheme` is `None`, both default to `HMACSHA256Scheme` — backward compatible with every existing call site.

### 3.8 Event append path

In `_events.py::append_event()` and `_events.py::append_transition_event()`, after resolving `key_entry = key_set.active_key()`:

```python
scheme = key_set.active_scheme()
signature, canonical_hash, canonical_envelope = sign_event(
    ..., key=key_entry.secret, scheme=scheme,
)
```

The INSERT statement includes `scheme_id`:

```sql
INSERT INTO events (..., scheme_id, ...) VALUES (..., %s, ...)
```

with `scheme.scheme_id` as the parameter.

### 3.9 InMemory event store

`_event_store.py::append_event()` follows the same pattern: resolve scheme from `key_set.active_scheme()`, pass to `sign_event()`. The `Event` object stores `scheme_id`. No Postgres dependency.

### 3.10 Replay

In `_replay.py` and `_in_memory_replay.py`, replay reads `scheme_id` from the event row (Postgres) or `Event.scheme_id` (in-memory), resolves the scheme via `get_scheme(scheme_id)`, and passes it to `verify_event()`:

```python
scheme = get_scheme(evt["scheme_id"])
if not verify_event(
    ...,
    key=key_entry.secret,
    scheme=scheme,
):
    raise _ReplayHaltError(...)
```

Unknown scheme IDs (e.g., a custom scheme not registered in this process) produce a clear `SubstrateError(SCHEME_NOT_FOUND, ...)` — not a generic signature failure.

## 4. Key File Format

### Current format (unchanged)

```json
{
  "keys": [
    {"key_id": "key-001", "secret": "a2V5LWNvbnRlbnQ=", "status": "active"}
  ]
}
```

Treated as `scheme: "hmac-sha256"` by default.

### New format (Ed25519 key added)

```json
{
  "keys": [
    {"key_id": "key-001", "secret": "a2V5LWNvbnRlbnQ=", "status": "deprecated", "scheme": "hmac-sha256"},
    {"key_id": "key-002", "secret": "ZWQyNTUxOV9wcml2YXRlX2tleV9zZWVk", "status": "active", "scheme": "ed25519"}
  ]
}
```

Key material for Ed25519: the 32-byte private key seed, base64-encoded in the JSON `secret` field. For verification-only deployments, the `secret` field contains the 32-byte public key instead; the `verify` path detects this by key length and context (the `KeySet` could be loaded with `verify_only=True` in a future plan — out of scope here).

### Validation

- `scheme` must be a non-empty string present in the scheme registry at load time.
- `scheme` defaults to `"hmac-sha256"` if omitted (backward compat).
- If the scheme's required library is not installed, `KeySet._load()` raises `SubstrateError(KEY_LOAD_ERROR, "Scheme 'ed25519' requires PyNaCl: pip install substrate[ed25519]")`.

## 5. Migration

**Migration 014:** `014_event_scheme_id.sql`

```sql
ALTER TABLE events ADD COLUMN scheme_id TEXT NOT NULL DEFAULT 'hmac-sha256';
```

- No data backfill needed. `DEFAULT 'hmac-sha256'` fills all existing rows.
- No index needed. `scheme_id` is used in replay (sequential scan over per-work-item events, already constrained by PK). An operator adding a custom analytics query on scheme_id can add their own index.
- Column is `NOT NULL` with a default — no application-level constraint violations.

**Migration 015:** Update `migration_checksums` table (automatically handled by `_migrations.py` when migration 012 is present).

## 6. API Changes

### Public API (no changes)

The `Substrate` class public API is unchanged. Scheme selection is driven by the key file. Operators opt into Ed25519 by:

1. Installing `pip install substrate[ed25519]`.
2. Adding an Ed25519 key entry to their key file with `"scheme": "ed25519"`.
3. Setting its `status` to `"active"` and the old HMAC key to `"deprecated"`.

### Internal API

| Module | Change |
|---|---|
| `_signing_scheme.py` | **New file.** Protocol, registry, `HMACSHA256Scheme`, `Ed25519Scheme`. |
| `_signing.py` | `sign_event()` and `verify_event()` gain optional `scheme` parameter. Default preserves backward compat. |
| `_keys.py` | `KeyEntry` gains `scheme: str = "hmac-sha256"`. `KeySet` gains `active_scheme()` and `get_scheme()` methods. `_load()` reads and validates `scheme` field. |
| `_types.py` | `Event` gains `scheme_id: str = "hmac-sha256"`. `to_dict()` / `from_dict()` include `scheme_id`. |
| `_events.py` | `_EVENT_FIELDS` includes `scheme_id`. `_row_to_event()` reads `scheme_id`. INSERT includes `scheme_id`. Call sites pass scheme to `sign_event()`. |
| `_event_store.py` | In-memory append passes scheme to `sign_event()`. |
| `_replay.py` | Reads `scheme_id` from event row, resolves scheme, passes to `verify_event()`. |
| `_in_memory_replay.py` | Reads `scheme_id` from `Event`, resolves scheme, passes to `verify_event()`. |
| `_testing.py` | Re-exports `get_scheme` and `available_schemes` for test access. |
| `_errors.py` | New error code: `SIGNING_SCHEME_NOT_FOUND = "SIGNING_SCHEME_NOT_FOUND"`. |

### Error codes

| Code | When |
|---|---|
| `SIGNING_SCHEME_NOT_FOUND` | Replay encounters an event with a `scheme_id` not in the registry. |
| `KEY_LOAD_ERROR` (existing) | Key file references a scheme whose library is not installed. |

## 7. Backward Compatibility

| Concern | Resolution |
|---|---|
| Existing key files without `scheme` field | Defaults to `"hmac-sha256"`. No change required. |
| Existing events without `scheme_id` column | Migration 014 adds column with `DEFAULT 'hmac-sha256'`. All existing rows get the correct value. |
| Existing call sites of `sign_event()` / `verify_event()` | `scheme` parameter defaults to `None` → `HMACSHA256Scheme()`. All existing callers work unchanged. |
| Existing `Event` dataclass usage | `scheme_id` has default `"hmac-sha256"`. Existing code constructing `Event` without `scheme_id` works. |
| Existing `KeyEntry` construction | `scheme` has default `"hmac-sha256"`. Existing code constructing `KeyEntry` without `scheme` works. |
| Replay of existing events | Reads `scheme_id = 'hmac-sha256'` from column, resolves `HMACSHA256Scheme`, verifies identically to today. |
| InMemorySubstrate events | `scheme_id` defaults to `"hmac-sha256"`. In-memory replay works unchanged. |
| Sidecar (Plan 005) | Sidecar rejects `signature` and `payload_canonical_hash` in request bodies (sole-signer middleware). `scheme_id` is not a request field — it's internal. No sidecar change needed. |
| CLI (Plan 002) | `events show/tail` display `scheme_id` in `--json` output. No behavior change. |

## 8. Dependencies

### New optional dependency

```toml
[project.optional-dependencies]
ed25519 = ["PyNaCl>=1.5"]
```

Rationale:
- PyNaCl is the standard Python binding for libsodium. Well-maintained, MIT/Apache-2.0 licensed.
- `cryptography` (pyca) also supports Ed25519 but is heavier (OpenSSL binding). PyNaCl's API is more direct for seed-based signing.
- Marked optional. Substrate installs and functions fully without it. Only Ed25519 scheme requires it.
- Import is deferred to method body, not module top-level. Missing library raises `ImportError` with a clear message at use time.

### No new runtime dependencies

The `hmac-sha256` scheme uses only stdlib (`hashlib`, `hmac`). The scheme registry and protocol have no dependencies.

## 9. Testing

### Unit tests (`tests/test_signing_scheme.py`, new)

1. `HMACSHA256Scheme` round-trip: sign, verify, assert true. Tamper one byte, assert false.
2. `HMACSHA256Scheme` produces identical output to current `compute_hmac` / `compute_canonical_hash` for the same inputs (regression guard).
3. `Ed25519Scheme` round-trip: sign with seed, verify with public key, assert true.
4. `Ed25519Scheme` tamper: flip one byte of signature, assert false. Flip one byte of envelope, assert false.
5. Registry: `register_scheme`, `get_scheme`, `available_schemes`. Unknown scheme raises `ValueError`.
6. `sign_event` with explicit `scheme=HMACSHA256Scheme()` produces same output as `scheme=None`.
7. `verify_event` with explicit scheme matches default behavior.

### Integration tests (`tests/test_signing_ed25519.py`, new)

1. Create project, register workflow, create work item, transition with Ed25519 active key. Read events, assert `scheme_id = 'ed25519'`. Verify signature with public key only.
2. Key rotation: events signed with HMAC key, then rotate to Ed25519 key, then more events. Replay verifies both correctly using `scheme_id` from each event.
3. Key file with `"scheme": "ed25519"` but PyNaCl not installed: assert `KEY_LOAD_ERROR` at `KeySet._load()`.
4. Replay with `scheme_id` not in registry: assert `SIGNING_SCHEME_NOT_FOUND`.

### Existing test impact

- `tests/test_signing.py`: unchanged. Tests `sign_event` / `verify_event` with default (HMAC) scheme.
- `tests/test_key_lifecycle.py`: add test for `scheme` field in `KeyEntry`, default value, and explicit value.
- `tests/test_in_memory_conformance.py`: unchanged (uses `HMACSHA256Scheme` by default).
- Property-based tests (`tests/test_property_conformance.py`): extend to generate events with both schemes, verify round-trip for each.

### Test coverage for migration

- Integration test: create events (pre-migration), run migration 014, assert all existing events have `scheme_id = 'hmac-sha256'`.
- New events after migration have correct `scheme_id` matching active key's scheme.

## 10. Files Changed

| File | Action | Description |
|---|---|---|
| `src/substrate/_signing_scheme.py` | **New** | Protocol, registry, `HMACSHA256Scheme`, `Ed25519Scheme` |
| `src/substrate/_signing.py` | Modify | `sign_event()` / `verify_event()` gain `scheme` parameter |
| `src/substrate/_keys.py` | Modify | `KeyEntry.scheme`, `KeySet.active_scheme()`, `KeySet.get_scheme()`, scheme validation in `_load()` |
| `src/substrate/_types.py` | Modify | `Event.scheme_id` field, `to_dict()` / `from_dict()` |
| `src/substrate/_events.py` | Modify | `_EVENT_FIELDS`, `_row_to_event()`, INSERT statements, scheme resolution at sign time |
| `src/substrate/_event_store.py` | Modify | In-memory append passes scheme to `sign_event()` |
| `src/substrate/_replay.py` | Modify | Reads `scheme_id`, resolves scheme, passes to `verify_event()` |
| `src/substrate/_in_memory_replay.py` | Modify | Reads `scheme_id` from `Event`, resolves scheme, passes to `verify_event()` |
| `src/substrate/_errors.py` | Modify | Add `SIGNING_SCHEME_NOT_FOUND` |
| `src/substrate/_testing.py` | Modify | Re-export `get_scheme`, `available_schemes` |
| `migrations/014_event_scheme_id.sql` | **New** | Add `scheme_id TEXT NOT NULL DEFAULT 'hmac-sha256'` to `events` |
| `pyproject.toml` | Modify | Add `[project.optional-dependencies] ed25519 = ["PyNaCl>=1.5"]` |
| `tests/test_signing_scheme.py` | **New** | Unit tests for protocol, registry, both schemes |
| `tests/test_signing_ed25519.py` | **New** | Integration tests for Ed25519 event lifecycle |

## 11. Open Questions

1. **Ed25519 key representation in the key file.** The `secret` field holds base64-encoded bytes. For Ed25519, this is the 32-byte private key seed. Should we also support the 64-byte expanded key (seed + public key concatenated) that `nacl.signing.SigningKey.encode()` produces? **Recommendation:** start with 32-byte seed only. Document the expected format. Expanded key support can be added later if operators find it useful.

2. **Verification-only mode.** A consumer that only reads events and verifies signatures needs only the public key. Currently `KeySet` stores `secret: bytes` used for both signing and verification. A `verify_only` mode where `KeyEntry.secret` holds the public key is useful but adds complexity to the `verify()` dispatch. **Recommendation:** defer to a follow-up. For now, consumers that verify also have access to the full key file (homelab trust boundary). The `scheme_id` column enables future verification-only deployments.

3. **Custom scheme registration.** The registry is module-level. A consumer can `from substrate._signing_scheme import register_scheme` and add their own. Should this be part of the public API (`Substrate.register_signing_scheme()`)? **Recommendation:** keep it internal for now. The `_signing_scheme` module is stable enough for advanced consumers to import directly, but we don't commit to its API surface until there's demand.

4. **Migration numbering.** Migration 014 is next in sequence. This plan assumes no other plan adds migrations between 013 and 014. If plans are developed concurrently, renumber accordingly.
