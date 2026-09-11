# Plan 008 — Trust Model Hardening for Multi-Tenant Deployment

**Status:** Draft RFC
**Owner:** plm
**Prereq for:** production multi-tenant use beyond single-operator homelab
**Spec touched:** §17.9 (trust tiers), BR-09 (authorization), BR-13 (schema isolation), §20 (consumer expectation boundary)
**Related:** BC-100 (HMAC in plaintext memory), BC-101 (self-attested roles), BC-102 (no rate limiting), BC-172 (rfc8785 SPOF), BC-174 (unknown key status silently skipped)

## 1. Problem Statement

Regista's trust model is designed for a single-operator homelab: one person runs all agents, trusts them not to misdeclare roles, and has physical access to the database and key material. The spec (§17.9) explicitly defines three trust tiers:

1. **Authenticated** — `actor_id` proven by HMAC (FR-15)
2. **Server-stamped** — `timestamp`, `event_seq`, `key_id` set by the library
3. **Actor-claimed** — `actor_metadata` (role, model, provider) — signed but not validated

Four accepted breadcrumbs document the gap between this model and what a multi-tenant deployment requires:

| BC | Issue | Current status |
|---|---|---|
| BC-100 | HMAC key material held in plaintext Python memory | Accepted — environmental trust boundary |
| BC-101 | `actor_metadata.role` is self-attested | Accepted — by design per BR-09 |
| BC-102 | No rate limiting on any API endpoint | Accepted — library, not daemon |
| BC-172 | `rfc8785` is a single point of failure for signature integrity | Pin only; vendoring deferred |
| BC-174 | Unknown key status silently skipped — typo drops keys from rotation | Warning only |

In a multi-tenant deployment (multiple operators, multiple agent pools, shared Postgres), these accepted tradeoffs become security vulnerabilities.

## 2. Threat Model: Homelab vs Multi-Tenant

| Threat | Homelab risk | Multi-tenant risk | Current defense |
|---|---|---|---|
| Actor misdeclares role | Low — single operator trusts all agents | High — competing agents may claim elevated roles | FR-24 (opt-in, per-actor) |
| Key exfiltration from memory | Low — physical access assumed | Medium — shared runtime, container escapes | None |
| Replay/signature forgery via rfc8785 bug | Low — single canonicalizer | Low but high blast radius | Version pin |
| Denial of service via unbounded API calls | Low — trusted callers | High — any authenticated actor can exhaust resources | None |
| Key rotation typo (BC-174) | Low — operator notices missing metrics | Medium — missing key silently drops from rotation | Log warning |
| Cross-project data access | Impossible — schema isolation (FR-19) | Impossible — same mechanism | Schema-per-project |

## 3. Proposed Hardening (Five Workstreams)

### WS-1: Mandatory role enforcement with role-provenance

**Current:** FR-24 is opt-in. Actors with no registered roles are trusted.

**Proposal:** Add a `strict_roles: bool = False` flag to `Regista.__init__`. When `True`:

1. Every actor must have at least one registered role before any transition is allowed.
2. `actor_metadata.role_source` must be `config` or `env` — `prompt`-source roles are rejected.
3. Unregistered actors receive `ACTOR_ROLE_NOT_AUTHORIZED` instead of being silently trusted.

This preserves backward compatibility (`strict_roles=False` is the default) while giving operators a single flag to flip when the threat model changes.

**Spec impact:** Adds a new §17.10 subsection "Enforcement modes: permissive vs strict." BR-09 is extended, not replaced.

**Implementation:** Pure `_contract.py` change. `resolve_transition` already checks `check_actor_role_authorized`. Add a `strict: bool` parameter that rejects when `registered_roles` is empty.

### WS-2: Key material protection

**Current:** HMAC keys are loaded from a JSON file into Python `str` objects. They remain in memory for the lifetime of the process. `KeySet._load()` logs a plaintext-at-rest warning (BC-180).

**Proposal (layered):**

1. **Environment-variable injection.** Accept `REGISTA_HMAC_KEY_<KEY_ID>` env vars. Keys never touch disk in production. `KeySet` resolves keys from env vars first, falling back to file.
2. **Memory-lock hint.** Call `mlock()` on key buffers via `ctypes` on Linux. Best-effort — logs a warning if `mlock` is unavailable (containers, unprivileged).
3. **Key zeroization on `close()`.** Overwrite key bytes with zeros before releasing. Not deterministic (Python string interning), but reduces the window for core-dump extraction.

**Spec impact:** Adds `hmac_key_env_prefix` parameter to `Regista.__init__`. Backward compatible.

**What this does NOT do:** Full KMS integration (AWS KMS, Vault transit) is out of scope for this RFC. The library is in-process and must hold the key material to sign. A KMS integration would require an HSM-backed signing delegation model, which is a separate architectural decision.

### WS-3: rfc8785 supply-chain hardening

**Current:** Pinned to `rfc8785==0.1.4`. No cross-validation.

**Proposal:**

1. **Vendor `rfc8785` into `src/regista/_vendor/rfc8785/`.** The library is a single Python module (~400 lines). Vendoring eliminates PyPI supply-chain risk.
2. **Add a cross-validation test.** At build time, generate a corpus of 1,000 random JSON objects, canonicalize with both the vendored copy and the system `rfc8785` package, assert byte-identical output. This catches divergence during upgrades.
3. **Pin `rfc8785` as a test-only dependency.** Production uses the vendored copy. Tests can opt into cross-validation by installing `rfc8785` from PyPI.

**Spec impact:** None. The canonicalization contract (§17, FR-15) is unchanged.

### WS-4: Rate limiting at the sidecar boundary

**Current:** No rate limiting. BC-102 accepted as "library, not daemon."

**Proposal:** Rate limiting belongs at the sidecar (Plan 005), not the library. Add middleware to the sidecar:

```python
from slowapi import Limiter

limiter = Limiter(key_func=get_actor_id_from_token)

@app.post("/work-items")
@limiter.limit("100/minute")
async def create_work_item(request, body): ...
```

The library remains rate-limit-free. The sidecar enforces per-actor and per-endpoint limits. Operators who embed regista in-process (the primary use case) are responsible for their own rate limiting.

**Spec impact:** None. Sidecar is an optional deployment artifact.

**Dependency:** `slowapi` (MIT license, wraps `limits` library). Optional, under `[sidecar]` extra.

### WS-5: Key rotation safety

**Current:** Unknown key status in the key file is silently skipped (BC-174). A typo in the `status` field (e.g., `"actve"` instead of `"active"`) drops the key from rotation with only a metric counter to signal it.

**Proposal:**

1. **Raise on unknown status.** Instead of `continue`, raise `RegistaError(KEY_LOAD_ERROR)` with the offending key ID and status value. This makes typos fail-fast at startup rather than silently degrading.
2. **Add a key-count assertion.** `KeySet.__init__` accepts `expected_key_count: int | None`. If provided and the loaded count doesn't match, raise. This lets operators pin their expectations.
3. **Add `keys_loaded` structured log at INFO level** (currently only the plaintext-at-rest warning is emitted).

**Spec impact:** None. Key loading is an internal concern.

## 4. What This Plan Does NOT Cover

| Topic | Reason |
|---|---|
| TLS certificate pinning | Postgres connection TLS is already supported (BC-173). Certificate pinning is an operator concern. |
| Row-level security for tenant isolation | BR-13 already documents the migration path. This is a separate infrastructure change. |
| Audit log shipping | Structured logs already exist (FR-21). Shipping to an external SIEM is an operator concern. |
| Encrypted key files (KMS, Vault) | Requires a signing delegation model that changes the architecture. Separate RFC if needed. |

## 5. Implementation Priority

| Workstream | Effort | Impact | Priority |
|---|---|---|---|
| WS-1 (strict roles) | Small (pure `_contract.py`) | High — closes BC-101 gap | 1 |
| WS-5 (key rotation safety) | Small (3-line fix + test) | Medium — closes BC-174 | 2 |
| WS-3 (vendor rfc8785) | Small (copy file + build hook) | Medium — closes BC-172 | 3 |
| WS-2 (key material protection) | Medium (env var + mlock + zeroize) | Medium — defense in depth | 4 |
| WS-4 (sidecar rate limiting) | Medium (new dependency + middleware) | Low — sidecar is optional | 5 |

## 6. Risks

| Risk | Mitigation |
|---|---|
| `strict_roles=True` breaks existing agents | Default is `False`. Operators opt in. Error message includes which actor and which transition. |
| `mlock()` fails in containers | Best-effort with warning log. Container deployments should use env-var injection instead. |
| Vendored rfc8785 drifts from upstream | Cross-validation test in CI. Update vendored copy on upstream release. |
| `slowapi` adds dependency surface | Optional under `[sidecar]` extra. Library users unaffected. |
