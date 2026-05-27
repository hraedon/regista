# Plan 005 — Thin HTTP Sidecar for Regista

Status: draft / provisional
Owner: regista
Related spec sections: §19 (Public API Surface), §19.2 (Signing), §19.3 (Service-wrapping is mechanical), §19.5 (What the API exposes), AC-33

## 1. Motivation & scope

Regista is today a Python library (`src/regista/__init__.py`, the `Regista` class). Spec §19.3 (`spec.md:696-705`) commits to a future sidecar that exposes the same public operations over HTTP/gRPC so non-Python consumers can participate. No such consumer exists yet. The single consumer of regista today is `software-factory-2`, which imports it in-process.

The risk of designing a "REST API for regista" with N=1 callers is baking in resource models, naming conventions, and convenience endpoints that the second consumer will need to break. The spec already takes a position here (§19.3, `spec.md:700`): "Mirror the public operations 1:1. No consolidation, no 'convenience' endpoints that bundle multiple operations behind a single call."

This plan therefore scopes the sidecar as a **thin 1:1 pass-through** of the `Regista` Python API. Each public method becomes one HTTP endpoint. Argument shapes are preserved. Return values are JSON-serialized domain types (already documented as language-agnostic per §19.5, `spec.md:721-725`). No REST resource modeling beyond what regista's primitives imply. v1 is provisional and will be reshaped when consumer #2 lands.

What this unlocks: a non-Python agent (Go, TypeScript, shell tooling) can drive regista without re-implementing JCS, HMAC signing, idempotency handling, or migration management. The spec's "library is the sole signer" invariant (FR-15, `spec.md:137`) holds because the sidecar process owns the only key material.

## 2. Framework choice

**Recommend FastAPI.** Rationale:
- Pydantic models give per-endpoint request validation with low boilerplate, matching regista's already-strict argument validation (`_contract.validate_mutation_params`).
- OpenAPI generation is automatic. The sidecar's whole purpose is to be machine-discoverable from non-Python consumers; an OpenAPI doc is the cheapest possible client-generation contract.
- Starlette underneath; we are not blocked from dropping to raw Starlette routes if a particular endpoint needs streaming later.
- aiohttp considered and rejected: no schema generation, more boilerplate, and regista's calls are sync (psycopg) so the async-first framework is not a defining advantage.

**Installation shape.** Optional install extra, not a hard dependency on the core library:

```toml
[project.optional-dependencies]
sidecar = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.7",
]
```

Library consumers who only import `regista` get no FastAPI in their dependency closure. The sidecar is a separately invoked entrypoint (e.g., `python -m regista.sidecar`) that the in-process library never imports.

## 3. Endpoint surface

1:1 with the `Regista` class in `src/regista/__init__.py`. Convention: `POST /v1/<operation_name>` for mutations and operations with side effects, `GET /v1/<resource>/<id>` for pure lookups, request body is the kwarg dict, response body is the JSON-serialized return value. No path-encoded business identifiers beyond `get_work_item` and similar pure reads.

Examples (not exhaustive):

| Regista method (`__init__.py` line) | HTTP route |
|---|---|
| `register_workflow` (276) | `POST /v1/register_workflow` |
| `get_workflow` (380) | `GET /v1/workflows/{name}/{version}` |
| `create_work_item` (398) | `POST /v1/create_work_item` |
| `get_work_item` (871) | `GET /v1/work_items/{work_item_id}` |
| `transition` (556) | `POST /v1/transition` |
| `append_event` (460) | `POST /v1/append_event` |
| `read_events` (738) | `POST /v1/read_events` |
| `read_events_since` (790) | `POST /v1/read_events_since` |
| `query_work_items` (817) | `POST /v1/query_work_items` |
| `acquire_claim` (882) | `POST /v1/acquire_claim` |
| `heartbeat_claim` (942) | `POST /v1/heartbeat_claim` |
| `release_claim` (982) | `POST /v1/release_claim` |
| `sweep_expired_claims` (1018) | `POST /v1/sweep_expired_claims` |
| `create_link` (1031) | `POST /v1/create_link` |
| `remove_link` (1091) | `POST /v1/remove_link` |
| `update_not_before` (1240) | `POST /v1/update_not_before` |
| `replay` (1143) | `POST /v1/replay` |
| `list_dead_lettered_hooks` (1207) | `GET /v1/dead_lettered_hooks` |
| `requeue_dead_lettered_hook` (1186) | `POST /v1/requeue_dead_lettered_hook` |
| `register_actor_role` (1325) | `POST /v1/register_actor_role` |
| `unregister_actor_role` (1345) | `POST /v1/unregister_actor_role` |
| `list_actor_roles` (1366) | `GET /v1/actor_roles` |

### 3.1 Hook queue access (closes the non-Python consumer gap)

`register_validator`, `register_hook_handler`, `start_hook_consumer`, `stop_hook_consumer`, and the existing `poll_hooks` are excluded from the HTTP surface — they accept Python callables or drive an in-process callback loop. But excluding them entirely would force any non-Python consumer to deploy a Python companion to do async work, which defeats the sidecar's purpose.

Resolution: expose the **hook queue lifecycle** (not the handler registration) over HTTP. Non-Python consumers poll for work, process it themselves, and ack. This requires new public methods on `Regista` that decompose `poll_and_process_hooks` (`_hooks.py:135`) into claim / complete / fail primitives:

| New `Regista` method | HTTP route | Semantics |
|---|---|---|
| `claim_hooks(max_batch: int, lease_seconds: int)` | `POST /v1/hooks/claim` | `SELECT ... FOR UPDATE SKIP LOCKED LIMIT n`, mark rows `in_progress`, set a lease deadline; returns the batch (hook_queue id, event_id, hook_name, payload, retry_count, max_retries) |
| `complete_hook(hook_queue_id)` | `POST /v1/hooks/{id}/complete` | Set `status='completed'` (mirrors `_hooks.py:187`) |
| `fail_hook(hook_queue_id, error: str)` | `POST /v1/hooks/{id}/fail` | Increment `retry_count`; if `< max_retries` requeue to `pending` (`_hooks.py:208`); if exhausted, move to dead-letter and emit `hook_dead_lettered` (`_hooks.py:225-`). Same code path the in-process consumer already uses — do not duplicate the dead-letter logic. |
| `sweep_expired_hook_leases()` | `POST /v1/hooks/sweep_expired_leases` | Requeue `in_progress` rows past their lease deadline. Cron-style; sidecar can call it on a timer. |

The lease deadline replaces the "still in this Python process" implicit liveness check that today's in-process consumer relies on. A crashed HTTP consumer's hooks come back to the pool when their lease expires, matching how `_hooks.py` recovers from a crashed worker today.

Bearer-token actor identity (§5) carries through to the `failed_at_actor` field on dead-letter rows, so the audit trail still attributes which consumer dropped a hook.

### 3.2 Synchronous validators are not exposed over HTTP — intentional

Spec FR-13 (`spec.md:128`) is normative: transition validators **"Must NOT perform I/O — local computation only"**. A sidecar handler that called out to an external validator endpoint would be I/O on the synchronous transition path, holding the Postgres canonical lock (§17.2) for the round-trip and giving the consumer the ability to wedge transitions indefinitely or beyond the 5s timeout. AC-30 (`spec.md:385`) labels this a contract violation.

Non-Python consumers therefore **cannot register synchronous validators in v1.** Their options:

1. Express the invariant as an **async hook** instead (FR-13 second branch), which is exactly what FR-13's own text directs: *"Validators that need to call out to other systems should instead enqueue an async hook."* The hook polling API (§3.1) gives them this.
2. Wait for a future WASM-runtime path (out of scope — see §12) where pure, I/O-free validators could be uploaded as compiled modules and executed inside the sidecar process with no network egress.

This is an intentional architectural boundary, not a gap to fix. Document it prominently in the sidecar README.

Domain-type JSON shape comes from `_types.py` frozen dataclasses; Pydantic response models mirror them field-for-field. `UUID` → string, `datetime` → ISO 8601, `Jsonb` payload → JSON object.

## 4. Signing & threat model

Spec §19.2 (`spec.md:690-694`) and AC-33 (`spec.md:388`) are normative. Implementation rules:

- **Requests carry unsigned payloads only.** Pydantic request models do NOT include `signature` or `payload_canonical_hash` fields. Any extra field rejection is enforced via `model_config = ConfigDict(extra="forbid")` on every request model.
- **Sidecar signs internally.** Each handler calls into the `Regista` instance exactly as in-process code does. Signing happens inside `_signing.py` / `_event_store.py`, unchanged.
- **HMAC key location.** Path passed as `--hmac-key-path` CLI flag or `REGISTA_HMAC_KEY_PATH` env var. The key file is read at startup by the existing `KeySet` (`_keys.py`) and never traverses the HTTP boundary. The sidecar process MUST run with filesystem permissions that no caller process shares.
- **Rejection error.** Any request body containing a `signature` or `payload_canonical_hash` key returns `400 Bearer is sole signer` with regista error code `LIBRARY_IS_SOLE_SIGNER` (this error code is implied by AC-33; if not yet present in `_errors.py`, add it as part of step 4 below).

## 5. Caller authentication

The sidecar must know who the HTTP caller is so the `actor_id` recorded in the signed event is correct. The spec leaves this to the wrapper.

**v1 minimum: shared-secret bearer tokens.** A YAML config file maps token → actor identity:

```yaml
tokens:
  - token_sha256: "<hex>"
    actor_id: "agent-tsx-runner-1"
    actor_kind: "agent"
    allowed_roles: ["coder", "reviewer"]
```

- Tokens stored hashed; the request carries the raw token in `Authorization: Bearer <token>`.
- The handler injects `actor_id` and `actor_kind` from the resolved token into the regista call. The request body MUST NOT carry `actor_id` directly — overriding the authenticated identity is forbidden. (Mirror the no-pre-signed rule: identity is server-asserted.)
- `allowed_roles` constrains which roles a token can claim via `actor_metadata.role`. Validation lives in the sidecar; regista still re-enforces via FR-24 once `register_actor_role` is populated.

**Deferred to later versions.** mTLS for service-to-service; OIDC / JWT for human consumers; per-token rate limits; token rotation API; audit log of authentication decisions distinct from regista's event log. v1 ships with the shared-secret file plus instructions to rotate by editing-and-restart.

## 6. Error mapping

`RegistaError` (`src/regista/_errors.py:42`) carries a `code: ErrorCode`. The sidecar translates:

| ErrorCode | HTTP |
|---|---|
| `WORK_ITEM_NOT_FOUND`, `WORKFLOW_NOT_REGISTERED`, `CLAIM_NOT_FOUND`, `HOOK_NOT_FOUND`, `LINK_NOT_FOUND`, `LINK_TARGET_NOT_FOUND`, `ACTOR_ROLE_NOT_REGISTERED` | 404 |
| `INVALID_TRANSITION`, `INVALID_FILTER`, `INVALID_ARGUMENT`, `INVALID_ACTOR_KIND`, `WORK_ITEM_TYPE_NOT_DECLARED`, `CUSTOM_FIELD_VIOLATION`, `TRANSITION_VIA_APPEND_BLOCKED`, `WORKFLOW_VALIDATION_FAILED`, `WORKFLOW_SEMANTIC_ERROR`, `LINK_TYPE_NOT_ALLOWED`, `LINK_CROSS_PROJECT`, `NOT_BEFORE_FUTURE` | 400 |
| `ROLE_NOT_PERMITTED`, `ACTOR_ROLE_NOT_AUTHORIZED`, `VALIDATOR_IO_UNSAFE` | 403 |
| `CLAIM_CONTESTED`, `CLAIM_LOST`, `CONCURRENT_MODIFICATION`, `WORKFLOW_VERSION_CONFLICT`, `IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD` | 409 |
| `VALIDATOR_TIMEOUT` | 504 |
| `UNKNOWN_KEY_ID`, `REVOKED_KEY_ID`, `MIGRATION_REQUIRED`, `WORKFLOW_VERSION_INCOMPATIBLE`, `REPLAY_HALTED`, `DB_NOT_FOUND`, `VALIDATOR_FAILED` | 500 |
| `LIBRARY_IS_SOLE_SIGNER` (new, per AC-33) | 400 |

Response body for any error:

```json
{"error": {"code": "<ErrorCode>", "message": "...", "detail": {...}}}
```

`code` is the regista `ErrorCode` string verbatim — error codes are part of the public API contract per §19.5 (`spec.md:725`).

## 7. Deployment shape

**Recommend separate process.** Regista connects to Postgres directly; the sidecar process is the regista process. The "host application" that today imports regista becomes either (a) the sidecar itself, when it has no in-process work beyond the API, or (b) a workers process that imports regista locally for validators and hooks.

Single artifact: a `Dockerfile` in `deploy/sidecar/` with `CMD ["python", "-m", "regista.sidecar"]`. Configuration via env: `REGISTA_DSN`, `REGISTA_PROJECT`, `REGISTA_HMAC_KEY_PATH`, `REGISTA_TOKENS_PATH`, `REGISTA_BIND` (default `0.0.0.0:8080`), `REGISTA_POOL_MIN`/`MAX`.

Isolation rationale: a process boundary makes HMAC key exfiltration require code execution inside the sidecar, not merely a SQL injection or library exploit in a co-tenant app. Same process is permitted but not recommended; document it as an option for tests only.

**Hook handlers — two deployment shapes, operator chooses.**

- *Python in-process consumer (today's shape):* a Python worker process imports regista directly, calls `register_hook_handler` for each hook name, and runs `start_hook_consumer`. The sidecar does not run a hook consumer of its own. Same Postgres DSN.
- *Non-Python HTTP polling consumer (new, per §3.1):* a Go/TS/Rust process holds a bearer token, calls `POST /v1/hooks/claim` on a loop, processes hooks in its own runtime, and acks with `complete` or `fail`. The sidecar should run a periodic in-process call to `sweep_expired_hook_leases()` so crashed consumers don't starve the queue — a single asyncio background task in the sidecar process, not a separate daemon.

Both shapes can coexist (some hooks handled in Python, others via HTTP) because `claim_hooks` operates on the same `hook_queue` rows as the in-process consumer; `FOR UPDATE SKIP LOCKED` keeps them from stepping on each other. Document this in the sidecar README.

Synchronous validators remain Python-in-process only (see §3.2). A sidecar-only deployment with no Python worker is therefore only viable for workflows that declare no transition validators.

## 8. Streaming / long-poll

Out of scope for v1. Regista's event subscription primitive today is poll-based: `read_events_since(work_item_id, after_seq)` (`__init__.py:790`). The sidecar exposes that endpoint; consumers needing near-real-time updates poll it. Document an explicit minimum-poll-interval recommendation (e.g., 500 ms per work item) to discourage tight loops.

WebSockets / SSE / gRPC streaming deferred until a real consumer asks. When that lands, the natural primitive is "subscribe by `project + workflow + after_seq`" wrapping the existing Postgres `LISTEN` channel used by `_hooks.HookConsumer` — but designing it now is speculative.

## 9. Implementation steps

1. Add `[project.optional-dependencies] sidecar` group to `pyproject.toml` (after line 27).
2. Add `LIBRARY_IS_SOLE_SIGNER` to `ErrorCode` in `_errors.py` (closes AC-33's machine-distinguishable error requirement).
3. **Decompose `_hooks.py` to expose hook-queue primitives.** Add public `Regista` methods `claim_hooks(max_batch, lease_seconds)`, `complete_hook(hook_queue_id)`, `fail_hook(hook_queue_id, error)`, `sweep_expired_hook_leases()` by extracting the in-progress / completed / retry / dead-letter transitions already implemented inline in `poll_and_process_hooks` (`_hooks.py:135-225`). The existing in-process consumer must be refactored to call these same methods so both deployment shapes share one code path. Schema change: add `lease_expires_at TIMESTAMPTZ` to `hook_queue` (new migration). This step lands **before** any HTTP code; it's a strictly additive change to the public Python API and unblocks both §3.1 and the in-process consumer's crash recovery.
4. Create `src/regista/sidecar/` package:
   - `__init__.py` — empty.
   - `__main__.py` — argparse / env loader, builds `Regista` instance, mounts FastAPI app, invokes uvicorn, schedules an asyncio task that calls `regista.sweep_expired_hook_leases()` every N seconds (default 30).
   - `app.py` — FastAPI app factory `create_app(regista: Regista, tokens: TokenRegistry) -> FastAPI`.
   - `routes.py` — one file per resource group is fine; each route is < 15 lines (parse Pydantic body, call regista method, serialize result). Hook-queue routes (§3.1) live in `routes_hooks.py` for clarity.
   - `models.py` — Pydantic request/response models, one pair per endpoint, all with `extra="forbid"`.
   - `auth.py` — token loader, dependency that resolves `Authorization: Bearer` to an `AuthenticatedActor` and rejects requests carrying `actor_id` in the body.
   - `errors.py` — `RegistaError → HTTPException` mapper, registered as FastAPI exception handler.
5. Add `tests/sidecar/` with the test plan from §10.
6. Add `deploy/sidecar/Dockerfile` and a minimal `deploy/sidecar/README.md` listing the env vars and documenting the FR-13 validator restriction prominently.
7. Document in `AGENTS.md` under a new "Sidecar (optional)" section. Cross-link from spec §19.3.
8. Open a follow-up breadcrumb for v2 decisions (streaming, mTLS, rate limiting, WASM validators) before merging.

## 10. Test approach

`tests/sidecar/` uses FastAPI's `TestClient` against a `Regista` connected to the existing test DSN (`AGENTS.md:74`).

Required test cases:

- **`test_sole_signer_rejection`** — POST `/v1/create_work_item` with a body containing `"signature": "deadbeef"`. Assert 400, `code == "LIBRARY_IS_SOLE_SIGNER"`. Repeat with `"payload_canonical_hash"`. This is the AC-33 verifier on the wire.
- **`test_actor_id_override_rejected`** — authenticated as `agent-A`, POST `/v1/append_event` with `"actor_id": "agent-B"` in the body. Assert 400. The signed event must use the authenticated identity.
- **`test_endpoint_per_public_method`** — introspect `Regista.__dict__` for public methods, assert each in the §3 surface list has a route, fail with a diff if the library grows a method without a route entry (defends §19.3 1:1 invariant).
- **`test_round_trip_happy_path`** — register workflow, create work item, acquire claim, transition, read events. All via HTTP. Verify the events on the way out have non-empty `signature` and `payload_canonical_hash` (regista signed them).
- **`test_error_code_mapping`** — for each ErrorCode in §6, force the underlying error and verify the HTTP status + body shape.
- **`test_idempotency_over_http`** — submit the same `event_id` twice for `append_event`; assert identical response (BR-12 over the wire, mirrors §19.3 idempotency requirement).
- **`test_auth_required`** — missing / invalid bearer token → 401.
- **`test_role_constraint_enforced_at_sidecar`** — token configured without role `reviewer` attempts a transition that requires it → 403 before regista is called.
- **`test_hook_claim_complete_round_trip`** — enqueue a hook (transition that fires one); claim via `POST /v1/hooks/claim`; assert the row's `status` is `in_progress` with a `lease_expires_at` in the future; `POST /v1/hooks/{id}/complete`; assert the row is `completed` and the event log shows no further activity.
- **`test_hook_claim_skip_locked`** — two concurrent `claim` calls each request batch size 10 from a queue of 5; assert total returned is 5 with no overlap (verifies `FOR UPDATE SKIP LOCKED`).
- **`test_hook_fail_retries_then_dead_letters`** — `fail` a hook with `retry_count < max_retries`; assert it's back to `pending`. `fail` it past `max_retries`; assert dead-letter row appears and `hook_dead_lettered` event is emitted. Same path as `_hooks.py:225-` — verifies the in-process and HTTP consumers share the implementation.
- **`test_hook_lease_expiry_requeues`** — claim a hook, do not ack, advance clock past lease; call `sweep_expired_hook_leases()`; assert hook is back to `pending` and retry count is unchanged (the sweep is not a fail).
- **`test_no_validator_registration_over_http`** — assert there is no route for `register_validator`. Belt-and-suspenders against accidental exposure since §3.2 is the architectural commitment.

## 11. Open questions / risks

- **REST shape is provisional.** §1 acknowledges this. When consumer #2 lands, the URL conventions, body shapes, and error envelope may need adjustment. v1 must therefore advertise itself as `/v1` and treat the version segment as load-bearing — `/v2` is expected.
- **Pydantic vs frozen-dataclass duplication.** Every domain type has a frozen dataclass in `_types.py` AND a Pydantic model in `sidecar/models.py`. These will drift. Mitigation: a structural test that asserts field-name parity between each pair; or generate Pydantic models from dataclasses at import time. Decide before merging.
- **JSON Schema for workflow YAML.** `register_workflow` accepts raw YAML; the sidecar passes it through. Non-Python consumers must vendor their own YAML serializer; this is acceptable but worth documenting.
- **No multi-project sidecar.** One sidecar = one `Regista` = one project. Multi-project routing is deferred to consumer demand.
- **Timezone semantics.** `not_before` and `start`/`end` filters are `datetime`; require ISO 8601 with timezone; reject naive datetimes at the Pydantic layer.
- **Replay over HTTP.** `replay()` can be long-running. v1 returns synchronously; consumers must set generous HTTP client timeouts. Async replay job pattern deferred.

## 12. Out of scope

- GraphQL.
- WebSockets / SSE / gRPC streaming.
- Multi-tenant routing (one sidecar per regista project).
- Rate limiting beyond a coarse `uvicorn --limit-concurrency` default.
- A web UI.
- **Synchronous transition validators over HTTP** — Python-only, per FR-13 / AC-30 and §3.2. Non-Python consumers express invariants as async hooks instead.
- **WASM-runtime validators in the sidecar** — a plausible future path for I/O-free cross-language validation, but adds a runtime dependency and a sandboxing surface that is not justified at N=1 consumer. Revisit if a non-Python consumer needs synchronous validation.
- In-process plugin loading for Python hook handlers running inside the sidecar (these run in a separate Python worker process, or non-Python consumers use the §3.1 polling API).
- Token management API (rotation, issuance) — edit-and-restart for v1.
- Distributed tracing propagation beyond logging an inbound request id.

---

Cross-references:
- Spec §19 — `/projects/regista/spec.md:682-726`
- Spec §19.2 signing invariant — `spec.md:690-694`
- Spec §19.3 service-wrapping rules — `spec.md:696-705`
- AC-33 — `spec.md:388`
- Regista public API — `/projects/regista/src/regista/__init__.py` class `Regista`
- ErrorCode enum — `/projects/regista/src/regista/_errors.py:4`
- Existing deps for context — `/projects/regista/pyproject.toml:10-18`
