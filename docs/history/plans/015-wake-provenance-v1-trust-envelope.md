# Plan 015 — Wake/Provenance v1 Trust-Envelope Completion

**Status:** Draft RFC
**Owner:** regista
**Resolves:** BC-214, BC-215, BC-218, BC-219, BC-220, BC-221 (six of the eight items in `agent-wake/design/v1-implementation-spec.md` §2)
**Defers:** BC-216, BC-217 (require BC-196 asymmetric-signing implementation; tracked separately)
**Spec touched:** §17 (signing envelope), §17.9 (trust tiers), §19 (public API), §19.5 (error codes)
**Related:** Plan 008 (trust hardening), Plan 010 (delegation chain — shipped), Plan 011 (pluggable signing), Plan 012 (RFC 3161), BC-196/198 (open, asymmetric signing & operator-forgery)

## 1. Motivation

`agent-wake/design/v1-implementation-spec.md` §2 ("Regista change inventory") enumerates eight discrete regista changes that, together, complete the trust envelope required for both `agent-wake` v1 (durable external-ingest signaling) and `agent-provenance` v1 (Claude Code PreToolUse/PostToolUse attestation). Six of those changes are independent of BC-196 asymmetric signing and can ship now. Shipping them as a coherent slice — rather than ad-hoc per breadcrumb — keeps the signing envelope evolution legible and avoids three separate envelope-version bumps.

This is the load-bearing unblock for `agent-provenance` plan 002 ("Harness-level interception") and `agent-wake` v1 ingest. It also closes the residual gap in Plan 010: today `validate_delegation_chain` accepts `session_id` but does not validate its shape, so the field is structurally present but semantically dark.

## 2. Scope

In scope (six BCs):

| BC | Change | File(s) |
|---|---|---|
| BC-214 | Add `timestamp`, `key_id`, `event_seq`, `workflow_name`, `workflow_version` to signing envelope (envelope v4) | `_signing.py`, `_event_store.py`, `_replay.py`, `_in_memory_replay.py`, spec §17 |
| BC-215 | Add `revoked_at: str \| None` to `KeyEntry`; `verify_key_status` accepts events timestamped before revocation as valid | `_keys.py` |
| BC-218 | Add `role: str = "actor"` to `KeyEntry`; sign-time policy gate refuses keys whose role disallows the requested operation (initial values: `actor`, `auditor`, `recovery`) | `_keys.py`, `_signing.py` |
| BC-219 | `validate_delegation_chain` validates `session_id` (UUID), accepts optional `expires_at` (ISO-8601, must be > event timestamp), accepts optional `session_grant_event_id` (UUID; referent existence is a verifier concern, not enforced here) | `_contract.py` |
| BC-220 | Unify event timestamp source between `InMemoryEventStore` and `PostgresEventStore` — both use a single caller-resolvable clock, the same value is signed and persisted, no backend drift | `_event_store.py`, `_events.py`, `_in_memory_events.py` |
| BC-221 | Reserve `checkpoint` event transition for log compaction; spec-level reservation only — no v1 enforcement, but `transition` name is reserved against workflow YAML to prevent collision | `_workflow.py` validator, `spec.md` |

Out of scope (and why):

- BC-216, BC-217 — require Ed25519 + per-principal key resolution; tracked by future plan once BC-196 lands.
- BC-198 (operator forgery defense) — properly belongs with Plan 012 RFC 3161 maturation, not here.
- Plan 013 (witness hooks) — independently scoped; will follow this plan once envelope is stable.
- Auditor-side verifier tool — lives in `agent-provenance`, not regista.

## 3. Design

### 3.1 Envelope v4 (BC-214)

The signing envelope (currently v3 from BC-233's hash-chain addition) gains five fields. Canonical ordering after RFC 8785:

```
event_id, work_item_id, actor_id, on_behalf_of, transition, payload,
prev_event_hash, global_seq,                     # v3 (BC-233/Plan 014)
timestamp, key_id, event_seq,                    # v4 NEW
workflow_name, workflow_version                  # v4 NEW
```

All five new fields are already on the `Event` record. The change is purely envelope coverage. `build_signing_envelope()` gains the parameters; `sign_event` and `verify_event` thread them. `stored_envelope` round-trip remains the authoritative verification path for already-signed historical events (see Plan 010 §3.4 pattern).

`signing_envelope_version` is not stored on rows. Replay detects v4 by attempting v4 first and falling back to v3, then v2, on signature mismatch. Backward-compat fallback is bounded: replay reports `envelope_version_drift` warnings rather than failing.

### 3.2 KeyEntry extension (BC-215, BC-218)

`KeyEntry` (frozen dataclass in `_keys.py`) gains:

```python
revoked_at: str | None = None     # ISO-8601 UTC; None = never revoked
role: str = "actor"                # actor | auditor | recovery
```

`verify_key_status(key_id, event_timestamp)` becomes a timestamped query:

- Status `active` or `rotated`: always valid.
- Status `revoked`: valid iff `event_timestamp < revoked_at`.
- Status `unknown`: raises `KEY_LOAD_ERROR` per Plan 008 WS-5.

`role` enforcement is read-only in v1: a future plan can add a sign-time gate that refuses `auditor` keys for `transition()`. For now, the field is persisted and surfaced in `keys_loaded` log lines so consumers can verify operator intent. This avoids breakage on existing single-role deployments.

New key file schema (additive; old files still load):

```json
{
  "key_id": "operator-2026-05",
  "secret_b64": "...",
  "status": "active",
  "scheme": "hmac-sha256",
  "role": "actor",
  "revoked_at": null
}
```

### 3.3 Delegation chain validation upgrade (BC-219)

`validate_delegation_chain()` in `_contract.py` already accepts `session_id`/`authenticated_at` as strings. v1 strengthens:

- `session_id`, if present, must be a valid UUID string. Reject otherwise.
- `expires_at`, if present, must parse as RFC 3339 UTC. If the event's signing timestamp is `≥ expires_at`, raise `DELEGATION_CHAIN_EXPIRED` (new error code).
- `session_grant_event_id`, if present, must be a valid UUID string. Referential integrity is NOT checked at sign time (the grant event may live in a separate regista project or be verifier-resolved); structural validation only.
- `authenticated_at`, if present, must parse as RFC 3339 UTC and be ≤ event timestamp.

New error codes: `DELEGATION_CHAIN_EXPIRED`. Existing `INVALID_ARGUMENT` continues for structural failures (keep churn down).

### 3.4 Timestamp source unification (BC-220)

Today, `InMemoryEventStore.append()` and `PostgresEventStore.append()` independently resolve `now()`. The DB path uses `now()` in SQL; InMemory uses `datetime.now(UTC)`. The envelope is built from a Python-side `event_timestamp` that may not equal the persisted column.

Fix: shared `append_event()` in `_event_store.py` resolves a single `event_timestamp: datetime` once (parameter override allowed for tests; default `datetime.now(UTC)`), passes it to the signer, and both stores persist that exact value. Postgres switches to explicit parameter substitution in the INSERT for `timestamp` rather than `DEFAULT now()`.

Migration `019_explicit_event_timestamp.sql`: no schema change; documentation only. Existing `DEFAULT now()` on the column remains as a safety net but is overridden by the application.

### 3.5 Checkpoint transition reservation (BC-221)

`_workflow.py` semantic validator rejects a workflow YAML that defines a transition literally named `checkpoint`. New error code: `RESERVED_TRANSITION_NAME`. No event behavior change; this only prevents collision before v2 ships checkpoint semantics.

Spec §17 gains a one-paragraph note explaining the reservation.

## 4. Migration

- `019_explicit_event_timestamp.sql` — comment-only migration (idempotent, runs cleanly on prior schema).
- No data backfill. Old events keep their v3 envelope; replay falls back per §3.1.
- Key files: additive. Old files without `role`/`revoked_at` load with defaults.

## 5. Work-item breakdown (implementation order)

Each item is one PR-sized unit; sequencing matches `agent-wake` v1 spec §6.

1. **WI-1 (BC-220):** Unify timestamp source. Test: identical events appended via InMemory and Postgres with the same `event_timestamp` produce identical envelopes and identical persisted rows. (Foundational — every later signing change depends on stable timestamp semantics.)
2. **WI-2 (BC-214):** Envelope v4. Test: v4 round-trip; replay accepts pre-v4 stored envelopes; envelope-version-drift warning is emitted for mixed logs.
3. **WI-3 (BC-215):** `revoked_at` on `KeyEntry` + timestamped `verify_key_status`. Test: revoked key still verifies pre-revocation events.
4. **WI-4 (BC-218):** `role` on `KeyEntry`. Test: round-trip; surfaced in `keys_loaded` log; unknown role rejected.
5. **WI-5 (BC-219):** Delegation-chain v2 validation. Test: invalid UUID, expired `expires_at`, future `authenticated_at` all rejected with appropriate error codes.
6. **WI-6 (BC-221):** Reserve `checkpoint`. Test: workflow YAML with `checkpoint` transition rejected with `RESERVED_TRANSITION_NAME`.
7. **WI-7:** Spec v9 + AGENTS.md status block + CHANGELOG.

## 6. Acceptance criteria

- All existing tests pass; no envelope-version regressions.
- New tests added per work item above; aggregate test count ≥ +25.
- `replay()` over a mixed log (pre-v4 + v4 events) returns `ok=True` with `warnings` populated only for envelope-version notes.
- `agent-provenance` consumer (live or stub) can sign and verify events whose envelope includes `timestamp`/`key_id`/`workflow_name`.
- `agent-wake` v1 verifier prerequisites are satisfiable from regista alone for the non-BC-196 path.
- spec.md revision history advances to v9; FR-15 lists envelope v4 fields.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Envelope v4 introduces signature non-portability with v3 logs | `stored_envelope` path remains authoritative for pre-v4 rows; replay fallback is bounded and emits warnings, not failures |
| Caller-provided `event_timestamp` opens clock-skew attacks | v1 keeps `datetime.now(UTC)` as default; override is keyword-only and tests-only; Plan 012 TSA anchoring is the long-term defense (BC-198) |
| Multiple new error codes break sf2 / agent-provenance | New codes (`DELEGATION_CHAIN_EXPIRED`, `RESERVED_TRANSITION_NAME`) are additive; existing call sites continue to use existing codes |
| `role` field on key file creates upgrade hazard | Defaults to `"actor"` for any key file lacking it; deployment requires no key-file changes |

## 8. Open questions

- **Q1:** Should `role="auditor"` keys be allowed to call `transition()` at all in v1, or merely flagged? Spec says deferred to BC-196; defaulting to "allowed but logged" for now.
- **Q2:** Should envelope-version mismatches emit a Prometheus counter (`regista_envelope_version_drift_total`) in addition to replay warnings? Probably yes; adding to WI-2.
- **Q3:** `session_grant_event_id` referential check — punted to verifier. Confirm with agent-provenance owner that this split is acceptable.

## 9. Cross-project impact

- **agent-provenance:** Unblocks plan 002 (PreToolUse/PostToolUse hooks) end-to-end for the non-Ed25519 path. `Plan 002 §"Gaps to close"` BC-197 line is already satisfied by Plan 010; this plan closes the BC-219 follow-up. Verifier work for `session_grant_event_id` referential checks moves to `agent-provenance`.
- **agent-wake:** Unblocks v1 regista dependency completely except BC-196/216/217 (asymmetric path). agent-wake adapters can now rely on a stable envelope v4 and unified timestamps.
- **agent-notes:** No direct change; the eventual NOTIFY → wake bridge still uses regista's normal append path, which now has the strengthened envelope automatically.
- **software-factory-2:** Receives envelope v4 transparently. The positional constructor contract (BC-195) is unaffected. sf2 should see no behavior change unless it inspects raw envelopes.
