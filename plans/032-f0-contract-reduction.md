# Plan 032 / F0 — Contract reduction and deletion map

**Status:** Working F0 deliverable (WI-364). Feeds F0a and F1.
**Base:** `main` @ `7707c81`, package `0.7.2`.
**Owner decisions (2026-09-11):**
1. Produce the reduced kernel by **fresh extraction** into a clean package tree, not in-place deletion.
2. **Delete signing/cryptography entirely** from the supported contract. Keep canonical serialization and consistency checks only.
3. **Remove all default removals** from Plan 032 §3 (trust, custody, bundles, witness, lineage/assurance, suite config, encryption, recurrence, hooks/webhooks, workflow inheritance, HTTP sidecar, in-memory backend).

## 1. Retained kernel (KEEP)

The general coordination ledger. Transitive dependency closure of the coordination modules is **37 modules**; after de-signing and pruning this shrinks further.

| Module | Responsibility |
| --- | --- |
| `_connection.py` | Pool, schema-per-project, `SET LOCAL search_path` |
| `_migrations.py` | Migration runner against the fresh baseline |
| `_errors.py` | `ErrorCode` + `RegistaError` (pruned) |
| `_types.py` | Frozen domain dataclasses (pruned) |
| `_contract.py` | Single-source-of-truth validation/decisions (lineage removed) |
| `_jcs.py` | Deterministic canonical JSON for content hashes/idempotency (no signing) |
| `_events.py` | Append, gap-free `event_seq`, idempotency (signing removed) |
| `_event_store.py` | `EventStore` protocol + shared append (signing removed) |
| `_reducer.py` | Projection reduction rules |
| `_workflow.py` | YAML parse, JSON Schema validate, semantic checks |
| `_work_items.py` | Create + structured query (FR-01/02/05b/27) |
| `_claims.py` | Claim lifecycle (FR-06…09b) |
| `_links.py` | Typed directed links (FR-22/23) |
| `_transition.py` | Transition validation + commit (FR-11/12/24/26) |
| `_replay.py` | Rebuild projection, honest drift reporting (FR-16) |
| `_integrity.py` | Startup migration + workflow compatibility (FR-20) |
| `_observability.py` | Structured logs + Prometheus metrics (FR-21) |
| `_datetime_utils.py` | Shared datetime comparison |
| `_actor_roles.py` | Actor → allowed_roles mapping (FR-24) |
| `_projects.py` | Project catalog (`create_project`/`list`) |
| `_version_info.py` | Minimal version surface (library/schema/workflow) |
| `_doctor.py` | Small reachability/schema health check (rewritten) |
| `_testing.py` | Test-only helpers (pruned of principal/hook coupling) |
| `_ops.py` | Facades: `WorkflowOps`, `WorkItemOps`, `EventOps`, `ClaimOps`, `LinkOps` |
| `_api_base.py`, `_api_meta.py`, `_api_claim.py`, `_api_external.py`, `_api_workflow.py` | Public API mixins (rewritten) |
| `_events_api.py`, `_claims_api.py`, `_links_api.py`, `_work_items_api.py`, `_workflow_api.py` | API-layer helpers (rewritten) |
| `__init__.py` | `Regista` entry point (rewritten) |
| `_cli.py` | Small admin CLI (rewritten) |
| `_vendor/rfc8785.py` | Retained only while `_jcs` uses it; otherwise drop |

### Deliberately deferred (decide in F0a; default remove)

- `_archive.py` — dormant-work-item archival (FR archive). Not MVP; remove unless an example needs it.
- `_workflow_compose.py` — `extends:` composition (FR-29). Plan §3 defaults to removal.
- `_maintenance.py` — timer thread. Sweep stays an explicit method; no background thread.

## 2. Removed (DELETE)

Grouped by responsibility. All code, tests, migrations, CLI verbs, docs, and dependencies belonging only to these are removed.

| Group | Modules |
| --- | --- |
| Signing / keys | `_signing.py`, `_signing_scheme.py`, `_keys.py` |
| Trust domain / genesis | `_trust_domain.py`, `_trust_log.py`, `_trust_log_writer.py`, `_trust_log_export.py`, `_trust_projection.py`, `_trust_genesis_file.py`, `_genesis.py`, `_genesis_open.py`, `_estate_catalog.py`, `_v6_writer.py`, `_v6_referents.py`, `_invariant_probe.py`, `_testing_v6.py`, `_in_memory_v6.py` |
| Audit bundle / verification | `_bundle.py`, `_bundle_v3.py`, `_verification.py`, `verification.py` |
| Principals / custody / delegation | `_principals.py`, `_principal_keys.py`, `_principal_alias.py`, `principal_lifecycle.py`, `_custody.py`, `_secrets.py`, `secrets.py`, `client_signer.py`, `_action_delegation.py` |
| Encryption-at-rest | `_encryption.py` |
| Lineage / assurance / review policy | `_lineage.py`, `_assurance.py`, `_review_validators.py`, `_lint.py` |
| Suite config / provisioning | `_config.py`, `_provision.py` |
| Hooks / webhooks | `_hooks.py`, `_hooks_api.py`, `_webhooks.py`, `_in_mem_hook.py`, `_in_memory_hooks.py` |
| Recurrence | `_recurrence.py`, `_recurrence_api.py`, `_in_memory_recurrence.py` |
| Witness | `_witness.py`, `_in_mem_witness.py` |
| In-memory backend | `_in_memory*.py`, `_in_mem_*.py` (all) |
| HTTP sidecar | `sidecar/` package |
| Archive (deferred) | `_archive.py` pending F0a |
| Compose (deferred) | `_workflow_compose.py` pending F0a |

## 3. Signing removal — event model delta

Remove from the event row and signing envelope:

- `signature`, `key_id`, `scheme_id`, `payload_canonical_hash`, `canonical_envelope`
- `prev_event_hash`, `prev_global_event_hash`, `global_seq` (tamper-evidence chain)
- `_v6_referents`/referent resolution used only by v6 signing
- `hmac_key_path` / key file plumbing from `Regista(...)` construction

Retain:

- `event_id`, `work_item_id`, `event_seq` (gap-free per item), `actor_id`, `actor_kind`, `actor_metadata`, `workflow_name`, `workflow_version`, `timestamp`, `transition`, `payload`
- `on_behalf_of` only if retained by the reduced contract (default: keep as a self-attested attribution field, unsigned)
- Canonical JSON + content hash for idempotency and projection consistency
- `actor_id` is caller-supplied attribution; the trusted-host/database-admin boundary is documented, not cryptographically enforced

## 4. Schema baseline

Fresh, single consolidated schema (no migration chain through trust schemas). Replace migrations `001–050` with one baseline.

Retained tables:

- `events` (de-signed, flat, `UNIQUE(event_id)`, per-item `event_seq`)
- `project_identity`
- `work_items_current` (projection)
- `claims`
- `workflow_registry`
- `actor_roles`
- `public.projects` catalog (schema qualification)
- custom-fields GIN index

Dropped: `hook_queue`, `hook_dead_letter`, `witness_*`, `principal_*`, `trust_*`, `anchor_*`, `tsp_batches`, `event_segments`, `lifecycle_*`, `action_delegation_credentials`, `recurrence_rules`, archive tables.

Open/init must distinguish: supported new schema, empty destination, old/unknown schema → **refuse before writes**; never auto-drop/reset.

## 5. Public API surface (target)

```python
Regista.create_project(dsn, project, *, pool_min=1, pool_max=10)
Regista(dsn, project, *, pool_min=1, pool_max=10)

register_workflow(yaml) / workflows.register(yaml)
create_work_item(workflow, type, actor_id, *, custom_fields=..., not_before=..., idempotency_key=...)
query_work_items(workflow=..., states=..., claimed_by=..., claimable_now=..., custom_field_filters=..., limit=..., after=...)
transition(work_item_id, transition, actor_id, *, custom_fields_update=..., expected_attempt_number=...)
append_event(work_item_id, actor_id, *, transition=..., payload=..., idempotency_key=...)
read_events(work_item_id=..., actor_id=..., since=..., until=..., transition=..., limit=..., after=...)
acquire_claim(work_item_id, actor_id, ttl_seconds=300)
heartbeat_claim(work_item_id, actor_id, ttl_seconds, *, expected_attempt_number=...)
release_claim(work_item_id, actor_id, *, expected_attempt_number=...)
sweep_expired_claims()
create_link / remove_link / query_links
register_actor_role / unregister_actor_role / list_actor_roles
update_not_before(work_item_id, not_before, actor_id)
replay() -> ReplayReport
versions()
close()
```

Removed from the surface: `enroll_principal`, `principals.*`, `principal_lifecycle.*`, `verify_trust_log`, `sign_spec`/`read_spec_events`, `witnesses.*`, `webhooks.*`, `hooks.*`, `recurrence.*`, `timestamping.*`, `archive.*`, `assurance.*`, `secrets.*`, `config.*`, all signing/key methods.

**Lease fencing:** expose `attempt_number` and require `expected_attempt_number` on lease-protected mutations (transition/append/release) so a stale worker is refused.

## 6. CLI surface (target)

Keep: `workflow validate`, `work-item show/list/create/transition`, `events show/tail`, `replay`, `schema init/status`, `actor-roles list`, `version --json`, `doctor --json` (small).

Remove: `bundle`, `hooks`, `recurrence`, `witness`, `webhook`, `principal`, `signer`, `provision`, `provision-principal`, `trust`, `genesis`, `spec`, `assurance`, `invariants`, `keys`, `secrets`, `config`.

## 7. Dependencies / packaging

- Distribution stays `regista-hraedon`; import + console script stay `regista`.
- Keep: `psycopg[binary]`, `psycopg-pool`, `pyyaml`, `jsonschema`, `structlog`, `prometheus-client`.
- Remove deps/extras: `pynacl` (ed25519/witness), `python-dateutil` (recurrence) unless dateutil is still used elsewhere, `cryptography` (encryption), `fastapi`/`uvicorn`/`pydantic`/`httpx`/`hvac`/`azure-*`/`rfc8785`/`agent-suite-conformance`.
- Confirm advertised vs tested Python range (Plan 032 §2: metadata says >=3.11, CI runs 3.13/3.14).

## 8. Test reconciliation

- Port kernel behavior tests (workflows, work items, claims, transitions, links, idempotency, replay, scoping, queries, role checks).
- Retire all deleted-feature tests; the existing `tests/retired_tests_ledger.json` + pin machinery is part of the removed trust-test apparatus and is not carried forward.
- Existing uncommitted edits to `tests/test_retired_tests_ledger.py` / `tests/test_wi289_cluster4_ledger_mapping.py` belong to the trust machinery; superseded by extraction.
- In-memory backend removal means kernel tests run against disposable PostgreSQL fixtures.

## 9. Open items / risks

- **Signing removal ripple:** `_events`, `_event_store`, `_replay`, `_transition`, `_contract`, `_api_meta`, `_testing` all reference keys/signing. Extraction edits each.
- **`_contract` ↔ `_lineage`:** remove the lineage validator from the shared contract.
- **`_jcs` / vendored rfc8785:** keep only if canonical content hashing remains load-bearing for idempotency.
- **In-memory removal cost:** every kernel test needs Postgres; qualification must cover disposable fixtures.
- **SEC-01…SEC-13:** classify as removed-from-0.8.0 after residual-reachability checks, not fixed on old versions. Retained-path findings (e.g. SEC-10 separation-of-duties if review validators are cut; SEC-09 cache staleness if any retained lifecycle path exists) get repaired only if the path ships.
- **Open-format refusal:** implement and test refusal of 0.5/0.6/0.7 schemas without mutation (F3.5).

## 10. Exit criteria for F0 → F0a

- [x] Owner decisions recorded (extraction / de-sign / remove-all-defaults).
- [x] Keep/delete map produced.
- [ ] F0a examples pass through the proposed public surface with no suite config, keys, private modules, or app-specific patches.
- [ ] Product-fit report; revise API or narrow product before F1 broad removal.